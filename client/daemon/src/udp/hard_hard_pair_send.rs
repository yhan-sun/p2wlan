use super::*;

impl UdpTransport {
    /// Classify at the boundary: owner/readiness failures never claim a
    /// physical error, while every returned send syscall error retains its cost.
    #[allow(clippy::too_many_arguments)]
    pub(super) async fn send_hh2_probe_datagram(
        &self,
        index: usize,
        socket: &Arc<UdpSocket>,
        bytes: &[u8],
        peer: &str,
        endpoint: SocketAddr,
        token: &str,
        purpose: PendingProbePurpose,
        use_candidate: bool,
    ) -> std::result::Result<usize, ProbeSendFailure> {
        let rejected = || {
            ProbeSendFailure::new(
                ProbeSendFailureKind::SocketRevoked,
                DaemonError::Network("hh2 pair send intent, deadline or owner revoked".into()),
            )
        };
        let pair = crate::peer::HardHardPairKey {
            socket_index: index,
            local_endpoint: socket.local_addr().map_err(|error| {
                ProbeSendFailure::new(
                    ProbeSendFailureKind::SocketUnavailable,
                    DaemonError::Network(error.to_string()),
                )
            })?,
            remote_endpoint: endpoint,
        };
        let send = async {
            loop {
                socket.writable().await.map_err(|error| {
                    ProbeSendFailure::new(
                        ProbeSendFailureKind::SocketUnavailable,
                        DaemonError::Network(error.to_string()),
                    )
                })?;
                let _epoch = self.network_epoch_gate.lock().await;
                let Some(scope) = self.peers.hard_hard_pair_scope(peer, token).await else {
                    return Err(rejected());
                };
                if use_candidate != (purpose == PendingProbePurpose::HardHardNomination)
                    || !matches!(
                        purpose,
                        PendingProbePurpose::ConnectivityCheck
                            | PendingProbePurpose::HardHardTriggeredCheck
                            | PendingProbePurpose::HardHardNomination
                    )
                    || (purpose == PendingProbePurpose::ConnectivityCheck
                        && self.peers.hard_hard_pair_is_prepared(peer, token).await)
                {
                    return Err(rejected());
                }
                let Some(deadline) = self
                    .peers
                    .hard_hard_pair_send_deadline(peer, token, &pair, use_candidate)
                    .await
                else {
                    return Err(rejected());
                };
                let state = self.socket_state.lock().await;
                if !state.dynamic.get(&index).is_some_and(|entry| {
                    entry.peer_id == peer
                        && entry.phase.is_usable()
                        && entry.hard_hard_pair_required
                        && entry.hard_hard_session_token.as_deref() == Some(token)
                        && entry.network_generation == scope.local_network_generation
                        && Arc::ptr_eq(&entry.socket, socket)
                }) || scope.cancellation.is_cancelled()
                    || tokio::time::Instant::now() >= deadline
                    || scope.local_network_generation
                        != self.peers.current_network_generation_sync()
                {
                    return Err(rejected());
                }
                let mut exploration = if purpose == PendingProbePurpose::ConnectivityCheck {
                    Some(
                        self.peers
                            .hard_hard_exploration_handoff_guard(peer, token, &pair)
                            .await
                            .ok_or_else(rejected)?,
                    )
                } else {
                    None
                };
                if exploration
                    .as_ref()
                    .is_some_and(|guard| !guard.is_current(&self.peers))
                {
                    return Err(rejected());
                }
                #[cfg(test)]
                if self.should_fail_probe_send_for_test() {
                    return Err(ProbeSendFailure::with_physical_send_error(
                        DaemonError::Network("test-injected physical probe send failure".into()),
                        bytes.len(),
                    ));
                }
                // Epoch and exact-socket fences remain held through this
                // nonblocking kernel handoff, but never through a wait for IO.
                match socket.try_send_to(bytes, endpoint) {
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => continue,
                    Ok(sent) => {
                        if let Some(guard) = exploration.as_mut() {
                            guard.handoff_succeeded();
                        }
                        let confirmation_purpose = match purpose {
                            PendingProbePurpose::HardHardTriggeredCheck => {
                                Some(crate::peer::HardHardConfirmationPurpose::TriggeredCheck)
                            }
                            PendingProbePurpose::HardHardNomination => {
                                Some(crate::peer::HardHardConfirmationPurpose::Nomination)
                            }
                            _ => None,
                        };
                        if let Some(purpose) = confirmation_purpose {
                            scope
                                .measurement
                                .evidence
                                .record_confirmation_handoff(purpose, sent);
                        }
                        if let Some(plan) = scope.coordinated_plan.as_ref() {
                            if let Some(lease) = plan.measurement_lease.as_ref() {
                                lease.on_probe_handoff(plan.agreement.map_or(
                                    crate::peer::HardHardProbeStrategy::Birthday,
                                    |agreement| agreement.strategy,
                                ));
                            }
                        }
                        return Ok(sent);
                    }
                    Err(error) => {
                        return Err(ProbeSendFailure::with_physical_send_error(
                            DaemonError::Network(format!(
                                "UDP probe send to {endpoint} failed: {error}"
                            )),
                            bytes.len(),
                        ));
                    }
                }
            }
        };
        timeout(Duration::from_millis(100), send)
            .await
            .map_err(|_| {
                ProbeSendFailure::new(
                    ProbeSendFailureKind::PreHandoffTimeout,
                    DaemonError::Network(
                        "hh2 probe readiness timed out before kernel handoff".into(),
                    ),
                )
            })?
    }
}
