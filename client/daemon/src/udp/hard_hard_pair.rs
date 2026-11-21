use super::*;
use crate::peer::{
    HardHardPairAction, HardHardPairEvidence, HardHardPairKey, HardHardPairSendOutcome,
    HardHardPairSendPhase, HARD_HARD_PAIR_RETRY_INTERVAL,
};

impl UdpTransport {
    /// Run inside the existing HH worker, never as a detached task. No action
    /// can extend discovery or the session TTL; only an already prepared pair
    /// receives the existing two-second confirmation grace.
    pub(crate) async fn run_hard_hard_pair_nomination(
        &self,
        peer: &str,
        token: &str,
        discovery_deadline: tokio::time::Instant,
    ) {
        if !self
            .peers
            .hard_hard_pair_claim_worker(peer, token, discovery_deadline)
            .await
        {
            return;
        }
        let confirmation_deadline = discovery_deadline + Duration::from_secs(2);
        let worker = async {
            loop {
                let now = tokio::time::Instant::now();
                if self.peers.hard_hard_pair_scope(peer, token).await.is_none()
                    || self
                        .peers
                        .hard_hard_winner_for_token(peer, token)
                        .await
                        .is_some()
                {
                    return;
                }
                let discovery_open = now < discovery_deadline;
                if !discovery_open && !self.peers.hard_hard_pair_is_prepared(peer, token).await {
                    return;
                }
                if let Some(action) = self
                    .peers
                    .hard_hard_pair_next_action(peer, token, discovery_open)
                    .await
                {
                    match action {
                        HardHardPairAction::Validate(pair) => {
                            // The single-flight scheduler may be full; repeat a
                            // bounded observation until it admits a worker.
                            let gate = self.network_epoch_gate.lock().await;
                            if self
                                .hh2_validation_pair_matches(
                                    peer,
                                    pair.socket_index,
                                    pair.remote_endpoint,
                                )
                                .await
                            {
                                self.peers
                                    .learn_authenticated_endpoint_in_epoch(
                                        &gate,
                                        peer,
                                        pair.remote_endpoint,
                                    )
                                    .await;
                                self.peers
                                    .record_direct_probe_success_with_local_endpoint(
                                        peer,
                                        pair.remote_endpoint,
                                        Some(pair.local_endpoint),
                                    )
                                    .await;
                                let admission = self
                                    .trigger_encrypted_validation(peer, pair.remote_endpoint)
                                    .await;
                                if admission == DirectValidationAdmission::Backpressured {
                                    trace!(peer_id = peer, token,
                                        "HH validation observation deferred by bounded ingress; no Request allowance spent");
                                }
                            }
                        }
                        HardHardPairAction::Send(pair, phase) => {
                            let outcome =
                                self.send_hh2_pair_action(peer, token, &pair, phase).await;
                            self.peers
                                .hard_hard_pair_record_send_outcome(
                                    peer, token, &pair, phase, outcome,
                                )
                                .await;
                        }
                    }
                }
                sleep(Duration::from_millis(25)).await;
            }
        };
        // Bounds lock acquisition and readiness as well as the network send.
        let _ = tokio::time::timeout_at(confirmation_deadline, worker).await;
    }

    pub(super) async fn send_hh2_pair_action(
        &self,
        peer: &str,
        token: &str,
        pair: &HardHardPairKey,
        phase: HardHardPairSendPhase,
    ) -> HardHardPairSendOutcome {
        let nominate = phase == HardHardPairSendPhase::Nomination;
        let Some((deadline, budget_purpose)) = self
            .peers
            .hard_hard_pair_send_admission(peer, token, pair, phase)
            .await
        else {
            return HardHardPairSendOutcome::Stopped;
        };
        // Before the classified sender starts there can be no packet. After
        // entry a timeout may interrupt post-syscall bookkeeping, so retain
        // its attempt instead of blindly refunding an unknown delivery.
        let mut sender_entered = false;
        let action = async {
            let admission = self
                .admit_hard_hard_connectivity_probe(
                    peer,
                    pair.remote_endpoint,
                    pair.socket_index,
                    token,
                    budget_purpose,
                )
                .await;
            if admission != OutboundProbeAdmission::Accepted {
                return match admission {
                    OutboundProbeAdmission::RecoveryIdentityStale
                    | OutboundProbeAdmission::EpochCreditExhausted
                    | OutboundProbeAdmission::HardHardRecoveryConfirmationReserved
                    | OutboundProbeAdmission::HardHardConfirmationCreditReserved => {
                        HardHardPairSendOutcome::Stopped
                    }
                    _ => HardHardPairSendOutcome::BudgetDeferred,
                };
            }
            let Some((index, socket, _lease)) = self
                .resolve_dynamic_socket_index_for_send(peer, pair.socket_index)
                .await
            else {
                return HardHardPairSendOutcome::Stopped;
            };
            let purpose = if nominate {
                PendingProbePurpose::HardHardNomination
            } else {
                PendingProbePurpose::HardHardTriggeredCheck
            };
            sender_entered = true;
            match self
                .send_probe_on_socket_result_with_hard_hard_token_classified(
                    index,
                    socket,
                    Some(peer),
                    pair.remote_endpoint,
                    nominate,
                    purpose,
                    Some(token),
                    true,
                    None,
                )
                .await
            {
                Ok(_) => HardHardPairSendOutcome::Sent,
                // HH2 sends exactly one primary datagram and no compatibility
                // burst. This returned error proves that handoff failed; it
                // is different from cancellation while awaiting its result.
                Err(failure) if failure.retryable_not_sent() => {
                    HardHardPairSendOutcome::RetryableNotSent
                }
                Err(_) => HardHardPairSendOutcome::Stopped,
            }
        };
        // Leave room for the sender's own 100ms readiness bound to return a
        // definite non-send. Never extend the negotiated phase/TTL deadline.
        let outcome = match tokio::time::timeout_at(
            deadline.min(tokio::time::Instant::now() + HARD_HARD_PAIR_RETRY_INTERVAL),
            action,
        )
        .await
        {
            Ok(outcome) => outcome,
            Err(_) if sender_entered => HardHardPairSendOutcome::DeliveryUnknown,
            Err(_) => HardHardPairSendOutcome::RetryableNotSent,
        };
        if outcome != HardHardPairSendOutcome::Sent {
            debug!(event = "hard_hard_pair_send_deferred", peer_id = peer,
                phase = ?phase, outcome = ?outcome,
                "bounded pair send did not report a successful handoff");
        }
        outcome
    }

    /// Separate hh2 receive reducer: none of the legacy learning/affinity
    /// fallbacks can run before nomination and encrypted validation complete.
    #[allow(clippy::too_many_arguments)]
    pub(super) async fn handle_hard_hard_pair_packet(
        &self,
        peer: &str,
        token: &str,
        packet: &p2pnet_nat::DecodedPunchPacket,
        key: &p2pnet_nat::ProbeMacKey,
        peer_session: PeerSessionGeneration,
        authenticated_probe_session: Option<&str>,
        socket_index: usize,
        socket: &Arc<UdpSocket>,
        source: SocketAddr,
    ) {
        let adoption = self.adoption_lock_for(peer).await;
        let _adoption = adoption.lock().await;
        let _epoch = self.network_epoch_gate.lock().await;
        if !self.peers.peer_session_is_current_sync(peer, peer_session)
            || self.peers.hard_hard_pair_scope(peer, token).await.is_none()
        {
            return;
        }
        let generation = self.peers.current_network_generation_sync();
        let Ok(local_endpoint) = socket.local_addr() else {
            return;
        };
        let pair = HardHardPairKey {
            socket_index,
            local_endpoint,
            remote_endpoint: source,
        };
        {
            let state = self.socket_state.lock().await;
            if !state.dynamic.get(&socket_index).is_some_and(|entry| {
                entry.peer_id == peer
                    && entry.network_generation == generation
                    && entry.phase.is_usable()
                    && Arc::ptr_eq(&entry.socket, socket)
                    && entry.hard_hard_session_token.as_deref() == Some(token)
            }) {
                return;
            }
        }
        let mut diagnostic_session = authenticated_probe_session.map(str::to_owned);
        let evidence = match packet.kind {
            PunchPacketKind::Punch => {
                let admission = self
                    .admit_authenticated_punch(
                        peer,
                        packet.generation.unwrap_or(0),
                        packet.kind,
                        packet.nonce,
                        source,
                    )
                    .await;
                if matches!(admission, AuthenticatedPunchAdmission::RateLimited) {
                    return;
                }
                let evidence = if packet.use_candidate {
                    HardHardPairEvidence::NominationRequest
                } else {
                    HardHardPairEvidence::Observed
                };
                if !self
                    .peers
                    .hard_hard_pair_observe(peer, token, pair.clone(), evidence)
                    .await
                {
                    return;
                }
                let Some(local_id) = self.local_node_id.as_deref() else {
                    return;
                };
                let ack =
                    build_authenticated_punch_ack(packet.nonce, local_id, peer, generation, key);
                if self
                    .send_hh2_probe_ack(
                        &_epoch,
                        peer,
                        token,
                        &pair,
                        socket,
                        &ack,
                        packet.use_candidate,
                    )
                    .await
                    .is_ok()
                {
                    self.update_socket_diagnostics(socket_index, |m| m.probe_acks_sent += 1)
                        .await;
                }
                evidence
            }
            PunchPacketKind::Ack => {
                let current_candidate_epoch = self
                    .peers
                    .current_remote_candidate_epoch(peer)
                    .await
                    .unwrap_or(0);
                let state = self.socket_state.lock().await;
                let cleanup = state.probe_cleanup_epochs.get(peer).copied().unwrap_or(0);
                let mut pending = self.pending_probes.lock().await;
                let mut bindings = self.hard_hard_probe_bindings.lock().await;
                let Some(probe) = pending.get(&packet.nonce) else {
                    return;
                };
                // Keep the pending transaction when an authentic response
                // comes from another tuple. It is not this pair's confirmation.
                if probe.peer_id.as_deref() != Some(peer)
                    || probe.socket_index != socket_index
                    || probe.endpoint != source
                    || probe.local_endpoint != Some(local_endpoint)
                    || probe.generation != generation
                    || probe.remote_candidate_epoch != current_candidate_epoch
                    || probe.cleanup_epoch != cleanup
                    || probe.is_expired(Instant::now())
                    || probe.direct_commit_seq
                        != self.peers.direct_commit_seq_sync(peer).unwrap_or(0)
                    || !probe.accepts_authenticated_ack
                    || bindings.get(&packet.nonce).map(String::as_str) != Some(token)
                {
                    return;
                }
                let evidence = match probe.purpose {
                    PendingProbePurpose::ConnectivityCheck
                    | PendingProbePurpose::HardHardTriggeredCheck => {
                        HardHardPairEvidence::ConnectivityAck
                    }
                    PendingProbePurpose::HardHardNomination => HardHardPairEvidence::NominationAck,
                    _ => return,
                };
                diagnostic_session = probe.probe_session_id.clone();
                pending.remove(&packet.nonce);
                bindings.remove(&packet.nonce);
                drop(bindings);
                drop(pending);
                drop(state);
                if !self
                    .peers
                    .hard_hard_pair_observe(peer, token, pair.clone(), evidence)
                    .await
                {
                    return;
                }
                self.update_socket_diagnostics(socket_index, |m| m.probe_acks_received += 1)
                    .await;
                self.peers
                    .record_hard_hard_receive(
                        peer,
                        token,
                        peer_session,
                        pair,
                        crate::peer::HardHardReceiveObservation::MatchedAck,
                        monotonic_millis(),
                    )
                    .await;
                evidence
            }
        };
        self.update_peer_probe_rx_diagnostics(
            peer,
            generation,
            diagnostic_session.as_deref(),
            |m| {
                m.authenticated_probe_packets_received =
                    m.authenticated_probe_packets_received.saturating_add(1);
                if matches!(
                    evidence,
                    HardHardPairEvidence::ConnectivityAck | HardHardPairEvidence::NominationAck
                ) {
                    m.authenticated_probe_acks_observed =
                        m.authenticated_probe_acks_observed.saturating_add(1);
                    m.probe_acks_received = m.probe_acks_received.saturating_add(1);
                }
            },
        )
        .await;
    }

    #[allow(clippy::too_many_arguments)]
    pub(super) async fn send_hh2_probe_ack(
        &self,
        _epoch: &tokio::sync::MutexGuard<'_, ()>,
        peer: &str,
        token: &str,
        pair: &HardHardPairKey,
        socket: &Arc<UdpSocket>,
        bytes: &[u8],
        nomination_request: bool,
    ) -> std::io::Result<usize> {
        let rejected = || {
            std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "hh2 ACK exact pair, deadline or owner revoked",
            )
        };
        let send = async {
            loop {
                socket.writable().await?;
                let permit = self
                    .peers
                    .hard_hard_probe_ack_send_permit(peer, token, pair, nomination_request)
                    .await
                    .ok_or_else(rejected)?;
                #[cfg(test)]
                {
                    let gate = self.hh2_probe_ack_send_gate.lock().await.clone();
                    if let Some(gate) = gate {
                        gate.reached.notify_one();
                        gate.release.notified().await;
                    }
                }
                let state = self.socket_state.lock().await;
                if !permit.is_current(&self.peers)
                    || !state.dynamic.get(&pair.socket_index).is_some_and(|entry| {
                        entry.peer_id == peer
                            && entry.phase.is_usable()
                            && entry.hard_hard_pair_required
                            && entry.hard_hard_session_token.as_deref() == Some(token)
                            && entry.network_generation
                                == self.peers.current_network_generation_sync()
                            && Arc::ptr_eq(&entry.socket, socket)
                            && socket.local_addr().ok() == Some(pair.local_endpoint)
                    })
                {
                    return Err(rejected());
                }
                // Cancellation, action deadline and exact socket identity are
                // rechecked after every await, immediately before kernel IO.
                match socket.try_send_to(bytes, pair.remote_endpoint) {
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => continue,
                    Ok(sent) => {
                        permit.record_handoff(
                            crate::peer::HardHardConfirmationPurpose::ProbeAck,
                            sent,
                        );
                        return Ok(sent);
                    }
                    result => return result,
                }
            }
        };
        timeout(Duration::from_millis(25), send)
            .await
            .map_err(|_| rejected())?
    }
}
