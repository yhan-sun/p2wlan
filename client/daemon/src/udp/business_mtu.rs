use super::*;

impl UdpTransport {
    pub(crate) fn with_dplpmtud_local_virtual_ip(mut self, local_virtual_ip: Ipv4Addr) -> Self {
        self.dplpmtud_local_virtual_ip = Some(local_virtual_ip);
        self
    }

    pub(crate) fn dplpmtud_runtime(&self) -> crate::dplpmtud::DplpmtudRuntime {
        self.dplpmtud.clone()
    }

    pub(crate) fn dplpmtud_worker_ingress(&self) -> crate::dplpmtud::DplpmtudWorkerIngress {
        self.dplpmtud_worker_ingress.clone()
    }

    pub(crate) fn mark_peer_dplpmtud_supported(
        &self,
        peer_id: &str,
        peer_session_generation: PeerSessionGeneration,
    ) -> bool {
        self.peers
            .mark_dplpmtud_capable_sync(peer_id, peer_session_generation);
        self.dplpmtud
            .mark_supported(peer_id, peer_session_generation.value())
    }

    pub(crate) fn direct_business_budget_ready_for_peer(&self, peer_id: &str) -> bool {
        let Some(session_generation) = self.peers.peer_session_generation_sync(peer_id) else {
            return false;
        };
        if !self
            .peers
            .peer_supports_dplpmtud_sync(peer_id, session_generation)
        {
            return true;
        }
        self.dplpmtud
            .direct_business_budget_entry(peer_id)
            .is_some_and(|entry| {
                !entry.enforced
                    || (entry.update.budget.is_some() && self.inbound_publication_owner() != 0)
            })
    }

    /// Bind the peer's authenticated Direct-validation Request ingress to the
    /// exact receiving socket and local lifecycle. The route is response-only:
    /// it never selects or promotes a business path.
    pub(crate) fn remember_dplpmtud_ack_reverse_route(
        &self,
        peer_id: &str,
        network_generation: u64,
        peer_session_generation: PeerSessionGeneration,
        remote_endpoint: SocketAddr,
        local_endpoint: Option<SocketAddr>,
        socket_index: Option<usize>,
    ) -> bool {
        let (Some(local_endpoint), Some(socket_index)) = (local_endpoint, socket_index) else {
            return false;
        };
        if self.peers.current_network_generation_sync() != network_generation
            || !self
                .peers
                .peer_session_is_current_sync(peer_id, peer_session_generation)
            || local_endpoint.is_ipv4() != remote_endpoint.is_ipv4()
        {
            return false;
        }
        let mut routes = self
            .dplpmtud_ack_reverse_routes
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if routes.len() >= crate::dplpmtud::MAX_TRACKED_DPLPMTUD_PEERS
            && !routes.contains_key(peer_id)
        {
            return false;
        }
        routes.insert(
            peer_id.to_string(),
            DplpmtudAckReverseRoute {
                network_generation,
                peer_session_generation,
                remote_endpoint,
                local_endpoint,
                socket_index,
            },
        );
        true
    }

    /// Read one exact current reverse route without awaiting or touching the
    /// DPLPMTUD registry. Stale generation/session/socket bindings fail closed.
    pub(crate) fn dplpmtud_ack_reverse_endpoint(
        &self,
        peer_id: &str,
        peer_session_generation: PeerSessionGeneration,
        local_endpoint: SocketAddr,
        socket_index: usize,
    ) -> Option<SocketAddr> {
        let route = self
            .dplpmtud_ack_reverse_routes
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .get(peer_id)
            .copied()?;
        (route.network_generation == self.peers.current_network_generation_sync()
            && route.peer_session_generation == peer_session_generation
            && self
                .peers
                .peer_session_is_current_sync(peer_id, peer_session_generation)
            && route.local_endpoint == local_endpoint
            && route.socket_index == socket_index)
            .then_some(route.remote_endpoint)
    }

    pub(crate) fn peer_requires_direct_business_budget(&self, peer_id: &str) -> bool {
        self.peers
            .peer_session_generation_sync(peer_id)
            .is_some_and(|generation| self.peers.peer_supports_dplpmtud_sync(peer_id, generation))
            && self
                .dplpmtud
                .direct_business_budget_entry(peer_id)
                .is_none_or(|entry| entry.enforced)
    }

    /// Capture exact committed Direct identity, exact socket lease, owner and
    /// confirmed budget before allocating a WireGuard counter.
    pub(crate) async fn prepare_direct_business_send(
        &self,
        peer_id: &str,
        expected_endpoint: SocketAddr,
    ) -> DirectBusinessBudgetGate {
        let Some(session_generation) = self.peers.peer_session_generation_sync(peer_id) else {
            return DirectBusinessBudgetGate::ManagedPending {
                reason: "peer_session_missing",
            };
        };
        if !self
            .peers
            .peer_supports_dplpmtud_sync(peer_id, session_generation)
        {
            return DirectBusinessBudgetGate::Unmanaged;
        }

        let Some((socket_index, socket, lease)) = self
            .resolve_send_socket_with_lease_for_endpoint(peer_id, Some(expected_endpoint))
            .await
        else {
            return DirectBusinessBudgetGate::ManagedPending {
                reason: "exact_socket_missing",
            };
        };
        let Some(committed) = self.peers.committed_business_path_snapshot_sync(peer_id) else {
            return DirectBusinessBudgetGate::ManagedPending {
                reason: "committed_path_missing",
            };
        };
        let validation = match committed.active {
            ActiveBusinessPath::Direct(validation)
                if committed.lifecycle == PeerPathLifecycle::Online =>
            {
                validation
            }
            _ => {
                return DirectBusinessBudgetGate::ManagedPending {
                    reason: "active_path_not_direct",
                }
            }
        };
        let Some(epoch) = committed.epoch.filter(|epoch| *epoch == validation.epoch) else {
            return DirectBusinessBudgetGate::ManagedPending {
                reason: "path_epoch_mismatch",
            };
        };
        let Some(remote_endpoint) = validation.commit_endpoint() else {
            return DirectBusinessBudgetGate::ManagedPending {
                reason: "direct_identity_unconfirmed",
            };
        };
        if remote_endpoint != expected_endpoint {
            return DirectBusinessBudgetGate::ManagedPending {
                reason: "selector_endpoint_changed",
            };
        }
        let Some(pair) = self.peers.direct_commit_pair_snapshot_sync(peer_id) else {
            return DirectBusinessBudgetGate::ManagedPending {
                reason: "direct_pair_missing",
            };
        };
        let Some(local_endpoint) = pair.local_endpoint else {
            return DirectBusinessBudgetGate::ManagedPending {
                reason: "local_endpoint_missing",
            };
        };
        if pair.generation != epoch.network_generation
            || pair.remote_candidate_epoch != epoch.remote_candidate_epoch
            || socket.local_addr().ok() != Some(local_endpoint)
        {
            return DirectBusinessBudgetGate::ManagedPending {
                reason: "exact_socket_identity_changed",
            };
        }
        let Some(path_identity) = crate::dplpmtud::DplpmtudPathIdentity::from_committed_validation(
            peer_id,
            validation,
            remote_endpoint,
            local_endpoint,
            self.transport_instance_id,
            socket_index,
        ) else {
            return DirectBusinessBudgetGate::ManagedPending {
                reason: "exact_path_identity_incomplete",
            };
        };
        let Some(entry) = self.dplpmtud.direct_business_budget_entry(peer_id) else {
            return DirectBusinessBudgetGate::ManagedPending {
                reason: "budget_not_published",
            };
        };
        if !entry.enforced {
            return DirectBusinessBudgetGate::Unmanaged;
        }
        if entry.update.path_identity != path_identity {
            return DirectBusinessBudgetGate::ManagedPending {
                reason: "budget_path_identity_stale",
            };
        }
        let Some(publication) = entry.update.budget else {
            return DirectBusinessBudgetGate::ManagedPending {
                reason: "confirmed_budget_withheld",
            };
        };
        let publication_owner = self.inbound_publication_owner();
        if publication_owner == 0 {
            return DirectBusinessBudgetGate::ManagedPending {
                reason: "udp_publication_withdrawn",
            };
        }
        let token = crate::dplpmtud::DirectBusinessSendToken {
            path_identity,
            budget_revision: publication.budget_revision,
            max_udp_datagram_size: publication.udp_datagram_size,
            max_overlay_payload_size: publication.overlay_payload_budget,
            udp_publication_owner: publication_owner,
        };
        DirectBusinessBudgetGate::Ready(Box::new(PreparedDirectBusinessSend {
            token,
            socket,
            endpoint: remote_endpoint,
            socket_index,
            _lease: lease,
        }))
    }

    /// Final exact Direct UDP handoff. The caller owns `network_epoch_gate`;
    /// the runtime gate below orders budget/owner revocation against this one
    /// synchronous nonblocking syscall.
    pub(crate) fn try_send_direct_business_packet(
        &self,
        prepared: &PreparedDirectBusinessSend,
        packet: &EncryptedPeerPacket,
    ) -> std::result::Result<usize, DirectBusinessUdpSendError> {
        if packet.wire_bytes.len() > prepared.token.max_udp_datagram_size.0 as usize {
            return Err(DirectBusinessUdpSendError::CiphertextTooLarge);
        }
        let attempted = self
            .dplpmtud
            .with_current_direct_business_token(&prepared.token, || {
                if packet
                    .room_authorization
                    .as_ref()
                    .is_some_and(|permit| !permit.is_valid())
                {
                    return Err(DirectBusinessUdpSendError::Io(
                        "room send authorization expired or revoked".into(),
                    ));
                }
                if self.inbound_publication_owner() != prepared.token.udp_publication_owner
                    || self.transport_instance_id
                        != prepared.token.path_identity.socket.transport_instance_id
                    || prepared.socket.local_addr().ok()
                        != Some(prepared.token.path_identity.local_endpoint)
                {
                    return Err(DirectBusinessUdpSendError::StaleToken);
                }
                #[cfg(test)]
                if self
                    .direct_business_emsgsize_once
                    .swap(false, Ordering::AcqRel)
                {
                    return Err(DirectBusinessUdpSendError::LocalPacketTooLarge);
                }
                #[cfg(test)]
                if self.injected_direct_business_would_block_for_test(
                    &prepared.token.path_identity.peer_id,
                ) {
                    return Err(DirectBusinessUdpSendError::WouldBlock);
                }
                prepared
                    .socket
                    .try_send_to(&packet.wire_bytes, prepared.endpoint)
                    .map_err(|error| {
                        if is_local_packet_too_large(&error) {
                            DirectBusinessUdpSendError::LocalPacketTooLarge
                        } else if error.kind() == std::io::ErrorKind::WouldBlock {
                            DirectBusinessUdpSendError::WouldBlock
                        } else {
                            DirectBusinessUdpSendError::Io(error.to_string())
                        }
                    })
            });
        let sent = attempted.ok_or(DirectBusinessUdpSendError::StaleToken)??;
        if sent != packet.wire_bytes.len() {
            return Err(DirectBusinessUdpSendError::Short {
                sent,
                expected: packet.wire_bytes.len(),
            });
        }
        self.update_socket_diagnostics_try(prepared.socket_index, |metrics| {
            metrics.encrypted_packets_sent += 1;
        });
        Ok(sent)
    }

    pub(crate) fn invalidate_direct_business_budget(
        &self,
        token: &crate::dplpmtud::DirectBusinessSendToken,
    ) -> bool {
        self.dplpmtud
            .invalidate_direct_business_budget(token, tokio::time::Instant::now())
    }

    #[cfg(test)]
    pub(crate) fn set_direct_business_send_gate_for_test(&self, gate: Arc<DirectBusinessSendGate>) {
        *self
            .direct_business_send_gate
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = Some(gate);
    }

    #[cfg(test)]
    pub(crate) async fn wait_at_direct_business_send_gate_for_test(&self) {
        let gate = self
            .direct_business_send_gate
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .take();
        if let Some(gate) = gate {
            gate.reached.wait().await;
            gate.release.wait().await;
        }
    }

    #[cfg(test)]
    pub(crate) fn inject_direct_business_emsgsize_once_for_test(&self) {
        self.direct_business_emsgsize_once
            .store(true, Ordering::Release);
    }

    /// Inject exactly `attempts` local-backpressure results for one peer and
    /// return an observable attempt counter. The peer key is part of the exact
    /// immutable send token, so a blocked Peer A cannot affect Peer B.
    #[cfg(test)]
    pub(crate) fn inject_direct_business_would_block_for_test(
        &self,
        peer_id: &str,
        attempts: usize,
    ) -> watch::Receiver<usize> {
        assert!(attempts > 0, "WouldBlock injection must contain an attempt");
        let (attempts_tx, attempts_rx) = watch::channel(0usize);
        self.direct_business_would_block
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .insert(
                peer_id.to_string(),
                DirectBusinessWouldBlockInjection {
                    remaining: attempts,
                    attempts_tx,
                },
            );
        attempts_rx
    }

    #[cfg(test)]
    pub(super) fn injected_direct_business_would_block_for_test(&self, peer_id: &str) -> bool {
        let mut injections = self
            .direct_business_would_block
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let Some(injection) = injections.get_mut(peer_id) else {
            return false;
        };
        if injection.remaining == 0 {
            return false;
        }
        injection.remaining = injection.remaining.saturating_sub(1);
        injection
            .attempts_tx
            .send_modify(|attempts| *attempts = attempts.saturating_add(1));
        true
    }

    /// Reconcile DPLPMTUD only from the authoritative committed-path mirror.
    /// This never selects a path; it starts or cancels a worker for the exact
    /// Direct state which the Path State Machine already committed.
    pub(crate) async fn reconcile_dplpmtud_paths(&self) {
        let now = tokio::time::Instant::now();
        let snapshots = self.peers.committed_business_path_snapshots_sync();
        let known_peers = snapshots
            .iter()
            .map(|snapshot| snapshot.peer_id.clone())
            .collect::<HashSet<_>>();
        self.dplpmtud.retain_known_peers(&known_peers, now);

        let Some(local_virtual_ip) = self.dplpmtud_local_virtual_ip else {
            return;
        };

        for snapshot in snapshots {
            let validation = match snapshot.active {
                ActiveBusinessPath::Direct(validation)
                    if snapshot.lifecycle == PeerPathLifecycle::Online =>
                {
                    validation
                }
                _ => {
                    self.dplpmtud
                        .cancel_peer(&snapshot.peer_id, "active_path_not_direct", now);
                    continue;
                }
            };
            let Some(epoch) = snapshot.epoch else {
                self.dplpmtud
                    .cancel_peer(&snapshot.peer_id, "path_identity_unbound", now);
                continue;
            };
            if validation.epoch != epoch {
                self.dplpmtud
                    .cancel_peer(&snapshot.peer_id, "path_epoch_mismatch", now);
                continue;
            }
            let Some(remote_endpoint) = validation.commit_endpoint() else {
                self.dplpmtud.cancel_peer(
                    &snapshot.peer_id,
                    "direct_validation_not_authenticated",
                    now,
                );
                continue;
            };
            let Some(pair) = self
                .peers
                .direct_commit_pair_snapshot_sync(&snapshot.peer_id)
            else {
                self.dplpmtud
                    .cancel_peer(&snapshot.peer_id, "direct_pair_missing", now);
                continue;
            };
            let Some(local_endpoint) = pair.local_endpoint else {
                self.dplpmtud
                    .cancel_peer(&snapshot.peer_id, "local_endpoint_missing", now);
                continue;
            };
            if pair.generation != epoch.network_generation
                || pair.remote_candidate_epoch != epoch.remote_candidate_epoch
            {
                self.dplpmtud
                    .cancel_peer(&snapshot.peer_id, "direct_pair_stale", now);
                continue;
            }
            let Some((socket_index, socket)) = self.socket_for_peer(Some(&snapshot.peer_id)).await
            else {
                self.dplpmtud
                    .cancel_peer(&snapshot.peer_id, "local_socket_missing", now);
                continue;
            };
            if socket.local_addr().ok() != Some(local_endpoint) {
                self.dplpmtud
                    .cancel_peer(&snapshot.peer_id, "local_socket_changed", now);
                continue;
            }
            let Some(identity) = crate::dplpmtud::DplpmtudPathIdentity::from_committed_validation(
                snapshot.peer_id.clone(),
                validation,
                remote_endpoint,
                local_endpoint,
                self.transport_instance_id,
                socket_index,
            ) else {
                self.dplpmtud.cancel_peer(
                    &snapshot.peer_id,
                    "direct_validation_identity_incomplete",
                    now,
                );
                continue;
            };
            let previous_identity = self.dplpmtud.path_identity(&snapshot.peer_id);
            let previous_snapshot = self.dplpmtud.snapshot_for_peer(&snapshot.peer_id);
            if previous_identity
                .as_ref()
                .is_some_and(|previous| previous != &identity)
            {
                self.peers.emit_timeline(
                    "dplpmtud_reset",
                    Some("direct"),
                    Some("path_identity_changed"),
                    Some(format!(
                        "peer={} previous_identity={:?} next_identity={:?}",
                        snapshot.peer_id, previous_identity, identity,
                    )),
                );
            }
            // Capability belongs to the peer session, not to one UDP
            // transport instance. A replacement transport starts with an
            // empty DPLPMTUD runtime, so its first reconcile must seed that
            // runtime from the immutable session-scoped manager mirror. If it
            // consulted only the new runtime here, a negotiated peer could
            // transiently become `Unmanaged` and bypass BASE confirmation.
            let protocol_supported = self
                .peers
                .peer_supports_dplpmtud_sync(&snapshot.peer_id, epoch.peer_session_generation);
            if protocol_supported {
                let _ = self
                    .dplpmtud
                    .mark_supported(&snapshot.peer_id, epoch.peer_session_generation.value());
            }
            let no_fragment_supported =
                p2pnet_netbind::udp_no_fragment_supported(&socket, remote_endpoint.ip());
            let supported = protocol_supported && no_fragment_supported;
            let unsupported_reason = if !protocol_supported {
                "capability_not_negotiated"
            } else {
                "no_fragment_probe_unsupported"
            };
            let identity_summary = identity.summary();
            let install = self.dplpmtud.install_path_with_reason(
                identity,
                supported,
                unsupported_reason,
                now,
            );
            if !supported
                && install.decision == crate::dplpmtud::DplpmtudInstallDecision::Unsupported
                && !previous_snapshot.is_some_and(|previous| {
                    previous.state == crate::dplpmtud::DplpmtudState::Unsupported
                        && previous.path_identity.as_ref() == Some(&identity_summary)
                })
            {
                self.peers.emit_timeline(
                    "dplpmtud_unsupported",
                    Some("direct"),
                    Some(unsupported_reason),
                    Some(format!(
                        "peer={} path_identity={:?} protocol_supported={} no_fragment_supported={} confirmed_udp_datagram_size=none search_upper_udp_datagram_size={}",
                        snapshot.peer_id,
                        identity_summary,
                        protocol_supported,
                        no_fragment_supported,
                        identity_summary
                            .outer_ip_family
                            .ceiling_udp_datagram_size()
                            .0,
                    )),
                );
            }
            if install.decision != crate::dplpmtud::DplpmtudInstallDecision::Spawned {
                debug!(
                    peer_id = %snapshot.peer_id,
                    decision = ?install.decision,
                    supported,
                    "DPLPMTUD path reconciliation did not spawn a worker"
                );
                continue;
            }
            let Some(lease) = install.worker else {
                continue;
            };
            let Ok(peer_virtual_ip) = snapshot.virtual_ip.parse::<Ipv4Addr>() else {
                self.dplpmtud
                    .cancel_peer(&snapshot.peer_id, "peer_virtual_ip_not_ipv4", now);
                continue;
            };
            if !self
                .dplpmtud_worker_ingress
                .submit(crate::dplpmtud::DplpmtudWorkerStart {
                    lease,
                    socket,
                    local_virtual_ip,
                    peer_virtual_ip,
                })
            {
                self.dplpmtud.cancel_peer(
                    &snapshot.peer_id,
                    "worker_ingress_capacity_exceeded",
                    now,
                );
            }
        }
    }
}
