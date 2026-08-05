impl UdpTransport {
    /// Commit a modern responder handshake transaction from an authenticated
    /// pending Probe-v2 packet. WireGuard is promoted first; Probe is only
    /// promoted for the same exact token after that succeeds.
    async fn confirm_pending_probe_adoption(&self, peer_id: &str, token: &str) -> bool {
        let Some(wireguard) = self.wireguard_transport.as_ref() else {
            return false;
        };
        if !self
            .peers
            .confirm_probe_and_transport_transaction(peer_id, token, || async {
                matches!(
                    wireguard.confirm_responder_session(peer_id, token).await,
                    ResponderSessionConfirmation::Promoted
                        | ResponderSessionConfirmation::AlreadyActive
                )
            })
            .await
        {
            return false;
        }
        wireguard
            .acknowledge_promoted_responder_token(peer_id, token)
            .await;
        true
    }

    /// Receive encrypted UDP datagrams until the socket or channel closes.
    pub async fn run_inbound(
        self,
        inbound_tx: mpsc::Sender<ReceivedEncryptedPacket>,
    ) -> Result<()> {
        let sockets = self.active_sockets().to_vec();
        let mut readers = JoinSet::new();
        for (socket_index, socket) in sockets.into_iter().enumerate() {
            let transport = self.clone();
            let inbound_tx = inbound_tx.clone();
            readers.spawn(async move {
                transport
                    .run_inbound_socket(socket_index, socket, inbound_tx)
                    .await
            });
        }

        match readers.join_next().await {
            Some(Ok(result)) => result,
            Some(Err(error)) => Err(DaemonError::Network(format!(
                "UDP socket reader task failed: {error}"
            ))),
            None => Ok(()),
        }
    }

    async fn run_inbound_socket(
        &self,
        socket_index: usize,
        socket: Arc<UdpSocket>,
        inbound_tx: mpsc::Sender<ReceivedEncryptedPacket>,
    ) -> Result<()> {
        let mut buf = vec![0u8; 65_535];

        loop {
            let (n, source) = match socket.recv_from(&mut buf).await {
                Ok(packet) => packet,
                Err(err) if is_ignorable_udp_receive_error(&err) => {
                    debug!("Ignoring transient UDP receive error on direct transport: {err}");
                    continue;
                }
                Err(err) => {
                    return Err(DaemonError::Network(format!(
                        "UDP receive on direct transport failed: {err}"
                    )));
                }
            };

            if n == 0 {
                continue;
            }

            self.update_socket_diagnostics(socket_index, |metrics| {
                metrics.datagrams_received = metrics.datagrams_received.saturating_add(1)
            })
            .await;

            if self.peers.has_known_public_candidate_ip(source.ip()).await {
                self.update_socket_diagnostics(socket_index, |metrics| {
                    metrics.known_peer_ip_datagrams_received = metrics
                        .known_peer_ip_datagrams_received
                        .saturating_add(1)
                })
                .await;
            }

            let data = &buf[..n];

            if let Some(transaction_id) = stun_transaction_id(data) {
                let waiter = self.stun_waiters.lock().await.remove(&transaction_id);
                if let Some(waiter) = waiter {
                    let _ = waiter.send((data.to_vec(), source));
                } else {
                    trace!("Ignored unmatched STUN response from {source}");
                }
                continue;
            }

            if is_authenticated_punch_candidate(data) {
                self.update_socket_diagnostics(socket_index, |metrics| {
                    metrics.authenticated_probe_packets_received = metrics
                        .authenticated_probe_packets_received
                        .saturating_add(1)
                })
                .await;
                let Some(identity) = peek_authenticated_punch_identity(data) else {
                    self.update_socket_diagnostics(socket_index, |metrics| {
                        metrics.authenticated_probe_malformed =
                            metrics.authenticated_probe_malformed.saturating_add(1)
                    })
                    .await;
                    trace!("Ignored malformed authenticated UDP probe from {source}");
                    continue;
                };
                let Some(local_node_id) = self.local_node_id.as_deref() else {
                    trace!(
                        "Ignored authenticated UDP probe from {source}; local node ID is unknown"
                    );
                    continue;
                };
                if identity.target_node_id != local_node_id {
                    self.update_socket_diagnostics(socket_index, |metrics| {
                        metrics.authenticated_probe_wrong_target =
                            metrics.authenticated_probe_wrong_target.saturating_add(1)
                    })
                    .await;
                    trace!(
                        "Ignored authenticated UDP probe from {} for target {}",
                        identity.source_node_id,
                        identity.target_node_id
                    );
                    continue;
                }
                let key_candidates = self
                    .peers
                    .probe_key_candidates_for_peer(&identity.source_node_id)
                    .await;
                if key_candidates.is_empty() {
                    self.update_socket_diagnostics(socket_index, |metrics| {
                        metrics.authenticated_probe_no_key =
                            metrics.authenticated_probe_no_key.saturating_add(1)
                    })
                    .await;
                    trace!(
                        "Ignored authenticated UDP probe from {}; no Probe v2 MAC key",
                        identity.source_node_id
                    );
                    continue;
                }
                let Some((packet, key_candidate)) = key_candidates.into_iter().find_map(|candidate| {
                    decode_authenticated_punch_packet(data, &candidate.key)
                        .map(|packet| (packet, candidate))
                }) else {
                    self.update_socket_diagnostics(socket_index, |metrics| {
                        metrics.authenticated_probe_invalid_mac =
                            metrics.authenticated_probe_invalid_mac.saturating_add(1)
                    })
                    .await;
                    trace!(
                        "Ignored authenticated UDP probe from {}; invalid MAC",
                        identity.source_node_id
                    );
                    continue;
                };
                let pending_token = match &key_candidate.role {
                    ProbeKeyRole::Pending { token } => Some(token.clone()),
                    _ => None,
                };
                let key = key_candidate.key;

                match packet.kind {
                    PunchPacketKind::Punch => {
                        let punch_generation =
                            packet.generation.unwrap_or(identity.generation);
                        match self
                            .admit_authenticated_punch(
                                &identity.source_node_id,
                                punch_generation,
                                packet.kind,
                                packet.nonce,
                                source,
                            )
                            .await
                        {
                            AuthenticatedPunchAdmission::Accepted => {
                                if let Some(token) = pending_token.as_deref() {
                                    if self
                                        .confirm_pending_probe_adoption(
                                            &identity.source_node_id,
                                            token,
                                        )
                                        .await
                                    {
                                        debug!(
                                            "Promoted matching WireGuard and Probe v2 bindings for peer {} after accepted authenticated punch",
                                            identity.source_node_id
                                        );
                                    } else {
                                        self.rollback_authenticated_punch_replay_admission(
                                            &identity.source_node_id,
                                            punch_generation,
                                            packet.kind,
                                            packet.nonce,
                                        )
                                        .await;
                                        debug!(
                                            "Ignored accepted pending Probe v2 punch from {}; matching WireGuard/Probe transaction is unavailable",
                                            identity.source_node_id
                                        );
                                        continue;
                                    }
                                }
                                self.update_socket_diagnostics(socket_index, |metrics| {
                                    metrics.authenticated_probe_punches_received = metrics
                                        .authenticated_probe_punches_received
                                        .saturating_add(1)
                                })
                                .await;
                            }
                            AuthenticatedPunchAdmission::Replay => {
                                if pending_token.is_some() {
                                    // A replay that still authenticated only
                                    // as Pending means the original Accepted
                                    // packet did not finish the matching WG +
                                    // Probe transaction. ACKing it would let
                                    // the sender infer Direct success even
                                    // though this side deliberately refused
                                    // adoption.
                                    debug!(
                                        "Ignored replayed pending Probe v2 punch from peer {} at {}; transaction is not active",
                                        identity.source_node_id, source
                                    );
                                    continue;
                                }
                                let generation = self.peers.current_network_generation().await;
                                let ack = build_authenticated_punch_ack(
                                    packet.nonce,
                                    local_node_id,
                                    &identity.source_node_id,
                                    generation,
                                    &key,
                                );
                                match socket.send_to(&ack, source).await {
                                    Ok(_) => {
                                        self.update_socket_diagnostics(socket_index, |metrics| {
                                            metrics.probe_acks_sent += 1
                                        })
                                        .await;
                                        trace!(
                                            "ACKed replayed authenticated UDP punch from peer {} at {} without mutating candidate state",
                                            identity.source_node_id, source
                                        );
                                    }
                                    Err(err) => debug!(
                                        "Failed to ACK replayed authenticated UDP punch from peer {} at {}: {}",
                                        identity.source_node_id, source, err
                                    ),
                                }
                                continue;
                            }
                            AuthenticatedPunchAdmission::RateLimited => {
                                debug!(
                                    "Rate-limited authenticated UDP punch from peer {} at {}",
                                    identity.source_node_id, source
                                );
                                continue;
                            }
                        }

                        // Reply on the receiving socket before doing any peer
                        // learning or candidate bookkeeping. NAT filters keep
                        // the return window short, and the sender's nonce is
                        // only pending for this punch session.
                        let generation = self.peers.current_network_generation().await;
                        let ack = build_authenticated_punch_ack(
                            packet.nonce,
                            local_node_id,
                            &identity.source_node_id,
                            generation,
                            &key,
                        );
                        let ack_sent = match self
                            .send_punch_ack_burst(
                                socket_index,
                                socket.clone(),
                                ack,
                                source,
                                identity.source_node_id.clone(),
                            )
                            .await
                        {
                            Ok(()) => true,
                            Err(err) => {
                                warn!(
                                    "Failed to immediately ACK authenticated UDP punch from peer {} at {}: {}",
                                    identity.source_node_id, source, err
                                );
                                false
                            }
                        };

                        let learned = self
                            .peers
                            .learn_authenticated_endpoint(&identity.source_node_id, source)
                            .await;
                        if !learned {
                            trace!(
                                "Ignored authenticated UDP punch from {}; peer disappeared before endpoint learning",
                                identity.source_node_id
                            );
                            continue;
                        }
                        self.peers
                            .record_direct_probe_success_with_local_endpoint(
                                &identity.source_node_id,
                                source,
                                socket.local_addr().ok(),
                            )
                            .await;
                        if packet.use_candidate {
                            self.peers
                                .record_direct_nomination_check_with_local_endpoint(
                                    &identity.source_node_id,
                                    source,
                                    socket.local_addr().ok(),
                                )
                                .await;
                        }
                        self.remember_peer_socket(&identity.source_node_id, socket_index)
                            .await;
                        self.notify_peer_reflexive_observation(&identity.source_node_id, source)
                            .await;

                        if ack_sent {
                            debug!(
                                "Received authenticated UDP punch from peer {} at {}; sent immediate ACK burst",
                                identity.source_node_id, source
                            );
                            self.trigger_peer_reflexive_check(
                                socket_index,
                                &identity.source_node_id,
                                source,
                            )
                            .await;
                        } else {
                            debug!(
                                "Received authenticated UDP punch from peer {} at {} without an ACK",
                                identity.source_node_id, source
                            );
                        }
                    }
                    PunchPacketKind::Ack => {
                        self.update_socket_diagnostics(socket_index, |metrics| {
                            metrics.authenticated_probe_acks_observed = metrics
                                .authenticated_probe_acks_observed
                                .saturating_add(1)
                        })
                        .await;
                        let ack_match = {
                            let generation = self.peers.current_network_generation().await;
                            let mut pending_probes = self.pending_probes.lock().await;
                            let matched = pending_probes
                                .get(&packet.nonce)
                                .filter(|pending| {
                                    pending.generation == generation
                                        && pending.socket_index == socket_index
                                        && pending.peer_id.as_deref()
                                            == Some(identity.source_node_id.as_str())
                                        && pending.accepts_authenticated_ack
                                })
                                .cloned();
                            if matched.is_some() {
                                pending_probes.remove(&packet.nonce);
                            }
                            matched
                        };

                        if let Some(pending) = ack_match {
                            if let Some(token) = pending_token.as_deref() {
                                if self
                                    .confirm_pending_probe_adoption(
                                        &identity.source_node_id,
                                        token,
                                    )
                                    .await
                                {
                                    debug!(
                                        "Promoted matching WireGuard and Probe v2 bindings for peer {} after matched authenticated ACK",
                                        identity.source_node_id
                                    );
                                } else {
                                    debug!(
                                        "Ignored matched pending Probe v2 ACK from {}; matching WireGuard/Probe transaction is unavailable",
                                        identity.source_node_id
                                    );
                                    self.pending_probes
                                        .lock()
                                        .await
                                        .entry(packet.nonce)
                                        .or_insert(pending);
                                    continue;
                                }
                            }
                            let latency = pending.sent_at.elapsed();
                            let generation = pending.generation;
                            let local_endpoint = pending.local_endpoint;
                            let purpose = pending.purpose;
                            self.update_socket_diagnostics(socket_index, |metrics| {
                                metrics.probe_acks_received += 1
                            })
                            .await;
                            self.remember_peer_socket(&identity.source_node_id, socket_index)
                                .await;
                            self.peers
                                .learn_authenticated_endpoint(&identity.source_node_id, source)
                                .await;
                            self.notify_peer_reflexive_observation(
                                &identity.source_node_id,
                                source,
                            )
                            .await;
                            let accepted = self
                                .peers
                                .record_direct_probe_success_with_latency_for_generation_and_local_endpoint(
                                    &identity.source_node_id,
                                    source,
                                    Some(latency),
                                    generation,
                                    local_endpoint,
                                )
                                .await;
                            if accepted {
                                if purpose == PendingProbePurpose::ConsentCheck {
                                    self.peers
                                        .record_direct_event(
                                            &identity.source_node_id,
                                            "consent_ack_received",
                                            Some(source),
                                            Some(1),
                                            None,
                                            format!(
                                                "received direct UDP consent ACK from {source} rtt={}ms local_endpoint={}",
                                                latency.as_millis(),
                                                format_optional_endpoint(local_endpoint)
                                            ),
                                        )
                                        .await;
                                }
                                debug!(
                                    "Received authenticated UDP punch ACK from peer {} at {} (rtt={latency:?})",
                                    identity.source_node_id, source
                                );
                            } else {
                                trace!(
                                    "Ignored stale authenticated UDP punch ACK from peer {} at {}",
                                    identity.source_node_id,
                                    source
                                );
                            }
                        } else {
                            self.update_socket_diagnostics(socket_index, |metrics| {
                                metrics.authenticated_probe_acks_unmatched = metrics
                                    .authenticated_probe_acks_unmatched
                                    .saturating_add(1)
                            })
                            .await;
                            trace!(
                                "Ignored unmatched authenticated UDP punch ACK from peer {} at {}",
                                identity.source_node_id,
                                source
                            );
                        }
                    }
                }
                continue;
            }

            if let Some(packet) = decode_punch_packet(data) {
                match packet.kind {
                    PunchPacketKind::Punch => {
                        let ack = build_punch_ack(packet.nonce).to_vec();
                        match self
                            .send_punch_ack_burst(
                                socket_index,
                                socket.clone(),
                                ack,
                                source,
                                source.to_string(),
                            )
                            .await
                        {
                            Ok(()) => {
                                debug!("Received UDP punch from {source}; sent ACK burst");
                                if let Some(peer_id) =
                                    self.peers.learn_endpoint_from_addr(source).await
                                {
                                    self.peers
                                        .record_direct_probe_success_with_local_endpoint(
                                            &peer_id,
                                            source,
                                            socket.local_addr().ok(),
                                        )
                                        .await;
                                    self.remember_peer_socket(&peer_id, socket_index).await;
                                    self.notify_peer_reflexive_observation(&peer_id, source)
                                        .await;
                                    self.trigger_peer_reflexive_check(
                                        socket_index,
                                        &peer_id,
                                        source,
                                    )
                                    .await;
                                    debug!(
                                        "Recorded direct UDP probe success from peer {peer_id} at {source}"
                                    );
                                }
                            }
                            Err(err) => warn!("Failed to ACK UDP punch from {source}: {err}"),
                        }
                    }
                    PunchPacketKind::Ack => {
                        self.update_socket_diagnostics(socket_index, |metrics| {
                            metrics.legacy_probe_acks_observed = metrics
                                .legacy_probe_acks_observed
                                .saturating_add(1)
                        })
                        .await;
                        let ack_match = {
                            let generation = self.peers.current_network_generation().await;
                            let mut pending_probes = self.pending_probes.lock().await;
                            let matched = pending_probes
                                .get(&packet.nonce)
                                .filter(|pending| {
                                    legacy_ack_matches_pending(
                                        pending,
                                        source,
                                        generation,
                                        socket_index,
                                    )
                                })
                                .map(|pending| {
                                    (
                                        pending.sent_at.elapsed(),
                                        pending.generation,
                                        pending.peer_id.clone(),
                                        pending.local_endpoint,
                                        pending.purpose,
                                    )
                                });
                            if matched.is_some() {
                                pending_probes.remove(&packet.nonce);
                            }
                            matched
                        };
                        let ack_matched = ack_match.is_some();
                        let pending_peer_id = ack_match
                            .as_ref()
                            .and_then(|(_, _, peer_id, _, _)| peer_id.clone());
                        let peer_id = match pending_peer_id.as_ref() {
                            Some(peer_id) => {
                                self.peers
                                    .learn_correlated_probe_endpoint(peer_id, source)
                                    .await;
                                Some(peer_id.clone())
                            }
                            None => self.peers.learn_endpoint_from_addr(source).await,
                        };
                        if let Some(peer_id) = peer_id {
                            if let Some((latency, generation, _, local_endpoint, purpose)) =
                                ack_match
                            {
                                self.update_socket_diagnostics(socket_index, |metrics| {
                                    metrics.probe_acks_received += 1
                                })
                                .await;
                                self.remember_peer_socket(&peer_id, socket_index).await;
                                self.notify_peer_reflexive_observation(&peer_id, source)
                                    .await;
                                let accepted = self
                                    .peers
                                    .record_direct_probe_success_with_latency_for_generation_and_local_endpoint(
                                        &peer_id,
                                        source,
                                        Some(latency),
                                        generation,
                                        local_endpoint,
                                    )
                                    .await;
                                if accepted {
                                    if purpose == PendingProbePurpose::ConsentCheck {
                                        self.peers
                                            .record_direct_event(
                                                &peer_id,
                                                "consent_ack_received",
                                                Some(source),
                                                Some(1),
                                                None,
                                                format!(
                                                    "received direct UDP consent ACK from {source} rtt={}ms local_endpoint={}",
                                                    latency.as_millis(),
                                                    format_optional_endpoint(local_endpoint)
                                                ),
                                            )
                                            .await;
                                    }
                                    debug!(
                                        "Received UDP punch ACK from peer {peer_id} at {source} (rtt={latency:?})"
                                    );
                                } else {
                                    trace!(
                                        "Ignored stale UDP punch ACK from peer {peer_id} at {source}"
                                    );
                                }
                            } else {
                                self.update_socket_diagnostics(socket_index, |metrics| {
                                    metrics.legacy_probe_acks_unmatched = metrics
                                        .legacy_probe_acks_unmatched
                                        .saturating_add(1)
                                })
                                .await;
                                trace!("Ignored stale or unmatched UDP punch ACK from {source}");
                            }
                        } else {
                            if !ack_matched {
                                self.update_socket_diagnostics(socket_index, |metrics| {
                                    metrics.legacy_probe_acks_unmatched = metrics
                                        .legacy_probe_acks_unmatched
                                        .saturating_add(1)
                                })
                                .await;
                            }
                            trace!("Received UDP punch ACK from unknown candidate {source}");
                        }
                    }
                }
                continue;
            }

            if let Some(peer_id) = self.peers.learn_endpoint_from_addr(source).await {
                self.remember_peer_socket(&peer_id, socket_index).await;
                trace!("Learned encrypted UDP source {source} for peer {peer_id}");
            }

            self.update_socket_diagnostics(socket_index, |metrics| {
                metrics.encrypted_packets_received += 1
            })
            .await;

            inbound_tx
                .send(ReceivedEncryptedPacket {
                    source: Some(source),
                    local_endpoint: socket.local_addr().ok(),
                    relay_endpoint: None,
                    relay_peer_id: None,
                    wire_bytes: data.to_vec(),
                })
                .await
                .map_err(|_| {
                    DaemonError::Network("received encrypted packet channel closed".to_string())
                })?;

            debug!("Received {n} encrypted UDP bytes from {source}");
        }
    }
}
