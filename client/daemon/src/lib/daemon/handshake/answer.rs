impl Daemon {
    async fn handle_peer_answer(
        &self,
        from_node_id: &str,
        handshake_response: &[u8],
        session_id: Option<String>,
        probe_ephemeral_public_key: Option<String>,
    ) -> Result<()> {
        let lock_wait_started = Instant::now();
        let ingress_generation = self.peers.current_network_generation_sync();
        self.timeline.emit(
            "peer_answer_received",
            None,
            None,
            Some(format!(
                "peer={from_node_id} generation={ingress_generation} response_bytes={} session_fp={}",
                handshake_response.len(),
                handshake_token_fingerprint(session_id.as_deref())
            )),
        );
        self.timeline.emit(
            "initiator_answer_lock_wait",
            None,
            None,
            Some(format!(
                "peer={from_node_id} generation={ingress_generation} session_fp={}",
                handshake_token_fingerprint(session_id.as_deref())
            )),
        );
        let _handshake_guard = self.handshake_arbiter.acquire(from_node_id).await;
        self.timeline.emit(
            "initiator_answer_lock_acquired",
            None,
            None,
            Some(format!(
                "peer={from_node_id} generation={} wait_ms={} session_fp={}",
                self.peers.current_network_generation_sync(),
                lock_wait_started.elapsed().as_millis(),
                handshake_token_fingerprint(session_id.as_deref())
            )),
        );
        let response = MessageResponse::from_bytes(handshake_response)
            .map_err(|e| DaemonError::Peer(format!("invalid WireGuard response: {e}")))?;
        // The pending initiator and its answer must cross the local network
        // generation boundary as one short transaction.  Acquire the emit
        // guard first: the outbound actor uses `emit -> generation`, and
        // taking this in the opposite order can deadlock an answer behind a
        // live TUN packet.
        self.timeline.emit(
            "peer_answer_emit_lock_wait",
            None,
            None,
            Some(format!(
                "peer={from_node_id} generation={} session_fp={}",
                self.peers.current_network_generation_sync(),
                handshake_token_fingerprint(session_id.as_deref())
            )),
        );
        let emit_guard = self.transport.acquire_outbound_emit_guard(from_node_id).await;
        self.timeline.emit(
            "peer_answer_emit_lock_acquired",
            None,
            None,
            Some(format!(
                "peer={from_node_id} generation={} session_fp={}",
                self.peers.current_network_generation_sync(),
                handshake_token_fingerprint(session_id.as_deref())
            )),
        );
        let epoch_gate = self.peers.network_epoch_gate();
        let epoch_guard = epoch_gate.lock().await;
        let current_generation = self.peers.current_network_generation_sync();
        let (keys, expected_session_id, probe_ephemeral_shared) = {
            let mut state = self.pending_handshakes.lock().await;
            let expected_session_id = state.session_id(from_node_id).map(str::to_string);
            let expected_generation = state
                .network_generation(from_node_id)
                .unwrap_or(current_generation);
            if expected_generation != current_generation {
                warn!(
                    "Ignoring WireGuard answer from {from_node_id}: pending handshake belongs to generation {expected_generation}, current generation is {current_generation}"
                );
                self.timeline.emit(
                    "peer_answer_rejected",
                    None,
                    Some("stale_network_generation"),
                    Some(format!(
                        "peer={from_node_id} answer_generation={expected_generation} current_generation={current_generation}"
                    )),
                );
                return Ok(());
            }
            if expected_session_id.as_deref() != session_id.as_deref() {
                warn!(
                    "Ignoring WireGuard answer from {from_node_id} with missing or mismatched session_id"
                );
                self.timeline.emit(
                    "peer_answer_rejected",
                    None,
                    Some("session_id_mismatch"),
                    Some(format!(
                        "peer={from_node_id} generation={current_generation} expected_session_fp={} received_session_fp={}",
                        handshake_token_fingerprint(expected_session_id.as_deref()),
                        handshake_token_fingerprint(session_id.as_deref())
                    )),
                );
                return Ok(());
            }

            // A modern initiator generated its Probe ephemeral key together
            // with this exact WireGuard initiation. Validate the matching
            // answer key before consuming the one-shot Noise initiator. A
            // missing or malformed key is an incomplete answer, not a reason
            // to destroy the pending retry or replace the still-usable active
            // session.
            let probe_ephemeral_shared = match state.probe_ephemeral(from_node_id) {
                Some(local_probe_ephemeral) => {
                    let Some(peer_probe_public_key) = probe_ephemeral_public_key
                        .as_deref()
                        .map(str::trim)
                        .filter(|key| !key.is_empty())
                    else {
                        warn!(
                            "Ignoring WireGuard answer from {from_node_id} without the required probe ephemeral public key"
                        );
                        return Ok(());
                    };
                    match derive_probe_ephemeral_shared(
                        &local_probe_ephemeral,
                        peer_probe_public_key,
                    ) {
                        Ok(shared) => Some(shared),
                        Err(err) => {
                            warn!(
                                "Ignoring malformed probe ephemeral public key from {from_node_id}: {err}"
                            );
                            return Ok(());
                        }
                    }
                }
                None => None,
            };

            let Some(initiator) = state.pending.get_mut(from_node_id) else {
                warn!("No pending WireGuard handshake for answer from {from_node_id}");
                return Ok(());
            };

            let keys = match initiator.consume_response(&response) {
                Ok(keys) => keys,
                Err(err) => {
                    warn!(
                        "Ignoring WireGuard answer from {from_node_id} that does not match the pending handshake: {err}"
                    );
                    return Ok(());
                }
            };

            state.remove(from_node_id);
            state.attempts.remove(from_node_id);
            (keys, expected_session_id, probe_ephemeral_shared)
        };

        // Replace the outbound key while retaining the old receive key for a
        // short overlap. The answer and in-flight UDP packets can be reordered.
        let new_session = TransportSession::new(keys);
        let transport_token = expected_session_id.clone().or_else(|| session_id.clone());
        let replaced_existing_session = self
            .transport
            .install_active_session_locked(from_node_id, transport_token, new_session)
            .await;
        if let Some(received_session_id) = session_id.clone() {
            let binding_token = expected_session_id
                .clone()
                .unwrap_or_else(|| received_session_id.clone());
            self.peers
                .install_probe_session_binding(
                    from_node_id,
                    binding_token,
                    Some(received_session_id),
                    probe_ephemeral_shared,
                )
                .await;
        }
        drop(epoch_guard);
        drop(emit_guard);
        // Match the public install wrapper: session-ready backlog is flushed
        // only after the emit/generation transaction is fully released.
        self.transport
            .flush_pending_outbound_for_peer(from_node_id)
            .await;

        let current_state = self
            .peers
            .get_connection(from_node_id)
            .await
            .map(|connection| connection.state);
        if should_mark_connecting_after_session_install(
            replaced_existing_session,
            current_state,
        ) {
            self.peers
                .update_state(from_node_id, ConnectionState::Connecting)
                .await;
        }
        info!(
            "Installed WireGuard initiator session for {from_node_id} (rekey={replaced_existing_session})"
        );
        if replaced_existing_session || session_id.is_some() {
            self.start_rekey_confirmation(from_node_id).await;
        }
        self.peers
            .record_direct_event(
                from_node_id,
                "peer_answer_applied",
                None,
                None,
                None,
                format!(
                    "installed initiator session from {} response bytes",
                    handshake_response.len()
                ),
            )
            .await;
        Ok(())
    }

    async fn start_rekey_confirmation(&self, peer_id: &str) {
        let transport = self.transport.clone();
        let peers = self.peers.clone();
        let udp_transport = self.udp_transport.clone();
        let relay_transport = self.relay_transport.clone();
        let local_ip = self.config.network.virtual_ip.parse::<Ipv4Addr>().ok();
        let peer_id = peer_id.to_string();

        tokio::spawn(async move {
            let confirmation_id = unix_time_millis() as u16;
            let mut wireguard_sent = 0u32;
            let mut last_direct_endpoint = None;
            for (sequence, delay) in REKEY_CONFIRMATION_DELAYS.into_iter().enumerate() {
                if !delay.is_zero() {
                    sleep(delay).await;
                }

                // UDP, Relay, and the learned peer-reflexive endpoint can all
                // become ready after the answer is installed. Resolve them on
                // every attempt instead of freezing a short startup snapshot.
                let Some(connection) = peers.get_connection(&peer_id).await else {
                    break;
                };
                let Some(local_ip) = local_ip else {
                    continue;
                };
                let Ok(peer_ip) = connection.virtual_ip.parse::<Ipv4Addr>() else {
                    continue;
                };
                let peer_virtual_ip = connection.virtual_ip;
                let direct_endpoint = connection.endpoint;
                if direct_endpoint.is_some() {
                    last_direct_endpoint = direct_endpoint;
                }
                let udp = udp_transport.read().await.clone();
                let relay = relay_transport.read().await.clone();

                let build_packet = || OutboundPacket {
                    peer_id: peer_id.clone(),
                    dst_ip: peer_virtual_ip.clone(),
                    packet: Ipv4Packet::build_icmp_echo_request(
                        local_ip,
                        peer_ip,
                        confirmation_id,
                        sequence as u16,
                        REKEY_CONFIRMATION_PAYLOAD,
                    ),
                };

                if let (Some(udp), Some(endpoint)) = (udp, direct_endpoint) {
                    let direct_result = transport
                        .encrypt_and_emit_outbound(build_packet(), move |encrypted| async move {
                            udp.send_packet_to(&encrypted, endpoint).await.map(|_| ())
                        })
                        .await;
                    match direct_result {
                        Ok(true) => wireguard_sent = wireguard_sent.saturating_add(1),
                        Ok(false) => debug!(
                            "WireGuard rekey confirmation skipped for {peer_id}; active session unavailable"
                        ),
                        Err(error) => debug!(
                            "Failed to send WireGuard rekey confirmation directly to {peer_id} at {endpoint}: {error}"
                        ),
                    }
                }

                if let Some(relay) = relay {
                    let relay_result = transport
                        .encrypt_and_emit_outbound(build_packet(), move |encrypted| async move {
                            timeout(Duration::from_secs(2), relay.send_packet(&encrypted))
                                .await
                                .map_err(|_| {
                                    DaemonError::Relay(
                                        "relay rekey confirmation send timed out".to_string(),
                                    )
                                })?
                        })
                        .await;
                    match relay_result {
                        Ok(true) => wireguard_sent = wireguard_sent.saturating_add(1),
                        Ok(false) => debug!(
                            "WireGuard rekey confirmation skipped for {peer_id}; active session unavailable"
                        ),
                        Err(error) => debug!(
                            "Failed to send WireGuard rekey confirmation through relay to {peer_id}: {error}"
                        ),
                    }
                }
            }
            peers
                .record_direct_event(
                    &peer_id,
                    "rekey_confirmation_sent",
                    last_direct_endpoint,
                    None,
                    Some(wireguard_sent),
                    format!(
                        "sent {wireguard_sent} internal WireGuard confirmation packets; matching Probe v2 binding is promoted by the authenticated session token"
                    ),
                )
                .await;
        });
    }

}
