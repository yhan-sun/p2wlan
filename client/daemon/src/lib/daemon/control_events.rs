fn peer_offer_updates_probe_session(
    handshake_init: &[u8],
    session_id: Option<&str>,
) -> bool {
    !handshake_init.is_empty() || session_id.is_some()
}

impl Daemon {
    async fn run_control_event_loop(
        &mut self,
        relay_started: &mut bool,
        network_inbound_tx: mpsc::Sender<ReceivedEncryptedPacket>,
    ) {
        // Process control events until shutdown is requested.
        let mut shutdown_rx = self.shutdown_rx.clone();
        let mut task_shutdown_rx = self.task_manager.shutdown_rx();
        loop {
            tokio::select! {
                _ = shutdown_rx.changed() => {
                    if *shutdown_rx.borrow() {
                        info!("Shutdown signal received in main event loop");
                        break;
                    }
                }
                _ = task_shutdown_rx.changed() => {
                    if *task_shutdown_rx.borrow() {
                        warn!("Task manager requested daemon shutdown");
                        break;
                    }
                }
                event = self.control_rx.recv() => {
                    let Some(event) = event else {
                        warn!("Control event channel closed");
                        break;
                    };
                    match event {
                ControlEvent::Registered {
                    node_id,
                    virtual_ip: _,
                    cidr: _,
                    relay_servers,
                    relay_catalog,
                } => {
                    self.health.mark_control_success().await;
                    if !*relay_started {
                        let relay_node_id =
                            node_id.unwrap_or_else(|| self.config.node.node_id.clone());
                        let relay_servers = if relay_servers.is_empty() {
                            self.config.relay.servers.clone()
                        } else {
                            relay_servers
                        };
                        let relay_candidates =
                            relay_candidates_from_sources(&relay_catalog, &relay_servers);
                        if relay_candidates.is_empty() {
                            debug!("No relay servers advertised by control plane");
                            continue;
                        }
                        *relay_started = true;
                        let allow_insecure_plaintext = effective_relay_allow_insecure_plaintext(
                            &self.config.control.server_url,
                            &relay_catalog,
                            &relay_servers,
                            self.config.relay.allow_insecure_plaintext,
                        );
                        if allow_insecure_plaintext
                            && !self.config.relay.allow_insecure_plaintext
                        {
                            info!(
                                "Allowing plaintext relay because HTTP control plane supplied legacy relay candidates"
                            );
                        }
        spawn_relay_inbound(RelayInboundSpawnContext {
            task_manager: self.task_manager.clone(),
            relay_candidates,
            preferred_regions: self.config.relay.preferred_regions.clone(),
            selection_timeout: Duration::from_millis(
        self.config.relay.selection_timeout_ms.max(1),
            ),
            node_id: relay_node_id,
            peers: self.peers.clone(),
            relay_transport: self.relay_transport.clone(),
            relay_selection: self.relay_selection.clone(),
            inbound_tx: network_inbound_tx.clone(),
            control: self.control.clone(),
            allow_insecure_plaintext,
            ca_cert_path: self.config.relay.ca_cert_path.clone(),
        })
        .await;
                    }
                }

                ControlEvent::PeerJoined(peer_info) => {
                    info!(
                        "Peer joined: {} ({})",
                        peer_info.node_id, peer_info.virtual_ip
                    );
                    self.peers.add_peer(&peer_info).await;

                    if peer_info.online {
                        let mut sent_handshake_offer = false;
                        match self.maybe_initiate_handshake(&peer_info).await {
                            Ok(punch_at_ms) => {
                                sent_handshake_offer = punch_at_ms.is_some();
                                self.start_hole_punch_at(&peer_info.node_id, punch_at_ms).await;
                            }
                            Err(err) => {
                                warn!(
                                    "Failed to initiate WireGuard handshake with {}: {err}",
                                    peer_info.node_id
                                );
                                self.start_hole_punch(&peer_info.node_id).await;
                            }
                        }
                        if !sent_handshake_offer {
                            self.publish_current_candidates_to_peer(
                                &peer_info.node_id,
                                "peer joined",
                            )
                            .await;
                        }

                        if self.dns.is_enabled() {
                            self.dns
                                .register(
                                    &peer_info.node_id,
                                    &peer_info.virtual_ip,
                                    Some(&peer_info.node_id),
                                )
                                .await;
                        }
                    } else {
                        debug!(
                            "Peer {} is currently offline; keeping it in diagnostics without starting traversal",
                            peer_info.node_id
                        );
                    }
                }

                ControlEvent::PeerUpdated(peer_info) => {
                    let previous = self.peers.get_connection(&peer_info.node_id).await;
                    let update = self.peers.add_peer(&peer_info).await;
                    if !peer_info.online {
                        self.transport.remove_session(&peer_info.node_id).await;
                        self.pending_handshakes
                            .lock()
                            .await
                            .clear_peer(&peer_info.node_id);
                        if self.dns.is_enabled() {
                            if let Some(previous) = previous.as_ref() {
                                self.dns.unregister(&previous.virtual_ip).await;
                            } else {
                                self.dns.unregister(&peer_info.virtual_ip).await;
                            }
                        }
                        debug!(
                            "Peer {} is offline according to control plane; cleared active sessions and skipped traversal",
                            peer_info.node_id
                        );
                        continue;
                    }
                    if update.public_key_changed {
                        self.transport.remove_session(&peer_info.node_id).await;
                        self.pending_handshakes
                            .lock()
                            .await
                            .clear_peer(&peer_info.node_id);
                        info!(
                            "Peer {} public key changed; discarded the old WireGuard session",
                            peer_info.node_id
                        );
                    }
                    let was_offline = previous.as_ref().is_some_and(|peer| !peer.online);
                    if (update.virtual_ip_changed || was_offline) && self.dns.is_enabled() {
                        if let Some(previous) = previous {
                            self.dns.unregister(&previous.virtual_ip).await;
                        }
                        self.dns
                            .register(
                                &peer_info.node_id,
                                &peer_info.virtual_ip,
                                Some(&peer_info.node_id),
                            )
                            .await;
                    }
                    let mut sent_handshake_offer = false;
                    match self.maybe_initiate_handshake(&peer_info).await {
                        Ok(punch_at_ms) => {
                            sent_handshake_offer = punch_at_ms.is_some();
                            self.start_hole_punch_at(&peer_info.node_id, punch_at_ms).await;
                        }
                        Err(err) => {
                            warn!(
                                "Failed to refresh WireGuard handshake with {} after peer update: {err}",
                                peer_info.node_id
                            );
                            self.start_hole_punch(&peer_info.node_id).await;
                        }
                    }
                    if !sent_handshake_offer {
                        self.publish_current_candidates_to_peer(
                            &peer_info.node_id,
                            "peer updated",
                        )
                        .await;
                    }
                }

                ControlEvent::PeerLeft(node_id) => {
                    info!("Peer left: {}", node_id);
                    if let Some(previous) = self.peers.get_connection(&node_id).await {
                        if self.dns.is_enabled() {
                            self.dns.unregister(&previous.virtual_ip).await;
                        }
                    }
                    self.transport.remove_session(&node_id).await;
                    self.pending_handshakes.lock().await.clear_peer(&node_id);
                    self.peers.remove_peer(&node_id).await;
                }

                ControlEvent::PeerOffer {
                    from_node_id,
                    candidates,
                    session_id,
                    probe_ephemeral_public_key,
                    candidate_sources,
                    candidate_generation,
                    candidates_expires_at_ms,
                    handshake_init,
                    punch_at_ms,
                    punch_at_server_ms,
                } => {
                    info!(
                        "Received peer offer from {} ({} candidates)",
                        from_node_id,
                        candidates.len()
                    );
                    // Candidate-only trickle offers intentionally omit session
                    // metadata. They must not clear the MAC key negotiated by
                    // the current WireGuard handshake.
                    if peer_offer_updates_probe_session(
                        &handshake_init,
                        session_id.as_deref(),
                    ) {
                        self.peers
                            .set_probe_session_id(&from_node_id, session_id.clone())
                            .await;
                    }
                    self.peers
                        .record_direct_event(
                            &from_node_id,
                            "peer_offer_received",
                            None,
                            Some(candidates.len()),
                            None,
                            format!(
                                "received offer handshake_bytes={} punch_at_ms={punch_at_ms:?}",
                                handshake_init.len()
                            ),
                        )
                        .await;
                    self.peers
                        .add_candidates_with_metadata(
                            &from_node_id,
                            &candidates,
                            &candidate_sources,
                            candidate_generation,
                            candidates_expires_at_ms,
                        )
                        .await;
                    if !handshake_init.is_empty() {
                        if let Err(err) = self
                            .handle_peer_offer(
                                &from_node_id,
                                &candidates,
                                &handshake_init,
                                punch_at_ms,
                                punch_at_server_ms,
                                session_id.clone(),
                                probe_ephemeral_public_key.clone(),
                            )
                            .await
                        {
                            warn!("Failed to handle peer offer from {from_node_id}: {err}");
                        }
                    }
                    self.start_hole_punch_at(&from_node_id, punch_at_ms).await;
                }

                ControlEvent::PeerAnswer {
                    from_node_id,
                    candidates,
                    session_id,
                    probe_ephemeral_public_key,
                    candidate_sources,
                    candidate_generation,
                    candidates_expires_at_ms,
                    handshake_response,
                    punch_at_ms,
                    punch_at_server_ms: _,
                } => {
                    info!(
                        "Received peer answer from {} ({} candidates)",
                        from_node_id,
                        candidates.len()
                    );
                    self.peers
                        .record_direct_event(
                            &from_node_id,
                            "peer_answer_received",
                            None,
                            Some(candidates.len()),
                            None,
                            format!(
                                "received answer handshake_bytes={} punch_at_ms={punch_at_ms:?}",
                                handshake_response.len()
                            ),
                        )
                        .await;
                    self.peers
                        .add_candidates_with_metadata(
                            &from_node_id,
                            &candidates,
                            &candidate_sources,
                            candidate_generation,
                            candidates_expires_at_ms,
                        )
                        .await;
                    if !handshake_response.is_empty() {
                        if let Err(err) = self
                            .handle_peer_answer(
                                &from_node_id,
                                &handshake_response,
                                session_id.clone(),
                                probe_ephemeral_public_key.clone(),
                            )
                            .await
                        {
                            warn!("Failed to handle peer answer from {from_node_id}: {err}");
                        }
                    }
                    self.start_hole_punch_at(&from_node_id, punch_at_ms).await;
                }

                ControlEvent::PeerReflexive {
                    from_node_id,
                    observed_endpoint,
                    punch_at_ms,
                } => {
                    let local_candidate_changed = self
                        .add_local_peer_reflexive_candidate(&observed_endpoint)
                        .await;
                    let punch_at_ms =
                        punch_at_ms.or_else(|| Some(relay_assisted_punch_at_ms()));
                    let candidates = self.local_candidates.read().await.clone();
                    let candidate_sources = self.local_candidate_sources.read().await.clone();
                    self.peers
                        .record_direct_event(
                            &from_node_id,
                            "peer_reflexive_received",
                            observed_endpoint.parse().ok(),
                            Some(candidates.len()),
                            None,
                            format!(
                                "peer observed our UDP source as {observed_endpoint}; punch_at_ms={punch_at_ms:?}"
                            ),
                        )
                        .await;
                    if local_candidate_changed && !candidates.is_empty() {
                        if let Err(err) = self
                            .control
                            .send_peer_offer_with_sources_and_punch_at(
                                &from_node_id,
                                &candidates,
                                &candidate_sources,
                                &[],
                                punch_at_ms,
                            )
                            .await
                        {
                            warn!(
                                "Failed to re-advertise peer-reflexive local candidate to {from_node_id}: {err}"
                            );
                        } else {
                            self.peers
                                .record_direct_event(
                                    &from_node_id,
                                    "peer_reflexive_offer_sent",
                                    observed_endpoint.parse().ok(),
                                    Some(candidates.len()),
                                    None,
                                    "re-advertised local candidates after peer-reflexive observation",
                                )
                                .await;
                        }
                    } else if !local_candidate_changed {
                        self.peers
                            .record_direct_event(
                                &from_node_id,
                                "peer_reflexive_offer_skipped",
                                observed_endpoint.parse().ok(),
                                Some(candidates.len()),
                                None,
                                "peer-reflexive candidate already advertised; skipped full offer re-advertisement",
                            )
                            .await;
                    }
                    self.start_hole_punch_at(&from_node_id, punch_at_ms).await;
                }

                ControlEvent::PeerRejected {
                    from_node_id,
                    reason,
                } => {
                    warn!("Peer {} rejected connection: {}", from_node_id, reason);
                }

                ControlEvent::TunnelCreated {
                    tunnel_id,
                    public_endpoint,
                } => {
                    info!("Tunnel created: {} → {}", tunnel_id, public_endpoint);
                    self.port_mappings
                        .activate(&tunnel_id, &public_endpoint)
                        .await
                        .ok();
                }

                ControlEvent::ServerError { code, message } => {
                    error!("Control server error: {} - {}", code, message);
                }

                ControlEvent::Disconnected => {
                    // Control loop will re-register; do not shut down the daemon.
                    self.health.set_control_connected(false);
                    warn!("Disconnected from control server; waiting for recovery");
                }

                ControlEvent::ReauthRequired { message } => {
                    error!("Reauthentication required: {message}");
                    self.health.set_reauth_required(true);
                    // Keep running so operator can re-auth; do not exit daemon.
                }

                ControlEvent::ControlRecovered { .. } => {
                    info!("Control plane recovered after disconnection");
                    self.health.mark_control_success().await;
                }
                ControlEvent::ControlHealthy => {
                    self.health.mark_control_success().await;
                }
                    }
                }
            }
        }
    }
}
