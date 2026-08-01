impl UdpTransport {
    /// Send active UDP probes to every candidate for a peer.
    pub async fn punch_candidates(
        &self,
        peer_id: &str,
        candidates: Vec<SocketAddr>,
        probe_interval: Duration,
        attempts: u32,
    ) -> Result<u32> {
        if candidates.is_empty() || attempts == 0 {
            return Ok(0);
        }

        let schedule = build_probe_schedule(&candidates, probe_interval, attempts);
        trace!(
            "Built adaptive UDP probe schedule for peer {}: {} rounds across {} candidates",
            peer_id,
            schedule.len(),
            candidates.len()
        );

        let mut packets_sent = 0;
        let mut budget_skipped = 0u32;
        let mut last_budget_reason = None;
        let mut session_capped = false;
        'schedule: for (round_index, round) in schedule.iter().enumerate() {
            if !round.delay_before.is_zero() {
                sleep(round.delay_before).await;
            }

            for &candidate in &round.endpoints {
                // Before a direct path is authenticated, each bounded pool
                // member gets one independently mapped chance at the remote
                // candidate. Once a peer has an affinity, normal sends use
                // that socket rather than changing its NAT mapping.
                for socket_index in 0..self.punch_socket_count() {
                    if packets_sent >= MAX_PUNCH_PROBES_PER_SESSION {
                        session_capped = true;
                        break 'schedule;
                    }
                    match self
                        .admit_outbound_connectivity_probe(peer_id, candidate)
                        .await
                    {
                        OutboundProbeAdmission::Accepted => {}
                        OutboundProbeAdmission::NetworkRateLimited => {
                            budget_skipped = budget_skipped.saturating_add(1);
                            last_budget_reason = Some("network_rate_limited");
                            trace!(
                                "Skipped UDP punch probe from socket {} to peer {} candidate {}: network probe budget exhausted",
                                socket_index, peer_id, candidate
                            );
                            continue;
                        }
                        OutboundProbeAdmission::PeerRateLimited => {
                            budget_skipped = budget_skipped.saturating_add(1);
                            last_budget_reason = Some("peer_rate_limited");
                            trace!(
                                "Skipped UDP punch probe from socket {} to peer {} candidate {}: peer probe budget exhausted",
                                socket_index, peer_id, candidate
                            );
                            continue;
                        }
                        OutboundProbeAdmission::RemoteIpRateLimited => {
                            budget_skipped = budget_skipped.saturating_add(1);
                            last_budget_reason = Some("remote_ip_rate_limited");
                            trace!(
                                "Skipped UDP punch probe from socket {} to peer {} candidate {}: remote IP probe budget exhausted",
                                socket_index, peer_id, candidate
                            );
                            continue;
                        }
                        OutboundProbeAdmission::GlobalNetworkRateLimited => {
                            budget_skipped = budget_skipped.saturating_add(1);
                            last_budget_reason = Some("global_network_rate_limited");
                            trace!(
                                "Skipped UDP punch probe from socket {} to peer {} candidate {}: global network probe budget exhausted",
                                socket_index, peer_id, candidate
                            );
                            continue;
                        }
                        OutboundProbeAdmission::GlobalPeerRateLimited => {
                            budget_skipped = budget_skipped.saturating_add(1);
                            last_budget_reason = Some("global_peer_rate_limited");
                            trace!(
                                "Skipped UDP punch probe from socket {} to peer {} candidate {}: global peer probe budget exhausted",
                                socket_index, peer_id, candidate
                            );
                            continue;
                        }
                        OutboundProbeAdmission::GlobalRemoteIpRateLimited => {
                            budget_skipped = budget_skipped.saturating_add(1);
                            last_budget_reason = Some("global_remote_ip_rate_limited");
                            trace!(
                                "Skipped UDP punch probe from socket {} to peer {} candidate {}: global remote IP probe budget exhausted",
                                socket_index, peer_id, candidate
                            );
                            continue;
                        }
                    }

                    match self
                        .send_probe_from_socket(socket_index, Some(peer_id), candidate)
                        .await
                    {
                        Ok(_) => {
                            packets_sent += 1;
                            self.peers
                                .record_direct_probe_sent(peer_id, candidate)
                                .await;
                            trace!(
                                "Sent adaptive punch probe round {} from socket {} to peer {} candidate {}",
                                round_index + 1,
                                socket_index,
                                peer_id,
                                candidate
                            );
                            if !OUTBOUND_CONNECTIVITY_PROBE_SPACING.is_zero() {
                                sleep(OUTBOUND_CONNECTIVITY_PROBE_SPACING).await;
                            }
                        }
                        Err(err) => {
                            debug!(
                                "Failed to send punch probe from socket {} to peer {} candidate {}: {}",
                                socket_index, peer_id, candidate, err
                            );
                        }
                    }
                }
            }
        }

        if session_capped {
            self.peers
                .record_direct_event(
                    peer_id,
                    "probe_session_capped",
                    candidates.first().copied(),
                    Some(candidates.len()),
                    Some(packets_sent),
                    format!(
                        "stopped UDP punch after the {MAX_PUNCH_PROBES_PER_SESSION}-probe session cap"
                    ),
                )
                .await;
        }

        if budget_skipped > 0 {
            let reason = last_budget_reason.unwrap_or("probe_budget_limited");
            self.peers
                .record_direct_event(
                    peer_id,
                    "probe_budget_limited",
                    candidates.first().copied(),
                    Some(candidates.len()),
                    Some(packets_sent),
                    format!(
                        "skipped {budget_skipped} UDP punch probes due to outbound {reason}; sent {packets_sent}"
                    ),
                )
                .await;
        }

        Ok(packets_sent)
    }

    /// Send a single encrypted packet.
    ///
    /// Returns `Ok(Some(bytes))` when sent, `Ok(None)` when no endpoint is known
    /// for the destination peer, and `Err` for socket-level failures.
    pub async fn send_packet(&self, packet: &EncryptedPeerPacket) -> Result<Option<usize>> {
        let Some(endpoint) = self.peers.direct_endpoint_for_send(&packet.peer_id).await else {
            trace!(
                "No UDP endpoint for {}; dropping {} byte encrypted packet",
                packet.peer_id,
                packet.wire_bytes.len()
            );
            return Ok(None);
        };

        self.send_packet_to(packet, endpoint).await.map(Some)
    }

    /// Send a single encrypted packet to a selector-provided direct endpoint.
    pub async fn send_packet_to(
        &self,
        packet: &EncryptedPeerPacket,
        endpoint: SocketAddr,
    ) -> Result<usize> {
        let socket_index = self.socket_index_for_peer(Some(&packet.peer_id)).await;
        let socket = self
            .active_sockets()
            .get(socket_index)
            .cloned()
            .unwrap_or_else(|| self.socket.clone());
        let sent = socket
            .send_to(&packet.wire_bytes, endpoint)
            .await
            .map_err(|e| {
                DaemonError::Network(format!(
                    "UDP send to {} for peer {} failed: {}",
                    endpoint, packet.peer_id, e
                ))
            })?;

        if sent != packet.wire_bytes.len() {
            return Err(DaemonError::Network(format!(
                "short UDP send to {} for peer {}: sent {} of {} bytes",
                endpoint,
                packet.peer_id,
                sent,
                packet.wire_bytes.len()
            )));
        }

        self.update_socket_diagnostics(socket_index, |metrics| metrics.encrypted_packets_sent += 1)
            .await;

        debug!(
            "Sent {} encrypted bytes to peer {} at {} (dst={})",
            sent, packet.peer_id, endpoint, packet.dst_ip
        );
        Ok(sent)
    }

    /// Consume encrypted packets until the channel closes.
    pub async fn run_outbound(self, mut encrypted_rx: mpsc::Receiver<EncryptedPeerPacket>) {
        while let Some(packet) = encrypted_rx.recv().await {
            match self.send_packet(&packet).await {
                Ok(Some(_)) => {}
                Ok(None) => {
                    debug!(
                        "Encrypted packet for peer {} has no UDP endpoint yet",
                        packet.peer_id
                    );
                }
                Err(err) => {
                    warn!("UDP transport send failed: {err}");
                }
            }
        }
    }

    /// Periodically refresh direct UDP NAT mappings.
    pub async fn run_keepalives(self, keepalive_interval: Duration) {
        if keepalive_interval.is_zero() {
            return;
        }

        let mut ticker = interval(keepalive_interval);
        loop {
            ticker.tick().await;

            self.run_keepalive_round(DIRECT_KEEPALIVE_ACK_TIMEOUT).await;
        }
    }

    async fn run_keepalive_round(&self, ack_timeout: Duration) {
        let mut sent = Vec::new();

        for (peer_id, endpoint) in self.peers.direct_endpoints().await {
            let socket_index = self.socket_index_for_peer(Some(&peer_id)).await;
            match self
                .send_probe_from_socket_with_nomination(
                    socket_index,
                    Some(&peer_id),
                    endpoint,
                    false,
                    PendingProbePurpose::ConsentCheck,
                )
                .await
            {
                Ok(nonce) => {
                    let local_endpoint = self
                        .pending_probes
                        .lock()
                        .await
                        .get(&nonce)
                        .and_then(|pending| pending.local_endpoint);
                    self.peers
                        .record_direct_event(
                            &peer_id,
                            "consent_check_sent",
                            Some(endpoint),
                            Some(1),
                            Some(1),
                            format!(
                                "sent direct UDP consent check to {endpoint} local_endpoint={}",
                                format_optional_endpoint(local_endpoint)
                            ),
                        )
                        .await;
                    trace!("Sent direct UDP keepalive to peer {peer_id} at {endpoint}");
                    sent.push((peer_id, endpoint, nonce));
                }
                Err(err) => {
                    self.peers
                        .record_direct_failure_with_code(
                            &peer_id,
                            REASON_DIRECT_SEND_FAILED,
                            format!("direct keepalive to {endpoint} failed: {err}"),
                        )
                        .await;
                    debug!(
                        "Failed to send direct UDP keepalive to peer {peer_id} at {endpoint}: {err}"
                    );
                }
            }
        }

        if sent.is_empty() {
            return;
        }

        sleep(ack_timeout).await;
        for (peer_id, endpoint, nonce) in sent {
            let unanswered = self.pending_probes.lock().await.remove(&nonce);
            let Some(pending) = unanswered else {
                continue;
            };
            if pending.peer_id.as_deref() != Some(peer_id.as_str()) || pending.endpoint != endpoint
            {
                continue;
            }
            if pending.purpose == PendingProbePurpose::ConsentCheck {
                self.peers
                    .record_direct_event(
                        &peer_id,
                        "consent_timeout",
                        Some(endpoint),
                        Some(1),
                        None,
                        format!(
                            "direct UDP consent ACK timed out for {endpoint} local_endpoint={}",
                            format_optional_endpoint(pending.local_endpoint)
                        ),
                    )
                    .await;
            }

            if self
                .peers
                .record_direct_keepalive_timeout_for_generation_with_local_endpoint(
                    &peer_id,
                    endpoint,
                    pending.generation,
                    pending.local_endpoint,
                )
                .await
            {
                debug!("Direct UDP keepalive ACK timed out for peer {peer_id} at {endpoint}");
            }
        }
    }
}
