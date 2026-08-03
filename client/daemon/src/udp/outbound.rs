impl UdpTransport {
    /// Keep a mapping-dependent local NAT binding warm toward one stable peer endpoint.
    ///
    /// This is intentionally separate from the bounded candidate punch: a
    /// symmetric/hard NAT side should maintain one destination-specific binding
    /// with the primary socket while the easier peer scans the hard side's
    /// predicted/birthday window.
    pub async fn spawn_nat_binding_maintainer(
        &self,
        peer_id: &str,
        endpoint: SocketAddr,
        interval: Duration,
        duration: Duration,
    ) -> bool {
        if interval.is_zero() || duration.is_zero() {
            return false;
        }

        let key = (peer_id.to_string(), endpoint);
        let now = Instant::now();
        let expires_at = now + duration;
        {
            let mut maintainers = self.nat_maintainers.lock().await;
            maintainers.retain(|_, expires_at| *expires_at > now);
            if maintainers.contains_key(&key) {
                self.peers
                    .record_direct_event(
                        peer_id,
                        "nat_maintainer_suppressed",
                        Some(endpoint),
                        Some(1),
                        None,
                        "suppressed overlapping NAT-state maintainer for this peer endpoint",
                    )
                    .await;
                return false;
            }
            maintainers.insert(key.clone(), expires_at);
        }

        let transport = self.clone();
        let peers = self.peers.clone();
        let peer_id = peer_id.to_string();
        tokio::spawn(async move {
            peers
                .record_direct_event(
                    &peer_id,
                    "nat_maintainer_started",
                    Some(endpoint),
                    Some(1),
                    None,
                    format!(
                        "maintaining hard-NAT binding toward stable endpoint for {}ms every {}ms",
                        duration.as_millis(),
                        interval.as_millis()
                    ),
                )
                .await;

            let started_at = Instant::now();
            let deadline = started_at + duration;
            let mut sent = 0u32;
            let mut skipped = 0u32;
            let mut last_skip_reason = None;
            let mut stop_reason = "duration_elapsed";

            loop {
                if peers.is_direct(&peer_id).await {
                    stop_reason = "direct_confirmed";
                    break;
                }
                if Instant::now() >= deadline {
                    break;
                }

                match transport
                    .admit_outbound_connectivity_probe(&peer_id, endpoint)
                    .await
                {
                    OutboundProbeAdmission::Accepted => {
                        match transport
                            .send_probe_from_socket(0, Some(&peer_id), endpoint)
                            .await
                        {
                            Ok(_) => {
                                sent = sent.saturating_add(1);
                                transport
                                    .update_socket_diagnostics(0, |metrics| {
                                        metrics.nat_maintainer_probes_sent =
                                            metrics.nat_maintainer_probes_sent.saturating_add(1);
                                    })
                                    .await;
                                peers.record_direct_probe_sent(&peer_id, endpoint).await;
                            }
                            Err(err) => {
                                stop_reason = "send_error";
                                peers
                                    .record_direct_event(
                                        &peer_id,
                                        "nat_maintainer_send_error",
                                        Some(endpoint),
                                        Some(1),
                                        Some(sent),
                                        format!("NAT-state maintainer send failed: {err}"),
                                    )
                                    .await;
                                break;
                            }
                        }
                    }
                    limited => {
                        skipped = skipped.saturating_add(1);
                        last_skip_reason = Some(outbound_probe_admission_reason(limited));
                        transport
                            .update_socket_diagnostics(0, |metrics| {
                                metrics.nat_maintainer_probe_skips =
                                    metrics.nat_maintainer_probe_skips.saturating_add(1);
                            })
                            .await;
                    }
                }

                let remaining = deadline.saturating_duration_since(Instant::now());
                if remaining.is_zero() {
                    break;
                }
                sleep(interval.min(remaining)).await;
            }

            peers
                .record_direct_event(
                    &peer_id,
                    "nat_maintainer_stopped",
                    Some(endpoint),
                    Some(1),
                    Some(sent),
                    format!(
                        "stopped NAT-state maintainer reason={stop_reason} sent={sent} skipped={skipped} last_skip_reason={}",
                        last_skip_reason.unwrap_or("none")
                    ),
                )
                .await;

            let mut maintainers = transport.nat_maintainers.lock().await;
            if maintainers.get(&key).copied() == Some(expires_at) {
                maintainers.remove(&key);
            }
        });

        true
    }

    /// Send active UDP probes to every candidate for a peer.
    pub async fn punch_candidates(
        &self,
        peer_id: &str,
        candidates: Vec<SocketAddr>,
        probe_interval: Duration,
        attempts: u32,
    ) -> Result<u32> {
        self.punch_candidates_with_socket_policy(
            peer_id,
            candidates,
            probe_interval,
            attempts,
            PunchSocketPolicy::ActivePool,
        )
        .await
    }

    /// Send active UDP probes only from the primary socket.
    ///
    /// This is reserved for explicit single-socket diagnostics and tests. The
    /// hard-NAT binding maintainer sends on socket 0 directly, while normal
    /// synchronized/retry punching uses the active pool so alternate sockets
    /// can open peer-specific NAT filter state instead of only publishing
    /// STUN-observed mappings.
    pub async fn punch_candidates_primary_socket(
        &self,
        peer_id: &str,
        candidates: Vec<SocketAddr>,
        probe_interval: Duration,
        attempts: u32,
    ) -> Result<u32> {
        self.punch_candidates_with_socket_policy(
            peer_id,
            candidates,
            probe_interval,
            attempts,
            PunchSocketPolicy::PrimaryOnly,
        )
        .await
    }

    async fn punch_candidates_with_socket_policy(
        &self,
        peer_id: &str,
        candidates: Vec<SocketAddr>,
        probe_interval: Duration,
        attempts: u32,
        socket_policy: PunchSocketPolicy,
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
        let mut sent_endpoints = HashSet::new();
        let mut sent_ports = HashSet::new();
        let mut socket0_sent = 0u32;
        let mut alt_socket_sent = 0u32;
        let socket_count = socket_policy.socket_count(self);
        'schedule: for (round_index, round) in schedule.iter().enumerate() {
            if !round.delay_before.is_zero() {
                sleep(round.delay_before).await;
            }

            let probe_order = match socket_policy {
                PunchSocketPolicy::ActivePool if socket_count > 1 => {
                    // Hard NAT traversal needs the alternate sockets to send real
                    // peer-directed traffic, not just STUN probes. Candidate-major
                    // ordering gives every high-priority remote port a chance from
                    // each active local socket before the per-peer/IP budget or
                    // session cap is exhausted.
                    let mut order = Vec::with_capacity(round.endpoints.len() * socket_count);
                    for &candidate in &round.endpoints {
                        for socket_index in 0..socket_count {
                            order.push((socket_index, candidate));
                        }
                    }
                    order
                }
                _ => {
                    // Primary-only scans and single-socket fallback keep the
                    // original stable source-port sweep semantics.
                    let mut order = Vec::with_capacity(round.endpoints.len() * socket_count);
                    for socket_index in 0..socket_count {
                        for &candidate in &round.endpoints {
                            order.push((socket_index, candidate));
                        }
                    }
                    order
                }
            };

            for (socket_index, candidate) in probe_order {
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
                        if socket_index == 0 {
                            socket0_sent = socket0_sent.saturating_add(1);
                        } else {
                            alt_socket_sent = alt_socket_sent.saturating_add(1);
                        }
                        sent_endpoints.insert(candidate);
                        sent_ports.insert(candidate.port());
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

        let unique_target_ports = u32::try_from(sent_ports.len()).unwrap_or(u32::MAX);
        let repeated_target_ports = packets_sent.saturating_sub(unique_target_ports);
        let stage = match socket_policy {
            PunchSocketPolicy::ActivePool if socket_count > 1 => "active_pool_scan_completed",
            PunchSocketPolicy::ActivePool => "single_socket_scan_completed",
            PunchSocketPolicy::PrimaryOnly => "primary_socket_scan_completed",
        };
        self.peers
            .record_direct_event_with_probe_coverage(
                peer_id,
                stage,
                candidates.first().copied(),
                Some(candidates.len()),
                Some(packets_sent),
                format!(
                    "scan_socket_policy={} active_sockets={} punch_sockets={} candidate_count={} attempts={} unique_target_endpoints={} unique_target_ports={} repeated_target_probes={}",
                    socket_policy.label(),
                    self.socket_count(),
                    socket_count,
                    candidates.len(),
                    attempts,
                    sent_endpoints.len(),
                    sent_ports.len(),
                    repeated_target_ports
                ),
                socket0_sent,
                alt_socket_sent,
                unique_target_ports,
                repeated_target_ports,
            )
            .await;

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
