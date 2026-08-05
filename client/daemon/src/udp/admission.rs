impl UdpTransport {
    async fn admit_authenticated_punch(
        &self,
        peer_id: &str,
        generation: u64,
        kind: PunchPacketKind,
        nonce: ProbeNonce,
        source: SocketAddr,
    ) -> AuthenticatedPunchAdmission {
        let now = Instant::now();
        let mut rate = self.authenticated_punch_rate.lock().await;
        rate.retain(|_, seen| {
            while seen
                .front()
                .is_some_and(|seen_at| now.duration_since(*seen_at) >= AUTH_PUNCH_RATE_WINDOW)
            {
                seen.pop_front();
            }
            !seen.is_empty()
        });
        let seen = rate.entry((peer_id.to_string(), source)).or_default();
        while seen
            .front()
            .is_some_and(|seen_at| now.duration_since(*seen_at) >= AUTH_PUNCH_RATE_WINDOW)
        {
            seen.pop_front();
        }
        if seen.len() >= AUTH_PUNCH_RATE_LIMIT_PER_SOURCE {
            return AuthenticatedPunchAdmission::RateLimited;
        }
        seen.push_back(now);
        drop(rate);

        {
            let mut replay = self.authenticated_punch_replay.lock().await;
            replay.retain(|_, seen_at| seen_at.elapsed() < AUTH_PUNCH_REPLAY_WINDOW);
            let key = (
                peer_id.to_string(),
                generation,
                nonce,
                punch_kind_code(kind),
            );
            if replay.contains_key(&key) {
                return AuthenticatedPunchAdmission::Replay;
            }
            replay.insert(key, now);

            if replay.len() > AUTH_PUNCH_REPLAY_MAX_ENTRIES {
                let mut entries = replay
                    .iter()
                    .map(|(key, seen_at)| (key.clone(), *seen_at))
                    .collect::<Vec<_>>();
                entries.sort_by_key(|(_, seen_at)| *seen_at);
                let remove_count = replay
                    .len()
                    .saturating_sub(AUTH_PUNCH_REPLAY_TARGET_ENTRIES);
                for (key, _) in entries.into_iter().take(remove_count) {
                    replay.remove(&key);
                }
            }
        }

        AuthenticatedPunchAdmission::Accepted
    }

    async fn rollback_authenticated_punch_replay_admission(
        &self,
        peer_id: &str,
        generation: u64,
        kind: PunchPacketKind,
        nonce: ProbeNonce,
    ) {
        self.authenticated_punch_replay.lock().await.remove(&(
            peer_id.to_string(),
            generation,
            nonce,
            punch_kind_code(kind),
        ));
    }

    async fn admit_outbound_connectivity_probe(
        &self,
        peer_id: &str,
        peer_addr: SocketAddr,
    ) -> OutboundProbeAdmission {
        let now = Instant::now();
        let network_key = OutboundProbeBudgetKey::Network;
        let peer_key = OutboundProbeBudgetKey::Peer(peer_id.to_string());
        let remote_ip_key =
            OutboundProbeBudgetKey::PeerRemoteIp(peer_id.to_string(), peer_addr.ip());
        let mut budget = self.outbound_probe_budget.lock().await;
        retain_live_budget_entries(&mut budget, now);

        if budget.get(&network_key).map_or(0, VecDeque::len) >= OUTBOUND_PROBE_BUDGET_PER_NETWORK {
            return OutboundProbeAdmission::NetworkRateLimited;
        }
        if budget.get(&peer_key).map_or(0, VecDeque::len) >= OUTBOUND_PROBE_BUDGET_PER_PEER {
            return OutboundProbeAdmission::PeerRateLimited;
        }
        if budget.get(&remote_ip_key).map_or(0, VecDeque::len)
            >= OUTBOUND_PROBE_BUDGET_PER_PEER_REMOTE_IP
        {
            return OutboundProbeAdmission::RemoteIpRateLimited;
        }

        if let Some(global_budget) = self.global_outbound_probe_budget.as_ref() {
            match global_budget.admit(peer_id, peer_addr).await {
                OutboundProbeAdmission::Accepted => {}
                limited => return limited,
            }
        }

        budget.entry(network_key).or_default().push_back(now);
        budget.entry(peer_key).or_default().push_back(now);
        budget.entry(remote_ip_key).or_default().push_back(now);
        OutboundProbeAdmission::Accepted
    }

    async fn notify_peer_reflexive_observation(
        &self,
        peer_id: &str,
        observed_endpoint: SocketAddr,
    ) {
        let Some(tx) = self.peer_reflexive_tx.as_ref() else {
            return;
        };
        let key = (peer_id.to_string(), observed_endpoint);
        {
            let mut notifications = self.peer_reflexive_notifications.lock().await;
            notifications.retain(|_, sent_at| sent_at.elapsed() < PEER_REFLEXIVE_NOTIFY_COOLDOWN);
            if notifications.contains_key(&key) {
                return;
            }
            notifications.insert(key, Instant::now());
        }

        if let Err(err) = tx.try_send(PeerReflexiveObservation {
            peer_id: peer_id.to_string(),
            observed_endpoint,
        }) {
            debug!(
                "Dropping peer-reflexive observation for {peer_id} at {observed_endpoint}: {err}"
            );
        }
    }

    async fn trigger_peer_reflexive_check(
        &self,
        socket_index: usize,
        peer_id: &str,
        observed_endpoint: SocketAddr,
    ) {
        let key = (peer_id.to_string(), observed_endpoint, socket_index);
        {
            let mut checks = self.triggered_checks.lock().await;
            checks.retain(|_, sent_at| sent_at.elapsed() < TRIGGERED_CHECK_COOLDOWN);
            if checks.contains_key(&key) {
                return;
            }
            checks.insert(key, Instant::now());
        }

        let local_endpoint = self
            .active_sockets()
            .get(socket_index)
            .and_then(|socket| socket.local_addr().ok());
        match self
            .send_probe_from_socket(socket_index, Some(peer_id), observed_endpoint)
            .await
        {
            Ok(_) => info!(
                event = "candidate_pair_triggered_check",
                peer_id = %peer_id,
                local_endpoint = %local_endpoint.map(|endpoint| endpoint.to_string()).unwrap_or_else(|| "unknown".to_string()),
                remote_endpoint = %observed_endpoint,
                candidate_source = "peer_reflexive",
                reason = "authenticated inbound punch observed",
                "candidate_pair_triggered_check peer_id={} remote_endpoint={} reason=authenticated inbound punch observed",
                peer_id,
                observed_endpoint
            ),
            Err(err) => debug!(
                "Failed triggered UDP check from socket {socket_index} to peer {peer_id} at {observed_endpoint}: {err}"
            ),
        }
    }

    #[cfg(test)]
    async fn send_probe(&self, peer_id: Option<&str>, peer_addr: SocketAddr) -> Result<ProbeNonce> {
        let socket_index = self.socket_index_for_peer(peer_id).await;
        self.send_probe_from_socket_with_nomination(
            socket_index,
            peer_id,
            peer_addr,
            false,
            PendingProbePurpose::ConnectivityCheck,
        )
        .await
    }

    async fn send_probe_from_socket(
        &self,
        socket_index: usize,
        peer_id: Option<&str>,
        peer_addr: SocketAddr,
    ) -> Result<ProbeNonce> {
        self.send_probe_from_socket_with_nomination(
            socket_index,
            peer_id,
            peer_addr,
            false,
            PendingProbePurpose::ConnectivityCheck,
        )
        .await
    }

    async fn send_probe_from_socket_with_nomination(
        &self,
        socket_index: usize,
        peer_id: Option<&str>,
        peer_addr: SocketAddr,
        use_candidate: bool,
        purpose: PendingProbePurpose,
    ) -> Result<ProbeNonce> {
        let socket = self
            .active_sockets()
            .get(socket_index)
            .cloned()
            .ok_or_else(|| {
                DaemonError::Network(format!(
                    "UDP socket pool member {socket_index} is unavailable"
                ))
            })?;
        let generation = self.peers.current_network_generation().await;
        let requires_legacy_probe = match peer_id {
            Some(peer_id) => self.peers.peer_requires_legacy_probe(peer_id).await,
            None => true,
        };
        let should_retransmit = use_candidate || purpose == PendingProbePurpose::ConsentCheck;
        let authenticated_probe = match (peer_id, self.local_node_id.as_deref()) {
            (Some(peer_id), Some(local_node_id))
                if local_node_id.len() <= u8::MAX as usize && peer_id.len() <= u8::MAX as usize =>
            {
                self.peers.probe_key_for_peer(peer_id).await.map(|key| {
                    let (bytes, nonce) = build_authenticated_punch_packet_with_nomination(
                        local_node_id,
                        peer_id,
                        generation,
                        use_candidate,
                        &key,
                    );
                    (bytes, nonce)
                })
            }
            _ => None,
        };

        let (
            bytes,
            nonce,
            accepts_authenticated_ack,
            accepts_legacy_ack,
            compat_legacy_probe,
        ) =
            if let Some((bytes, nonce)) = authenticated_probe {
                // Compatibility bridge for pre-v2 peers. v0.1.24 and older only
                // understand PNCH v1 and otherwise forward PNCH v2 into the
                // WireGuard parser, producing "invalid message type: 80".
                // Send a legacy probe with the same nonce so either ACK form clears
                // the same pending probe without weakening the v2 path between
                // upgraded peers.
                (
                    bytes,
                    nonce,
                    true,
                    requires_legacy_probe,
                    requires_legacy_probe
                        .then(|| build_punch_packet_with_nonce(nonce).to_vec()),
                )
            } else {
                let bytes = build_punch_packet();
                let nonce = decode_punch_packet(&bytes)
                    .map(|packet| packet.nonce)
                    .ok_or_else(|| {
                        DaemonError::Network("failed to create UDP probe".to_string())
                    })?;
                (bytes.to_vec(), nonce, false, true, None)
            };

        {
            let mut pending = self.pending_probes.lock().await;
            pending.retain(|_, pending| {
                pending.sent_at.elapsed() < Duration::from_secs(60)
                    && pending.generation == generation
            });
            pending.insert(
                nonce,
                PendingProbe {
                    sent_at: Instant::now(),
                    endpoint: peer_addr,
                    local_endpoint: socket.local_addr().ok(),
                    socket_index,
                    generation,
                    peer_id: peer_id.map(str::to_string),
                    purpose,
                    accepts_authenticated_ack,
                    accepts_legacy_ack,
                },
            );
        }

        if let Err(error) = socket.send_to(&bytes, peer_addr).await {
            self.pending_probes.lock().await.remove(&nonce);
            return Err(DaemonError::Network(format!(
                "UDP probe send to {peer_addr} failed: {error}"
            )));
        }

        self.update_socket_diagnostics(socket_index, |metrics| metrics.probes_sent += 1)
            .await;

        if let Some(legacy_probe) = compat_legacy_probe.clone() {
            match socket.send_to(&legacy_probe, peer_addr).await {
                Ok(_) => {
                    self.update_socket_diagnostics(socket_index, |metrics| {
                        metrics.probes_sent += 1
                    })
                    .await;
                    trace!(
                        "Sent compatibility legacy UDP punch probe to peer {} at {}",
                        peer_id.unwrap_or("unknown"),
                        peer_addr
                    );
                    if should_retransmit {
                        self.retransmit_probe_burst(
                            socket.clone(),
                            socket_index,
                            legacy_probe,
                            peer_addr,
                            peer_id.map(str::to_string),
                        );
                    }
                }
                Err(err) => {
                    debug!(
                        "Failed to send compatibility legacy UDP punch probe to peer {} at {}: {}",
                        peer_id.unwrap_or("unknown"),
                        peer_addr,
                        err
                    );
                }
            }
        }

        if should_retransmit {
            self.retransmit_probe_burst(
                socket,
                socket_index,
                bytes,
                peer_addr,
                peer_id.map(str::to_string),
            );
        }
        Ok(nonce)
    }

    /// Send an authenticated ICE-style nominated connectivity check for a direct trial.
    pub async fn send_nomination_probe(&self, peer_id: &str, peer_addr: SocketAddr) -> Result<()> {
        let socket_index = self.socket_index_for_peer(Some(peer_id)).await;
        self.send_probe_from_socket_with_nomination(
            socket_index,
            Some(peer_id),
            peer_addr,
            true,
            PendingProbePurpose::ConnectivityCheck,
        )
        .await?;
        Ok(())
    }

    fn retransmit_probe_burst(
        &self,
        socket: Arc<UdpSocket>,
        socket_index: usize,
        probe: Vec<u8>,
        peer_addr: SocketAddr,
        peer_id: Option<String>,
    ) {
        let peer_label = peer_id.unwrap_or_else(|| peer_addr.to_string());
        let diagnostics = self.socket_pool_diagnostics.clone();
        tokio::spawn(async move {
            for delay_ms in PUNCH_PROBE_RETRANSMIT_DELAYS_MS {
                sleep(Duration::from_millis(delay_ms)).await;
                match socket.send_to(&probe, peer_addr).await {
                    Ok(_) => {
                        if let Some(metrics) = diagnostics.lock().await.get_mut(socket_index) {
                            metrics.probe_retransmissions_sent += 1;
                        }
                        trace!(
                            "Retransmitted UDP punch probe to peer {} at {} after {}ms",
                            peer_label,
                            peer_addr,
                            delay_ms
                        );
                    }
                    Err(err) => {
                        debug!(
                            "Failed to retransmit UDP punch probe to peer {} at {} after {}ms: {}",
                            peer_label, peer_addr, delay_ms, err
                        );
                        break;
                    }
                }
            }
        });
    }

    async fn send_punch_ack_burst(
        &self,
        socket_index: usize,
        socket: Arc<UdpSocket>,
        ack: Vec<u8>,
        source: SocketAddr,
        peer_label: impl Into<String>,
    ) -> std::io::Result<()> {
        socket.send_to(&ack, source).await?;
        self.update_socket_diagnostics(socket_index, |metrics| metrics.probe_acks_sent += 1)
            .await;

        let peer_label = peer_label.into();
        let diagnostics = self.socket_pool_diagnostics.clone();
        tokio::spawn(async move {
            for delay_ms in PUNCH_ACK_RETRANSMIT_DELAYS_MS {
                sleep(Duration::from_millis(delay_ms)).await;
                match socket.send_to(&ack, source).await {
                    Ok(_) => {
                        if let Some(metrics) = diagnostics.lock().await.get_mut(socket_index) {
                            metrics.probe_ack_retransmissions_sent += 1;
                        }
                        trace!(
                            "Retransmitted UDP punch ACK to peer {} at {} after {}ms",
                            peer_label,
                            source,
                            delay_ms
                        );
                    }
                    Err(err) => {
                        debug!(
                            "Failed to retransmit UDP punch ACK to peer {} at {} after {}ms: {}",
                            peer_label, source, delay_ms, err
                        );
                        break;
                    }
                }
            }
        });
        Ok(())
    }
}
