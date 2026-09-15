use super::*;

impl UdpTransport {
    /// A stable, endpoint-free view of the bounded socket pool activity.
    pub async fn socket_pool_diagnostics(&self) -> Vec<UdpSocketPoolMemberDiagnostics> {
        let mut sockets = self.socket_pool_diagnostics.lock().await.clone();
        // A fresh-mapping socket can become the adopted Direct socket. It is
        // just as relevant to an audited traversal run as the static pool,
        // so expose its counters in the same stable, endpoint-free view.
        sockets.extend(
            self.dynamic_socket_diagnostics
                .lock()
                .await
                .values()
                .cloned(),
        );
        sockets.sort_by_key(|member| member.socket_index);
        sockets
    }

    /// Return the diagnostics for the dedicated IPv6 underlay socket, if bound.
    pub async fn ipv6_socket_diagnostics(&self) -> Option<UdpSocketPoolMemberDiagnostics> {
        self.ipv6_socket_diagnostics.lock().await.clone()
    }

    /// Aggregate receive-side probe counters across every bound UDP socket.
    ///
    /// The direct probe loops use this around a punch burst to distinguish
    /// "ACK was not matched" from the more useful runtime signal
    /// "no authenticated probe/ACK datagram reached this daemon at all".
    pub async fn probe_rx_snapshot(&self) -> UdpProbeRxSnapshot {
        let pool = self.socket_pool_diagnostics.lock().await.clone();
        let dynamic = self.dynamic_socket_diagnostics.lock().await.clone();
        let ipv6 = self.ipv6_socket_diagnostics.lock().await.clone();
        pool.into_iter()
            .chain(dynamic.into_values())
            .chain(ipv6)
            .fold(UdpProbeRxSnapshot::default(), |mut snapshot, member| {
                snapshot.known_peer_ip_datagrams_received = snapshot
                    .known_peer_ip_datagrams_received
                    .saturating_add(member.known_peer_ip_datagrams_received);
                snapshot.authenticated_probe_packets_received = snapshot
                    .authenticated_probe_packets_received
                    .saturating_add(member.authenticated_probe_packets_received);
                snapshot.authenticated_probe_acks_observed = snapshot
                    .authenticated_probe_acks_observed
                    .saturating_add(member.authenticated_probe_acks_observed);
                snapshot.authenticated_probe_acks_unmatched = snapshot
                    .authenticated_probe_acks_unmatched
                    .saturating_add(member.authenticated_probe_acks_unmatched);
                snapshot.legacy_probe_acks_observed = snapshot
                    .legacy_probe_acks_observed
                    .saturating_add(member.legacy_probe_acks_observed);
                snapshot.legacy_probe_acks_unmatched = snapshot
                    .legacy_probe_acks_unmatched
                    .saturating_add(member.legacy_probe_acks_unmatched);
                snapshot.probe_acks_received = snapshot
                    .probe_acks_received
                    .saturating_add(member.probe_acks_received);
                snapshot
            })
    }

    /// Return authenticated probe receive counters for exactly one peer in one
    /// local network generation and current Probe session. Unlike
    /// `probe_rx_snapshot`, this cannot be advanced by another peer sharing a
    /// socket pool or an older session for the same peer.
    #[allow(dead_code)]
    // retained for focused attribution tests; live loops pin a session below.
    pub(crate) async fn probe_rx_snapshot_for_peer(
        &self,
        peer_id: &str,
        generation: u64,
    ) -> UdpProbeRxSnapshot {
        let session_id = self.peers.probe_session_id_for_peer(peer_id).await;
        self.probe_rx_snapshot_for_peer_session(peer_id, generation, session_id.as_deref())
            .await
    }

    /// Read counters for the exact Probe-v2 session which was active when a
    /// punch task started.  Callers that take a before/after delta must keep
    /// this session value stable for the lifetime of that task: looking up
    /// the *current* binding at the end would otherwise accidentally compare
    /// two different rekey epochs.
    pub(crate) async fn probe_rx_snapshot_for_peer_session(
        &self,
        peer_id: &str,
        generation: u64,
        session_id: Option<&str>,
    ) -> UdpProbeRxSnapshot {
        let now = Instant::now();
        let mut diagnostics = self.peer_probe_rx_diagnostics.lock().await;
        diagnostics.retain(|_, entry| {
            now.saturating_duration_since(entry.last_updated) < PEER_PROBE_RX_DIAGNOSTICS_RETENTION
        });
        diagnostics
            .get(&(
                peer_id.to_string(),
                generation,
                session_id.map(str::to_string),
            ))
            .map(|entry| entry.snapshot)
            .unwrap_or_default()
    }

    /// Update bounded authenticated probe counters for one verified peer and
    /// generation.  The key is derived from the authenticated Probe-v2 source
    /// identity (or a matched pending probe for legacy compatibility), never
    /// from an unauthenticated source address.
    pub(crate) async fn update_peer_probe_rx_diagnostics(
        &self,
        peer_id: &str,
        generation: u64,
        session_id: Option<&str>,
        update: impl FnOnce(&mut UdpProbeRxSnapshot),
    ) {
        let now = Instant::now();
        let key = (
            peer_id.to_string(),
            generation,
            session_id.map(str::to_string),
        );
        let mut diagnostics = self.peer_probe_rx_diagnostics.lock().await;
        diagnostics.retain(|_, entry| {
            now.saturating_duration_since(entry.last_updated) < PEER_PROBE_RX_DIAGNOSTICS_RETENTION
        });
        if !diagnostics.contains_key(&key)
            && diagnostics.len() >= PEER_PROBE_RX_DIAGNOSTICS_MAX_ENTRIES
        {
            if let Some(oldest) = diagnostics
                .iter()
                .min_by_key(|(_, entry)| entry.last_updated)
                .map(|(key, _)| key.clone())
            {
                diagnostics.remove(&oldest);
            }
        }
        let entry = diagnostics.entry(key).or_insert_with(|| PeerProbeRxEntry {
            snapshot: UdpProbeRxSnapshot::default(),
            last_updated: now,
        });
        update(&mut entry.snapshot);
        entry.last_updated = now;
    }

    pub(super) async fn update_socket_diagnostics(
        &self,
        socket_index: usize,
        update: impl FnOnce(&mut UdpSocketPoolMemberDiagnostics),
    ) {
        if socket_index == IPV6_SOCKET_INDEX {
            if let Some(metrics) = self.ipv6_socket_diagnostics.lock().await.as_mut() {
                update(metrics);
            }
            return;
        }
        if socket_index >= DYNAMIC_SOCKET_INDEX_BASE {
            if let Some(metrics) = self
                .dynamic_socket_diagnostics
                .lock()
                .await
                .get_mut(&socket_index)
            {
                update(metrics);
            }
            return;
        }
        if let Some(diagnostics) = self
            .socket_pool_diagnostics
            .lock()
            .await
            .get_mut(socket_index)
        {
            update(diagnostics);
        }
    }

    /// Best-effort diagnostics update for the encrypted business-packet path.
    ///
    /// The UDP receive loop must not wait for a diagnostics mutex before it
    /// hands an authenticated-encrypted candidate to the bounded transport
    /// queue. Probe/control packets may use the awaited helper above because
    /// they are not on the normal data path; business packets use this helper
    /// only after enqueue and silently skip a contended sample.
    pub(super) fn update_socket_diagnostics_try(
        &self,
        socket_index: usize,
        update: impl FnOnce(&mut UdpSocketPoolMemberDiagnostics),
    ) {
        if socket_index == IPV6_SOCKET_INDEX {
            if let Ok(mut diagnostics) = self.ipv6_socket_diagnostics.try_lock() {
                if let Some(metrics) = diagnostics.as_mut() {
                    update(metrics);
                }
            }
            return;
        }
        if socket_index >= DYNAMIC_SOCKET_INDEX_BASE {
            if let Ok(mut diagnostics) = self.dynamic_socket_diagnostics.try_lock() {
                if let Some(metrics) = diagnostics.get_mut(&socket_index) {
                    update(metrics);
                }
            }
            return;
        }
        if let Ok(mut diagnostics) = self.socket_pool_diagnostics.try_lock() {
            if let Some(metrics) = diagnostics.get_mut(socket_index) {
                update(metrics);
            }
        }
    }

    /// Number of Hard↔Hard-owned pending probe transactions for one peer.
    /// Test-only lifecycle assertions use this to prove a failed synchronized
    /// attempt did not leave an ACK admission lease behind; ordinary recovery
    /// probes are intentionally outside this counter.
    #[cfg(test)]
    pub(crate) async fn hard_hard_pending_probe_count_for_test(&self, peer_id: &str) -> usize {
        let pending = self.pending_probes.lock().await;
        let hard_hard_bindings = self.hard_hard_probe_bindings.lock().await;
        pending
            .iter()
            .filter(|(nonce, probe)| {
                probe.peer_id.as_deref() == Some(peer_id) && hard_hard_bindings.contains_key(*nonce)
            })
            .count()
    }

    #[cfg(test)]
    pub(crate) async fn hard_hard_pending_probe_count_for_token_for_test(
        &self,
        peer_id: &str,
        token: &str,
    ) -> usize {
        let pending = self.pending_probes.lock().await;
        let hard_hard_bindings = self.hard_hard_probe_bindings.lock().await;
        pending
            .iter()
            .filter(|(nonce, probe)| {
                probe.peer_id.as_deref() == Some(peer_id)
                    && hard_hard_bindings
                        .get(*nonce)
                        .is_some_and(|bound| bound == token)
            })
            .count()
    }

    /// Redacted lifecycle evidence for deterministic Hard↔Hard timeout
    /// diagnostics. Tokens and nonces never leave this method; only an
    /// equality bit and a short process-local digest are exposed.
    #[cfg(test)]
    pub(crate) async fn hard_hard_udp_lifecycle_snapshot_for_test(
        &self,
        peer_id: &str,
        expected_token: Option<&str>,
    ) -> HardHardUdpLifecycleSnapshot {
        let token_digest = |token: &str| {
            let mut hasher = std::collections::hash_map::DefaultHasher::new();
            std::hash::Hash::hash(token, &mut hasher);
            format!("{:08x}", std::hash::Hasher::finish(&hasher) as u32)
        };
        let mut dynamic_sockets = {
            let state = self.socket_state.lock().await;
            let selected = state.affinity.get(peer_id).map(|pin| pin.socket_index);
            state
                .dynamic
                .values()
                .filter(|entry| entry.peer_id == peer_id)
                .map(|entry| HardHardDynamicSocketLifecycleSnapshot {
                    socket_index: entry.socket_index,
                    phase: entry.phase,
                    network_generation: entry.network_generation,
                    punch_generation: entry.punch_generation,
                    token_present: entry.hard_hard_session_token.is_some(),
                    token_matches_expected: expected_token.is_some_and(|expected| {
                        entry.hard_hard_session_token.as_deref() == Some(expected)
                    }),
                    token_digest: entry.hard_hard_session_token.as_deref().map(token_digest),
                    authenticated_evidence: entry.authenticated_evidence,
                    outstanding_send_leases: entry.send_leases.outstanding(),
                    pending_probe_count: 0,
                    reader_finished: entry.reader.is_finished(),
                    affinity_selected: selected == Some(entry.socket_index),
                })
                .collect::<Vec<_>>()
        };
        dynamic_sockets.sort_by_key(|entry| entry.socket_index);
        let dynamic_indices = dynamic_sockets
            .iter()
            .map(|entry| entry.socket_index)
            .collect::<HashSet<_>>();

        let now = Instant::now();
        let pending = self.pending_probes.lock().await;
        let bindings = self.hard_hard_probe_bindings.lock().await;
        let mut pending_probes = pending
            .iter()
            .filter_map(|(nonce, probe)| {
                let binding = bindings.get(nonce);
                let peer_matches = probe.peer_id.as_deref() == Some(peer_id);
                let token_matches_expected = expected_token
                    .zip(binding.map(String::as_str))
                    .is_some_and(|(expected, actual)| expected == actual);
                (peer_matches
                    && (binding.is_some() || dynamic_indices.contains(&probe.socket_index))
                    || token_matches_expected)
                    .then_some(HardHardPendingProbeLifecycleSnapshot {
                        socket_index: probe.socket_index,
                        token_matches_expected,
                        peer_matches,
                        expired: probe.is_expired(now),
                        binding_present: binding.is_some(),
                    })
            })
            .collect::<Vec<_>>();
        pending_probes.sort_by_key(|probe| probe.socket_index);
        for socket in &mut dynamic_sockets {
            socket.pending_probe_count = pending_probes
                .iter()
                .filter(|probe| probe.socket_index == socket.socket_index)
                .count();
        }
        let orphan_probe_bindings = bindings
            .keys()
            .filter(|nonce| !pending.contains_key(*nonce))
            .count();

        HardHardUdpLifecycleSnapshot {
            peer_id: peer_id.to_string(),
            expected_token_present: expected_token.is_some(),
            dynamic_sockets,
            pending_probes,
            orphan_probe_bindings,
        }
    }
}
