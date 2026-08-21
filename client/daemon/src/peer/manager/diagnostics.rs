impl PeerManager {
    /// Record bytes sent to a peer.
    pub async fn record_sent(&self, node_id: &str, n: u64) {
        if let Some(conn) = self.connections.write().await.get_mut(node_id) {
            conn.record_sent(n);
        }
    }

    /// Record bytes received from a peer.
    pub async fn record_received(&self, node_id: &str, n: u64) {
        if let Some(conn) = self.connections.write().await.get_mut(node_id) {
            conn.record_received(n);
        }
    }

    /// Get all active connections.
    pub async fn active_connections(&self) -> Vec<PeerConnection> {
        self.connections
            .read()
            .await
            .values()
            .filter(|c| c.is_active())
            .cloned()
            .collect()
    }

    /// Get all connections (including inactive).
    pub async fn all_connections(&self) -> Vec<PeerConnection> {
        self.connections.read().await.values().cloned().collect()
    }

    /// Return peers that need an active relay data-plane confirmation.
    pub async fn relay_validation_targets(
        &self,
        max_success_age: Duration,
    ) -> Vec<(String, String)> {
        // A relay `peer_not_found` starts a bounded registration-handoff
        // grace window. The dedicated forced-relay probe loop owns the fast,
        // per-peer retry during that window. This slower validation loop must
        // stay quiet so it does not duplicate the retry or consume the shared
        // relay writer lane; once the grace expires it may re-check the
        // registration and a second 404 can enter quarantine.
        let grace_peers = self.relay_not_found_grace_peers().await;
        let candidates: Vec<_> = self
            .connections
            .read()
            .await
            .values()
            .filter(|conn| {
                // The validation loop is a proactive data-plane check, not a
                // cleanup mechanism for the historical peer roster. Offline
                // and closed peers are not registered at the relay; sending
                // to them every five seconds creates a 404 storm, consumes
                // the relay writer lane, and can delay the current peer's
                // probe. They are handled by lifecycle cleanup instead.
                conn.online
                    && conn.state != ConnectionState::Closed
                    && !grace_peers.contains(&conn.node_id)
                    && (conn.state != ConnectionState::Direct
                    || conn
                        .direct_health
                        .rtt_ewma_ms
                        .or(conn.direct_health.latency_ms)
                        .is_some_and(|rtt| rtt >= SLOW_DIRECT_RELAY_VALIDATION_RTT_MS))
            })
            .filter(|conn| !conn.relay_health.is_confirmed_recent(max_success_age))
            .map(|conn| (conn.node_id.clone(), conn.virtual_ip.clone()))
            .collect();
        let mut targets = Vec::with_capacity(candidates.len());
        for candidate in candidates {
            if !self.peer_quarantined(&candidate.0).await {
                targets.push(candidate);
            }
        }
        targets
    }

    /// Get serializable diagnostics for every peer.
    pub async fn diagnostics(&self) -> Vec<PeerDiagnostics> {
        // Diagnostics is a read-only fast path.  Do not wait behind the
        // network-generation write lock here: a generation transition may
        // legitimately hold that lock while it invalidates live paths.  The
        // atomic mirror is published in the same critical section and is the
        // value already used by the dataplane-safe diagnostics path below.
        let generation = self.current_network_generation_sync();
        let profile_generation = self.current_local_profile_generation_sync();
        let local_nat_capabilities = self
            .local_nat_profile
            .try_read()
            .ok()
            .and_then(|profile| {
                profile.as_ref().map(|profile| {
                    NatCapabilities::from_profile(profile).with_profile_generation(profile_generation)
                })
            });
        let relay_available = self.relay_first_required();
        let traversal_history = self
            .traversal_history
            .try_read()
            .map(|history| history.clone())
            .unwrap_or_default();
        let fresh_mapping_history = self
            .fresh_mapping_history
            .try_lock()
            .map(|history| history.clone())
            .unwrap_or_default();
        let recovery_reports = self.recovery_epoch_diagnostics();
        let mut peers: Vec<_> = self
            .connections
            .try_read()
            .map(|connections| {
                connections
                    .values()
                    .map(|conn| {
                        let mut diagnostics = PeerDiagnostics::from_connection_with_path_selection(
                            conn,
                            None,
                            None,
                            generation,
                            None,
                            local_nat_capabilities.as_ref(),
                            relay_available,
                            Some(&traversal_history),
                            Some(&fresh_mapping_history),
                        );
                        diagnostics.recovery = recovery_reports.get(&conn.node_id).cloned();
                        diagnostics
                    })
                    .collect()
            })
            .unwrap_or_default();
        peers.sort_by(|a, b| a.node_id.cmp(&b.node_id));
        peers
    }

    /// Get diagnostics with the live path-selector decision for every peer.
    ///
    /// This does not update `last_path_selection`; it is a read-only snapshot
    /// used by CLI/UI diagnostics to explain why data would use Direct or Relay
    /// right now.
    pub async fn diagnostics_with_path_selection(
        &self,
        prefer_direct: bool,
        relay_available: bool,
        direct_retry_after: Duration,
        local_endpoint: Option<SocketAddr>,
    ) -> Vec<PeerDiagnostics> {
        // Use the lock-free generation mirror so a busy handover cannot make
        // /status or /peers wait until the diagnostics timeout.
        let generation = self.current_network_generation_sync();
        let profile_generation = self.current_local_profile_generation_sync();
        let local_nat_capabilities = self
            .local_nat_profile
            .try_read()
            .ok()
            .and_then(|profile| {
                profile.as_ref().map(|profile| {
                    NatCapabilities::from_profile(profile).with_profile_generation(profile_generation)
                })
            });
        let traversal_history = self
            .traversal_history
            .try_read()
            .map(|history| history.clone())
            .unwrap_or_default();
        let fresh_mapping_history = self
            .fresh_mapping_history
            .try_lock()
            .map(|history| history.clone())
            .unwrap_or_default();
        let recovery_reports = self.recovery_epoch_diagnostics();
        let mut peers: Vec<_> = self
            .connections
            .try_read()
            .map(|connections| {
                connections
                    .values()
                    .map(|conn| {
                        let current_selection =
                            conn.select_path_for_data(generation, prefer_direct, relay_available);
                        let mut diagnostics = PeerDiagnostics::from_connection_with_path_selection(
                            conn,
                            Some(&current_selection),
                            Some(direct_retry_after),
                            generation,
                            local_endpoint,
                            local_nat_capabilities.as_ref(),
                            relay_available,
                            Some(&traversal_history),
                            Some(&fresh_mapping_history),
                        );
                        diagnostics.recovery = recovery_reports.get(&conn.node_id).cloned();
                        diagnostics
                    })
                    .collect()
            })
            .unwrap_or_default();
        peers.sort_by(|a, b| a.node_id.cmp(&b.node_id));
        peers
    }

    /// Return one peer's diagnostics from a single connection-lock snapshot.
    ///
    /// The diagnostics HTTP fast path uses this instead of materializing every
    /// peer in a large control network.  The selector decision is computed
    /// from one immutable connection snapshot.  Diagnostics must not acquire
    /// the network epoch gate: that gate is reserved for dataplane state
    /// transitions, and making a read-only status request wait behind a
    /// generation cancellation can make the health endpoint report a false
    /// outage while relay traffic is still progressing.
    pub async fn diagnostic_with_path_selection(
        &self,
        node_id: &str,
        prefer_direct: bool,
        relay_available: bool,
        direct_retry_after: Duration,
        local_endpoint: Option<SocketAddr>,
    ) -> Option<(u64, PeerDiagnostics)> {
        let traversal_history = self
            .traversal_history
            .try_read()
            .map(|history| history.clone())
            .unwrap_or_default();
        let fresh_mapping_history = self
            .fresh_mapping_history
            .try_lock()
            .map(|history| history.clone())
            .unwrap_or_default();
        let recovery = self.recovery_epoch_diagnostics().remove(node_id);
        let generation = self.current_network_generation_sync();
        let profile_generation = self.current_local_profile_generation_sync();
        let local_nat_capabilities = self
            .local_nat_profile
            .try_read()
            .ok()
            .and_then(|profile| {
                profile.as_ref().map(|profile| {
                    NatCapabilities::from_profile(profile).with_profile_generation(profile_generation)
                })
            });
        let conns = self.connections.try_read().ok()?;
        let conn = conns.get(node_id)?;
        let current_selection =
            conn.select_path_for_data(generation, prefer_direct, relay_available);
        let mut diagnostics = PeerDiagnostics::from_connection_with_path_selection(
            conn,
            Some(&current_selection),
            Some(direct_retry_after),
            generation,
            local_endpoint,
            local_nat_capabilities.as_ref(),
            relay_available,
            Some(&traversal_history),
            Some(&fresh_mapping_history),
        );
        diagnostics.recovery = recovery;
        Some((generation, diagnostics))
    }

    /// Number of active peers. Offline control records do not count toward
    /// the isolated two-device acceptance guard.
    pub async fn active_connection_count(&self) -> usize {
        self.connections
            .read()
            .await
            .values()
            .filter(|connection| connection.is_active())
            .count()
    }

    /// Serialized recovery-epoch budget reports for every peer with an active
    /// recovery epoch: the hard per-epoch ceilings (probe credit,
    /// fresh-mapping generations, HTTP publishes) are surfaced in status.
    fn recovery_epoch_diagnostics(&self) -> HashMap<String, RecoveryEpochDiagnostics> {
        let now = Instant::now();
        let Ok(epochs) = self.recovery_epochs.try_read() else {
            return HashMap::new();
        };
        let mut reports = HashMap::new();
        for (peer_id, state) in epochs.iter() {
            reports.insert(
                peer_id.clone(),
                RecoveryEpochDiagnostics {
                    epoch: state.epoch,
                    stage: state.stage.label().to_string(),
                    stage_age_ms: duration_millis(now.saturating_duration_since(state.stage_started_at)),
                    epoch_age_ms: duration_millis(now.saturating_duration_since(state.epoch_started_at)),
                    probe_credit_remaining: state.epoch_probe_credit_remaining,
                    fresh_generation_quota_remaining: state.epoch_fresh_generation_quota_remaining,
                    http_quota_remaining: state.epoch_http_quota_remaining,
                    scatter_windows_sent: state.epoch_scatter_windows_sent,
                    ack_feedback_seen: state.ack_feedback_seen,
                },
            );
        }
        reports
    }

    /// Get connection statistics.
    pub async fn stats(&self) -> PeerManagerStats {
        let conns = self.connections.read().await;
        let total = conns.len();
        let direct = conns
            .values()
            .filter(|c| c.state == ConnectionState::Direct)
            .count();
        let relay = conns
            .values()
            .filter(|c| c.state == ConnectionState::Relay)
            .count();
        let total_bytes_sent = conns.values().map(|c| c.bytes_sent).sum();
        let total_bytes_received = conns.values().map(|c| c.bytes_received).sum();

        PeerManagerStats {
            total_peers: total,
            direct_connections: direct,
            relay_connections: relay,
            total_bytes_sent,
            total_bytes_received,
            outbound_drops: HashMap::new(),
            outbound_send_failures: HashMap::new(),
            outbound_loss_events: Vec::new(),
        }
    }
}

#[cfg(test)]
mod diagnostics_tests {
    use super::*;

    #[tokio::test]
    async fn full_diagnostics_does_not_wait_for_generation_writer() {
        let config = Config::generate_default("http://ctrl.test", "default").unwrap();
        let manager = PeerManager::new(config);
        let _generation_writer = manager.network_generation.write().await;
        let _connection_writer = manager.connections.write().await;

        let result = tokio::time::timeout(
            Duration::from_millis(100),
            manager.diagnostics_with_path_selection(
                true,
                false,
                DIRECT_RETRY_BASE_INTERVAL,
                None,
            ),
        )
        .await;

        assert!(result.is_ok());
        assert!(result.unwrap().is_empty());
    }
}
