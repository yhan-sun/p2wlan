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
        self.connections
            .read()
            .await
            .values()
            .filter(|conn| {
                conn.state != ConnectionState::Direct
                    || conn
                        .direct_health
                        .rtt_ewma_ms
                        .or(conn.direct_health.latency_ms)
                        .is_some_and(|rtt| rtt >= SLOW_DIRECT_RELAY_VALIDATION_RTT_MS)
            })
            .filter(|conn| !conn.relay_health.is_confirmed_recent(max_success_age))
            .map(|conn| (conn.node_id.clone(), conn.virtual_ip.clone()))
            .collect()
    }

    /// Get serializable diagnostics for every peer.
    pub async fn diagnostics(&self) -> Vec<PeerDiagnostics> {
        let generation = self.current_network_generation().await;
        let traversal_history = self.traversal_history.read().await.clone();
        let mut peers: Vec<_> = self
            .connections
            .read()
            .await
            .values()
            .map(|conn| {
                PeerDiagnostics::from_connection_with_path_selection(
                    conn,
                    None,
                    None,
                    generation,
                    None,
                    Some(&traversal_history),
                )
            })
            .collect();
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
        let generation = self.current_network_generation().await;
        let traversal_history = self.traversal_history.read().await.clone();
        let mut peers: Vec<_> = self
            .connections
            .read()
            .await
            .values()
            .map(|conn| {
                let current_selection =
                    conn.select_path_for_data(generation, prefer_direct, relay_available);
                PeerDiagnostics::from_connection_with_path_selection(
                    conn,
                    Some(&current_selection),
                    Some(direct_retry_after),
                    generation,
                    local_endpoint,
                    Some(&traversal_history),
                )
            })
            .collect();
        peers.sort_by(|a, b| a.node_id.cmp(&b.node_id));
        peers
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
        }
    }
}
