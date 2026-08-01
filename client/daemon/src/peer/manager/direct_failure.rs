impl PeerManager {
    /// Record a failed direct-path event and enter relay fallback state.
    pub async fn record_direct_failure(&self, node_id: &str, reason: impl Into<String>) {
        self.record_direct_failure_with_code(node_id, REASON_DIRECT_PROBE_FAILED, reason)
            .await;
    }

    /// Record a failed direct-path event with a stable reason code.
    pub async fn record_direct_failure_with_code(
        &self,
        node_id: &str,
        code: impl Into<String>,
        reason: impl Into<String>,
    ) {
        self.record_direct_failure_with_code_and_local_endpoint(node_id, code, reason, None)
            .await;
    }

    /// Record a failed direct-path event with a stable reason code and local UDP endpoint.
    pub async fn record_direct_failure_with_code_and_local_endpoint(
        &self,
        node_id: &str,
        code: impl Into<String>,
        reason: impl Into<String>,
        local_endpoint: Option<SocketAddr>,
    ) {
        let generation = self.current_network_generation().await;
        self.record_direct_failure_for_generation_with_local_endpoint(
            node_id,
            generation,
            code,
            reason,
            local_endpoint,
        )
        .await;
    }

    /// Record a failed direct-path event for a specific local network generation.
    /// Returns false when the result belongs to an old generation and was ignored.
    pub async fn record_direct_failure_for_generation(
        &self,
        node_id: &str,
        generation: u64,
        code: impl Into<String>,
        reason: impl Into<String>,
    ) -> bool {
        self.record_direct_failure_for_generation_with_local_endpoint(
            node_id, generation, code, reason, None,
        )
        .await
    }

    /// Record a failed direct-path event for a specific local network generation.
    /// Returns false when the result belongs to an old generation and was ignored.
    pub async fn record_direct_failure_for_generation_with_local_endpoint(
        &self,
        node_id: &str,
        generation: u64,
        code: impl Into<String>,
        reason: impl Into<String>,
        local_endpoint: Option<SocketAddr>,
    ) -> bool {
        if generation != self.current_network_generation().await {
            return false;
        }
        let probed_sources = {
            let mut conns = self.connections.write().await;
            let Some(conn) = conns.get_mut(node_id) else {
                return false;
            };
            let code = code.into();
            let reason = reason.into();
            conn.direct_health
                .record_failure(code.clone(), reason.clone());
            conn.record_direct_event(
                generation,
                code.clone(),
                conn.endpoint,
                Some(conn.candidate_pairs.len()),
                None,
                reason.clone(),
            );
            let probed_sources =
                conn.mark_current_candidate_pairs_failed(generation, code, reason, local_endpoint);
            if conn.state != ConnectionState::Relay {
                conn.transition(ConnectionState::FallbackToRelay);
                let local_endpoint_text = format_log_endpoint(local_endpoint);
                info!(
                    event = "direct_path_degraded",
                    peer_id = %node_id,
                    local_endpoint = %local_endpoint_text,
                    remote_endpoint = ?conn.endpoint,
                    candidate_source = ?conn.endpoint.and_then(|endpoint| {
                        conn.candidate_pairs
                            .iter()
                            .find(|pair| {
                                pair.local_generation == generation
                                    && pair.remote_endpoint == endpoint
                            })
                            .map(|pair| pair.source)
                    }),
                    rtt_ms = ?conn.direct_health.rtt_ewma_ms.or(conn.direct_health.latency_ms),
                    reason = %conn.direct_health.last_error.as_deref().unwrap_or("direct path failed"),
                    "direct_path_degraded peer_id={} reason={}",
                    node_id,
                    conn.direct_health.last_error.as_deref().unwrap_or("direct path failed")
                );
            }
            probed_sources
        };
        self.record_traversal_failures(probed_sources).await;
        true
    }

    /// Record an unanswered direct keepalive without tearing down a path on one lost probe.
    pub async fn record_direct_keepalive_timeout_for_generation(
        &self,
        node_id: &str,
        endpoint: SocketAddr,
        generation: u64,
    ) -> bool {
        self.record_direct_keepalive_timeout_for_generation_with_local_endpoint(
            node_id, endpoint, generation, None,
        )
        .await
    }

    /// Record an unanswered direct keepalive and the local UDP endpoint that sent it.
    pub async fn record_direct_keepalive_timeout_for_generation_with_local_endpoint(
        &self,
        node_id: &str,
        endpoint: SocketAddr,
        generation: u64,
        local_endpoint: Option<SocketAddr>,
    ) -> bool {
        if generation != self.current_network_generation().await {
            return false;
        }

        let source = {
            let mut conns = self.connections.write().await;
            let Some(conn) = conns.get_mut(node_id) else {
                return false;
            };
            if conn.direct_generation != generation || conn.state != ConnectionState::Direct {
                return false;
            }

            let reason = format!("direct keepalive ACK timeout for {endpoint}");
            conn.direct_health
                .record_failure(REASON_DIRECT_KEEPALIVE_TIMEOUT, reason.clone());
            let peer_id = conn.node_id.clone();
            let pair = conn.ensure_candidate_pair(endpoint, generation);
            let source = pair.source;
            let old_state = pair.state;
            pair.record_failure(
                REASON_DIRECT_KEEPALIVE_TIMEOUT,
                reason.clone(),
                local_endpoint,
            );
            log_candidate_pair_state_changed(&peer_id, pair, old_state, &reason);

            if conn.direct_health.consecutive_failures >= DIRECT_KEEPALIVE_FAILURE_THRESHOLD {
                conn.transition(ConnectionState::FallbackToRelay);
                let local_endpoint_text = format_log_endpoint(local_endpoint);
                info!(
                    event = "direct_path_degraded",
                    peer_id = %node_id,
                    local_endpoint = %local_endpoint_text,
                    remote_endpoint = %endpoint,
                    candidate_source = ?source,
                    rtt_ms = ?conn.direct_health.rtt_ewma_ms.or(conn.direct_health.latency_ms),
                    reason = "direct keepalive failure threshold reached",
                    "direct_path_degraded peer_id={} remote_endpoint={} reason=direct keepalive failure threshold reached",
                    node_id,
                    endpoint
                );
            }
            source
        };
        self.record_traversal_failures(vec![source]).await;
        true
    }
}
