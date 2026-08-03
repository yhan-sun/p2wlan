impl PeerManager {
    /// Record a successful direct-path event.
    pub async fn record_direct_success(&self, node_id: &str, endpoint: Option<SocketAddr>) {
        self.record_direct_success_with_local_endpoint(node_id, endpoint, None)
            .await;
    }

    /// Record a successful direct-path event with the local UDP endpoint that received it.
    pub async fn record_direct_success_with_local_endpoint(
        &self,
        node_id: &str,
        endpoint: Option<SocketAddr>,
        local_endpoint: Option<SocketAddr>,
    ) {
        let generation = self.current_network_generation().await;
        self.record_direct_success_for_generation_with_local_endpoint(
            node_id,
            endpoint,
            generation,
            local_endpoint,
        )
        .await;
    }

    /// Record a successful direct-path event for a specific local network generation.
    /// Returns false when the result belongs to an old generation and was ignored.
    pub async fn record_direct_success_for_generation(
        &self,
        node_id: &str,
        endpoint: Option<SocketAddr>,
        generation: u64,
    ) -> bool {
        self.record_direct_success_for_generation_with_local_endpoint(
            node_id, endpoint, generation, None,
        )
        .await
    }

    /// Record a successful direct-path event for a specific local network generation.
    /// Returns false when the result belongs to an old generation and was ignored.
    pub async fn record_direct_success_for_generation_with_local_endpoint(
        &self,
        node_id: &str,
        endpoint: Option<SocketAddr>,
        generation: u64,
        local_endpoint: Option<SocketAddr>,
    ) -> bool {
        if generation != self.current_network_generation().await {
            return false;
        }
        let pair_success = {
            let mut conns = self.connections.write().await;
            let Some(conn) = conns.get_mut(node_id) else {
                return false;
            };
            let was_direct = conn.state == ConnectionState::Direct;
            let previous_endpoint = conn.endpoint;
            let previous_generation = conn.direct_generation;
            let selected_endpoint = endpoint.or(conn.endpoint);
            let pair_success = selected_endpoint.map(|endpoint| {
                conn.endpoint = Some(endpoint);
                conn.mark_candidate_pair_success(endpoint, generation, None, true, local_endpoint)
            });
            let direct_confirmation_changed = !was_direct
                || previous_endpoint != selected_endpoint
                || previous_generation != generation;
            conn.direct_generation = generation;
            conn.direct_health.record_success();
            conn.clear_direct_reclaim_window();
            if direct_confirmation_changed {
                conn.record_direct_event(
                    generation,
                    "direct_confirmed",
                    selected_endpoint,
                    selected_endpoint.map(|_| 1),
                    None,
                    "encrypted data path confirmed Direct UDP",
                );
            }
            conn.transition(ConnectionState::Direct);
            if let (Some(endpoint), Some((source, _))) = (selected_endpoint, pair_success) {
                let direct_type = classify_confirmed_direct_endpoint(endpoint, source);
                let local_endpoint_text = format_log_endpoint(local_endpoint);
                if direct_confirmation_changed {
                    info!(
                        event = "candidate_pair_selected",
                        peer_id = %node_id,
                        local_endpoint = %local_endpoint_text,
                        remote_endpoint = %endpoint,
                        candidate_source = ?source,
                        rtt_ms = ?conn.direct_health.rtt_ewma_ms.or(conn.direct_health.latency_ms),
                        reason = "encrypted data path confirmed Direct UDP",
                        "candidate_pair_selected peer_id={} remote_endpoint={} reason=encrypted data path confirmed Direct UDP",
                        node_id,
                        endpoint
                    );
                }
                if !was_direct {
                    info!(
                        event = "direct_path_promoted",
                        peer_id = %node_id,
                        local_endpoint = %local_endpoint_text,
                        remote_endpoint = %endpoint,
                        candidate_source = ?source,
                        rtt_ms = ?conn.direct_health.rtt_ewma_ms.or(conn.direct_health.latency_ms),
                        reason = "encrypted data path confirmed Direct UDP",
                        "direct_path_promoted peer_id={} remote_endpoint={} reason=encrypted data path confirmed Direct UDP",
                        node_id,
                        endpoint
                    );
                }
                if direct_confirmation_changed {
                    match direct_type {
                        DirectPathType::PublicUdp => info!(
                            event = "public_udp_direct_selected",
                            peer_id = %node_id,
                            local_endpoint = %local_endpoint_text,
                            remote_endpoint = %endpoint,
                            candidate_source = ?source,
                            rtt_ms = ?conn.direct_health.rtt_ewma_ms.or(conn.direct_health.latency_ms),
                            reason = "encrypted data path confirmed Direct UDP",
                            "public_udp_direct_selected peer_id={} remote_endpoint={}",
                            node_id,
                            endpoint
                        ),
                        DirectPathType::PeerReflexive => info!(
                            event = "peer_reflexive_direct_selected",
                            peer_id = %node_id,
                            local_endpoint = %local_endpoint_text,
                            remote_endpoint = %endpoint,
                            candidate_source = ?source,
                            rtt_ms = ?conn.direct_health.rtt_ewma_ms.or(conn.direct_health.latency_ms),
                            reason = "encrypted data path confirmed Direct UDP",
                            "peer_reflexive_direct_selected peer_id={} remote_endpoint={}",
                            node_id,
                            endpoint
                        ),
                        DirectPathType::Overlay => info!(
                            event = "overlay_direct_selected",
                            peer_id = %node_id,
                            local_endpoint = %local_endpoint_text,
                            remote_endpoint = %endpoint,
                            candidate_source = ?source,
                            rtt_ms = ?conn.direct_health.rtt_ewma_ms.or(conn.direct_health.latency_ms),
                            reason = "encrypted data path confirmed Direct UDP",
                            "overlay_direct_selected peer_id={} remote_endpoint={}",
                            node_id,
                            endpoint
                        ),
                        DirectPathType::Lan => info!(
                            event = "lan_direct_selected",
                            peer_id = %node_id,
                            local_endpoint = %local_endpoint_text,
                            remote_endpoint = %endpoint,
                            candidate_source = ?source,
                            rtt_ms = ?conn.direct_health.rtt_ewma_ms.or(conn.direct_health.latency_ms),
                            reason = "encrypted data path confirmed Direct UDP",
                            "lan_direct_selected peer_id={} remote_endpoint={}",
                            node_id,
                            endpoint
                        ),
                        _ => {}
                    }
                }
            }
            pair_success
        };
        if let Some((source, true)) = pair_success {
            self.record_traversal_success(source).await;
        }
        true
    }

    /// Record that a UDP punch endpoint is reachable. A matched ACK confirms
    /// bidirectional UDP reachability; an inbound punch alone remains provisional.
    pub async fn record_direct_probe_success(&self, node_id: &str, endpoint: SocketAddr) {
        self.record_direct_probe_success_with_local_endpoint(node_id, endpoint, None)
            .await;
    }

    /// Record that a UDP punch endpoint is reachable with the local socket that saw it.
    pub async fn record_direct_probe_success_with_local_endpoint(
        &self,
        node_id: &str,
        endpoint: SocketAddr,
        local_endpoint: Option<SocketAddr>,
    ) {
        self.record_direct_probe_success_with_latency_and_local_endpoint(
            node_id,
            endpoint,
            None,
            local_endpoint,
        )
        .await;
    }

    /// Record a successful direct-path probe and its measured round-trip time.
    pub async fn record_direct_probe_success_with_latency(
        &self,
        node_id: &str,
        endpoint: SocketAddr,
        latency: Option<Duration>,
    ) {
        self.record_direct_probe_success_with_latency_and_local_endpoint(
            node_id, endpoint, latency, None,
        )
        .await;
    }

    /// Record a successful direct-path probe, latency, and local UDP endpoint.
    pub async fn record_direct_probe_success_with_latency_and_local_endpoint(
        &self,
        node_id: &str,
        endpoint: SocketAddr,
        latency: Option<Duration>,
        local_endpoint: Option<SocketAddr>,
    ) {
        let generation = self.current_network_generation().await;
        self.record_direct_probe_success_with_latency_for_generation_and_local_endpoint(
            node_id,
            endpoint,
            latency,
            generation,
            local_endpoint,
        )
        .await;
    }

    /// Record a direct-path probe result for a specific local network generation.
    /// Returns false when the result belongs to an old generation and was ignored.
    pub async fn record_direct_probe_success_with_latency_for_generation(
        &self,
        node_id: &str,
        endpoint: SocketAddr,
        latency: Option<Duration>,
        generation: u64,
    ) -> bool {
        self.record_direct_probe_success_with_latency_for_generation_and_local_endpoint(
            node_id, endpoint, latency, generation, None,
        )
        .await
    }

    /// Record a direct-path probe result for a specific local network generation.
    /// Returns false when the result belongs to an old generation and was ignored.
    pub async fn record_direct_probe_success_with_latency_for_generation_and_local_endpoint(
        &self,
        node_id: &str,
        endpoint: SocketAddr,
        latency: Option<Duration>,
        generation: u64,
        local_endpoint: Option<SocketAddr>,
    ) -> bool {
        if generation != self.current_network_generation().await {
            return false;
        }
        let pair_success = {
            let mut conns = self.connections.write().await;
            let Some(conn) = conns.get_mut(node_id) else {
                return false;
            };
            conn.endpoint = Some(endpoint);
            let ack_confirmed = latency.is_some();
            let pair_success = if ack_confirmed {
                Some(conn.mark_candidate_pair_success(
                    endpoint,
                    generation,
                    latency,
                    false,
                    local_endpoint,
                ))
            } else {
                conn.mark_candidate_pair_probing_with_local_endpoint(
                    endpoint,
                    generation,
                    local_endpoint,
                );
                None
            };
            match latency {
                Some(latency) => {
                    conn.direct_health.record_success_with_latency(latency);
                    if let Some((source, true)) = pair_success {
                        conn.record_direct_event(
                            generation,
                            "probe_ack_received",
                            Some(endpoint),
                            Some(1),
                            None,
                            format!(
                                "received UDP punch ACK from {endpoint} rtt={}ms",
                                duration_millis(latency)
                            ),
                        );
                        let local_endpoint_text = format_log_endpoint(local_endpoint);
                        info!(
                            event = "candidate_pair_probe_succeeded",
                            peer_id = %node_id,
                            local_endpoint = %local_endpoint_text,
                            remote_endpoint = %endpoint,
                            candidate_source = ?source,
                            rtt_ms = duration_millis(latency),
                            reason = "received UDP punch ACK",
                            "candidate_pair_probe_succeeded peer_id={} remote_endpoint={} rtt_ms={}",
                            node_id,
                            endpoint,
                            duration_millis(latency)
                        );
                    }
                }
                None => conn.direct_health.record_success(),
            }
            if !ack_confirmed {
                conn.record_direct_event(
                    generation,
                    "inbound_probe_received",
                    Some(endpoint),
                    Some(1),
                    None,
                    format!("received inbound UDP probe from {endpoint}"),
                );
            }
            if conn.state != ConnectionState::Direct
                && matches!(
                    conn.state,
                    ConnectionState::Idle
                        | ConnectionState::Connecting
                        | ConnectionState::FallbackToRelay
                )
            {
                conn.transition(ConnectionState::HolePunching);
            }
            pair_success
        };
        if let Some((source, true)) = pair_success {
            self.record_traversal_success(source).await;
        }
        true
    }
}
