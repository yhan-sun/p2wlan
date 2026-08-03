impl PeerConnection {
    fn record_path_selection_event(
        &mut self,
        local_generation: u64,
        selection: &PathSelection,
        local_endpoint: Option<SocketAddr>,
    ) {
        let previous = self.last_path_selection.as_ref();
        let changed = previous
            .map(|previous| {
                previous.path != selection.path
                    || previous.reason_code != selection.reason_code
                    || previous.direct_endpoint != selection.direct_endpoint
                    || previous.relay_hedged != selection.relay_hedged
            })
            .unwrap_or(true);
        if !changed {
            return;
        }

        let previous_path = previous.and_then(|selection| selection.path);
        let pair = selection.direct_endpoint.and_then(|endpoint| {
            self.candidate_pairs.iter().find(|pair| {
                pair.local_generation == local_generation && pair.remote_endpoint == endpoint
            })
        });
        let remote_endpoint = selection.direct_endpoint;
        let remote_endpoint_text = match selection.path {
            Some(NetworkPath::Relay) => self
                .relay_server
                .clone()
                .unwrap_or_else(|| "unknown".to_string()),
            _ => remote_endpoint
                .map(|endpoint| endpoint.to_string())
                .unwrap_or_else(|| "unknown".to_string()),
        };
        let local_endpoint_text = format_log_endpoint(
            local_endpoint.or_else(|| pair.and_then(|pair| pair.local_endpoint)),
        );
        let candidate_source = pair.map(|pair| pair.source);
        let rtt_ms = pair.and_then(|pair| pair.rtt_ewma_ms.or(pair.rtt_ms));
        let direct_type =
            classify_candidate_pair_path(selection.path, pair, selection.direct_confirmed);

        if selection.path == Some(NetworkPath::Direct) && selection.direct_confirmed {
            info!(
                event = "candidate_pair_selected",
                peer_id = %self.node_id,
                local_endpoint = %local_endpoint_text,
                remote_endpoint = %remote_endpoint_text,
                candidate_source = ?candidate_source,
                rtt_ms = ?rtt_ms,
                reason = %selection.reason,
                "candidate_pair_selected peer_id={} remote_endpoint={:?} reason={}",
                self.node_id,
                remote_endpoint,
                selection.reason
            );
            match direct_type {
                DirectPathType::PublicUdp => info!(
                    event = "public_udp_direct_selected",
                    peer_id = %self.node_id,
                    local_endpoint = %local_endpoint_text,
                    remote_endpoint = %remote_endpoint_text,
                    candidate_source = ?candidate_source,
                    rtt_ms = ?rtt_ms,
                    reason = %selection.reason,
                    "public_udp_direct_selected peer_id={} remote_endpoint={:?} reason={}",
                    self.node_id,
                    remote_endpoint,
                    selection.reason
                ),
                DirectPathType::PeerReflexive => info!(
                    event = "peer_reflexive_direct_selected",
                    peer_id = %self.node_id,
                    local_endpoint = %local_endpoint_text,
                    remote_endpoint = %remote_endpoint_text,
                    candidate_source = ?candidate_source,
                    rtt_ms = ?rtt_ms,
                    reason = %selection.reason,
                    "peer_reflexive_direct_selected peer_id={} remote_endpoint={:?} reason={}",
                    self.node_id,
                    remote_endpoint,
                    selection.reason
                ),
                DirectPathType::Overlay => info!(
                    event = "overlay_direct_selected",
                    peer_id = %self.node_id,
                    local_endpoint = %local_endpoint_text,
                    remote_endpoint = %remote_endpoint_text,
                    candidate_source = ?candidate_source,
                    rtt_ms = ?rtt_ms,
                    reason = %selection.reason,
                    "overlay_direct_selected peer_id={} remote_endpoint={:?} reason={}",
                    self.node_id,
                    remote_endpoint,
                    selection.reason
                ),
                DirectPathType::Lan => info!(
                    event = "lan_direct_selected",
                    peer_id = %self.node_id,
                    local_endpoint = %local_endpoint_text,
                    remote_endpoint = %remote_endpoint_text,
                    candidate_source = ?candidate_source,
                    rtt_ms = ?rtt_ms,
                    reason = %selection.reason,
                    "lan_direct_selected peer_id={} remote_endpoint={:?} reason={}",
                    self.node_id,
                    remote_endpoint,
                    selection.reason
                ),
                _ => {}
            }
        }

        if selection.path == Some(NetworkPath::Direct) && previous_path != Some(NetworkPath::Direct)
        {
            info!(
                event = "direct_path_promoted",
                peer_id = %self.node_id,
                local_endpoint = %local_endpoint_text,
                remote_endpoint = %remote_endpoint_text,
                candidate_source = ?candidate_source,
                rtt_ms = ?rtt_ms,
                reason = %selection.reason,
                "direct_path_promoted peer_id={} remote_endpoint={:?} reason={}",
                self.node_id,
                remote_endpoint,
                selection.reason
            );
        }

        if selection.reason_code == REASON_PATH_DIRECT_DEGRADED {
            info!(
                event = "direct_path_degraded",
                peer_id = %self.node_id,
                local_endpoint = %local_endpoint_text,
                remote_endpoint = %remote_endpoint_text,
                candidate_source = ?candidate_source,
                rtt_ms = ?rtt_ms,
                reason = %selection.reason,
                "direct_path_degraded peer_id={} remote_endpoint={:?} reason={}",
                self.node_id,
                remote_endpoint,
                selection.reason
            );
        }

        if selection.path == Some(NetworkPath::Relay) {
            info!(
                event = "relay_fallback_selected",
                peer_id = %self.node_id,
                local_endpoint = %local_endpoint_text,
                remote_endpoint = %remote_endpoint_text,
                relay_server = ?self.relay_server,
                candidate_source = ?candidate_source,
                rtt_ms = ?rtt_ms,
                reason = %selection.reason,
                "relay_fallback_selected peer_id={} reason={}",
                self.node_id,
                selection.reason
            );
        }

        self.path_events.push(PathSelectionEvent {
            selected_at: Instant::now(),
            network_generation: local_generation,
            previous_path,
            selected_path: selection.path,
            direct_endpoint: selection.direct_endpoint,
            reason_code: selection.reason_code.to_string(),
            reason: selection.reason.clone(),
            direct_confirmed: selection.direct_confirmed,
            relay_hedged: selection.relay_hedged,
            direct_score: selection.direct_score.clone(),
            relay_score: selection.relay_score.clone(),
        });

        if self.path_events.len() > PATH_SELECTION_EVENT_LIMIT {
            let excess = self.path_events.len() - PATH_SELECTION_EVENT_LIMIT;
            self.path_events.drain(0..excess);
        }
    }

    fn record_direct_event(
        &mut self,
        local_generation: u64,
        stage: impl Into<String>,
        endpoint: Option<SocketAddr>,
        candidate_count: Option<usize>,
        sent_probes: Option<u32>,
        detail: impl Into<String>,
    ) {
        self.push_direct_event(DirectTraversalEvent::new(
            local_generation,
            stage,
            endpoint,
            candidate_count,
            sent_probes,
            detail,
        ));
    }

    #[allow(clippy::too_many_arguments)]
    fn record_direct_event_with_probe_coverage(
        &mut self,
        local_generation: u64,
        stage: impl Into<String>,
        endpoint: Option<SocketAddr>,
        candidate_count: Option<usize>,
        sent_probes: Option<u32>,
        detail: impl Into<String>,
        socket0_count: u32,
        alt_socket_count: u32,
        unique_target_ports: u32,
        repeated_target_ports: u32,
    ) {
        self.push_direct_event(
            DirectTraversalEvent::new(
                local_generation,
                stage,
                endpoint,
                candidate_count,
                sent_probes,
                detail,
            )
            .with_probe_coverage(
                socket0_count,
                alt_socket_count,
                unique_target_ports,
                repeated_target_ports,
            ),
        );
    }

    fn push_direct_event(&mut self, event: DirectTraversalEvent) {
        self.direct_events.push(event);

        if self.direct_events.len() > DIRECT_TRAVERSAL_EVENT_LIMIT {
            let excess = self.direct_events.len() - DIRECT_TRAVERSAL_EVENT_LIMIT;
            self.direct_events.drain(0..excess);
        }
    }
}
