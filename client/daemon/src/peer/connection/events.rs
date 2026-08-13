impl PeerConnection {
    pub(super) fn record_path_selection_event(
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
                    || (selection.path == Some(NetworkPath::Relay)
                        && previous.relay_server != selection.relay_server)
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

        if should_record_direct_promotion(previous_path, selection) {
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
            relay_server: selection.relay_server.clone(),
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
    fn record_direct_event_with_socket(
        &mut self,
        local_generation: u64,
        stage: impl Into<String>,
        endpoint: Option<SocketAddr>,
        socket_index: Option<usize>,
        candidate_count: Option<usize>,
        sent_probes: Option<u32>,
        detail: impl Into<String>,
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
            .with_socket_index(socket_index),
        );
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn record_direct_validation_event_with_metadata(
        &mut self,
        generation: u64,
        metadata: DirectValidationEventMetadata,
        stage: impl Into<String>,
        endpoint: Option<SocketAddr>,
        socket_index: Option<usize>,
        candidate_count: Option<usize>,
        sent_probes: Option<u32>,
        detail: impl Into<String>,
    ) {
        let mut event = DirectTraversalEvent::new(
            generation,
            stage,
            endpoint,
            candidate_count,
            sent_probes,
            detail,
        );
        event.validation_session_id = metadata.local_validation_session_id;
        event.remote_validation_owner = metadata.remote_validation_owner;
        event.request_id = metadata.request_id;
        event.expected_endpoint = metadata.expected_endpoint;
        event.observed_ack_endpoint = metadata.observed_ack_endpoint;
        event.selected_endpoint = metadata.selected_endpoint;
        event.ack_endpoint_authenticated = metadata.ack_endpoint_authenticated;
        event.socket_index = socket_index;
        self.push_direct_event(event);
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

    /// Push one direct-traversal event into the bounded ring.
    ///
    /// The strict acceptance lifecycle (owned validation request -> ACK ->
    /// promoted -> path) is the authoritative proof of a real Direct
    /// promotion, so those evidence stages are protected from eviction: a
    /// post-promotion burst of ordinary traversal events (scan completions,
    /// inbound probes, maintainer stops) must never push the validation
    /// chain out of the ring before the harness snapshot captures it
    /// (field evidence: the v0.1.116 acceptance rounds that converged in
    /// ~1 s produced enough post-promotion events to evict
    /// `direct_validation_request_sent`, so the strict parser could not
    /// reconstruct the owned chain).
    fn push_direct_event(&mut self, event: DirectTraversalEvent) {
        self.direct_events.push(event);
        if self.direct_events.len() <= DIRECT_TRAVERSAL_EVENT_LIMIT {
            return;
        }
        // Evict ordinary events first so the owned request -> ACK -> promoted
        // -> path chain survives the ring no matter which side pushed the
        // overflow.  If the ring is entirely validation evidence (impossible
        // in practice), the final drain below still enforces the hard cap.
        let mut evicted = 0usize;
        let excess = self.direct_events.len() - DIRECT_TRAVERSAL_EVENT_LIMIT;
        self.direct_events.retain(|candidate| {
            if evicted >= excess {
                return true;
            }
            if is_validation_evidence_stage(&candidate.stage) {
                true
            } else {
                evicted += 1;
                false
            }
        });
        if self.direct_events.len() > DIRECT_TRAVERSAL_EVENT_LIMIT {
            let excess = self.direct_events.len() - DIRECT_TRAVERSAL_EVENT_LIMIT;
            self.direct_events.drain(0..excess);
        }
    }
}

/// Direct-validation lifecycle stages that the strict acceptance parser
/// requires as one owned chain.  These events are never evicted from the
/// bounded event ring by ordinary traversal noise.
fn is_validation_evidence_stage(stage: &str) -> bool {
    matches!(
        stage,
        "direct_validation_request_sent"
            | "direct_validation_request_received"
            | "direct_validation_ack_sent"
            | "direct_validation_ack_received"
            | "direct_validation_promoted"
            | "direct_path_promoted"
    )
}

/// A Direct path is promoted only after the encrypted data-plane confirmation
/// transaction has committed.  Candidate nomination and trial-window sends
/// may still be recorded in `PathSelectionEvent`, but they are not a user
/// visible path transition and must never emit `direct_path_promoted`.
fn should_record_direct_promotion(
    previous_path: Option<NetworkPath>,
    selection: &PathSelection,
) -> bool {
    selection.path == Some(NetworkPath::Direct)
        && selection.direct_confirmed
        && previous_path != Some(NetworkPath::Direct)
}

#[cfg(test)]
mod path_promotion_tests {
    use super::*;

    #[test]
    fn trial_direct_selection_cannot_emit_promotion() {
        let selection = PathSelection::direct(
            "192.0.2.10:40000".parse().unwrap(),
            "direct_trial",
            "candidate probe only",
            false,
        );
        assert!(!should_record_direct_promotion(None, &selection));
    }

    #[test]
    fn encrypted_direct_selection_emits_promotion_once() {
        let selection = PathSelection::direct(
            "192.0.2.10:40000".parse().unwrap(),
            "direct_confirmed",
            "encrypted data path confirmed",
            true,
        );
        assert!(should_record_direct_promotion(None, &selection));
        assert!(!should_record_direct_promotion(
            Some(NetworkPath::Direct),
            &selection
        ));
    }
}
