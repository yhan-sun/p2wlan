use super::*;

/// Aggregate statistics for the peer manager.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeerManagerStats {
    pub total_peers: usize,
    pub direct_connections: usize,
    pub relay_connections: usize,
    pub total_bytes_sent: u64,
    pub total_bytes_received: u64,
}

impl PeerManagerStats {
    /// Build aggregate statistics from diagnostics using the live selected data path.
    pub fn from_diagnostics(peers: &[PeerDiagnostics]) -> Self {
        Self {
            total_peers: peers.len(),
            direct_connections: peers
                .iter()
                .filter(|peer| peer.active_path == Some(NetworkPath::Direct))
                .count(),
            relay_connections: peers
                .iter()
                .filter(|peer| peer.active_path == Some(NetworkPath::Relay))
                .count(),
            total_bytes_sent: peers.iter().map(|peer| peer.bytes_sent).sum(),
            total_bytes_received: peers.iter().map(|peer| peer.bytes_received).sum(),
        }
    }
}

/// Aggregated direct candidate-pair outcomes grouped by endpoint source.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CandidatePairSourceStats {
    pub source: CandidatePairSource,
    pub pair_count: u64,
    pub current_pair_count: u64,
    pub selected_count: u64,
    pub succeeded_count: u64,
    pub probing_count: u64,
    pub failed_count: u64,
    pub degraded_count: u64,
    pub success_count: u64,
    pub failure_count: u64,
    pub success_rate_per_mille: Option<u16>,
    pub last_success_age_ms: Option<u64>,
    pub last_failure_age_ms: Option<u64>,
    pub history_success_count: Option<u64>,
    pub history_failure_count: Option<u64>,
    pub history_consecutive_failures: Option<u32>,
    pub history_success_rate_per_mille: Option<u16>,
    pub history_cooldown_remaining_ms: Option<u64>,
    pub source_quality_rank: Option<u16>,
    pub probe_budget_per_cycle: Option<usize>,
    pub probe_budget_reason: Option<String>,
}

/// Serializable peer connection diagnostics.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeerDiagnostics {
    pub node_id: String,
    pub device_name: String,
    pub app_version: String,
    pub virtual_ip: String,
    pub endpoint: Option<String>,
    pub nat_type: String,
    pub online: bool,
    pub last_seen: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub remote_relay_latency_ms: Option<u64>,
    pub state: ConnectionState,
    pub active_path: Option<NetworkPath>,
    pub direct_type: DirectPathType,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub probe_session_id: Option<String>,
    pub probe_key_type: String,
    pub selected_pair: Option<CandidatePairDiagnostics>,
    pub current_direct_pair: Option<CandidatePairDiagnostics>,
    pub consent_endpoint: Option<String>,
    pub is_public_udp_direct: bool,
    pub is_overlay_direct: bool,
    pub is_relay: bool,
    pub warning: Option<String>,
    pub connected_for_ms: Option<u64>,
    pub bytes_sent: u64,
    pub bytes_received: u64,
    pub relay_server: Option<String>,
    pub candidates: Vec<String>,
    pub direct: PathHealthDiagnostics,
    pub relay: PathHealthDiagnostics,
    pub direct_generation: u64,
    pub candidate_pair_stats: Vec<CandidatePairSourceStats>,
    pub candidate_pairs: Vec<CandidatePairDiagnostics>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub direct_retry_after_ms: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub direct_retry_remaining_ms: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub current_path_selection: Option<PathSelectionDiagnostics>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_path_selection: Option<PathSelectionDiagnostics>,
    pub path_events: Vec<PathSelectionEventDiagnostics>,
    pub direct_events: Vec<DirectTraversalEventDiagnostics>,
}

impl PeerDiagnostics {
    pub(super) fn from_connection_with_path_selection(
        conn: &PeerConnection,
        current_selection: Option<&PathSelection>,
        direct_retry_after: Option<Duration>,
        local_generation: u64,
        local_endpoint: Option<SocketAddr>,
        traversal_history: Option<&TraversalHistory>,
    ) -> Self {
        let active_path = match current_selection {
            Some(selection) => match selection.path {
                Some(NetworkPath::Direct) if selection.direct_confirmed => {
                    Some(NetworkPath::Direct)
                }
                Some(NetworkPath::Direct)
                    if conn
                        .relay_health
                        .is_confirmed_recent(RELAY_PEER_CONFIRMATION_MAX_AGE) =>
                {
                    Some(NetworkPath::Relay)
                }
                Some(NetworkPath::Relay)
                    if conn
                        .relay_health
                        .is_confirmed_recent(RELAY_PEER_CONFIRMATION_MAX_AGE) =>
                {
                    Some(NetworkPath::Relay)
                }
                _ => None,
            },
            None => match conn.active_path() {
                Some(NetworkPath::Relay)
                    if !conn
                        .relay_health
                        .is_confirmed_recent(RELAY_PEER_CONFIRMATION_MAX_AGE) =>
                {
                    None
                }
                path => path,
            },
        };
        let selected_pair = conn.selected_candidate_pair_for_diagnostics(local_generation);
        let current_pair =
            conn.current_direct_pair_for_diagnostics(local_generation, current_selection);
        let current_pair_endpoint = current_pair.map(|pair| pair.remote_endpoint);
        let consent_endpoint = conn.selected_direct_endpoint_for_consent(local_generation);
        let direct_confirmed = active_path == Some(NetworkPath::Direct)
            && current_pair.is_some_and(|pair| pair.state == CandidatePairState::Selected)
            && current_selection
                .map(|selection| selection.direct_confirmed)
                .unwrap_or(conn.state == ConnectionState::Direct);
        let direct_type = classify_candidate_pair_path(active_path, current_pair, direct_confirmed);
        let selected_pair = selected_pair.map(|pair| {
            let is_current = Some(pair.remote_endpoint) == current_pair_endpoint;
            CandidatePairDiagnostics::from_pair(
                pair,
                local_endpoint,
                is_current.then_some(active_path).flatten(),
                direct_confirmed && is_current,
            )
        });
        let current_direct_pair = current_pair.map(|pair| {
            CandidatePairDiagnostics::from_pair(pair, local_endpoint, active_path, direct_confirmed)
        });
        let mut candidate_pairs = conn
            .candidate_pairs
            .iter()
            .map(|pair| {
                let is_current = Some(pair.remote_endpoint) == current_pair_endpoint;
                CandidatePairDiagnostics::from_pair(
                    pair,
                    local_endpoint,
                    is_current.then_some(active_path).flatten(),
                    direct_confirmed && is_current,
                )
            })
            .collect::<Vec<_>>();
        candidate_pairs.sort_by(|a, b| {
            a.local_generation
                .cmp(&b.local_generation)
                .then_with(|| a.remote_endpoint.cmp(&b.remote_endpoint))
        });

        let is_public_udp_direct = direct_type == DirectPathType::PublicUdp;
        let is_overlay_direct = direct_type == DirectPathType::Overlay;
        let is_relay = direct_type == DirectPathType::Relay;
        let warning = is_overlay_direct
            .then(|| "direct path is overlay/utun, not public NAT traversal".to_string());

        Self {
            node_id: conn.node_id.clone(),
            device_name: conn.device_name.clone(),
            app_version: conn.app_version.clone(),
            virtual_ip: conn.virtual_ip.clone(),
            endpoint: conn.endpoint.map(|endpoint| endpoint.to_string()),
            nat_type: conn.nat_type.clone(),
            online: conn.online,
            last_seen: conn.last_seen,
            remote_relay_latency_ms: conn.remote_relay_rtt_ms,
            state: conn.state,
            active_path,
            direct_type,
            probe_session_id: conn.probe_session_id.clone(),
            probe_key_type: probe_key_type(conn).to_string(),
            selected_pair,
            current_direct_pair,
            consent_endpoint: consent_endpoint.map(|endpoint| endpoint.to_string()),
            is_public_udp_direct,
            is_overlay_direct,
            is_relay,
            warning,
            connected_for_ms: conn
                .connected_at
                .map(|connected_at| duration_millis(connected_at.elapsed())),
            bytes_sent: conn.bytes_sent,
            bytes_received: conn.bytes_received,
            relay_server: conn.relay_server.clone(),
            candidates: conn.candidates.clone(),
            direct: PathHealthDiagnostics::from(&conn.direct_health),
            relay: PathHealthDiagnostics::from(&conn.relay_health),
            direct_generation: conn.direct_generation,
            candidate_pair_stats: candidate_pair_source_stats(
                &conn.candidate_pairs,
                local_generation,
                traversal_history,
            ),
            candidate_pairs,
            direct_retry_after_ms: direct_retry_after
                .map(|base| duration_millis(conn.direct_retry_after(base))),
            direct_retry_remaining_ms: direct_retry_after
                .map(|base| duration_millis(conn.direct_retry_remaining(base))),
            current_path_selection: current_selection.map(PathSelectionDiagnostics::from),
            last_path_selection: conn
                .last_path_selection
                .as_ref()
                .map(PathSelectionDiagnostics::from),
            path_events: conn
                .path_events
                .iter()
                .map(PathSelectionEventDiagnostics::from)
                .collect(),
            direct_events: conn
                .direct_events
                .iter()
                .map(DirectTraversalEventDiagnostics::from)
                .collect(),
        }
    }
}

impl From<&PeerConnection> for PeerDiagnostics {
    fn from(conn: &PeerConnection) -> Self {
        Self::from_connection_with_path_selection(
            conn,
            None,
            None,
            conn.direct_generation,
            None,
            None,
        )
    }
}

/// Serializable path-selector transition diagnostics.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PathSelectionEventDiagnostics {
    pub selected_age_ms: u64,
    pub network_generation: u64,
    pub previous_path: Option<NetworkPath>,
    pub selected_path: Option<NetworkPath>,
    pub direct_endpoint: Option<String>,
    pub reason_code: String,
    pub reason: String,
    pub direct_confirmed: bool,
    pub relay_hedged: bool,
    pub direct_score: Option<PathScoreDiagnostics>,
    pub relay_score: Option<PathScoreDiagnostics>,
}

impl From<&PathSelectionEvent> for PathSelectionEventDiagnostics {
    fn from(event: &PathSelectionEvent) -> Self {
        Self {
            selected_age_ms: duration_millis(event.selected_at.elapsed()),
            network_generation: event.network_generation,
            previous_path: event.previous_path,
            selected_path: event.selected_path,
            direct_endpoint: event.direct_endpoint.map(|endpoint| endpoint.to_string()),
            reason_code: event.reason_code.clone(),
            reason: event.reason.clone(),
            direct_confirmed: event.direct_confirmed,
            relay_hedged: event.relay_hedged,
            direct_score: event.direct_score.as_ref().map(PathScoreDiagnostics::from),
            relay_score: event.relay_score.as_ref().map(PathScoreDiagnostics::from),
        }
    }
}

/// Serializable direct traversal timeline event.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DirectTraversalEventDiagnostics {
    pub age_ms: u64,
    pub network_generation: u64,
    pub stage: String,
    pub endpoint: Option<String>,
    pub candidate_count: Option<usize>,
    pub sent_probes: Option<u32>,
    pub detail: String,
}

impl From<&DirectTraversalEvent> for DirectTraversalEventDiagnostics {
    fn from(event: &DirectTraversalEvent) -> Self {
        Self {
            age_ms: duration_millis(event.recorded_at.elapsed()),
            network_generation: event.network_generation,
            stage: event.stage.clone(),
            endpoint: event.endpoint.map(|endpoint| endpoint.to_string()),
            candidate_count: event.candidate_count,
            sent_probes: event.sent_probes,
            detail: event.detail.clone(),
        }
    }
}

/// Serializable candidate-pair diagnostics.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CandidatePairDiagnostics {
    pub local_endpoint: Option<String>,
    pub remote_endpoint: String,
    pub local_candidate_type: Option<CandidatePairSource>,
    pub remote_candidate_type: CandidatePairSource,
    pub local_interface: Option<String>,
    pub local_source: Option<String>,
    pub remote_source: CandidatePairSource,
    pub source: CandidatePairSource,
    pub local_generation: u64,
    pub state: CandidatePairState,
    pub pair_state: CandidatePairState,
    pub nominated: bool,
    pub selected: bool,
    pub nominated_age_ms: Option<u64>,
    pub selected_age_ms: Option<u64>,
    pub source_observed_age_ms: Option<u64>,
    pub last_probe_age_ms: Option<u64>,
    pub probe_count: u64,
    pub probe_due: bool,
    pub probe_retry_after_ms: Option<u64>,
    pub probe_retry_remaining_ms: Option<u64>,
    pub first_success_age_ms: Option<u64>,
    pub last_success_age_ms: Option<u64>,
    pub last_failure_age_ms: Option<u64>,
    pub consecutive_failures: u32,
    pub last_error: Option<String>,
    pub last_error_code: Option<String>,
    pub rtt_ms: Option<u64>,
    pub rtt_ewma_ms: Option<u64>,
    pub jitter_ms: Option<u64>,
    pub success_count: u64,
    pub failure_count: u64,
    pub direct_type: DirectPathType,
    pub is_public_udp_direct: bool,
    pub is_overlay_direct: bool,
    pub is_relay: bool,
    pub warning: Option<String>,
}

impl CandidatePairDiagnostics {
    fn from_pair(
        pair: &CandidatePair,
        local_endpoint: Option<SocketAddr>,
        active_path: Option<NetworkPath>,
        direct_confirmed: bool,
    ) -> Self {
        let direct_type = classify_candidate_pair_path(active_path, Some(pair), direct_confirmed);
        let selected = pair.state == CandidatePairState::Selected;
        let nominated = pair.nominated || selected;
        let is_public_udp_direct = direct_type == DirectPathType::PublicUdp;
        let is_overlay_direct = direct_type == DirectPathType::Overlay;
        let is_relay = direct_type == DirectPathType::Relay;
        let local_endpoint = pair.local_endpoint.or(local_endpoint);
        let probe_due = candidate_pair_probe_due(pair);
        let probe_retry_after_ms = candidate_pair_failure_cooldown(pair).map(duration_millis);
        let probe_retry_remaining_ms =
            candidate_pair_probe_retry_remaining(pair).map(duration_millis);
        Self {
            local_endpoint: local_endpoint.map(|endpoint| endpoint.to_string()),
            remote_endpoint: pair.remote_endpoint.to_string(),
            local_candidate_type: local_endpoint.map(|_| CandidatePairSource::Host),
            remote_candidate_type: pair.source,
            local_interface: None,
            local_source: local_endpoint.map(|_| "udp_socket".to_string()),
            remote_source: pair.source,
            source: pair.source,
            local_generation: pair.local_generation,
            state: pair.state,
            pair_state: pair.state,
            nominated,
            selected,
            nominated_age_ms: pair.nominated_at.map(|at| duration_millis(at.elapsed())),
            selected_age_ms: pair.selected_at.map(|at| duration_millis(at.elapsed())),
            source_observed_age_ms: candidate_pair_source_observed_age_ms(pair),
            last_probe_age_ms: pair.last_probe_at.map(|at| duration_millis(at.elapsed())),
            probe_count: pair.probe_count,
            probe_due,
            probe_retry_after_ms,
            probe_retry_remaining_ms,
            first_success_age_ms: pair.first_success_age().map(duration_millis),
            last_success_age_ms: pair.success_age().map(duration_millis),
            last_failure_age_ms: pair.failure_age().map(duration_millis),
            consecutive_failures: pair.consecutive_failures,
            last_error: pair.last_error.clone(),
            last_error_code: pair.last_error_code.clone(),
            rtt_ms: pair.rtt_ms,
            rtt_ewma_ms: pair.rtt_ewma_ms,
            jitter_ms: pair.jitter_ms,
            success_count: pair.success_count,
            failure_count: pair.failure_count,
            direct_type,
            is_public_udp_direct,
            is_overlay_direct,
            is_relay,
            warning: is_overlay_direct
                .then(|| "direct path is overlay/utun, not public NAT traversal".to_string()),
        }
    }
}

impl From<&CandidatePair> for CandidatePairDiagnostics {
    fn from(pair: &CandidatePair) -> Self {
        Self::from_pair(pair, None, None, false)
    }
}

/// Serializable health counters for one transport path.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PathHealthDiagnostics {
    pub last_success_age_ms: Option<u64>,
    pub last_failure_age_ms: Option<u64>,
    pub consecutive_failures: u32,
    pub last_error: Option<String>,
    pub last_error_code: Option<String>,
    pub latency_ms: Option<u64>,
    pub rtt_ewma_ms: Option<u64>,
    pub jitter_ms: Option<u64>,
    pub success_count: u64,
    pub failure_count: u64,
}

impl From<&PathHealth> for PathHealthDiagnostics {
    fn from(health: &PathHealth) -> Self {
        Self {
            last_success_age_ms: health.success_age().map(duration_millis),
            last_failure_age_ms: health.failure_age().map(duration_millis),
            consecutive_failures: health.consecutive_failures,
            last_error: health.last_error.clone(),
            last_error_code: health.last_error_code.clone(),
            latency_ms: health.latency_ms,
            rtt_ewma_ms: health.rtt_ewma_ms,
            jitter_ms: health.jitter_ms,
            success_count: health.success_count,
            failure_count: health.failure_count,
        }
    }
}

pub(super) fn candidate_pair_source_stats(
    pairs: &[CandidatePair],
    local_generation: u64,
    history: Option<&TraversalHistory>,
) -> Vec<CandidatePairSourceStats> {
    let mut stats = [
        CandidatePairSource::PeerReflexive,
        CandidatePairSource::Learned,
        CandidatePairSource::Host,
        CandidatePairSource::Upnp,
        CandidatePairSource::Pcp,
        CandidatePairSource::NatPmp,
        CandidatePairSource::StunObserved,
        CandidatePairSource::Signaled,
        CandidatePairSource::Predicted,
        CandidatePairSource::Birthday,
    ]
    .into_iter()
    .filter_map(|source| candidate_pair_source_stats_for(pairs, local_generation, source, history))
    .collect::<Vec<_>>();

    if let Some(history) = history {
        let stats_snapshot = stats.clone();
        for source_stats in &mut stats {
            source_stats.source_quality_rank = Some(candidate_pair_source_quality_rank(
                &stats_snapshot,
                history,
                source_stats.source,
            ));
            let (budget, reason) =
                candidate_pair_source_probe_budget(&stats_snapshot, history, source_stats.source);
            source_stats.probe_budget_per_cycle = budget;
            source_stats.probe_budget_reason = Some(reason.to_string());
        }
    }

    stats
}

fn candidate_pair_source_stats_for(
    pairs: &[CandidatePair],
    local_generation: u64,
    source: CandidatePairSource,
    history: Option<&TraversalHistory>,
) -> Option<CandidatePairSourceStats> {
    let mut pair_count = 0u64;
    let mut current_pair_count = 0u64;
    let mut selected_count = 0u64;
    let mut succeeded_count = 0u64;
    let mut probing_count = 0u64;
    let mut failed_count = 0u64;
    let mut degraded_count = 0u64;
    let mut success_count = 0u64;
    let mut failure_count = 0u64;
    let mut last_success_at: Option<Instant> = None;
    let mut last_failure_at: Option<Instant> = None;

    for pair in pairs.iter().filter(|pair| pair.source == source) {
        pair_count = pair_count.saturating_add(1);
        if pair.local_generation == local_generation {
            current_pair_count = current_pair_count.saturating_add(1);
        }
        match pair.state {
            CandidatePairState::Selected => selected_count = selected_count.saturating_add(1),
            CandidatePairState::Succeeded => succeeded_count = succeeded_count.saturating_add(1),
            CandidatePairState::Probing => probing_count = probing_count.saturating_add(1),
            CandidatePairState::Failed => failed_count = failed_count.saturating_add(1),
            CandidatePairState::Degraded => degraded_count = degraded_count.saturating_add(1),
            CandidatePairState::Frozen | CandidatePairState::Waiting => {}
        }
        success_count = success_count.saturating_add(pair.success_count);
        failure_count = failure_count.saturating_add(pair.failure_count);
        last_success_at = latest_instant(last_success_at, pair.last_success_at);
        last_failure_at = latest_instant(last_failure_at, pair.last_failure_at);
    }

    let history_entry = history.and_then(|history| history.source(source));

    (pair_count > 0).then(|| CandidatePairSourceStats {
        source,
        pair_count,
        current_pair_count,
        selected_count,
        succeeded_count,
        probing_count,
        failed_count,
        degraded_count,
        success_count,
        failure_count,
        success_rate_per_mille: success_rate_per_mille(success_count, failure_count),
        last_success_age_ms: last_success_at.map(|at| duration_millis(at.elapsed())),
        last_failure_age_ms: last_failure_at.map(|at| duration_millis(at.elapsed())),
        history_success_count: history_entry.map(|entry| entry.success_count),
        history_failure_count: history_entry.map(|entry| entry.failure_count),
        history_consecutive_failures: history_entry.map(|entry| entry.consecutive_failures),
        history_success_rate_per_mille: history_entry
            .and_then(|entry| entry.success_rate_per_mille()),
        history_cooldown_remaining_ms: history
            .and_then(|history| history.source_cooldown_remaining_ms(source)),
        source_quality_rank: None,
        probe_budget_per_cycle: None,
        probe_budget_reason: None,
    })
}
