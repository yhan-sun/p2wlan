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
    pub last_slow_validation_age_ms: Option<u64>,
    pub slow_validation_count: u64,
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
    pub is_peer_reflexive_direct: bool,
    pub public_mapping_stable: bool,
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
        // A peer-reflexive pair over a real public endpoint is public UDP
        // direct; only overlay/relay paths are not.
        let is_public_udp_direct = matches!(
            direct_type,
            DirectPathType::PublicUdp | DirectPathType::PeerReflexive
        );
        let is_peer_reflexive_direct = direct_type == DirectPathType::PeerReflexive;
        let public_mapping_stable = direct_type == DirectPathType::PublicUdp;
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
            last_slow_validation_age_ms: pair.slow_validation_age().map(duration_millis),
            slow_validation_count: pair.slow_validation_count,
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
            is_peer_reflexive_direct,
            public_mapping_stable,
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
