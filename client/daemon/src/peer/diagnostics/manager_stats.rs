/// Aggregate statistics for the peer manager.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeerManagerStats {
    pub total_peers: usize,
    pub direct_connections: usize,
    pub relay_connections: usize,
    pub total_bytes_sent: u64,
    pub total_bytes_received: u64,
    /// Dropped outbound business packets (packets/bytes) by stable reason
    /// code, accumulated since daemon start.  Terminal loss only.
    #[serde(default)]
    pub outbound_drops: HashMap<String, OutboundDropCounters>,
    /// Transient outbound send-failure attempts (packets by reason code),
    /// accumulated since daemon start.  A failed attempt is re-parked and
    /// retried; a packet that is finally lost lands in `outbound_drops`
    /// instead — the two maps never double-count the same loss.
    #[serde(default)]
    pub outbound_send_failures: HashMap<String, OutboundDropCounters>,
    /// Bounded peer/generation/correlation ledger for outbound loss and
    /// retry events.
    #[serde(default)]
    pub outbound_loss_events: Vec<OutboundLossEvent>,
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
            outbound_drops: HashMap::new(),
            outbound_send_failures: HashMap::new(),
            outbound_loss_events: Vec::new(),
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
    /// Pairs retired to Frozen while a confirmed Direct path is healthy.
    pub frozen_count: u64,
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
