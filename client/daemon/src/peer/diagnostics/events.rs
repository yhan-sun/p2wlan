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
    pub probe_tx_socket0_count: Option<u32>,
    pub probe_tx_alt_socket_count: Option<u32>,
    pub probe_tx_unique_target_ports: Option<u32>,
    pub probe_tx_repeated_target_ports: Option<u32>,
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
            probe_tx_socket0_count: event.probe_tx_socket0_count,
            probe_tx_alt_socket_count: event.probe_tx_alt_socket_count,
            probe_tx_unique_target_ports: event.probe_tx_unique_target_ports,
            probe_tx_repeated_target_ports: event.probe_tx_repeated_target_ports,
            detail: event.detail.clone(),
        }
    }
}
