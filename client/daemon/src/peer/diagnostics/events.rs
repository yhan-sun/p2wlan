/// Serializable path-selector transition diagnostics.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PathSelectionEventDiagnostics {
    pub selected_age_ms: u64,
    pub network_generation: u64,
    pub previous_path: Option<NetworkPath>,
    pub selected_path: Option<NetworkPath>,
    pub direct_endpoint: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub relay_server: Option<String>,
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
            relay_server: event.relay_server.clone(),
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
    /// Daemon-local encrypted validation worker owner, when this event belongs
    /// to a validation lifecycle.  It is intentionally separate from the
    /// signaling probe session ID: the owner is the token the encrypted
    /// request/ACK exchange must match.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub validation_session_id: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub remote_validation_owner: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub request_id: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub socket_index: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expected_endpoint: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub observed_ack_endpoint: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub selected_endpoint: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ack_endpoint_authenticated: Option<bool>,
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
            validation_session_id: event.validation_session_id,
            remote_validation_owner: event.remote_validation_owner,
            request_id: event.request_id,
            socket_index: event.socket_index,
            expected_endpoint: event.expected_endpoint.map(|endpoint| endpoint.to_string()),
            observed_ack_endpoint: event
                .observed_ack_endpoint
                .map(|endpoint| endpoint.to_string()),
            selected_endpoint: event.selected_endpoint.map(|endpoint| endpoint.to_string()),
            ack_endpoint_authenticated: event.ack_endpoint_authenticated,
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
