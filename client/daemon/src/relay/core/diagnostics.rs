/// Diagnostics for one configured relay candidate.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RelayCandidateDiagnostics {
    pub region: String,
    pub endpoint: String,
    pub connect_latency_ms: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cooldown_remaining_ms: Option<u64>,
    pub error: Option<String>,
    pub error_code: Option<String>,
    /// How this candidate's connect attempt ended in the most recent
    /// selection pass: `success`, `failed`, `timeout`, or `cancelled` (a
    /// better relay was already published and the in-flight connect was
    /// aborted).  Kept for failover diagnostics.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub outcome: Option<String>,
}

/// Result of the most recent relay selection pass.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct RelaySelectionDiagnostics {
    pub selected_region: Option<String>,
    pub selected_endpoint: Option<String>,
    pub selected_connect_latency_ms: Option<u64>,
    pub selected_last_pong_at_unix_ms: Option<u64>,
    pub selected_last_pong_age_ms: Option<u64>,
    pub selected_last_pong_rtt_ms: Option<u64>,
    pub selected_rtt_ewma_ms: Option<u64>,
    pub selected_jitter_ms: Option<u64>,
    pub selected_pong_count: u64,
    pub selected_error_count: u64,
    pub candidates: Vec<RelayCandidateDiagnostics>,
    pub last_error: Option<String>,
    pub last_error_code: Option<String>,
}

impl RelaySelectionDiagnostics {
    pub fn refresh_runtime_ages(&mut self) {
        let now_ms = now_unix_millis();
        if let Some(last_pong_at) = self.selected_last_pong_at_unix_ms {
            self.selected_last_pong_age_ms = Some(now_ms.saturating_sub(last_pong_at));
        }
    }
}
