struct RelayCandidate {
    index: usize,
    region: String,
    audience: Option<String>,
    endpoint: String,
    preference_rank: usize,
}

struct ConnectedCandidate {
    candidate: RelayCandidate,
    transport: RelayTransport,
    relay_rx: mpsc::Receiver<RelayMessage>,
}

/// Relay selector output. A failed pass still returns diagnostics.
pub struct RelaySelectionOutcome {
    pub transport: Option<RelayTransport>,
    pub relay_rx: Option<mpsc::Receiver<RelayMessage>>,
    pub diagnostics: RelaySelectionDiagnostics,
}
