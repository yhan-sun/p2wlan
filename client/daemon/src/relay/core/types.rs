#[derive(Debug, Clone)]
struct RelayCandidate {
    index: usize,
    region: String,
    audience: Option<String>,
    endpoint: String,
    preference_rank: usize,
}

struct ConnectedCandidate<I = RelayMessage> {
    candidate: RelayCandidate,
    transport: RelayTransport,
    relay_rx: mpsc::Receiver<I>,
}

/// Relay selector output. A failed pass still returns diagnostics.
pub struct RelaySelectionOutcome {
    pub transport: Option<RelayTransport>,
    pub relay_rx: Option<mpsc::Receiver<RelayMessage>>,
    pub diagnostics: RelaySelectionDiagnostics,
}

/// Private typed selector result; public legacy output keeps its original shape.
pub(crate) struct RelayReadSelectionOutcome<I> {
    pub(crate) transport: Option<RelayTransport>,
    pub(crate) relay_rx: Option<mpsc::Receiver<I>>,
    pub(crate) diagnostics: RelaySelectionDiagnostics,
}
