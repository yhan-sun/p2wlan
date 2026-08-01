// ============================================================
// Connection State
// ============================================================

/// The state of a peer connection attempt.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConnectionState {
    /// No connection attempted yet.
    Idle,
    /// Currently performing NAT detection / ICE candidate gathering.
    Connecting,
    /// Attempting UDP hole punching.
    HolePunching,
    /// Direct P2P connection established.
    Direct,
    /// Direct connection failed, falling back to relay.
    FallbackToRelay,
    /// Connected via relay server.
    Relay,
    /// Connection failed.
    Failed,
    /// Connection closed.
    Closed,
}

impl std::fmt::Display for ConnectionState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Idle => write!(f, "idle"),
            Self::Connecting => write!(f, "connecting"),
            Self::HolePunching => write!(f, "hole_punching"),
            Self::Direct => write!(f, "direct"),
            Self::FallbackToRelay => write!(f, "fallback_to_relay"),
            Self::Relay => write!(f, "relay"),
            Self::Failed => write!(f, "failed"),
            Self::Closed => write!(f, "closed"),
        }
    }
}

/// The transport path used for peer traffic.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NetworkPath {
    /// Direct UDP path.
    Direct,
    /// Relay fallback path.
    Relay,
}

/// Diagnostic classification for the currently selected or best direct path.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DirectPathType {
    /// Confirmed direct UDP over a private/link-local LAN endpoint.
    Lan,
    /// Confirmed direct UDP over a public Internet endpoint.
    PublicUdp,
    /// Direct packets are using the overlay/TUN address space, not NAT traversal.
    Overlay,
    /// Relay is the active data path.
    Relay,
    /// A direct pair exists or is being tried, but is not selected/nominated yet.
    Probing,
    /// No selected or classifiable candidate pair is available yet.
    Unknown,
}

impl std::fmt::Display for NetworkPath {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Direct => write!(f, "direct"),
            Self::Relay => write!(f, "relay"),
        }
    }
}

/// Explicit result from the data path selector.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PathSelection {
    /// Selected path, if any path can be attempted.
    pub path: Option<NetworkPath>,
    /// Direct UDP endpoint to use when `path == Direct`.
    pub direct_endpoint: Option<SocketAddr>,
    /// Stable machine-readable reason code.
    pub reason_code: &'static str,
    /// Human-readable reason for diagnostics and logs.
    pub reason: String,
    /// Whether the chosen Direct path is fully confirmed.
    pub direct_confirmed: bool,
    /// Whether Relay should receive a hedged copy while Direct remains selected.
    pub relay_hedged: bool,
    /// Explainable Direct path score, when a Direct endpoint exists.
    pub direct_score: Option<PathScore>,
    /// Explainable Relay path score, when Relay is available.
    pub relay_score: Option<PathScore>,
}

impl PathSelection {
    pub(super) fn direct(
        endpoint: SocketAddr,
        reason_code: &'static str,
        reason: impl Into<String>,
        direct_confirmed: bool,
    ) -> Self {
        Self {
            path: Some(NetworkPath::Direct),
            direct_endpoint: Some(endpoint),
            reason_code,
            reason: reason.into(),
            direct_confirmed,
            relay_hedged: false,
            direct_score: None,
            relay_score: None,
        }
    }

    pub(super) fn relay(reason_code: &'static str, reason: impl Into<String>) -> Self {
        Self {
            path: Some(NetworkPath::Relay),
            direct_endpoint: None,
            reason_code,
            reason: reason.into(),
            direct_confirmed: false,
            relay_hedged: false,
            direct_score: None,
            relay_score: None,
        }
    }

    pub(super) fn unavailable(reason_code: &'static str, reason: impl Into<String>) -> Self {
        Self {
            path: None,
            direct_endpoint: None,
            reason_code,
            reason: reason.into(),
            direct_confirmed: false,
            relay_hedged: false,
            direct_score: None,
            relay_score: None,
        }
    }

    pub(super) fn with_scores(
        mut self,
        direct_score: Option<PathScore>,
        relay_score: Option<PathScore>,
    ) -> Self {
        self.direct_score = direct_score;
        self.relay_score = relay_score;
        self
    }

    pub(super) fn with_relay_hedge(mut self) -> Self {
        self.relay_hedged = true;
        self
    }
}

/// Explainable score used by the path selector.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PathScore {
    pub path: NetworkPath,
    pub score: i32,
    pub reachable: bool,
    pub reachability_score: i32,
    pub preference_score: i32,
    pub latency_score: i32,
    pub stability_score: i32,
    pub penalty_score: i32,
    pub reason: String,
}

/// Serializable path selector diagnostics.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PathSelectionDiagnostics {
    pub path: Option<NetworkPath>,
    pub direct_endpoint: Option<String>,
    pub reason_code: String,
    pub reason: String,
    pub direct_confirmed: bool,
    pub relay_hedged: bool,
    pub direct_score: Option<PathScoreDiagnostics>,
    pub relay_score: Option<PathScoreDiagnostics>,
}

impl From<&PathSelection> for PathSelectionDiagnostics {
    fn from(selection: &PathSelection) -> Self {
        Self {
            path: selection.path,
            direct_endpoint: selection
                .direct_endpoint
                .map(|endpoint| endpoint.to_string()),
            reason_code: selection.reason_code.to_string(),
            reason: selection.reason.clone(),
            direct_confirmed: selection.direct_confirmed,
            relay_hedged: selection.relay_hedged,
            direct_score: selection
                .direct_score
                .as_ref()
                .map(PathScoreDiagnostics::from),
            relay_score: selection
                .relay_score
                .as_ref()
                .map(PathScoreDiagnostics::from),
        }
    }
}

/// Serializable path score diagnostics.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PathScoreDiagnostics {
    pub path: NetworkPath,
    pub score: i32,
    pub reachable: bool,
    pub reachability_score: i32,
    pub preference_score: i32,
    pub latency_score: i32,
    pub stability_score: i32,
    pub penalty_score: i32,
    pub reason: String,
}

impl From<&PathScore> for PathScoreDiagnostics {
    fn from(score: &PathScore) -> Self {
        Self {
            path: score.path,
            score: score.score,
            reachable: score.reachable,
            reachability_score: score.reachability_score,
            preference_score: score.preference_score,
            latency_score: score.latency_score,
            stability_score: score.stability_score,
            penalty_score: score.penalty_score,
            reason: score.reason.clone(),
        }
    }
}

/// One recorded path-selector transition for a peer.
#[derive(Debug, Clone)]
pub struct PathSelectionEvent {
    pub selected_at: Instant,
    pub network_generation: u64,
    pub previous_path: Option<NetworkPath>,
    pub selected_path: Option<NetworkPath>,
    pub direct_endpoint: Option<SocketAddr>,
    pub reason_code: String,
    pub reason: String,
    pub direct_confirmed: bool,
    pub relay_hedged: bool,
    pub direct_score: Option<PathScore>,
    pub relay_score: Option<PathScore>,
}

/// One recorded direct traversal event for a peer.
#[derive(Debug, Clone)]
pub struct DirectTraversalEvent {
    pub recorded_at: Instant,
    pub network_generation: u64,
    pub stage: String,
    pub endpoint: Option<SocketAddr>,
    pub candidate_count: Option<usize>,
    pub sent_probes: Option<u32>,
    pub detail: String,
}

impl DirectTraversalEvent {
    pub(super) fn new(
        network_generation: u64,
        stage: impl Into<String>,
        endpoint: Option<SocketAddr>,
        candidate_count: Option<usize>,
        sent_probes: Option<u32>,
        detail: impl Into<String>,
    ) -> Self {
        Self {
            recorded_at: Instant::now(),
            network_generation,
            stage: stage.into(),
            endpoint,
            candidate_count,
            sent_probes,
            detail: detail.into(),
        }
    }
}
