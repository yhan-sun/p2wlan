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
    /// Confirmed peer-reflexive UDP reachability; not proof of a stable public mapping.
    PeerReflexive,
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
    /// Relay server backing a Relay selection, for diagnostics and deduplication.
    pub relay_server: Option<String>,
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
            relay_server: None,
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
            relay_server: None,
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
            relay_server: None,
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
    pub relay_server: Option<String>,
    pub reason_code: String,
    pub reason: String,
    pub direct_confirmed: bool,
    pub relay_hedged: bool,
    pub direct_score: Option<PathScore>,
    pub relay_score: Option<PathScore>,
}

/// One recorded direct traversal event for a peer.
#[derive(Debug, Clone, Copy, Default)]
pub struct DirectValidationEventMetadata {
    /// The local daemon-owned validation worker, if this event belongs to one.
    pub(crate) local_validation_session_id: Option<u64>,
    /// Owner token echoed from a remote validation Request. This is never a
    /// local session identifier and must remain separately attributable.
    pub(crate) remote_validation_owner: Option<u64>,
    /// Structured validation request identifier.
    pub(crate) request_id: Option<u16>,
    /// Endpoint selected before the owned Request was sent.
    pub(crate) expected_endpoint: Option<SocketAddr>,
    /// Endpoint observed on the consumed encrypted ACK.
    pub(crate) observed_ack_endpoint: Option<SocketAddr>,
    /// Endpoint accepted by the Direct promotion transaction.
    pub(crate) selected_endpoint: Option<SocketAddr>,
    /// Whether the observed ACK endpoint passed authenticated endpoint
    /// admission. Required when it differs from `expected_endpoint`.
    pub(crate) ack_endpoint_authenticated: Option<bool>,
    /// RTT measured from the actual encrypted validation Request send to its
    /// matched ACK. This is stronger than a queued candidate-probe RTT.
    pub(crate) validation_rtt_ms: Option<u64>,
}

#[derive(Debug, Clone)]
pub struct DirectTraversalEvent {
    pub recorded_at: Instant,
    pub network_generation: u64,
    /// Owner token of the daemon-internal encrypted direct-validation worker
    /// that emitted this event.  The token is a bounded diagnostic handle,
    /// not authentication material; it lets a peer's timeline distinguish
    /// overlapping generations and stale worker cleanup.
    pub validation_session_id: Option<u64>,
    /// Owner token carried by a remote validation Request. It is deliberately
    /// separate from this daemon's local validation session identifier.
    pub remote_validation_owner: Option<u64>,
    /// Structured identifier of the validation Request/ACK exchange.
    pub request_id: Option<u16>,
    /// Index of the UDP socket that actually received or emitted the event,
    /// when the receive/send path can identify it. This is deliberately an
    /// index rather than a local address, so diagnostics do not expose
    /// sensitive endpoint material.
    pub socket_index: Option<usize>,
    pub expected_endpoint: Option<SocketAddr>,
    pub observed_ack_endpoint: Option<SocketAddr>,
    pub selected_endpoint: Option<SocketAddr>,
    pub ack_endpoint_authenticated: Option<bool>,
    pub validation_rtt_ms: Option<u64>,
    pub stage: String,
    pub endpoint: Option<SocketAddr>,
    pub candidate_count: Option<usize>,
    pub sent_probes: Option<u32>,
    pub probe_tx_socket0_count: Option<u32>,
    pub probe_tx_alt_socket_count: Option<u32>,
    pub probe_tx_unique_target_ports: Option<u32>,
    pub probe_tx_repeated_target_ports: Option<u32>,
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
            validation_session_id: None,
            remote_validation_owner: None,
            request_id: None,
            socket_index: None,
            expected_endpoint: None,
            observed_ack_endpoint: None,
            selected_endpoint: None,
            ack_endpoint_authenticated: None,
            validation_rtt_ms: None,
            stage: stage.into(),
            endpoint,
            candidate_count,
            sent_probes,
            probe_tx_socket0_count: None,
            probe_tx_alt_socket_count: None,
            probe_tx_unique_target_ports: None,
            probe_tx_repeated_target_ports: None,
            detail: detail.into(),
        }
    }

    pub(super) fn with_socket_index(mut self, socket_index: Option<usize>) -> Self {
        self.socket_index = socket_index;
        self
    }

    pub(super) fn with_probe_coverage(
        mut self,
        socket0_count: u32,
        alt_socket_count: u32,
        unique_target_ports: u32,
        repeated_target_ports: u32,
    ) -> Self {
        self.probe_tx_socket0_count = Some(socket0_count);
        self.probe_tx_alt_socket_count = Some(alt_socket_count);
        self.probe_tx_unique_target_ports = Some(unique_target_ports);
        self.probe_tx_repeated_target_ports = Some(repeated_target_ports);
        self
    }
}
