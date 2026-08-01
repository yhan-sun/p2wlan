use super::*;

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

/// Reachability state for one direct candidate pair.
///
/// The daemon currently has a single local UDP socket per network generation,
/// so the pair key is represented as `(local network generation, remote endpoint)`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CandidatePairState {
    /// Candidate is known but not scheduled yet.
    Frozen,
    /// Candidate is ready for probing.
    Waiting,
    /// Probe traffic has been sent or an inbound punch was observed.
    Probing,
    /// Bidirectional probe succeeded but the pair is not selected.
    Succeeded,
    /// Selected direct traffic path.
    Selected,
    /// Probe failed before selection.
    Failed,
    /// Previously usable pair became stale or unhealthy.
    Degraded,
}

/// Where a candidate pair endpoint came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CandidatePairSource {
    /// Endpoint was signaled by the control plane or static peer metadata.
    Signaled,
    /// Endpoint came from the peer's host/local-interface candidate.
    Host,
    /// Endpoint came from the peer's STUN-observed server-reflexive candidate.
    StunObserved,
    /// Endpoint was opened through local gateway port mapping such as UPnP IGD.
    Upnp,
    /// Endpoint was opened through PCP MAP.
    Pcp,
    /// Endpoint was opened through NAT-PMP UDP mapping.
    NatPmp,
    /// Endpoint was predicted from the remote peer's NAT mapping delta.
    Predicted,
    /// Endpoint was synthesized by bounded birthday probing around a public candidate.
    Birthday,
    /// Endpoint was learned from legacy candidate-matched traffic.
    Learned,
    /// Endpoint was learned from an authenticated Probe v2 source address.
    PeerReflexive,
}

impl CandidatePairSource {
    pub fn history_label(self) -> &'static str {
        match self {
            Self::Signaled => "signaled",
            Self::Host => "host",
            Self::StunObserved => "stun_observed",
            Self::Upnp => "upnp",
            Self::Pcp => "pcp",
            Self::NatPmp => "nat_pmp",
            Self::Predicted => "predicted",
            Self::Birthday => "birthday",
            Self::Learned => "learned",
            Self::PeerReflexive => "peer_reflexive",
        }
    }

    pub fn is_persisted_history_source(self) -> bool {
        !matches!(self, Self::Signaled)
    }
}

/// State and health for one direct candidate pair.
#[derive(Debug, Clone)]
pub struct CandidatePair {
    /// Local UDP endpoint that last probed or confirmed this pair.
    pub local_endpoint: Option<SocketAddr>,
    /// Remote UDP candidate endpoint.
    pub remote_endpoint: SocketAddr,
    /// Endpoint source used for probe ranking and diagnostics.
    pub source: CandidatePairSource,
    /// When this source/endpoint combination was last refreshed by a real
    /// signal or authenticated observation, not merely by scheduler reuse.
    pub source_observed_at: Option<Instant>,
    /// Local network generation this pair belongs to.
    pub local_generation: u64,
    /// Current reachability state.
    pub state: CandidatePairState,
    /// Whether the selector has nominated this pair for direct data trials.
    pub nominated: bool,
    /// When this pair was first nominated for direct data trials.
    pub nominated_at: Option<Instant>,
    /// When this pair was first selected by encrypted direct data confirmation.
    pub selected_at: Option<Instant>,
    /// Most recent active probe sent for this pair.
    pub last_probe_at: Option<Instant>,
    /// Active probe packets sent to this pair.
    pub probe_count: u64,
    /// First successful bidirectional probe or encrypted packet.
    pub first_success_at: Option<Instant>,
    /// Most recent successful bidirectional probe or encrypted packet.
    pub last_success_at: Option<Instant>,
    /// Most recent failed probe/path event.
    pub last_failure_at: Option<Instant>,
    /// Consecutive pair-level failures since the last success.
    pub consecutive_failures: u32,
    /// Stable machine-readable reason for the last failure.
    pub last_error_code: Option<String>,
    /// Human-readable last failure detail.
    pub last_error: Option<String>,
    /// Most recent RTT measurement for this pair.
    pub rtt_ms: Option<u64>,
    /// Smoothed RTT estimate for this pair.
    pub rtt_ewma_ms: Option<u64>,
    /// Smoothed absolute RTT variation for this pair.
    pub jitter_ms: Option<u64>,
    /// Successful reachability samples observed for this pair.
    pub success_count: u64,
    /// Failed reachability samples observed for this pair.
    pub failure_count: u64,
}

impl CandidatePair {
    pub(super) fn new_with_source(
        remote_endpoint: SocketAddr,
        local_generation: u64,
        source: CandidatePairSource,
    ) -> Self {
        Self {
            local_endpoint: None,
            remote_endpoint,
            source,
            source_observed_at: Some(Instant::now()),
            local_generation,
            state: CandidatePairState::Waiting,
            nominated: false,
            nominated_at: None,
            selected_at: None,
            last_probe_at: None,
            probe_count: 0,
            first_success_at: None,
            last_success_at: None,
            last_failure_at: None,
            consecutive_failures: 0,
            last_error_code: None,
            last_error: None,
            rtt_ms: None,
            rtt_ewma_ms: None,
            jitter_ms: None,
            success_count: 0,
            failure_count: 0,
        }
    }

    pub(super) fn promote_source(&mut self, source: CandidatePairSource) {
        if candidate_pair_source_rank(source) < candidate_pair_source_rank(self.source) {
            self.source = source;
        }
    }

    pub(super) fn observe_source(&mut self, source: CandidatePairSource) {
        if candidate_pair_source_rank(source) <= candidate_pair_source_rank(self.source) {
            self.source = source;
            self.source_observed_at = Some(Instant::now());
        }
    }

    pub(super) fn record_probing(&mut self, local_endpoint: Option<SocketAddr>) {
        if local_endpoint.is_some() {
            self.local_endpoint = local_endpoint;
        }
        self.last_probe_at = Some(Instant::now());
        self.probe_count = self.probe_count.saturating_add(1);
        if !matches!(
            self.state,
            CandidatePairState::Succeeded | CandidatePairState::Selected
        ) {
            self.state = CandidatePairState::Probing;
        }
    }

    pub(super) fn record_success(
        &mut self,
        latency: Option<Duration>,
        selected: bool,
        local_endpoint: Option<SocketAddr>,
    ) {
        let now = Instant::now();
        if local_endpoint.is_some() {
            self.local_endpoint = local_endpoint;
        }
        if self.first_success_at.is_none() {
            self.first_success_at = Some(now);
        }
        self.last_success_at = Some(now);
        self.consecutive_failures = 0;
        self.success_count = self.success_count.saturating_add(1);
        self.last_error_code = None;
        self.last_error = None;
        if let Some(latency) = latency {
            let latency_ms = duration_millis(latency);
            self.rtt_ms = Some(latency_ms);
            update_latency_ewma(&mut self.rtt_ewma_ms, &mut self.jitter_ms, latency_ms);
        }
        if selected {
            self.nominated = true;
            if self.nominated_at.is_none() {
                self.nominated_at = Some(now);
            }
            if self.selected_at.is_none() {
                self.selected_at = Some(now);
            }
            self.state = CandidatePairState::Selected;
        } else if self.state != CandidatePairState::Selected {
            self.state = CandidatePairState::Succeeded;
        }
    }

    pub(super) fn nominate(&mut self, local_endpoint: Option<SocketAddr>) -> bool {
        if local_endpoint.is_some() {
            self.local_endpoint = local_endpoint;
        }
        if !matches!(
            self.state,
            CandidatePairState::Probing
                | CandidatePairState::Succeeded
                | CandidatePairState::Degraded
                | CandidatePairState::Selected
        ) || self.nominated
        {
            return false;
        }

        self.nominated = true;
        self.nominated_at = Some(Instant::now());
        true
    }

    pub(super) fn nomination_age(&self) -> Option<Duration> {
        self.nominated_at.map(|nominated_at| nominated_at.elapsed())
    }

    pub(super) fn expire_stale_nomination(
        &mut self,
        window: Duration,
        reason: impl Into<String>,
        local_endpoint: Option<SocketAddr>,
    ) -> bool {
        if !self.nominated || self.selected_at.is_some() {
            return false;
        }
        if self.nomination_age().is_none_or(|age| age <= window) {
            return false;
        }

        self.nominated = false;
        self.nominated_at = None;
        self.record_failure(REASON_DIRECT_TRIAL_EXPIRED, reason, local_endpoint);
        true
    }

    pub(super) fn record_failure(
        &mut self,
        code: impl Into<String>,
        reason: impl Into<String>,
        local_endpoint: Option<SocketAddr>,
    ) {
        if local_endpoint.is_some() {
            self.local_endpoint = local_endpoint;
        }
        self.last_failure_at = Some(Instant::now());
        self.consecutive_failures = self.consecutive_failures.saturating_add(1);
        self.failure_count = self.failure_count.saturating_add(1);
        self.last_error_code = Some(code.into());
        self.last_error = Some(reason.into());
        self.state = if matches!(
            self.state,
            CandidatePairState::Succeeded | CandidatePairState::Selected
        ) {
            CandidatePairState::Degraded
        } else {
            CandidatePairState::Failed
        };
    }

    pub(super) fn record_generation_change(&mut self, reason: impl Into<String>) {
        self.record_failure(REASON_NETWORK_GENERATION_CHANGED, reason, None);
        self.state = CandidatePairState::Degraded;
    }

    pub(super) fn retained_for_generation(&self, local_generation: u64) -> Self {
        let mut retained = self.clone();
        let now = Instant::now();
        retained.local_generation = local_generation;
        retained.state = CandidatePairState::Selected;
        retained.nominated = true;
        retained.nominated_at.get_or_insert(now);
        retained.selected_at.get_or_insert(now);
        retained.first_success_at.get_or_insert(now);
        retained.last_success_at.get_or_insert(now);
        retained.consecutive_failures = 0;
        retained.last_error_code = None;
        retained.last_error = None;
        retained
    }

    pub(super) fn failure_age(&self) -> Option<Duration> {
        self.last_failure_at
            .map(|last_failure| last_failure.elapsed())
    }

    pub(super) fn first_success_age(&self) -> Option<Duration> {
        self.first_success_at
            .map(|first_success| first_success.elapsed())
    }

    pub(super) fn success_age(&self) -> Option<Duration> {
        self.last_success_at
            .map(|last_success| last_success.elapsed())
    }
}

/// Health counters for one transport path.
#[derive(Debug, Clone, Default)]
pub struct PathHealth {
    /// Last successful path event.
    pub last_success_at: Option<Instant>,
    /// Last failed path event.
    pub last_failure_at: Option<Instant>,
    /// Consecutive failures since the last success.
    pub consecutive_failures: u32,
    /// Last diagnostic error for this path.
    pub last_error: Option<String>,
    /// Stable machine-readable reason for the last failure.
    pub last_error_code: Option<String>,
    /// Most recent measured round-trip time for this path.
    pub latency_ms: Option<u64>,
    /// Smoothed RTT estimate for this path.
    pub rtt_ewma_ms: Option<u64>,
    /// Smoothed absolute RTT variation for this path.
    pub jitter_ms: Option<u64>,
    /// Successful path samples observed.
    pub success_count: u64,
    /// Failed path samples observed.
    pub failure_count: u64,
}

impl PathHealth {
    pub(super) fn record_success(&mut self) {
        self.last_success_at = Some(Instant::now());
        self.consecutive_failures = 0;
        self.success_count = self.success_count.saturating_add(1);
        self.last_error = None;
        self.last_error_code = None;
    }

    pub(super) fn record_success_with_latency(&mut self, latency: Duration) {
        self.record_success();
        let latency_ms = duration_millis(latency);
        self.latency_ms = Some(latency_ms);
        update_latency_ewma(&mut self.rtt_ewma_ms, &mut self.jitter_ms, latency_ms);
    }

    pub(super) fn record_failure(&mut self, code: impl Into<String>, reason: impl Into<String>) {
        self.last_failure_at = Some(Instant::now());
        self.consecutive_failures = self.consecutive_failures.saturating_add(1);
        self.failure_count = self.failure_count.saturating_add(1);
        self.last_error_code = Some(code.into());
        self.last_error = Some(reason.into());
    }

    pub(super) fn record_generation_change(&mut self, reason: impl Into<String>) {
        self.last_success_at = None;
        self.latency_ms = None;
        self.rtt_ewma_ms = None;
        self.jitter_ms = None;
        self.consecutive_failures = 0;
        self.record_failure(REASON_NETWORK_GENERATION_CHANGED, reason);
    }

    pub(super) fn failure_age(&self) -> Option<Duration> {
        self.last_failure_at
            .map(|last_failure| last_failure.elapsed())
    }

    pub(super) fn success_age(&self) -> Option<Duration> {
        self.last_success_at
            .map(|last_success| last_success.elapsed())
    }

    pub(super) fn is_confirmed(&self) -> bool {
        self.last_success_at.is_some_and(|success| {
            self.last_failure_at
                .map(|failure| success >= failure)
                .unwrap_or(true)
        })
    }

    pub(super) fn is_confirmed_recent(&self, max_age: Duration) -> bool {
        self.is_confirmed()
            && self
                .success_age()
                .map(|age| age <= max_age)
                .unwrap_or(false)
    }

    pub(super) fn retry_after(&self, base: Duration) -> Duration {
        if base.is_zero() || self.consecutive_failures <= 1 {
            return base;
        }
        let exponent = self
            .consecutive_failures
            .saturating_sub(1)
            .min(DIRECT_RETRY_BACKOFF_MAX_EXPONENT);
        base.checked_mul(1_u32 << exponent).unwrap_or(Duration::MAX)
    }

    pub(super) fn retry_remaining(&self, base: Duration) -> Duration {
        let retry_after = self.retry_after(base);
        match self.failure_age() {
            Some(age) if age < retry_after => retry_after - age,
            _ => Duration::ZERO,
        }
    }

    pub(super) fn retry_due(&self, base: Duration) -> bool {
        self.retry_remaining(base).is_zero()
    }
}
