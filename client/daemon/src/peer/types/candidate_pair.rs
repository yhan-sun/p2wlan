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
