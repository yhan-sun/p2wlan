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
    /// Most recent outbound-UDP liveness verdict for this peer (punch-time
    /// diagnostic; distinct from the STUN-phase `UdpBlocked`).  None until the
    /// first probe; cleared on network-generation change so a stale egress
    /// verdict never survives an IP change.
    pub last_liveness: Option<p2pnet_nat::outbound_liveness::LivenessVerdict>,
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

    /// Record an authoritative data-plane RTT.  Candidate probes are useful
    /// for ranking, but their timestamp can include NAT-sweep queueing.  An
    /// encrypted Request -> ACK exchange is stronger evidence and must replace
    /// that stale sample rather than being blended into it.
    pub(super) fn record_success_with_authoritative_latency(&mut self, latency: Duration) {
        self.record_success();
        let latency_ms = duration_millis(latency);
        self.latency_ms = Some(latency_ms);
        self.rtt_ewma_ms = Some(latency_ms);
        self.jitter_ms = Some(0);
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
        self.last_liveness = None;
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

    /// Whether the next retry is due using a fixed short cadence, ignoring
    /// the exponential backoff growth.
    ///
    /// Used only for a peer whose relay path already carries the data plane
    /// during a background Direct retry.  There the retry interval is a
    /// scan-density choice, not a failure-avoidance backoff: the wide scatter
    /// window must stay warm so the first probe after a transient UDP black
    /// hole clears lands immediately (field evidence: a dual-CGNAT cold-start
    /// round sat at the 7-8s exponential cap for the whole window and then
    /// matched exactly on the first post-hole retry probe).  An exponential
    /// ramp in that state only delays the eventual hit.
    pub(super) fn retry_due_relay_flat(&self, base: Duration) -> bool {
        match self.failure_age() {
            Some(age) => age >= base,
            None => true,
        }
    }
}
