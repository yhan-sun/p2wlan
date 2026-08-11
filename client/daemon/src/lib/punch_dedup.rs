#[derive(Clone, Default)]
struct PunchAttemptDeduplicator {
    state: Arc<std::sync::Mutex<PunchAttemptState>>,
}

#[derive(Default)]
struct PunchAttemptState {
    next_session_id: u64,
    active: HashMap<String, PunchAttemptRecord>,
}

struct PunchAttemptRecord {
    session_id: u64,
    priority: u8,
    /// Recovery epoch the claim belongs to (0 for epoch-less legacy claims).
    /// A claim from a different non-zero epoch normally supersedes the active
    /// session. A same-generation plan that reaches the short rendezvous lead
    /// is folded instead, so a candidate refresh cannot erase its first send.
    epoch: u64,
    /// Identity of the fresh-mapping prediction backing this session, when
    /// the session is a fresh-prediction claim.  Ordering is lexicographic on
    /// (incarnation boot epoch, generation): a newer incarnation supersedes
    /// an older one, and within one incarnation a newer generation wins.
    fresh_generation: Option<crate::FreshPredictionId>,
    /// Local network generation captured when this punch plan was admitted.
    /// Epochs normally rotate with this value, but keeping it on the active
    /// permit makes a generation-changing replacement explicit rather than
    /// looking like an arbitrary dedup cancellation.
    network_generation: u64,
    /// Relay-coordinated first-send target for this session. A non-fresh
    /// candidate update inside the same epoch must not re-clock this window.
    punch_at_ms: Option<u64>,
    /// Set at the dispatch boundary immediately before the first owned send
    /// sweep. It gives a short, bounded protection interval to a rendezvous
    /// that has already reached its first-send edge.
    first_send_started_at_ms: Option<u64>,
    cancellation: Arc<PunchSessionCancellation>,
}

/// Why a new trigger was deliberately folded into the active punch plan.
///
/// This is separate from a hard cancellation: callers use it to record that
/// a candidate refresh or fresh prediction did not silently erase a valid
/// first rendezvous window.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PunchClaimDeferredReason {
    SameEpochActive,
    LowerPriorityActive,
    SameOrOlderFreshPrediction,
    RendezvousLeadProtected,
    FirstSendProtected,
}

impl PunchClaimDeferredReason {
    fn label(self) -> &'static str {
        match self {
            Self::SameEpochActive => "same_epoch_active_session",
            Self::LowerPriorityActive => "higher_priority_active_session",
            Self::SameOrOlderFreshPrediction => "same_or_older_fresh_prediction",
            Self::RendezvousLeadProtected => "active_rendezvous_lead_protected",
            Self::FirstSendProtected => "active_first_send_protected",
        }
    }
}

/// Details of an incoming trigger that was merged into an active plan.
#[derive(Debug, Clone, Copy)]
struct DeferredPunchClaim {
    active_session_id: u64,
    active_epoch: u64,
    active_network_generation: u64,
    active_punch_at_ms: Option<u64>,
    reason: PunchClaimDeferredReason,
}

/// Result of claiming a relay-coordinated synchronized punch.
///
/// Unlike the legacy `Option` return, this preserves the reason and active
/// plan identity when a trigger is folded into a currently valid window.
enum RendezvousPunchClaim {
    Claimed(PunchSessionPermit),
    Deferred(DeferredPunchClaim),
}

/// Explicit reason recorded by a cancelled permit. The cancellation itself
/// remains synchronous so it can still stop an owned worker at its next gate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PunchCancellationReason {
    PeerLifecycle,
    NetworkGenerationChanged,
    RecoveryEpochChanged,
    SynchronizedPreemptedBackground,
    FreshPredictionPreempted,
}

impl PunchCancellationReason {
    fn label(self) -> &'static str {
        match self {
            Self::PeerLifecycle => "peer_lifecycle",
            Self::NetworkGenerationChanged => "network_generation_changed",
            Self::RecoveryEpochChanged => "recovery_epoch_changed",
            Self::SynchronizedPreemptedBackground => "synchronized_preempted_background",
            Self::FreshPredictionPreempted => "fresh_prediction_preempted",
        }
    }
}

/// Background retry / birthday sweep sessions.  Never preempts anything.
const PUNCH_PRIORITY_BACKGROUND: u8 = 0;
/// Ordinary synchronized punch (candidate refresh, handshake offers).
const PUNCH_PRIORITY_SYNCHRONIZED: u8 = 1;
/// Synchronized punch triggered by a fresh-mapping prediction signal.
///
/// The peer measured its NAT port sequence and signaled a predicted window;
/// this session must preempt every older ordinary/birthday session so the
/// prediction is used while it is still fresh.
const PUNCH_PRIORITY_FRESH_PREDICTION: u8 = 2;

#[derive(Default)]
pub(crate) struct PunchSessionCancellation {
    cancelled: std::sync::atomic::AtomicBool,
    notify: tokio::sync::Notify,
    reason: std::sync::Mutex<Option<PunchCancellationReason>>,
}

struct PunchSessionPermit {
    owner: PunchAttemptDeduplicator,
    peer_id: String,
    session_id: u64,
    cancellation: Arc<PunchSessionCancellation>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PunchSessionOutcome {
    Completed,
    Cancelled,
    DeadlineExceeded,
}

impl PunchSessionCancellation {
    /// External lifecycle and test cancellation. Scheduler replacements use
    /// `cancel_with_reason` so their precise cause remains observable.
    #[cfg(test)]
    pub(crate) fn cancel(&self) {
        self.cancel_with_reason(PunchCancellationReason::PeerLifecycle);
    }

    fn cancel_with_reason(&self, reason: PunchCancellationReason) {
        let mut recorded = self
            .reason
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if recorded.is_none() {
            *recorded = Some(reason);
        }
        drop(recorded);
        self.cancelled
            .store(true, std::sync::atomic::Ordering::Release);
        self.notify.notify_waiters();
    }

    async fn cancelled(&self) {
        loop {
            let notified = self.notify.notified();
            if self
                .cancelled
                .load(std::sync::atomic::Ordering::Acquire)
            {
                return;
            }
            notified.await;
        }
    }

    pub(crate) fn is_cancelled(&self) -> bool {
        self.cancelled
            .load(std::sync::atomic::Ordering::Acquire)
    }

    fn cancellation_reason(&self) -> Option<PunchCancellationReason> {
        *self
            .reason
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }
}

impl PunchSessionPermit {
    async fn cancelled(&self) {
        self.cancellation.cancelled().await;
    }

    fn is_cancelled(&self) -> bool {
        self.cancellation.is_cancelled()
    }

    /// Handle for watchers that must observe this session's cancellation
    /// (e.g. cleanup of a provisional fresh-mapping socket whose owning work
    /// future may be dropped at an await point).
    pub(crate) fn cancellation_handle(&self) -> Arc<PunchSessionCancellation> {
        self.cancellation.clone()
    }

    fn session_id(&self) -> u64 {
        self.session_id
    }

    fn cancellation_reason(&self) -> Option<PunchCancellationReason> {
        self.cancellation.cancellation_reason()
    }

    /// Mark the first owned UDP send dispatch. This is deliberately a
    /// synchronous operation: a concurrent fresh signal sees the protection
    /// before it can cancel the rendezvous whose first packet is about to
    /// leave the socket.
    fn mark_first_send_started(&self) -> u64 {
        self.owner
            .mark_first_send_started(&self.peer_id, self.session_id)
    }
}

impl Drop for PunchSessionPermit {
    fn drop(&mut self) {
        self.owner.release(&self.peer_id, self.session_id);
    }
}

impl PunchAttemptDeduplicator {
    #[cfg(test)]
    async fn claim(&self, peer_id: &str) -> Option<PunchSessionPermit> {
        self.claim_with_priority(peer_id, 0, PUNCH_PRIORITY_SYNCHRONIZED, None)
    }

    #[cfg(test)]
    async fn claim_with_window(
        &self,
        peer_id: &str,
        _window: Duration,
    ) -> Option<PunchSessionPermit> {
        self.claim_with_priority(peer_id, 0, PUNCH_PRIORITY_BACKGROUND, None)
    }

    /// Claim the punch session for a recovery-epoch-scoped trigger.
    ///
    /// All production punch entry points (offers, fresh predictions,
    /// background retries, peer-reflexive observations) claim through here:
    /// the epoch is the authoritative `(peer_id, generation, epoch)` plan
    /// identity, so a new plan always supersedes the active session while
    /// triggers inside the SAME plan follow the priority rules below.
    async fn claim_for_epoch(
        &self,
        peer_id: &str,
        epoch: u64,
        priority: u8,
        fresh_generation: Option<crate::FreshPredictionId>,
    ) -> Option<PunchSessionPermit> {
        self.claim_with_priority(peer_id, epoch, priority, fresh_generation)
    }

    /// Claim a relay-coordinated rendezvous session with the complete plan
    /// identity. Same-generation refreshes are folded into an active first
    /// window; only a real generation change can bypass that short protection.
    async fn claim_for_epoch_with_rendezvous(
        &self,
        peer_id: &str,
        network_generation: u64,
        epoch: u64,
        priority: u8,
        fresh_generation: Option<crate::FreshPredictionId>,
        punch_at_ms: Option<u64>,
    ) -> RendezvousPunchClaim {
        self.claim_with_rendezvous(
            peer_id,
            network_generation,
            epoch,
            priority,
            fresh_generation,
            punch_at_ms,
        )
    }

    /// Claim the punch session for a fresh-mapping prediction signal.
    ///
    /// `signal_id` is the incarnation+generation identity carried by the
    /// offer that delivered the predicted window.  A newer fresh prediction
    /// supersedes an older one at the same priority (including one from an
    /// older daemon incarnation); any older ordinary or background session is
    /// cancelled immediately.
    #[cfg(test)]
    async fn claim_fresh_prediction(
        &self,
        peer_id: &str,
        signal_id: crate::FreshPredictionId,
    ) -> Option<PunchSessionPermit> {
        self.claim_with_priority(peer_id, 0, PUNCH_PRIORITY_FRESH_PREDICTION, Some(signal_id))
    }

    fn claim_with_priority(
        &self,
        peer_id: &str,
        epoch: u64,
        priority: u8,
        fresh_generation: Option<crate::FreshPredictionId>,
    ) -> Option<PunchSessionPermit> {
        match self.claim_with_rendezvous(peer_id, 0, epoch, priority, fresh_generation, None) {
            RendezvousPunchClaim::Claimed(permit) => Some(permit),
            RendezvousPunchClaim::Deferred(_) => None,
        }
    }

    fn claim_with_rendezvous(
        &self,
        peer_id: &str,
        network_generation: u64,
        epoch: u64,
        priority: u8,
        fresh_generation: Option<crate::FreshPredictionId>,
        punch_at_ms: Option<u64>,
    ) -> RendezvousPunchClaim {
        let mut state = self.state.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        if let Some(active) = state.active.get(peer_id) {
            let generation_preempts = active.network_generation != 0
                && network_generation != 0
                && active.network_generation != network_generation;
            let epoch_preempts = active.epoch != 0 && epoch != 0 && active.epoch != epoch;
            let priority_preempts = active.priority < priority;
            let newer_fresh_preempts = active.priority == priority
                && priority == PUNCH_PRIORITY_FRESH_PREDICTION
                && active
                    .fresh_generation
                    .is_some_and(|active_id| fresh_generation.is_some_and(|id| id > active_id));
            let preempt = generation_preempts
                || epoch_preempts
                || priority_preempts
                || newer_fresh_preempts;
            if !preempt {
                let reason = if priority < active.priority {
                    PunchClaimDeferredReason::LowerPriorityActive
                } else if priority == PUNCH_PRIORITY_FRESH_PREDICTION {
                    PunchClaimDeferredReason::SameOrOlderFreshPrediction
                } else {
                    PunchClaimDeferredReason::SameEpochActive
                };
                return RendezvousPunchClaim::Deferred(DeferredPunchClaim {
                    active_session_id: active.session_id,
                    active_epoch: active.epoch,
                    active_network_generation: active.network_generation,
                    active_punch_at_ms: active.punch_at_ms,
                    reason,
                });
            }

            // Candidate refresh and a newer fresh prediction remain useful,
            // but cannot erase a same-generation rendezvous once it reached
            // the lead or first-send edge. The caller records and stashes the
            // newest trusted target for the active session instead.
            if !generation_preempts && active.first_send_is_protected(now_unix_millis()) {
                let reason = if active.first_send_started_at_ms.is_some() {
                    PunchClaimDeferredReason::FirstSendProtected
                } else {
                    PunchClaimDeferredReason::RendezvousLeadProtected
                };
                return RendezvousPunchClaim::Deferred(DeferredPunchClaim {
                    active_session_id: active.session_id,
                    active_epoch: active.epoch,
                    active_network_generation: active.network_generation,
                    active_punch_at_ms: active.punch_at_ms,
                    reason,
                });
            }

            let reason = if generation_preempts {
                PunchCancellationReason::NetworkGenerationChanged
            } else if epoch_preempts {
                PunchCancellationReason::RecoveryEpochChanged
            } else if priority == PUNCH_PRIORITY_FRESH_PREDICTION {
                PunchCancellationReason::FreshPredictionPreempted
            } else {
                PunchCancellationReason::SynchronizedPreemptedBackground
            };
            active.cancellation.cancel_with_reason(reason);
        }

        state.next_session_id = state.next_session_id.wrapping_add(1).max(1);
        let session_id = state.next_session_id;
        let cancellation = Arc::new(PunchSessionCancellation::default());
        state.active.insert(
            peer_id.to_string(),
            PunchAttemptRecord {
                session_id,
                priority,
                epoch,
                fresh_generation,
                network_generation,
                punch_at_ms,
                first_send_started_at_ms: None,
                cancellation: cancellation.clone(),
            },
        );
        RendezvousPunchClaim::Claimed(PunchSessionPermit {
            owner: self.clone(),
            peer_id: peer_id.to_string(),
            session_id,
            cancellation,
        })
    }

    fn mark_first_send_started(&self, peer_id: &str, session_id: u64) -> u64 {
        let now = now_unix_millis();
        let mut state = self.state.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        if let Some(active) = state.active.get_mut(peer_id) {
            if active.session_id == session_id {
                return *active.first_send_started_at_ms.get_or_insert(now);
            }
        }
        now
    }

    fn release(&self, peer_id: &str, session_id: u64) {
        let mut state = self.state.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        if state
            .active
            .get(peer_id)
            .is_some_and(|active| active.session_id == session_id)
        {
            state.active.remove(peer_id);
        }
    }

    /// Cancel and drop the active session for a peer (peer left / offline).
    ///
    /// A fast rejoin must not be suppressed by a stale punch session, nor
    /// must that stale session keep mutating socket state after the peer is
    /// gone.
    pub(crate) fn cancel(&self, peer_id: &str) {
        let mut state = self.state.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        if let Some(active) = state.active.remove(peer_id) {
            active
                .cancellation
                .cancel_with_reason(PunchCancellationReason::PeerLifecycle);
        }
    }

    #[cfg(test)]
    fn active_session_count(&self) -> usize {
        self.state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .active
            .len()
    }
}

impl PunchAttemptRecord {
    fn first_send_is_protected(&self, now_ms: u64) -> bool {
        let guard_ms = RELAY_ASSISTED_PUNCH_LEAD.as_millis() as u64;
        if let Some(first_send_started_at_ms) = self.first_send_started_at_ms {
            return now_ms.saturating_sub(first_send_started_at_ms) <= guard_ms;
        }
        let Some(punch_at_ms) = self.punch_at_ms else {
            return false;
        };
        let lead_start = punch_at_ms.saturating_sub(guard_ms);
        let lead_end = punch_at_ms.saturating_add(guard_ms);
        (lead_start..=lead_end).contains(&now_ms)
    }
}

fn now_unix_millis() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
        .try_into()
        .unwrap_or(u64::MAX)
}

/// Run a punch session with a caller-chosen hard deadline.
///
/// Wide remote-scatter sweeps plan hundreds of ports across multiple sockets
/// and need a deadline derived from the actual probe schedule instead of the
/// fixed 24s bound, which kills them mid-scan before the tail of the birthday
/// window has been covered.
async fn run_owned_punch_session_with_deadline<F>(
    session: &PunchSessionPermit,
    deadline: Duration,
    work: F,
) -> PunchSessionOutcome
where
    F: std::future::Future<Output = ()>,
{
    tokio::select! {
        biased;
        _ = session.cancelled() => PunchSessionOutcome::Cancelled,
        _ = sleep(deadline) => PunchSessionOutcome::DeadlineExceeded,
        _ = work => PunchSessionOutcome::Completed,
    }
}

fn should_cancel_maintenance_offer(
    is_rekey: bool,
    has_session: bool,
    needs_rekey: bool,
    expired: bool,
    has_pending_responder: bool,
) -> bool {
    if has_pending_responder {
        return true;
    }
    if is_rekey {
        has_session && !needs_rekey && !expired
    } else {
        has_session
    }
}
