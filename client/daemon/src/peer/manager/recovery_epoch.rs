// ============================================================
// Recovery epoch: the authoritative per-peer traversal scheduler
// ============================================================
//
// The failure-recovery scheduler owns ONE traversal plan per
// `(peer_id, network_generation, recovery_epoch)`.
//
// Every punch trigger (offer, fresh prediction, background retry,
// peer-reflexive, birthday scan, reclaim) enters through
// `PeerManager::recovery_epoch_admit` and shares the same per-epoch
// budget: outbound probe credit, fresh-mapping generations, fresh sockets
// and HTTP publishes.  New candidates can only update the newest-wins
// pending target; they can never reset the failure backoff, spawn a
// parallel fresh socket, bypass the epoch's probe credit or keep working
// after Direct / PeerLeft / a generation advance.
//
// Recovery itself is a feedback-driven stage machine:
// `Initial -> Predicted -> ScatterSmall -> ScatterExtended -> RelayBackoff`.
// Widening the scan is only allowed after a bounded ACK-feedback window
// produced NO matched ACK; any matched ACK resets the stage so a live path
// is never expanded.

use tokio::sync::Notify;

/// Total outbound-probe credit for one recovery epoch.
///
/// A failing peer can burn at most this many probes per recovery episode
/// regardless of how many offers, retries or fresh predictions arrive.  The
/// 60-second persistent budgets in the UDP layer remain as the rate ceiling;
/// this is the per-epoch *total*.
pub(crate) const RECOVERY_EPOCH_PROBE_CREDIT: u32 = 4_000;

/// Fresh-mapping generations allowed per recovery epoch.  Each generation
/// allocates one dedicated dynamic socket, so this also caps fresh sockets.
pub(crate) const RECOVERY_EPOCH_FRESH_GENERATIONS: u32 = 1;

/// HTTP publishes (fresh-prediction advertisements) allowed per recovery
/// epoch.
pub(crate) const RECOVERY_EPOCH_HTTP_PUBLISHES: u32 = 8;

/// An exhausted epoch is re-armed after this age so long-running recovery
/// keeps a slow heartbeat; age-based rotation is time-driven, not
/// candidate-driven, so churn can never reset the budget.
pub(crate) const RECOVERY_EPOCH_MAX_AGE: Duration = Duration::from_secs(30 * 60);

/// Per-stage probe ceilings (the stage target construction enforces these in
/// addition to the epoch credit).
pub(crate) const RECOVERY_STAGE_INITIAL_MAX_PROBES: u32 = 96;
pub(crate) const RECOVERY_STAGE_PREDICTED_MAX_PROBES: u32 = 384;
pub(crate) const RECOVERY_STAGE_SCATTER_SMALL_MAX_PROBES: u32 = 512;

/// Bounded feedback window a stage waits for a matched ACK before the next
/// stage may expand the scan.
pub(crate) const RECOVERY_EPOCH_ACK_FEEDBACK_WINDOW: Duration = Duration::from_secs(2);

/// Stages of one failure-recovery epoch.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum RecoveryStage {
    /// Trusted endpoints only (signaled, learned, recently successful).
    Initial,
    /// Predicted port window (local fresh model or remote frozen prediction).
    Predicted,
    /// Small remote-port scatter around the best base ports.
    ScatterSmall,
    /// Extended remote-port scatter (birthday windows).  Only reachable
    /// after ScatterSmall produced zero matched ACKs.
    ScatterExtended,
    /// Relay path governs; exponential backoff paces retries.
    RelayBackoff,
}

impl RecoveryStage {
    pub(crate) fn label(self) -> &'static str {
        match self {
            RecoveryStage::Initial => "initial",
            RecoveryStage::Predicted => "predicted",
            RecoveryStage::ScatterSmall => "scatter_small",
            RecoveryStage::ScatterExtended => "scatter_extended",
            RecoveryStage::RelayBackoff => "relay_backoff",
        }
    }

    /// Probe ceiling for the stage's target set.
    pub(crate) fn max_probes(self) -> u32 {
        match self {
            RecoveryStage::Initial => RECOVERY_STAGE_INITIAL_MAX_PROBES,
            RecoveryStage::Predicted => RECOVERY_STAGE_PREDICTED_MAX_PROBES,
            RecoveryStage::ScatterSmall => RECOVERY_STAGE_SCATTER_SMALL_MAX_PROBES,
            // ScatterExtended AND RelayBackoff keep the full scatter coverage:
            // relay is the data-plane fallback, but the traversal scan must
            // still cover the peer's whole predicted window (capping it back
            // to 96 ports made the scan permanently incomplete on
            // address/port-dependent peers).
            RecoveryStage::ScatterExtended | RecoveryStage::RelayBackoff => u32::MAX,
        }
    }
}

/// Verdict of a punch trigger against the epoch scheduler.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RecoveryAdmission {
    /// The trigger may start (or continue) the epoch's single session.
    Accepted { epoch: u64 },
    /// The peer is Direct, gone or offline: no recovery work may start.
    Superseded,
}

/// Newest-wins pending target: a newer trigger replaces the pending target
/// but can never spawn a parallel session or reset the epoch's budgets.
#[derive(Debug, Clone)]
pub(crate) struct PendingRecoveryTarget {
    pub peer_id: String,
    /// Shared candidate set snapshot at trigger time.
    pub candidates: Vec<SocketAddr>,
    /// Immutable frozen targets for a fresh-prediction session.
    pub frozen_targets: Option<Vec<SocketAddr>>,
    /// Fresh-prediction identity when the trigger is a fresh signal.
    pub fresh_prediction: Option<crate::FreshPredictionId>,
    pub punch_at_ms: Option<u64>,
    pub seen_at: Instant,
}

/// Per-peer recovery epoch state.
#[derive(Debug, Clone)]
pub(crate) struct RecoveryEpochState {
    pub epoch: u64,
    pub network_generation: u64,
    pub stage: RecoveryStage,
    pub stage_started_at: Instant,
    pub epoch_started_at: Instant,
    /// Remaining outbound probe credit for this epoch.
    pub epoch_probe_credit_remaining: u32,
    /// Remaining fresh-mapping generations (and fresh sockets) for this epoch.
    pub epoch_fresh_generation_quota_remaining: u32,
    /// Remaining HTTP publishes (fresh-prediction advertisements).
    pub epoch_http_quota_remaining: u32,
    /// Complete scatter windows sent this epoch.
    pub epoch_scatter_windows_sent: u32,
    /// Whether any matched ACK was observed this epoch.
    pub ack_feedback_seen: bool,
    pub last_matched_ack: Option<SocketAddr>,
    pub last_matched_ack_at: Option<Instant>,
    /// Newest-wins pending target awaiting the running session's next stage
    /// boundary.
    pub pending_target: Option<PendingRecoveryTarget>,
}

impl RecoveryEpochState {
    fn new(epoch: u64, network_generation: u64, now: Instant) -> Self {
        Self {
            epoch,
            network_generation,
            stage: RecoveryStage::Initial,
            stage_started_at: now,
            epoch_started_at: now,
            epoch_probe_credit_remaining: RECOVERY_EPOCH_PROBE_CREDIT,
            epoch_fresh_generation_quota_remaining: RECOVERY_EPOCH_FRESH_GENERATIONS,
            epoch_http_quota_remaining: RECOVERY_EPOCH_HTTP_PUBLISHES,
            epoch_scatter_windows_sent: 0,
            ack_feedback_seen: false,
            last_matched_ack: None,
            last_matched_ack_at: None,
            pending_target: None,
        }
    }
}

impl PeerManager {
    /// The authoritative admission gate for every punch trigger.
    ///
    /// A trigger is admitted only while the peer is in recovery and inside
    /// the same `(network_generation, epoch)` plan; a new epoch starts only
    /// on a generation advance, a stale exhausted epoch (age rotation), or
    /// the first trigger after the peer re-entered recovery.  Direct peers,
    /// missing connections and generation changes end the epoch.
    pub(crate) async fn recovery_epoch_admit(&self, peer_id: &str) -> RecoveryAdmission {
        let generation = self.current_network_generation().await;
        let now = Instant::now();

        if self.is_direct(peer_id).await || self.get_connection(peer_id).await.is_none() {
            self.recovery_epoch_end(peer_id, "peer_direct_or_gone").await;
            return RecoveryAdmission::Superseded;
        }

        let mut epochs = self.recovery_epochs.write().await;
        let entry = epochs.entry(peer_id.to_string()).or_insert_with(|| {
            RecoveryEpochState::new(1, generation, now)
        });
        let mut new_epoch = None;
        let rotation_reason = if entry.network_generation != generation {
            "network_generation_changed"
        } else if now.duration_since(entry.epoch_started_at) >= RECOVERY_EPOCH_MAX_AGE {
            "epoch_max_age_exceeded"
        } else {
            ""
        };
        if !rotation_reason.is_empty() {
            new_epoch = Some(entry.epoch.wrapping_add(1));
        }
        if let Some(epoch) = new_epoch {
            info!(
                event = "recovery_epoch_rotated",
                peer_id = %peer_id,
                epoch = epoch,
                network_generation = generation,
                previous_epoch = entry.epoch,
                reason = %rotation_reason,
                "recovery_epoch_rotated peer_id={} epoch={} network_generation={} reason={}",
                peer_id,
                epoch,
                generation,
                rotation_reason,
            );
            *entry = RecoveryEpochState::new(epoch, generation, now);
        }
        RecoveryAdmission::Accepted {
            epoch: entry.epoch,
        }
    }

    /// End (and drop) the recovery epoch for a peer: Direct confirmation,
    /// PeerLeft, offline, public-key change or generation advance.
    pub(crate) async fn recovery_epoch_end(&self, peer_id: &str, reason: &str) {
        let removed = self
            .recovery_epochs
            .write()
            .await
            .remove(peer_id)
            .is_some();
        if removed {
            info!(
                event = "recovery_epoch_ended",
                peer_id = %peer_id,
                reason = %reason,
                "recovery_epoch_ended peer_id={} reason={}",
                peer_id,
                reason
            );
        }
    }

    /// Current recovery epoch number for a peer (0 when none exists).
    pub(crate) async fn recovery_epoch_for(&self, peer_id: &str) -> u64 {
        self.recovery_epochs
            .read()
            .await
            .get(peer_id)
            .map(|state| state.epoch)
            .unwrap_or(0)
    }

    /// Current recovery stage for a peer (Initial when no epoch exists).
    pub(crate) async fn recovery_stage_for(&self, peer_id: &str) -> RecoveryStage {
        self.recovery_epochs
            .read()
            .await
            .get(peer_id)
            .map(|state| state.stage)
            .unwrap_or(RecoveryStage::Initial)
    }

    /// Feedback-driven advancement: a probe batch completed with zero matched
    /// ACKs, so the next stage may widen the scan.
    pub(crate) async fn advance_recovery_stage_after_no_ack(
        &self,
        peer_id: &str,
        detail: &str,
    ) {
        let mut epochs = self.recovery_epochs.write().await;
        let Some(state) = epochs.get_mut(peer_id) else {
            return;
        };
        let next = match state.stage {
            RecoveryStage::Initial => RecoveryStage::Predicted,
            RecoveryStage::Predicted => RecoveryStage::ScatterSmall,
            RecoveryStage::ScatterSmall => RecoveryStage::ScatterExtended,
            RecoveryStage::ScatterExtended => RecoveryStage::ScatterExtended,
            RecoveryStage::RelayBackoff => RecoveryStage::RelayBackoff,
        };
        if next == state.stage {
            return;
        }
        state.stage = next;
        state.stage_started_at = Instant::now();
        info!(
            event = "recovery_stage_advanced",
            peer_id = %peer_id,
            epoch = state.epoch,
            stage = next.label(),
            detail = %detail,
            "recovery_stage_advanced peer_id={} epoch={} stage={} detail={}",
            peer_id,
            state.epoch,
            next.label(),
            detail
        );
    }

    /// Mark the recovery as relay-backed: a hard failure (send error,
    /// handshake timeout) entered the relay-backoff stage where the
    /// exponential backoff paces the retries.
    pub(crate) async fn mark_recovery_relay_backoff(&self, peer_id: &str, reason: &str) {
        let mut epochs = self.recovery_epochs.write().await;
        let Some(state) = epochs.get_mut(peer_id) else {
            return;
        };
        if state.stage == RecoveryStage::RelayBackoff {
            return;
        }
        state.stage = RecoveryStage::RelayBackoff;
        state.stage_started_at = Instant::now();
        info!(
            event = "recovery_stage_relay_backoff",
            peer_id = %peer_id,
            epoch = state.epoch,
            reason = %reason,
            "recovery_stage_relay_backoff peer_id={} epoch={} reason={}",
            peer_id,
            state.epoch,
            reason
        );
    }

    /// Any matched ACK resets the stage: a live path must never be expanded
    /// by a later no-ACK batch.
    pub(crate) async fn record_recovery_ack_feedback(
        &self,
        peer_id: &str,
        endpoint: SocketAddr,
    ) {
        let mut epochs = self.recovery_epochs.write().await;
        let Some(state) = epochs.get_mut(peer_id) else {
            return;
        };
        state.ack_feedback_seen = true;
        state.last_matched_ack = Some(endpoint);
        state.last_matched_ack_at = Some(Instant::now());
        if state.stage != RecoveryStage::Initial {
            state.stage = RecoveryStage::Initial;
            state.stage_started_at = Instant::now();
            info!(
                event = "recovery_stage_reset_by_ack",
                peer_id = %peer_id,
                epoch = state.epoch,
                endpoint = %endpoint,
                "recovery_stage_reset_by_ack peer_id={} epoch={} endpoint={}",
                peer_id,
                state.epoch,
                endpoint
            );
        }
    }

    /// Record one completed scatter-extended window (birthday cursor advance).
    pub(crate) async fn record_recovery_scatter_window(&self, peer_id: &str) {
        let mut epochs = self.recovery_epochs.write().await;
        if let Some(state) = epochs.get_mut(peer_id) {
            state.epoch_scatter_windows_sent = state.epoch_scatter_windows_sent.saturating_add(1);
        }
    }

    /// Consume one unit of the epoch's outbound probe credit.
    ///
    /// Returns `true` when the probe may be sent: no epoch exists (direct
    /// callers and tests) or credit remains.  Returns `false` when the
    /// epoch's hard probe budget is exhausted.
    pub(crate) async fn try_consume_recovery_probe_credit(&self, peer_id: &str) -> bool {
        let mut epochs = self.recovery_epochs.write().await;
        let Some(state) = epochs.get_mut(peer_id) else {
            return true;
        };
        if state.epoch_probe_credit_remaining == 0 {
            return false;
        }
        state.epoch_probe_credit_remaining -= 1;
        true
    }

    /// Consume the epoch's fresh-mapping generation quota (one generation,
    /// one dedicated dynamic socket per epoch).
    pub(crate) async fn try_begin_fresh_generation(&self, peer_id: &str) -> bool {
        let mut epochs = self.recovery_epochs.write().await;
        let Some(state) = epochs.get_mut(peer_id) else {
            return true;
        };
        if state.epoch_fresh_generation_quota_remaining == 0 {
            return false;
        }
        state.epoch_fresh_generation_quota_remaining -= 1;
        true
    }

    /// Consume the epoch's HTTP publish quota (fresh-prediction
    /// advertisements).
    pub(crate) async fn try_consume_recovery_http_quota(&self, peer_id: &str) -> bool {
        let mut epochs = self.recovery_epochs.write().await;
        let Some(state) = epochs.get_mut(peer_id) else {
            return true;
        };
        if state.epoch_http_quota_remaining == 0 {
            return false;
        }
        state.epoch_http_quota_remaining -= 1;
        true
    }

    /// Report the remaining epoch budgets (epoch, probe credit, fresh
    /// generations, HTTP publishes).
    #[cfg(test)]
    pub(crate) async fn recovery_epoch_budget_report(
        &self,
        peer_id: &str,
    ) -> Option<(u64, u32, u32, u32)> {
        self.recovery_epochs
            .read()
            .await
            .get(peer_id)
            .map(|state| {
                (
                    state.epoch,
                    state.epoch_probe_credit_remaining,
                    state.epoch_fresh_generation_quota_remaining,
                    state.epoch_http_quota_remaining,
                )
            })
    }

    /// Newest-wins: a newer trigger replaces the pending target.  A stale
    /// (older) target never overwrites a newer one.
    pub(crate) async fn stash_recovery_target(&self, target: PendingRecoveryTarget) {
        let mut epochs = self.recovery_epochs.write().await;
        let Some(state) = epochs.get_mut(&target.peer_id) else {
            return;
        };
        let replace = state
            .pending_target
            .as_ref()
            .is_none_or(|old| target.seen_at >= old.seen_at);
        if replace {
            state.pending_target = Some(target);
        }
    }

    /// Take the newest pending target for the running session's next stage
    /// boundary, if any.
    pub(crate) async fn take_recovery_target(&self, peer_id: &str) -> Option<PendingRecoveryTarget> {
        self.recovery_epochs
            .write()
            .await
            .get_mut(peer_id)
            .and_then(|state| state.pending_target.take())
    }

    /// Synchronous per-peer direct-commit sequence mirror.  The mirror is
    /// bumped in the same network-epoch critical section as the Direct state
    /// transition, so a send gate that reads it per probe can never miss a
    /// promotion that already committed.
    pub(crate) fn direct_commit_seq_sync(&self, peer_id: &str) -> Option<u64> {
        self.direct_commit_seq_mirror
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .get(peer_id)
            .copied()
    }

    /// Bump the direct-commit sequence for a peer and wake every waiters.
    /// Must be called inside the network-epoch critical section together
    /// with the Direct state transition.
    pub(crate) fn bump_direct_commit_seq(&self, peer_id: &str) -> u64 {
        let seq = {
            let mut mirror = self
                .direct_commit_seq_mirror
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            let entry = mirror.entry(peer_id.to_string()).or_insert(0);
            *entry = entry.wrapping_add(1);
            *entry
        };
        self.direct_commit_notify.notify_waiters();
        seq
    }

    /// Notification for any Direct commit; waiters must re-check the peer's
    /// sequence after waking.
    pub(crate) fn direct_commit_notify(&self) -> Arc<Notify> {
        self.direct_commit_notify.clone()
    }

    /// Bounded feedback wait: block until the peer's direct-commit sequence
    /// advances past `from_seq` (or becomes Some when it was None), or until
    /// `timeout` elapses.  Used instead of a bare sleep so a promotion
    /// reliably preempts the next sweep stage without relying on scheduler
    /// preemption of `yield_now()`.
    pub(crate) async fn wait_for_direct_commit_or_timeout(
        &self,
        peer_id: &str,
        from_seq: Option<u64>,
        timeout: Duration,
    ) -> bool {
        let notify = self.direct_commit_notify();
        let deadline = Instant::now() + timeout;
        loop {
            if self.direct_commit_seq_sync(peer_id) != from_seq {
                return true;
            }
            if self.is_direct_sync(peer_id) {
                return true;
            }
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return false;
            }
            let notified = notify.notified();
            tokio::select! {
                _ = notified => {}
                _ = tokio::time::sleep(remaining) => return false,
            }
        }
    }

    /// Whether the recovery epoch budget diagnostics should be surfaced.
    pub(crate) async fn recovery_epoch_active(&self, peer_id: &str) -> bool {
        self.recovery_epochs.read().await.contains_key(peer_id)
    }
}
