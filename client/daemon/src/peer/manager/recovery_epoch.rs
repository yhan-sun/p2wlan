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
// budget: outbound probe credit, plan builds, sessions, candidate
// iterations, fresh-mapping generations, fresh sockets and HTTP publishes.
// New candidates can only update the newest-wins pending target; they can
// never reset the failure backoff, spawn a parallel fresh socket, bypass
// the epoch's budget or keep working after Direct / PeerLeft / a
// generation advance.
//
// Recovery itself is a feedback-driven stage machine:
// `Initial -> Predicted -> ScatterSmall -> ScatterExtended -> RelayBackoff`.
// Widening the scan is only allowed after a bounded ACK-feedback window
// produced NO matched ACK; any matched ACK resets the stage so a live path
// is never expanded.
//
// A budget-exhausted epoch is FROZEN: `recovery_epoch_admit` returns
// `BudgetExhausted` until a controlled backoff elapses, so a "sent == 0"
// probe batch is never silently swallowed and the next 1-second tick can
// never rebuild the same 778/3072-candidate plan.  Re-opening a frozen
// epoch only happens through the controlled backoff expiry, an epoch
// rotation (generation advance / max age) or authoritative new control-
// plane evidence (online/endpoint/incarnation/offer via the caller), never
// through offer churn.

use tokio::sync::Notify;

/// Total outbound-probe credit for one recovery epoch.
///
/// A failing peer can burn at most this many probes per recovery episode
/// regardless of how many offers, retries or fresh predictions arrive.  The
/// 60-second persistent budgets in the UDP layer remain as the rate ceiling;
/// this is the per-epoch *total*.  4,000 covers the full cold-start
/// progression (96 Initial + 384 Predicted + 512 ScatterSmall + several
/// 3,072-wide ScatterExtended windows) while keeping a failing peer bounded
/// for a whole episode.
pub(crate) const RECOVERY_EPOCH_PROBE_CREDIT: u32 = 4_000;

/// Plan builds allowed per recovery epoch.
///
/// The primary anti-storm control is the budget-exhausted freeze: a plan
/// whose probes were all rejected by the budget is never rebuilt while the
/// epoch is frozen.  This quota is the last-resort ceiling for legitimately
/// progressing stage transitions (Initial -> Predicted -> ScatterSmall ->
/// ScatterExtended, each with cursor-sliced windows that can span several
/// due ticks): 16 plans cover the full progression plus several wide-window
/// slices without ever allowing per-second plan churn to continue
/// indefinitely.
pub(crate) const RECOVERY_EPOCH_PLAN_BUILDS: u32 = 16;

/// Punch sessions allowed per recovery epoch.  Each session is one owned
/// sweep with its own ACK-feedback window; the cap bounds the wall-clock
/// work a failing peer can occupy in the scheduler.
pub(crate) const RECOVERY_EPOCH_SESSIONS: u32 = 16;

/// Candidate evaluations (endpoint iterations inside punch sweeps) allowed
/// per recovery epoch.  This is the hard ceiling on the "traverse the whole
/// 778/3072 endpoint list" work: even when the UDP budget keeps rejecting,
/// the epoch can never iterate more candidates than this total.  Sized to
/// fit the full cold-start capability (several 3,072-wide windows) without
/// ever permitting millions of rejected iterations per second.
pub(crate) const RECOVERY_EPOCH_CANDIDATE_ITERATIONS: u64 = 30_000;

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

/// Bounded re-opens of a frozen/exhausted epoch driven by NEW authenticated
/// evidence (an inbound authenticated punch, a peer-reflexive observation, a
/// matched ACK already has its own unfreeze path).  Each re-open grants a
/// small retry allowance so the evidence can actually be acted on, but the
/// per-epoch cap keeps repeated evidence from turning into an endless
/// re-planning loop.
pub(crate) const RECOVERY_EPOCH_MAX_EVIDENCE_REOPENS: u32 = 8;

/// Probe credit granted by one evidence-driven re-open: enough for one
/// targeted retry of the stable socket-pool mappings (3-4 endpoints x a few
/// attempts plus the triggered check), never a full-epoch refill.
pub(crate) const RECOVERY_EVIDENCE_RETRY_CREDIT: u32 = 96;

/// Plan builds regranted by one evidence-driven re-open (one plan for the
/// retry plus one for the stage follow-up).
pub(crate) const RECOVERY_EVIDENCE_REGRANT_PLAN_BUILDS: u32 = 2;

/// Sessions regranted by one evidence-driven re-open.
pub(crate) const RECOVERY_EVIDENCE_REGRANT_SESSIONS: u32 = 1;

/// Per-stage probe ceilings (the stage target construction enforces these in
/// addition to the epoch credit).
///
/// v0.1.116: all ActivePool stage ceilings are bounded by the punch session's
/// physical-datagram cap (192) so a planned window always fits ONE session —
/// the stage target planner divides the ceiling by the active socket count,
/// and a window larger than the session cap would be truncated mid-window
/// (field evidence: a 384-candidate ScatterSmall plan was cut at 171 unique
/// endpoints by the 512-datagram session cap, leaving the window's tail never
/// scanned).  A single controlled coverage of a 64-candidate window from a
/// 3-socket pool is 192 datagrams, well below the previous 512.
pub(crate) const RECOVERY_STAGE_INITIAL_MAX_PROBES: u32 = 96;
pub(crate) const RECOVERY_STAGE_PREDICTED_MAX_PROBES: u32 = 192;
pub(crate) const RECOVERY_STAGE_SCATTER_SMALL_MAX_PROBES: u32 = 192;
pub(crate) const RECOVERY_STAGE_SCATTER_EXTENDED_MAX_PROBES: u32 = 192;
/// RelayBackoff (and relay-backed ScatterExtended) stages probe at most this
/// many trusted endpoints: the relay is the data plane, so traversal work is
/// a low-frequency, bounded heartbeat instead of a full wide scan.
pub(crate) const RECOVERY_STAGE_RELAY_BACKOFF_MAX_PROBES: u32 = 96;

/// Base backoff after a budget-exhausted / zero-send session.  Doubles on
/// every consecutive zero-send episode up to `RECOVERY_BUDGET_BACKOFF_MAX`.
pub(crate) const RECOVERY_BUDGET_BACKOFF_BASE: Duration = Duration::from_secs(60);
/// Long-term cap for the budget-exhausted backoff.
pub(crate) const RECOVERY_BUDGET_BACKOFF_MAX: Duration = Duration::from_secs(15 * 60);

/// Work slots the per-tick recovery scheduler grants to peers.  Every tick
/// at most this many peers may enter a recovery session; high-priority
/// (recently-Direct reclaim / new endpoint) peers are served first, so one
/// failing stale peer can never starve the main peer's recovery.
pub(crate) const RECOVERY_WORK_SLOTS_PER_TICK: usize = 2;

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

    /// Probe ceiling for the stage's target set.  `ScatterExtended` keeps
    /// the full wide-scatter capability ONLY when no relay safety net is
    /// available; the caller (`cap_targets_by_recovery_stage`) downgrades it
    /// to `RECOVERY_STAGE_RELAY_BACKOFF_MAX_PROBES` once a relay path exists.
    /// `RelayBackoff` is always bounded: relay governs the data plane, so
    /// the scan is a low-frequency trusted-endpoint heartbeat.
    pub(crate) fn max_probes(self) -> u32 {
        match self {
            RecoveryStage::Initial => RECOVERY_STAGE_INITIAL_MAX_PROBES,
            RecoveryStage::Predicted => RECOVERY_STAGE_PREDICTED_MAX_PROBES,
            RecoveryStage::ScatterSmall => RECOVERY_STAGE_SCATTER_SMALL_MAX_PROBES,
            RecoveryStage::ScatterExtended => RECOVERY_STAGE_SCATTER_EXTENDED_MAX_PROBES,
            RecoveryStage::RelayBackoff => RECOVERY_STAGE_RELAY_BACKOFF_MAX_PROBES,
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
    /// The epoch's budget is exhausted and its backoff has not elapsed: the
    /// trigger is frozen until the controlled backoff (or an epoch
    /// rotation).  This is an observable, schedulable verdict: the caller
    /// must NOT rebuild a plan, start a session or enumerate candidates.
    BudgetExhausted { epoch: u64 },
}

/// Newest-wins pending target: a newer trigger replaces the pending target
/// but can never spawn a parallel session or reset the epoch's budgets.
#[derive(Debug, Clone)]
pub(crate) struct PendingRecoveryTarget {
    pub peer_id: String,
    /// Shared candidate set snapshot at trigger time.
    pub candidates: Vec<SocketAddr>,
    /// Authenticated/learned candidates that deserve the larger bounded fast
    /// prefix when this snapshot is consumed by an already-running session.
    pub preferred_fast_candidates: Vec<SocketAddr>,
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
    /// Remaining plan builds for this epoch.  A plan whose probes were all
    /// rejected by the budget must not be rebuilt on the next tick.
    pub epoch_plan_builds_remaining: u32,
    /// Remaining punch sessions for this epoch.
    pub epoch_sessions_remaining: u32,
    /// Remaining candidate evaluations (endpoint iterations) for this epoch.
    pub epoch_candidate_iterations_remaining: u64,
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
    /// The epoch budget was exhausted (probe credit, candidate iterations or
    /// plan builds hit zero) and a controlled backoff is running.  While
    /// frozen, `recovery_epoch_admit` returns `BudgetExhausted`.
    pub budget_exhausted: bool,
    pub budget_backoff_until: Option<Instant>,
    /// Consecutive zero-send / budget-exhausted episodes, driving the
    /// exponential backoff.
    pub zero_send_streak: u32,
    pub last_budget_exhausted_at: Option<Instant>,
    /// Number of bounded evidence-driven re-opens spent this epoch.  New
    /// authenticated evidence (inbound punch, peer-reflexive observation)
    /// can re-open a frozen epoch this many times; after the cap, the epoch
    /// stays frozen until its backoff/age rotation.
    pub evidence_reopens: u32,
    /// The last quota-exhausted event stage reported for this epoch
    /// (`plan_build` / `session`).  Used to deduplicate the per-tick
    /// `recovery_plan_build_quota_exhausted` / `recovery_session_quota_exhausted`
    /// events so a frozen epoch does not log them once per second.
    pub last_quota_event: Option<String>,
    /// Structured summary of the last budget-exhausted session (counts only,
    /// no sensitive content), surfaced once per freeze instead of once per
    /// rejected probe.
    pub last_budget_event: Option<RecoveryBudgetEvent>,
}

/// Structured, deduplicated summary of a budget-exhausted recovery session.
/// Contains only counts and timings — never candidate contents.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct RecoveryBudgetEvent {
    pub candidate_count: u64,
    pub visited: u64,
    pub sent: u64,
    pub skipped: u64,
    pub reason: String,
    pub next_retry_at_ms_since_epoch: u64,
    pub zero_send_streak: u32,
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
            epoch_plan_builds_remaining: RECOVERY_EPOCH_PLAN_BUILDS,
            epoch_sessions_remaining: RECOVERY_EPOCH_SESSIONS,
            epoch_candidate_iterations_remaining: RECOVERY_EPOCH_CANDIDATE_ITERATIONS,
            epoch_fresh_generation_quota_remaining: RECOVERY_EPOCH_FRESH_GENERATIONS,
            epoch_http_quota_remaining: RECOVERY_EPOCH_HTTP_PUBLISHES,
            epoch_scatter_windows_sent: 0,
            ack_feedback_seen: false,
            last_matched_ack: None,
            last_matched_ack_at: None,
            pending_target: None,
            budget_exhausted: false,
            budget_backoff_until: None,
            zero_send_streak: 0,
            last_budget_exhausted_at: None,
            evidence_reopens: 0,
            last_quota_event: None,
            last_budget_event: None,
        }
    }
}

impl PeerManager {
    /// The authoritative admission gate for every punch trigger.
    ///
    /// A trigger is admitted only while the peer is in recovery, inside the
    /// same `(network_generation, epoch)` plan, and the epoch still has
    /// budget.  A new epoch starts only on a generation advance, a stale
    /// exhausted epoch (age rotation), or the first trigger after the peer
    /// re-entered recovery.  Direct peers, missing connections and
    /// generation changes end the epoch.
    ///
    /// A budget-exhausted epoch returns `BudgetExhausted` (not `Accepted`)
    /// until its controlled backoff elapses: the caller must not rebuild a
    /// plan or start a session, so the 1-second retry tick can never
    /// resurrect a 778/3072-candidate plan.
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
        // A frozen epoch stays frozen until its controlled backoff elapses.
        // The freeze survives pending targets and offers: only the backoff
        // expiry or an epoch rotation re-opens recovery.
        if entry.budget_exhausted
            && entry
                .budget_backoff_until
                .is_some_and(|until| now < until)
        {
            return RecoveryAdmission::BudgetExhausted {
                epoch: entry.epoch,
            };
        }
        if entry.budget_exhausted {
            // The controlled backoff elapsed: unfreeze and record that the
            // re-open was backoff-driven (observable, budgeted, not churn).
            entry.budget_exhausted = false;
            entry.budget_backoff_until = None;
            info!(
                event = "recovery_budget_reopened",
                peer_id = %peer_id,
                epoch = entry.epoch,
                reason = "controlled_backoff_elapsed",
                "recovery_budget_reopened peer_id={} epoch={} reason=controlled_backoff_elapsed",
                peer_id,
                entry.epoch,
            );
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
    /// by a later no-ACK batch.  A matched ACK also unfreezes a budget-
    /// exhausted epoch: a live path is the strongest re-open signal.
    pub(crate) async fn record_recovery_ack_feedback(
        &self,
        peer_id: &str,
        endpoint: SocketAddr,
    ) {
        {
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
        self.recovery_unfreeze_on_ack(peer_id).await;
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

    /// Consume one plan-build slot.  Returns `false` when the epoch's hard
    /// plan-build budget is exhausted (a rejected plan must not be rebuilt
    /// on the next tick).
    pub(crate) async fn try_consume_recovery_plan_build(&self, peer_id: &str) -> bool {
        let mut epochs = self.recovery_epochs.write().await;
        let Some(state) = epochs.get_mut(peer_id) else {
            return true;
        };
        if state.epoch_plan_builds_remaining == 0 {
            return false;
        }
        state.epoch_plan_builds_remaining -= 1;
        true
    }

    /// Consume one session slot.  Returns `false` when the epoch's hard
    /// session budget is exhausted.
    pub(crate) async fn try_consume_recovery_session(&self, peer_id: &str) -> bool {
        let mut epochs = self.recovery_epochs.write().await;
        let Some(state) = epochs.get_mut(peer_id) else {
            return true;
        };
        if state.epoch_sessions_remaining == 0 {
            return false;
        }
        state.epoch_sessions_remaining -= 1;
        true
    }

    /// Consume candidate-iteration credit for the epoch.
    ///
    /// Returns `true` when `count` iterations may be evaluated.  Returns
    /// `false` when the epoch's hard candidate-iteration budget is
    /// exhausted — the caller must stop enumerating candidates immediately
    /// (a "budget exhausted" sweep may never keep traversing a 3,072-entry
    /// endpoint list).
    pub(crate) async fn try_consume_recovery_candidate_iterations(
        &self,
        peer_id: &str,
        count: u64,
    ) -> bool {
        let mut epochs = self.recovery_epochs.write().await;
        let Some(state) = epochs.get_mut(peer_id) else {
            return true;
        };
        if state.epoch_candidate_iterations_remaining < count {
            return false;
        }
        state.epoch_candidate_iterations_remaining -= count;
        true
    }

    /// Freeze the epoch after a budget-exhausted / zero-send session.
    ///
    /// Applies an exponential backoff (doubling on consecutive zero-send
    /// episodes, capped at `RECOVERY_BUDGET_BACKOFF_MAX`) and records ONE
    /// structured event with counts and the next retry time.  While frozen,
    /// `recovery_epoch_admit` returns `BudgetExhausted`, so the next 1-second
    /// tick cannot rebuild the plan.  The backoff expiry or an epoch
    /// rotation is the only re-open path.
    pub(crate) async fn mark_recovery_budget_exhausted(
        &self,
        peer_id: &str,
        candidate_count: u64,
        visited: u64,
        sent: u64,
        skipped: u64,
        reason: &str,
    ) {
        let mut epochs = self.recovery_epochs.write().await;
        let Some(state) = epochs.get_mut(peer_id) else {
            return;
        };
        state.budget_exhausted = true;
        state.last_budget_exhausted_at = Some(Instant::now());
        state.zero_send_streak = state.zero_send_streak.saturating_add(1);
        let exponent = state
            .zero_send_streak
            .saturating_sub(1)
            .min(10); // 60s << 10 = ~17h, capped below at 15min
        let backoff = RECOVERY_BUDGET_BACKOFF_BASE
            .checked_mul(1_u32 << exponent)
            .unwrap_or(RECOVERY_BUDGET_BACKOFF_MAX)
            .min(RECOVERY_BUDGET_BACKOFF_MAX);
        state.budget_backoff_until = Some(Instant::now() + backoff);
        let next_retry_at_ms = (std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64)
            .saturating_add(u64::try_from(backoff.as_millis()).unwrap_or(u64::MAX));
        let event = RecoveryBudgetEvent {
            candidate_count,
            visited,
            sent,
            skipped,
            reason: reason.to_string(),
            next_retry_at_ms_since_epoch: next_retry_at_ms,
            zero_send_streak: state.zero_send_streak,
        };
        state.last_budget_event = Some(event.clone());
        info!(
            event = "recovery_budget_exhausted",
            peer_id = %peer_id,
            epoch = state.epoch,
            stage = state.stage.label(),
            candidate_count = event.candidate_count,
            visited = event.visited,
            sent = event.sent,
            skipped = event.skipped,
            reason = %event.reason,
            backoff_ms = backoff.as_millis(),
            next_retry_at_ms = event.next_retry_at_ms_since_epoch,
            zero_send_streak = event.zero_send_streak,
            "recovery_budget_exhausted peer_id={} epoch={} stage={} candidate_count={} visited={} sent={} skipped={} reason={} backoff_ms={} next_retry_at_ms={} zero_send_streak={}",
            peer_id,
            state.epoch,
            state.stage.label(),
            event.candidate_count,
            event.visited,
            event.sent,
            event.skipped,
            event.reason,
            backoff.as_millis(),
            event.next_retry_at_ms_since_epoch,
            event.zero_send_streak,
        );
        // A budget-exhausted freeze also moves the stage into the bounded
        // relay-backoff regime: with the budget gone there is no feedback
        // signal that could justify a wide scan, so recovery continues as a
        // low-frequency trusted-endpoint heartbeat only.
        if state.stage != RecoveryStage::RelayBackoff {
            state.stage = RecoveryStage::RelayBackoff;
            state.stage_started_at = Instant::now();
        }
    }

    /// Whether the peer's epoch is currently frozen by budget exhaustion.
    #[cfg(test)]
    pub(crate) async fn recovery_budget_frozen(&self, peer_id: &str) -> bool {
        let now = Instant::now();
        self.recovery_epochs
            .read()
            .await
            .get(peer_id)
            .is_some_and(|state| {
                state.budget_exhausted
                    && state
                        .budget_backoff_until
                        .is_some_and(|until| now < until)
            })
    }

    /// Record a matched-ACK feedback even when the epoch was frozen: a live
    /// path is the strongest possible re-open signal, so an ACK observed
    /// during the backoff unfreezes the epoch (the caller confirms Direct).
    pub(crate) async fn recovery_unfreeze_on_ack(&self, peer_id: &str) {
        let mut epochs = self.recovery_epochs.write().await;
        let Some(state) = epochs.get_mut(peer_id) else {
            return;
        };
        if state.budget_exhausted {
            state.budget_exhausted = false;
            state.budget_backoff_until = None;
            info!(
                event = "recovery_budget_reopened",
                peer_id = %peer_id,
                epoch = state.epoch,
                reason = "matched_ack",
                "recovery_budget_reopened peer_id={} epoch={} reason=matched_ack",
                peer_id,
                state.epoch,
            );
        }
    }

    /// Re-open a frozen or quota-exhausted recovery epoch on NEW
    /// authenticated evidence.
    ///
    /// A matched ACK already unfreezes through [`Self::recovery_unfreeze_on_ack`].
    /// This is the bounded re-open for the other authoritative live-path
    /// signals: an inbound authenticated punch, a new authenticated
    /// peer-reflexive observation, or real candidate change.  Without it, a
    /// peer whose epoch froze after the maintainer/sweep burned its budget
    /// stays unable to retry for the whole 30-minute epoch even when the
    /// peer is actively punching us right now.
    ///
    /// Each re-open:
    /// - unfreezes the epoch and clears the budget backoff,
    /// - grants a small retry allowance (probe credit, plan builds,
    ///   sessions) so the retry can actually run,
    /// - resets the stage to Initial so the retry is compact,
    /// - is counted and capped at [`RECOVERY_EPOCH_MAX_EVIDENCE_REOPENS`]
    ///   per epoch so evidence cannot churn re-plans endlessly.
    ///
    /// Re-opens never refill a healthy epoch: when nothing is frozen or
    /// exhausted, this is a no-op.
    pub(crate) async fn recovery_reopen_on_evidence(&self, peer_id: &str, reason: &str) {
        let mut epochs = self.recovery_epochs.write().await;
        let Some(state) = epochs.get_mut(peer_id) else {
            return;
        };
        let frozen = state.budget_exhausted;
        let credit_empty = state.epoch_probe_credit_remaining == 0;
        let plans_empty = state.epoch_plan_builds_remaining == 0;
        let sessions_empty = state.epoch_sessions_remaining == 0;
        if !frozen && !credit_empty && !plans_empty && !sessions_empty {
            return;
        }
        if state.evidence_reopens >= RECOVERY_EPOCH_MAX_EVIDENCE_REOPENS {
            debug!(
                event = "recovery_evidence_reopen_capped",
                peer_id = %peer_id,
                epoch = state.epoch,
                "recovery evidence re-open capped: epoch {} already used its {RECOVERY_EPOCH_MAX_EVIDENCE_REOPENS} evidence re-opens",
                state.epoch,
            );
            return;
        }
        state.evidence_reopens = state.evidence_reopens.saturating_add(1);
        state.budget_exhausted = false;
        state.budget_backoff_until = None;
        state.zero_send_streak = 0;
        state.epoch_probe_credit_remaining = state
            .epoch_probe_credit_remaining
            .max(RECOVERY_EVIDENCE_RETRY_CREDIT);
        state.epoch_plan_builds_remaining = state
            .epoch_plan_builds_remaining
            .max(RECOVERY_EVIDENCE_REGRANT_PLAN_BUILDS);
        state.epoch_sessions_remaining = state
            .epoch_sessions_remaining
            .max(RECOVERY_EVIDENCE_REGRANT_SESSIONS);
        // A live-path signal means a compact retry is the right next plan.
        if state.stage != RecoveryStage::Initial {
            state.stage = RecoveryStage::Initial;
            state.stage_started_at = Instant::now();
        }
        // Quota-exhausted events may be reported again after the re-open.
        state.last_quota_event = None;
        info!(
            event = "recovery_budget_reopened",
            peer_id = %peer_id,
            epoch = state.epoch,
            reason = %reason,
            evidence_reopens = state.evidence_reopens,
            "recovery_budget_reopened peer_id={} epoch={} reason={} evidence_reopens={}",
            peer_id,
            state.epoch,
            reason,
            state.evidence_reopens,
        );
    }

    /// Whether a quota-exhausted event for `stage` should be surfaced for
    /// this peer's epoch.  Returns `true` only the first time per epoch (or
    /// after an evidence re-open cleared the marker), so a frozen epoch
    /// cannot emit `recovery_plan_build_quota_exhausted` once per second.
    pub(crate) async fn recovery_quota_event_report_due(
        &self,
        peer_id: &str,
        stage: &str,
    ) -> bool {
        let mut epochs = self.recovery_epochs.write().await;
        let Some(state) = epochs.get_mut(peer_id) else {
            return false;
        };
        if state.last_quota_event.as_deref() == Some(stage) {
            return false;
        }
        state.last_quota_event = Some(stage.to_string());
        true
    }

    /// Record a zero-send probe session as an observable verdict.
    ///
    /// `sent == 0` with a non-empty candidate set means every probe was
    /// rejected by the admission layer (rate limits or epoch credit).  This
    /// is NOT a silent success: it records the `zero_send_session` event and
    /// freezes the epoch with the budget-exhausted backoff, so the next
    /// 1-second tick cannot rebuild the same wide plan.
    pub(crate) async fn record_zero_send_recovery_session(
        &self,
        peer_id: &str,
        candidate_count: u64,
        visited: u64,
        skipped: u64,
        reason: &str,
    ) {
        self.record_direct_event(
            peer_id,
            "zero_send_session",
            None,
            Some(candidate_count as usize),
            Some(0),
            format!(
                "zero-send recovery session: all {candidate_count} candidates were rejected by the admission budget (skipped={skipped}); freezing the recovery epoch with a controlled backoff: {reason}"
            ),
        )
        .await;
        self.mark_recovery_budget_exhausted(
            peer_id,
            candidate_count,
            visited,
            0,
            skipped,
            reason,
        )
        .await;
    }

    /// Report the remaining epoch budgets (epoch, probe credit, plan
    /// builds, sessions, candidate iterations, fresh generations, HTTP
    /// publishes).
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

    /// Full budget snapshot for tests and diagnostics.
    #[cfg(test)]
    pub(crate) async fn recovery_epoch_work_budget_report(
        &self,
        peer_id: &str,
    ) -> Option<RecoveryEpochWorkBudgetSnapshot> {
        self.recovery_epochs.read().await.get(peer_id).map(|state| {
            RecoveryEpochWorkBudgetSnapshot {
                epoch: state.epoch,
                probe_credit_remaining: state.epoch_probe_credit_remaining,
                plan_builds_remaining: state.epoch_plan_builds_remaining,
                sessions_remaining: state.epoch_sessions_remaining,
                candidate_iterations_remaining: state.epoch_candidate_iterations_remaining,
                fresh_generations_remaining: state.epoch_fresh_generation_quota_remaining,
                http_remaining: state.epoch_http_quota_remaining,
                budget_exhausted: state.budget_exhausted,
                zero_send_streak: state.zero_send_streak,
                stage: state.stage,
                next_retry_at_ms_since_epoch: state
                    .last_budget_event
                    .as_ref()
                    .map(|event| event.next_retry_at_ms_since_epoch),
            }
        })
    }

    /// Last budget-exhausted event summary for tests.
    #[cfg(test)]
    pub(crate) async fn recovery_last_budget_event(
        &self,
        peer_id: &str,
    ) -> Option<RecoveryBudgetEvent> {
        self.recovery_epochs
            .read()
            .await
            .get(peer_id)
            .and_then(|state| state.last_budget_event.clone())
    }

    /// Test-only: force the budget backoff to expire (simulates the
    /// controlled backoff elapsing without waiting for wall-clock time).
    #[cfg(test)]
    pub(crate) async fn test_force_budget_backoff_elapsed(&self, peer_id: &str) {
        let mut epochs = self.recovery_epochs.write().await;
        if let Some(state) = epochs.get_mut(peer_id) {
            state.budget_backoff_until = None;
        }
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

    /// Synchronous per-peer relay-confirm sequence mirror, updated together
    /// with the peer's relay confirmation state so an outbound waiter reading
    /// it per notification can never miss a confirmation that already committed.
    pub(crate) fn relay_confirm_seq_sync(&self, peer_id: &str) -> Option<u64> {
        self.relay_confirm_seq_mirror
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .get(peer_id)
            .copied()
    }

    /// Bump the relay-confirm sequence for a peer and wake every waiter.  Must
    /// be called in the same critical section as the relay confirmation state
    /// transition so no waiter observes the sequence without the state.
    pub(crate) fn bump_relay_confirm_seq(&self, peer_id: &str) -> u64 {
        let seq = {
            let mut mirror = self
                .relay_confirm_seq_mirror
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            let entry = mirror.entry(peer_id.to_string()).or_insert(0);
            *entry = entry.wrapping_add(1);
            *entry
        };
        self.relay_confirm_notify.notify_waiters();
        seq
    }

    /// Notification for any relay-confirm bump; waiters must re-check the
    /// peer's sequence and confirmation state after waking.
    pub(crate) fn relay_confirm_notify(&self) -> Arc<Notify> {
        self.relay_confirm_notify.clone()
    }

    /// Whether the recovery epoch budget diagnostics should be surfaced.
    pub(crate) async fn recovery_epoch_active(&self, peer_id: &str) -> bool {
        self.recovery_epochs.read().await.contains_key(peer_id)
    }
}

/// Test/diagnostic snapshot of one peer's recovery work budget.
#[cfg(test)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct RecoveryEpochWorkBudgetSnapshot {
    pub epoch: u64,
    pub probe_credit_remaining: u32,
    pub plan_builds_remaining: u32,
    pub sessions_remaining: u32,
    pub candidate_iterations_remaining: u64,
    pub fresh_generations_remaining: u32,
    pub http_remaining: u32,
    pub budget_exhausted: bool,
    pub zero_send_streak: u32,
    pub stage: RecoveryStage,
    pub next_retry_at_ms_since_epoch: Option<u64>,
}
