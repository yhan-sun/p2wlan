// Hard↔Hard synchronized fresh-mapping rendezvous.
//
// This is intentionally a narrow integration around the existing fresh
// mapping, `peer_offer_fresh`, Probe v2, pending-probe and Direct validation
// machinery. It does not introduce a second wire protocol or promote a path:
// the existing authenticated ACK and PathSelector remain authoritative.

use crate::udp::{
    apply_live_birthday_counters, hard_hard_birthday_socket_count, hard_hard_birthday_wave_count,
    update_birthday_sweep_counters, BirthdaySweepFailureKind, BirthdaySweepProgress,
    BirthdaySweepReport, UdpProbeRxSnapshot,
};

const HARD_HARD_SESSION_PREFIX: &str = "hh1";
const HARD_HARD_PUNCH_LEAD: Duration = Duration::from_millis(3_500);
const HARD_HARD_MIN_RESPONSE_LEAD: Duration = Duration::from_millis(1_250);
/// Keep the speculative session hot only for the measured rendezvous window;
/// ordinary Relay/backoff recovery owns all later retries.
const HARD_HARD_SESSION_TTL: Duration = Duration::from_secs(8);
const HARD_HARD_SWEEP_DEADLINE: Duration = Duration::from_secs(3);
// The validation worker's individual ACK lease is 750ms.  Keep a bounded
// second lease for scheduler/ingress handoff under a busy executor without
// changing the send budget or any identity/generation fence.
const HARD_HARD_DIRECT_CONFIRMATION_GRACE: Duration = Duration::from_secs(2);
const HARD_HARD_SWEEP_INTERVAL: Duration = Duration::from_millis(20);
const HARD_HARD_SWEEP_ATTEMPTS: u32 = 2;
const HARD_HARD_MAX_PREDICTION_TARGETS: usize = 32;
const HARD_HARD_MAX_BIRTHDAY_TARGETS: usize = 256;
const HARD_HARD_PROTECTED_CLAIM_RETRY_SLACK: Duration = Duration::from_millis(10);

#[cfg(test)]
struct HardHardResponderMeasurementGate {
    reached: tokio::sync::Notify,
    release: tokio::sync::Notify,
    completed: tokio::sync::Notify,
}

#[cfg(test)]
struct HardHardResponderMeasurementGateCompletion(Option<Arc<HardHardResponderMeasurementGate>>);

#[cfg(test)]
impl Drop for HardHardResponderMeasurementGateCompletion {
    fn drop(&mut self) {
        if let Some(gate) = self.0.take() {
            gate.completed.notify_one();
        }
    }
}

#[cfg(test)]
static HARD_HARD_RESPONDER_MEASUREMENT_GATE: std::sync::LazyLock<
    std::sync::Mutex<Option<Arc<HardHardResponderMeasurementGate>>>,
> = std::sync::LazyLock::new(|| std::sync::Mutex::new(None));

#[cfg(test)]
fn install_hard_hard_responder_measurement_gate_for_test() -> Arc<HardHardResponderMeasurementGate>
{
    let gate = Arc::new(HardHardResponderMeasurementGate {
        reached: tokio::sync::Notify::new(),
        release: tokio::sync::Notify::new(),
        completed: tokio::sync::Notify::new(),
    });
    *HARD_HARD_RESPONDER_MEASUREMENT_GATE
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner()) = Some(gate.clone());
    gate
}

#[cfg(test)]
async fn pause_hard_hard_responder_after_measurement_for_test(
) -> HardHardResponderMeasurementGateCompletion {
    let gate = HARD_HARD_RESPONDER_MEASUREMENT_GATE
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .take();
    if let Some(gate) = &gate {
        gate.reached.notify_one();
        gate.release.notified().await;
    }
    HardHardResponderMeasurementGateCompletion(gate)
}
/// Until an initiator record is installed in the manager ledger, no other
/// owner will cancel its shared handle when the short-lived punch permit is
/// dropped.  Make every pre-ledger return (including cancellation/panic
/// unwinding) cancel the exact handle so the UDP-lease watcher cannot outlive
/// a failed measurement until the whole transport is replaced.
struct PendingHardHardSessionCancellation {
    cancellation: Option<Arc<crate::PunchSessionCancellation>>,
}

impl PendingHardHardSessionCancellation {
    fn new(cancellation: Arc<crate::PunchSessionCancellation>) -> Self {
        Self {
            cancellation: Some(cancellation),
        }
    }

    fn disarm(&mut self) {
        self.cancellation = None;
    }
}

impl Drop for PendingHardHardSessionCancellation {
    fn drop(&mut self) {
        if let Some(cancellation) = self.cancellation.take() {
            cancellation.cancel_for_hard_hard_cleanup();
        }
    }
}

#[derive(Clone)]
struct HardHardCleanupDescriptor {
    peer_id: String,
    session_id: String,
    session_token: String,
    fresh_socket: crate::peer::HardHardFreshSocketIdentity,
    expires_at_ms: u64,
    cancellation: Arc<crate::PunchSessionCancellation>,
}

impl HardHardCleanupDescriptor {
    fn from_record(record: &HardHardSessionRecord) -> Self {
        Self {
            peer_id: record.peer_id.clone(),
            session_id: record.session_id.clone(),
            session_token: record.session_token.clone(),
            fresh_socket: record.fresh_socket.clone(),
            expires_at_ms: record.expires_at_ms,
            cancellation: record.cancellation.clone(),
        }
    }
}

#[derive(Clone)]
struct HardHardCleanupCompletion {
    completed: Arc<std::sync::atomic::AtomicBool>,
    notify: Arc<tokio::sync::Notify>,
}

impl HardHardCleanupCompletion {
    fn new() -> Self {
        Self {
            completed: Arc::new(std::sync::atomic::AtomicBool::new(false)),
            notify: Arc::new(tokio::sync::Notify::new()),
        }
    }

    fn finish(&self) {
        self.completed
            .store(true, std::sync::atomic::Ordering::Release);
        self.notify.notify_waiters();
    }

    #[cfg(test)]
    async fn wait(&self) {
        loop {
            if self
                .completed
                .load(std::sync::atomic::Ordering::Acquire)
            {
                return;
            }
            let notified = self.notify.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            if self
                .completed
                .load(std::sync::atomic::Ordering::Acquire)
            {
                return;
            }
            notified.await;
        }
    }
}

struct HardHardCleanupCompletionGuard(HardHardCleanupCompletion);

impl Drop for HardHardCleanupCompletionGuard {
    fn drop(&mut self) {
        self.0.finish();
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum HardHardInitiatorStart {
    /// A new Hard↔Hard measurement worker owns the punch session.
    Started,
    /// The peer already has a live Hard↔Hard ledger session.
    ExistingSession,
    /// Another punch permit already owns this peer's recovery window.
    ExistingPunchOwner,
    /// The UDP publication lease which requested this attempt was already
    /// withdrawn.  This invocation is handled by stopping; it must not fall
    /// through and attach an ordinary worker to the same retired socket.
    InvocationCancelled,
    /// Hard↔Hard did not acquire an owner; the caller must continue through
    /// the ordinary synchronized-punch path.
    NotStarted(HardHardInitiatorNotStarted),
}

/// Whether handling an admitted remote `hh1` offer actually acquired the
/// local Hard↔Hard worker.  Callers must distinguish a protocol/session
/// rejection from a locally unavailable optimization: only the latter may
/// fall through to the already-admitted ordinary fresh punch.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum HardHardRemoteStart {
    Started,
    NotStarted,
    Rejected,
}
impl HardHardInitiatorStart {
    pub(crate) fn is_handled(self) -> bool {
        !matches!(self, Self::NotStarted(_))
    }

    pub(crate) fn fallback_reason(self) -> Option<&'static str> {
        match self {
            Self::NotStarted(reason) => Some(reason.label()),
            Self::Started
            | Self::ExistingSession
            | Self::ExistingPunchOwner
            | Self::InvocationCancelled => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum HardHardInitiatorNotStarted {
    PlanChanged,
    BootEpochUnavailable,
    InsufficientStunObservers,
    RecoverySuperseded,
    RecoveryBudgetExhausted,
    FreshGenerationQuotaExhausted,
}

impl HardHardInitiatorNotStarted {
    fn label(self) -> &'static str {
        match self {
            Self::PlanChanged => "plan_changed_before_start",
            Self::BootEpochUnavailable => "boot_epoch_unavailable",
            Self::InsufficientStunObservers => "insufficient_stun_observers",
            Self::RecoverySuperseded => "recovery_superseded",
            Self::RecoveryBudgetExhausted => "recovery_budget_exhausted",
            Self::FreshGenerationQuotaExhausted => "fresh_generation_quota_exhausted",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum HardHardRole {
    Initiator,
    Responder,
}

/// Compact metadata envelope carried in the existing `session_id` field.
///
/// The field is opaque to the signaling service and old clients.  The sender
/// identity and the authenticated Probe v2 key still come from the existing
/// control/peer registration path; this envelope is an epoch fence, not an
/// authentication primitive.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct HardHardCoordination {
    pub(crate) role: HardHardRole,
    pub(crate) token: String,
    pub(crate) local_network_generation: u64,
    pub(crate) remote_candidate_epoch: u64,
    pub(crate) local_profile_generation: u64,
    pub(crate) remote_profile_generation: u64,
    pub(crate) local_prediction_confidence: u8,
    pub(crate) remote_prediction_confidence: u8,
    /// Compact allocation-model labels exchanged with the confidence. They
    /// are hints only; the authenticated peer-reflexive packet remains the
    /// highest-priority evidence.
    pub(crate) local_prediction_model: String,
    pub(crate) remote_prediction_model: String,
    /// The other endpoint's local network generation.  The first offer has
    /// no way to know it, so it is zero there; the reciprocal response echoes
    /// the initiator's value and carries the responder's value in `local`.
    pub(crate) remote_network_generation: u64,
}

impl HardHardCoordination {
    pub(crate) fn looks_like(value: &str) -> bool {
        value.starts_with("hh1:")
    }

    pub(crate) fn parse(value: &str) -> Option<Self> {
        let mut fields = value.split(':');
        if fields.next()? != HARD_HARD_SESSION_PREFIX {
            return None;
        }
        let role = match fields.next()? {
            "i" => HardHardRole::Initiator,
            "r" => HardHardRole::Responder,
            _ => return None,
        };
        let token = fields.next()?.to_string();
        if token.is_empty()
            || token.len() > 32
            || !token
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit() || byte == b'-')
        {
            return None;
        }
        let local_network_generation = fields.next()?.parse().ok()?;
        let remote_candidate_epoch = fields.next()?.parse().ok()?;
        let local_profile_generation = fields.next()?.parse().ok()?;
        let remote_profile_generation = fields.next()?.parse().ok()?;
        // Confidence was added to the opaque envelope without changing the
        // signaling schema.  Accept an older hh1 envelope as a bounded
        // zero-confidence value, but newly generated sessions always carry
        // both model confidences before they are admitted.
        let local_prediction_confidence = fields.next().unwrap_or("0").parse().ok()?;
        let remote_prediction_confidence = fields.next().unwrap_or("0").parse().ok()?;
        let remote_network_generation = fields.next().unwrap_or("0").parse().ok()?;
        let local_prediction_model = fields.next().unwrap_or("unknown").to_string();
        let remote_prediction_model = fields.next().unwrap_or("unknown").to_string();
        for model in [&local_prediction_model, &remote_prediction_model] {
            if model.len() > 32
                || !model
                    .bytes()
                    .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_')
            {
                return None;
            }
        }
        if fields.next().is_some() {
            return None;
        }
        Some(Self {
            role,
            token,
            local_network_generation,
            remote_candidate_epoch,
            local_profile_generation,
            remote_profile_generation,
            local_prediction_confidence,
            remote_prediction_confidence,
            remote_network_generation,
            local_prediction_model,
            remote_prediction_model,
        })
    }

    fn encode(&self) -> String {
        format!(
            "{HARD_HARD_SESSION_PREFIX}:{}:{}:{}:{}:{}:{}:{}:{}:{}:{}:{}",
            match self.role {
                HardHardRole::Initiator => "i",
                HardHardRole::Responder => "r",
            },
            self.token,
            self.local_network_generation,
            self.remote_candidate_epoch,
            self.local_profile_generation,
            self.remote_profile_generation,
            self.local_prediction_confidence,
            self.remote_prediction_confidence,
            self.remote_network_generation,
            self.local_prediction_model,
            self.remote_prediction_model,
        )
    }

    fn as_response(
        &self,
        snapshot: crate::peer::HardHardPlanSnapshot,
        local_prediction_confidence: u8,
        local_prediction_model: String,
    ) -> Self {
        Self {
            role: HardHardRole::Responder,
            token: self.token.clone(),
            local_network_generation: snapshot.local_network_generation,
            remote_candidate_epoch: snapshot.remote_candidate_epoch,
            local_profile_generation: snapshot.local_profile_generation,
            remote_profile_generation: self.local_profile_generation,
            local_prediction_confidence,
            remote_prediction_confidence: self.local_prediction_confidence,
            remote_network_generation: self.local_network_generation,
            local_prediction_model,
            remote_prediction_model: self.local_prediction_model.clone(),
        }
    }
}

/// Override only the Hard↔Hard rendezvous clock for deterministic integration
/// tests. Production builds do not contain this state, and all other runtime
/// deadlines continue to use their existing constants and timers.
#[cfg(test)]
pub(crate) fn set_hard_hard_test_now_ms(now_ms: Option<u64>) {
    crate::peer::set_hard_hard_test_now_ms(now_ms);
}

fn hard_hard_now_ms() -> u64 {
    crate::peer::hard_hard_now_ms()
}

fn hard_hard_session_token(session_id: u64) -> String {
    format!("{:x}{:x}", hard_hard_now_ms(), session_id)
}

fn hard_hard_coordination_from_plan(
    token: String,
    role: HardHardRole,
    plan: crate::peer::HardHardPlanSnapshot,
) -> HardHardCoordination {
    HardHardCoordination {
        role,
        token,
        local_network_generation: plan.local_network_generation,
        remote_candidate_epoch: plan.remote_candidate_epoch,
        local_profile_generation: plan.local_profile_generation,
        remote_profile_generation: plan.remote_profile_generation,
        local_prediction_confidence: 0,
        remote_prediction_confidence: 0,
        remote_network_generation: 0,
        local_prediction_model: "unknown".to_string(),
        remote_prediction_model: "unknown".to_string(),
    }
}

fn hard_hard_prediction_payload(
    result: &FreshMappingResult,
    boot_epoch_ms: u64,
) -> Option<(Vec<String>, HashMap<String, String>)> {
    let public_ip = result.public_ip.filter(|ip| !ip.is_unspecified())?;
    let fresh_id = FreshPredictionId {
        boot_epoch: boot_epoch_ms,
        generation: result.punch_generation,
    };
    let fresh_label = fresh_prediction_source_label(fresh_id);
    let limit = hard_hard_prediction_limit(&result.model.kind, result.model.confidence);
    let mut candidates = Vec::with_capacity(limit);
    let mut sources = HashMap::with_capacity(limit);
    for port in result.predicted_ports.iter().take(limit) {
        let endpoint = SocketAddr::new(public_ip, *port).to_string();
        if !candidates.contains(&endpoint) {
            candidates.push(endpoint.clone());
            sources.insert(endpoint, fresh_label.clone());
        }
    }
    (!candidates.is_empty()).then_some((candidates, sources))
}

fn hard_hard_model_label(kind: &p2pnet_nat::mapping::PortModelKind) -> &'static str {
    match kind {
        p2pnet_nat::mapping::PortModelKind::Stable => "stable",
        p2pnet_nat::mapping::PortModelKind::FixedStep { .. } => "fixed_step",
        p2pnet_nat::mapping::PortModelKind::Linear { .. } => "linear",
        p2pnet_nat::mapping::PortModelKind::NoisyLinear { .. } => "noisy_linear",
        p2pnet_nat::mapping::PortModelKind::MonotonicWindow { .. } => "small_window",
        p2pnet_nat::mapping::PortModelKind::Periodic { .. } => "periodic",
        p2pnet_nat::mapping::PortModelKind::Unpredictable { .. } => "high_entropy",
    }
}

fn hard_hard_prediction_limit(
    kind: &p2pnet_nat::mapping::PortModelKind,
    confidence: u8,
) -> usize {
    if matches!(
        kind,
        p2pnet_nat::mapping::PortModelKind::FixedStep { .. }
            | p2pnet_nat::mapping::PortModelKind::Linear { .. }
            | p2pnet_nat::mapping::PortModelKind::NoisyLinear { .. }
    ) {
        if confidence >= 90 {
            8
        } else if confidence >= 75 {
            16
        } else {
            32
        }
    } else {
        32
    }
}

fn hard_hard_plan_matches(
    left: crate::peer::HardHardPlanSnapshot,
    right: crate::peer::HardHardPlanSnapshot,
) -> bool {
    left.local_network_generation == right.local_network_generation
        && left.remote_candidate_epoch == right.remote_candidate_epoch
        && left.local_profile_generation == right.local_profile_generation
        && left.remote_profile_generation == right.remote_profile_generation
}

fn hard_hard_prediction_targets(candidates: &[String], limit: usize) -> Vec<SocketAddr> {
    candidates
        .iter()
        .filter_map(|candidate| candidate.parse::<SocketAddr>().ok())
        .take(limit)
        .collect()
}

async fn hard_hard_plan_claim_fence_is_current(
    peers: &PeerManager,
    peer_id: &str,
    peer_session_generation: crate::peer::PeerSessionGeneration,
    plan: crate::peer::HardHardPlanSnapshot,
    epoch: u64,
    punch_at_ms: u64,
) -> bool {
    hard_hard_punch_window_is_usable(hard_hard_now_ms(), punch_at_ms)
        && !peers.is_direct(peer_id).await
        && peers.peer_session_is_current_sync(peer_id, peer_session_generation)
        && peers
            .hard_hard_plan_for_peer(peer_id)
            .await
            .is_some_and(|current| hard_hard_plan_matches(current, plan))
        && matches!(
            peers.recovery_epoch_admit(peer_id).await,
            RecoveryAdmission::Accepted { epoch: current } if current == epoch
        )
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum HardHardPunchWindow {
    TooSoon,
    Usable,
    BeyondFreshLifetime,
}

fn hard_hard_punch_window(now_ms: u64, punch_at_ms: u64) -> HardHardPunchWindow {
    if punch_at_ms <= now_ms.saturating_add(HARD_HARD_MIN_RESPONSE_LEAD.as_millis() as u64) {
        HardHardPunchWindow::TooSoon
    } else if punch_at_ms > now_ms.saturating_add(HARD_HARD_SESSION_TTL.as_millis() as u64) {
        HardHardPunchWindow::BeyondFreshLifetime
    } else {
        HardHardPunchWindow::Usable
    }
}

fn hard_hard_punch_window_is_usable(now_ms: u64, punch_at_ms: u64) -> bool {
    hard_hard_punch_window(now_ms, punch_at_ms) == HardHardPunchWindow::Usable
}

/// A fresh Hard↔Hard response normally preempts an ordinary punch, but the
/// deduplicator deliberately protects an ordinary rendezvous which already
/// reached its lead/first-send edge.  Wait only until that short protection is
/// guaranteed to have elapsed, then retry exactly once while the much longer
/// canonical Hard↔Hard window is still useful.
fn hard_hard_protected_claim_retry_delay(
    deferred: DeferredPunchClaim,
    now_ms: u64,
) -> Option<Duration> {
    let guard_ms = RELAY_ASSISTED_PUNCH_LEAD.as_millis().min(u64::MAX as u128) as u64;
    let slack_ms = HARD_HARD_PROTECTED_CLAIM_RETRY_SLACK
        .as_millis()
        .min(u64::MAX as u128) as u64;
    let max_delay_ms = guard_ms.saturating_mul(2).saturating_add(slack_ms);
    let delay_ms = match deferred.reason {
        PunchClaimDeferredReason::FirstSendProtected => guard_ms.saturating_add(slack_ms),
        PunchClaimDeferredReason::RendezvousLeadProtected => deferred
            .active_punch_at_ms
            .map(|active_punch_at_ms| {
                active_punch_at_ms
                    .saturating_add(guard_ms)
                    .saturating_sub(now_ms)
                    .saturating_add(slack_ms)
            })
            .unwrap_or_else(|| guard_ms.saturating_add(slack_ms)),
        PunchClaimDeferredReason::SameEpochActive
        | PunchClaimDeferredReason::LowerPriorityActive
        | PunchClaimDeferredReason::SameOrOlderFreshPrediction => return None,
    };
    Some(Duration::from_millis(delay_ms.clamp(1, max_delay_ms)))
}

#[allow(clippy::too_many_arguments)]
async fn claim_hard_hard_responder_session(
    peers: &PeerManager,
    punch_deduplicator: &PunchAttemptDeduplicator,
    peer_id: &str,
    peer_session_generation: crate::peer::PeerSessionGeneration,
    plan: crate::peer::HardHardPlanSnapshot,
    epoch: u64,
    punch_at_ms: u64,
) -> Option<(PunchSessionPermit, crate::peer::RecoveryEpochIdentity)> {
    let Some(reservation) = peers
        .try_begin_hard_hard_generation_for_epoch(peer_id, epoch)
        .await
    else {
        peers
            .record_direct_event(
                peer_id,
                "hard_hard_fresh_generation_quota_exhausted",
                None,
                None,
                None,
                "Hard↔Hard responder fresh-generation quota exhausted before punch claim; Relay remains usable",
            )
            .await;
        return None;
    };
    if !hard_hard_plan_claim_fence_is_current(
        peers,
        peer_id,
        peer_session_generation,
        plan,
        epoch,
        punch_at_ms,
    )
    .await
    {
        reservation.refund().await;
        return None;
    }
    let Some(claim) = punch_deduplicator
        .claim_for_epoch_with_rendezvous_for_peer_session(
            peers,
            peer_id,
            peer_session_generation,
            plan.local_network_generation,
            epoch,
            PUNCH_PRIORITY_FRESH_PREDICTION,
            None,
            Some(punch_at_ms),
        )
        .await
    else {
        reservation.refund().await;
        return None;
    };
    let deferred = match claim {
        RendezvousPunchClaim::Claimed(session) => {
            if !hard_hard_plan_claim_fence_is_current(
                peers,
                peer_id,
                peer_session_generation,
                plan,
                epoch,
                punch_at_ms,
            )
            .await
            {
                drop(session);
                reservation.refund().await;
                return None;
            }
            let recovery_identity = reservation.identity();
            reservation.commit();
            return Some((session, recovery_identity));
        }
        RendezvousPunchClaim::Deferred(deferred) => deferred,
        RendezvousPunchClaim::RejectedStalePeerSession => {
            reservation.refund().await;
            return None;
        }
    };
    let epoch_identity = reservation.identity();
    reservation.refund().await;
    let Some(retry_delay) = hard_hard_protected_claim_retry_delay(deferred, unix_time_millis())
    else {
        peers
            .record_direct_event(
                peer_id,
                "hard_hard_responder_claim_deferred",
                None,
                None,
                None,
                format!(
                    "Hard↔Hard responder folded behind session_id={} without retry reason={}",
                    deferred.active_session_id,
                    deferred.reason.label(),
                ),
            )
            .await;
        return None;
    };

    peers
        .record_direct_event(
            peer_id,
            "hard_hard_responder_claim_deferred",
            None,
            None,
            None,
            format!(
                "Hard↔Hard responder waiting once for protected ordinary session_id={} reason={} retry_delay_ms={}",
                deferred.active_session_id,
                deferred.reason.label(),
                retry_delay.as_millis(),
            ),
        )
        .await;
    sleep(retry_delay).await;

    let retry_fence_is_current = hard_hard_plan_claim_fence_is_current(
        peers,
        peer_id,
        peer_session_generation,
        plan,
        epoch,
        punch_at_ms,
    )
    .await;
    if !retry_fence_is_current {
        peers
            .record_direct_event(
                peer_id,
                "hard_hard_responder_claim_retry_fenced",
                None,
                None,
                None,
                "Hard↔Hard responder protected-claim retry crossed its punch/session/recovery fence",
            )
            .await;
        return None;
    }

    let Some(retry_reservation) = peers
        .try_begin_hard_hard_generation_for_identity(peer_id, epoch_identity)
        .await
    else {
        peers
            .record_direct_event(
                peer_id,
                "hard_hard_responder_claim_retry_fenced",
                None,
                None,
                None,
                "Hard↔Hard responder protected-claim retry lost its exact recovery reservation",
            )
            .await;
        return None;
    };
    if !peers.peer_session_is_current_sync(peer_id, peer_session_generation) {
        retry_reservation.refund().await;
        return None;
    }
    let Some(retry_claim) = punch_deduplicator
        .claim_for_epoch_with_rendezvous_for_peer_session(
            peers,
            peer_id,
            peer_session_generation,
            plan.local_network_generation,
            epoch,
            PUNCH_PRIORITY_FRESH_PREDICTION,
            None,
            Some(punch_at_ms),
        )
        .await
    else {
        retry_reservation.refund().await;
        return None;
    };
    match retry_claim {
        RendezvousPunchClaim::Claimed(session) => {
            if !hard_hard_plan_claim_fence_is_current(
                peers,
                peer_id,
                peer_session_generation,
                plan,
                epoch,
                punch_at_ms,
            )
            .await
            {
                drop(session);
                retry_reservation.refund().await;
                return None;
            }
            let recovery_identity = retry_reservation.identity();
            retry_reservation.commit();
            Some((session, recovery_identity))
        }
        RendezvousPunchClaim::Deferred(retry) => {
            retry_reservation.refund().await;
            peers
                .record_direct_event(
                    peer_id,
                    "hard_hard_responder_claim_retry_exhausted",
                    None,
                    None,
                    None,
                    format!(
                        "Hard↔Hard responder bounded claim retry remained deferred behind session_id={} reason={}",
                        retry.active_session_id,
                        retry.reason.label(),
                    ),
                )
                .await;
            None
        }
        RendezvousPunchClaim::RejectedStalePeerSession => {
            retry_reservation.refund().await;
            None
        }
    }
}

fn hard_hard_initiator_response_record_matches(
    current: &HardHardSessionRecord,
    expected: &HardHardSessionRecord,
) -> bool {
    current.session_id == expected.session_id
        && current.session_token == expected.session_token
        && current.peer_id == expected.peer_id
        && current.initiator
        && current.state == HardHardSessionState::AwaitingPeer
        && current.attempt_count == expected.attempt_count
        && current.remote_network_generation == expected.remote_network_generation
        && current.local_network_generation == expected.local_network_generation
        && current.remote_candidate_epoch == expected.remote_candidate_epoch
        && current.local_profile_generation == expected.local_profile_generation
        && current.remote_profile_generation == expected.remote_profile_generation
        && current.local_prediction_confidence == expected.local_prediction_confidence
        && current.remote_prediction_confidence == expected.remote_prediction_confidence
        && current.requested_birthday_level == expected.requested_birthday_level
        && current.generated_candidate_count == expected.generated_candidate_count
        && current.signaled_candidate_count == expected.signaled_candidate_count
        && current.birthday == expected.birthday
        && current.requested_socket_indices == expected.requested_socket_indices
        && current.requested_socket_count == expected.requested_socket_count
        && current.prediction_window == expected.prediction_window
        && current.remote_prediction == expected.remote_prediction
        && current.fresh_socket == expected.fresh_socket
        && current.punch_at_ms == expected.punch_at_ms
        && current.expires_at_ms == expected.expires_at_ms
        && Arc::ptr_eq(&current.cancellation, &expected.cancellation)
        && !current.cancellation.is_cancelled()
}

async fn hard_hard_initiator_response_claim_fence_is_current(
    peers: &PeerManager,
    peer_id: &str,
    peer_session_generation: crate::peer::PeerSessionGeneration,
    plan: crate::peer::HardHardPlanSnapshot,
    record: &HardHardSessionRecord,
    epoch: u64,
) -> bool {
    let current_record = peers
        .hard_hard_session_by_token(peer_id, &record.session_token)
        .await;
    let current_plan = peers.hard_hard_plan_for_peer(peer_id).await;
    // The initiator already owns a measured socket. A reciprocal response is
    // deliberately allowed at the canonical punch instant (the test/control
    // forwarder may advance the shared clock to exactly `punch_at_ms`) and
    // through the bounded sweep deadline. Reusing the responder's
    // pre-measurement minimum-lead check here incorrectly rejects the on-time
    // response and leaves only the responder sweeping.
    record
        .punch_at_ms
        .saturating_add(HARD_HARD_SWEEP_DEADLINE.as_millis() as u64)
        >= hard_hard_now_ms()
        && !peers.is_direct(peer_id).await
        && peers.peer_session_is_current_sync(peer_id, peer_session_generation)
        && current_record
            .as_ref()
            .is_some_and(|current| hard_hard_initiator_response_record_matches(current, record))
        && current_plan.is_some_and(|current| hard_hard_plan_matches(current, plan))
        && matches!(
            peers.recovery_epoch_admit(peer_id).await,
            RecoveryAdmission::Accepted { epoch: current } if current == epoch
        )
}

/// A reciprocal response may collide with the short first-send protection of
/// an ordinary rendezvous which started while the initiator awaited its peer.
/// Preserve that already-dispatched send, then retry the higher-priority fresh
/// response exactly once.  Every delayed owner is re-admitted through all
/// independent session, planner, recovery, lifecycle and time fences first.
#[allow(clippy::too_many_arguments)]
async fn claim_hard_hard_initiator_response_session(
    peers: &PeerManager,
    punch_deduplicator: &PunchAttemptDeduplicator,
    peer_id: &str,
    peer_session_generation: crate::peer::PeerSessionGeneration,
    plan: crate::peer::HardHardPlanSnapshot,
    record: &HardHardSessionRecord,
    epoch: u64,
) -> Option<PunchSessionPermit> {
    if !hard_hard_initiator_response_claim_fence_is_current(
        peers,
        peer_id,
        peer_session_generation,
        plan,
        record,
        epoch,
    )
    .await
    {
        return None;
    }
    let claim = punch_deduplicator
        .claim_for_epoch_with_rendezvous_for_peer_session(
            peers,
            peer_id,
            peer_session_generation,
            record.local_network_generation,
            epoch,
            PUNCH_PRIORITY_FRESH_PREDICTION,
            None,
            Some(record.punch_at_ms),
        )
        .await?;
    let deferred = match claim {
        RendezvousPunchClaim::Claimed(session) => {
            if hard_hard_initiator_response_claim_fence_is_current(
                peers,
                peer_id,
                peer_session_generation,
                plan,
                record,
                epoch,
            )
            .await
            {
                return Some(session);
            }
            drop(session);
            return None;
        }
        RendezvousPunchClaim::Deferred(deferred) => deferred,
        RendezvousPunchClaim::RejectedStalePeerSession => return None,
    };
    let Some(retry_delay) = hard_hard_protected_claim_retry_delay(deferred, unix_time_millis())
    else {
        peers
            .record_direct_event(
                peer_id,
                "hard_hard_initiator_response_claim_deferred",
                None,
                None,
                None,
                format!(
                    "Hard↔Hard initiator response folded behind session_id={} without retry reason={}",
                    deferred.active_session_id,
                    deferred.reason.label(),
                ),
            )
            .await;
        return None;
    };

    peers
        .record_direct_event(
            peer_id,
            "hard_hard_initiator_response_claim_deferred",
            None,
            None,
            None,
            format!(
                "Hard↔Hard initiator response waiting once for protected ordinary session_id={} reason={} retry_delay_ms={}",
                deferred.active_session_id,
                deferred.reason.label(),
                retry_delay.as_millis(),
            ),
        )
        .await;
    sleep(retry_delay).await;

    let retry_fence_is_current = hard_hard_initiator_response_claim_fence_is_current(
        peers,
        peer_id,
        peer_session_generation,
        plan,
        record,
        epoch,
    )
    .await;
    if !retry_fence_is_current {
        peers
            .record_direct_event(
                peer_id,
                "hard_hard_initiator_response_claim_retry_fenced",
                None,
                None,
                None,
                "Hard↔Hard initiator response protected-claim retry crossed its token/session/plan/recovery/lifecycle/punch-window fence",
            )
            .await;
        return None;
    }

    let retry_claim = punch_deduplicator
        .claim_for_epoch_with_rendezvous_for_peer_session(
            peers,
            peer_id,
            peer_session_generation,
            record.local_network_generation,
            epoch,
            PUNCH_PRIORITY_FRESH_PREDICTION,
            None,
            Some(record.punch_at_ms),
        )
        .await?;
    match retry_claim {
        RendezvousPunchClaim::Claimed(session) => {
            if hard_hard_initiator_response_claim_fence_is_current(
                peers,
                peer_id,
                peer_session_generation,
                plan,
                record,
                epoch,
            )
            .await
            {
                Some(session)
            } else {
                drop(session);
                None
            }
        }
        RendezvousPunchClaim::Deferred(retry) => {
            peers
                .record_direct_event(
                    peer_id,
                    "hard_hard_initiator_response_claim_retry_exhausted",
                    None,
                    None,
                    None,
                    format!(
                        "Hard↔Hard initiator response bounded claim retry remained deferred behind session_id={} reason={}",
                        retry.active_session_id,
                        retry.reason.label(),
                    ),
                )
                .await;
            None
        }
        RendezvousPunchClaim::RejectedStalePeerSession => None,
    }
}

fn hard_hard_socket_identity(
    peer_id: &str,
    session_token: &str,
    result: &FreshMappingResult,
    plan: crate::peer::HardHardPlanSnapshot,
) -> crate::peer::HardHardFreshSocketIdentity {
    crate::peer::HardHardFreshSocketIdentity {
        peer_id: peer_id.to_string(),
        session_token: session_token.to_string(),
        network_generation: result.network_generation,
        remote_candidate_epoch: plan.remote_candidate_epoch,
        local_profile_generation: plan.local_profile_generation,
        remote_profile_generation: plan.remote_profile_generation,
        punch_generation: result.punch_generation,
        socket_index: result.socket_index,
        socket_local_endpoint: result.socket_local_endpoint,
    }
}

enum HardHardLocalMeasurement {
    Predictable {
        result: Box<FreshMappingResult>,
        handoff: Box<ProvisionalSocketGuard>,
    },
    Birthday(Box<HardHardBirthdayResult>),
}

struct HardHardMeasurementPayload {
    candidates: Vec<String>,
    candidate_sources: HashMap<String, String>,
    local_confidence: u8,
    local_model: String,
    candidate_contract: crate::candidate_refresh::SignalCandidateContract,
}

fn hard_hard_measurement_target_limit(measurement: &HardHardLocalMeasurement) -> usize {
    match measurement {
        HardHardLocalMeasurement::Predictable { .. } => HARD_HARD_MAX_PREDICTION_TARGETS,
        HardHardLocalMeasurement::Birthday(result) => result
            .level
            .min(HARD_HARD_MAX_BIRTHDAY_TARGETS),
    }
}

fn hard_hard_measurement_is_birthday(measurement: &HardHardLocalMeasurement) -> bool {
    matches!(measurement, HardHardLocalMeasurement::Birthday(_))
}

fn hard_hard_measurement_requested_level(measurement: &HardHardLocalMeasurement) -> usize {
    match measurement {
        HardHardLocalMeasurement::Predictable { .. } => 0,
        HardHardLocalMeasurement::Birthday(result) => result.requested_level,
    }
}

fn hard_hard_measurement_socket_indices(measurement: &HardHardLocalMeasurement) -> Vec<usize> {
    match measurement {
        HardHardLocalMeasurement::Predictable { result, .. } => vec![result.socket_index],
        HardHardLocalMeasurement::Birthday(result) => result
            .sockets
            .iter()
            .map(|socket| socket.socket_index)
            .collect(),
    }
}

fn hard_hard_measurement_requested_socket_count(
    measurement: &HardHardLocalMeasurement,
) -> usize {
    match measurement {
        HardHardLocalMeasurement::Predictable { .. } => 1,
        HardHardLocalMeasurement::Birthday(result) => result.requested_socket_count,
    }
}

fn hard_hard_measurement_summary(measurement: &HardHardLocalMeasurement) -> String {
    match measurement {
        HardHardLocalMeasurement::Predictable { result, .. } => format!(
            "mode=predictable model={} confidence={} public_ip={:?} public_port_samples={:?} socket_count=1 sample_count={} target_count={}",
            hard_hard_model_label(&result.model.kind),
            result.model.confidence,
            result.public_ip,
            result.model.sequence,
            result.model.sequence.len(),
            result.predicted_ports.len(),
        ),
        HardHardLocalMeasurement::Birthday(result) => format!(
            "mode=birthday model={} strategy=bounded_birthday confidence={} level={} requested_level={} requested_socket_count={} public_ip={} public_port_samples={:?} socket_count={} sample_count={} target_count={}",
            result.model_label,
            result.model_confidence,
            result.level,
            result.requested_level,
            result.requested_socket_count,
            result.public_ip,
            result.public_port_samples,
            result.sockets.len(),
            result.observation_count,
            result.candidate_endpoints.len(),
        ),
    }
}

/// Make every speculative socket durable only after the control-plane offer
/// has succeeded. A birthday result owns one guard per socket; finalizing all
/// of them is what keeps the non-winning candidates alive until authenticated
/// peer-reflexive evidence selects one.
async fn finalize_hard_hard_measurement(measurement: &mut HardHardLocalMeasurement) -> bool {
    match measurement {
        HardHardLocalMeasurement::Predictable { handoff, .. } => handoff.finalize().await,
        HardHardLocalMeasurement::Birthday(result) => {
            let mut finalized = true;
            for socket in &result.sockets {
                if !socket.guard.finalize().await {
                    finalized = false;
                }
            }
            finalized
        }
    }
}

fn hard_hard_birthday_level_for_stage(
    android_platform: bool,
    stage: crate::peer::RecoveryStage,
) -> usize {
    let desktop_level = match stage {
        crate::peer::RecoveryStage::Initial => 64,
        crate::peer::RecoveryStage::Predicted | crate::peer::RecoveryStage::ScatterSmall => 128,
        crate::peer::RecoveryStage::ScatterExtended | crate::peer::RecoveryStage::RelayBackoff => {
            256
        }
    };
    if android_platform {
        desktop_level.min(128)
    } else {
        desktop_level
    }
}

async fn hard_hard_birthday_level(peers: &PeerManager, peer_id: &str) -> usize {
    hard_hard_birthday_level_for_stage(
        peers.is_android_platform(),
        peers.recovery_stage_for(peer_id).await,
    )
}

async fn run_hard_hard_local_measurement(
    udp: &UdpTransport,
    peers: &PeerManager,
    peer_id: &str,
    observers: &[SocketAddr],
    stun_timeout: Duration,
    session_token: &str,
    cancellation: Option<&Arc<crate::PunchSessionCancellation>>,
) -> Option<HardHardLocalMeasurement> {
    if peers
        .hard_hard_plan_uses_birthday(peer_id)
        .await
        .unwrap_or(false)
    {
        let level = hard_hard_birthday_level(peers, peer_id).await;
        return udp
            .run_hard_hard_birthday_generation(
                peer_id,
                observers,
                stun_timeout,
                level,
                session_token,
                cancellation,
            )
            .await
            .ok()
            .map(|result| HardHardLocalMeasurement::Birthday(Box::new(result)));
    }
    match udp
        .run_hard_hard_fresh_mapping_generation(peer_id, observers, stun_timeout, cancellation)
        .await
    {
        FreshMappingOutcome::Accepted(result, handoff) => {
            if !udp
                .tag_hard_hard_socket(peer_id, result.socket_index, session_token)
                .await
            {
                return None;
            }
            Some(HardHardLocalMeasurement::Predictable { result, handoff })
        }
        FreshMappingOutcome::Rejected(_) => None,
    }
}

fn hard_hard_measurement_payload(
    measurement: &HardHardLocalMeasurement,
    boot_epoch_ms: u64,
) -> Option<HardHardMeasurementPayload> {
    match measurement {
        HardHardLocalMeasurement::Predictable { result, .. } => {
            let (candidates, sources) = hard_hard_prediction_payload(result, boot_epoch_ms)?;
            let (candidates, sources, candidate_contract) =
                crate::candidate_refresh::normalize_signal_candidates_with_counts(
                    &candidates,
                    &sources,
                    result
                        .predicted_ports
                        .len()
                        .min(HARD_HARD_MAX_PREDICTION_TARGETS),
                    candidates.len(),
                );
            (!candidates.is_empty()).then_some(HardHardMeasurementPayload {
                candidates,
                candidate_sources: sources,
                local_confidence: result.model.confidence,
                local_model: hard_hard_model_label(&result.model.kind).to_string(),
                candidate_contract,
            })
        }
        HardHardLocalMeasurement::Birthday(result) => {
            let fresh_id = FreshPredictionId {
                boot_epoch: boot_epoch_ms,
                generation: result
                    .sockets
                    .first()
                    .map(|socket| socket.punch_generation)?,
            };
            let source = fresh_prediction_source_label(fresh_id);
            let mut candidates = Vec::with_capacity(result.candidate_endpoints.len());
            let mut sources = HashMap::with_capacity(result.candidate_endpoints.len());
            for endpoint in &result.candidate_endpoints {
                let endpoint = endpoint.to_string();
                if sources.contains_key(&endpoint) {
                    continue;
                }
                sources.insert(endpoint.clone(), source.clone());
                candidates.push(endpoint);
            }
            let (candidates, sources, candidate_contract) =
                crate::candidate_refresh::normalize_signal_candidates_with_counts(
                    &candidates,
                    &sources,
                    result.requested_level,
                    candidates.len(),
                );
            (!candidates.is_empty()).then_some(HardHardMeasurementPayload {
                candidates,
                candidate_sources: sources,
                local_confidence: result.model_confidence,
                local_model: result.model_label.clone(),
                candidate_contract,
            })
        }
    }
}

async fn record_hard_hard_candidate_contract(
    peers: &PeerManager,
    peer_id: &str,
    contract: crate::candidate_refresh::SignalCandidateContract,
    signaling_accepted: bool,
) {
    peers
        .record_direct_event(
            peer_id,
            "hard_hard_candidate_contract",
            None,
            Some(contract.signaled_candidate_count),
            None,
            format!(
                "requested_candidate_count={} generated_candidate_count={} deduplicated_candidate_count={} signaled_candidate_count={} cap={} capped={} candidate_source_count={} reason={} signaling_result={}",
                contract.requested_candidate_count,
                contract.generated_candidate_count,
                contract.deduplicated_candidate_count,
                contract.signaled_candidate_count,
                contract.cap,
                contract.capped,
                contract.candidate_source_count,
                contract.reason,
                if signaling_accepted { "accepted" } else { "failed" },
            ),
        )
        .await;
}

fn hard_hard_measurement_primary_socket(
    peer_id: &str,
    token: &str,
    measurement: &HardHardLocalMeasurement,
    plan: crate::peer::HardHardPlanSnapshot,
) -> Option<crate::peer::HardHardFreshSocketIdentity> {
    match measurement {
        HardHardLocalMeasurement::Predictable { result, .. } => {
            Some(hard_hard_socket_identity(peer_id, token, result, plan))
        }
        HardHardLocalMeasurement::Birthday(result) => result.sockets.first().map(|socket| {
            crate::peer::HardHardFreshSocketIdentity {
                peer_id: peer_id.to_string(),
                session_token: token.to_string(),
                network_generation: plan.local_network_generation,
                remote_candidate_epoch: plan.remote_candidate_epoch,
                local_profile_generation: plan.local_profile_generation,
                remote_profile_generation: plan.remote_profile_generation,
                punch_generation: socket.punch_generation,
                socket_index: socket.socket_index,
                socket_local_endpoint: socket.socket_local_endpoint,
            }
        }),
    }
}

/// The single Hard↔Hard success proof.  Peer-global Direct is only one input:
/// the same current session identity must have selected a Direct candidate on
/// the expected local endpoint, and the exact dynamic socket must be the
/// affinity pin with authenticated evidence of its own.
async fn hard_hard_exact_direct_confirmation_is_current(
    udp: &UdpTransport,
    peers: &PeerManager,
    identity: &crate::peer::HardHardFreshSocketIdentity,
) -> bool {
    peers
        .hard_hard_direct_confirmation_is_current(identity)
        .await
        && udp
            .hard_hard_socket_identity_has_authenticated_evidence(identity)
            .await
}

/// Wait for the existing Direct commit sequence, then require the exact
/// Hard↔Hard socket proof.  A Direct transition on another socket terminates
/// immediately; a matching manager commit gets a short bounded opportunity for
/// the ACK transaction to finish its affinity adoption under the same epoch
/// fence.
async fn hard_hard_wait_for_exact_direct_confirmation(
    udp: &UdpTransport,
    peers: &PeerManager,
    session: &PunchSessionPermit,
    identity: &crate::peer::HardHardFreshSocketIdentity,
    from_commit_seq: Option<u64>,
) -> bool {
    let deadline = Instant::now() + HARD_HARD_DIRECT_CONFIRMATION_GRACE;
    loop {
        let session_current = peers
            .hard_hard_session_identity_is_current_for_confirmation(identity)
            .await;
        if session.is_cancelled() || !session_current {
            return false;
        }

        let commit_advanced = peers.direct_commit_seq_sync(&identity.peer_id) != from_commit_seq;
        let manager_pair_matches = peers.direct_commit_pair_matches_sync(identity);
        if commit_advanced
            && manager_pair_matches
            && udp
                .hard_hard_socket_identity_has_authenticated_evidence(identity)
                .await
        {
            return true;
        }

        // A peer-global Direct commit that selected another local endpoint is
        // the competing ordinary-Direct case.  Do not wait for a misleading
        // success on the Hard↔Hard socket.
        if peers.is_direct_sync(&identity.peer_id) && !manager_pair_matches {
            return false;
        }

        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return false;
        }
        // Wait on the commit sequence notification rather than polling at a
        // fixed cadence.  The sequence is re-checked after every wake, and
        // `enable` closes the check-to-wait race because `notify_waiters`
        // itself does not retain a permit for a not-yet-enabled waiter.
        let notify = peers.direct_commit_notify();
        let notified = notify.notified();
        tokio::pin!(notified);
        notified.as_mut().enable();
        tokio::select! {
            _ = session.cancelled() => return false,
            _ = notified => {}
            _ = sleep(remaining) => return false,
        }
    }
}

/// Cleanup may run after the short rendezvous session has expired.  It still
/// retains a socket only when the current Direct candidate pair and the exact
/// socket's authenticated evidence agree; the expired session token itself is
/// intentionally not required for this post-success retention decision.
async fn hard_hard_exact_direct_socket_is_current_for_cleanup(
    udp: &UdpTransport,
    peers: &PeerManager,
    identity: &crate::peer::HardHardFreshSocketIdentity,
) -> bool {
    peers.hard_hard_direct_pair_is_current(identity).await
        && udp
            .hard_hard_socket_identity_has_authenticated_evidence(identity)
            .await
}

/// An authenticated Hard↔Hard winner may reach the encrypted validation
/// worker just after the short rendezvous sweep expires. Keep that exact
/// socket alive until the normal bounded session cleanup gets a chance to see
/// the Direct commit; a winner with no socket-local authenticated evidence is
/// still cleaned immediately by the caller.
async fn hard_hard_authenticated_winner_for_cleanup(
    udp: &UdpTransport,
    peers: &PeerManager,
    peer_id: &str,
    session_token: &str,
) -> Option<crate::peer::HardHardFreshSocketIdentity> {
    let winner = peers
        .hard_hard_winner_for_token(peer_id, session_token)
        .await?;
    let identity = peers
        .hard_hard_fresh_socket_for_token(peer_id, session_token)
        .await?;
    if identity.socket_index != winner
        || !peers.hard_hard_session_identity_is_current(&identity).await
        || !udp
            .hard_hard_socket_identity_has_authenticated_evidence(&identity)
            .await
    {
        return None;
    }
    Some(identity)
}

async fn hard_hard_authenticated_socket_for_cleanup(
    udp: &UdpTransport,
    peers: &PeerManager,
    identity: &crate::peer::HardHardFreshSocketIdentity,
) -> bool {
    peers.hard_hard_session_identity_is_current(identity).await
        && udp
            .hard_hard_socket_identity_has_authenticated_evidence(identity)
            .await
}

/// Start the local side of a Hard↔Hard rendezvous.  The task measures first,
/// advertises the result, finalizes the exact dynamic socket only after the
/// signal is accepted, then waits for the peer's reciprocal prediction.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn spawn_hard_hard_initiator(
    udp: UdpTransport,
    peers: Arc<PeerManager>,
    punch_deduplicator: PunchAttemptDeduplicator,
    peer_id: String,
    signal: HolePunchSignalContext,
    invocation_shutdown_rx: Option<tokio::sync::watch::Receiver<bool>>,
) -> HardHardInitiatorStart {
    if punch_invocation_is_cancelled(invocation_shutdown_rx.as_ref()) {
        return HardHardInitiatorStart::InvocationCancelled;
    }
    let Some(peer_session_generation) = peers.peer_session_generation_sync(&peer_id) else {
        return HardHardInitiatorStart::NotStarted(HardHardInitiatorNotStarted::RecoverySuperseded);
    };
    if peers.hard_hard_session_is_active(&peer_id).await {
        return HardHardInitiatorStart::ExistingSession;
    }
    let Some(plan) = peers.hard_hard_plan_for_peer(&peer_id).await else {
        return HardHardInitiatorStart::NotStarted(HardHardInitiatorNotStarted::PlanChanged);
    };
    peers
        .record_direct_event(
            &peer_id,
            "hard_hard_plan_selected",
            None,
            None,
            None,
            format!(
                "role=initiator network_generation={} remote_candidate_epoch={} local_profile_generation={} remote_profile_generation={}",
                plan.local_network_generation,
                plan.remote_candidate_epoch,
                plan.local_profile_generation,
                plan.remote_profile_generation,
            ),
        )
        .await;
    if signal.boot_epoch_ms == 0 {
        peers
            .record_direct_event(
                &peer_id,
                "hard_hard_skipped",
                None,
                None,
                None,
                "Hard↔Hard requires a trustworthy boot incarnation; continuing with ordinary punching",
            )
            .await;
        return HardHardInitiatorStart::NotStarted(
            HardHardInitiatorNotStarted::BootEpochUnavailable,
        );
    }
    if signal.stun_servers.len() < 3 {
        peers
            .record_direct_event(
                &peer_id,
                "hard_hard_skipped",
                None,
                None,
                None,
                "Hard↔Hard requires at least three STUN observers; continuing with ordinary punching",
            )
            .await;
        return HardHardInitiatorStart::NotStarted(
            HardHardInitiatorNotStarted::InsufficientStunObservers,
        );
    }
    if punch_invocation_is_cancelled(invocation_shutdown_rx.as_ref()) {
        return HardHardInitiatorStart::InvocationCancelled;
    }
    let epoch = match peers.recovery_epoch_admit(&peer_id).await {
        RecoveryAdmission::Accepted { epoch } => epoch,
        RecoveryAdmission::Superseded => {
            return HardHardInitiatorStart::NotStarted(
                HardHardInitiatorNotStarted::RecoverySuperseded,
            );
        }
        RecoveryAdmission::BudgetExhausted { .. } => {
            return HardHardInitiatorStart::NotStarted(
                HardHardInitiatorNotStarted::RecoveryBudgetExhausted,
            );
        }
    };
    let Some(fresh_generation_reservation) = peers
        .try_begin_hard_hard_generation_for_epoch(&peer_id, epoch)
        .await
    else {
        peers
            .record_direct_event(
                &peer_id,
                "hard_hard_fresh_generation_quota_exhausted",
                None,
                None,
                None,
                "Hard↔Hard fresh-generation quota exhausted for this recovery epoch; Relay remains usable",
            )
            .await;
        return HardHardInitiatorStart::NotStarted(
            HardHardInitiatorNotStarted::FreshGenerationQuotaExhausted,
        );
    };
    if punch_invocation_is_cancelled(invocation_shutdown_rx.as_ref()) {
        fresh_generation_reservation.refund().await;
        return HardHardInitiatorStart::InvocationCancelled;
    }
    let punch_at_ms = hard_hard_now_ms().saturating_add(HARD_HARD_PUNCH_LEAD.as_millis() as u64);
    if !hard_hard_plan_claim_fence_is_current(
        &peers,
        &peer_id,
        peer_session_generation,
        plan,
        epoch,
        punch_at_ms,
    )
    .await
    {
        fresh_generation_reservation.refund().await;
        return HardHardInitiatorStart::NotStarted(HardHardInitiatorNotStarted::PlanChanged);
    }
    let Some(claim) = punch_deduplicator
        .claim_for_epoch_with_rendezvous_for_peer_session(
            &peers,
            &peer_id,
            peer_session_generation,
            plan.local_network_generation,
            epoch,
            PUNCH_PRIORITY_FRESH_PREDICTION,
            None,
            Some(punch_at_ms),
        )
        .await
    else {
        fresh_generation_reservation.refund().await;
        return HardHardInitiatorStart::NotStarted(HardHardInitiatorNotStarted::RecoverySuperseded);
    };
    let (session, recovery_identity) = match claim {
        RendezvousPunchClaim::Claimed(session) => {
            if !hard_hard_plan_claim_fence_is_current(
                &peers,
                &peer_id,
                peer_session_generation,
                plan,
                epoch,
                punch_at_ms,
            )
            .await
            {
                drop(session);
                fresh_generation_reservation.refund().await;
                return HardHardInitiatorStart::NotStarted(
                    HardHardInitiatorNotStarted::PlanChanged,
                );
            }
            let recovery_identity = fresh_generation_reservation.identity();
            fresh_generation_reservation.commit();
            (session, recovery_identity)
        }
        RendezvousPunchClaim::Deferred(deferred) => {
            fresh_generation_reservation.refund().await;
            peers
                .record_direct_event(
                    &peer_id,
                    "hard_hard_deferred",
                    None,
                    None,
                    None,
                    format!(
                        "Hard↔Hard initiator folded behind session_id={} epoch={} reason={}",
                        deferred.active_session_id,
                        deferred.active_epoch,
                        deferred.reason.label()
                    ),
                )
                .await;
            return HardHardInitiatorStart::ExistingPunchOwner;
        }
        RendezvousPunchClaim::RejectedStalePeerSession => {
            fresh_generation_reservation.refund().await;
            return HardHardInitiatorStart::NotStarted(
                HardHardInitiatorNotStarted::RecoverySuperseded,
            );
        }
    };
    let token = hard_hard_session_token(session.session_id());
    let coordination = hard_hard_coordination_from_plan(token, HardHardRole::Initiator, plan);
    let cancellation = session.cancellation_handle();
    // Capture the authoritative Probe receive-session identity before the
    // deadline-sensitive rendezvous task exists.  The sweep must not perform
    // a best-effort try-read at punch time and accidentally attribute ACKs to
    // the unscoped `None` bucket.
    let probe_session_id = peers.probe_session_id_for_peer(&peer_id).await;
    bind_hard_hard_session_to_punch_invocation(invocation_shutdown_rx, cancellation.clone());
    tokio::spawn(async move {
        // Keep the dedup permit until the measured session is installed in the
        // authoritative manager ledger. Without this capture `session` was
        // dropped as soon as the worker was spawned, allowing an ordinary
        // trigger to run in parallel while Hard↔Hard was still measuring.
        let session_owner = session;
        let mut pending_session_cancellation =
            PendingHardHardSessionCancellation::new(cancellation.clone());
        let Some(mut measurement) = run_hard_hard_local_measurement(
            &udp,
            &peers,
            &peer_id,
            &signal.stun_servers,
            signal.stun_timeout,
            &coordination.token,
            Some(&cancellation),
        )
        .await else {
            if cancellation.is_cancelled() {
                return;
            }
            peers
                .record_direct_event(
                    &peer_id,
                    "hard_hard_measurement_failed",
                    None,
                    None,
                    None,
                    "Hard↔Hard fresh measurement/model failed; keeping Relay or the existing path",
                )
                .await;
            return;
        };
        if cancellation.is_cancelled()
            || !peers.peer_session_is_current_sync(&peer_id, peer_session_generation)
            || peers.is_direct(&peer_id).await
            || peers
                .hard_hard_plan_for_peer(&peer_id)
                .await
                .is_none_or(|current| !hard_hard_plan_matches(current, plan))
        {
            peers
                .record_direct_event(
                    &peer_id,
                    "hard_hard_measurement_fenced",
                    None,
                    None,
                    None,
                    "Hard↔Hard measurement completed after a session/profile/network fence changed; socket was not advertised",
                )
                .await;
            return;
        }
        let Some(HardHardMeasurementPayload {
            candidates,
            candidate_sources,
            local_confidence,
            local_model,
            candidate_contract,
        }) = hard_hard_measurement_payload(&measurement, signal.boot_epoch_ms)
        else {
            peers
                .record_direct_event(
                    &peer_id,
                    "hard_hard_measurement_failed",
                    None,
                    None,
                    None,
                    "Hard↔Hard model produced no usable public prediction window; Relay remains available",
                )
                .await;
            return;
        };
        let Some(primary_socket) = hard_hard_measurement_primary_socket(
            &peer_id,
            &coordination.token,
            &measurement,
            plan,
        ) else {
            return;
        };
        peers
            .record_direct_event(
                &peer_id,
                "hard_hard_local_nat_model",
                None,
                Some(candidates.len()),
                None,
                format!(
                    "role=initiator token={} model={} confidence={} {}",
                    coordination.token,
                    local_model,
                    local_confidence,
                    hard_hard_measurement_summary(&measurement),
                ),
            )
            .await;
        let mut coordination = coordination;
        coordination.local_prediction_confidence = local_confidence;
        coordination.local_prediction_model = local_model;
        let session_id = coordination.encode();
        let prediction_window = hard_hard_prediction_targets(
            &candidates,
            hard_hard_measurement_target_limit(&measurement),
        );
        let requested_birthday_level = hard_hard_measurement_requested_level(&measurement);
        let birthday = hard_hard_measurement_is_birthday(&measurement);
        let requested_socket_indices = hard_hard_measurement_socket_indices(&measurement);
        let record = HardHardSessionRecord {
            session_id: session_id.clone(),
            probe_session_id: probe_session_id.clone(),
            session_token: coordination.token.clone(),
            peer_id: peer_id.clone(),
            initiator: true,
            remote_network_generation: 0,
            local_network_generation: plan.local_network_generation,
            remote_candidate_epoch: plan.remote_candidate_epoch,
            local_profile_generation: plan.local_profile_generation,
            remote_profile_generation: plan.remote_profile_generation,
            local_prediction_confidence: local_confidence,
            remote_prediction_confidence: 0,
            requested_birthday_level,
            generated_candidate_count: candidate_contract.generated_candidate_count,
            signaled_candidate_count: candidate_contract.signaled_candidate_count,
            birthday,
            requested_socket_count:
                hard_hard_measurement_requested_socket_count(&measurement),
            requested_socket_indices,
            prediction_window,
            remote_prediction: Vec::new(),
            fresh_socket: primary_socket.clone(),
            punch_at_ms,
            expires_at_ms: hard_hard_now_ms()
                .saturating_add(HARD_HARD_SESSION_TTL.as_millis() as u64),
            state: HardHardSessionState::AwaitingPeer,
            attempt_count: 0,
            created_at: Instant::now(),
            cancellation: cancellation.clone(),
        };
        let cleanup_descriptor = HardHardCleanupDescriptor::from_record(&record);
        let registered = !cancellation.is_cancelled()
            && peers.peer_session_is_current_sync(&peer_id, peer_session_generation)
            && peers.hard_hard_register_session(record).await;
        if !registered {
            return;
        }
        let _cleanup_completion =
            spawn_hard_hard_session_cleanup(udp.clone(), peers.clone(), cleanup_descriptor.clone());
        if cancellation.is_cancelled()
            || !peers.peer_session_is_current_sync(&peer_id, peer_session_generation)
        {
            let _ = peers
                .hard_hard_retire_session(
                    &cleanup_descriptor.peer_id,
                    &cleanup_descriptor.session_id,
                    &cleanup_descriptor.session_token,
                )
                .await;
            return;
        }
        peers
            .record_direct_event(
                &peer_id,
                "hard_hard_session_started",
                None,
                Some(candidates.len()),
                None,
                format!(
                    "role=initiator token={} network_generation={} remote_candidate_epoch={} local_profile_generation={} remote_profile_generation={} punch_at_ms={} local_clock_ms={}",
                    coordination.token,
                    plan.local_network_generation,
                    plan.remote_candidate_epoch,
                    plan.local_profile_generation,
                    plan.remote_profile_generation,
                    punch_at_ms,
                    hard_hard_now_ms(),
                ),
            )
            .await;
        pending_session_cancellation.disarm();
        // The manager ledger is now the authoritative active-session gate.
        // Release the measurement permit before publishing: the peer cannot
        // send its reciprocal response until that publish succeeds, and the
        // initiator-response worker must be able to claim the punch owner as
        // soon as such a response arrives.  Holding this permit through the
        // publish would fold and silently lose an extremely fast response.
        drop(session_owner);
        let advertised = if !cancellation.is_cancelled()
            && peers.peer_session_is_current_sync(&peer_id, peer_session_generation)
            && peers
                .try_consume_recovery_http_quota_for_identity(&peer_id, recovery_identity)
                .await
            && !cancellation.is_cancelled()
            && peers.peer_session_is_current_sync(&peer_id, peer_session_generation)
        {
            matches!(
                signal
                    .control
                    .send_fresh_peer_offer_with_session_and_punch_at(
                        &peer_id,
                        &candidates,
                        &candidate_sources,
                        &[],
                        Some(punch_at_ms),
                        Some(session_id.clone()),
                        cancellation.clone(),
                    )
                    .await,
                Ok(())
            )
        } else {
            false
        };
        record_hard_hard_candidate_contract(
            &peers,
            &peer_id,
            candidate_contract,
            advertised,
        )
        .await;
        if !advertised
            || peers.is_direct(&peer_id).await
            || cancellation.is_cancelled()
            || !peers.peer_session_is_current_sync(&peer_id, peer_session_generation)
        {
            peers
                .record_direct_event(
                    &peer_id,
                    "hard_hard_advertisement_failed",
                    None,
                    Some(candidates.len()),
                    None,
                    "Hard↔Hard prediction was not accepted or was superseded; the measured socket was rolled back and Relay remains usable",
                )
                .await;
            let _ = peers
                .hard_hard_retire_session(
                    &cleanup_descriptor.peer_id,
                    &cleanup_descriptor.session_id,
                    &cleanup_descriptor.session_token,
                )
                .await;
            return;
        }
        let handoff_ok = finalize_hard_hard_measurement(&mut measurement).await;
        if !handoff_ok {
            peers
                .record_direct_event(
                    &peer_id,
                    "hard_hard_handoff_failed",
                    None,
                    Some(candidates.len()),
                    None,
                    "Hard↔Hard prediction reached the control plane but the measured socket lost ownership before handoff",
                )
                .await;
            let _ = peers
                .hard_hard_retire_session(
                    &cleanup_descriptor.peer_id,
                    &cleanup_descriptor.session_id,
                    &cleanup_descriptor.session_token,
                )
                .await;
            return;
        }
        peers
            .record_direct_event(
                &peer_id,
                "hard_hard_rendezvous_scheduled",
                None,
                Some(candidates.len()),
                None,
                format!(
                    "role=initiator token={} punch_at_ms={} local_clock_ms={} lead_ms={} sweep_deadline_ms={} {}",
                    coordination.token,
                    punch_at_ms,
                    hard_hard_now_ms(),
                    punch_at_ms.saturating_sub(hard_hard_now_ms()),
                    HARD_HARD_SWEEP_DEADLINE.as_millis(),
                    hard_hard_measurement_summary(&measurement),
                ),
            )
            .await;
        peers
            .record_direct_event(
                &peer_id,
                "hard_hard_prediction_signaled",
                None,
                Some(candidates.len()),
                None,
                format!(
                    "session_bound=true punch_at_ms={} socket_index={} punch_generation={} local_network_generation={} remote_candidate_epoch={} local_profile_generation={} remote_profile_generation={} local_prediction_confidence={} attempts_bounded={HARD_HARD_SWEEP_ATTEMPTS}",
                    punch_at_ms,
                    primary_socket.socket_index,
                    primary_socket.punch_generation,
                    plan.local_network_generation,
                    plan.remote_candidate_epoch,
                    plan.local_profile_generation,
                    plan.remote_profile_generation,
                    local_confidence,
                ),
            )
            .await;
        // The initiator's exact-socket sweep starts only when the responder's
        // reciprocal prediction arrives.  Relay continues to carry data while
        // this short response fence is pending.
    });
    HardHardInitiatorStart::Started
}

/// Start the responder half after a fresh prediction was admitted by the
/// existing control context and candidate transaction.  The compact `hh1`
/// envelope is an epoch/session fence, not a cryptographic authenticator;
/// Probe v2 MAC/nonce validation and encrypted Direct validation remain the
/// authorities for peer identity and path promotion.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn spawn_hard_hard_responder(
    udp: UdpTransport,
    peers: Arc<PeerManager>,
    punch_deduplicator: PunchAttemptDeduplicator,
    signal: HolePunchSignalContext,
    peer_id: String,
    coordination: HardHardCoordination,
    punch_at_ms: u64,
    remote_prediction: Vec<SocketAddr>,
) -> HardHardRemoteStart {
    let now = hard_hard_now_ms();
    if remote_prediction.is_empty()
        || remote_prediction.len() > HARD_HARD_MAX_BIRTHDAY_TARGETS
        || remote_prediction
            .iter()
            .any(|endpoint| endpoint.ip().is_unspecified())
    {
        peers
            .record_direct_event(
                &peer_id,
                "hard_hard_session_rejected",
                remote_prediction.first().copied(),
                Some(remote_prediction.len()),
                None,
                "Hard↔Hard offer carried an empty, oversized, or unspecified prediction window; no fallback punch started",
            )
            .await;
        return HardHardRemoteStart::Rejected;
    }
    match hard_hard_punch_window(now, punch_at_ms) {
        HardHardPunchWindow::TooSoon => {
            peers
                .record_direct_event(
                    &peer_id,
                    "hard_hard_late_offer",
                    remote_prediction.first().copied(),
                    Some(remote_prediction.len()),
                    None,
                    "Hard↔Hard canonical window is too close for local measurement; continuing with the admitted ordinary fresh punch",
                )
                .await;
            return HardHardRemoteStart::NotStarted;
        }
        HardHardPunchWindow::BeyondFreshLifetime => {
            peers
                .record_direct_event(
                    &peer_id,
                    "hard_hard_session_rejected",
                    remote_prediction.first().copied(),
                    Some(remote_prediction.len()),
                    None,
                    "Hard↔Hard canonical window exceeds the fresh-candidate lifetime; no stale prediction fallback started",
                )
                .await;
            return HardHardRemoteStart::Rejected;
        }
        HardHardPunchWindow::Usable => {}
    }
    if signal.boot_epoch_ms == 0 || signal.stun_servers.len() < 3 {
        peers
            .record_direct_event(
                &peer_id,
                "hard_hard_skipped",
                remote_prediction.first().copied(),
                Some(remote_prediction.len()),
                None,
                "Hard↔Hard responder lacks a trustworthy boot epoch or three STUN observers; continuing with ordinary fresh punching",
            )
            .await;
        return HardHardRemoteStart::NotStarted;
    }
    let Some(plan) = peers.hard_hard_plan_for_peer(&peer_id).await else {
        return HardHardRemoteStart::NotStarted;
    };
    peers
        .record_direct_event(
            &peer_id,
            "hard_hard_plan_selected",
            None,
            Some(remote_prediction.len()),
            None,
            format!(
                "role=responder network_generation={} remote_candidate_epoch={} local_profile_generation={} remote_profile_generation={} punch_at_ms={}",
                plan.local_network_generation,
                plan.remote_candidate_epoch,
                plan.local_profile_generation,
                plan.remote_profile_generation,
                punch_at_ms,
            ),
        )
        .await;
    if coordination.role != HardHardRole::Initiator
        || coordination.remote_network_generation != 0
        || coordination.local_profile_generation != plan.remote_profile_generation
        || coordination.remote_profile_generation != plan.local_profile_generation
        || coordination.local_prediction_confidence == 0
    {
        peers
            .record_direct_event(
                &peer_id,
                "hard_hard_session_fenced",
                None,
                None,
                None,
                "Hard↔Hard offer profile/session generations did not match the current planner snapshot",
            )
            .await;
        return HardHardRemoteStart::Rejected;
    }
    let RecoveryAdmission::Accepted { epoch } = peers.recovery_epoch_admit(&peer_id).await else {
        return HardHardRemoteStart::NotStarted;
    };
    let Some(peer_session_generation) = peers.peer_session_generation_sync(&peer_id) else {
        return HardHardRemoteStart::NotStarted;
    };
    let Some((session, recovery_identity)) = claim_hard_hard_responder_session(
        &peers,
        &punch_deduplicator,
        &peer_id,
        peer_session_generation,
        plan,
        epoch,
        punch_at_ms,
    )
    .await
    else {
        return HardHardRemoteStart::NotStarted;
    };
    let cancellation = session.cancellation_handle();
    let session_id = coordination.encode();
    tokio::spawn(async move {
        let mut pending_session_cancellation =
            PendingHardHardSessionCancellation::new(cancellation.clone());
        let Some(mut measurement) = run_hard_hard_local_measurement(
            &udp,
            &peers,
            &peer_id,
            &signal.stun_servers,
            signal.stun_timeout,
            &coordination.token,
            Some(&cancellation),
        )
        .await else {
            peers
                .record_direct_event(
                    &peer_id,
                    "hard_hard_measurement_failed",
                    None,
                    None,
                    None,
                    "Hard↔Hard responder measurement/model failed; Relay remains usable",
                )
                .await;
            return;
        };
        #[cfg(test)]
        let _measurement_gate_completion =
            pause_hard_hard_responder_after_measurement_for_test().await;
        let Some(current_plan) = peers.hard_hard_plan_for_peer(&peer_id).await else {
            return;
        };
        if cancellation.is_cancelled()
            || !peers.peer_session_is_current_sync(&peer_id, peer_session_generation)
            || peers.is_direct(&peer_id).await
            || !hard_hard_plan_matches(current_plan, plan)
        {
            peers
                .record_direct_event(
                    &peer_id,
                    "hard_hard_measurement_fenced",
                    None,
                    None,
                    None,
                    "Hard↔Hard responder measurement crossed a generation/profile fence",
                )
                .await;
            return;
        }
        let Some(HardHardMeasurementPayload {
            candidates,
            candidate_sources,
            local_confidence,
            local_model,
            candidate_contract,
        }) = hard_hard_measurement_payload(&measurement, signal.boot_epoch_ms)
        else {
            return;
        };
        let Some(primary_socket) = hard_hard_measurement_primary_socket(
            &peer_id,
            &coordination.token,
            &measurement,
            current_plan,
        ) else {
            return;
        };
        peers
            .record_direct_event(
                &peer_id,
                "hard_hard_local_nat_model",
                None,
                Some(candidates.len()),
                None,
                format!(
                    "role=responder token={} model={} confidence={} {}",
                    coordination.token,
                    local_model,
                    local_confidence,
                    hard_hard_measurement_summary(&measurement),
                ),
            )
            .await;
        peers
            .record_direct_event(
                &peer_id,
                "hard_hard_remote_nat_model",
                None,
                Some(remote_prediction.len()),
                None,
                format!(
                    "role=responder token={} model={} confidence={}",
                    coordination.token,
                    coordination.local_prediction_model,
                    coordination.local_prediction_confidence,
                ),
            )
            .await;
        let response_coordination = coordination.as_response(
            current_plan,
            local_confidence,
            local_model,
        );
        let prediction_window = hard_hard_prediction_targets(
            &candidates,
            hard_hard_measurement_target_limit(&measurement),
        );
        if prediction_window.is_empty() {
            return;
        }
        let requested_birthday_level = hard_hard_measurement_requested_level(&measurement);
        let birthday = hard_hard_measurement_is_birthday(&measurement);
        let requested_socket_indices = hard_hard_measurement_socket_indices(&measurement);
        let probe_session_id = peers.probe_session_id_for_peer(&peer_id).await;
        let record = HardHardSessionRecord {
            session_id: session_id.clone(),
            probe_session_id: probe_session_id.clone(),
            session_token: coordination.token.clone(),
            peer_id: peer_id.clone(),
            initiator: false,
            remote_network_generation: coordination.local_network_generation,
            local_network_generation: current_plan.local_network_generation,
            remote_candidate_epoch: current_plan.remote_candidate_epoch,
            local_profile_generation: current_plan.local_profile_generation,
            remote_profile_generation: current_plan.remote_profile_generation,
            local_prediction_confidence: local_confidence,
            remote_prediction_confidence: coordination.local_prediction_confidence,
            requested_birthday_level,
            generated_candidate_count: candidate_contract.generated_candidate_count,
            signaled_candidate_count: candidate_contract.signaled_candidate_count,
            birthday,
            requested_socket_count:
                hard_hard_measurement_requested_socket_count(&measurement),
            requested_socket_indices,
            prediction_window,
            remote_prediction: remote_prediction.clone(),
            fresh_socket: primary_socket.clone(),
            punch_at_ms,
            expires_at_ms: hard_hard_now_ms()
                .saturating_add(HARD_HARD_SESSION_TTL.as_millis() as u64),
            state: HardHardSessionState::AwaitingPeer,
            attempt_count: 0,
            created_at: Instant::now(),
            cancellation: cancellation.clone(),
        };
        let cleanup_descriptor = HardHardCleanupDescriptor::from_record(&record);
        let registered = !cancellation.is_cancelled()
            && peers.peer_session_is_current_sync(&peer_id, peer_session_generation)
            && peers.hard_hard_register_session(record).await;
        if !registered {
            return;
        }
        let cleanup_owner = session.clone_for_cleanup();
        let _cleanup_completion = spawn_hard_hard_session_cleanup_with_owner(
            udp.clone(),
            peers.clone(),
            cleanup_descriptor.clone(),
            Some(cleanup_owner),
        );
        // The registered ledger record and its cleanup owner now cover the
        // exact cancellation path. Before this handoff, dropping the
        // responder task must cancel the shared handle so the provisional
        // measurement guard cannot outlive a pre-ledger return.
        pending_session_cancellation.disarm();
        if cancellation.is_cancelled()
            || !peers.peer_session_is_current_sync(&peer_id, peer_session_generation)
        {
            let _ = peers
                .hard_hard_retire_session(
                    &cleanup_descriptor.peer_id,
                    &cleanup_descriptor.session_id,
                    &cleanup_descriptor.session_token,
                )
                .await;
            return;
        }
        peers
            .record_direct_event(
                &peer_id,
                "hard_hard_session_started",
                None,
                Some(candidates.len()),
                None,
                format!(
                    "role=responder token={} network_generation={} remote_candidate_epoch={} local_profile_generation={} remote_profile_generation={} punch_at_ms={} local_clock_ms={}",
                    coordination.token,
                    current_plan.local_network_generation,
                    current_plan.remote_candidate_epoch,
                    current_plan.local_profile_generation,
                    current_plan.remote_profile_generation,
                    punch_at_ms,
                    hard_hard_now_ms(),
                ),
            )
            .await;
        let sent = if !cancellation.is_cancelled()
            && peers.peer_session_is_current_sync(&peer_id, peer_session_generation)
            && peers
                .try_consume_recovery_http_quota_for_identity(&peer_id, recovery_identity)
                .await
            && !cancellation.is_cancelled()
            && peers.peer_session_is_current_sync(&peer_id, peer_session_generation)
        {
            matches!(
                signal
                    .control
                    .send_fresh_peer_offer_with_session_and_punch_at(
                        &peer_id,
                        &candidates,
                        &candidate_sources,
                        &[],
                        Some(punch_at_ms),
                        Some(response_coordination.encode()),
                        cancellation.clone(),
                    )
                    .await,
                Ok(())
            )
        } else {
            false
        };
        record_hard_hard_candidate_contract(&peers, &peer_id, candidate_contract, sent).await;
        if !sent
            || cancellation.is_cancelled()
            || !peers.peer_session_is_current_sync(&peer_id, peer_session_generation)
        {
            peers
                .record_direct_event(
                    &peer_id,
                    "hard_hard_advertisement_failed",
                    None,
                    Some(candidates.len()),
                    None,
                    "Hard↔Hard responder could not advertise its reciprocal prediction; Relay remains usable",
                )
                .await;
            let _ = peers
                .hard_hard_retire_session(
                    &cleanup_descriptor.peer_id,
                    &cleanup_descriptor.session_id,
                    &cleanup_descriptor.session_token,
                )
                .await;
            return;
        }
        if !finalize_hard_hard_measurement(&mut measurement).await {
            peers
                .record_direct_event(
                    &peer_id,
                    "hard_hard_handoff_failed",
                    None,
                    Some(candidates.len()),
                    None,
                    "Hard↔Hard responder prediction reached the control plane but one or more measured sockets lost ownership before handoff",
                )
                .await;
            let _ = peers
                .hard_hard_retire_session(
                    &cleanup_descriptor.peer_id,
                    &cleanup_descriptor.session_id,
                    &cleanup_descriptor.session_token,
                )
                .await;
            return;
        }
        peers
            .record_direct_event(
                &peer_id,
                "hard_hard_rendezvous_scheduled",
                None,
                Some(candidates.len()),
                None,
                format!(
                    "role=responder token={} punch_at_ms={} local_clock_ms={} lead_ms={} sweep_deadline_ms={} {}",
                    coordination.token,
                    punch_at_ms,
                    hard_hard_now_ms(),
                    punch_at_ms.saturating_sub(hard_hard_now_ms()),
                    HARD_HARD_SWEEP_DEADLINE.as_millis(),
                    hard_hard_measurement_summary(&measurement),
                ),
            )
            .await;
        let fresh_socket = primary_socket;
        let birthday_socket_indices = birthday
            .then(|| hard_hard_measurement_socket_indices(&measurement));
        let cleanup_udp = udp.clone();
        let swept = hard_hard_wait_and_sweep(
            udp,
            peers.clone(),
            session,
            peer_id.clone(),
            peer_session_generation,
            fresh_socket.clone(),
            birthday_socket_indices,
            coordination.token.clone(),
            remote_prediction,
            requested_birthday_level,
            candidate_contract.generated_candidate_count,
            candidate_contract.signaled_candidate_count,
            punch_at_ms,
            current_plan.local_network_generation,
            (
                current_plan.local_profile_generation,
                current_plan.remote_profile_generation,
            ),
            probe_session_id,
            "responder",
        )
        .await;
        let confirmed_socket = peers
            .hard_hard_fresh_socket_for_token(&peer_id, &coordination.token)
            .await
            .unwrap_or_else(|| fresh_socket.clone());
        let direct_on_fresh_socket = hard_hard_exact_direct_confirmation_is_current(
            &cleanup_udp,
            &peers,
            &confirmed_socket,
        )
        .await;
        if swept {
            if !direct_on_fresh_socket && peers.is_direct(&peer_id).await {
                peers
                    .record_direct_event(
                        &peer_id,
                        "hard_hard_superseded_by_other_direct",
                        None,
                        None,
                        None,
                        format!(
                            "peer became Direct on another socket; detached Hard↔Hard socket index={} exact_socket=false",
                            confirmed_socket.socket_index
                        ),
                    )
                    .await;
                let _ = peers
                    .hard_hard_retire_session(
                        &cleanup_descriptor.peer_id,
                        &cleanup_descriptor.session_id,
                        &cleanup_descriptor.session_token,
                    )
                    .await;
            }
        } else {
            let authenticated_winner =
                hard_hard_authenticated_winner_for_cleanup(
                    &cleanup_udp,
                    &peers,
                    &peer_id,
                    &coordination.token,
                )
                .await;
            let retained_socket = if authenticated_winner.is_some() {
                authenticated_winner
            } else if hard_hard_authenticated_socket_for_cleanup(
                &cleanup_udp,
                &peers,
                &fresh_socket,
            )
            .await
            {
                Some(fresh_socket.clone())
            } else {
                direct_on_fresh_socket.then_some(fresh_socket.clone())
            };
            if retained_socket.is_none() {
                if peers.is_direct(&peer_id).await {
                    peers
                        .record_direct_event(
                            &peer_id,
                            "hard_hard_superseded_by_other_direct",
                            None,
                            None,
                            None,
                            format!(
                                "peer became Direct on another socket after the sweep failed; detached all Hard↔Hard sockets; socket index={} exact_socket=false",
                                fresh_socket.socket_index
                            ),
                        )
                        .await;
                }
                let _ = peers
                    .hard_hard_retire_session(
                        &cleanup_descriptor.peer_id,
                        &cleanup_descriptor.session_id,
                        &cleanup_descriptor.session_token,
                    )
                    .await;
            }
        }
    });
    HardHardRemoteStart::Started
}

/// Consume the reciprocal response at the initiator and sweep its measured
/// socket toward the responder's fresh prediction window.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn spawn_hard_hard_initiator_response(
    udp: UdpTransport,
    peers: Arc<PeerManager>,
    punch_deduplicator: PunchAttemptDeduplicator,
    peer_id: String,
    coordination: HardHardCoordination,
    remote_prediction: Vec<SocketAddr>,
    punch_at_ms: u64,
) -> HardHardRemoteStart {
    if coordination.role != HardHardRole::Responder {
        return HardHardRemoteStart::Rejected;
    }
    let Some(record) = peers
        .hard_hard_session_by_token(&peer_id, &coordination.token)
        .await
    else {
        return HardHardRemoteStart::Rejected;
    };
    let Some(current_plan) = peers.hard_hard_plan_for_peer(&peer_id).await else {
        return HardHardRemoteStart::NotStarted;
    };
    let expected_plan = crate::peer::HardHardPlanSnapshot {
        local_network_generation: record.local_network_generation,
        remote_candidate_epoch: record.remote_candidate_epoch,
        local_profile_generation: record.local_profile_generation,
        remote_profile_generation: record.remote_profile_generation,
    };
    if !record.initiator
        || record.state != HardHardSessionState::AwaitingPeer
        || record.attempt_count >= 1
        || record.local_network_generation != peers.current_network_generation_sync()
        || !hard_hard_plan_matches(current_plan, expected_plan)
        || coordination.local_profile_generation != record.remote_profile_generation
        || coordination.remote_profile_generation != record.local_profile_generation
        || coordination.local_prediction_confidence == 0
        || coordination.remote_prediction_confidence != record.local_prediction_confidence
        || coordination.remote_network_generation != record.local_network_generation
        || punch_at_ms != record.punch_at_ms
        || record.fresh_socket.punch_generation == 0
        || punch_at_ms.saturating_add(HARD_HARD_SWEEP_DEADLINE.as_millis() as u64)
            < hard_hard_now_ms()
    {
        peers
            .record_direct_event(
                &peer_id,
                "hard_hard_response_fenced",
                remote_prediction.first().copied(),
                Some(remote_prediction.len()),
                None,
                "Hard↔Hard reciprocal response failed session/profile/time fencing; no stale ACK can promote Direct",
            )
            .await;
        return HardHardRemoteStart::Rejected;
    }
    let current_epoch = peers
        .current_remote_candidate_epoch(&peer_id)
        .await
        .unwrap_or_default();
    // `hard_hard_prepare_response` already admitted and rebound the one
    // expected reciprocal candidate transition. Any later transition means
    // this worker raced a newer candidate session and must be rejected.
    if current_epoch != record.remote_candidate_epoch {
        peers
            .record_direct_event(
                &peer_id,
                "hard_hard_response_fenced",
                remote_prediction.first().copied(),
                Some(remote_prediction.len()),
                None,
                format!(
                    "Hard↔Hard reciprocal response remote_candidate_epoch={} expected {}",
                    current_epoch, record.remote_candidate_epoch
                ),
            )
            .await;
        return HardHardRemoteStart::Rejected;
    }
    if remote_prediction.is_empty() || remote_prediction.len() > HARD_HARD_MAX_BIRTHDAY_TARGETS {
        return HardHardRemoteStart::Rejected;
    }
    let RecoveryAdmission::Accepted { epoch } = peers.recovery_epoch_admit(&peer_id).await else {
        return HardHardRemoteStart::NotStarted;
    };
    let Some(peer_session_generation) = peers.peer_session_generation_sync(&peer_id) else {
        return HardHardRemoteStart::NotStarted;
    };
    let Some(session) = claim_hard_hard_initiator_response_session(
        &peers,
        &punch_deduplicator,
        &peer_id,
        peer_session_generation,
        expected_plan,
        &record,
        epoch,
    )
    .await
    else {
        return HardHardRemoteStart::NotStarted;
    };
    let Some(record) = peers
        .hard_hard_begin_sweep(
            &peer_id,
            &coordination.token,
            remote_prediction.clone(),
            coordination.local_prediction_confidence,
            coordination.local_network_generation,
        )
        .await
    else {
        return HardHardRemoteStart::NotStarted;
    };
    if !udp
        .hard_hard_socket_identity_is_current(&record.fresh_socket)
        .await
        || session.is_cancelled()
        || !peers.peer_session_is_current_sync(&peer_id, peer_session_generation)
    {
        let _ = peers
            .hard_hard_retire_session(
                &record.peer_id,
                &record.session_id,
                &record.session_token,
            )
            .await;
        return HardHardRemoteStart::NotStarted;
    }
    let fresh_socket = record.fresh_socket.clone();
    let birthday_socket_indices = record
        .birthday
        .then(|| record.requested_socket_indices.clone());
    let cleanup_udp = udp.clone();
    let swept = hard_hard_wait_and_sweep(
        udp,
        peers.clone(),
        session,
        peer_id.clone(),
        peer_session_generation,
        fresh_socket.clone(),
        birthday_socket_indices,
        record.session_token.clone(),
        remote_prediction,
        record
            .requested_birthday_level,
        record.generated_candidate_count,
        record.signaled_candidate_count,
        punch_at_ms,
        record.local_network_generation,
        (
            record.local_profile_generation,
            record.remote_profile_generation,
        ),
        record.probe_session_id.clone(),
        "initiator",
    )
    .await;
    let direct_on_fresh_socket =
        hard_hard_exact_direct_confirmation_is_current(&cleanup_udp, &peers, &fresh_socket).await;
    if swept {
        if !direct_on_fresh_socket && peers.is_direct(&peer_id).await {
            peers
                .record_direct_event(
                    &peer_id,
                    "hard_hard_superseded_by_other_direct",
                    None,
                    None,
                    None,
                    format!(
                        "peer became Direct on another socket; detached Hard↔Hard socket index={} exact_socket=false",
                        fresh_socket.socket_index
                    ),
                )
                .await;
            peers
                .hard_hard_retire_session(
                    &record.peer_id,
                    &record.session_id,
                    &record.session_token,
                )
                .await;
        }
    } else {
        let authenticated_winner =
            hard_hard_authenticated_winner_for_cleanup(
                &cleanup_udp,
                &peers,
                &peer_id,
                &record.session_token,
            )
            .await;
        let retained_socket = if authenticated_winner.is_some() {
            authenticated_winner
        } else if hard_hard_authenticated_socket_for_cleanup(&cleanup_udp, &peers, &fresh_socket)
            .await
        {
            Some(fresh_socket.clone())
        } else {
            direct_on_fresh_socket.then_some(fresh_socket.clone())
        };
        if retained_socket.is_none() {
            if peers.is_direct(&peer_id).await {
                peers
                    .record_direct_event(
                        &peer_id,
                        "hard_hard_superseded_by_other_direct",
                        None,
                        None,
                        None,
                        format!(
                            "peer became Direct on another socket after the sweep failed; detached all Hard↔Hard sockets; socket index={} exact_socket=false",
                            fresh_socket.socket_index
                        ),
                    )
                    .await;
            }
            peers
                .hard_hard_retire_session(
                    &record.peer_id,
                    &record.session_id,
                    &record.session_token,
                )
                .await;
        }
    }
    HardHardRemoteStart::Started
}

#[allow(clippy::too_many_arguments)]
async fn hard_hard_wait_and_sweep(
    udp: UdpTransport,
    peers: Arc<PeerManager>,
    session: PunchSessionPermit,
    peer_id: String,
    peer_session_generation: crate::peer::PeerSessionGeneration,
    fresh_socket: crate::peer::HardHardFreshSocketIdentity,
    birthday_socket_indices: Option<Vec<usize>>,
    session_token: String,
    targets: Vec<SocketAddr>,
    requested_level: usize,
    generated_candidate_count: usize,
    signaled_candidate_count: usize,
    punch_at_ms: u64,
    network_generation: u64,
    profile_generations: (u64, u64),
    probe_session_id: Option<String>,
    origin: &'static str,
) -> bool {
    let socket_index = fresh_socket.socket_index;
    let birthday_waves_planned = birthday_socket_indices.as_ref().map_or(1, |indices| {
        hard_hard_birthday_wave_count(indices.len())
    });
    let birthday_progress = birthday_socket_indices.as_ref().map(|_| {
        Arc::new(tokio::sync::Mutex::new(BirthdaySweepProgress {
            birthday: BirthdaySweepReport {
                requested_level,
                generated_candidate_count,
                signaled_candidate_count,
                effective_target_count: targets.len().min(crate::MAX_SIGNAL_CANDIDATES),
                requested_socket_count: hard_hard_birthday_socket_count(requested_level),
                ..BirthdaySweepReport::default()
            },
            aggregate: PunchSendReport::default(),
            ..BirthdaySweepProgress::default()
        }))
    });
    let delay = punch_at_ms.saturating_sub(hard_hard_now_ms());
    if delay > 0 {
        tokio::select! {
            _ = sleep(Duration::from_millis(delay)) => {}
            _ = session.cancelled() => return false,
        }
    }
    if peers.is_direct_sync(&peer_id)
        || peers.current_network_generation_sync() != network_generation
        || (birthday_socket_indices.is_none()
            && !udp
                .hard_hard_socket_identity_is_current(&fresh_socket)
                .await)
        || session.is_cancelled()
        || !peers.peer_session_is_current_sync(&peer_id, peer_session_generation)
    {
        return false;
    }
    // Capture receive/commit baselines before the lifecycle marker. The
    // marker is intentionally nonblocking, and no diagnostics-map write is
    // allowed to sit in front of the first scheduled UDP send.
    let direct_commit_seq = peers.direct_commit_seq_sync(&peer_id);
    let probe_rx_before = udp
        .probe_rx_snapshot_for_peer_session(
            &peer_id,
            network_generation,
            probe_session_id.as_deref(),
        )
        .await;
    let dispatch_at_ms = session.mark_first_send_started();
    peers
        .record_direct_event(
            &peer_id,
            "hard_hard_sweep_started",
            targets.first().copied(),
            Some(targets.len()),
            None,
            format!(
                "origin={origin} mode={} socket_count={} target_count={} attempt={} waves_planned={} punch_at_ms={} local_clock_ms={} sweep_deadline_ms={}",
                if birthday_socket_indices.is_some() { "birthday" } else { "predictable" },
                birthday_socket_indices.as_ref().map_or(1, Vec::len),
                targets.len(),
                if birthday_socket_indices.is_some() { 1 } else { HARD_HARD_SWEEP_ATTEMPTS },
                birthday_waves_planned,
                punch_at_ms,
                hard_hard_now_ms(),
                HARD_HARD_SWEEP_DEADLINE.as_millis(),
            ),
        )
        .await;
    let mut report = None;
    let birthday_progress_for_work = birthday_progress.clone();
    let outcome = run_owned_punch_session_with_deadline(&session, HARD_HARD_SWEEP_DEADLINE, async {
        report = Some(if let Some(socket_indices) = birthday_socket_indices.clone() {
            udp.punch_hard_hard_birthday_candidates_with_metadata(
                &peer_id,
                socket_indices,
                targets.clone(),
                requested_level,
                generated_candidate_count,
                signaled_candidate_count,
                peer_session_generation,
                profile_generations,
                &session_token,
                birthday_progress_for_work,
            )
            .await
        } else {
            udp.punch_candidates_from_dynamic_socket_index_with_profile_fence_and_session(
                &peer_id,
                socket_index,
                targets.clone(),
                HARD_HARD_SWEEP_INTERVAL,
                HARD_HARD_SWEEP_ATTEMPTS,
                Some(profile_generations),
                Some(&session_token),
            )
            .await
        });
    })
    .await;
    let probe_rx_after = udp
        .probe_rx_snapshot_for_peer_session(
            &peer_id,
            network_generation,
            probe_session_id.as_deref(),
        )
        .await;
    let probe_rx_delta = probe_rx_after.delta_since(probe_rx_before);
    match (outcome, report) {
        (PunchSessionOutcome::Completed, Some(Ok(mut report))) => {
            let worker_failure_reason = report
                .failure_kind
                .map(BirthdaySweepFailureKind::stop_reason)
                .or_else(|| {
                    report.birthday.as_ref().and_then(|birthday| match birthday
                        .stop_reason
                        .as_deref()
                    {
                        Some(reason) if BirthdaySweepFailureKind::from_stop_reason(reason).is_some() => {
                            Some(reason)
                        }
                        _ => None,
                    })
                });
            let worker_failed = worker_failure_reason.is_some();
            let confirmation_identity = if birthday_socket_indices.is_some() {
                peers
                    .hard_hard_fresh_socket_for_token(&peer_id, &session_token)
                    .await
                    .unwrap_or_else(|| fresh_socket.clone())
            } else {
                fresh_socket.clone()
            };
            let authenticated_winner_evidence = udp
                .hard_hard_socket_identity_has_authenticated_evidence(&confirmation_identity)
                .await;
            let authenticated_winner_selected = peers
                .hard_hard_winner_for_token(&peer_id, &session_token)
                .await
                .is_some_and(|winner| winner == confirmation_identity.socket_index);
            // An authenticated exact-socket Probe can select the winner while
            // the local worker is still before its first send.  A zero local
            // send is not proof of failure when that evidence already exists;
            // the bounded confirmation below still requires the authoritative
            // Direct commit, selected pair, and every session fence.
            let direct_confirmed = if worker_failed
                || (report.packets_sent == 0
                    && !authenticated_winner_evidence
                    && !authenticated_winner_selected)
            {
                false
            } else {
                peers
                    .record_direct_event(
                        &peer_id,
                        "hard_hard_direct_validation_started",
                        targets.first().copied(),
                        Some(targets.len()),
                        Some(report.packets_sent),
                        format!(
                            "origin={origin} socket_index={} local_endpoint={} grace_ms={} local_clock_ms={}",
                            confirmation_identity.socket_index,
                            confirmation_identity.socket_local_endpoint,
                            HARD_HARD_DIRECT_CONFIRMATION_GRACE.as_millis(),
                            hard_hard_now_ms(),
                        ),
                    )
                    .await;
                let confirmed = tokio::time::timeout(
                    HARD_HARD_DIRECT_CONFIRMATION_GRACE + Duration::from_millis(250),
                    hard_hard_wait_for_exact_direct_confirmation(
                        &udp,
                        &peers,
                        &session,
                        &confirmation_identity,
                        direct_commit_seq,
                    ),
                )
                .await
                .unwrap_or(false);
                confirmed
            };
            let session_stop_reason = if let Some(reason) = worker_failure_reason {
                Some(reason.to_string())
            } else if direct_confirmed {
                None
            } else {
                Some("no_authenticated_direct_confirmation".to_string())
            };
            if let (Some(reason), Some(birthday)) =
                (session_stop_reason.as_deref(), report.birthday.as_mut())
            {
                birthday.stop_reason = Some(reason.to_string());
            }
            let mut per_socket_counts = report.per_socket_sent.clone();
            per_socket_counts.sort_by_key(|(socket_index, _)| *socket_index);
            let per_socket_sent = per_socket_counts
                .iter()
                .map(|(socket_index, sent)| format!("{socket_index}:{sent}"))
                .collect::<Vec<_>>()
                .join(",");
            let birthday_detail = birthday_sweep_detail(&report);
            peers
                .record_direct_event_for_generation_with_socket(
                    &peer_id,
                    network_generation,
                    "hard_hard_probe_summary",
                    targets.first().copied(),
                    Some(socket_index),
                    Some(report.unique_target_endpoints as usize),
                    Some(report.logical_probes_sent.max(report.packets_sent)),
                    format!(
                        "origin={origin} mode={} sent={} logical_probes_attempted={} logical_probes_sent={} logical_probe_send_failures={} physical_datagrams_sent={} physical_send_errors={} partial_physical_send_errors={} probe_path_errors={} targets_assigned={} targets_examined={} targets_attempted={} targets_cancelled={} received={} matched_ack={} authenticated_rx={} authenticated_ack_unmatched={} target_count={} unique_targets={} budget_skipped={} first_send_at_ms={:?} last_send_at_ms={:?} per_socket_sent={}{}",
                        if birthday_detail.is_some() { "birthday" } else { "predictable" },
                        report.packets_sent,
                        report.logical_probes_attempted,
                        report.logical_probes_sent.max(report.packets_sent),
                        report.logical_probe_send_failures,
                        report.physical_datagrams_sent,
                        report.physical_send_errors,
                        report.partial_physical_send_errors,
                        report.probe_path_errors,
                        report.targets_assigned,
                        report.targets_examined,
                        report.targets_attempted,
                        report.targets_cancelled,
                        probe_rx_delta.known_peer_ip_datagrams_received,
                        probe_rx_delta.probe_acks_received,
                        probe_rx_delta.authenticated_probe_packets_received,
                        probe_rx_delta.authenticated_probe_acks_unmatched,
                        targets.len(),
                        report.unique_target_endpoints,
                        report.budget_skipped,
                        report.first_send_at_ms,
                        report.last_send_at_ms,
                        per_socket_sent,
                        birthday_detail
                            .as_deref()
                            .map(|detail| format!(" {detail}"))
                            .unwrap_or_default(),
                    ),
                )
                .await;
            record_hard_hard_birthday_sweep_summary(
                &peers,
                &peer_id,
                network_generation,
                socket_index,
                targets.first().copied(),
                report.unique_target_endpoints as usize,
                report.packets_sent,
                origin,
                &report,
                probe_rx_delta,
            )
            .await;
            if direct_confirmed {
                peers
                    .record_direct_event(
                        &peer_id,
                        "hard_hard_direct_confirmed",
                        targets.first().copied(),
                        Some(targets.len()),
                        Some(report.packets_sent),
                        format!(
                            "origin={origin} socket_index={} local_clock_ms={} exact_socket=true",
                            socket_index,
                            hard_hard_now_ms(),
                        ),
                    )
                    .await;
                peers
                    .record_direct_event_for_generation_with_socket(
                        &peer_id,
                        network_generation,
                        "hard_hard_sweep_completed",
                        targets.first().copied(),
                        Some(socket_index),
                        Some(targets.len()),
                        Some(report.packets_sent),
                        format!(
                            "origin={origin} dispatch_at_ms={dispatch_at_ms} actual_first_send_at_ms={:?} punch_at_ms={} unique_targets={} budget_skipped={} exact_socket=true direct_confirmed=true",
                            report.first_send_at_ms,
                            punch_at_ms,
                            report.unique_target_endpoints,
                            report.budget_skipped,
                        ),
                    )
                    .await;
            } else {
                peers
                    .record_direct_event(
                        &peer_id,
                        "hard_hard_sweep_failed",
                        targets.first().copied(),
                        Some(targets.len()),
                        Some(report.packets_sent),
                        format!(
                            "origin={origin} stop_reason={} exact-socket sweep found no authenticated Direct confirmation within {:?}",
                            session_stop_reason.as_deref().unwrap_or("no_authenticated_direct_confirmation"),
                            HARD_HARD_DIRECT_CONFIRMATION_GRACE,
                        ),
                    )
                    .await;
                peers
                    .record_direct_event(
                        &peer_id,
                        "hard_hard_failed",
                        targets.first().copied(),
                        Some(targets.len()),
                        Some(report.packets_sent),
                        format!(
                            "origin={origin} stage=sweep reason={} stop_reason={} budget_used={}",
                            session_stop_reason.as_deref().unwrap_or("no_authenticated_direct_confirmation"),
                            session_stop_reason.as_deref().unwrap_or("no_authenticated_direct_confirmation"),
                            report.packets_sent,
                        ),
                    )
                    .await;
            }
            direct_confirmed
        }
        (PunchSessionOutcome::Completed, Some(Err(_error))) => {
            let partial_report = birthday_terminal_report(&birthday_progress, "send_error").await;
            let stop_reason = partial_report
                .as_ref()
                .and_then(|report| report.birthday.as_ref())
                .and_then(|birthday| birthday.stop_reason.as_deref())
                .unwrap_or("send_error")
                .to_string();
            if let Some(partial_report) = partial_report {
                record_hard_hard_birthday_sweep_summary(
                    &peers,
                    &peer_id,
                    network_generation,
                    socket_index,
                    targets.first().copied(),
                    partial_report.unique_target_endpoints as usize,
                    partial_report.packets_sent,
                    origin,
                    &partial_report,
                    probe_rx_delta,
                )
                .await;
            }
            peers
                    .record_direct_event(
                        &peer_id,
                        "hard_hard_sweep_failed",
                        targets.first().copied(),
                        Some(targets.len()),
                        None,
                        format!(
                            "origin={origin} stop_reason={} exact-socket sweep failed before confirmation",
                            stop_reason.as_str(),
                        ),
                    )
                    .await;
                peers
                    .record_direct_event(
                        &peer_id,
                        "hard_hard_failed",
                        targets.first().copied(),
                        Some(targets.len()),
                        None,
                        format!(
                            "origin={origin} exact-socket sweep error stop_reason={}",
                            stop_reason.as_str(),
                        ),
                    )
                    .await;
            false
        }
        (PunchSessionOutcome::DeadlineExceeded, _) => {
            let partial_report = birthday_terminal_report(&birthday_progress, "deadline").await;
            let stop_reason = partial_report
                .as_ref()
                .and_then(|report| report.birthday.as_ref())
                .and_then(|birthday| birthday.stop_reason.as_deref())
                .unwrap_or("deadline")
                .to_string();
            if let Some(partial_report) = partial_report {
                record_hard_hard_birthday_sweep_summary(
                    &peers,
                    &peer_id,
                    network_generation,
                    socket_index,
                    targets.first().copied(),
                    partial_report.unique_target_endpoints as usize,
                    partial_report.packets_sent,
                    origin,
                    &partial_report,
                    probe_rx_delta,
                )
                .await;
            }
            peers
                    .record_direct_event(
                        &peer_id,
                        "hard_hard_sweep_failed",
                        targets.first().copied(),
                        Some(targets.len()),
                        None,
                        format!(
                            "origin={origin} mode={} requested_level={} effective_target_count={} waves_planned={} stop_reason={} exact-socket sweep deadline elapsed before authenticated Direct confirmation",
                            if birthday_socket_indices.is_some() { "birthday" } else { "predictable" },
                            requested_level,
                            targets.len(),
                            birthday_waves_planned,
                            stop_reason.as_str(),
                        ),
                    )
                    .await;
                peers
                    .record_direct_event(
                        &peer_id,
                        "hard_hard_failed",
                        targets.first().copied(),
                        Some(targets.len()),
                        None,
                        format!(
                            "origin={origin} mode={} stage=sweep reason={} stop_reason={} requested_level={} effective_target_count={} budget_ms={}",
                            if birthday_socket_indices.is_some() { "birthday" } else { "predictable" },
                            stop_reason.as_str(),
                            stop_reason.as_str(),
                            requested_level,
                            targets.len(),
                            HARD_HARD_SWEEP_DEADLINE.as_millis(),
                        ),
                    )
                    .await;
            false
        }
        (PunchSessionOutcome::Cancelled, _) => {
            let cancellation_reason = session
                .cancellation_reason()
                .map(PunchCancellationReason::label)
                .unwrap_or("unknown");
            let partial_report =
                birthday_terminal_report(&birthday_progress, "session_cancelled").await;
            let stop_reason = partial_report
                .as_ref()
                .and_then(|report| report.birthday.as_ref())
                .and_then(|birthday| birthday.stop_reason.as_deref())
                .unwrap_or("session_cancelled")
                .to_string();
            if let Some(partial_report) = partial_report {
                record_hard_hard_birthday_sweep_summary(
                    &peers,
                    &peer_id,
                    network_generation,
                    socket_index,
                    targets.first().copied(),
                    partial_report.unique_target_endpoints as usize,
                    partial_report.packets_sent,
                    origin,
                    &partial_report,
                    probe_rx_delta,
                )
                .await;
            }
            peers
                .record_direct_event(
                    &peer_id,
                    "hard_hard_sweep_failed",
                    targets.first().copied(),
                    Some(targets.len()),
                    None,
                    format!(
                        "origin={origin} mode={} requested_level={} effective_target_count={} waves_planned={} stop_reason={} cancellation_reason={cancellation_reason}",
                        if birthday_socket_indices.is_some() {
                            "birthday"
                        } else {
                            "predictable"
                        },
                        requested_level,
                        targets.len(),
                        birthday_waves_planned,
                        stop_reason.as_str(),
                    ),
                )
                .await;
            peers
                .record_direct_event(
                    &peer_id,
                    "hard_hard_failed",
                    targets.first().copied(),
                    Some(targets.len()),
                    None,
                    format!(
                        "origin={origin} mode={} stage=sweep reason={} stop_reason={} cancellation_reason={cancellation_reason}",
                        if birthday_socket_indices.is_some() {
                            "birthday"
                        } else {
                            "predictable"
                        },
                        stop_reason.as_str(),
                        stop_reason.as_str(),
                    ),
                )
                .await;
            false
        }
        _ => false,
    }
}

fn birthday_sweep_detail(report: &PunchSendReport) -> Option<String> {
    let birthday = report.birthday.as_ref()?;
    let mut per_socket_counts = report.per_socket_sent.clone();
    per_socket_counts.sort_by_key(|(socket_index, _)| *socket_index);
    let per_socket_sent = per_socket_counts
        .iter()
        .map(|(socket_index, sent)| format!("{socket_index}:{sent}"))
        .collect::<Vec<_>>()
        .join(",");
    let physical_datagrams_sent = per_socket_counts
        .iter()
        .map(|(_, sent)| *sent as usize)
        .sum::<usize>();
    Some(format!(
        "requested_level={} generated_candidate_count={} signaled_candidate_count={} effective_target_count={} requested_socket_count={} attached_socket_count={} usable_socket_count={} unavailable_socket_count={} socket_count={} degraded_reason={} waves_planned={} waves_started={} waves_fully_completed={} waves_completed={} targets_assigned={} targets_examined={} targets_attempted={} logical_probes_attempted={} logical_probes_sent={} logical_probe_send_failures={} physical_datagrams_sent={} physical_send_errors={} partial_physical_send_errors={} probe_path_errors={} failure_kind={:?} targets_budget_skipped={} targets_cancelled={} packets_planned={} packets_sent={} unique_target_endpoints={} budget_skipped={} per_socket_sent={} first_send_at_ms={:?} last_send_at_ms={:?} stop_reason={}",
        birthday.requested_level,
        birthday.generated_candidate_count,
        birthday.signaled_candidate_count,
        birthday.effective_target_count,
        birthday.requested_socket_count,
        birthday.attached_socket_count,
        birthday.usable_socket_count,
        birthday.unavailable_socket_count,
        birthday.socket_count,
        birthday.degraded_reason.as_deref().unwrap_or("none"),
        birthday.waves_planned,
        birthday.waves_started,
        birthday.waves_fully_completed,
        birthday.waves_completed,
        birthday.targets_assigned,
        birthday.targets_examined,
        birthday.targets_attempted,
        birthday.logical_probes_attempted,
        birthday.logical_probes_sent,
        birthday.logical_probe_send_failures,
        physical_datagrams_sent,
        birthday.physical_send_errors,
        birthday.partial_physical_send_errors,
        report.probe_path_errors,
        report.failure_kind,
        birthday.targets_budget_skipped,
        birthday.targets_cancelled,
        birthday.packets_planned,
        report.packets_sent,
        report.unique_target_endpoints,
        report.budget_skipped,
        per_socket_sent,
        report.first_send_at_ms,
        report.last_send_at_ms,
        birthday.stop_reason.as_deref().unwrap_or("unknown"),
    ))
}

#[allow(clippy::too_many_arguments)]
async fn record_hard_hard_birthday_sweep_summary(
    peers: &PeerManager,
    peer_id: &str,
    network_generation: u64,
    socket_index: usize,
    target: Option<SocketAddr>,
    unique_target_count: usize,
    packets_sent: u32,
    origin: &str,
    report: &PunchSendReport,
    probe_rx_delta: UdpProbeRxSnapshot,
) {
    let Some(detail) = birthday_sweep_detail(report) else {
        return;
    };
    peers
        .record_direct_event_for_generation_with_socket(
            peer_id,
            network_generation,
            "hard_hard_birthday_sweep_summary",
            target,
            Some(socket_index),
            Some(unique_target_count),
            Some(packets_sent),
            format!(
                "origin={origin} mode=birthday {detail} known_peer_ip_rx_delta={} authenticated_probe_rx_delta={} matched_probe_ack_rx_delta={} authenticated_probe_ack_unmatched_delta={}",
                probe_rx_delta.known_peer_ip_datagrams_received,
                probe_rx_delta.authenticated_probe_packets_received,
                probe_rx_delta.probe_acks_received,
                probe_rx_delta.authenticated_probe_acks_unmatched,
            ),
        )
        .await;
}

async fn birthday_terminal_report(
    progress: &Option<Arc<tokio::sync::Mutex<BirthdaySweepProgress>>>,
    stop_reason: &str,
) -> Option<PunchSendReport> {
    let progress = progress.as_ref()?;
    let (mut report, mut birthday, live) = {
        let current = progress.lock().await;
        (
            current.aggregate.clone(),
            current.birthday.clone(),
            current.live.clone(),
        )
    };
    let live_snapshot = live
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .clone();
    apply_live_birthday_counters(&mut report, &live_snapshot);
    report.unique_target_endpoints =
        u32::try_from(report.sent_target_endpoints.len()).unwrap_or(u32::MAX);
    if birthday.stop_reason.is_none() {
        birthday.stop_reason = Some(
            report
                .failure_kind
                .map(BirthdaySweepFailureKind::stop_reason)
                .unwrap_or(stop_reason)
                .to_string(),
        );
    }
    birthday.waves_completed = birthday.waves_fully_completed;
    report.targets_assigned = report
        .targets_assigned
        .max(u32::try_from(birthday.targets_assigned).unwrap_or(u32::MAX));
    report.targets_cancelled = report.targets_cancelled.max(
        report
            .targets_assigned
            .saturating_sub(report.targets_attempted),
    );
    update_birthday_sweep_counters(&mut birthday, &report);
    report.birthday = Some(birthday);
    Some(report)
}

fn spawn_hard_hard_session_cleanup(
    udp: UdpTransport,
    peers: Arc<PeerManager>,
    descriptor: HardHardCleanupDescriptor,
) -> HardHardCleanupCompletion {
    spawn_hard_hard_session_cleanup_with_owner(udp, peers, descriptor, None)
}

fn spawn_hard_hard_session_cleanup_with_owner(
    udp: UdpTransport,
    peers: Arc<PeerManager>,
    descriptor: HardHardCleanupDescriptor,
    cleanup_owner: Option<PunchSessionPermit>,
) -> HardHardCleanupCompletion {
    let completion = HardHardCleanupCompletion::new();
    let watcher_completion = completion.clone();
    tokio::spawn(async move {
        // Keep the exact punch-dedup record occupied until this cleanup task
        // has completed both the token-scoped UDP cleanup and the ledger
        // removal. This closes the window in which a peer-reflexive worker
        // could otherwise claim a lower-priority ordinary punch after the
        // Hard↔Hard worker released its short-lived permit.
        let _completion_guard = HardHardCleanupCompletionGuard(watcher_completion);
        let _cleanup_owner = cleanup_owner;
        if !peers
            .hard_hard_claim_cleanup_owner(
                &descriptor.peer_id,
                &descriptor.session_id,
                &descriptor.session_token,
            )
            .await
        {
            return;
        }

        let expiry_woke = if descriptor.cancellation.is_cancelled() {
            false
        } else {
            let delay = descriptor
                .expires_at_ms
                .saturating_sub(hard_hard_now_ms());
            tokio::select! {
                biased;
                _ = descriptor.cancellation.cancelled() => false,
                _ = sleep(Duration::from_millis(delay)) => true,
            }
        };
        let snapshot = peers
            .hard_hard_session_snapshot_for_cleanup(
                &descriptor.peer_id,
                &descriptor.session_id,
                &descriptor.session_token,
            )
            .await;
        let current_socket = snapshot
            .as_ref()
            .map(|record| record.fresh_socket.clone())
            .unwrap_or_else(|| descriptor.fresh_socket.clone());
        let retain_fresh_socket = expiry_woke
            && snapshot.as_ref().is_some_and(|record| {
                record.state != crate::peer::HardHardSessionState::Retiring
                    && !record.cancellation.is_cancelled()
            })
            && !descriptor.cancellation.is_cancelled()
            && hard_hard_exact_direct_socket_is_current_for_cleanup(&udp, &peers, &current_socket)
                .await;

        // The ledger is retired before any UDP cleanup await. This is the
        // completion-fence boundary: no admission/fence query can revive the
        // session, while the descriptor and token still own cleanup.
        let _ = peers
            .hard_hard_retire_session(
                &descriptor.peer_id,
                &descriptor.session_id,
                &descriptor.session_token,
            )
            .await;
        #[cfg(test)]
        peers
            .pause_hard_hard_cleanup_for_test(
                &descriptor.peer_id,
                &descriptor.session_id,
                &descriptor.session_token,
            )
            .await;

        if retain_fresh_socket {
            udp.detach_hard_hard_sockets_for_token(
                &descriptor.peer_id,
                &descriptor.session_token,
                Some(current_socket.socket_index),
                "hard_hard_session_expired_losers",
            )
            .await;
        } else {
            udp.detach_hard_hard_sockets_for_token(
                &descriptor.peer_id,
                &descriptor.session_token,
                None,
                "hard_hard_session_expired",
            )
            .await;
            udp.detach_hard_hard_socket_if_identity(&current_socket, "hard_hard_session_expired")
                .await;
            if current_socket != descriptor.fresh_socket {
                udp.detach_hard_hard_socket_if_identity(
                    &descriptor.fresh_socket,
                    "hard_hard_session_expired",
                )
                .await;
            }
        }
        udp.clear_hard_hard_pending_probes_for_token(
            &descriptor.peer_id,
            &descriptor.session_token,
            retain_fresh_socket.then_some(current_socket.socket_index),
        )
        .await;
        let _ = peers
            .hard_hard_complete_session_cleanup(
                &descriptor.peer_id,
                &descriptor.session_id,
                &descriptor.session_token,
            )
            .await;
        #[cfg(test)]
        peers.signal_hard_hard_cleanup_completed_for_test(
            &descriptor.peer_id,
            &descriptor.session_id,
            &descriptor.session_token,
        );
    });
    completion
}

#[cfg(test)]
mod hard_hard_tests {
    use super::*;

    #[test]
    fn birthday_level_caps_android_without_downgrading_desktop() {
        use crate::peer::RecoveryStage;

        assert_eq!(
            hard_hard_birthday_level_for_stage(false, RecoveryStage::Initial),
            64
        );
        assert_eq!(
            hard_hard_birthday_level_for_stage(false, RecoveryStage::ScatterExtended),
            256
        );
        assert_eq!(
            hard_hard_birthday_level_for_stage(true, RecoveryStage::Initial),
            64
        );
        assert_eq!(
            hard_hard_birthday_level_for_stage(true, RecoveryStage::Predicted),
            128
        );
        assert_eq!(
            hard_hard_birthday_level_for_stage(true, RecoveryStage::ScatterExtended),
            128
        );
        assert_eq!(
            hard_hard_birthday_level_for_stage(true, RecoveryStage::RelayBackoff),
            128
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn birthday_runtime_level_cap_tracks_platform_and_recovery_stage() {
        use crate::peer::RecoveryStage;

        for (platform, expected_level) in [("android", 128), ("linux", 256)] {
            let identity = NodeIdentity::generate();
            let mut config = Config::generate_default(
                "https://hard-hard-runtime-cap.test",
                &format!("hard-hard-runtime-cap-{platform}"),
            )
            .unwrap();
            config.node.node_id = format!("hard-hard-runtime-cap-{platform}");
            config.node.platform = platform.to_string();
            let peers = PeerManager::new(config);
            let peer_id = format!("peer-runtime-cap-{platform}");
            peers
                .add_peer(&crate::control::PeerInfo {
                    node_id: peer_id.clone(),
                    device_name: "runtime-cap".to_string(),
                    app_version: "test".to_string(),
                    public_key: hex::encode(identity.public_key()),
                    endpoint: "198.51.100.20:41000".to_string(),
                    nat_type:
                        "p2v2:m=address_or_port_dependent;a=random;d=?;c=90;f=address_or_port_dependent;h=unknown;g=1"
                            .to_string(),
                    virtual_ip: "10.20.0.20".to_string(),
                    online: true,
                    last_seen: 1,
                    relay_rtt_ms: None,
                })
                .await;
            assert!(matches!(
                peers.recovery_epoch_admit(&peer_id).await,
                crate::peer::RecoveryAdmission::Accepted { .. }
            ));
            for _ in 0..3 {
                peers
                    .advance_recovery_stage_after_no_ack(&peer_id, "runtime cap test")
                    .await;
            }
            assert_eq!(
                peers.recovery_stage_for(&peer_id).await,
                RecoveryStage::ScatterExtended
            );
            assert_eq!(hard_hard_birthday_level(&peers, &peer_id).await, expected_level);
        }
    }

    #[test]
    fn initiator_response_match_keeps_raw_birthday_level_after_candidate_cap() {
        let endpoint = "198.51.100.20:41000".parse().unwrap();
        let identity = crate::peer::HardHardFreshSocketIdentity {
            peer_id: "peer-raw-level".to_string(),
            session_token: "raw-level-token".to_string(),
            network_generation: 3,
            remote_candidate_epoch: 5,
            local_profile_generation: 7,
            remote_profile_generation: 11,
            punch_generation: 13,
            socket_index: 4_096,
            socket_local_endpoint: endpoint,
        };
        let expected = HardHardSessionRecord {
            session_id: "hh1:i:raw-level-token:3:5:7:11:90:0:0".to_string(),
            probe_session_id: None,
            session_token: identity.session_token.clone(),
            peer_id: identity.peer_id.clone(),
            initiator: true,
            remote_network_generation: 0,
            local_network_generation: identity.network_generation,
            remote_candidate_epoch: identity.remote_candidate_epoch,
            local_profile_generation: identity.local_profile_generation,
            remote_profile_generation: identity.remote_profile_generation,
            local_prediction_confidence: 90,
            remote_prediction_confidence: 0,
            requested_birthday_level: 128,
            generated_candidate_count: 128,
            signaled_candidate_count: 96,
            birthday: true,
            requested_socket_indices: vec![4_096, 4_097, 4_098, 4_099],
            requested_socket_count: 4,
            prediction_window: vec![endpoint; 96],
            remote_prediction: Vec::new(),
            fresh_socket: identity.clone(),
            punch_at_ms: hard_hard_now_ms().saturating_add(5_000),
            expires_at_ms: hard_hard_now_ms().saturating_add(30_000),
            state: HardHardSessionState::AwaitingPeer,
            attempt_count: 0,
            created_at: Instant::now(),
            cancellation: Arc::new(crate::PunchSessionCancellation::default()),
        };
        assert!(hard_hard_initiator_response_record_matches(&expected, &expected));

        let mut capped_level = expected.clone();
        capped_level.requested_birthday_level = capped_level.signaled_candidate_count;
        assert!(!hard_hard_initiator_response_record_matches(
            &capped_level,
            &expected
        ));

        let mut replaced_socket = expected.clone();
        replaced_socket.requested_socket_indices = vec![4_096, 4_097, 4_098, 5_000];
        assert!(!hard_hard_initiator_response_record_matches(
            &replaced_socket,
            &expected
        ));
    }

    #[tokio::test]
    async fn birthday_terminal_report_preserves_partial_logical_and_physical_progress() {
        let progress = Arc::new(tokio::sync::Mutex::new(BirthdaySweepProgress {
            birthday: BirthdaySweepReport {
                requested_level: 256,
                generated_candidate_count: 256,
                signaled_candidate_count: 96,
                effective_target_count: 96,
                requested_socket_count: 8,
                attached_socket_count: 8,
                usable_socket_count: 8,
                socket_count: 8,
                waves_planned: 2,
                waves_started: 1,
                waves_fully_completed: 0,
                waves_completed: 0,
                targets_assigned: 96,
                ..BirthdaySweepReport::default()
            },
            aggregate: PunchSendReport {
                packets_sent: 2,
                per_socket_sent: vec![(4_096, 3)],
                sent_target_endpoints: vec![endpoint_for_test(41000), endpoint_for_test(41001)],
                targets_assigned: 96,
                targets_attempted: 2,
                targets_cancelled: 94,
                ..PunchSendReport::default()
            },
            ..BirthdaySweepProgress::default()
        }));

        let report = birthday_terminal_report(&Some(progress), "worker_failed")
            .await
            .expect("birthday progress must yield a terminal partial report");
        let birthday = report
            .birthday
            .as_ref()
            .expect("terminal report must retain Birthday details");
        assert_eq!(birthday.requested_level, 256);
        assert_eq!(birthday.signaled_candidate_count, 96);
        assert_eq!(birthday.waves_fully_completed, 0);
        assert_eq!(birthday.waves_completed, 0);
        assert_eq!(birthday.logical_probes_sent, 2);
        assert_eq!(birthday.physical_datagrams_sent, 3);
        assert_eq!(birthday.targets_cancelled, 94);
        assert_eq!(birthday.stop_reason.as_deref(), Some("worker_failed"));
    }

    #[tokio::test]
    async fn birthday_terminal_report_reads_in_flight_live_counters() {
        let progress = Arc::new(tokio::sync::Mutex::new(BirthdaySweepProgress {
            birthday: BirthdaySweepReport {
                targets_assigned: 4,
                waves_planned: 2,
                waves_started: 1,
                ..BirthdaySweepReport::default()
            },
            ..BirthdaySweepProgress::default()
        }));
        {
            let live = {
                let current = progress.lock().await;
                current.live.clone()
            };
            let mut progress = live
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            progress.counters.targets_assigned = 4;
            progress.counters.targets_examined = 3;
            progress.counters.targets_attempted = 1;
            progress.counters.targets_cancelled = 3;
            progress.counters.budget_skipped = 1;
            progress.counters.logical_probes_attempted = 1;
            progress.counters.logical_probes_sent = 1;
            progress.counters.physical_datagrams_sent = 2;
            progress.counters.physical_send_errors = 1;
            progress.sent_target_endpoints.insert(endpoint_for_test(41000));
            progress.per_socket_sent.insert(4_096, 2);
            progress.first_send_at_ms = Some(100);
            progress.last_send_at_ms = Some(110);
        }

        let report = birthday_terminal_report(&Some(progress), "deadline")
            .await
            .expect("live birthday progress must produce a terminal report");
        let birthday = report.birthday.as_ref().unwrap();
        assert_eq!(report.targets_assigned, 4);
        assert_eq!(report.targets_examined, 3);
        assert_eq!(report.targets_attempted, 1);
        assert_eq!(report.logical_probes_attempted, 1);
        assert_eq!(report.logical_probes_sent, 1);
        assert_eq!(report.physical_datagrams_sent, 2);
        assert_eq!(report.physical_send_errors, 1);
        assert_eq!(report.unique_target_endpoints, 1);
        assert_eq!(report.per_socket_sent, vec![(4_096, 2)]);
        assert_eq!(report.first_send_at_ms, Some(100));
        assert_eq!(report.last_send_at_ms, Some(110));
        assert_eq!(birthday.targets_examined, 3);
        assert_eq!(birthday.logical_probes_attempted, 1);
        assert_eq!(birthday.physical_send_errors, 1);
        assert_eq!(birthday.targets_cancelled, 3);
        assert_eq!(birthday.stop_reason.as_deref(), Some("deadline"));
        assert!(report.logical_probes_sent <= report.logical_probes_attempted);
        assert!(report.physical_datagrams_sent >= report.logical_probes_sent);
        assert!(report.targets_attempted <= report.targets_examined);
        assert!(report.targets_examined <= report.targets_assigned);
    }

    #[tokio::test]
    async fn birthday_terminal_report_preserves_scheduler_failure_reason() {
        let progress = Arc::new(tokio::sync::Mutex::new(BirthdaySweepProgress {
            birthday: BirthdaySweepReport {
                stop_reason: Some("worker_failed".to_string()),
                ..BirthdaySweepReport::default()
            },
            aggregate: PunchSendReport {
                failure_kind: Some(BirthdaySweepFailureKind::WorkerJoin),
                worker_failed: true,
                ..PunchSendReport::default()
            },
            ..BirthdaySweepProgress::default()
        }));

        let report = birthday_terminal_report(&Some(progress), "send_error")
            .await
            .expect("scheduler failure must remain observable");
        assert_eq!(
            report.birthday.unwrap().stop_reason.as_deref(),
            Some("worker_failed")
        );
    }

    #[test]
    fn direct_confirmation_grace_is_bounded_after_busy_executor_regression() {
        // The earlier one-second grace was insufficient in the full reciprocal
        // birthday suite when validation and durable event work shared a busy
        // executor. Keep the evidence-backed two-second lease, but retain the
        // explicit outer 250ms bound so this is not an unbounded wait.
        assert_eq!(HARD_HARD_DIRECT_CONFIRMATION_GRACE, Duration::from_secs(2));
        assert!(
            HARD_HARD_DIRECT_CONFIRMATION_GRACE + Duration::from_millis(250)
                <= HARD_HARD_SWEEP_DEADLINE
        );
    }

    #[tokio::test(start_paused = true)]
    async fn direct_confirmation_grace_accepts_an_exact_commit_after_one_second() {
        let _serial = crate::tests::HARD_HARD_E2E_SERIAL.acquire().await.unwrap();
        let (peers, udp, identity, remote) = exact_socket_proof_fixture().await;
        let deduplicator = PunchAttemptDeduplicator::default();
        let session = deduplicator
            .claim("peer-exact-proof")
            .await
            .expect("test must own the confirmation session");
        let wait = tokio::spawn({
            let peers = peers.clone();
            let udp = udp.clone();
            let identity = identity.clone();
            async move {
                hard_hard_wait_for_exact_direct_confirmation(
                    &udp,
                    &peers,
                    &session,
                    &identity,
                    None,
                )
                .await
            }
        });
        tokio::task::yield_now().await;
        assert!(!wait.is_finished(), "confirmation must still be pending");

        tokio::time::advance(Duration::from_secs(1)).await;
        tokio::task::yield_now().await;
        assert!(
            !wait.is_finished(),
            "one second must not exhaust the two-second confirmation grace"
        );

        assert!(
            peers
                .record_direct_success_for_generation_with_local_endpoint(
                    &identity.peer_id,
                    Some(remote),
                    identity.network_generation,
                    Some(identity.socket_local_endpoint),
                )
                .await
        );
        assert!(wait.await.unwrap());
        udp.detach_all_dynamic_punch_sockets("test_confirmation_grace").await;
    }

    #[tokio::test]
    async fn direct_confirmation_start_does_not_wait_for_connection_writer() {
        let _serial = crate::tests::HARD_HARD_E2E_SERIAL.acquire().await.unwrap();
        let (peers, udp, identity, remote) = exact_socket_proof_fixture().await;
        let session = PunchAttemptDeduplicator::default()
            .claim("peer-exact-proof")
            .await
            .expect("test must own the confirmation session");
        let before_commit = peers.direct_commit_seq_sync(&identity.peer_id);
        assert!(
            peers
                .record_direct_success_for_generation_with_local_endpoint(
                    &identity.peer_id,
                    Some(remote),
                    identity.network_generation,
                    Some(identity.socket_local_endpoint),
                )
                .await
        );

        let connection_writer = peers.hold_connections_writer_for_test().await;
        let confirmed = tokio::time::timeout(
            Duration::from_millis(100),
            hard_hard_wait_for_exact_direct_confirmation(
                &udp,
                &peers,
                &session,
                &identity,
                before_commit,
            ),
        )
        .await
        .expect("confirmation must not await the connection writer");
        assert!(confirmed);
        drop(connection_writer);

        peers
            .record_direct_event(
                &identity.peer_id,
                "hard_hard_failed",
                Some(remote),
                Some(1),
                Some(1),
                "lock contention terminal event",
            )
            .await;
        assert!(peers
            .diagnostics()
            .await
            .into_iter()
            .flat_map(|peer| peer.direct_events)
            .any(|event| event.stage == "hard_hard_failed"));
        udp.detach_all_dynamic_punch_sockets("test_confirmation_writer").await;
    }

    #[tokio::test]
    async fn exact_probe_session_diagnostics_survive_connection_writer_contention() {
        let _serial = crate::tests::HARD_HARD_E2E_SERIAL.acquire().await.unwrap();
        let (peers, udp, identity, _remote) = exact_socket_proof_fixture().await;
        udp.update_peer_probe_rx_diagnostics(
            &identity.peer_id,
            identity.network_generation,
            Some("probe-session-exact"),
            |snapshot| {
                snapshot.authenticated_probe_acks_observed = 3;
                snapshot.probe_acks_received = 2;
            },
        )
        .await;

        let connection_writer = peers.hold_connections_writer_for_test().await;
        let snapshot = tokio::time::timeout(
            Duration::from_millis(100),
            udp.probe_rx_snapshot_for_peer_session(
                &identity.peer_id,
                identity.network_generation,
                Some("probe-session-exact"),
            ),
        )
        .await
        .expect("exact session diagnostics must not consult connections");
        drop(connection_writer);
        assert_eq!(snapshot.authenticated_probe_acks_observed, 3);
        assert_eq!(snapshot.probe_acks_received, 2);
        udp.detach_all_dynamic_punch_sockets("test_probe_session_lock").await;
    }

    fn birthday_runtime_nat_profile() -> p2pnet_nat::NatProfile {
        p2pnet_nat::NatProfile {
            local_addr: "127.0.0.1:0".to_string(),
            observations: Vec::new(),
            udp_blocked: false,
            public_endpoint: Some("198.51.100.10:40000".to_string()),
            public_ip_stable: Some(true),
            public_port_stable: Some(false),
            port_preserved: Some(false),
            port_delta: None,
            likely_symmetric: Some(true),
            mapping_behavior: p2pnet_nat::MappingBehavior::AddressOrPortDependent,
            filtering_behavior: p2pnet_nat::FilteringBehavior::AddressOrPortDependent,
            hairpin_behavior: p2pnet_nat::HairpinBehavior::Unknown,
            mapping_lifetime: p2pnet_nat::MappingLifetime::Unknown,
            prediction_candidate: false,
            predicted_endpoints: Vec::new(),
            birthday_candidate: true,
            confidence: 70,
        }
    }

    async fn exact_birthday_runtime_fixture() -> (
        Arc<PeerManager>,
        UdpTransport,
        crate::peer::HardHardFreshSocketIdentity,
        SocketAddr,
        crate::peer::PeerSessionGeneration,
    ) {
        let (peers, udp, mut identity, remote) = exact_socket_proof_fixture().await;
        let mut record = peers
            .hard_hard_session_for_test(&identity.peer_id)
            .await
            .expect("exact fixture must install a session ledger record");

        peers.update_nat_profile(birthday_runtime_nat_profile()).await;
        let local_profile_generation = peers.current_local_profile_generation_sync();
        let session_token = "birthday-runtime-token".to_string();
        identity.session_token = session_token.clone();
        identity.local_profile_generation = local_profile_generation;
        record.session_id = "birthday-runtime-session".to_string();
        record.session_token = session_token.clone();
        record.probe_session_id = Some("probe-session-exact".to_string());
        record.local_profile_generation = local_profile_generation;
        record.requested_birthday_level = 64;
        record.generated_candidate_count = 64;
        record.signaled_candidate_count = 1;
        record.birthday = true;
        record.requested_socket_indices = vec![identity.socket_index, identity.socket_index + 1];
        record.requested_socket_count = 2;
        record.prediction_window = vec![remote];
        record.remote_prediction = vec![remote];
        record.fresh_socket = identity.clone();
        record.punch_at_ms = hard_hard_now_ms();
        record.expires_at_ms = record.punch_at_ms.saturating_add(30_000);
        record.state = crate::peer::HardHardSessionState::AwaitingPeer;
        record.attempt_count = 0;
        record.cancellation = Arc::new(crate::PunchSessionCancellation::default());
        assert!(peers.hard_hard_register_session(record).await);
        assert!(
            udp.tag_hard_hard_socket(&identity.peer_id, identity.socket_index, &session_token)
                .await
        );
        let peer_session_generation = peers
            .peer_session_generation_sync(&identity.peer_id)
            .expect("exact fixture peer must have an active lifecycle generation");
        (peers, udp, identity, remote, peer_session_generation)
    }

    #[tokio::test]
    async fn hard_hard_winner_promotion_commits_evidence_before_durable_diagnostics() {
        let _serial = crate::tests::HARD_HARD_E2E_SERIAL.acquire().await.unwrap();
        let (peers, udp, identity, remote, _peer_session_generation) =
            exact_birthday_runtime_fixture().await;
        udp.clear_authenticated_evidence_for_test(identity.socket_index)
            .await;
        assert!(!udp
            .hard_hard_socket_identity_has_authenticated_evidence(&identity)
            .await);

        let sweeping = peers
            .hard_hard_begin_sweep(
                &identity.peer_id,
                &identity.session_token,
                vec![remote],
                90,
                0,
            )
            .await
            .expect("fixture session must enter its single sweep");
        assert_eq!(sweeping.fresh_socket, identity);

        // Both winner diagnostics are durable events. Holding the connection
        // writer parks the production promotion only after its manager winner
        // and UDP evidence/affinity/phase transaction is complete.
        let connections_writer = peers.hold_connections_writer_for_test().await;
        let socket_index = identity.socket_index;
        let network_generation = identity.network_generation;
        let promotion = tokio::spawn({
            let udp = udp.clone();
            let peer_id = identity.peer_id.clone();
            let token = identity.session_token.clone();
            async move {
                udp.promote_hard_hard_winner_for_test(
                    &peer_id,
                    &token,
                    socket_index,
                    network_generation,
                )
                .await
            }
        });
        for _ in 0..256 {
            if udp
                .hard_hard_socket_identity_has_authenticated_evidence(&identity)
                .await
            {
                break;
            }
            tokio::task::yield_now().await;
        }
        assert!(udp
            .hard_hard_socket_identity_has_authenticated_evidence(&identity)
            .await);
        assert_eq!(
            peers
                .hard_hard_winner_for_token(&identity.peer_id, &identity.session_token)
                .await,
            Some(identity.socket_index)
        );
        assert!(
            !promotion.is_finished(),
            "durable diagnostics must still be waiting on the held connection writer"
        );
        drop(connections_writer);
        assert!(
            tokio::time::timeout(Duration::from_secs(1), promotion)
                .await
                .expect("promotion must finish after diagnostics are released")
                .expect("promotion task must not panic")
        );
        assert_eq!(
            hard_hard_authenticated_winner_for_cleanup(
                &udp,
                &peers,
                &identity.peer_id,
                &identity.session_token,
            )
            .await,
            Some(identity.clone()),
            "cleanup retention requires the same transaction's authenticated socket evidence"
        );

        assert!(peers
            .hard_hard_retire_session(
                &identity.peer_id,
                &sweeping.session_id,
                &identity.session_token,
            )
            .await);
        udp.detach_hard_hard_sockets_for_token(
            &identity.peer_id,
            &identity.session_token,
            None,
            "test_winner_promotion_cleanup",
        )
        .await;
        udp.clear_hard_hard_pending_probes_for_token(
            &identity.peer_id,
            &identity.session_token,
            None,
        )
        .await;
        assert!(peers
            .hard_hard_complete_session_cleanup(
                &identity.peer_id,
                &sweeping.session_id,
                &identity.session_token,
            )
            .await);
        assert_eq!(udp.dynamic_socket_count().await, 0);
    }

    #[tokio::test]
    async fn hard_hard_duplicate_registration_keeps_new_measurement_under_rollback_owner() {
        let _serial = crate::tests::HARD_HARD_E2E_SERIAL.acquire().await.unwrap();
        let (peers, udp, identity, _remote, _peer_session_generation) =
            exact_birthday_runtime_fixture().await;
        let original = peers
            .hard_hard_session_snapshot_for_cleanup(
                &identity.peer_id,
                "birthday-runtime-session",
                &identity.session_token,
            )
            .await
            .expect("fixture must expose its authoritative session");
        let duplicate_cancellation = Arc::new(crate::PunchSessionCancellation::default());
        let mut duplicate = original.clone();
        duplicate.fresh_socket.socket_index = identity.socket_index.saturating_add(100);
        duplicate.fresh_socket.punch_generation = identity.punch_generation.saturating_add(1);
        duplicate.fresh_socket.socket_local_endpoint = "127.0.0.1:45000".parse().unwrap();
        duplicate.cancellation = duplicate_cancellation.clone();
        duplicate.created_at = Instant::now();

        {
            let _rollback_owner =
                PendingHardHardSessionCancellation::new(duplicate_cancellation.clone());
            assert!(
                !peers.hard_hard_register_session(duplicate).await,
                "an existing session must not transfer its cleanup ownership to a duplicate measurement"
            );
        }
        assert!(
            duplicate_cancellation.is_cancelled(),
            "the rejected duplicate measurement must keep its rollback cancellation armed"
        );
        let current = peers
            .hard_hard_session_snapshot_for_cleanup(
                &identity.peer_id,
                &original.session_id,
                &identity.session_token,
            )
            .await
            .expect("the original session must remain authoritative");
        assert_eq!(current.fresh_socket, original.fresh_socket);
        assert!(Arc::ptr_eq(&current.cancellation, &original.cancellation));
        assert!(!current.cancellation.is_cancelled());
        assert_eq!(udp.dynamic_socket_count().await, 1);

        assert!(peers
            .hard_hard_retire_session(
                &identity.peer_id,
                &original.session_id,
                &identity.session_token,
            )
            .await);
        udp.detach_hard_hard_sockets_for_token(
            &identity.peer_id,
            &identity.session_token,
            None,
            "test_duplicate_registration_cleanup",
        )
        .await;
        udp.clear_hard_hard_pending_probes_for_token(
            &identity.peer_id,
            &identity.session_token,
            None,
        )
        .await;
        assert!(peers
            .hard_hard_complete_session_cleanup(
                &identity.peer_id,
                &original.session_id,
                &identity.session_token,
            )
            .await);
        assert_eq!(udp.dynamic_socket_count().await, 0);
    }

    #[tokio::test]
    async fn hard_hard_winner_promotion_cancellation_before_commit_leaves_no_half_winner() {
        let _serial = crate::tests::HARD_HARD_E2E_SERIAL.acquire().await.unwrap();
        let (peers, udp, identity, remote, _peer_session_generation) =
            exact_birthday_runtime_fixture().await;
        udp.clear_authenticated_evidence_for_test(identity.socket_index)
            .await;
        let sweeping = peers
            .hard_hard_begin_sweep(
                &identity.peer_id,
                &identity.session_token,
                vec![remote],
                90,
                0,
            )
            .await
            .expect("fixture session must enter its single sweep");

        let winner_writer = peers.hold_hard_hard_winner_writer_for_test().await;
        let socket_index = identity.socket_index;
        let network_generation = identity.network_generation;
        let promotion = tokio::spawn({
            let udp = udp.clone();
            let peer_id = identity.peer_id.clone();
            let token = identity.session_token.clone();
            async move {
                udp.promote_hard_hard_winner_for_test(
                    &peer_id,
                    &token,
                    socket_index,
                    network_generation,
                )
                .await
            }
        });
        for _ in 0..256 {
            if udp.hard_hard_socket_state_is_locked_for_test() {
                break;
            }
            tokio::task::yield_now().await;
        }
        assert!(
            udp.hard_hard_socket_state_is_locked_for_test(),
            "promotion must own the exact socket transaction before cancellation"
        );
        promotion.abort();
        let cancelled = tokio::time::timeout(Duration::from_secs(1), promotion)
            .await
            .expect("aborted promotion must stop without waiting for the winner writer")
            .expect_err("promotion must be cancelled at the pre-commit lock wait");
        assert!(cancelled.is_cancelled());
        drop(winner_writer);

        assert_eq!(
            peers
                .hard_hard_winner_for_token(&identity.peer_id, &identity.session_token)
                .await,
            None,
            "pre-commit cancellation must not strand a manager-only winner"
        );
        assert!(!udp
            .hard_hard_socket_identity_has_authenticated_evidence(&identity)
            .await);
        assert_eq!(
            hard_hard_authenticated_winner_for_cleanup(
                &udp,
                &peers,
                &identity.peer_id,
                &identity.session_token,
            )
            .await,
            None,
            "an unauthenticated pre-commit socket must never be preserved"
        );

        assert!(peers
            .hard_hard_retire_session(
                &identity.peer_id,
                &sweeping.session_id,
                &identity.session_token,
            )
            .await);
        udp.detach_hard_hard_sockets_for_token(
            &identity.peer_id,
            &identity.session_token,
            None,
            "test_cancelled_winner_promotion_cleanup",
        )
        .await;
        udp.clear_hard_hard_pending_probes_for_token(
            &identity.peer_id,
            &identity.session_token,
            None,
        )
        .await;
        assert!(peers
            .hard_hard_complete_session_cleanup(
                &identity.peer_id,
                &sweeping.session_id,
                &identity.session_token,
            )
            .await);
        assert_eq!(udp.dynamic_socket_count().await, 0);
    }

    struct HardHardTestClockReset;

    impl Drop for HardHardTestClockReset {
        fn drop(&mut self) {
            set_hard_hard_test_now_ms(None);
        }
    }

    async fn seed_hard_hard_pending_probes(
        udp: &UdpTransport,
        identity: &crate::peer::HardHardFreshSocketIdentity,
        count: usize,
    ) -> PunchSendReport {
        let localhost = "127.0.0.1".parse().unwrap();
        let candidates = (0..count)
            .map(|offset| {
                SocketAddr::new(localhost, 41_000 + u16::try_from(offset).unwrap())
            })
            .collect::<Vec<_>>();
        let task = tokio::spawn({
            let udp = udp.clone();
            let peer_id = identity.peer_id.clone();
            let token = identity.session_token.clone();
            let socket_index = identity.socket_index;
            async move {
                udp.punch_candidates_from_dynamic_socket_index_with_profile_fence_and_session(
                    &peer_id,
                    socket_index,
                    candidates,
                    Duration::ZERO,
                    1,
                    None,
                    Some(&token),
                )
                .await
            }
        });
        for _ in 0..128 {
            if task.is_finished() {
                break;
            }
            tokio::task::yield_now().await;
            tokio::time::advance(Duration::from_millis(5)).await;
        }
        assert!(
            task.is_finished(),
            "test probe seeding must finish before pending-probe leases expire"
        );
        task.await
            .expect("test probe seeding task must not panic")
            .expect("test probe seeding must produce a report")
    }

    async fn wait_for_hard_hard_cleanup_owner(
        peers: &PeerManager,
        descriptor: &HardHardCleanupDescriptor,
    ) {
        for _ in 0..256 {
            if peers
                .hard_hard_cleanup_owner_claimed_for_test(
                    &descriptor.peer_id,
                    &descriptor.session_id,
                    &descriptor.session_token,
                )
                .await
            {
                return;
            }
            tokio::task::yield_now().await;
        }
        panic!("Hard↔Hard cleanup watcher did not claim its exact owner");
    }

    async fn wait_for_hard_hard_cleanup_gate(
        gate: &Arc<crate::peer::HardHardCleanupGate>,
    ) {
        let reached = gate.reached.notified();
        tokio::pin!(reached);
        let watchdog = async {
            for _ in 0..512 {
                tokio::task::yield_now().await;
            }
        };
        tokio::pin!(watchdog);
        tokio::select! {
            _ = &mut reached => {}
            _ = &mut watchdog => panic!("Hard↔Hard cleanup did not reach the test gate"),
        }
    }

    async fn wait_for_hard_hard_cleanup_completion(completion: &HardHardCleanupCompletion) {
        let wait = completion.wait();
        tokio::pin!(wait);
        let watchdog = async {
            for _ in 0..64 {
                tokio::time::advance(Duration::from_millis(100)).await;
                tokio::task::yield_now().await;
            }
        };
        tokio::pin!(watchdog);
        tokio::select! {
            _ = &mut wait => {}
            _ = &mut watchdog => panic!("Hard↔Hard cleanup did not complete"),
        }
    }

    async fn exercise_hard_hard_cleanup_cancellation(cancel_before_watcher: bool) {
        let _serial = crate::tests::HARD_HARD_E2E_SERIAL.acquire().await.unwrap();
        set_hard_hard_test_now_ms(Some(4_000_000_000));
        let _clock = HardHardTestClockReset;
        let (peers, udp, identity, _remote, _peer_session_generation) =
            exact_birthday_runtime_fixture().await;
        let record = peers
            .hard_hard_session_snapshot_for_cleanup(
                &identity.peer_id,
                "birthday-runtime-session",
                &identity.session_token,
            )
            .await
            .expect("Birthday fixture must expose its exact session record");
        let descriptor = HardHardCleanupDescriptor::from_record(&record);
        assert!(matches!(
            peers.recovery_epoch_admit(&identity.peer_id).await,
            crate::peer::RecoveryAdmission::Accepted { .. }
        ));
        let report = seed_hard_hard_pending_probes(&udp, &identity, 5).await;
        assert_eq!(report.logical_probes_sent, 5, "{report:?}");
        assert_eq!(report.physical_datagrams_sent, 5, "{report:?}");
        assert_eq!(
            udp.hard_hard_pending_probe_count_for_token_for_test(
                &identity.peer_id,
                &identity.session_token,
            )
            .await,
            5
        );

        let (gate, _gate_guard) = peers.install_hard_hard_cleanup_gate_for_test(
            &descriptor.peer_id,
            &descriptor.session_id,
            &descriptor.session_token,
        );
        if cancel_before_watcher {
            assert!(!peers
                .hard_hard_cleanup_owner_claimed_for_test(
                    &descriptor.peer_id,
                    &descriptor.session_id,
                    &descriptor.session_token,
                )
                .await);
            descriptor.cancellation.cancel_for_hard_hard_cleanup();
        }
        let completion = spawn_hard_hard_session_cleanup(udp.clone(), peers.clone(), descriptor.clone());
        if !cancel_before_watcher {
            wait_for_hard_hard_cleanup_owner(&peers, &descriptor).await;
            assert_eq!(
                peers
                    .hard_hard_session_snapshot_for_cleanup(
                        &descriptor.peer_id,
                        &descriptor.session_id,
                        &descriptor.session_token,
                    )
                    .await
                    .expect("registered cleanup session must remain observable")
                    .state,
                HardHardSessionState::AwaitingPeer
            );
            descriptor.cancellation.cancel_for_hard_hard_cleanup();
        }

        wait_for_hard_hard_cleanup_gate(&gate).await;
        let retiring = peers
            .hard_hard_session_snapshot_for_cleanup(
                &descriptor.peer_id,
                &descriptor.session_id,
                &descriptor.session_token,
            )
            .await
            .expect("retiring record must remain until UDP cleanup completes");
        assert_eq!(retiring.state, HardHardSessionState::Retiring);
        assert!(!peers.hard_hard_session_is_active(&descriptor.peer_id).await);
        assert_eq!(udp.dynamic_socket_count().await, 1);
        assert_eq!(
            udp.hard_hard_pending_probe_count_for_token_for_test(
                &descriptor.peer_id,
                &descriptor.session_token,
            )
            .await,
            5
        );
        assert!(!udp
            .hard_hard_socket_indices_for_token(&descriptor.peer_id, &descriptor.session_token)
            .await
            .is_empty());

        gate.release.notify_waiters();
        wait_for_hard_hard_cleanup_completion(&completion).await;
        assert!(
            peers
                .hard_hard_session_snapshot_for_cleanup(
                    &descriptor.peer_id,
                    &descriptor.session_id,
                    &descriptor.session_token,
                )
                .await
                .is_none()
        );
        assert!(!peers
            .hard_hard_cleanup_owner_claimed_for_test(
                &descriptor.peer_id,
                &descriptor.session_id,
                &descriptor.session_token,
            )
            .await);
        assert_eq!(udp.dynamic_socket_count().await, 0);
        assert_eq!(
            udp.hard_hard_pending_probe_count_for_token_for_test(
                &descriptor.peer_id,
                &descriptor.session_token,
            )
            .await,
            0
        );
        assert!(udp
            .hard_hard_socket_indices_for_token(&descriptor.peer_id, &descriptor.session_token)
            .await
            .is_empty());
    }

    #[tokio::test(start_paused = true)]
    async fn hard_hard_cleanup_cancellation_before_watcher_registration_is_exact_and_complete() {
        exercise_hard_hard_cleanup_cancellation(true).await;
    }

    #[tokio::test(start_paused = true)]
    async fn hard_hard_cleanup_cancellation_after_watcher_registration_is_exact_and_complete() {
        exercise_hard_hard_cleanup_cancellation(false).await;
    }

    #[tokio::test]
    async fn hard_hard_session_observers_do_not_prune_expired_records_and_cleanup_is_idempotent() {
        let _serial = crate::tests::HARD_HARD_E2E_SERIAL.acquire().await.unwrap();
        set_hard_hard_test_now_ms(Some(4_000_000_000));
        let _clock = HardHardTestClockReset;
        let (peers, udp, identity, _remote) = exact_socket_proof_fixture().await;
        let record = peers
            .hard_hard_session_snapshot_for_cleanup(
                &identity.peer_id,
                "proof-session",
                &identity.session_token,
            )
            .await
            .expect("exact proof fixture must expose its session");
        let cancellation = record.cancellation.clone();
        assert!(peers.hard_hard_session_is_active(&identity.peer_id).await);
        assert!(peers
            .hard_hard_session_by_token(&identity.peer_id, &identity.session_token)
            .await
            .is_some());
        assert!(peers
            .hard_hard_session_snapshot_for_cleanup(
                &identity.peer_id,
                "proof-session",
                &identity.session_token,
            )
            .await
            .is_some());
        assert!(!cancellation.is_cancelled());

        set_hard_hard_test_now_ms(Some(record.expires_at_ms.saturating_add(1)));
        assert!(!peers.hard_hard_session_is_active(&identity.peer_id).await);
        assert!(peers
            .hard_hard_session_by_token(&identity.peer_id, &identity.session_token)
            .await
            .is_none());
        let expired_snapshot = peers
            .hard_hard_session_snapshot_for_cleanup(
                &identity.peer_id,
                "proof-session",
                &identity.session_token,
            )
            .await
            .expect("pure snapshots must not remove expired records");
        assert_eq!(expired_snapshot.state, HardHardSessionState::AwaitingPeer);
        assert!(!cancellation.is_cancelled());

        assert!(peers
            .hard_hard_retire_session(
                &identity.peer_id,
                "proof-session",
                &identity.session_token,
            )
            .await);
        assert!(peers
            .hard_hard_retire_session(
                &identity.peer_id,
                "proof-session",
                &identity.session_token,
            )
            .await);
        assert!(!peers.hard_hard_session_is_active(&identity.peer_id).await);
        assert!(peers
            .hard_hard_complete_session_cleanup(
                &identity.peer_id,
                "proof-session",
                &identity.session_token,
            )
            .await);
        assert!(!peers
            .hard_hard_complete_session_cleanup(
                &identity.peer_id,
                "proof-session",
                &identity.session_token,
            )
            .await);
        assert!(peers
            .hard_hard_session_snapshot_for_cleanup(
                &identity.peer_id,
                "proof-session",
                &identity.session_token,
            )
            .await
            .is_none());
        udp.detach_all_dynamic_punch_sockets("test_cleanup_idempotence")
            .await;
    }

    #[tokio::test]
    async fn hard_hard_late_cleanup_cannot_remove_replacement_session() {
        let _serial = crate::tests::HARD_HARD_E2E_SERIAL.acquire().await.unwrap();
        let (peers, udp, old_identity, _remote) = exact_socket_proof_fixture().await;
        let old = peers
            .hard_hard_session_snapshot_for_cleanup(
                &old_identity.peer_id,
                "proof-session",
                &old_identity.session_token,
            )
            .await
            .expect("replacement fixture must expose its old session");
        let mut replacement = old.clone();
        replacement.session_id = "replacement-session".to_string();
        replacement.session_token = "replacement-token".to_string();
        replacement.fresh_socket.session_token = replacement.session_token.clone();
        replacement.cancellation = Arc::new(crate::PunchSessionCancellation::default());
        assert!(peers.hard_hard_register_session(replacement.clone()).await);
        assert!(old.cancellation.is_cancelled());
        assert_eq!(
            peers
                .hard_hard_session_snapshot_for_cleanup(
                    &old.peer_id,
                    &old.session_id,
                    &old.session_token,
                )
                .await
                .expect("old session must remain in Retiring state")
                .state,
            HardHardSessionState::Retiring
        );
        assert!(udp
            .tag_hard_hard_socket(
                &replacement.peer_id,
                replacement.fresh_socket.socket_index,
                &replacement.session_token,
            )
            .await);

        let _ = peers
            .hard_hard_retire_session(&old.peer_id, &old.session_id, &old.session_token)
            .await;
        udp.detach_hard_hard_sockets_for_token(
            &old.peer_id,
            &old.session_token,
            None,
            "test_old_token_cleanup",
        )
        .await;
        udp.detach_hard_hard_socket_if_identity(
            &old.fresh_socket,
            "test_old_identity_cleanup",
        )
        .await;
        udp.clear_hard_hard_pending_probes_for_token(&old.peer_id, &old.session_token, None)
            .await;
        assert!(peers
            .hard_hard_complete_session_cleanup(&old.peer_id, &old.session_id, &old.session_token)
            .await);
        assert_eq!(udp.dynamic_socket_count().await, 1);
        assert!(peers
            .hard_hard_session_by_token(&replacement.peer_id, &replacement.session_token)
            .await
            .is_some());
        assert!(peers.hard_hard_session_is_active(&replacement.peer_id).await);
        assert_eq!(
            udp.hard_hard_socket_indices_for_token(
                &replacement.peer_id,
                &replacement.session_token,
            )
            .await,
            vec![replacement.fresh_socket.socket_index]
        );

        assert!(peers
            .hard_hard_retire_session(
                &replacement.peer_id,
                &replacement.session_id,
                &replacement.session_token,
            )
            .await);
        udp.detach_hard_hard_sockets_for_token(
            &replacement.peer_id,
            &replacement.session_token,
            None,
            "test_replacement_cleanup",
        )
        .await;
        udp.clear_hard_hard_pending_probes_for_token(
            &replacement.peer_id,
            &replacement.session_token,
            None,
        )
        .await;
        assert!(peers
            .hard_hard_complete_session_cleanup(
                &replacement.peer_id,
                &replacement.session_id,
                &replacement.session_token,
            )
            .await);
        assert_eq!(udp.dynamic_socket_count().await, 0);
    }

    #[tokio::test]
    async fn hard_hard_token_cleanup_uses_exact_fallback_and_preserves_mismatched_token() {
        let _serial = crate::tests::HARD_HARD_E2E_SERIAL.acquire().await.unwrap();
        let (peers, udp, identity, _remote) = exact_socket_proof_fixture().await;
        udp.detach_hard_hard_sockets_for_token(
            &identity.peer_id,
            &identity.session_token,
            None,
            "test_token_mismatch_no_match",
        )
        .await;
        assert_eq!(udp.dynamic_socket_count().await, 1);
        udp.detach_hard_hard_socket_if_identity(&identity, "test_exact_identity_fallback")
            .await;
        assert_eq!(udp.dynamic_socket_count().await, 0);

        let (socket_index, socket) = udp.bind_fresh_punch_socket().await.unwrap();
        let socket_local_endpoint = socket.local_addr().unwrap();
        let handoff = udp
            .attach_dynamic_punch_socket(&identity.peer_id, socket_index, socket, 0, 2, None)
            .await
            .unwrap();
        assert!(handoff
            .commit_and_pin_for_test(&udp, &identity.peer_id, socket_index, 0, 2)
            .await);
        assert!(handoff.finalize().await);
        assert!(udp
            .tag_hard_hard_socket(&identity.peer_id, socket_index, "replacement-token")
            .await);
        let mut mismatched_identity = identity.clone();
        mismatched_identity.socket_index = socket_index;
        mismatched_identity.punch_generation = 2;
        mismatched_identity.socket_local_endpoint = socket_local_endpoint;
        udp.detach_hard_hard_sockets_for_token(
            &identity.peer_id,
            &identity.session_token,
            None,
            "test_old_token_does_not_match_replacement",
        )
        .await;
        udp.detach_hard_hard_socket_if_identity(
            &mismatched_identity,
            "test_old_identity_does_not_match_replacement",
        )
        .await;
        assert_eq!(udp.dynamic_socket_count().await, 1);
        udp.detach_hard_hard_sockets_for_token(
            &identity.peer_id,
            "replacement-token",
            None,
            "test_replacement_token_cleanup",
        )
        .await;
        assert_eq!(udp.dynamic_socket_count().await, 0);
        peers
            .clear_hard_hard_sessions(Some(&identity.peer_id))
            .await;
        udp.detach_all_dynamic_punch_sockets("test_token_mismatch_cleanup")
            .await;
    }

    #[tokio::test(start_paused = true)]
    async fn hard_hard_expiry_retains_only_authenticated_current_direct_socket() {
        let _serial = crate::tests::HARD_HARD_E2E_SERIAL.acquire().await.unwrap();
        set_hard_hard_test_now_ms(Some(4_000_000_000));
        let _clock = HardHardTestClockReset;
        let (peers, udp, identity, remote, _peer_session_generation) =
            exact_birthday_runtime_fixture().await;
        assert!(peers
            .record_direct_success_for_generation_with_local_endpoint(
                &identity.peer_id,
                Some(remote),
                identity.network_generation,
                Some(identity.socket_local_endpoint),
            )
            .await);
        assert!(
            hard_hard_exact_direct_socket_is_current_for_cleanup(&udp, &peers, &identity).await
        );
        let record = peers
            .hard_hard_session_snapshot_for_cleanup(
                &identity.peer_id,
                "birthday-runtime-session",
                &identity.session_token,
            )
            .await
            .unwrap();
        let descriptor = HardHardCleanupDescriptor::from_record(&record);
        set_hard_hard_test_now_ms(Some(record.expires_at_ms.saturating_add(1)));
        let (gate, _gate_guard) = peers.install_hard_hard_cleanup_gate_for_test(
            &descriptor.peer_id,
            &descriptor.session_id,
            &descriptor.session_token,
        );
        let completion = spawn_hard_hard_session_cleanup(udp.clone(), peers.clone(), descriptor.clone());
        wait_for_hard_hard_cleanup_gate(&gate).await;
        assert_eq!(
            udp.hard_hard_socket_indices_for_token(&identity.peer_id, &identity.session_token)
                .await,
            vec![identity.socket_index]
        );
        gate.release.notify_waiters();
        wait_for_hard_hard_cleanup_completion(&completion).await;
        assert!(peers
            .hard_hard_session_snapshot_for_cleanup(
                &descriptor.peer_id,
                &descriptor.session_id,
                &descriptor.session_token,
            )
            .await
            .is_none());
        assert_eq!(udp.dynamic_socket_count().await, 1);
        udp.detach_dynamic_socket_by_index(identity.socket_index, "test_retained_direct_cleanup")
            .await;
        assert_eq!(udp.dynamic_socket_count().await, 0);
    }

    async fn wait_for_birthday_worker_gate(
        gate: &Arc<crate::udp::BirthdayWorkerCompletionGate>,
    ) {
        let reached = gate.reached.notified();
        let mut watchdog = tokio::spawn(async {
            for _ in 0..64 {
                tokio::task::yield_now().await;
            }
            tokio::time::advance(Duration::from_secs(1)).await;
        });
        tokio::select! {
            _ = reached => {
                watchdog.abort();
            }
            _ = &mut watchdog => panic!("production Birthday worker did not publish live progress"),
        }
    }

    async fn wait_for_birthday_post_send_gate(
        gate: &Arc<crate::udp::ProbePostSendGate>,
    ) {
        // Register the waiter before starting the production task: the hook
        // uses notify_waiters, so an already-reached gate must not be lost.
        let reached = gate.reached.notified();
        let mut watchdog = tokio::spawn(async {
            for _ in 0..128 {
                tokio::task::yield_now().await;
            }
        });
        tokio::select! {
            _ = reached => {
                watchdog.abort();
            }
            _ = &mut watchdog => panic!("production Birthday send did not reach the post-send gate"),
        }
    }

    fn assert_live_birthday_terminal_summary(
        events: &[crate::peer::DirectTraversalEventDiagnostics],
        stop_reason: &str,
    ) {
        let summary = events
            .iter()
            .find(|event| event.stage == "hard_hard_birthday_sweep_summary")
            .expect("terminal Birthday summary must be durable");
        for field in [
            "physical_datagrams_sent=",
            "per_socket_sent=",
            "first_send_at_ms=Some(",
            "last_send_at_ms=Some(",
            "unique_target_endpoints=1",
            "waves_fully_completed=0",
        ] {
            assert!(
                summary.detail.contains(field),
                "terminal summary is missing {field}: {}",
                summary.detail
            );
        }
        assert!(
            summary.detail.contains(&format!("stop_reason={stop_reason}")),
            "terminal summary has an unexpected stop reason: {}",
            summary.detail
        );
    }

    fn assert_post_send_race_summary(
        events: &[crate::peer::DirectTraversalEventDiagnostics],
        stop_reason: &str,
        require_physical_error: bool,
    ) {
        let summary = events
            .iter()
            .find(|event| event.stage == "hard_hard_birthday_sweep_summary")
            .expect("post-send race must emit a durable Birthday summary");
        let count = |key: &str| {
            summary
                .detail
                .split_whitespace()
                .find_map(|field| field.strip_prefix(key)?.parse::<u64>().ok())
                .unwrap_or_else(|| panic!("summary is missing {key}: {}", summary.detail))
        };
        if require_physical_error {
            assert!(count("physical_send_errors=") >= 1);
        } else {
            assert!(count("physical_datagrams_sent=") >= 1);
            assert!(count("logical_probes_sent=") >= 1);
            assert!(count("unique_target_endpoints=") >= 1);
            assert!(summary.detail.contains("per_socket_sent=") && !summary.detail.contains("per_socket_sent= "));
            assert!(summary.detail.contains("first_send_at_ms=Some("));
            assert!(summary.detail.contains("last_send_at_ms=Some("));
        }
        assert!(summary.detail.contains("waves_fully_completed=0"));
        assert!(
            summary
                .detail
                .contains(&format!("stop_reason={stop_reason}")),
            "terminal summary has an unexpected stop reason: {}",
            summary.detail
        );
    }

    #[tokio::test(start_paused = true)]
    async fn hard_hard_birthday_deadline_snapshots_live_progress_at_production_entry() {
        let _serial = crate::tests::HARD_HARD_E2E_SERIAL.acquire().await.unwrap();
        set_hard_hard_test_now_ms(None);
        let (peers, udp, identity, _remote, peer_session_generation) =
            exact_birthday_runtime_fixture().await;
        let remote: SocketAddr = "127.0.0.1:41000".parse().unwrap();
        let session = PunchAttemptDeduplicator::default()
            .claim(&identity.peer_id)
            .await
            .expect("test must own the production Hard↔Hard punch session");
        let (gate, _gate_guard) = crate::udp::install_birthday_worker_completion_gate_for_test();
        let socket_indices = vec![identity.socket_index, identity.socket_index + 1];
        let task = tokio::spawn({
            let udp = udp.clone();
            let peers = peers.clone();
            let identity = identity.clone();
            async move {
                hard_hard_wait_and_sweep(
                    udp,
                    peers,
                    session,
                    identity.peer_id.clone(),
                    peer_session_generation,
                    identity,
                    Some(socket_indices),
                    "birthday-runtime-token".to_string(),
                    vec![remote],
                    64,
                    64,
                    1,
                    hard_hard_now_ms(),
                    0,
                    (1, 7),
                    Some("probe-session-exact".to_string()),
                    "test-deadline",
                )
                .await
            }
        });
        wait_for_birthday_worker_gate(&gate).await;
        tokio::time::advance(HARD_HARD_SWEEP_DEADLINE).await;
        tokio::task::yield_now().await;
        assert!(!task.await.unwrap());

        let events = peers.diagnostics().await[0].direct_events.clone();
        assert_live_birthday_terminal_summary(&events, "deadline");
        assert!(events
            .iter()
            .any(|event| event.stage == "hard_hard_sweep_failed"));
        gate.release.notify_waiters();
        udp.detach_all_dynamic_punch_sockets("test_deadline_live_progress")
            .await;
    }

    #[tokio::test(start_paused = true)]
    async fn hard_hard_birthday_cancellation_snapshots_live_progress_at_production_entry() {
        let _serial = crate::tests::HARD_HARD_E2E_SERIAL.acquire().await.unwrap();
        set_hard_hard_test_now_ms(None);
        let (peers, udp, identity, _remote, peer_session_generation) =
            exact_birthday_runtime_fixture().await;
        let remote: SocketAddr = "127.0.0.1:41001".parse().unwrap();
        let session = PunchAttemptDeduplicator::default()
            .claim(&identity.peer_id)
            .await
            .expect("test must own the production Hard↔Hard punch session");
        let cancellation = session.cancellation_handle();
        let (gate, _gate_guard) = crate::udp::install_birthday_worker_completion_gate_for_test();
        let socket_indices = vec![identity.socket_index, identity.socket_index + 1];
        let task = tokio::spawn({
            let udp = udp.clone();
            let peers = peers.clone();
            let identity = identity.clone();
            async move {
                hard_hard_wait_and_sweep(
                    udp,
                    peers,
                    session,
                    identity.peer_id.clone(),
                    peer_session_generation,
                    identity,
                    Some(socket_indices),
                    "birthday-runtime-token".to_string(),
                    vec![remote],
                    64,
                    64,
                    1,
                    hard_hard_now_ms(),
                    0,
                    (1, 7),
                    Some("probe-session-exact".to_string()),
                    "test-cancel",
                )
                .await
            }
        });
        wait_for_birthday_worker_gate(&gate).await;
        cancellation.cancel_for_hard_hard_cleanup();
        tokio::task::yield_now().await;
        assert!(!task.await.unwrap());

        let events = peers.diagnostics().await[0].direct_events.clone();
        assert_live_birthday_terminal_summary(&events, "session_cancelled");
        assert!(events
            .iter()
            .any(|event| event.stage == "hard_hard_failed"));
        gate.release.notify_waiters();
        udp.detach_all_dynamic_punch_sockets("test_cancel_live_progress")
            .await;
    }

    #[tokio::test(start_paused = true)]
    async fn hard_hard_birthday_post_send_deadline_preserves_live_progress() {
        let _serial = crate::tests::HARD_HARD_E2E_SERIAL.acquire().await.unwrap();
        set_hard_hard_test_now_ms(None);
        let (peers, udp, identity, _remote, peer_session_generation) =
            exact_birthday_runtime_fixture().await;
        let remote: SocketAddr = "127.0.0.1:41002".parse().unwrap();
        let session = PunchAttemptDeduplicator::default()
            .claim(&identity.peer_id)
            .await
            .expect("test must own the production Hard↔Hard punch session");
        let (gate, _gate_guard) = crate::udp::install_probe_post_send_gate_for_test();
        let socket_indices = vec![identity.socket_index, identity.socket_index + 1];
        let task = tokio::spawn({
            let udp = udp.clone();
            let peers = peers.clone();
            let identity = identity.clone();
            async move {
                hard_hard_wait_and_sweep(
                    udp,
                    peers,
                    session,
                    identity.peer_id.clone(),
                    peer_session_generation,
                    identity,
                    Some(socket_indices),
                    "birthday-runtime-token".to_string(),
                    vec![remote],
                    64,
                    64,
                    1,
                    hard_hard_now_ms(),
                    0,
                    (1, 7),
                    Some("probe-session-exact".to_string()),
                    "test-post-send-deadline",
                )
                .await
            }
        });
        wait_for_birthday_post_send_gate(&gate).await;
        tokio::time::advance(HARD_HARD_SWEEP_DEADLINE).await;
        tokio::task::yield_now().await;
        assert!(!task.await.unwrap());

        let events = peers.diagnostics().await[0].direct_events.clone();
        assert_post_send_race_summary(&events, "deadline", false);
        gate.release.notify_waiters();
        udp.detach_all_dynamic_punch_sockets("test_post_send_deadline").await;
    }

    #[tokio::test(start_paused = true)]
    async fn hard_hard_birthday_post_send_cancellation_preserves_live_progress() {
        let _serial = crate::tests::HARD_HARD_E2E_SERIAL.acquire().await.unwrap();
        set_hard_hard_test_now_ms(None);
        let (peers, udp, identity, _remote, peer_session_generation) =
            exact_birthday_runtime_fixture().await;
        let remote: SocketAddr = "127.0.0.1:41003".parse().unwrap();
        let session = PunchAttemptDeduplicator::default()
            .claim(&identity.peer_id)
            .await
            .expect("test must own the production Hard↔Hard punch session");
        let cancellation = session.cancellation_handle();
        let (gate, _gate_guard) = crate::udp::install_probe_post_send_gate_for_test();
        let socket_indices = vec![identity.socket_index, identity.socket_index + 1];
        let task = tokio::spawn({
            let udp = udp.clone();
            let peers = peers.clone();
            let identity = identity.clone();
            async move {
                hard_hard_wait_and_sweep(
                    udp,
                    peers,
                    session,
                    identity.peer_id.clone(),
                    peer_session_generation,
                    identity,
                    Some(socket_indices),
                    "birthday-runtime-token".to_string(),
                    vec![remote],
                    64,
                    64,
                    1,
                    hard_hard_now_ms(),
                    0,
                    (1, 7),
                    Some("probe-session-exact".to_string()),
                    "test-post-send-cancel",
                )
                .await
            }
        });
        wait_for_birthday_post_send_gate(&gate).await;
        cancellation.cancel_for_hard_hard_cleanup();
        tokio::task::yield_now().await;
        assert!(!task.await.unwrap());

        let events = peers.diagnostics().await[0].direct_events.clone();
        assert_post_send_race_summary(&events, "session_cancelled", false);
        gate.release.notify_waiters();
        udp.detach_all_dynamic_punch_sockets("test_post_send_cancellation")
            .await;
    }

    #[tokio::test(start_paused = true)]
    async fn hard_hard_birthday_primary_send_error_is_recorded_before_cleanup_cancel() {
        let _serial = crate::tests::HARD_HARD_E2E_SERIAL.acquire().await.unwrap();
        set_hard_hard_test_now_ms(None);
        let (peers, udp, identity, _remote, peer_session_generation) =
            exact_birthday_runtime_fixture().await;
        let remote: SocketAddr = "127.0.0.1:41004".parse().unwrap();
        let session = PunchAttemptDeduplicator::default()
            .claim(&identity.peer_id)
            .await
            .expect("test must own the production Hard↔Hard punch session");
        let cancellation = session.cancellation_handle();
        let _send_failures = udp.set_probe_send_failures_for_test([1]);
        let (gate, _gate_guard) = crate::udp::install_probe_post_send_gate_for_test();
        let socket_indices = vec![identity.socket_index, identity.socket_index + 1];
        let task = tokio::spawn({
            let udp = udp.clone();
            let peers = peers.clone();
            let identity = identity.clone();
            async move {
                hard_hard_wait_and_sweep(
                    udp,
                    peers,
                    session,
                    identity.peer_id.clone(),
                    peer_session_generation,
                    identity,
                    Some(socket_indices),
                    "birthday-runtime-token".to_string(),
                    vec![remote],
                    64,
                    64,
                    1,
                    hard_hard_now_ms(),
                    0,
                    (1, 7),
                    Some("probe-session-exact".to_string()),
                    "test-primary-error-cancel",
                )
                .await
            }
        });
        wait_for_birthday_post_send_gate(&gate).await;
        cancellation.cancel_for_hard_hard_cleanup();
        tokio::task::yield_now().await;
        assert!(!task.await.unwrap());

        let events = peers.diagnostics().await[0].direct_events.clone();
        assert_post_send_race_summary(&events, "session_cancelled", true);
        gate.release.notify_waiters();
        udp.detach_all_dynamic_punch_sockets("test_primary_error_cancel")
            .await;
    }

    fn endpoint_for_test(port: u16) -> SocketAddr {
        SocketAddr::new("198.51.100.20".parse().unwrap(), port)
    }

    async fn exact_socket_proof_fixture() -> (
        Arc<PeerManager>,
        UdpTransport,
        crate::peer::HardHardFreshSocketIdentity,
        SocketAddr,
    ) {
        let peers = Arc::new(PeerManager::new(
            Config::generate_default("https://ctrl.test", "hard-hard-exact-proof").unwrap(),
        ));
        let remote: SocketAddr = "198.51.100.20:41000".parse().unwrap();
        peers
            .add_peer(&crate::control::PeerInfo {
                node_id: "peer-exact-proof".to_string(),
                device_name: String::new(),
                app_version: String::new(),
                public_key: "pk".to_string(),
                endpoint: remote.to_string(),
                nat_type:
                    "p2v2:m=address_or_port_dependent;a=linear;d=4;c=90;f=address_dependent;h=unknown;g=7"
                        .to_string(),
                virtual_ip: "10.20.0.2".to_string(),
                online: true,
                last_seen: 0,
                relay_rtt_ms: None,
            })
            .await;
        let sources = HashMap::from([(remote.to_string(), "stun_observed".to_string())]);
        peers
            .add_candidates_with_sources("peer-exact-proof", &[remote.to_string()], &sources)
            .await;
        let remote_candidate_epoch = peers
            .current_remote_candidate_epoch("peer-exact-proof")
            .await
            .unwrap();
        assert!(
            peers
                .bind_remote_nat_profile_to_candidate_epoch("peer-exact-proof", 7)
                .await
        );
        assert!(
            peers
                .set_probe_session_id(
                    "peer-exact-proof",
                    Some("probe-session-exact".to_string()),
                )
                .await
        );

        let (inbound_tx, _inbound_rx) = tokio::sync::mpsc::channel(8);
        let udp = UdpTransport::bind("127.0.0.1:0".parse().unwrap(), peers.clone())
            .await
            .unwrap()
            .with_inbound_channel(inbound_tx);
        let (socket_index, socket) = udp.bind_fresh_punch_socket().await.unwrap();
        let socket_local_endpoint = socket.local_addr().unwrap();
        let handoff = udp
            .attach_dynamic_punch_socket("peer-exact-proof", socket_index, socket, 0, 1, None)
            .await
            .unwrap();
        assert!(
            handoff
                .commit_and_pin_for_test(&udp, "peer-exact-proof", socket_index, 0, 1)
                .await
        );
        assert!(handoff.finalize().await);
        udp.remember_peer_socket(
            "peer-exact-proof",
            socket_index,
            crate::udp::SocketEvidence::Fresh,
        )
        .await;

        let identity = crate::peer::HardHardFreshSocketIdentity {
            peer_id: "peer-exact-proof".to_string(),
            session_token: "proof-token".to_string(),
            network_generation: 0,
            remote_candidate_epoch,
            local_profile_generation: 0,
            remote_profile_generation: 7,
            punch_generation: 1,
            socket_index,
            socket_local_endpoint,
        };
        let now = hard_hard_now_ms();
        assert!(
            peers
                .hard_hard_register_session(crate::peer::HardHardSessionRecord {
                    session_id: "proof-session".to_string(),
                    probe_session_id: Some("probe-session-exact".to_string()),
                    session_token: identity.session_token.clone(),
                    peer_id: identity.peer_id.clone(),
                    initiator: true,
                    remote_network_generation: 0,
                    local_network_generation: identity.network_generation,
                    remote_candidate_epoch: identity.remote_candidate_epoch,
                    local_profile_generation: identity.local_profile_generation,
                    remote_profile_generation: identity.remote_profile_generation,
                    local_prediction_confidence: 90,
                    remote_prediction_confidence: 90,
                    requested_birthday_level: 0,
                    generated_candidate_count: 1,
                    signaled_candidate_count: 1,
                    birthday: false,
                    requested_socket_indices: vec![socket_index],
                    requested_socket_count: 1,
                    prediction_window: vec![remote],
                    remote_prediction: vec![remote],
                    fresh_socket: identity.clone(),
                    punch_at_ms: now.saturating_add(5_000),
                    expires_at_ms: now.saturating_add(30_000),
                    state: crate::peer::HardHardSessionState::AwaitingPeer,
                    attempt_count: 0,
                    created_at: Instant::now(),
                    cancellation: Arc::new(crate::PunchSessionCancellation::default()),
                })
                .await
        );
        (peers, udp, identity, remote)
    }

    #[tokio::test]
    async fn hard_hard_exact_proof_rejects_peer_global_direct_on_other_socket() {
        let _serial = crate::tests::HARD_HARD_E2E_SERIAL.acquire().await.unwrap();
        let (peers, udp, identity, remote) = exact_socket_proof_fixture().await;
        let other_local: SocketAddr = "127.0.0.1:41001".parse().unwrap();
        let commit_before = peers.direct_commit_seq_sync(&identity.peer_id);
        assert!(
            peers
                .record_direct_success_for_generation_with_local_endpoint(
                    &identity.peer_id,
                    Some(remote),
                    identity.network_generation,
                    Some(other_local),
                )
                .await
        );
        assert!(peers.is_direct(&identity.peer_id).await);
        assert_ne!(
            peers.direct_commit_seq_sync(&identity.peer_id),
            commit_before,
            "the competing ordinary Direct path must have a distinct commit"
        );
        assert!(udp.hard_hard_socket_identity_is_current(&identity).await);
        assert!(
            udp.hard_hard_socket_identity_has_authenticated_evidence(&identity)
                .await
        );
        assert!(
            !hard_hard_exact_direct_confirmation_is_current(&udp, &peers, &identity).await,
            "peer-global Direct on another local socket must not be Hard↔Hard success"
        );
        let events = peers.diagnostics().await[0].direct_events.clone();
        assert!(
            !events
                .iter()
                .any(|event| event.stage == "hard_hard_sweep_completed"),
            "a competing Direct path must not create a Hard↔Hard success event"
        );
        udp.detach_all_dynamic_punch_sockets("test_exact_proof")
            .await;
    }

    #[tokio::test]
    async fn hard_hard_exact_proof_requires_selected_pair_and_authenticated_evidence() {
        let _serial = crate::tests::HARD_HARD_E2E_SERIAL.acquire().await.unwrap();
        let (peers, udp, identity, remote) = exact_socket_proof_fixture().await;
        let commit_before = peers.direct_commit_seq_sync(&identity.peer_id);
        assert!(
            peers
                .record_direct_success_for_generation_with_local_endpoint(
                    &identity.peer_id,
                    Some(remote),
                    identity.network_generation,
                    Some(identity.socket_local_endpoint),
                )
                .await
        );
        assert_ne!(
            peers.direct_commit_seq_sync(&identity.peer_id),
            commit_before,
            "the exact Direct confirmation must advance the existing commit sequence"
        );
        assert!(
            hard_hard_exact_direct_confirmation_is_current(&udp, &peers, &identity).await,
            "selected pair, current generations, affinity, and authenticated evidence must agree"
        );
        assert!(udp.hard_hard_socket_identity_is_current(&identity).await);
        let (data_socket_index, data_socket) = udp
            .socket_for_peer(Some(&identity.peer_id))
            .await
            .expect("the proven Hard↔Hard socket must remain the data socket");
        assert_eq!(data_socket_index, identity.socket_index);
        assert_eq!(
            data_socket.local_addr().unwrap(),
            identity.socket_local_endpoint
        );
        let selection = peers
            .select_path_for_data(&identity.peer_id, true, true)
            .await;
        assert_eq!(selection.path, Some(crate::peer::NetworkPath::Direct));
        assert!(selection.direct_confirmed);

        let mut mismatched_peer = identity.clone();
        mismatched_peer.peer_id = "peer-other".to_string();
        let mut mismatched_token = identity.clone();
        mismatched_token.session_token = "retired-token".to_string();
        let mut mismatched_network = identity.clone();
        mismatched_network.network_generation += 1;
        let mut mismatched_candidate_epoch = identity.clone();
        mismatched_candidate_epoch.remote_candidate_epoch += 1;
        let mut mismatched_local_profile = identity.clone();
        mismatched_local_profile.local_profile_generation += 1;
        let mut mismatched_remote_profile = identity.clone();
        mismatched_remote_profile.remote_profile_generation += 1;
        let mut mismatched_punch = identity.clone();
        mismatched_punch.punch_generation += 1;
        let mut mismatched_index = identity.clone();
        mismatched_index.socket_index += 1;
        let mut mismatched_endpoint = identity.clone();
        mismatched_endpoint.socket_local_endpoint = SocketAddr::new(
            identity.socket_local_endpoint.ip(),
            identity.socket_local_endpoint.port().wrapping_add(1),
        );
        for mismatched in [
            mismatched_peer,
            mismatched_token,
            mismatched_network,
            mismatched_candidate_epoch,
            mismatched_local_profile,
            mismatched_remote_profile,
            mismatched_punch,
            mismatched_index,
            mismatched_endpoint,
        ] {
            assert!(
                !hard_hard_exact_direct_confirmation_is_current(&udp, &peers, &mismatched).await,
                "every HardHardFreshSocketIdentity field must be authoritative"
            );
        }
        udp.detach_all_dynamic_punch_sockets("test_exact_proof")
            .await;
    }

    #[test]
    fn coordination_envelope_round_trips_directional_fences() {
        let offer = HardHardCoordination {
            role: HardHardRole::Initiator,
            token: "deadbeef01".to_string(),
            local_network_generation: 7,
            remote_candidate_epoch: 11,
            local_profile_generation: 13,
            remote_profile_generation: 19,
            local_prediction_confidence: 83,
            remote_prediction_confidence: 0,
            local_prediction_model: "fixed_step".to_string(),
            remote_prediction_model: "unknown".to_string(),
            remote_network_generation: 0,
        };
        let encoded = offer.encode();
        assert!(encoded.len() < 128);
        assert_eq!(HardHardCoordination::parse(&encoded), Some(offer));

        let response = HardHardCoordination::parse(&encoded)
            .expect("encoded offer must parse")
            .as_response(
                crate::peer::HardHardPlanSnapshot {
                    local_network_generation: 23,
                    remote_candidate_epoch: 23,
                    local_profile_generation: 29,
                    remote_profile_generation: 13,
                },
                71,
                "small_window".to_string(),
            );
        assert_eq!(response.role, HardHardRole::Responder);
        assert_eq!(response.token, "deadbeef01");
        assert_eq!(response.local_network_generation, 23);
        assert_eq!(response.remote_candidate_epoch, 23);
        assert_eq!(response.local_profile_generation, 29);
        assert_eq!(response.remote_profile_generation, 13);
        assert_eq!(response.local_prediction_confidence, 71);
        assert_eq!(response.remote_prediction_confidence, 83);
        assert_eq!(
            HardHardCoordination::parse(&response.encode()),
            Some(response)
        );
    }

    #[test]
    fn malformed_or_oversized_session_envelopes_fail_closed() {
        assert!(!HardHardCoordination::looks_like("peer-session"));
        assert!(HardHardCoordination::parse("hh1:x:token:1:2:1:2").is_none());
        assert!(HardHardCoordination::parse("hh1:i:not*hex:1:2:1:2").is_none());
        assert!(
            HardHardCoordination::parse(&format!("hh1:i:{}:1:2:1:2", "a".repeat(33))).is_none()
        );
        assert!(HardHardCoordination::parse("hh1:i:token:1:2:1:2:bad").is_none());
        assert!(HardHardCoordination::parse("hh1:i:token:1:2:1:2:1:2:extra").is_none());
    }

    #[test]
    fn session_fence_requires_all_generation_domains_to_match() {
        let expected = crate::peer::HardHardPlanSnapshot {
            local_network_generation: 4,
            remote_candidate_epoch: 9,
            local_profile_generation: 12,
            remote_profile_generation: 12,
        };
        assert!(hard_hard_plan_matches(expected, expected));
        for changed in [
            crate::peer::HardHardPlanSnapshot {
                local_network_generation: 5,
                ..expected
            },
            crate::peer::HardHardPlanSnapshot {
                remote_candidate_epoch: 10,
                ..expected
            },
            crate::peer::HardHardPlanSnapshot {
                local_profile_generation: 5,
                ..expected
            },
            crate::peer::HardHardPlanSnapshot {
                remote_profile_generation: 13,
                ..expected
            },
        ] {
            assert!(!hard_hard_plan_matches(expected, changed));
        }
    }

    #[test]
    fn coordination_round_trip_exchanges_both_network_generations() {
        let offer = HardHardCoordination {
            role: HardHardRole::Initiator,
            token: "a1b2c3".to_string(),
            local_network_generation: 17,
            remote_candidate_epoch: 23,
            local_profile_generation: 29,
            remote_profile_generation: 31,
            local_prediction_confidence: 91,
            remote_prediction_confidence: 0,
            local_prediction_model: "fixed_step".to_string(),
            remote_prediction_model: "unknown".to_string(),
            remote_network_generation: 0,
        };
        let response = offer.as_response(
            crate::peer::HardHardPlanSnapshot {
                local_network_generation: 41,
                remote_candidate_epoch: 43,
                local_profile_generation: 47,
                remote_profile_generation: 29,
            },
            88,
            "high_entropy".to_string(),
        );
        assert_eq!(response.local_network_generation, 41);
        assert_eq!(response.remote_network_generation, 17);
        assert_eq!(response.remote_prediction_confidence, 91);
        assert_eq!(
            HardHardCoordination::parse(&response.encode()),
            Some(response)
        );
    }

    #[test]
    fn fixed_step_models_drive_unequal_stride_cross_sweeps() {
        fn model_window(start: u16, step: u16) -> Vec<u16> {
            let local = "0.0.0.0:41000".parse().unwrap();
            let observations = (0..4)
                .map(|sequence| p2pnet_nat::mapping::MappingObservation {
                    sequence,
                    observer: SocketAddr::new("192.0.2.1".parse().unwrap(), 3478 + sequence),
                    observed: SocketAddr::new(
                        "198.51.100.10".parse().unwrap(),
                        start.wrapping_add(step.wrapping_mul(sequence)),
                    ),
                    sent_at_ms: 1_000 + u64::from(sequence) * 10,
                    responded_at_ms: 1_005 + u64::from(sequence) * 10,
                    local_endpoint: local,
                })
                .collect();
            let batch = p2pnet_nat::mapping::MappingBatch {
                generation: 7,
                network_generation: 3,
                socket_identity: local,
                observations,
                started_at_ms: 1_000,
                finished_at_ms: 1_100,
            };
            let model =
                p2pnet_nat::mapping::build_model_for_batch(&batch, Duration::from_secs(5), 1_100)
                    .expect("the deterministic APDM sequence must model");
            p2pnet_nat::mapping::predict_ports(&model, start.wrapping_add(step * 3))
                .into_iter()
                .map(|candidate| candidate.port)
                .collect()
        }

        let a_window = model_window(30_000, 4);
        let b_window = model_window(40_000, 3);
        assert!(a_window.contains(&30_016));
        assert!(b_window.contains(&40_012));
        // Each side sweeps the other side's actual fresh window; no common
        // stride or equal window length is assumed by the coordinator.
        assert!(!a_window.is_empty() && !b_window.is_empty());

        let a_plus_one = model_window(50_000, 1);
        let b_plus_seven = model_window(55_000, 7);
        assert!(a_plus_one.contains(&50_004));
        assert!(b_plus_seven.contains(&55_028));
    }

    #[test]
    fn prediction_windows_and_punch_time_are_bounded_at_udp_edges() {
        let local = "0.0.0.0:41001".parse().unwrap();
        let observations = (0..4)
            .map(|sequence| p2pnet_nat::mapping::MappingObservation {
                sequence,
                observer: SocketAddr::new("192.0.2.2".parse().unwrap(), 4000 + sequence),
                observed: SocketAddr::new(
                    "198.51.100.11".parse().unwrap(),
                    65_520u16.wrapping_add(4 * sequence),
                ),
                sent_at_ms: 2_000 + u64::from(sequence),
                responded_at_ms: 2_001 + u64::from(sequence),
                local_endpoint: local,
            })
            .collect();
        let batch = p2pnet_nat::mapping::MappingBatch {
            generation: 8,
            network_generation: 4,
            socket_identity: local,
            observations,
            started_at_ms: 2_000,
            finished_at_ms: 2_010,
        };
        let model =
            p2pnet_nat::mapping::build_model_for_batch(&batch, Duration::from_secs(5), 2_010)
                .unwrap();
        let window = p2pnet_nat::mapping::predict_ports(&model, 65_532);
        assert!(!window.iter().any(|candidate| candidate.port == 0));
        assert_eq!(window.first().map(|candidate| candidate.port), Some(4));

        let now = 10_000;
        assert!(hard_hard_punch_window_is_usable(now, now + 1_300));
        // A modest ±50ms scheduling jitter stays inside the bounded window;
        // an expired punch deadline does not.
        assert!(hard_hard_punch_window_is_usable(now + 50, now + 1_301));
        assert_eq!(
            hard_hard_punch_window(now, now + 1_250),
            HardHardPunchWindow::TooSoon
        );
        assert_eq!(
            hard_hard_punch_window(now, now + 1_251),
            HardHardPunchWindow::Usable
        );
        assert_eq!(
            hard_hard_punch_window(now, now + HARD_HARD_SESSION_TTL.as_millis() as u64 + 1),
            HardHardPunchWindow::BeyondFreshLifetime
        );
        assert!(!hard_hard_punch_window_is_usable(
            now,
            now + HARD_HARD_SESSION_TTL.as_millis() as u64 + 1
        ));
    }

    #[tokio::test]
    async fn session_ledger_supersedes_old_token_and_cleans_up_100_cycles() {
        fn record(
            peer_id: &str,
            token: &str,
            cancellation: Arc<crate::PunchSessionCancellation>,
        ) -> crate::peer::HardHardSessionRecord {
            let endpoint = "0.0.0.0:41002".parse().unwrap();
            let identity = crate::peer::HardHardFreshSocketIdentity {
                peer_id: peer_id.to_string(),
                session_token: token.to_string(),
                network_generation: 1,
                remote_candidate_epoch: 2,
                local_profile_generation: 3,
                remote_profile_generation: 4,
                punch_generation: 5,
                socket_index: 4_096,
                socket_local_endpoint: endpoint,
            };
            crate::peer::HardHardSessionRecord {
                session_id: format!("hh1:i:{token}:1:2:3:4:90:0:0"),
                probe_session_id: None,
                session_token: token.to_string(),
                peer_id: peer_id.to_string(),
                initiator: true,
                remote_network_generation: 0,
                local_network_generation: 1,
                remote_candidate_epoch: 2,
                local_profile_generation: 3,
                remote_profile_generation: 4,
                local_prediction_confidence: 90,
                remote_prediction_confidence: 0,
                requested_birthday_level: 0,
                generated_candidate_count: 1,
                signaled_candidate_count: 1,
                birthday: false,
                requested_socket_indices: vec![4_096],
                requested_socket_count: 1,
                prediction_window: vec!["198.51.100.1:40000".parse().unwrap()],
                remote_prediction: Vec::new(),
                fresh_socket: identity,
                punch_at_ms: hard_hard_now_ms() + 3_000,
                expires_at_ms: hard_hard_now_ms() + 45_000,
                state: crate::peer::HardHardSessionState::AwaitingPeer,
                attempt_count: 0,
                created_at: Instant::now(),
                cancellation,
            }
        }

        let manager = crate::peer::PeerManager::new(
            crate::Config::generate_default("https://ctrl.test", "hard-hard-tests").unwrap(),
        );
        let first_cancel = Arc::new(crate::PunchSessionCancellation::default());
        assert!(
            manager
                .hard_hard_register_session(record(
                    "peer-session-ledger",
                    "a1",
                    first_cancel.clone()
                ))
                .await
        );
        assert!(
            manager
                .hard_hard_session_token_is_current("peer-session-ledger", "a1")
                .await
        );
        assert_eq!(
            manager
                .hard_hard_prepare_response("peer-session-ledger", "a1", 3)
                .await,
            crate::peer::HardHardResponseAdmission::Ready
        );
        let rebound = manager
            .hard_hard_session_by_token("peer-session-ledger", "a1")
            .await
            .expect("the live initiator session must survive its one expected remote epoch");
        assert_eq!(rebound.remote_candidate_epoch, 3);
        assert_eq!(rebound.fresh_socket.remote_candidate_epoch, 3);
        assert!(manager
            .hard_hard_begin_sweep(
                "peer-session-ledger",
                "a1",
                vec!["198.51.100.2:40000".parse().unwrap()],
                90,
                1,
            )
            .await
            .is_some());
        assert_eq!(
            manager
                .hard_hard_prepare_response("peer-session-ledger", "a1", 3)
                .await,
            crate::peer::HardHardResponseAdmission::AlreadySweeping
        );

        let second_cancel = Arc::new(crate::PunchSessionCancellation::default());
        assert!(
            manager
                .hard_hard_register_session(record(
                    "peer-session-ledger",
                    "b2",
                    second_cancel.clone()
                ))
                .await
        );
        assert!(first_cancel.is_cancelled());
        assert!(
            !manager
                .hard_hard_session_token_is_current("peer-session-ledger", "a1")
                .await
        );
        assert!(
            manager
                .hard_hard_session_token_is_current("peer-session-ledger", "b2")
                .await
        );

        for index in 0..100u64 {
            let token = format!("{index:x}");
            let cancellation = Arc::new(crate::PunchSessionCancellation::default());
            assert!(
                manager
                    .hard_hard_register_session(
                        record("peer-session-ledger", &token, cancellation,)
                    )
                    .await
            );
        }
        manager
            .clear_hard_hard_sessions(Some("peer-session-ledger"))
            .await;
        assert!(
            !manager
                .hard_hard_session_is_active("peer-session-ledger")
                .await
        );
        assert!(second_cancel.is_cancelled());
    }
}
