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
