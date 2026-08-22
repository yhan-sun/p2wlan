// Hard↔Hard synchronized fresh-mapping rendezvous.
//
// This is intentionally a narrow integration around the existing fresh
// mapping, `peer_offer_fresh`, Probe v2, pending-probe and Direct validation
// machinery. It does not introduce a second wire protocol or promote a path:
// the existing authenticated ACK and PathSelector remain authoritative.

const HARD_HARD_SESSION_PREFIX: &str = "hh1";
const HARD_HARD_PUNCH_LEAD: Duration = Duration::from_millis(3_500);
const HARD_HARD_MIN_RESPONSE_LEAD: Duration = Duration::from_millis(1_250);
const HARD_HARD_SESSION_TTL: Duration = Duration::from_secs(45);
const HARD_HARD_SWEEP_DEADLINE: Duration = Duration::from_secs(3);
const HARD_HARD_SWEEP_INTERVAL: Duration = Duration::from_millis(20);
const HARD_HARD_SWEEP_ATTEMPTS: u32 = 2;

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
        })
    }

    fn encode(&self) -> String {
        format!(
            "{HARD_HARD_SESSION_PREFIX}:{}:{}:{}:{}:{}:{}:{}:{}",
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
        )
    }

    fn as_response(
        &self,
        snapshot: crate::peer::HardHardPlanSnapshot,
        local_prediction_confidence: u8,
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
        }
    }
}

fn hard_hard_now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
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
    let mut candidates = Vec::with_capacity(result.predicted_ports.len());
    let mut sources = HashMap::with_capacity(result.predicted_ports.len());
    for port in &result.predicted_ports {
        let endpoint = SocketAddr::new(public_ip, *port).to_string();
        if !candidates.contains(&endpoint) {
            candidates.push(endpoint.clone());
            sources.insert(endpoint, fresh_label.clone());
        }
    }
    (!candidates.is_empty()).then_some((candidates, sources))
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
) {
    let Some(plan) = peers.hard_hard_plan_for_peer(&peer_id).await else {
        return;
    };
    if signal.boot_epoch_ms == 0 || signal.stun_servers.len() < 3 {
        peers
            .record_direct_event(
                &peer_id,
                "hard_hard_skipped",
                None,
                None,
                None,
                "Hard↔Hard requires a trustworthy boot incarnation and at least three STUN observers; Relay remains available",
            )
            .await;
        return;
    }
    let RecoveryAdmission::Accepted { epoch } = peers.recovery_epoch_admit(&peer_id).await else {
        return;
    };
    if !peers.try_begin_fresh_generation(&peer_id).await {
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
        return;
    }
    let punch_at_ms = hard_hard_now_ms().saturating_add(HARD_HARD_PUNCH_LEAD.as_millis() as u64);
    let session = match punch_deduplicator
        .claim_for_epoch_with_rendezvous(
            &peer_id,
            plan.local_network_generation,
            epoch,
            PUNCH_PRIORITY_FRESH_PREDICTION,
            None,
            Some(punch_at_ms),
        )
        .await
    {
        RendezvousPunchClaim::Claimed(session) => session,
        RendezvousPunchClaim::Deferred(deferred) => {
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
            return;
        }
    };
    let token = hard_hard_session_token(session.session_id());
    let coordination = hard_hard_coordination_from_plan(token, HardHardRole::Initiator, plan);
    let cancellation = session.cancellation_handle();
    tokio::spawn(async move {
        let outcome = udp
            .run_hard_hard_fresh_mapping_generation(
                &peer_id,
                &signal.stun_servers,
                signal.stun_timeout,
                Some(&cancellation),
            )
            .await;
        let FreshMappingOutcome::Accepted(result, handoff) = outcome else {
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
        let Some((candidates, candidate_sources)) =
            hard_hard_prediction_payload(&result, signal.boot_epoch_ms)
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
        let mut coordination = coordination;
        coordination.local_prediction_confidence = result.model.confidence;
        let session_id = coordination.encode();
        let record = HardHardSessionRecord {
            session_id: session_id.clone(),
            peer_id: peer_id.clone(),
            initiator: true,
            local_network_generation: plan.local_network_generation,
            remote_candidate_epoch: plan.remote_candidate_epoch,
            local_profile_generation: plan.local_profile_generation,
            remote_profile_generation: plan.remote_profile_generation,
            local_prediction_confidence: result.model.confidence,
            socket_index: Some(result.socket_index),
            punch_generation: Some(result.punch_generation),
            punch_at_ms,
            expires_at_ms: hard_hard_now_ms()
                .saturating_add(HARD_HARD_SESSION_TTL.as_millis() as u64),
            state: HardHardSessionState::AwaitingPeer,
            attempt_count: 0,
            created_at: Instant::now(),
        };
        if !peers.hard_hard_register_session(record).await {
            peers.hard_hard_remove_session(&peer_id, &session_id).await;
            return;
        }
        let advertised = if peers.try_consume_recovery_http_quota(&peer_id).await {
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
        if !advertised || cancellation.is_cancelled() || peers.is_direct(&peer_id).await {
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
            peers.hard_hard_remove_session(&peer_id, &session_id).await;
            return;
        }
        if !handoff.finalize().await {
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
            peers.hard_hard_remove_session(&peer_id, &session_id).await;
            return;
        }
        peers
            .record_direct_event(
                &peer_id,
                "hard_hard_prediction_signaled",
                None,
                Some(candidates.len()),
                None,
                format!(
                    "session_id={} punch_at_ms={} socket_index={} punch_generation={} local_network_generation={} remote_candidate_epoch={} local_profile_generation={} remote_profile_generation={} local_prediction_confidence={} attempts_bounded={HARD_HARD_SWEEP_ATTEMPTS}",
                    session_id,
                    punch_at_ms,
                    result.socket_index,
                    result.punch_generation,
                    plan.local_network_generation,
                    plan.remote_candidate_epoch,
                    plan.local_profile_generation,
                    plan.remote_profile_generation,
                    result.model.confidence,
                ),
            )
            .await;
        // The initiator's exact-socket sweep starts only when the responder's
        // reciprocal prediction arrives.  Relay continues to carry data while
        // this short response fence is pending.
    });
}

/// Start the responder half after an authenticated fresh prediction was
/// admitted by the existing candidate transaction.
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
) {
    let now = hard_hard_now_ms();
    if punch_at_ms <= now.saturating_add(HARD_HARD_MIN_RESPONSE_LEAD.as_millis() as u64) {
        peers
            .record_direct_event(
                &peer_id,
                "hard_hard_late_offer",
                remote_prediction.first().copied(),
                Some(remote_prediction.len()),
                None,
                "Hard↔Hard offer arrived too late for a fresh local measurement; Relay remains usable",
            )
            .await;
        return;
    }
    let Some(plan) = peers.hard_hard_plan_for_peer(&peer_id).await else {
        return;
    };
    if coordination.role != HardHardRole::Initiator
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
        return;
    }
    let RecoveryAdmission::Accepted { epoch } = peers.recovery_epoch_admit(&peer_id).await else {
        return;
    };
    if !peers.try_begin_fresh_generation(&peer_id).await {
        peers
            .record_direct_event(
                &peer_id,
                "hard_hard_fresh_generation_quota_exhausted",
                None,
                None,
                None,
                "Hard↔Hard responder fresh-generation quota exhausted for this recovery epoch; Relay remains usable",
            )
            .await;
        return;
    }
    let session = match punch_deduplicator
        .claim_for_epoch_with_rendezvous(
            &peer_id,
            plan.local_network_generation,
            epoch,
            PUNCH_PRIORITY_FRESH_PREDICTION,
            None,
            Some(punch_at_ms),
        )
        .await
    {
        RendezvousPunchClaim::Claimed(session) => session,
        RendezvousPunchClaim::Deferred(_) => return,
    };
    let cancellation = session.cancellation_handle();
    let session_id = coordination.encode();
    tokio::spawn(async move {
        let outcome = udp
            .run_hard_hard_fresh_mapping_generation(
                &peer_id,
                &signal.stun_servers,
                signal.stun_timeout,
                Some(&cancellation),
            )
            .await;
        let FreshMappingOutcome::Accepted(result, handoff) = outcome else {
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
        let Some(current_plan) = peers.hard_hard_plan_for_peer(&peer_id).await else {
            return;
        };
        if cancellation.is_cancelled()
            || peers.is_direct(&peer_id).await
            || current_plan.local_network_generation != plan.local_network_generation
            || current_plan.local_profile_generation != plan.local_profile_generation
            || current_plan.remote_profile_generation != plan.remote_profile_generation
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
        let Some((candidates, candidate_sources)) =
            hard_hard_prediction_payload(&result, signal.boot_epoch_ms)
        else {
            return;
        };
        let response_coordination =
            coordination.as_response(current_plan, result.model.confidence);
        let record = HardHardSessionRecord {
            session_id: session_id.clone(),
            peer_id: peer_id.clone(),
            initiator: false,
            local_network_generation: current_plan.local_network_generation,
            remote_candidate_epoch: current_plan.remote_candidate_epoch,
            local_profile_generation: current_plan.local_profile_generation,
            remote_profile_generation: current_plan.remote_profile_generation,
            local_prediction_confidence: result.model.confidence,
            socket_index: Some(result.socket_index),
            punch_generation: Some(result.punch_generation),
            punch_at_ms,
            expires_at_ms: hard_hard_now_ms()
                .saturating_add(HARD_HARD_SESSION_TTL.as_millis() as u64),
            state: HardHardSessionState::AwaitingPeer,
            attempt_count: 0,
            created_at: Instant::now(),
        };
        if !peers.hard_hard_register_session(record).await {
            return;
        }
        let sent = if peers.try_consume_recovery_http_quota(&peer_id).await {
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
        if !sent || cancellation.is_cancelled() || !handoff.finalize().await {
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
            return;
        }
        hard_hard_wait_and_sweep(
            udp,
            peers.clone(),
            session,
            peer_id.clone(),
            result.socket_index,
            remote_prediction,
            punch_at_ms,
            plan.local_network_generation,
            (plan.local_profile_generation, plan.remote_profile_generation),
            "responder",
        )
        .await;
        peers
            .hard_hard_remove_session(&peer_id, &session_id)
            .await;
    });
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
) {
    if coordination.role != HardHardRole::Responder {
        return;
    }
    let Some(record) = peers
        .hard_hard_session_by_token(&peer_id, &coordination.token)
        .await
    else {
        return;
    };
    let Some(current_plan) = peers.hard_hard_plan_for_peer(&peer_id).await else {
        return;
    };
    if !record.initiator
        || record.state != HardHardSessionState::AwaitingPeer
        || record.attempt_count >= 1
        || record.local_network_generation
            != peers
                .current_network_generation_sync()
        || current_plan.local_network_generation != record.local_network_generation
        || current_plan.local_profile_generation != record.local_profile_generation
        || current_plan.remote_profile_generation != record.remote_profile_generation
        || coordination.local_profile_generation != record.remote_profile_generation
        || coordination.remote_profile_generation != record.local_profile_generation
        || coordination.local_prediction_confidence == 0
        || coordination.remote_prediction_confidence != record.local_prediction_confidence
        || punch_at_ms != record.punch_at_ms
        || record.punch_generation.is_none()
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
        return;
    }
    let current_epoch = peers
        .current_remote_candidate_epoch(&peer_id)
        .await
        .unwrap_or_default();
    // Applying the reciprocal fresh candidate set is the one expected remote
    // candidate-epoch transition. Any additional transition means the
    // response raced a newer candidate session and is rejected.
    let expected_next = record.remote_candidate_epoch.wrapping_add(1).max(1);
    if current_epoch != record.remote_candidate_epoch && current_epoch != expected_next {
        peers
            .record_direct_event(
                &peer_id,
                "hard_hard_response_fenced",
                remote_prediction.first().copied(),
                Some(remote_prediction.len()),
                None,
                format!(
                    "Hard↔Hard reciprocal response remote_candidate_epoch={} expected {} or {}",
                    current_epoch, record.remote_candidate_epoch, expected_next
                ),
            )
            .await;
        return;
    }
    let Some(socket_index) = record.socket_index else {
        return;
    };
    let RecoveryAdmission::Accepted { epoch } = peers.recovery_epoch_admit(&peer_id).await else {
        return;
    };
    let session = match punch_deduplicator
        .claim_for_epoch_with_rendezvous(
            &peer_id,
            record.local_network_generation,
            epoch,
            PUNCH_PRIORITY_FRESH_PREDICTION,
            None,
            Some(punch_at_ms),
        )
        .await
    {
        RendezvousPunchClaim::Claimed(session) => session,
        RendezvousPunchClaim::Deferred(_) => return,
    };
    let Some(record) = peers
        .hard_hard_begin_sweep(&peer_id, &coordination.token)
        .await
    else {
        return;
    };
    hard_hard_wait_and_sweep(
        udp,
        peers.clone(),
        session,
        peer_id.clone(),
        socket_index,
        remote_prediction,
        punch_at_ms,
        record.local_network_generation,
        (record.local_profile_generation, record.remote_profile_generation),
        "initiator",
    )
    .await;
    peers
        .hard_hard_remove_session(&peer_id, &record.session_id)
        .await;
}

#[allow(clippy::too_many_arguments)]
async fn hard_hard_wait_and_sweep(
    udp: UdpTransport,
    peers: Arc<PeerManager>,
    session: PunchSessionPermit,
    peer_id: String,
    socket_index: usize,
    targets: Vec<SocketAddr>,
    punch_at_ms: u64,
    network_generation: u64,
    profile_generations: (u64, u64),
    origin: &'static str,
) {
    let delay = punch_at_ms.saturating_sub(hard_hard_now_ms());
    if delay > 0 {
        tokio::select! {
            _ = sleep(Duration::from_millis(delay)) => {}
            _ = session.cancelled() => return,
        }
    }
    if session.is_cancelled()
        || peers.is_direct(&peer_id).await
        || peers.current_network_generation_sync() != network_generation
    {
        return;
    }
    let dispatch_at_ms = session.mark_first_send_started();
    let cancellation = session.cancellation_handle();
    let mut report = None;
    let outcome = run_owned_punch_session_with_deadline(
        &session,
        HARD_HARD_SWEEP_DEADLINE,
        async {
            report = Some(
                udp.punch_candidates_from_dynamic_socket_index_with_profile_fence(
                    &peer_id,
                    socket_index,
                    targets.clone(),
                    HARD_HARD_SWEEP_INTERVAL,
                    HARD_HARD_SWEEP_ATTEMPTS,
                    Some(profile_generations),
                )
                .await,
            );
        },
    )
    .await;
    match (outcome, report) {
        (PunchSessionOutcome::Completed, Some(Ok(report))) => {
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
                        "origin={origin} dispatch_at_ms={dispatch_at_ms} actual_first_send_at_ms={:?} punch_at_ms={} unique_targets={} budget_skipped={} exact_socket=true",
                        report.first_send_at_ms,
                        punch_at_ms,
                        report.unique_target_endpoints,
                        report.budget_skipped,
                    ),
                )
                .await;
        }
        (PunchSessionOutcome::Completed, Some(Err(error))) => {
            peers
                .record_direct_event(
                    &peer_id,
                    "hard_hard_sweep_failed",
                    targets.first().copied(),
                    Some(targets.len()),
                    None,
                    format!("origin={origin} exact-socket sweep error: {error}"),
                )
                .await;
        }
        (PunchSessionOutcome::DeadlineExceeded, _) => {
            peers
                .record_direct_event(
                    &peer_id,
                    "hard_hard_sweep_deadline",
                    targets.first().copied(),
                    Some(targets.len()),
                    None,
                    format!("origin={origin} exact-socket sweep exceeded bounded deadline"),
                )
                .await;
        }
        (PunchSessionOutcome::Cancelled, _) => {}
        _ => {}
    }
    let _ = cancellation;
}

#[cfg(test)]
mod hard_hard_tests {
    use super::*;

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
            );
        assert_eq!(response.role, HardHardRole::Responder);
        assert_eq!(response.token, "deadbeef01");
        assert_eq!(response.local_network_generation, 23);
        assert_eq!(response.remote_candidate_epoch, 23);
        assert_eq!(response.local_profile_generation, 29);
        assert_eq!(response.remote_profile_generation, 13);
        assert_eq!(response.local_prediction_confidence, 71);
        assert_eq!(response.remote_prediction_confidence, 83);
        assert_eq!(HardHardCoordination::parse(&response.encode()), Some(response));
    }

    #[test]
    fn malformed_or_oversized_session_envelopes_fail_closed() {
        assert!(!HardHardCoordination::looks_like("peer-session"));
        assert!(HardHardCoordination::parse("hh1:x:token:1:2:1:2").is_none());
        assert!(HardHardCoordination::parse("hh1:i:not*hex:1:2:1:2").is_none());
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
}
