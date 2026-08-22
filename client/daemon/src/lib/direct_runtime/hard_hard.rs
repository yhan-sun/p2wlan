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
const HARD_HARD_DIRECT_CONFIRMATION_GRACE: Duration = Duration::from_secs(1);
const HARD_HARD_SWEEP_INTERVAL: Duration = Duration::from_millis(20);
const HARD_HARD_SWEEP_ATTEMPTS: u32 = 2;
const HARD_HARD_MAX_PREDICTION_TARGETS: usize = 96;

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
        })
    }

    fn encode(&self) -> String {
        format!(
            "{HARD_HARD_SESSION_PREFIX}:{}:{}:{}:{}:{}:{}:{}:{}:{}",
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
            remote_network_generation: self.local_network_generation,
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
        remote_network_generation: 0,
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

fn hard_hard_prediction_targets(candidates: &[String]) -> Vec<SocketAddr> {
    candidates
        .iter()
        .filter_map(|candidate| candidate.parse::<SocketAddr>().ok())
        .take(HARD_HARD_MAX_PREDICTION_TARGETS)
        .collect()
}

fn hard_hard_punch_window_is_usable(now_ms: u64, punch_at_ms: u64) -> bool {
    punch_at_ms > now_ms.saturating_add(HARD_HARD_MIN_RESPONSE_LEAD.as_millis() as u64)
        && punch_at_ms <= now_ms.saturating_add(HARD_HARD_SESSION_TTL.as_millis() as u64)
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
    if peers.hard_hard_session_is_active(&peer_id).await {
        return;
    }
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
        let prediction_window = hard_hard_prediction_targets(&candidates);
        let record = HardHardSessionRecord {
            session_id: session_id.clone(),
            session_token: coordination.token.clone(),
            peer_id: peer_id.clone(),
            initiator: true,
            remote_network_generation: 0,
            local_network_generation: plan.local_network_generation,
            remote_candidate_epoch: plan.remote_candidate_epoch,
            local_profile_generation: plan.local_profile_generation,
            remote_profile_generation: plan.remote_profile_generation,
            local_prediction_confidence: result.model.confidence,
            remote_prediction_confidence: 0,
            prediction_window,
            remote_prediction: Vec::new(),
            fresh_socket: hard_hard_socket_identity(
                &peer_id,
                &coordination.token,
                &result,
                plan,
            ),
            punch_at_ms,
            expires_at_ms: hard_hard_now_ms()
                .saturating_add(HARD_HARD_SESSION_TTL.as_millis() as u64),
            state: HardHardSessionState::AwaitingPeer,
            attempt_count: 0,
            created_at: Instant::now(),
            cancellation: cancellation.clone(),
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
        spawn_hard_hard_expiry_cleanup(
            udp.clone(),
            peers.clone(),
            peer_id.clone(),
            session_id.clone(),
            hard_hard_socket_identity(
                &peer_id,
                &coordination.token,
                &result,
                plan,
            ),
            cancellation.clone(),
            hard_hard_now_ms().saturating_add(HARD_HARD_SESSION_TTL.as_millis() as u64),
        );
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
    if remote_prediction.is_empty()
        || remote_prediction.len() > HARD_HARD_MAX_PREDICTION_TARGETS
        || remote_prediction
            .iter()
            .any(|endpoint| endpoint.ip().is_unspecified())
        || !hard_hard_punch_window_is_usable(now, punch_at_ms)
    {
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
        let prediction_window = hard_hard_prediction_targets(&candidates);
        if prediction_window.is_empty() {
            return;
        }
        let record = HardHardSessionRecord {
            session_id: session_id.clone(),
            session_token: coordination.token.clone(),
            peer_id: peer_id.clone(),
            initiator: false,
            remote_network_generation: coordination.local_network_generation,
            local_network_generation: current_plan.local_network_generation,
            remote_candidate_epoch: current_plan.remote_candidate_epoch,
            local_profile_generation: current_plan.local_profile_generation,
            remote_profile_generation: current_plan.remote_profile_generation,
            local_prediction_confidence: result.model.confidence,
            remote_prediction_confidence: coordination.local_prediction_confidence,
            prediction_window,
            remote_prediction: remote_prediction.clone(),
            fresh_socket: hard_hard_socket_identity(
                &peer_id,
                &coordination.token,
                &result,
                current_plan,
            ),
            punch_at_ms,
            expires_at_ms: hard_hard_now_ms()
                .saturating_add(HARD_HARD_SESSION_TTL.as_millis() as u64),
            state: HardHardSessionState::AwaitingPeer,
            attempt_count: 0,
            created_at: Instant::now(),
            cancellation: cancellation.clone(),
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
            peers.hard_hard_remove_session(&peer_id, &session_id).await;
            return;
        }
        let fresh_socket = hard_hard_socket_identity(
            &peer_id,
            &coordination.token,
            &result,
            current_plan,
        );
        let cleanup_udp = udp.clone();
        let swept = hard_hard_wait_and_sweep(
            udp,
            peers.clone(),
            session,
            peer_id.clone(),
            fresh_socket.clone(),
            coordination.token.clone(),
            remote_prediction,
            punch_at_ms,
            current_plan.local_network_generation,
            (
                current_plan.local_profile_generation,
                current_plan.remote_profile_generation,
            ),
            "responder",
        )
        .await;
        let direct_on_fresh_socket = peers.is_direct(&peer_id).await
            && cleanup_udp
                .hard_hard_socket_identity_is_current(&fresh_socket)
                .await;
        if swept {
            if direct_on_fresh_socket || !peers.is_direct(&peer_id).await {
                spawn_hard_hard_expiry_cleanup(
                    cleanup_udp.clone(),
                    peers.clone(),
                    peer_id.clone(),
                    session_id.clone(),
                    fresh_socket.clone(),
                    cancellation,
                    hard_hard_now_ms().saturating_add(
                        HARD_HARD_SESSION_TTL.as_millis() as u64,
                    ),
                );
            } else {
                cleanup_udp
                    .detach_hard_hard_socket_if_identity(
                        &fresh_socket,
                        "hard_hard_direct_other_socket",
                    )
                    .await;
                peers.hard_hard_remove_session(&peer_id, &session_id).await;
            }
        } else {
            if !direct_on_fresh_socket {
                cleanup_udp
                    .detach_hard_hard_socket_if_identity(&fresh_socket, "hard_hard_sweep_failed")
                    .await;
            }
            peers.hard_hard_remove_session(&peer_id, &session_id).await;
        }
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
    if remote_prediction.is_empty() || remote_prediction.len() > HARD_HARD_MAX_PREDICTION_TARGETS {
        return;
    }
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
    if coordination.remote_network_generation != record.local_network_generation {
        peers
            .record_direct_event(
                &peer_id,
                "hard_hard_response_fenced",
                remote_prediction.first().copied(),
                Some(remote_prediction.len()),
                None,
                "Hard↔Hard reciprocal response carried a different initiator network generation",
            )
            .await;
        return;
    }
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
        return;
    };
    if !udp
        .hard_hard_socket_identity_is_current(&record.fresh_socket)
        .await
    {
        peers
            .hard_hard_remove_session(&peer_id, &record.session_id)
            .await;
        return;
    }
    let fresh_socket = record.fresh_socket.clone();
    let cleanup_udp = udp.clone();
    let swept = hard_hard_wait_and_sweep(
        udp,
        peers.clone(),
        session,
        peer_id.clone(),
        fresh_socket.clone(),
        record.session_token.clone(),
        remote_prediction,
        punch_at_ms,
        record.local_network_generation,
        (record.local_profile_generation, record.remote_profile_generation),
        "initiator",
    )
    .await;
    let direct_on_fresh_socket = peers.is_direct(&peer_id).await
        && cleanup_udp
            .hard_hard_socket_identity_is_current(&fresh_socket)
            .await;
    if swept {
        if direct_on_fresh_socket || !peers.is_direct(&peer_id).await {
            spawn_hard_hard_expiry_cleanup(
                cleanup_udp.clone(),
                peers.clone(),
                peer_id.clone(),
                record.session_id.clone(),
                fresh_socket.clone(),
                record.cancellation,
                record.expires_at_ms,
            );
        } else {
            cleanup_udp
                .detach_hard_hard_socket_if_identity(
                    &fresh_socket,
                    "hard_hard_direct_other_socket",
                )
                .await;
            peers
                .hard_hard_remove_session(&record.peer_id, &record.session_id)
                .await;
        }
    } else {
        if !direct_on_fresh_socket {
            cleanup_udp
                .detach_hard_hard_socket_if_identity(&fresh_socket, "hard_hard_sweep_failed")
                .await;
        }
        peers
            .hard_hard_remove_session(&record.peer_id, &record.session_id)
            .await;
    }
}

#[allow(clippy::too_many_arguments)]
async fn hard_hard_wait_and_sweep(
    udp: UdpTransport,
    peers: Arc<PeerManager>,
    session: PunchSessionPermit,
    peer_id: String,
    fresh_socket: crate::peer::HardHardFreshSocketIdentity,
    session_token: String,
    targets: Vec<SocketAddr>,
    punch_at_ms: u64,
    network_generation: u64,
    profile_generations: (u64, u64),
    origin: &'static str,
) -> bool {
    let socket_index = fresh_socket.socket_index;
    let delay = punch_at_ms.saturating_sub(hard_hard_now_ms());
    if delay > 0 {
        tokio::select! {
            _ = sleep(Duration::from_millis(delay)) => {}
            _ = session.cancelled() => return false,
        }
    }
    if session.is_cancelled()
        || peers.is_direct(&peer_id).await
        || peers.current_network_generation_sync() != network_generation
        || !udp
            .hard_hard_socket_identity_is_current(&fresh_socket)
            .await
    {
        return false;
    }
    let dispatch_at_ms = session.mark_first_send_started();
    let direct_commit_seq = peers.direct_commit_seq_sync(&peer_id);
    let mut report = None;
    let outcome = run_owned_punch_session_with_deadline(
        &session,
        HARD_HARD_SWEEP_DEADLINE,
        async {
            report = Some(
                udp.punch_candidates_from_dynamic_socket_index_with_profile_fence_and_session(
                    &peer_id,
                    socket_index,
                    targets.clone(),
                    HARD_HARD_SWEEP_INTERVAL,
                    HARD_HARD_SWEEP_ATTEMPTS,
                    Some(profile_generations),
                    Some(&session_token),
                )
                .await,
            );
        },
    )
    .await;
    match (outcome, report) {
        (PunchSessionOutcome::Completed, Some(Ok(report))) => {
            let direct_confirmed = if report.packets_sent == 0 {
                false
            } else if peers.is_direct(&peer_id).await {
                true
            } else {
                tokio::select! {
                    _ = session.cancelled() => peers.is_direct(&peer_id).await,
                    _ = peers.wait_for_direct_commit_or_timeout(
                        &peer_id,
                        direct_commit_seq,
                        HARD_HARD_DIRECT_CONFIRMATION_GRACE,
                    ) => peers.is_direct(&peer_id).await,
                }
            };
            if direct_confirmed {
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
                            "origin={origin} exact-socket sweep found no authenticated Direct confirmation within {:?}",
                            HARD_HARD_DIRECT_CONFIRMATION_GRACE,
                        ),
                    )
                    .await;
            }
            direct_confirmed
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
            false
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
            false
        }
        (PunchSessionOutcome::Cancelled, _) => false,
        _ => false,
    }
}

fn spawn_hard_hard_expiry_cleanup(
    udp: UdpTransport,
    peers: Arc<PeerManager>,
    peer_id: String,
    session_id: String,
    fresh_socket: crate::peer::HardHardFreshSocketIdentity,
    cancellation: Arc<crate::PunchSessionCancellation>,
    expires_at_ms: u64,
) {
    tokio::spawn(async move {
        let delay = expires_at_ms.saturating_sub(hard_hard_now_ms());
        tokio::select! {
            _ = sleep(Duration::from_millis(delay)) => {}
            _ = cancellation.cancelled() => {}
        }
        let retain_fresh_socket = peers.is_direct(&peer_id).await
            && udp
                .hard_hard_socket_identity_is_current(&fresh_socket)
                .await;
        if !retain_fresh_socket {
            udp.detach_hard_hard_socket_if_identity(&fresh_socket, "hard_hard_session_expired").await;
        }
        peers.hard_hard_remove_session(&peer_id, &session_id).await;
    });
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
        );
        assert_eq!(response.local_network_generation, 41);
        assert_eq!(response.remote_network_generation, 17);
        assert_eq!(response.remote_prediction_confidence, 91);
        assert_eq!(HardHardCoordination::parse(&response.encode()), Some(response));
    }

    #[test]
    fn fixed_step_models_drive_unequal_stride_cross_sweeps() {
        fn model_window(start: u16, step: u16) -> Vec<u16> {
            let local = "0.0.0.0:41000".parse().unwrap();
            let observations = (0..4)
                .map(|sequence| p2pnet_nat::mapping::MappingObservation {
                    sequence,
                    observer: SocketAddr::new(
                        "192.0.2.1".parse().unwrap(),
                        3478 + sequence,
                    ),
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
            let model = p2pnet_nat::mapping::build_model_for_batch(
                &batch,
                Duration::from_secs(5),
                1_100,
            )
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
        let model = p2pnet_nat::mapping::build_model_for_batch(
            &batch,
            Duration::from_secs(5),
            2_010,
        )
        .unwrap();
        let window = p2pnet_nat::mapping::predict_ports(&model, 65_532);
        assert!(!window.iter().any(|candidate| candidate.port == 0));
        assert_eq!(window.first().map(|candidate| candidate.port), Some(4));

        let now = 10_000;
        assert!(hard_hard_punch_window_is_usable(now, now + 1_300));
        // A modest ±50ms scheduling jitter stays inside the bounded window;
        // an expired punch deadline does not.
        assert!(hard_hard_punch_window_is_usable(now + 50, now + 1_301));
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
            crate::Config::generate_default("https://ctrl.test", "hard-hard-tests")
                .unwrap(),
        );
        let first_cancel = Arc::new(crate::PunchSessionCancellation::default());
        assert!(manager
            .hard_hard_register_session(record(
                "peer-session-ledger",
                "a1",
                first_cancel.clone()
            ))
            .await);
        assert!(manager
            .hard_hard_session_token_is_current("peer-session-ledger", "a1")
            .await);
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
        assert!(manager
            .hard_hard_register_session(record(
                "peer-session-ledger",
                "b2",
                second_cancel.clone()
            ))
            .await);
        assert!(first_cancel.is_cancelled());
        assert!(!manager
            .hard_hard_session_token_is_current("peer-session-ledger", "a1")
            .await);
        assert!(manager
            .hard_hard_session_token_is_current("peer-session-ledger", "b2")
            .await);

        for index in 0..100u64 {
            let token = format!("{index:x}");
            let cancellation = Arc::new(crate::PunchSessionCancellation::default());
            assert!(manager
                .hard_hard_register_session(record(
                    "peer-session-ledger",
                    &token,
                    cancellation,
                ))
                .await);
        }
        manager
            .clear_hard_hard_sessions(Some("peer-session-ledger"))
            .await;
        assert!(!manager
            .hard_hard_session_is_active("peer-session-ledger")
            .await);
        assert!(second_cancel.is_cancelled());
    }
}
