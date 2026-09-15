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

/// Consume the reciprocal response at the initiator and sweep its measured
/// socket toward the responder's fresh prediction window.
///
/// This response is bound to an already-measured initiator session. Losing
/// any of its admission/ownership fences consumes the response; it must not
/// fall back to an ordinary fresh punch which could acquire a newer network
/// generation's owner and suppress that generation's real Hard-Hard retry.
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
        return HardHardRemoteStart::Rejected;
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
        return HardHardRemoteStart::Rejected;
    };
    let Some(peer_session_generation) = peers.peer_session_generation_sync(&peer_id) else {
        return HardHardRemoteStart::Rejected;
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
        return HardHardRemoteStart::Rejected;
    };
    #[cfg(test)]
    pause_hard_hard_initiator_response_for_test().await;
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
        return HardHardRemoteStart::Rejected;
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
        return HardHardRemoteStart::Rejected;
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
