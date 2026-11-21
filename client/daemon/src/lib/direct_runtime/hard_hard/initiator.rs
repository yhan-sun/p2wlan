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
    expected_lifecycle: Option<(u64, PeerSessionGeneration)>,
) -> HardHardInitiatorStart {
    if punch_invocation_is_cancelled(invocation_shutdown_rx.as_ref()) {
        hard_hard_a0_stage_log(
            &peers,
            "initiator",
            None,
            HardHardA0Stage::OwnerAdmission,
            HardHardA0Reason::CancelledBeforeSubmit,
        );
        return HardHardInitiatorStart::InvocationCancelled;
    }
    let lifecycle = expected_lifecycle.or_else(|| {
        peers
            .peer_session_generation_sync(&peer_id)
            .map(|session| (peers.current_network_generation_sync(), session))
    });
    let Some((network_generation, peer_session_generation)) = lifecycle else {
        hard_hard_a0_stage_log(
            &peers,
            "initiator",
            None,
            HardHardA0Stage::PlannerEligibility,
            HardHardA0Reason::PeerSessionUnavailable,
        );
        return HardHardInitiatorStart::NotStarted(HardHardInitiatorNotStarted::RecoverySuperseded);
    };
    if peers.current_network_generation_sync() != network_generation
        || !peers.peer_session_is_current_sync(&peer_id, peer_session_generation)
    {
        return HardHardInitiatorStart::NotStarted(HardHardInitiatorNotStarted::RecoverySuperseded);
    }
    if peers.hard_hard_session_is_active(&peer_id).await {
        hard_hard_a0_stage_log(
            &peers,
            "initiator",
            None,
            HardHardA0Stage::OwnerAdmission,
            HardHardA0Reason::ExistingOwner,
        );
        return HardHardInitiatorStart::ExistingSession;
    }
    let Some(plan) = peers.hard_hard_plan_for_peer(&peer_id).await else {
        hard_hard_a0_stage_log(
            &peers,
            "initiator",
            None,
            HardHardA0Stage::PlannerEligibility,
            HardHardA0Reason::PlanUnavailable,
        );
        return HardHardInitiatorStart::NotStarted(HardHardInitiatorNotStarted::PlanChanged);
    };
    // A candidate publication may cross the control response channel before
    // reaching this planner. Its old invocation must not acquire a new plan.
    if plan.local_network_generation != network_generation
        || !peers.peer_session_is_current_sync(&peer_id, peer_session_generation)
    {
        return HardHardInitiatorStart::NotStarted(HardHardInitiatorNotStarted::PlanChanged);
    }
    hard_hard_a0_stage_log(
        &peers,
        "initiator",
        None,
        HardHardA0Stage::PlannerEligibility,
        HardHardA0Reason::PlanAvailable,
    );
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
        hard_hard_a0_stage_log(
            &peers,
            "initiator",
            None,
            HardHardA0Stage::PlannerEligibility,
            HardHardA0Reason::BootEpochUnavailable,
        );
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
        hard_hard_a0_stage_log(
            &peers,
            "initiator",
            None,
            HardHardA0Stage::PlannerEligibility,
            HardHardA0Reason::StunObserversInsufficient,
        );
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
        hard_hard_a0_stage_log(
            &peers,
            "initiator",
            None,
            HardHardA0Stage::OwnerAdmission,
            HardHardA0Reason::CancelledBeforeSubmit,
        );
        return HardHardInitiatorStart::InvocationCancelled;
    }
    let epoch = match peers.recovery_epoch_admit(&peer_id).await {
        RecoveryAdmission::Accepted { epoch } => epoch,
        RecoveryAdmission::Superseded => {
            hard_hard_a0_stage_log(
                &peers,
                "initiator",
                None,
                HardHardA0Stage::OwnerAdmission,
                HardHardA0Reason::RecoveryAdmissionRejected,
            );
            return HardHardInitiatorStart::NotStarted(
                HardHardInitiatorNotStarted::RecoverySuperseded,
            );
        }
        RecoveryAdmission::BudgetExhausted { .. } => {
            hard_hard_a0_stage_log(
                &peers,
                "initiator",
                None,
                HardHardA0Stage::OwnerAdmission,
                HardHardA0Reason::RecoveryAdmissionRejected,
            );
            return HardHardInitiatorStart::NotStarted(
                HardHardInitiatorNotStarted::RecoveryBudgetExhausted,
            );
        }
    };
    let Some(fresh_generation_reservation) = peers
        .try_begin_hard_hard_generation_for_epoch(&peer_id, epoch)
        .await
    else {
        hard_hard_a0_stage_log(
            &peers,
            "initiator",
            None,
            HardHardA0Stage::OwnerAdmission,
            HardHardA0Reason::GenerationQuotaExhausted,
        );
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
        hard_hard_a0_stage_log(
            &peers,
            "initiator",
            None,
            HardHardA0Stage::OwnerAdmission,
            HardHardA0Reason::CancelledBeforeSubmit,
        );
        return HardHardInitiatorStart::InvocationCancelled;
    }
    let punch_at_ms = hard_hard_now_ms().saturating_add(HARD_HARD_PUNCH_LEAD.as_millis() as u64);
    let Some(punch_at_server_ms) = signal.control.hard_hard_server_deadline(punch_at_ms) else {
        fresh_generation_reservation.refund().await;
        hard_hard_a0_stage_log(
            &peers,
            "initiator",
            None,
            HardHardA0Stage::PlannerEligibility,
            HardHardA0Reason::MissingPunchDeadline,
        );
        peers
            .record_direct_event(
                &peer_id,
                "hard_hard_server_clock_unavailable",
                None,
                None,
                None,
                "Hard<->Hard has no fresh control-server clock sample; preserving Relay and suppressing an unsynchronized offer",
            )
            .await;
        return HardHardInitiatorStart::NotStarted(
            HardHardInitiatorNotStarted::ServerClockUnavailable,
        );
    };
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
        hard_hard_a0_stage_log(
            &peers,
            "initiator",
            None,
            HardHardA0Stage::OwnerAdmission,
            HardHardA0Reason::GenerationOrProfileFence,
        );
        return HardHardInitiatorStart::NotStarted(HardHardInitiatorNotStarted::PlanChanged);
    }
    let Some(claim) = punch_deduplicator
        .claim_for_epoch_with_rendezvous_for_peer_session(
            &peers,
            &peer_id,
            peer_session_generation,
            plan.local_network_generation,
            epoch,
            PUNCH_PRIORITY_HARD_HARD,
            None,
            Some(punch_at_ms),
        )
        .await
    else {
        fresh_generation_reservation.refund().await;
        hard_hard_a0_stage_log(
            &peers,
            "initiator",
            None,
            HardHardA0Stage::OwnerAdmission,
            HardHardA0Reason::ClaimRejected,
        );
        return HardHardInitiatorStart::NotStarted(HardHardInitiatorNotStarted::RecoverySuperseded);
    };
    let session = match claim {
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
                hard_hard_a0_stage_log(
                    &peers,
                    "initiator",
                    None,
                    HardHardA0Stage::OwnerAdmission,
                    HardHardA0Reason::GenerationOrProfileFence,
                );
                return HardHardInitiatorStart::NotStarted(
                    HardHardInitiatorNotStarted::PlanChanged,
                );
            }
            session
        }
        RendezvousPunchClaim::Deferred(deferred) => {
            fresh_generation_reservation.refund().await;
            hard_hard_a0_stage_log(
                &peers,
                "initiator",
                None,
                HardHardA0Stage::OwnerAdmission,
                HardHardA0Reason::ClaimDeferred,
            );
            peers
                .record_direct_event(
                    &peer_id,
                    "hard_hard_deferred",
                    None,
                    None,
                    None,
                    format!(
                        "Hard↔Hard initiator folded behind an active owner epoch={} reason={}",
                        deferred.active_epoch,
                        deferred.reason.label()
                    ),
                )
                .await;
            return HardHardInitiatorStart::ExistingPunchOwner;
        }
        RendezvousPunchClaim::RejectedStalePeerSession => {
            fresh_generation_reservation.refund().await;
            hard_hard_a0_stage_log(
                &peers,
                "initiator",
                None,
                HardHardA0Stage::OwnerAdmission,
                HardHardA0Reason::ClaimRejected,
            );
            return HardHardInitiatorStart::NotStarted(
                HardHardInitiatorNotStarted::RecoverySuperseded,
            );
        }
    };
    let recovery_identity = fresh_generation_reservation.identity();
    let coordinated =
        signal.control.local_supports_hh2() && peers.peer_supports_hh2(&peer_id).await;
    let token = if coordinated {
        format!("{:032x}", rand::random::<u128>())
    } else {
        hard_hard_session_token(session.session_id())
    };
    let mut coordination = hard_hard_coordination_from_plan(token, HardHardRole::Initiator, plan);
    if coordinated {
        let (rtt_ms, uncertainty_ms) =
            hard_hard_wire_timing(signal.control.hard_hard_timing_hint());
        coordination.v2 = Some(HardHardV2Envelope {
            stage: HardHardV2Stage::Offer,
            local: Default::default(),
            remote: Default::default(),
            phase: rand::random(),
            agreement: None,
            strategy_order: peers.hard_hard_strategy_order(&peer_id).await,
            rtt_ms,
            uncertainty_ms,
        });
    }
    hard_hard_a0_stage_log(
        &peers,
        "initiator",
        Some(&coordination.token),
        HardHardA0Stage::OwnerAdmission,
        HardHardA0Reason::OwnerClaimed,
    );
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
        hard_hard_a0_stage_log(
            &peers,
            "initiator",
            Some(&coordination.token),
            HardHardA0Stage::LocalMeasurement,
            HardHardA0Reason::Started,
        );
        let measurement_lease = if coordination.v2.is_some() {
            let deadline = Instant::now()
                + Duration::from_millis(200.min(punch_at_ms.saturating_sub(hard_hard_now_ms())));
            let Some(lease) = udp
                .acquire_hard_hard_measurement_lease(
                    plan.local_network_generation,
                    &cancellation,
                    deadline,
                )
                .await
            else {
                // No STUN has been sent while waiting for this shared lane.
                // Refund only the reservation owned by this exact epoch.
                fresh_generation_reservation.refund().await;
                hard_hard_a0_stage_log(
                    &peers,
                    "initiator",
                    Some(&coordination.token),
                    HardHardA0Stage::LocalMeasurement,
                    HardHardA0Reason::MeasurementAdmissionDeferred,
                );
                peers
                    .record_direct_event(
                        &peer_id,
                        "hard_hard_measurement_not_started",
                        None,
                        None,
                        Some(0),
                        "reason_code=measurement_admission_deferred; no STUN sent; exact generation reservation refunded",
                    )
                    .await;
                return;
            };
            Some(lease)
        } else {
            None
        };
        // Queueing does not spend a fresh generation. Revalidate the original
        // owner/plan before crossing into the actual measurement operation.
        let plan_current = hard_hard_plan_claim_fence_is_current(
            &peers,
            &peer_id,
            peer_session_generation,
            plan,
            epoch,
            punch_at_ms,
        )
        .await;
        // The plan fence can await locks. Observe cancellation afterwards so
        // a revoked invocation cannot commit its still-unused reservation.
        if cancellation.is_cancelled() || !plan_current {
            fresh_generation_reservation.refund().await;
            return;
        }
        fresh_generation_reservation.commit();
        let mut measurement = match run_hard_hard_local_measurement(
            &udp,
            &peers,
            &peer_id,
            HardHardMeasurementRequest {
                observers: &signal.stun_servers,
                stun_timeout: signal.stun_timeout,
                session_token: &coordination.token,
                cancellation: Some(&cancellation),
                punch_at_ms,
                coordinated: coordination.v2.is_some(),
            },
        )
        .await
        {
            Ok(measurement) => {
                hard_hard_a0_stage_log(
                    &peers,
                    "initiator",
                    Some(&coordination.token),
                    HardHardA0Stage::LocalMeasurement,
                    HardHardA0Reason::Completed,
                );
                measurement
            }
            Err(rejection) => {
                hard_hard_a0_stage_log(
                    &peers,
                    "initiator",
                    Some(&coordination.token),
                    HardHardA0Stage::LocalMeasurement,
                    HardHardA0Reason::MeasurementRejected,
                );
                let failure_class = hard_hard_measurement_failure_class(&rejection);
                let reason = rejection.label();
                let _ = record_hard_hard_pre_session_failure(
                    &peers,
                    &peer_id,
                    peer_session_generation,
                    plan,
                    &coordination.token,
                    "initiator",
                    0,
                    None,
                    failure_class,
                    reason,
                )
                .await;
                if !cancellation.is_cancelled() {
                    peers
                        .record_direct_event(
                            &peer_id,
                            "hard_hard_measurement_failed",
                            None,
                            None,
                            None,
                            format!(
                                "reason_code={reason} failure_class={failure_class} Hard↔Hard fresh measurement/model failed; keeping Relay or the existing path"
                            ),
                        )
                        .await;
                }
                return;
            }
        };
        let measurement_completed_at_ms = peers.timeline_uptime_ms();
        let mut measurement_observation = hard_hard_measurement_observation(
            &peers,
            &measurement,
            measurement_completed_at_ms,
            punch_at_ms,
        );
        if cancellation.is_cancelled()
            || !peers.peer_session_is_current_sync(&peer_id, peer_session_generation)
            || peers.is_direct(&peer_id).await
            || peers
                .hard_hard_plan_for_peer(&peer_id)
                .await
                .is_none_or(|current| !hard_hard_plan_matches(current, plan))
        {
            let _ = record_hard_hard_pre_session_failure(
                &peers,
                &peer_id,
                peer_session_generation,
                plan,
                &coordination.token,
                "initiator",
                0,
                Some(&measurement_observation),
                "cancelled_generation_changed",
                "measurement_fenced",
            )
            .await;
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
        let HardHardMeasurementPayload {
            v2_offer,
            candidates,
            candidate_sources,
            local_confidence,
            local_model,
            strategy_candidate_cap,
            candidate_contract,
        } = match hard_hard_measurement_payload(
            &measurement,
            signal.boot_epoch_ms,
            peers.current_network_generation_sync(),
        ) {
            Ok(payload) => payload,
            Err(rejection) => {
                let _ = record_hard_hard_pre_session_failure(
                    &peers,
                    &peer_id,
                    peer_session_generation,
                    plan,
                    &coordination.token,
                    "initiator",
                    0,
                    Some(&measurement_observation),
                    rejection.failure_class(),
                    rejection.reason(),
                )
                .await;
                peers
                .record_direct_event(
                    &peer_id,
                    "hard_hard_measurement_failed",
                    None,
                    None,
                    None,
                    format!("Hard↔Hard prediction publication rejected: {}; Relay remains available", rejection.reason()),
                )
                .await;
                return;
            }
        };
        let Some(primary_socket) =
            hard_hard_measurement_primary_socket(&peer_id, &coordination.token, &measurement, plan)
        else {
            let _ = record_hard_hard_pre_session_failure(
                &peers,
                &peer_id,
                peer_session_generation,
                plan,
                &coordination.token,
                "initiator",
                0,
                Some(&measurement_observation),
                "unknown",
                "primary_socket_missing",
            )
            .await;
            return;
        };
        hard_hard_apply_candidate_contract(
            &mut measurement_observation,
            &candidate_contract,
            strategy_candidate_cap,
            &candidates,
            &candidate_sources,
        );
        peers
            .record_direct_event(
                &peer_id,
                "hard_hard_local_nat_model",
                None,
                Some(candidates.len()),
                None,
                format!(
                    "role=initiator session_tag={} model={} confidence={} {}",
                    hard_hard_anonymized_tag(&coordination.token, "session"),
                    local_model,
                    local_confidence,
                    hard_hard_measurement_summary(&measurement),
                ),
            )
            .await;
        let mut coordination = coordination;
        coordination.local_prediction_confidence = local_confidence;
        coordination.local_prediction_model = local_model;
        let coordinated_plan = if let Some(meta) = coordination.v2.as_mut() {
            let Some(offer) = v2_offer else {
                return;
            };
            meta.local = offer;
            let Some(mut agreed) = hard_hard_new_coordinated_plan(
                &peers,
                &signal.control,
                &peer_id,
                offer,
                meta.phase,
                punch_at_ms,
                punch_at_server_ms,
            )
            .await
            else {
                return;
            };
            agreed.measurement_lease = measurement_lease.clone();
            agreed.recovery_identity = Some(recovery_identity);
            agreed.strategy_order = meta.strategy_order;
            Some(agreed)
        } else {
            None
        };
        let session_id = coordination.encode();
        if HardHardCoordination::parse(&session_id).is_none() {
            return;
        }
        let prediction_window = hard_hard_prediction_targets(
            &candidates,
            hard_hard_measurement_target_limit(&measurement),
        );
        let requested_birthday_level = hard_hard_measurement_requested_level(&measurement);
        let birthday = hard_hard_measurement_is_birthday(&measurement);
        let (planned_sockets, planned_socket_target_combinations, planned_logical_probes) =
            hard_hard_measurement_planned_dimensions(&measurement, 0);
        let requested_socket_indices = hard_hard_measurement_socket_indices(&measurement);
        let record = HardHardSessionRecord {
            session_id: session_id.clone(),
            probe_session_id: probe_session_id.clone(),
            session_token: coordination.token.clone(),
            peer_id: peer_id.clone(),
            initiator: true,
            pair_nomination: coordinated_plan.as_ref().map(|_| Default::default()),
            coordinated_plan,
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
            requested_socket_count: hard_hard_measurement_requested_socket_count(&measurement),
            requested_socket_indices,
            prediction_window,
            remote_prediction: Vec::new(),
            fresh_socket: primary_socket.clone(),
            punch_at_ms,
            expires_at_ms: hard_hard_now_ms()
                .saturating_add(HARD_HARD_SESSION_TTL.as_millis() as u64),
            state: HardHardSessionState::AwaitingPeer,
            attempt_count: 0,
            measurement: measurement_observation.clone(),
            created_at: Instant::now(),
            cancellation: cancellation.clone(),
        };
        let publication_deadline = record
            .coordinated_plan
            .as_ref()
            .map(|plan| plan.scheduled_start);
        let cleanup_descriptor = HardHardCleanupDescriptor::from_record(&record);
        let registered = !cancellation.is_cancelled()
            && peers.peer_session_is_current_sync(&peer_id, peer_session_generation)
            && peers.hard_hard_register_session(record).await;
        if !registered {
            hard_hard_a0_stage_log(
                &peers,
                "initiator",
                Some(&coordination.token),
                HardHardA0Stage::SessionRegistration,
                HardHardA0Reason::RegistrationRejected,
            );
            let _ = record_hard_hard_pre_session_failure(
                &peers,
                &peer_id,
                peer_session_generation,
                plan,
                &coordination.token,
                "initiator",
                0,
                Some(&measurement_observation),
                "cancelled_generation_changed",
                "session_registration_rejected",
            )
            .await;
            return;
        }
        let _cleanup_completion =
            spawn_hard_hard_session_cleanup(udp.clone(), peers.clone(), cleanup_descriptor.clone());
        if coordination.v2.is_some()
            && !udp
                .enable_hard_hard_pair_sockets(&peer_id, &coordination.token)
                .await
        {
            peers
                .hard_hard_retire_session(&peer_id, &session_id, &coordination.token)
                .await;
            return;
        }
        if cancellation.is_cancelled()
            || !peers.peer_session_is_current_sync(&peer_id, peer_session_generation)
        {
            let _ = record_hard_hard_terminal_attempt(
                &peers,
                &peer_id,
                peer_session_generation,
                &primary_socket,
                &coordination.token,
                "initiator",
                birthday,
                0,
                &measurement_observation,
                &[],
                planned_sockets,
                planned_socket_target_combinations,
                planned_logical_probes,
                None,
                &PunchSendReport::default(),
                UdpProbeRxSnapshot::default(),
                false,
                None,
                "session_cancelled",
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
                "hard_hard_session_started",
                None,
                Some(candidates.len()),
                None,
                format!(
                    "role=initiator session_tag={} network_generation={} remote_candidate_epoch={} local_profile_generation={} remote_profile_generation={} punch_at_ms={} local_clock_ms={}",
                    hard_hard_anonymized_tag(&coordination.token, "session"),
                    plan.local_network_generation,
                    plan.remote_candidate_epoch,
                    plan.local_profile_generation,
                    plan.remote_profile_generation,
                    punch_at_ms,
                    hard_hard_now_ms(),
                ),
            )
            .await;
        hard_hard_a0_stage_log(
            &peers,
            "initiator",
            Some(&coordination.token),
            HardHardA0Stage::SessionRegistration,
            HardHardA0Reason::Registered,
        );
        pending_session_cancellation.disarm();
        // The manager ledger is now the authoritative active-session gate.
        // Release the measurement permit before publishing: the peer cannot
        // send its reciprocal response until that publish succeeds, and the
        // initiator-response worker must be able to claim the punch owner as
        // soon as such a response arrives.  Holding this permit through the
        // publish would fold and silently lose an extremely fast response.
        drop(session_owner);
        let can_submit_offer = !cancellation.is_cancelled()
            && peers.peer_session_is_current_sync(&peer_id, peer_session_generation)
            && peers
                .try_consume_recovery_http_quota_for_identity(&peer_id, recovery_identity)
                .await
            && !cancellation.is_cancelled()
            && peers.peer_session_is_current_sync(&peer_id, peer_session_generation);
        let advertised = if can_submit_offer {
            hard_hard_experiment_signal_delay(peers.hard_hard_experiment_only()).await;
            hard_hard_a0_stage_log(
                &peers,
                "initiator",
                Some(&coordination.token),
                HardHardA0Stage::OfferApiDispatch,
                HardHardA0Reason::SubmitStarted,
            );
            let identity_current = peers
                .hard_hard_session_identity_is_current(&primary_socket)
                .await;
            let accepted = identity_current
                && !cancellation.is_cancelled()
                && hard_hard_measurement_publication_is_current(
                    &measurement,
                    &peers,
                    &peer_id,
                    v2_offer,
                )
                && hard_hard_publish_or_observe_progress(
                    &peers,
                    &signal.control,
                    &peer_id,
                    &coordination.token,
                    true,
                    publication_deadline,
                    hard_hard_send_initial_signal(
                        &peers,
                        &signal.control,
                        &peer_id,
                        &coordination.token,
                        &candidates,
                        &candidate_sources,
                        punch_at_ms,
                        Some(punch_at_server_ms),
                        session_id.clone(),
                        cancellation.clone(),
                        publication_deadline,
                        recovery_identity,
                    ),
                )
                .await;
            hard_hard_a0_stage_log(
                &peers,
                "initiator",
                Some(&coordination.token),
                HardHardA0Stage::OfferApiDispatch,
                if accepted {
                    HardHardA0Reason::ApiReturnedOk
                } else {
                    HardHardA0Reason::ApiReturnedError
                },
            );
            accepted
        } else {
            let reason = if cancellation.is_cancelled() {
                HardHardA0Reason::CancelledBeforeSubmit
            } else if !peers.peer_session_is_current_sync(&peer_id, peer_session_generation) {
                HardHardA0Reason::SessionChangedBeforeSubmit
            } else {
                HardHardA0Reason::RecoveryQuotaRejected
            };
            hard_hard_a0_stage_log(
                &peers,
                "initiator",
                Some(&coordination.token),
                HardHardA0Stage::OfferApiDispatch,
                reason,
            );
            false
        };
        let signaled_candidate_count = candidate_contract.signaled_candidate_count;
        record_hard_hard_candidate_contract(
            &peers,
            &peer_id,
            candidate_contract,
            strategy_candidate_cap,
            advertised,
        )
        .await;
        if !advertised
            || peers.is_direct(&peer_id).await
            || cancellation.is_cancelled()
            || !peers.peer_session_is_current_sync(&peer_id, peer_session_generation)
        {
            let terminal_reason = if cancellation.is_cancelled() {
                "session_cancelled"
            } else if !peers.peer_session_is_current_sync(&peer_id, peer_session_generation) {
                "peer_session_changed"
            } else if peers.is_direct(&peer_id).await {
                "superseded_by_other_direct"
            } else {
                "advertisement_failed"
            };
            let _ = record_hard_hard_terminal_attempt(
                &peers,
                &peer_id,
                peer_session_generation,
                &primary_socket,
                &coordination.token,
                "initiator",
                birthday,
                0,
                &measurement_observation,
                &[],
                planned_sockets,
                planned_socket_target_combinations,
                planned_logical_probes,
                None,
                &PunchSendReport::default(),
                UdpProbeRxSnapshot::default(),
                false,
                None,
                terminal_reason,
            )
            .await;
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
        // Publication is proven by the local API result or by an admitted
        // reciprocal HH2 answer; neither is permission to promote Direct.
        let candidate_signal_accepted_at_ms = peers.timeline_uptime_ms();
        measurement_observation.candidate_signal_accepted_at_ms = candidate_signal_accepted_at_ms;
        measurement_observation.advertised_candidate_count = signaled_candidate_count;
        let _ = peers
            .hard_hard_mark_candidate_signal_accepted(
                &peer_id,
                &coordination.token,
                candidate_signal_accepted_at_ms,
                signaled_candidate_count,
            )
            .await;
        let handoff_ok = finalize_hard_hard_measurement(&mut measurement).await;
        if !handoff_ok {
            let _ = record_hard_hard_terminal_attempt(
                &peers,
                &peer_id,
                peer_session_generation,
                &primary_socket,
                &coordination.token,
                "initiator",
                birthday,
                0,
                &measurement_observation,
                &[],
                planned_sockets,
                planned_socket_target_combinations,
                planned_logical_probes,
                None,
                &PunchSendReport::default(),
                UdpProbeRxSnapshot::default(),
                false,
                None,
                "socket_handoff_failed",
            )
            .await;
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
        // This marker is the simulator's direct-path release barrier. Emit it
        // only after the prediction is accepted and the measured socket has
        // completed its durable handoff; releasing packet flow any earlier can
        // perturb the very mapping generation being measured.
        let session_tag = hard_hard_anonymized_tag(&coordination.token, "session");
        let plan_tag = hard_hard_rendezvous_plan_tag(&coordination.token);
        hard_hard_a0_stage_log(
            &peers,
            "initiator",
            Some(&coordination.token),
            HardHardA0Stage::RendezvousSchedule,
            HardHardA0Reason::Scheduled,
        );
        let remote_network_generation = if coordination.remote_prediction_confidence == 0 {
            "unknown".to_string()
        } else {
            coordination.remote_network_generation.to_string()
        };
        info!(
            event = "hard_hard_rendezvous_scheduled",
            role = "initiator",
            network_generation = coordination.local_network_generation,
            peer_session_generation = peer_session_generation.value(),
            remote_candidate_epoch = coordination.remote_candidate_epoch,
            local_profile_generation = coordination.local_profile_generation,
            remote_profile_generation = coordination.remote_profile_generation,
            remote_network_generation = %remote_network_generation,
            session_tag = %session_tag,
            plan_tag = %plan_tag,
            punch_at_server_ms,
            clock_domain = "host_unix_ms",
            punch_at_ms,
            candidate_count = candidates.len(),
            "hard_hard_rendezvous_scheduled"
        );
        peers
            .record_direct_event(
                &peer_id,
                "hard_hard_rendezvous_scheduled",
                None,
                Some(candidates.len()),
                None,
                format!(
                    "role=initiator session_tag={} plan_tag={} punch_at_ms={} punch_at_server_ms={} clock_domain=host_unix_ms network_generation={} peer_session_generation={} remote_network_generation={} remote_candidate_epoch={} local_profile_generation={} remote_profile_generation={} lead_ms={} sweep_deadline_ms={} {}",
                    session_tag,
                    plan_tag,
                    punch_at_ms,
                    punch_at_server_ms,
                    coordination.local_network_generation,
                    peer_session_generation.value(),
                    remote_network_generation,
                    coordination.remote_candidate_epoch,
                    coordination.local_profile_generation,
                    coordination.remote_profile_generation,
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

/// Control may deliver a signal to its peer before completing the sender's
/// POST. Keep the current owner bounded by its original schedule, accepting
/// only the next authenticated transcript stage as alternative publication
/// evidence. Dropping the superseded response future frees the existing
/// per-peer FIFO; the peer's next stage proves this signal was delivered.
#[allow(clippy::too_many_arguments)]
async fn hard_hard_publish_or_observe_progress<T, E>(
    peers: &PeerManager,
    control: &ControlClient,
    peer: &str,
    token: &str,
    initiator: bool,
    deadline: Option<Instant>,
    publication: impl std::future::Future<Output = std::result::Result<T, E>>,
) -> bool {
    let Some(deadline) = deadline else {
        return publication.await.is_ok();
    };
    let progress = async {
        loop {
            let Some(current) = peers.hard_hard_session_by_token(peer, token).await else {
                return false;
            };
            let Some(plan) = current.coordinated_plan.as_ref() else {
                return false;
            };
            if current.initiator != initiator
                || current.cancellation.is_cancelled()
                || Instant::now() >= deadline
                || !hard_hard_plan_registration_is_current(peers, control, peer, plan).await
                || !peers
                    .hard_hard_session_identity_is_current(&current.fresh_socket)
                    .await
            {
                return false;
            }
            let delivered = if initiator {
                plan.agreement.is_some() && plan.remote_offer.is_some()
            } else {
                plan.ready_received
            };
            if delivered {
                return true;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    };
    tokio::pin!(progress);
    tokio::time::timeout_at(tokio::time::Instant::from_std(deadline), async {
        tokio::select! {
            biased;
            delivered = &mut progress => delivered,
            sent = publication => {
                if sent.is_ok() { true } else {
                    // A failed/late local receipt says nothing about whether
                    // the peer received the signal. Only its fenced next
                    // stage, inside the unchanged deadline, can rescue it.
                    progress.await
                }
            }
        }
    })
    .await
    .unwrap_or(false)
}

/// Consume the reciprocal response at the initiator and sweep its measured
/// socket toward the responder's fresh prediction window.
///
/// This response is bound to an already-measured initiator session. Losing
/// any of its admission/ownership fences consumes the response; it must not
/// fall back to an ordinary fresh punch which could acquire a newer network
/// generation's owner and suppress that generation's real Hard-Hard retry.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn spawn_hard_hard_initiator_response_with_signal(
    udp: UdpTransport,
    peers: Arc<PeerManager>,
    punch_deduplicator: PunchAttemptDeduplicator,
    peer_id: String,
    coordination: HardHardCoordination,
    remote_prediction: Vec<SocketAddr>,
    punch_at_ms: u64,
    signal: Option<HolePunchSignalContext>,
) -> HardHardRemoteStart {
    hard_hard_a0_stage_log(
        &peers,
        "initiator",
        Some(&coordination.token),
        HardHardA0Stage::ReciprocalResponseAdmission,
        HardHardA0Reason::SignalReceived,
    );
    if coordination.role != HardHardRole::Responder {
        hard_hard_a0_stage_log(
            &peers,
            "initiator",
            Some(&coordination.token),
            HardHardA0Stage::ReciprocalResponseAdmission,
            HardHardA0Reason::InvalidRole,
        );
        return HardHardRemoteStart::Rejected;
    }
    let Some(mut record) = peers
        .hard_hard_session_by_token(&peer_id, &coordination.token)
        .await
    else {
        hard_hard_a0_stage_log(
            &peers,
            "initiator",
            Some(&coordination.token),
            HardHardA0Stage::ReciprocalResponseAdmission,
            HardHardA0Reason::ResponseFenced,
        );
        return HardHardRemoteStart::Rejected;
    };
    let Some(peer_session_generation) = peers.peer_session_generation_sync(&peer_id) else {
        hard_hard_a0_stage_log(
            &peers,
            "initiator",
            Some(&coordination.token),
            HardHardA0Stage::ReciprocalResponseAdmission,
            HardHardA0Reason::ResponseFenced,
        );
        return HardHardRemoteStart::Rejected;
    };
    let Some(current_plan) = peers.hard_hard_plan_for_peer(&peer_id).await else {
        hard_hard_a0_stage_log(
            &peers,
            "initiator",
            Some(&coordination.token),
            HardHardA0Stage::ReciprocalResponseAdmission,
            HardHardA0Reason::PlanUnavailable,
        );
        let _ = record_hard_hard_unexecuted_session_attempt(
            &peers,
            &peer_id,
            peer_session_generation,
            &record,
            "initiator",
            &remote_prediction,
            "response_plan_unavailable",
        )
        .await;
        return HardHardRemoteStart::Rejected;
    };
    let expected_plan = crate::peer::HardHardPlanSnapshot {
        local_network_generation: record.local_network_generation,
        remote_candidate_epoch: record.remote_candidate_epoch,
        local_profile_generation: record.local_profile_generation,
        remote_profile_generation: record.remote_profile_generation,
    };
    if record.coordinated_plan.is_some() != coordination.v2.is_some()
        || (coordination.v2.is_some() && signal.is_none())
    {
        return HardHardRemoteStart::Rejected;
    }
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
        || !hard_hard_response_deadline_matches(record.punch_at_ms, punch_at_ms)
        || record.fresh_socket.punch_generation == 0
        || record
            .punch_at_ms
            .saturating_add(HARD_HARD_SWEEP_DEADLINE.as_millis() as u64)
            < hard_hard_now_ms()
    {
        let response_deadline_expired = record
            .punch_at_ms
            .saturating_add(HARD_HARD_SWEEP_DEADLINE.as_millis() as u64)
            < hard_hard_now_ms();
        hard_hard_a0_stage_log(
            &peers,
            "initiator",
            Some(&coordination.token),
            HardHardA0Stage::ReciprocalResponseAdmission,
            if response_deadline_expired {
                HardHardA0Reason::DeadlineExpired
            } else {
                HardHardA0Reason::ResponseFenced
            },
        );
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
        let terminal_reason = if response_deadline_expired {
            "deadline"
        } else {
            "response_fenced"
        };
        let _ = record_hard_hard_unexecuted_session_attempt(
            &peers,
            &peer_id,
            peer_session_generation,
            &record,
            "initiator",
            &remote_prediction,
            terminal_reason,
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
        hard_hard_a0_stage_log(
            &peers,
            "initiator",
            Some(&coordination.token),
            HardHardA0Stage::ReciprocalResponseAdmission,
            HardHardA0Reason::GenerationOrProfileFence,
        );
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
        let _ = record_hard_hard_unexecuted_session_attempt(
            &peers,
            &peer_id,
            peer_session_generation,
            &record,
            "initiator",
            &remote_prediction,
            "candidate_epoch_changed",
        )
        .await;
        return HardHardRemoteStart::Rejected;
    }
    if remote_prediction.is_empty() || remote_prediction.len() > HARD_HARD_MAX_BIRTHDAY_TARGETS {
        hard_hard_a0_stage_log(
            &peers,
            "initiator",
            Some(&coordination.token),
            HardHardA0Stage::ReciprocalResponseAdmission,
            HardHardA0Reason::InvalidPrediction,
        );
        let _ = record_hard_hard_unexecuted_session_attempt(
            &peers,
            &peer_id,
            peer_session_generation,
            &record,
            "initiator",
            &remote_prediction,
            "response_prediction_invalid",
        )
        .await;
        return HardHardRemoteStart::Rejected;
    }
    let ready_envelope = if record.coordinated_plan.is_some() {
        let Some(signal) = signal.as_ref() else {
            return HardHardRemoteStart::Rejected;
        };
        let Some((ready, committed)) = hard_hard_accept_answer(
            &peers,
            &signal.control,
            &record,
            &coordination,
            &remote_prediction,
        )
        .await
        else {
            return HardHardRemoteStart::Rejected;
        };
        record = committed;
        Some(ready)
    } else {
        None
    };
    let RecoveryAdmission::Accepted { epoch } = peers.recovery_epoch_admit(&peer_id).await else {
        hard_hard_a0_stage_log(
            &peers,
            "initiator",
            Some(&coordination.token),
            HardHardA0Stage::OwnerAdmission,
            HardHardA0Reason::RecoveryAdmissionRejected,
        );
        let _ = record_hard_hard_unexecuted_session_attempt(
            &peers,
            &peer_id,
            peer_session_generation,
            &record,
            "initiator",
            &remote_prediction,
            "recovery_admission_rejected",
        )
        .await;
        return HardHardRemoteStart::Rejected;
    };
    let session = match claim_hard_hard_initiator_response_session(
        &peers,
        &punch_deduplicator,
        &peer_id,
        peer_session_generation,
        expected_plan,
        &record,
        epoch,
    )
    .await
    {
        Ok(value) => value,
        Err(failure) => {
            failure.log(
                Some(&coordination.token),
                "initiator",
                expected_plan,
                peer_session_generation,
                epoch,
            );
            hard_hard_a0_stage_log(
                &peers,
                "initiator",
                Some(&coordination.token),
                HardHardA0Stage::OwnerAdmission,
                HardHardA0Reason::ClaimRejected,
            );
            let _ = record_hard_hard_unexecuted_session_attempt(
                &peers,
                &peer_id,
                peer_session_generation,
                &record,
                "initiator",
                &remote_prediction,
                "response_claim_rejected",
            )
            .await;
            return HardHardRemoteStart::Rejected;
        }
    };
    hard_hard_a0_stage_log(
        &peers,
        "initiator",
        Some(&coordination.token),
        HardHardA0Stage::ReciprocalResponseAdmission,
        HardHardA0Reason::ResponseAdmitted,
    );
    #[cfg(test)]
    pause_hard_hard_initiator_response_for_test().await;
    if let Some(ready) = ready_envelope {
        let Some(signal) = signal.as_ref() else {
            return HardHardRemoteStart::Rejected;
        };
        let Some(current) = peers
            .hard_hard_session_by_token(&peer_id, &coordination.token)
            .await
        else {
            return HardHardRemoteStart::Rejected;
        };
        if !hard_hard_exchange_ready(&peers, signal, &current, ready).await {
            peers
                .hard_hard_retire_session(&peer_id, &record.session_id, &coordination.token)
                .await;
            return HardHardRemoteStart::Rejected;
        }
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
        let _ = record_hard_hard_unexecuted_session_attempt(
            &peers,
            &peer_id,
            peer_session_generation,
            &record,
            "initiator",
            &remote_prediction,
            "response_sweep_admission_rejected",
        )
        .await;
        return HardHardRemoteStart::Rejected;
    };
    let socket_is_current = udp
        .hard_hard_socket_identity_is_current(&record.fresh_socket)
        .await;
    let peer_session_is_current =
        peers.peer_session_is_current_sync(&peer_id, peer_session_generation);
    if !socket_is_current || session.is_cancelled() || !peer_session_is_current {
        let terminal_reason = if !socket_is_current {
            "socket_revoked"
        } else if !peer_session_is_current {
            "peer_session_changed"
        } else {
            "session_cancelled"
        };
        let _ = record_hard_hard_unexecuted_session_attempt(
            &peers,
            &peer_id,
            peer_session_generation,
            &record,
            "initiator",
            &remote_prediction,
            terminal_reason,
        )
        .await;
        let _ = peers
            .hard_hard_retire_session(&record.peer_id, &record.session_id, &record.session_token)
            .await;
        return HardHardRemoteStart::Rejected;
    }
    let fresh_socket = record.fresh_socket.clone();
    let (remote_prediction, birthday_socket_indices) =
        match hard_hard_sweep_plan(&record, &remote_prediction) {
            Some(execution) => execution,
            None => return HardHardRemoteStart::Rejected,
        };
    let cleanup_udp = udp.clone();
    let swept = Box::pin(hard_hard_wait_and_sweep(
        udp,
        peers.clone(),
        session,
        peer_id.clone(),
        peer_session_generation,
        fresh_socket.clone(),
        birthday_socket_indices,
        record.session_token.clone(),
        remote_prediction,
        record.requested_birthday_level,
        record.generated_candidate_count,
        record.signaled_candidate_count,
        // Keep the initiator's original 3500ms schedule. The reciprocal
        // value was accepted only as bounded server-clock normalization
        // jitter above; it must not move the local send budget.
        record.punch_at_ms,
        record.local_network_generation,
        (
            record.local_profile_generation,
            record.remote_profile_generation,
        ),
        record.probe_session_id.clone(),
        "initiator",
        record.attempt_count,
        record.measurement.clone(),
    ))
    .await;
    // Nomination may commit any socket from this token, not only the primary
    // used to publish its measurement. Resolve the authority again after await.
    let confirmed_socket = peers
        .hard_hard_fresh_socket_for_token(&peer_id, &record.session_token)
        .await
        .unwrap_or_else(|| fresh_socket.clone());
    let direct_on_fresh_socket =
        hard_hard_exact_direct_confirmation_is_current(&cleanup_udp, &peers, &confirmed_socket)
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
        let authenticated_winner = hard_hard_authenticated_winner_for_cleanup(
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
            direct_on_fresh_socket.then_some(confirmed_socket.clone())
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
