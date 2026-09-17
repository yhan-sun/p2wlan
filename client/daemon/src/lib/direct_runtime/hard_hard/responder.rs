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
        .await
        else {
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
        let response_coordination =
            coordination.as_response(current_plan, local_confidence, local_model);
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
            requested_socket_count: hard_hard_measurement_requested_socket_count(&measurement),
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
        let birthday_socket_indices =
            birthday.then(|| hard_hard_measurement_socket_indices(&measurement));
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
            let authenticated_winner = hard_hard_authenticated_winner_for_cleanup(
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
