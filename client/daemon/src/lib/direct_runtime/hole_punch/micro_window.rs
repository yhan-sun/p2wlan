/// Schedule one small relay-coordinated peer-reflexive retry window.
///
/// A peer-reflexive observation is authenticated evidence, but it is not a
/// Direct-path proof.  The immediate fast punch keeps that just-observed NAT
/// mapping warm; this helper is the separate, relay-coordinated retry that
/// gives the observer and receiver a common `punch_at_ms`.  It deliberately
/// uses an endpoint slice and one socket rather than falling through to the
/// normal candidate × socket traversal, and it owns the shared deduplicator
/// so it cannot overlap an ordinary punch or send after cancellation.
async fn spawn_peer_reflexive_micro_window(
    udp: UdpTransport,
    peers: Arc<PeerManager>,
    punch_deduplicator: PunchAttemptDeduplicator,
    peer_id: String,
    candidates: Vec<SocketAddr>,
    punch_at_ms: Option<u64>,
    origin: &'static str,
) {
    let Some(punch_at_ms) = punch_at_ms else {
        peers
            .record_direct_event(
                &peer_id,
                "peer_reflexive_micro_window_skipped",
                None,
                None,
                None,
                format!(
                    "origin={origin} skipped relay-coordinated micro-window because no shared punch_at_ms was supplied"
                ),
            )
            .await;
        return;
    };

    let mut targets = Vec::with_capacity(PEER_REFLEXIVE_MICRO_WINDOW_MAX_TARGETS);
    let mut seen = HashSet::new();
    for candidate in candidates {
        if seen.insert(candidate) {
            targets.push(candidate);
        }
        if targets.len() == PEER_REFLEXIVE_MICRO_WINDOW_MAX_TARGETS {
            break;
        }
    }
    if targets.is_empty() {
        peers
            .record_direct_event(
                &peer_id,
                "peer_reflexive_micro_window_skipped",
                None,
                Some(0),
                None,
                format!(
                    "origin={origin} skipped relay-coordinated micro-window because no trusted target endpoint was available"
                ),
            )
            .await;
        return;
    }
    if peers.is_direct(&peer_id).await {
        return;
    }
    let Some(peer_session_generation) = peers.peer_session_generation_sync(&peer_id) else {
        return;
    };

    let RecoveryAdmission::Accepted { epoch } = peers.recovery_epoch_admit(&peer_id).await else {
        peers
            .record_direct_event(
                &peer_id,
                "peer_reflexive_micro_window_suppressed",
                targets.first().copied(),
                Some(targets.len()),
                None,
                format!(
                    "origin={origin} recovery epoch is not eligible for a peer-reflexive micro-window"
                ),
            )
            .await;
        return;
    };
    let generation = peers.current_network_generation().await;
    let Some(claim) = punch_deduplicator
        .claim_for_epoch_with_rendezvous_for_peer_session(
            &peers,
            &peer_id,
            peer_session_generation,
            generation,
            epoch,
            PUNCH_PRIORITY_SYNCHRONIZED,
            None,
            Some(punch_at_ms),
        )
        .await
    else {
        return;
    };
    let session = match claim {
        RendezvousPunchClaim::Claimed(session) => session,
        RendezvousPunchClaim::Deferred(deferred) => {
            peers
                .record_direct_event_for_generation_with_socket(
                    &peer_id,
                    generation,
                    "peer_reflexive_micro_window_deferred",
                    targets.first().copied(),
                    None,
                    Some(targets.len()),
                    None,
                    format!(
                        "origin={origin} deferred behind active session_id={} active_generation={} active_epoch={} active_punch_at_ms={:?} reason={}",
                        deferred.active_session_id,
                        deferred.active_network_generation,
                        deferred.active_epoch,
                        deferred.active_punch_at_ms,
                        deferred.reason.label(),
                    ),
                )
                .await;
            return;
        }
        RendezvousPunchClaim::RejectedStalePeerSession => return,
    };
    let delay = relay_assisted_punch_delay(Some(punch_at_ms));
    let session_id = session.session_id();
    tokio::spawn(async move {
        if !peers.peer_session_is_current_sync(&peer_id, peer_session_generation) {
            return;
        }
        peers
            .record_direct_event_for_generation_with_socket(
                &peer_id,
                generation,
                "peer_reflexive_micro_window_scheduled",
                targets.first().copied(),
                None,
                Some(targets.len()),
                None,
                format!(
                    "origin={origin} session_id={session_id} recovery_epoch={epoch} punch_at_ms={punch_at_ms} delay_ms={} max_targets={} attempts={} socket_policy=primary_only",
                    delay.as_millis(),
                    PEER_REFLEXIVE_MICRO_WINDOW_MAX_TARGETS,
                    PEER_REFLEXIVE_MICRO_WINDOW_ATTEMPTS,
                ),
            )
            .await;
        if !delay.is_zero() {
            tokio::select! {
                _ = sleep(delay) => {}
                _ = session.cancelled() => {
                    peers.record_direct_event_for_generation_with_socket(
                        &peer_id,
                        generation,
                        "peer_reflexive_micro_window_cancelled",
                        targets.first().copied(),
                        None,
                        Some(targets.len()),
                        None,
                        format!(
                            "origin={origin} session_id={session_id} cancelled while waiting for shared punch_at_ms={punch_at_ms}; reason={}",
                            session.cancellation_reason().map(PunchCancellationReason::label).unwrap_or("unknown"),
                        ),
                    ).await;
                    return;
                }
            }
        }
        if peers.is_direct(&peer_id).await
            || session.is_cancelled()
            || !peers.peer_session_is_current_sync(&peer_id, peer_session_generation)
        {
            return;
        }

        let dispatch_at_ms = session.mark_first_send_started();
        let cancellation = session.cancellation_handle();
        let mut send_result = None;
        let outcome = run_owned_punch_session_with_deadline(
            &session,
            PEER_REFLEXIVE_MICRO_WINDOW_DEADLINE,
            async {
                let owner_gate = || !cancellation.is_cancelled();
                send_result = Some(
                    udp.punch_candidates_primary_socket_until_not_direct_gated_report(
                        &peer_id,
                        targets.clone(),
                        PEER_REFLEXIVE_MICRO_WINDOW_INTERVAL,
                        PEER_REFLEXIVE_MICRO_WINDOW_ATTEMPTS,
                        &owner_gate,
                    )
                    .await,
                );
            },
        )
        .await;

        match outcome {
            PunchSessionOutcome::Cancelled => {
                peers.record_direct_event_for_generation_with_socket(
                    &peer_id,
                    generation,
                    "peer_reflexive_micro_window_cancelled",
                    targets.first().copied(),
                    None,
                    Some(targets.len()),
                    None,
                    format!(
                        "origin={origin} session_id={session_id} cancelled during bounded send; reason={}",
                        session.cancellation_reason().map(PunchCancellationReason::label).unwrap_or("unknown"),
                    ),
                ).await;
            }
            PunchSessionOutcome::DeadlineExceeded => {
                peers.record_direct_event_for_generation_with_socket(
                    &peer_id,
                    generation,
                    "peer_reflexive_micro_window_deadline",
                    targets.first().copied(),
                    None,
                    Some(targets.len()),
                    None,
                    format!(
                        "origin={origin} session_id={session_id} exceeded {}ms bounded send deadline",
                        PEER_REFLEXIVE_MICRO_WINDOW_DEADLINE.as_millis(),
                    ),
                ).await;
            }
            PunchSessionOutcome::Completed => match send_result {
                Some(Ok(report)) => {
                    let first_send_deviation_ms = report
                        .first_send_at_ms
                        .map(|actual| i128::from(actual) - i128::from(punch_at_ms));
                    let socket_index = report.per_socket_sent.first().map(|(index, _)| *index);
                    let per_socket_sent = report
                        .per_socket_sent
                        .iter()
                        .map(|(index, count)| format!("{index}:{count}"))
                        .collect::<Vec<_>>()
                        .join(",");
                    peers.record_direct_event_for_generation_with_socket(
                        &peer_id,
                        generation,
                        "peer_reflexive_micro_window_first_packet_sent",
                        targets.first().copied(),
                        socket_index,
                        Some(targets.len()),
                        Some(report.packets_sent),
                        format!(
                            "origin={origin} session_id={session_id} recovery_epoch={epoch} punch_at_ms={punch_at_ms} dispatch_at_ms={dispatch_at_ms} actual_first_send_at_ms={:?} first_send_deviation_ms={first_send_deviation_ms:?} per_socket_actual_datagrams={per_socket_sent}",
                            report.first_send_at_ms,
                        ),
                    ).await;
                    peers.record_direct_event_for_generation_with_socket(
                        &peer_id,
                        generation,
                        "peer_reflexive_micro_window_completed",
                        targets.first().copied(),
                        socket_index,
                        Some(targets.len()),
                        Some(report.packets_sent),
                        format!(
                            "origin={origin} session_id={session_id} sent={} unique_target_endpoints={} budget_skipped={} epoch_budget_exhausted={} candidate_iteration_capped={}",
                            report.packets_sent,
                            report.unique_target_endpoints,
                            report.budget_skipped,
                            report.epoch_budget_exhausted,
                            report.candidate_iteration_capped,
                        ),
                    ).await;
                }
                Some(Err(error)) => {
                    peers.record_direct_event_for_generation_with_socket(
                        &peer_id,
                        generation,
                        "peer_reflexive_micro_window_error",
                        targets.first().copied(),
                        None,
                        Some(targets.len()),
                        None,
                        format!("origin={origin} session_id={session_id} bounded send failed: {error}"),
                    ).await;
                }
                None => {
                    peers
                        .record_direct_event_for_generation_with_socket(
                            &peer_id,
                            generation,
                            "peer_reflexive_micro_window_cancelled",
                            targets.first().copied(),
                            None,
                            Some(targets.len()),
                            None,
                            format!("origin={origin} session_id={session_id} send did not start"),
                        )
                        .await;
                }
            },
        }
    });
}
