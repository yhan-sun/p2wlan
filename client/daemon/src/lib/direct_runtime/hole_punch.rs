/// Optional signaling context for a synchronized hole punch.
///
/// When present, the punch task can run a fresh-mapping generation and
/// immediately advertise the predicted port window to the peer so the stable
/// side probes the model's top-1 + successor window first.
#[derive(Clone)]
struct HolePunchSignalContext {
    control: ControlClient,
    local_candidates: Arc<RwLock<Vec<String>>>,
    local_candidate_sources: Arc<RwLock<HashMap<String, String>>>,
    stun_servers: Vec<SocketAddr>,
    stun_timeout: Duration,
    /// Daemon incarnation epoch embedded in the fresh-prediction label.
    boot_epoch_ms: u64,
}

#[allow(clippy::too_many_arguments)]
async fn spawn_hole_punch_task(
    udp: UdpTransport,
    peers: Arc<PeerManager>,
    punch_deduplicator: PunchAttemptDeduplicator,
    peer_id: String,
    probe_interval: Duration,
    attempts: u32,
    punch_at_ms: Option<u64>,
    signal: Option<HolePunchSignalContext>,
    fresh_prediction: Option<FreshPredictionId>,
    frozen_targets: Option<Vec<SocketAddr>>,
) {
    // A peer that is already Direct must not schedule a synchronized punch
    // session at all: the fresh-mapping measurement, the candidate sweep and
    // the prediction advertisement are all post-convergence scans on a
    // confirmed path.  The spawned task re-checks as well, because Direct can
    // be confirmed between this fence and the rendezvous window.
    if peers.is_direct(&peer_id).await {
        peers
            .record_direct_event(
                &peer_id,
                "punch_skipped_already_direct",
                None,
                None,
                None,
                "skipped UDP punch because Direct path is already confirmed",
            )
            .await;
        debug!("Skipping UDP punch for {peer_id}; Direct path is already confirmed");
        return;
    }
    let claimed = match fresh_prediction {
        Some(id) => punch_deduplicator.claim_fresh_prediction(&peer_id, id).await,
        None => punch_deduplicator.claim(&peer_id).await,
    };
    let Some(session) = claimed else {
        peers
            .record_direct_event(
                &peer_id,
                "punch_suppressed",
                None,
                None,
                None,
                "suppressed overlapping UDP punch session for this peer",
            )
            .await;
        debug!("Suppressing overlapping UDP punch session for {peer_id}");
        return;
    };
    let punch_delay = relay_assisted_punch_delay(punch_at_ms);
    if !punch_delay.is_zero() {
        debug!(
            "Scheduling relay-assisted UDP punch to peer {peer_id} in {}ms",
            punch_delay.as_millis()
        );
    }

    tokio::spawn(async move {
        peers
            .record_direct_event(
                &peer_id,
                "punch_scheduled",
                None,
                None,
                None,
                format!(
                    "scheduled relay-assisted UDP punch delay_ms={} punch_at_ms={punch_at_ms:?}",
                    punch_delay.as_millis()
                ),
            )
            .await;

        // Run the fresh-mapping generation before waiting for the rendezvous
        // window: the measurement needs ~1s, and the peer-facing mapping must
        // already exist when the stable side starts probing at punch_at.
        let fresh_generation = if let Some(signal) = signal.as_ref() {
            if signal.boot_epoch_ms == 0 {
                peers
                    .record_direct_event(
                        &peer_id,
                        "fresh_mapping_skipped",
                        None,
                        None,
                        None,
                        "fresh-mapping prediction disabled this boot (no trustworthy persistent incarnation); continuing with ordinary punching",
                    )
                    .await;
                FreshMappingOutcome::Rejected(FreshMappingRejection::StableLocalNat)
            } else {
                let targets = peers.stable_remote_punch_targets_for(&peer_id).await;
                let mut generation = udp
                    .run_fresh_mapping_generation(
                        &peer_id,
                        &signal.stun_servers,
                        signal.stun_timeout,
                        &targets,
                        probe_interval,
                        attempts.min(2),
                        Some(&session.cancellation_handle()),
                    )
                    .await;
                match &mut generation {
                    FreshMappingOutcome::Accepted(result, handoff) => {
                        // The session may have been superseded while the
                        // generation measured: a stale prediction must not be
                        // advertised (its HTTP-send-time generation would look
                        // newer to the peer and cancel the fresher session).
                        if session.is_cancelled() {
                            peers
                                .record_direct_event(
                                    &peer_id,
                                    "fresh_mapping_skipped",
                                    None,
                                    None,
                                    None,
                                    "fresh-mapping generation completed but its punch session was superseded; not advertising the prediction",
                                )
                                .await;
                            // The guard stays alive until this task ends; its
                            // watcher then rolls the peer back to its
                            // previous path (nothing was advertised).
                        } else if peers.is_direct(&peer_id).await {
                            // Direct was confirmed while the generation
                            // measured: the prediction must not be advertised
                            // (a post-convergence HTTP signal) and the socket
                            // rolls back when the guard drops.
                            peers
                                .record_direct_event(
                                    &peer_id,
                                    "fresh_mapping_skipped",
                                    None,
                                    None,
                                    None,
                                    "fresh-mapping prediction was not advertised because Direct was confirmed while measuring",
                                )
                                .await;
                        } else {
                            // The durable handoff happens ONLY after the
                            // prediction is really advertised: a send failure
                            // or a cancellation during the advertise keeps the
                            // socket rollable, so the guard is dropped without
                            // finalizing instead of leaving an un-advertised
                            // socket as the peer's long-term path.
                            let advertised =
                                advertise_fresh_mapping_prediction(
                                    signal,
                                    &peers,
                                    &peer_id,
                                    &*result,
                                    &session.cancellation_handle(),
                                )
                                .await;
                            if advertised {
                                if !handoff.finalize().await {
                                    peers
                                        .record_direct_event(
                                            &peer_id,
                                            "fresh_mapping_skipped",
                                            None,
                                            None,
                                            None,
                                            "fresh-mapping prediction was advertised but the socket was rolled back before the durable handoff; continuing with ordinary punching",
                                        )
                                        .await;
                                }
                            } else {
                                peers
                                    .record_direct_event(
                                        &peer_id,
                                        "fresh_mapping_skipped",
                                        None,
                                        None,
                                        None,
                                        "fresh-mapping prediction was not advertised; the generation's socket rolls back to the previous path",
                                    )
                                    .await;
                            }
                        }
                    }
                    FreshMappingOutcome::Rejected(reason) => {
                        peers
                            .record_direct_event(
                                &peer_id,
                                "fresh_mapping_skipped",
                                None,
                                None,
                                None,
                                format!("fresh-mapping generation skipped: {}", reason.label()),
                            )
                            .await;
                    }
                }
                generation
            }
        } else {
            FreshMappingOutcome::Rejected(FreshMappingRejection::StableLocalNat)
        };

        if !punch_delay.is_zero() {
            sleep(punch_delay).await;
        }

        // Direct may have been confirmed while the fresh-mapping generation
        // measured or while the rendezvous window was pending: a stale task
        // must not start its candidate sweep on a confirmed path.
        if peers.is_direct(&peer_id).await {
            peers
                .record_direct_event(
                    &peer_id,
                    "punch_skipped_already_direct",
                    None,
                    None,
                    None,
                    "skipped UDP punch because Direct was confirmed while the punch session was pending",
                )
                .await;
            debug!("Skipping UDP punch for {peer_id}; Direct path was confirmed while waiting");
            return;
        }

        let generation = peers.current_network_generation().await;
        // A fresh-mapping prediction session punches toward the immutable
        // candidate snapshot frozen when the fresh signal arrived; ordinary
        // sessions read the shared candidate set at session time.  A later
        // ordinary refresh may update the shared set, but it must never change
        // the target of a running fresh session.
        let target = match frozen_targets {
            Some(frozen) => Some(DirectProbeTargetSet {
                peer_id: peer_id.clone(),
                candidates: frozen,
                remote_scatter_pool: false,
                stable_remote_scatter: false,
                birthday_plan: None,
            }),
            None => peers.direct_probe_target_set_for(&peer_id).await,
        };
        let Some(target) = target else {
            if peers.is_direct(&peer_id).await {
                peers
                    .record_direct_event(
                        &peer_id,
                        "punch_skipped_already_direct",
                        None,
                        None,
                        None,
                        "skipped UDP punch because Direct path is already confirmed",
                    )
                    .await;
                debug!("Skipping UDP punch for {peer_id}; Direct path is already confirmed");
                return;
            }
            // No candidate set yet: the peer just joined and its candidates
            // are still travelling through the control plane.  This is NOT a
            // failed probe batch — nothing was even attempted — so the path
            // must not degrade and force a relay selection while the
            // candidate exchange is still in flight.
            debug!("No UDP candidates for {peer_id}; skipping hole punch");
            peers
                .record_direct_event(
                    &peer_id,
                    "punch_skipped_no_candidates",
                    None,
                    None,
                    None,
                    "skipped UDP punch because the peer candidate set is still being exchanged",
                )
                .await;
            return;
        };
        let candidates = target.candidates;
        let remote_scatter_pool = target.remote_scatter_pool;
        let stable_remote_scatter = target.stable_remote_scatter;
        let birthday_plan = target.birthday_plan;
        if candidates.is_empty() {
            if peers.is_direct(&peer_id).await {
                peers
                    .record_direct_event(
                        &peer_id,
                        "punch_skipped_already_direct",
                        None,
                        None,
                        None,
                        "skipped UDP punch because Direct path is already confirmed",
                    )
                    .await;
                debug!("Skipping UDP punch for {peer_id}; Direct path is already confirmed");
                return;
            }
            debug!("No UDP candidates for {peer_id}; skipping hole punch");
            peers
                .record_direct_event(
                    &peer_id,
                    "punch_skipped_no_candidates",
                    None,
                    None,
                    None,
                    "skipped UDP punch because the candidate set is empty",
                )
                .await;
            return;
        }
        peers
            .record_direct_event(
                &peer_id,
                "punch_started",
                candidates.first().copied(),
                Some(candidates.len()),
                None,
                format!(
                    "starting synchronized UDP punch across {} candidates",
                    candidates.len()
                ),
            )
            .await;
        if let Some(plan) = birthday_plan.as_ref() {
            peers
                .record_birthday_probe_plan_started(&peer_id, plan)
                .await;
        }

        for endpoint in peers.direct_nat_maintainer_targets_for(&peer_id).await {
            udp.spawn_nat_binding_maintainer(
                &peer_id,
                endpoint,
                HARD_NAT_MAINTAINER_CONNECTING_INTERVAL,
                HARD_NAT_MAINTAINER_CONNECTING_DURATION,
            )
            .await;
        }

        let success_count_before = peers
            .direct_probe_success_count_for_generation(&peer_id, generation)
            .await;

        let rx_before = udp.probe_rx_snapshot().await;
        let mut last_punch_report: Option<PunchSendReport> = None;
        let deadline = punch_session_deadline(
            &candidates,
            probe_interval,
            attempts,
            remote_scatter_pool,
            if stable_remote_scatter {
                1
            } else {
                udp.socket_count()
            },
        );
        let outcome = run_owned_punch_session_with_deadline(&session, deadline, async {
            if session.is_cancelled() {
                return;
            }
            let punch_result = if matches!(fresh_generation, FreshMappingOutcome::Accepted(..))
                && udp.has_dynamic_socket_for_peer(&peer_id).await
            {
                udp.punch_candidates_from_dynamic_socket(
                    &peer_id,
                    candidates.clone(),
                    probe_interval,
                    attempts,
                )
                .await
            } else if stable_remote_scatter {
                udp.punch_candidates_stable_unique_scatter_until_not_direct(
                    &peer_id,
                    candidates.clone(),
                    probe_interval,
                    attempts,
                )
                .await
            } else if remote_scatter_pool {
                udp.punch_candidates_remote_scatter_pool_until_not_direct(
                    &peer_id,
                    candidates.clone(),
                    probe_interval,
                    attempts,
                )
                .await
                .map(|sent| PunchSendReport {
                    packets_sent: sent,
                    unique_target_endpoints: 0,
                })
            } else {
                udp.punch_candidates_until_not_direct(
                    &peer_id,
                    candidates.clone(),
                    probe_interval,
                    attempts,
                )
                .await
                .map(|sent| PunchSendReport {
                    packets_sent: sent,
                    unique_target_endpoints: 0,
                })
            };

            match punch_result {
                Ok(report) => {
                    last_punch_report = Some(report);
                    let sent = report.packets_sent;
                    let birthday_window_completion = if let Some(plan) =
                        birthday_plan.as_ref().filter(|_| stable_remote_scatter)
                    {
                        let covered_all_selected_candidates = stable_remote_scatter
                            && report.unique_target_endpoints as usize >= candidates.len();
                        let cursor_advanced = peers
                            .commit_birthday_probe_cursor(
                                &peer_id,
                                plan,
                                covered_all_selected_candidates,
                            )
                            .await;
                        peers
                            .record_direct_event(
                                &peer_id,
                                "birthday_probe_plan_completed",
                                candidates.first().copied(),
                                Some(candidates.len()),
                                Some(sent),
                                format!(
                                    "stable_side={} unique_target_endpoints={} covered_all_selected_candidates={} cursor_advanced={} start_rank={} end_rank={}",
                                    stable_remote_scatter,
                                    report.unique_target_endpoints,
                                    covered_all_selected_candidates,
                                    cursor_advanced,
                                    plan.start_rank,
                                    plan.end_rank
                                ),
                            )
                            .await;
                        Some((cursor_advanced, plan.wrapped))
                    } else {
                        None
                    };
                    info!("Sent {sent} UDP punch probes to peer {peer_id}");
                    peers
                        .record_direct_event(
                            &peer_id,
                            "punch_probes_sent",
                            candidates.first().copied(),
                            Some(candidates.len()),
                            Some(sent),
                            format!(
                                "sent {sent} UDP punch probes across {} candidates",
                                candidates.len()
                            ),
                        )
                        .await;
                    sleep(direct_probe_ack_grace(probe_interval)).await;
                    let success_count_after = peers
                        .direct_probe_success_count_for_generation(&peer_id, generation)
                        .await;
                    let rx_delta = udp.probe_rx_snapshot().await.delta_since(rx_before);
                    if sent > 0 && success_count_after == success_count_before {
                        let timeout_detail = format!(
                            "no matched UDP punch ACK after {sent} probes; known_peer_ip_rx_delta={} authenticated_probe_rx_delta={} authenticated_probe_ack_observed_delta={} authenticated_probe_ack_unmatched_delta={} legacy_probe_ack_observed_delta={} legacy_probe_ack_unmatched_delta={} matched_probe_ack_rx_delta={}",
                            rx_delta.known_peer_ip_datagrams_received,
                            rx_delta.authenticated_probe_packets_received,
                            rx_delta.authenticated_probe_acks_observed,
                            rx_delta.authenticated_probe_acks_unmatched,
                            rx_delta.legacy_probe_acks_observed,
                            rx_delta.legacy_probe_acks_unmatched,
                            rx_delta.probe_acks_received
                        );
                        peers
                            .record_direct_event(
                                &peer_id,
                                "punch_ack_timeout",
                                candidates.first().copied(),
                                Some(candidates.len()),
                                Some(sent),
                                timeout_detail.clone(),
                            )
                            .await;
                        match birthday_window_completion {
                            Some((true, completed_epoch)) => {
                                peers
                                    .record_expected_birthday_window_miss_for_generation(
                                        &peer_id,
                                        generation,
                                        &candidates,
                                        completed_epoch,
                                        timeout_detail,
                                    )
                                    .await;
                            }
                            Some((false, _)) => {
                                peers
                                    .record_direct_event(
                                        &peer_id,
                                        "birthday_probe_window_incomplete",
                                        candidates.first().copied(),
                                        Some(candidates.len()),
                                        Some(sent),
                                        "stable-side birthday window was not fully sent or its cursor became stale; retaining short retry cadence without peer backoff",
                                    )
                                    .await;
                            }
                            None if peers.has_relay_safety_net(&peer_id).await => {
                                peers
                                    .record_direct_probe_batch_failure_for_generation(
                                        &peer_id,
                                        generation,
                                        timeout_detail,
                                    )
                                    .await;
                            }
                            None => {}
                        }
                    }
                }
                Err(err) => {
                    peers
                        .record_direct_event(
                            &peer_id,
                            "punch_send_error",
                            candidates.first().copied(),
                            Some(candidates.len()),
                            None,
                            format!("hole punch failed: {err}"),
                        )
                        .await;
                    peers
                        .record_direct_failure_for_generation(
                            &peer_id,
                            generation,
                            REASON_DIRECT_PROBE_FAILED,
                            format!("hole punch failed: {err}"),
                        )
                        .await;
                    warn!("Failed to punch peer {peer_id}: {err}");
                }
            }
        })
        .await;

        match outcome {
            PunchSessionOutcome::Completed => {}
            PunchSessionOutcome::Cancelled => {
                peers
                    .record_direct_event(
                        &peer_id,
                        "punch_session_cancelled",
                        None,
                        None,
                        None,
                        "cancelled stale UDP punch session before replacement",
                    )
                    .await;
            }
            PunchSessionOutcome::DeadlineExceeded => {
                let rx_delta = udp.probe_rx_snapshot().await.delta_since(rx_before);
                let timeout_detail = format!(
                    "synchronized UDP punch session stopped after {}ms deadline; known_peer_ip_rx_delta={} authenticated_probe_rx_delta={} authenticated_probe_ack_observed_delta={} authenticated_probe_ack_unmatched_delta={} legacy_probe_ack_observed_delta={} legacy_probe_ack_unmatched_delta={} matched_probe_ack_rx_delta={}",
                    deadline.as_millis(),
                    rx_delta.known_peer_ip_datagrams_received,
                    rx_delta.authenticated_probe_packets_received,
                    rx_delta.authenticated_probe_acks_observed,
                    rx_delta.authenticated_probe_acks_unmatched,
                    rx_delta.legacy_probe_acks_observed,
                    rx_delta.legacy_probe_acks_unmatched,
                    rx_delta.probe_acks_received
                );
                peers
                    .record_direct_event(
                        &peer_id,
                        "punch_session_deadline",
                        candidates.first().copied(),
                        Some(candidates.len()),
                        None,
                        timeout_detail.clone(),
                    )
                    .await;
                if let (true, Some(plan)) = (stable_remote_scatter, birthday_plan.as_ref()) {
                    let covered_all = last_punch_report.is_some_and(|report| {
                        report.unique_target_endpoints as usize >= candidates.len()
                    });
                    if covered_all {
                        let cursor_advanced = peers
                            .commit_birthday_probe_cursor(&peer_id, plan, true)
                            .await;
                        peers
                            .record_direct_event(
                                &peer_id,
                                "birthday_probe_plan_completed",
                                candidates.first().copied(),
                                Some(candidates.len()),
                                last_punch_report.map(|report| report.packets_sent),
                                format!(
                                    "stable-side birthday session deadline after a complete send report; cursor_advanced={cursor_advanced} start_rank={} end_rank={}",
                                    plan.start_rank,
                                    plan.end_rank
                                ),
                            )
                            .await;
                    } else {
                        peers
                            .record_direct_event(
                                &peer_id,
                                "birthday_probe_window_incomplete",
                                candidates.first().copied(),
                                Some(candidates.len()),
                                None,
                                "stable-side birthday session hit its deadline before a complete send report; cursor and peer backoff were left unchanged",
                            )
                            .await;
                    }
                } else if peers.has_relay_safety_net(&peer_id).await {
                    peers
                        .record_direct_probe_batch_failure_for_generation(
                            &peer_id,
                            generation,
                            timeout_detail,
                        )
                        .await;
                }
            }
        }
    });
}

/// Advertise the fresh-mapping prediction window to the peer.
///
/// The predicted ports are signaled in priority order (top-1 first, then the
/// successor window) as real `predicted` candidates carrying the distinct
/// fresh-prediction label with the sender's incarnation+generation.  No
/// reserved metadata keys are embedded in `candidate_sources`: the control
/// plane requires every key to be a real candidate, values to stay under 64
/// bytes, and the map size to stay within the candidate count, so model
/// details travel only in structured logs and diagnostics.  Older clients
/// simply probe the ordered candidates, so the signal degrades gracefully to
/// today's strategy.
///
/// Ownership checks run before building the payload, again before the
/// command is queued, and inside the HTTP worker just before the request;
/// once the command is irrevocably on the wire the receiver's per-peer
/// fresh-generation high-water rejects any superseded label, so a stale
/// prediction can never overwrite a newer one.  A cancellation observed at
/// any of these fences is reported distinctly from a send failure.
///
/// Returns `true` only when the prediction was really accepted by the control
/// server while the session's ownership was still valid: the caller then
/// finalizes the generation's durable handoff.  A cancellation or a send
/// failure leaves the generation's socket rollable, so the caller must drop
/// the guard instead of finalizing.
async fn advertise_fresh_mapping_prediction(
    signal: &HolePunchSignalContext,
    peers: &Arc<PeerManager>,
    peer_id: &str,
    result: &FreshMappingResult,
    cancellation: &Arc<crate::PunchSessionCancellation>,
) -> bool {
    if cancellation.is_cancelled() {
        peers
            .record_direct_event(
                peer_id,
                "fresh_mapping_skipped",
                None,
                None,
                None,
                "fresh-mapping prediction ownership was revoked before the payload was built",
            )
            .await;
        return false;
    }
    let (candidates, candidate_sources) = build_fresh_mapping_signal_payload(
        result,
        signal.boot_epoch_ms,
        &signal.local_candidates.read().await.clone(),
        &signal.local_candidate_sources.read().await.clone(),
    );

    let punch_at_ms = Some(relay_assisted_punch_at_ms());
    if cancellation.is_cancelled() {
        peers
            .record_direct_event(
                peer_id,
                "fresh_mapping_skipped",
                None,
                Some(candidates.len()),
                None,
                "fresh-mapping prediction ownership was revoked before the signal was queued",
            )
            .await;
        return false;
    }
    // Direct may have been confirmed while the generation measured: a
    // post-convergence prediction advertisement would be pure HTTP noise and
    // must not reach the wire.
    if peers.is_direct(peer_id).await {
        peers
            .record_direct_event(
                peer_id,
                "fresh_mapping_skipped",
                None,
                Some(candidates.len()),
                None,
                "fresh-mapping prediction was not advertised because Direct was confirmed before the HTTP request",
            )
            .await;
        return false;
    }
    // The command worker re-checks the ownership inside the queue AND again
    // just before the HTTP request: a cancellation at either point surfaces
    // as `Cancelled`, which must never be mistaken for a successful send.
    match signal
        .control
        .send_fresh_peer_offer_with_sources_and_punch_at(
            peer_id,
            &candidates,
            &candidate_sources,
            &[],
            punch_at_ms,
            cancellation.clone(),
        )
        .await
    {
        Ok(()) => {}
        Err(PeerOfferSendFailure::Cancelled) => {
            peers
                .record_direct_event(
                    peer_id,
                    "fresh_mapping_skipped",
                    None,
                    Some(candidates.len()),
                    None,
                    "fresh-mapping prediction ownership was revoked before the HTTP request; the prediction was not sent",
                )
                .await;
            debug!(
                "Fresh-mapping prediction to peer {peer_id} was cancelled before the HTTP request; not finalizing the socket"
            );
            return false;
        }
        Err(PeerOfferSendFailure::SendFailed | PeerOfferSendFailure::ChannelClosed) => {
            warn!(
                "Failed to advertise fresh-mapping prediction window to peer {peer_id}"
            );
            return false;
        }
    }
    // The HTTP request completed and the server accepted the signal, but the
    // ownership may have been revoked while the request was in flight: only a
    // still-valid ownership lets the caller finalize the socket, otherwise
    // the watcher restores the predecessor.
    if cancellation.is_cancelled() {
        peers
            .record_direct_event(
                peer_id,
                "fresh_mapping_skipped",
                None,
                Some(candidates.len()),
                None,
                "fresh-mapping prediction was sent but its punch session was superseded before the durable handoff; the socket rolls back",
            )
            .await;
        return false;
    }
    // Direct may have been confirmed while the advertisement HTTP request was
    // in flight: the request was already on the wire (pre-Direct), but the
    // socket must roll back and no post-convergence signal may be recorded.
    if peers.is_direct(peer_id).await {
        peers
            .record_direct_event(
                peer_id,
                "fresh_mapping_skipped",
                None,
                Some(candidates.len()),
                None,
                "fresh-mapping prediction was sent pre-Direct but Direct was confirmed while the advertisement was in flight; the socket rolls back",
            )
            .await;
        return false;
    }
    info!(
        event = "fresh_mapping_prediction_signaled",
        peer_id = %peer_id,
        punch_generation = result.punch_generation,
        network_generation = result.network_generation,
        socket_local_endpoint = %result.socket_local_endpoint,
        first_punch_sent_at_ms = result.first_punch_sent_at_ms,
        last_punch_sent_at_ms = result.last_punch_sent_at_ms,
        socket_index = result.socket_index,
        predicted = ?result.predicted_ports,
        model = ?result.model.kind,
        confidence = result.model.confidence,
        candidate_count = candidates.len(),
        punch_at_ms = ?punch_at_ms,
        "fresh_mapping_prediction_signaled peer_id={} punch_generation={} network_generation={} socket_local={} first_sent_ms={} last_sent_ms={} socket_index={} predicted={:?} model={:?} confidence={} candidates={}",
        peer_id,
        result.punch_generation,
        result.network_generation,
        result.socket_local_endpoint,
        result.first_punch_sent_at_ms,
        result.last_punch_sent_at_ms,
        result.socket_index,
        result.predicted_ports,
        result.model.kind,
        result.model.confidence,
        candidates.len()
    );
    peers
        .record_direct_event(
            peer_id,
            "fresh_mapping_prediction_signaled",
            None,
            Some(candidates.len()),
            None,
            format!(
                "signaled predicted window punch_generation={} network_generation={} socket_local={} first_sent_ms={} last_sent_ms={} predicted={:?} model={:?} confidence={} candidates={}",
                result.punch_generation,
                result.network_generation,
                result.socket_local_endpoint,
                result.first_punch_sent_at_ms,
                result.last_punch_sent_at_ms,
                result.predicted_ports,
                result.model.kind.clone().label(),
                result.model.confidence,
                candidates.len()
            ),
        )
        .await;
    true
}

/// Build the signal payload carrying the fresh-mapping prediction window.
///
/// The payload must satisfy the control-plane validation rules applied by the
/// Go signaling service: every `candidate_sources` key must be a real
/// candidate, values must stay under 64 bytes, and the map size must not
/// exceed the candidate count.  The predicted ports are ordered top-1 first so
/// the stable side probes the model prediction before the successor window.
fn build_fresh_mapping_signal_payload(
    result: &FreshMappingResult,
    boot_epoch_ms: u64,
    current_candidates: &[String],
    current_sources: &HashMap<String, String>,
) -> (Vec<String>, HashMap<String, String>) {
    let mut candidates = Vec::new();
    let mut candidate_sources = HashMap::new();
    // Distinct label carrying the sender's incarnation epoch and per-peer
    // punch generation: ordinary ICE `predicted` candidates must not be
    // mistaken for a fresh prediction, and the embedded identity orders
    // predictions by measurement generation instead of HTTP send time.
    let fresh_id = FreshPredictionId {
        boot_epoch: boot_epoch_ms,
        generation: result.punch_generation,
    };
    let fresh_label = fresh_prediction_source_label(fresh_id);
    for port in &result.predicted_ports {
        let endpoint = SocketAddr::new(
            result.public_ip.unwrap_or(IpAddr::V4(Ipv4Addr::UNSPECIFIED)),
            *port,
        )
        .to_string();
        if !candidates.contains(&endpoint) {
            candidates.push(endpoint.clone());
            candidate_sources.insert(endpoint, fresh_label.clone());
        }
    }
    for endpoint in current_candidates {
        if !candidates.contains(endpoint) {
            candidates.push(endpoint.clone());
        }
        if let Some(source) = current_sources.get(endpoint) {
            // Never overwrite the fresh-prediction label of an overlapping
            // predicted port with the ordinary ICE label.
            candidate_sources
                .entry(endpoint.clone())
                .or_insert_with(|| source.clone());
        }
    }
    let _network_identity = prepare_signal_candidates_and_network_identity(
        &[],
        &HashMap::new(),
        &mut candidates,
        &mut candidate_sources,
    );
    (candidates, candidate_sources)
}
