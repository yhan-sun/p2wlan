use crate::peer::RecoveryStage;

#[allow(clippy::too_many_arguments)]
async fn run_direct_probe_loop(
    peers: Arc<PeerManager>,
    udp_transport: Arc<RwLock<Option<UdpTransport>>>,
    local_candidates: Arc<RwLock<Vec<String>>>,
    candidate_snapshot: Arc<RwLock<Option<CandidateSnapshotLease>>>,
    punch_deduplicator: PunchAttemptDeduplicator,
    control: ControlClient,
    stun_servers: Arc<RwLock<Vec<SocketAddr>>>,
    stun_timeout: Arc<RwLock<Duration>>,
    boot_epoch_ms: u64,
    retry_after: Duration,
    probe_interval: Duration,
    attempts: u32,
) {
    if retry_after.is_zero() || attempts == 0 {
        return;
    }

    let mut ticker = interval(retry_after);
    loop {
        ticker.tick().await;

        let Some(udp) = udp_transport.read().await.clone() else {
            continue;
        };

        if local_candidates.read().await.is_empty() {
            debug!("Local UDP candidates are not ready; delaying background Direct probe cycle");
            continue;
        }

        for target in peers.direct_probe_targets_due(retry_after).await {
            let peer_id = target.peer_id;
            let candidates = target.candidates;
            let preferred_fast_candidates = target.preferred_fast_candidates;
            let remote_scatter_pool = target.remote_scatter_pool;
            let stable_remote_scatter = target.stable_remote_scatter;
            let birthday_plan = target.birthday_plan;
            let reclaim_active = peers.direct_reclaim_active(&peer_id).await;
            // Every retry trigger enters the authoritative recovery-epoch
            // scheduler: one plan per (peer_id, generation, epoch), shared
            // budgets, newest-wins pending targets.
            let epoch = target.recovery_epoch;
            let Some(session) = punch_deduplicator
                .claim_for_epoch(&peer_id, epoch, PUNCH_PRIORITY_BACKGROUND, None)
                .await
            else {
                peers
                    .record_direct_event(
                        &peer_id,
                        if reclaim_active {
                            "direct_reclaim_punch_suppressed"
                        } else {
                            "retry_punch_suppressed"
                        },
                        candidates.first().copied(),
                        Some(candidates.len()),
                        None,
                        if reclaim_active {
                            "suppressed overlapping UDP Direct reclaim session for this peer"
                        } else {
                            "suppressed overlapping UDP retry session for this peer"
                        },
                    )
                    .await;
                // Newest-wins: the newest target stays stashed for the running
                // session's next stage boundary instead of being dropped.
                peers
                    .stash_recovery_target(PendingRecoveryTarget {
                        peer_id: peer_id.clone(),
                        candidates: candidates.clone(),
                        preferred_fast_candidates: preferred_fast_candidates.clone(),
                        frozen_targets: None,
                        fresh_prediction: None,
                        punch_at_ms: None,
                        seen_at: Instant::now(),
                    })
                    .await;
                continue;
            };
            let udp = udp.clone();
            let peers = peers.clone();
            let signal = {
                let stun_servers = stun_servers.read().await.clone();
                let stun_timeout = *stun_timeout.read().await;
                HolePunchSignalContext {
                    control: control.clone(),
                    candidate_snapshot: candidate_snapshot.clone(),
                    stun_servers,
                    stun_timeout,
                    boot_epoch_ms,
                }
            };
            // A multi-socket peer may probe ANY of our advertised socket-pool
            // mappings: temporarily activate the pool so every socket sends
            // peer-directed probes and every advertised mapping stays alive
            // for the peer's first punch (see `peer_needs_local_socket_pool`).
            if peers.peer_needs_local_socket_pool(&peer_id).await {
                udp.set_socket_pool_active(true);
            }
            if udp.socket_count() > 1 {
                peers
                    .record_direct_event(
                        &peer_id,
                        "direct_fast_probe_socket_pool_selected",
                        candidates.first().copied(),
                        Some(candidates.len()),
                        Some(udp.socket_count() as u32),
                        format!(
                            "background fast Direct prefix will use {} already-bound UDP sockets; transport-wide ActivePool remains unchanged",
                            udp.socket_count()
                        ),
                    )
                    .await;
            }
            let attempts = peers.recommended_punch_attempts(attempts).await;
            let generation = peers.current_network_generation().await;
            tokio::spawn(async move {
                // The retry's receive delta is meaningful only for the
                // Probe-v2 binding in force when this task was admitted.
                // Keep that value fixed across an in-flight rekey rather
                // than reading a different current session at timeout time.
                let probe_rx_session_id = peers.probe_session_id_for_peer(&peer_id).await;
                let rx_before = udp
                    .probe_rx_snapshot_for_peer_session(
                        &peer_id,
                        generation,
                        probe_rx_session_id.as_deref(),
                    )
                    .await;
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
                    // Direct may have been confirmed between target selection
                    // and this cycle: the bounded retry must not send into a
                    // confirmed path.  Recovery re-enters this loop through the
                    // reclaim window after a Direct health failure or a
                    // network-generation change.
                    if peers.is_direct(&peer_id).await {
                        peers
                            .record_direct_event(
                                &peer_id,
                                "retry_skipped_direct_confirmed",
                                None,
                                None,
                                None,
                                "skipped background UDP retry because Direct was confirmed after target selection",
                            )
                            .await;
                        return;
                    }
                    // Pre-flight liveness gate (default OFF).  If a fresh Blocked verdict is
                    // already cached, skip this punch round: outbound UDP is firewalled and relay
                    // carries the data plane, so re-scattering into it only burns budget.  This is
                    // READ-ONLY — it neither spawns a probe (the 0-ACK trigger is the sole spawn
                    // path) nor takes the recovery_epochs lock.
                    if peers.pre_flight_liveness_blocked(&peer_id, generation).await {
                        peers
                            .record_direct_event(
                                &peer_id,
                                "outbound_liveness_pre_flight_skip",
                                candidates.first().copied(),
                                Some(candidates.len()),
                                None,
                                "pre-flight liveness Blocked; skipping this punch round (relay is the data plane)",
                            )
                            .await;
                        return;
                    }
                    let punch_started_stage = if reclaim_active {
                        "direct_reclaim_punch_started"
                    } else {
                        "retry_punch_started"
                    };
                    let probes_sent_stage = if reclaim_active {
                        "direct_reclaim_probes_sent"
                    } else {
                        "retry_probes_sent"
                    };
                    let ack_timeout_stage = if reclaim_active {
                        "direct_reclaim_ack_timeout"
                    } else {
                        "retry_ack_timeout"
                    };
                    let probe_succeeded_stage = if reclaim_active {
                        "direct_reclaim_probe_succeeded"
                    } else {
                        "retry_probe_succeeded"
                    };
                    let send_error_stage = if reclaim_active {
                        "direct_reclaim_send_error"
                    } else {
                        "retry_send_error"
                    };
                    let retry_label = if reclaim_active {
                        "generation-change Direct reclaim"
                    } else {
                        "background UDP retry"
                    };
                    let success_count_before = peers
                        .direct_probe_success_count_for_generation(&peer_id, generation)
                        .await;
                    let commit_seq_before = peers.direct_commit_seq_sync(&peer_id);
                    peers
                        .record_direct_event(
                            &peer_id,
                            punch_started_stage,
                            candidates.first().copied(),
                            Some(candidates.len()),
                            None,
                            format!(
                                "starting {retry_label} across {} candidates",
                                candidates.len()
                            ),
                        )
                        .await;
                    if let Some(plan) = birthday_plan.as_ref() {
                        peers
                            .record_birthday_probe_plan_started(&peer_id, plan)
                            .await;
                    }

                    // Background retries do not have a relay-coordinated
                    // punch_at_ms, but they must not wait for the wide
                    // birthday/scatter sweep before trying the strongest
                    // candidates.  Keep this bounded (eight targets, one
                    // active-pool pass) and retain the relay-first invariant:
                    // only an authenticated Direct validation ACK can make
                    // this return early; a send or ACK failure falls through
                    // to the existing complete sweep.
                    let fast_candidates = if preferred_fast_candidates.is_empty() {
                        direct_fast_probe_candidates(&candidates)
                    } else {
                        direct_fast_probe_candidates_with_preferred(
                            &candidates,
                            &preferred_fast_candidates,
                        )
                    };
                    if direct_fast_probe_is_allowed(
                        remote_scatter_pool,
                        stable_remote_scatter,
                        false,
                    ) && !fast_candidates.is_empty()
                    {
                        peers
                            .record_direct_event(
                                &peer_id,
                                "direct_fast_probe_started",
                                fast_candidates.first().copied(),
                                Some(fast_candidates.len()),
                                None,
                                format!(
                                    "background retry immediate candidate window generation={} candidates={} remote_scatter_pool={} stable_remote_scatter={}",
                                    generation,
                                    fast_candidates.len(),
                                    remote_scatter_pool,
                                    stable_remote_scatter,
                                ),
                            )
                            .await;
                        let fast_result = udp
                            .punch_candidates_fast_prefix_until_not_direct_report(
                                &peer_id,
                                fast_candidates.clone(),
                                Duration::ZERO,
                                DIRECT_FAST_PROBE_ATTEMPTS,
                            )
                            .await;
                        match fast_result {
                            Ok(report) => {
                                peers
                                    .record_direct_event(
                                        &peer_id,
                                        "direct_fast_probe_sent",
                                        fast_candidates.first().copied(),
                                        Some(fast_candidates.len()),
                                        Some(report.packets_sent),
                                        format!(
                                            "background retry packets_sent={} actual_first_send_at_ms={:?}",
                                            report.packets_sent,
                                            report.first_send_at_ms,
                                        ),
                                    )
                                    .await;
                            }
                            Err(error) => {
                                peers
                                    .record_direct_event(
                                        &peer_id,
                                        "direct_fast_probe_failed",
                                        fast_candidates.first().copied(),
                                        Some(fast_candidates.len()),
                                        None,
                                        format!(
                                            "background retry fast candidate hint failed; continuing wide sweep: {error}"
                                        ),
                                    )
                                    .await;
                            }
                        }
                        if peers.is_direct(&peer_id).await {
                            peers
                                .record_direct_event(
                                    &peer_id,
                                    "direct_fast_probe_confirmed",
                                    None,
                                    Some(fast_candidates.len()),
                                    None,
                                    "background retry Direct validation committed before wide sweep",
                                )
                                .await;
                            return;
                        }
                        let fast_commit_seq = peers.direct_commit_seq_sync(&peer_id);
                        if peers
                            .wait_for_direct_commit_or_timeout(
                                &peer_id,
                                fast_commit_seq,
                                DIRECT_FAST_PROBE_ACK_WINDOW,
                            )
                            .await
                        {
                            peers
                                .record_direct_event(
                                    &peer_id,
                                    "direct_fast_probe_confirmed",
                                    None,
                                    Some(fast_candidates.len()),
                                    None,
                                    "background retry Direct validation committed during fast ACK window",
                                )
                                .await;
                            return;
                        }
                    }

                    // Fresh mapping is an optimization for later Direct
                    // windows. It must not delay this retry's first ordinary
                    // sweep; the old ordering spent the fresh-mapping
                    // measurement in front of every retry.
                    let fresh_mapping_task = {
                        let udp = udp.clone();
                        let peers = peers.clone();
                        let peer_id = peer_id.clone();
                        let signal = signal.clone();
                        let cancellation = session.cancellation_handle();
                        tokio::spawn(async move {
                        let fresh_generation = {
                        let targets = peers.stable_remote_punch_targets_for(&peer_id).await;
                        let mut generation = if !peers.try_begin_fresh_generation(&peer_id).await {
                            peers
                                .record_direct_event(
                                    &peer_id,
                                    "fresh_mapping_epoch_quota_exhausted",
                                    None,
                                    None,
                                    None,
                                    format!(
                                        "fresh-mapping generation skipped: the recovery epoch {epoch} already used its fresh-generation quota"
                                    ),
                                )
                                .await;
                            FreshMappingOutcome::Rejected(FreshMappingRejection::Superseded)
                        } else {
                            udp.run_fresh_mapping_generation(
                                &peer_id,
                                &signal.stun_servers,
                                signal.stun_timeout,
                                &targets,
                                probe_interval,
                                attempts.min(2),
                                Some(&cancellation),
                            )
                            .await
                        };
                        match &mut generation {
                            FreshMappingOutcome::Accepted(result, handoff) => {
                                if cancellation.is_cancelled() {
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
                                } else {
                                    // The durable handoff happens only after
                                    // the prediction is really advertised: a
                                    // send failure or a cancellation during
                                    // the advertise keeps the socket
                                    // rollable.
                                    let advertised = if !peers
                                        .try_consume_recovery_http_quota(&peer_id)
                                        .await
                                    {
                                        peers
                                            .record_direct_event(
                                                &peer_id,
                                                "fresh_mapping_epoch_http_quota_exhausted",
                                                None,
                                                None,
                                                None,
                                                format!(
                                                    "fresh-mapping prediction was not advertised: the recovery epoch {epoch} used its HTTP publish quota"
                                                ),
                                            )
                                            .await;
                                        false
                                    } else {
                                        advertise_fresh_mapping_prediction(
                                            &signal,
                                            &peers,
                                            &peer_id,
                                            &*result,
                                            &cancellation,
                                        )
                                        .await
                                    };
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
                                        format!(
                                            "fresh-mapping generation skipped: {}",
                                            reason.label()
                                        ),
                                    )
                                    .await;
                            }
                        }
                        generation
                    };
                        drop(fresh_generation);
                        })
                    };

                    for endpoint in peers.direct_nat_maintainer_targets_for(&peer_id).await {
                        udp.spawn_nat_binding_maintainer(
                            &peer_id,
                            endpoint,
                            HARD_NAT_MAINTAINER_CONNECTING_INTERVAL,
                            HARD_NAT_MAINTAINER_CONNECTING_DURATION,
                        )
                        .await;
                    }
                    // The relay-backed heartbeat keeps the direct punch windows
                    // warm at a low sustained rate for as long as the relay
                    // carries the data plane, independent of the recovery
                    // epoch's one-time credit/plan quotas.
                    udp.spawn_relay_backoff_heartbeat(
                        &peer_id,
                        RELAY_BACKOFF_HEARTBEAT_INTERVAL,
                    )
                    .await;
                    // A wide remote-scatter sweep is one CONTROLLED window
                    // coverage (see the synchronized punch for the field
                    // evidence): a prediction / scatter window must never be
                    // repeated through `attempts` rounds — one complete
                    // coverage per stage, then the feedback machine widens or
                    // rotates the window.  Repeated rounds only multiply
                    // physical datagrams on ports that already missed.
                    let effective_attempts = if remote_scatter_pool || stable_remote_scatter {
                        1
                    } else {
                        attempts
                    };
                    let punch_result = if stable_remote_scatter {
                        udp.punch_candidates_stable_unique_scatter_until_not_direct(
                            &peer_id,
                            candidates.clone(),
                            probe_interval,
                            effective_attempts,
                        )
                        .await
                    } else if remote_scatter_pool {
                        udp.punch_candidates_remote_scatter_pool_until_not_direct_report(
                            &peer_id,
                            candidates.clone(),
                            probe_interval,
                            effective_attempts,
                        )
                        .await
                    } else {
                        udp.punch_candidates_until_not_direct_report(
                            &peer_id,
                            candidates.clone(),
                            probe_interval,
                            effective_attempts,
                        )
                        .await
                    };

                    match punch_result {
                        Ok(report) if report.packets_sent == 0 => {
                            // Zero-send is NOT a silent success: with a
                            // non-empty candidate set every probe was rejected
                            // by the admission layer.  Record the structured
                            // verdict and freeze the recovery epoch with a
                            // controlled backoff so the next 1-second tick
                            // cannot rebuild the same wide plan.
                            let (visited, skipped, reason) = if report.epoch_budget_exhausted {
                                (
                                    report.budget_skipped as u64,
                                    report.budget_skipped as u64,
                                    "recovery_epoch_credit_exhausted",
                                )
                            } else if report.candidate_iteration_capped {
                                (
                                    candidates.len() as u64,
                                    report.budget_skipped as u64,
                                    "recovery_candidate_iteration_budget_exhausted",
                                )
                            } else {
                                (
                                    candidates.len() as u64,
                                    report.budget_skipped as u64,
                                    "all_probes_rejected_by_budget",
                                )
                            };
                            peers
                                .record_zero_send_recovery_session(
                                    &peer_id,
                                    candidates.len() as u64,
                                    visited,
                                    skipped,
                                    reason,
                                )
                                .await;
                        }
                        Ok(report) => {
                            let sent = report.packets_sent;
                            let actual_first_send_at_ms = report.first_send_at_ms;
                            let per_socket_sent = report
                                .per_socket_sent
                                .iter()
                                .map(|(socket, count)| format!("{socket}:{count}"))
                                .collect::<Vec<_>>()
                                .join(",");
                            peers
                                .record_direct_event(
                                    &peer_id,
                                    "retry_first_packet_sent",
                                    candidates.first().copied(),
                                    Some(candidates.len()),
                                    Some(sent),
                                    format!(
                                        "session_id={} network_generation={} recovery_epoch={} actual_first_send_at_ms={actual_first_send_at_ms:?} per_socket_actual_datagrams={per_socket_sent}",
                                        session.session_id(),
                                        generation,
                                        epoch,
                                    ),
                                )
                                .await;
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
                            last_punch_report = Some(report);
                            peers
                                .record_direct_event(
                                    &peer_id,
                                    probes_sent_stage,
                                    candidates.first().copied(),
                                    Some(candidates.len()),
                                    Some(sent),
                                    format!("sent {sent} {retry_label} probes"),
                                )
                                .await;
                            // Bounded feedback window: wait for a matched ACK
                            // (or a Direct commit) instead of a bare sleep so
                            // a promotion reliably preempts the next retry
                            // stage.
                            let promoted = peers
                                .wait_for_direct_commit_or_timeout(
                                    &peer_id,
                                    commit_seq_before,
                                    RECOVERY_EPOCH_ACK_FEEDBACK_WINDOW
                                        .max(direct_probe_ack_grace(probe_interval)),
                                )
                                .await;
                            if promoted {
                                peers
                                    .record_direct_event(
                                        &peer_id,
                                        "retry_ack_feedback_commit",
                                        candidates.first().copied(),
                                        Some(candidates.len()),
                                        Some(sent),
                                        "Direct commit observed during the ACK feedback window; ending the retry session",
                                    )
                                    .await;
                            }
                            let success_count_after = peers
                                .direct_probe_success_count_for_generation(&peer_id, generation)
                                .await;
                            let rx_delta = udp
                                .probe_rx_snapshot_for_peer_session(
                                    &peer_id,
                                    generation,
                                    probe_rx_session_id.as_deref(),
                                )
                                .await
                                .delta_since(rx_before);
                            if success_count_after == success_count_before {
                                {
                                    // Outbound-UDP liveness (P1: spawned, never awaited here).
                                    // Trigger only at the ScatterExtended boundary where the
                                    // wide window has actually been sent (`window_completed`)
                                    // — triggering earlier (Initial/Predicted/ScatterSmall)
                                    // would judge a firewall before enough of the window was
                                    // scanned, and a birthday `Some((false,_))` window was not
                                    // fully sent so "exhausted" is not yet proven. The probe
                                    // runs in its own task; a Blocked verdict it writes is
                                    // consumed at the next tick's admission
                                    // (apply_cached_liveness_block).
                                    let stage = peers.recovery_stage_for(&peer_id).await;
                                    // `birthday_window_completion` is `Option<(bool, bool)>`;
                                    // borrow it (do NOT move — the `match` below consumes it).
                                    // Non-birthday sweeps (None) have sent their full window,
                                    // so `window_completed` is true.
                                    let window_completed = birthday_window_completion
                                        .as_ref()
                                        .map(|(cursor_advanced, _)| *cursor_advanced)
                                        .unwrap_or(!stable_remote_scatter);
                                    if stage == RecoveryStage::ScatterExtended
                                        && window_completed
                                        && peers.liveness_probe_due(&peer_id, generation).await
                                    {
                                        let p = peers.clone(); // Arc<PeerManager> → owned by the task
                                        let pid = peer_id.clone();
                                        tokio::spawn(async move {
                                            p.run_outbound_liveness_probe(&pid, generation)
                                                .await;
                                        });
                                    }
                                }
                                let timeout_detail = format!(
                                    "no matched direct probe ACK after {sent} {retry_label} probes; probe_session_id={} known_peer_ip_rx_delta={} authenticated_probe_rx_delta={} authenticated_probe_ack_observed_delta={} authenticated_probe_ack_unmatched_delta={} legacy_probe_ack_observed_delta={} legacy_probe_ack_unmatched_delta={} matched_probe_ack_rx_delta={}",
                                    probe_rx_session_id.as_deref().unwrap_or("legacy"),
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
                                        ack_timeout_stage,
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
                                    None => {
                                        peers
                                            .record_direct_probe_batch_failure_for_generation(
                                                &peer_id,
                                                generation,
                                                timeout_detail,
                                            )
                                            .await;
                                    }
                                }
                                debug!(
                                    "Direct UDP retry probes for peer {peer_id} received no ACK"
                                );
                            } else {
                                peers
                                    .record_direct_event(
                                        &peer_id,
                                        probe_succeeded_stage,
                                        candidates.first().copied(),
                                        Some(candidates.len()),
                                        Some(sent),
                                        format!(
                                            "{retry_label} received an ACK; awaiting encrypted validation"
                                        ),
                                    )
                                    .await;
                                debug!(
                                    "Direct UDP retry probes reached peer {peer_id}; awaiting encrypted validation"
                                );
                            }
                        }
                        Err(err) => {
                            peers
                                .record_direct_event(
                                    &peer_id,
                                    send_error_stage,
                                    candidates.first().copied(),
                                    Some(candidates.len()),
                                    None,
                                    format!("{retry_label} failed: {err}"),
                                )
                                .await;
                            peers
                                .record_direct_probe_batch_failure_for_generation(
                                    &peer_id,
                                    generation,
                                    format!("{retry_label} failed: {err}"),
                                )
                                .await;
                            peers
                                .mark_recovery_relay_backoff(
                                    &peer_id,
                                    &format!("{retry_label} failed: {err}"),
                                )
                                .await;
                            warn!("Failed to retry direct UDP probes for peer {peer_id}: {err}");
                        }
                    }
                    if let Err(error) = fresh_mapping_task.await {
                        peers
                            .record_direct_event(
                                &peer_id,
                                "fresh_mapping_worker_failed",
                                None,
                                None,
                                None,
                                format!("fresh-mapping worker failed after the retry sweep: {error}"),
                            )
                            .await;
                    }
                })
                .await;

                match outcome {
                    PunchSessionOutcome::Completed => {}
                    PunchSessionOutcome::Cancelled => {
                        peers
                            .record_direct_event(
                                &peer_id,
                                "retry_session_cancelled",
                                None,
                                None,
                                None,
                                "cancelled background UDP retry for a synchronized punch",
                            )
                            .await;
                    }
                    PunchSessionOutcome::DeadlineExceeded => {
                        let rx_delta = udp
                            .probe_rx_snapshot_for_peer_session(
                                &peer_id,
                                generation,
                                probe_rx_session_id.as_deref(),
                            )
                            .await
                            .delta_since(rx_before);
                        let timeout_detail = format!(
                            "background UDP retry stopped after {}ms deadline; probe_session_id={} known_peer_ip_rx_delta={} authenticated_probe_rx_delta={} authenticated_probe_ack_observed_delta={} authenticated_probe_ack_unmatched_delta={} legacy_probe_ack_observed_delta={} legacy_probe_ack_unmatched_delta={} matched_probe_ack_rx_delta={}",
                            deadline.as_millis(),
                            probe_rx_session_id.as_deref().unwrap_or("legacy"),
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
                                "retry_session_deadline",
                                candidates.first().copied(),
                                Some(candidates.len()),
                                None,
                                timeout_detail.clone(),
                            )
                            .await;
                        if let (true, Some(plan)) = (stable_remote_scatter, birthday_plan.as_ref()) {
                            // The deadline can cut the session short even
                            // though the whole planned window was already
                            // sent (the session was only waiting out the ACK
                            // grace): advance the cursor so the next cycle
                            // does not rescan the same 3,000 ports.
                            let covered_all = last_punch_report
                                .as_ref()
                                .is_some_and(|report| {
                                    report.unique_target_endpoints as usize >= candidates.len()
                                });
                            if covered_all {
                                let cursor_advanced = peers
                                    .commit_birthday_probe_cursor(
                                        &peer_id,
                                        plan,
                                        true,
                                    )
                                    .await;
                                peers
                                    .record_direct_event(
                                        &peer_id,
                                        "birthday_probe_plan_completed",
                                        candidates.first().copied(),
                                        Some(candidates.len()),
                                        last_punch_report
                                            .as_ref()
                                            .map(|report| report.packets_sent),
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
                        } else {
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
    }
}
