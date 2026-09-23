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
    spawn_hole_punch_task_with_lifecycle(
        udp,
        peers,
        punch_deduplicator,
        peer_id,
        probe_interval,
        attempts,
        punch_at_ms,
        signal,
        fresh_prediction,
        frozen_targets,
        None,
    )
    .await;
}

/// Publish one hard punch-send failure only for the lifecycle that admitted
/// the punch worker.  Keeping this in a small helper makes the delayed-worker
/// fence directly testable without relying on an operating-system-specific UDP
/// send failure.
async fn record_hole_punch_send_error_for_lifecycle(
    peers: &PeerManager,
    peer_id: &str,
    network_generation: u64,
    peer_session_generation: PeerSessionGeneration,
    detail: &str,
) -> bool {
    let failed = peers
        .record_direct_failure_for_generation_and_peer_session_with_local_endpoint(
            peer_id,
            network_generation,
            peer_session_generation,
            REASON_DIRECT_PROBE_FAILED,
            detail,
            None,
        )
        .await;
    if failed {
        peers
            .mark_recovery_relay_backoff_for_peer_session(peer_id, peer_session_generation, detail)
            .await;
    }
    failed
}

/// Spawn a hole-punch worker owned by one UDP publication lease.
///
/// The optional receiver is deliberately per invocation.  It cancels only the
/// permit/session created by this call and therefore cannot tear down a newer
/// worker which happens to target the same peer through a replacement socket.
#[allow(clippy::too_many_arguments)]
async fn spawn_hole_punch_task_with_lifecycle(
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
    invocation_shutdown_rx: Option<tokio::sync::watch::Receiver<bool>>,
) {
    if punch_invocation_is_cancelled(invocation_shutdown_rx.as_ref()) {
        return;
    }
    let hard_hard_experiment_only = peers.hard_hard_experiment_only();
    // Bind every delayed result from this invocation to the exact online
    // lifecycle that admitted it.  Peer IDs are reusable after PeerLeft, so a
    // worker which merely re-reads `online=true` at completion can otherwise
    // publish an old send error into a same-node replacement (ABA).
    let Some(peer_session_generation) = peers.peer_session_generation_sync(&peer_id) else {
        return;
    };
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
    if punch_invocation_is_cancelled(invocation_shutdown_rx.as_ref()) {
        return;
    }
    // Hard↔Hard is a planner-gated replacement for the ordinary first punch
    // only on the deterministic initiator side.  The initiator measures a
    // fresh socket and publishes the first prediction; the responder is
    // entered exclusively by the matching `hh1` fresh signal.  Other NAT
    // strategies continue through the existing scheduler below.
    let local_is_hard_hard_initiator = peers.local_node_id_for_traversal() < peer_id;
    if fresh_prediction.is_none() && frozen_targets.is_none() && local_is_hard_hard_initiator {
        if let Some(plan) = peers.hard_hard_plan_for_peer(&peer_id).await {
            if let Some(signal) = signal.clone() {
                peers
                    .record_direct_event(
                        &peer_id,
                        "hard_hard_initiator_selected",
                        None,
                        None,
                        None,
                        format!(
                            "planner authorized Hard↔Hard synchronized fresh mapping local_network_generation={} remote_candidate_epoch={} local_profile_generation={} remote_profile_generation={}",
                            plan.local_network_generation,
                            plan.remote_candidate_epoch,
                            plan.local_profile_generation,
                            plan.remote_profile_generation,
                        ),
                    )
                    .await;
                let hard_hard_start = spawn_hard_hard_initiator(
                    udp.clone(),
                    peers.clone(),
                    punch_deduplicator.clone(),
                    peer_id.clone(),
                    signal,
                    invocation_shutdown_rx.clone(),
                )
                .await;
                if hard_hard_start.is_handled() {
                    return;
                }
                peers
                    .record_direct_event(
                        &peer_id,
                        "hard_hard_fallback_to_ordinary",
                        None,
                        None,
                        None,
                        format!(
                            "Hard↔Hard did not acquire a traversal owner; {} reason={}",
                            if hard_hard_experiment_only {
                                "ordinary fallback suppressed by the explicit experiment lane"
                            } else {
                                "continuing with ordinary synchronized punching"
                            },
                            hard_hard_start
                                .fallback_reason()
                                .unwrap_or("unknown_not_started")
                        ),
                    )
                    .await;
            } else {
                hard_hard_a0_stage_log(
                    &peers,
                    "initiator",
                    None,
                    HardHardA0Stage::OwnerAdmission,
                    HardHardA0Reason::SignalContextUnavailable,
                );
            }
        } else {
            hard_hard_a0_stage_log(
                &peers,
                "initiator",
                None,
                HardHardA0Stage::PlannerEligibility,
                HardHardA0Reason::PlanUnavailable,
            );
        }
    }
    if hard_hard_experiment_only {
        if !local_is_hard_hard_initiator && fresh_prediction.is_none() && frozen_targets.is_none() {
            hard_hard_a0_stage_log(
                &peers,
                "responder",
                None,
                HardHardA0Stage::PeerSignalAdmission,
                HardHardA0Reason::AwaitingPeerSignal,
            );
        }
        peers
            .record_direct_event(
                &peer_id,
                "hard_hard_experiment_waiting",
                None,
                None,
                None,
                if fresh_prediction.is_some() || frozen_targets.is_some() {
                    "suppressed an ordinary predicted/frozen-target punch in the isolated Hard↔Hard experiment lane"
                } else if local_is_hard_hard_initiator {
                    "planner prerequisites are not currently authorized; Relay remains available while the experiment waits for a fresh fenced trigger"
                } else {
                    "deterministic responder is waiting for the initiator's authenticated hh1 signal"
                },
            )
            .await;
        return;
    }
    // Every trigger enters the authoritative recovery-epoch scheduler: one
    // traversal plan per (peer_id, generation, epoch) with shared hard
    // budgets.  A trigger inside the current epoch can never spawn a parallel
    // session; it only updates the newest-wins pending target.
    let RecoveryAdmission::Accepted { epoch } = peers.recovery_epoch_admit(&peer_id).await else {
        peers
            .record_direct_event(
                &peer_id,
                "punch_suppressed_superseded",
                None,
                None,
                None,
                "suppressed punch trigger: peer is Direct, offline or gone",
            )
            .await;
        return;
    };
    let claim_priority = if fresh_prediction.is_some() {
        PUNCH_PRIORITY_FRESH_PREDICTION
    } else {
        PUNCH_PRIORITY_SYNCHRONIZED
    };
    // Capture a trusted target snapshot before claiming. When this trigger is
    // folded into a valid first rendezvous window the snapshot is stashed for
    // that owner's dispatch; it is never silently discarded just because a
    // dedup permit is already active.
    let trigger_candidates = match &frozen_targets {
        Some(frozen) => frozen.clone(),
        None => peers
            .direct_probe_target_set_for(&peer_id)
            .await
            .map(|target| target.candidates)
            .unwrap_or_default(),
    };
    let trigger_candidates = peers
        .current_remote_endpoints_for(&peer_id, trigger_candidates)
        .await;
    let trigger_snapshot = punch_candidate_snapshot(&peers, &peer_id, trigger_candidates).await;
    if punch_invocation_is_cancelled(invocation_shutdown_rx.as_ref()) {
        return;
    }
    let network_generation = peers.current_network_generation().await;
    let Some(claimed) = punch_deduplicator
        .claim_for_epoch_with_rendezvous_for_peer_session(
            &peers,
            &peer_id,
            peer_session_generation,
            network_generation,
            epoch,
            claim_priority,
            fresh_prediction,
            punch_at_ms,
        )
        .await
    else {
        return;
    };
    let session = match claimed {
        RendezvousPunchClaim::Claimed(session) => session,
        RendezvousPunchClaim::Deferred(deferred) => {
            let stashed = if trigger_snapshot.candidates.is_empty() {
                false
            } else {
                peers
                    .stash_recovery_target(PendingRecoveryTarget {
                        peer_id: peer_id.clone(),
                        candidates: trigger_snapshot.candidates.clone(),
                        preferred_fast_candidates: trigger_snapshot
                            .preferred_fast_candidates
                            .clone(),
                        // A valid fresh snapshot stays immutable even when it
                        // is deferred behind the first ordinary send. An
                        // ordinary refresh remains a normal latest snapshot.
                        frozen_targets: fresh_prediction
                            .is_some()
                            .then_some(trigger_snapshot.candidates.clone()),
                        fresh_prediction,
                        // The active plan owns its already-coordinated
                        // punch_at. Do not re-clock it to this later offer.
                        punch_at_ms: None,
                        seen_at: Instant::now(),
                    })
                    .await;
                true
            };
            peers
                .record_direct_event(
                    &peer_id,
                    "punch_window_preserved",
                    trigger_snapshot.candidates.first().copied(),
                    Some(trigger_snapshot.candidates.len()),
                    None,
                    format!(
                        "incoming synchronized trigger folded into active session_id={} active_generation={} active_epoch={} active_punch_at_ms={:?} reason={} incoming_generation={} incoming_epoch={} incoming_punch_at_ms={punch_at_ms:?} candidate_snapshot_hash={:016x} candidate_source_count={} candidate_source_category_count={} candidate_source_counts={} target_stashed={stashed}",
                        deferred.active_session_id,
                        deferred.active_network_generation,
                        deferred.active_epoch,
                        deferred.active_punch_at_ms,
                        deferred.reason.label(),
                        network_generation,
                        epoch,
                        trigger_snapshot.hash,
                        trigger_snapshot.source_count,
                        trigger_snapshot.source_category_count,
                        trigger_snapshot.source_summary,
                    ),
                )
                .await;
            debug!(
                "Preserving active relay-assisted rendezvous for {peer_id}: session={} reason={}",
                deferred.active_session_id,
                deferred.reason.label()
            );
            return;
        }
        RendezvousPunchClaim::RejectedStalePeerSession => return,
    };
    let punch_delay = relay_assisted_punch_delay(punch_at_ms);
    if !punch_delay.is_zero() {
        debug!(
            "Scheduling relay-assisted UDP punch to peer {peer_id} in {}ms",
            punch_delay.as_millis()
        );
    }

    let invocation_cancellation = session.cancellation_handle();
    tokio::spawn(async move {
        let worker = async move {
            if !peers.peer_session_is_current_sync(&peer_id, peer_session_generation) {
                return;
            }
            peers
            .record_direct_event(
                &peer_id,
                "punch_scheduled",
                None,
                None,
                None,
                format!(
                    "scheduled relay-assisted UDP punch session_id={} network_generation={} recovery_epoch={} delay_ms={} punch_at_ms={punch_at_ms:?} candidate_snapshot_hash={:016x} candidate_source_count={} candidate_source_category_count={} candidate_source_counts={}",
                    session.session_id(),
                    network_generation,
                    epoch,
                    punch_delay.as_millis(),
                    trigger_snapshot.hash,
                    trigger_snapshot.source_count,
                    trigger_snapshot.source_category_count,
                    trigger_snapshot.source_summary,
                ),
            )
            .await;

            // Fresh mapping is an optimization for later Direct retries.  It must
            // not sit in front of the first relay-assisted/ordinary punch: field
            // evidence showed this measurement can take about a second.  Build a
            // self-contained future now and start it only after all early
            // cancellation/candidate gates below have passed; the first punch and
            // this optimization then run concurrently.
            let fresh_mapping_future = {
                let signal = signal.clone();
                let udp = udp.clone();
                let peers = peers.clone();
                let peer_id = peer_id.clone();
                let cancellation = session.cancellation_handle();
                async move {
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
                            let Some(reservation) = peers
                                .try_begin_fresh_generation_for_epoch(&peer_id, epoch)
                                .await
                            else {
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
                                return;
                            };
                            if cancellation.is_cancelled()
                                || !peers
                                    .peer_session_is_current_sync(&peer_id, peer_session_generation)
                            {
                                reservation.refund().await;
                                return;
                            }
                            let recovery_identity = reservation.identity();
                            reservation.commit();
                            let targets = peers.stable_remote_punch_targets_for(&peer_id).await;
                            let mut generation = udp
                                .run_fresh_mapping_generation(
                                    &peer_id,
                                    &signal.stun_servers,
                                    signal.stun_timeout,
                                    &targets,
                                    probe_interval,
                                    attempts.min(2),
                                    Some(&cancellation),
                                )
                                .await;
                            match &mut generation {
                                FreshMappingOutcome::Accepted(result, handoff) => {
                                    // The session may have been superseded while the
                                    // generation measured: a stale prediction must not be
                                    // advertised (its HTTP-send-time generation would look
                                    // newer to the peer and cancel the fresher session).
                                    if cancellation.is_cancelled()
                                        || !peers.peer_session_is_current_sync(
                                            &peer_id,
                                            peer_session_generation,
                                        )
                                    {
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
                                        let advertised = if cancellation.is_cancelled()
                                            || !peers.peer_session_is_current_sync(
                                                &peer_id,
                                                peer_session_generation,
                                            ) {
                                            false
                                        } else if !peers
                                            .try_consume_recovery_http_quota_for_identity(
                                                &peer_id,
                                                recovery_identity,
                                            )
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
                                        } else if cancellation.is_cancelled()
                                            || !peers.peer_session_is_current_sync(
                                                &peer_id,
                                                peer_session_generation,
                                            )
                                        {
                                            false
                                        } else {
                                            advertise_fresh_mapping_prediction(
                                                signal,
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
                        }
                    } else {
                        FreshMappingOutcome::Rejected(FreshMappingRejection::StableLocalNat)
                    };
                    drop(fresh_generation);
                }
            };

            if session.is_cancelled()
                || !peers.peer_session_is_current_sync(&peer_id, peer_session_generation)
            {
                peers
                .record_direct_event(
                    &peer_id,
                    "punch_session_cancelled",
                    None,
                    None,
                    None,
                    format!(
                        "cancelled scheduled UDP punch before rendezvous wait session_id={} network_generation={} recovery_epoch={} reason={}",
                        session.session_id(),
                        network_generation,
                        epoch,
                        session
                            .cancellation_reason()
                            .map(PunchCancellationReason::label)
                            .unwrap_or("unknown"),
                    ),
                )
                .await;
                return;
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

            // The dedup/recovery owner was claimed for `network_generation` before
            // this task was spawned. Never retag the delayed worker with whatever
            // network generation happens to be current after the rendezvous wait.
            let generation = network_generation;
            // A fresh-mapping prediction session punches toward the immutable
            // candidate snapshot frozen when the fresh signal arrived; ordinary
            // sessions read the shared candidate set at session time.  A later
            // ordinary refresh may update the shared set, but it must never change
            // the target of a running fresh session.
            //
            // The frozen prediction window NEVER replaces the ordinary candidate
            // set: it is UNIONED with it.  Field evidence (v0.1.115 Mini log): a
            // destination-dependent CGNAT peer (Air) advertised a 96-port
            // prediction window that its actual peer-facing mapping (port 6609)
            // was NOT inside, while the ordinary candidate set carried the peer's
            // STUN-observed endpoint (6467).  Because the frozen window replaced
            // the ordinary set, all four 512-probe sessions (2048 datagrams)
            // scanned the wrong window and the only working signal was the
            // peer-reflexive observation.  Merging keeps the trusted ordinary
            // candidates FIRST (they carry real authenticated evidence) and
            // appends the prediction window after them.
            //
            // The newest-wins pending target (stashed by a trigger that was
            // suppressed while another session ran) wins over a freshly computed
            // target: new candidates update the plan's target without ever
            // resetting its budgets or starting a parallel session.
            let pending_target = peers.take_recovery_target(&peer_id).await;
            let merge_frozen = |ordinary: Option<DirectProbeTargetSet>,
                                frozen: Option<Vec<SocketAddr>>,
                                preferred_fast_candidates: Option<Vec<SocketAddr>>,
                                recovery_epoch: u64|
             -> Option<DirectProbeTargetSet> {
                let frozen = frozen.unwrap_or_default();
                let preferred_fast_candidates =
                    preferred_fast_candidates.unwrap_or_else(|| frozen.clone());
                match ordinary {
                    Some(mut ordinary) => {
                        merge_unique_socket_addresses(&mut ordinary.candidates, &frozen);
                        merge_unique_socket_addresses(
                            &mut ordinary.preferred_fast_candidates,
                            &preferred_fast_candidates,
                        );
                        Some(ordinary)
                    }
                    None if !frozen.is_empty() => Some(DirectProbeTargetSet {
                        peer_id: peer_id.clone(),
                        preferred_fast_candidates,
                        candidates: frozen,
                        remote_scatter_pool: false,
                        stable_remote_scatter: false,
                        birthday_plan: None,
                        recovery_epoch,
                    }),
                    None => None,
                }
            };
            // Snapshot before the match consumes the option: the owned punch
            // block below still needs to know whether this session is a frozen
            // prediction window (it decides the attempt policy and the bounded
            // fast prefix). A pending fresh prediction can replace the original
            // trigger target, so retain that snapshot too.
            let mut is_frozen_prediction_window = frozen_targets.is_some();
            let mut fast_prediction_candidates = frozen_targets.clone().unwrap_or_default();
            let target = match pending_target {
                Some(pending) => {
                    if let Some(punch_at) = pending.punch_at_ms {
                        debug!(
                        "Punch session for {peer_id} picked up a newest-wins pending target (fresh_prediction={:?} punch_at_ms={punch_at} candidates={})",
                        pending.fresh_prediction,
                        pending.candidates.len()
                    );
                    }
                    let has_frozen = pending.frozen_targets.is_some();
                    let pending_preferred_fast_candidates = if has_frozen {
                        pending.frozen_targets.clone().unwrap_or_default()
                    } else {
                        pending.preferred_fast_candidates.clone()
                    };
                    if has_frozen {
                        fast_prediction_candidates = pending_preferred_fast_candidates.clone();
                        is_frozen_prediction_window = true;
                    } else {
                        // A newer ordinary refresh supersedes the original
                        // prediction target. Never let the old frozen window leak
                        // into the fast prefix of the replacement session, but do
                        // retain the refresh's authenticated/learned sources.
                        fast_prediction_candidates = pending_preferred_fast_candidates.clone();
                        is_frozen_prediction_window = false;
                    }
                    let frozen = if has_frozen {
                        pending.frozen_targets
                    } else {
                        Some(pending.candidates)
                    };
                    let ordinary = if has_frozen {
                        peers.direct_probe_target_set_for(&peer_id).await
                    } else {
                        None
                    };
                    merge_frozen(
                        ordinary,
                        frozen,
                        Some(pending_preferred_fast_candidates),
                        epoch,
                    )
                }
                None => match frozen_targets {
                    Some(frozen) => {
                        let ordinary = peers.direct_probe_target_set_for(&peer_id).await;
                        merge_frozen(ordinary, Some(frozen), None, epoch)
                    }
                    None => peers.direct_probe_target_set_for(&peer_id).await,
                },
            };
            let Some(mut target) = target else {
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
            // The target may have crossed another await boundary since it was
            // selected. Re-check the remote epoch immediately before deriving the
            // actual send vectors so a retired frozen prediction cannot be merged
            // back into the running session.
            target.candidates = peers
                .current_remote_endpoints_for(&peer_id, target.candidates)
                .await;
            target.preferred_fast_candidates = peers
                .current_remote_endpoints_for(&peer_id, target.preferred_fast_candidates)
                .await;
            fast_prediction_candidates = peers
                .current_remote_endpoints_for(&peer_id, fast_prediction_candidates)
                .await;
            let mut candidates = target.candidates;
            if fast_prediction_candidates.is_empty() {
                fast_prediction_candidates = target.preferred_fast_candidates;
            }
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
            let mut dispatch_snapshot =
                punch_candidate_snapshot(&peers, &peer_id, candidates.clone()).await;
            peers
            .record_direct_event(
                &peer_id,
                "punch_started",
                candidates.first().copied(),
                Some(candidates.len()),
                None,
                format!(
                    "starting synchronized UDP punch session_id={} network_generation={} recovery_epoch={} across {} candidates; candidate_snapshot_hash={:016x} candidate_source_count={} candidate_source_category_count={} candidate_source_counts={} punch_at_ms={punch_at_ms:?}",
                    session.session_id(),
                    network_generation,
                    epoch,
                    candidates.len(),
                    dispatch_snapshot.hash,
                    dispatch_snapshot.source_count,
                    dispatch_snapshot.source_category_count,
                    dispatch_snapshot.source_summary,
                ),
            )
            .await;
            // A multi-socket peer may probe ANY of our advertised socket-pool
            // mappings: temporarily activate the pool so every socket sends
            // peer-directed probes and every advertised mapping stays alive for
            // the peer's first punch (see `peer_needs_local_socket_pool`).
            if peers.peer_needs_local_socket_pool(&peer_id).await {
                udp.set_socket_pool_active(true);
            }

            // The bounded cold-start prefix is latency-sensitive even before NAT
            // classification has established that the peer needs a socket pool.
            // Use every socket that is already bound so one stale/private
            // candidate on socket 0 cannot delay the first public mapping.  The
            // FastPrefixPool policy is scoped to this one prefix; it does not
            // change the later stable/scatter policy or the transport-wide gate.
            if udp.socket_count() > 1 {
                peers
                .record_direct_event(
                    &peer_id,
                    "direct_fast_probe_socket_pool_selected",
                    candidates.first().copied(),
                    Some(candidates.len()),
                    Some(udp.socket_count() as u32),
                    format!(
                        "cold-start fast Direct prefix will use {} already-bound UDP sockets; transport-wide ActivePool remains unchanged",
                        udp.socket_count()
                    ),
                )
                .await;
            }

            // A relay-coordinated punch timestamp is deliberately conservative:
            // both peers need time to receive the signal before the wide window.
            // Do not make ordinary Direct paths wait for that rendezvous. Probe a
            // small, already-ranked candidate prefix immediately, then keep the
            // synchronized full window below as the dependent-NAT fallback. This
            // stage is control traffic only; business packets remain relay-first
            // until the encrypted Direct validation ACK commits the path.
            let has_fresh_prediction_window = !fast_prediction_candidates.is_empty();
            let fast_probe_is_allowed = direct_fast_probe_is_allowed(
                remote_scatter_pool,
                stable_remote_scatter,
                has_fresh_prediction_window,
            );
            if punch_at_ms.is_some()
                && !session.is_cancelled()
                && !peers.is_direct(&peer_id).await
                && peers.peer_session_is_current_sync(&peer_id, peer_session_generation)
                && fast_probe_is_allowed
            {
                let fast_candidates = if fast_prediction_candidates.is_empty() {
                    direct_fast_probe_candidates(&candidates)
                } else {
                    direct_fast_probe_candidates_with_predicted_window(
                        &candidates,
                        &fast_prediction_candidates,
                    )
                };
                if !fast_candidates.is_empty() {
                    peers
                    .record_direct_event(
                        &peer_id,
                        "direct_fast_probe_started",
                        fast_candidates.first().copied(),
                        Some(fast_candidates.len()),
                        None,
                        format!(
                            "immediate candidate window before synchronized rendezvous session_id={} generation={} candidates={} punch_at_ms={punch_at_ms:?}",
                            session.session_id(),
                            network_generation,
                            fast_candidates.len(),
                        ),
                    )
                    .await;
                    if session.is_cancelled()
                        || !peers.peer_session_is_current_sync(&peer_id, peer_session_generation)
                    {
                        return;
                    }
                    match udp
                        .punch_candidates_fast_prefix_until_not_direct_report(
                            &peer_id,
                            fast_candidates.clone(),
                            Duration::ZERO,
                            DIRECT_FAST_PROBE_ATTEMPTS,
                        )
                        .await
                    {
                        Ok(report) => {
                            peers
                                .record_direct_event(
                                    &peer_id,
                                    "direct_fast_probe_sent",
                                    fast_candidates.first().copied(),
                                    Some(fast_candidates.len()),
                                    Some(report.packets_sent),
                                    format!(
                                    "session_id={} packets_sent={} actual_first_send_at_ms={:?}",
                                    session.session_id(),
                                    report.packets_sent,
                                    report.first_send_at_ms,
                                ),
                                )
                                .await;
                        }
                        Err(error) => {
                            // The synchronized stage below is still authoritative;
                            // a failed fast hint must not degrade the relay path or
                            // consume the session's terminal failure state.
                            peers
                            .record_direct_event(
                                &peer_id,
                                "direct_fast_probe_failed",
                                fast_candidates.first().copied(),
                                Some(fast_candidates.len()),
                                None,
                                format!(
                                    "session_id={} fast candidate hint failed; continuing synchronized window: {error}",
                                    session.session_id(),
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
                                format!(
                                    "session_id={} Direct committed before synchronized rendezvous",
                                    session.session_id(),
                                ),
                            )
                            .await;
                        return;
                    }

                    // Give an ACK already in flight a short chance to commit, but
                    // never hold the relay-backed session behind a long validation
                    // wait. The per-probe Direct gate also stops the scheduled
                    // window immediately if the ACK lands after this check.
                    let commit_seq = peers.direct_commit_seq_sync(&peer_id);
                    if peers
                        .wait_for_direct_commit_or_timeout(
                            &peer_id,
                            commit_seq,
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
                                format!(
                                    "session_id={} Direct committed during fast ACK window",
                                    session.session_id(),
                                ),
                            )
                            .await;
                        return;
                    }
                }
            } else if punch_at_ms.is_some()
                && !session.is_cancelled()
                && !peers.is_direct(&peer_id).await
                && !fast_probe_is_allowed
            {
                peers
                .record_direct_event(
                    &peer_id,
                    "direct_fast_probe_skipped",
                    candidates.first().copied(),
                    Some(candidates.len()),
                    None,
                    format!(
                        "skipped immediate candidate prefix because synchronized rendezvous is required session_id={} generation={} remote_scatter_pool={} stable_remote_scatter={} fresh_prediction_window={}",
                        session.session_id(),
                        network_generation,
                        remote_scatter_pool,
                        stable_remote_scatter,
                        has_fresh_prediction_window,
                    ),
                )
                .await;
            }

            // Candidate resolution and the small fast prefix above are allowed to
            // run immediately.  The rendezvous timestamp only gates the broad,
            // synchronized sweep below; otherwise a healthy candidate would sit
            // behind the full relay-assisted delay before receiving its first
            // Direct probe.
            if !punch_delay.is_zero() {
                tokio::select! {
                    _ = sleep(punch_delay) => {}
                    _ = session.cancelled() => {
                        peers
                            .record_direct_event(
                                &peer_id,
                                "punch_session_cancelled",
                                None,
                                None,
                                None,
                                format!(
                                    "cancelled scheduled UDP punch while waiting for rendezvous session_id={} network_generation={} recovery_epoch={} reason={}",
                                    session.session_id(),
                                    network_generation,
                                    epoch,
                                    session
                                        .cancellation_reason()
                                        .map(PunchCancellationReason::label)
                                        .unwrap_or("unknown"),
                                ),
                            )
                            .await;
                        return;
                    }
                }
            }

            // A control-plane candidate refresh can arrive while the owned
            // rendezvous session is waiting for its scheduled broad window.  The
            // recovery scheduler intentionally folds that refresh into a
            // newest-wins pending target instead of starting a second per-peer
            // worker.  Consume that target at the last safe boundary before the
            // broad sweep: first give its strongest candidates the same bounded
            // fast-prefix opportunity, then append the complete snapshot to this
            // session's existing FIFO.  This keeps the original punch_at_ms and
            // epoch budgets intact while preventing a fresh peer-reflexive/public
            // endpoint from waiting for the next one-second retry tick.
            if !session.is_cancelled()
                && !peers.is_direct(&peer_id).await
                && peers.current_network_generation().await == generation
                && peers.peer_online(&peer_id).await
                && peers.peer_session_is_current_sync(&peer_id, peer_session_generation)
            {
                if let Some(pending) = peers.take_recovery_target(&peer_id).await {
                    let frozen_targets = match pending.frozen_targets {
                        Some(frozen) => {
                            Some(peers.current_remote_endpoints_for(&peer_id, frozen).await)
                        }
                        None => None,
                    };
                    let mut preferred = match frozen_targets.as_ref() {
                        Some(frozen) => frozen.clone(),
                        None => {
                            peers
                                .current_remote_endpoints_for(
                                    &peer_id,
                                    pending.preferred_fast_candidates,
                                )
                                .await
                        }
                    };
                    let mut pending_candidates = peers
                        .current_remote_endpoints_for(&peer_id, pending.candidates)
                        .await;
                    if !preferred.is_empty() {
                        // A fresh prediction carries only its immutable window.
                        // Keep the current ordinary candidates in the same
                        // refresh, because an authenticated/STUN endpoint is a
                        // stronger fallback than a prediction that may already be
                        // one NAT allocation behind.
                        if let Some(current) = peers.direct_probe_target_set_for(&peer_id).await {
                            merge_unique_socket_addresses(
                                &mut pending_candidates,
                                &current.candidates,
                            );
                            merge_unique_socket_addresses(
                                &mut preferred,
                                &current.preferred_fast_candidates,
                            );
                        }
                    }
                    let fast_candidates = if preferred.is_empty() {
                        direct_fast_probe_candidates(&pending_candidates)
                    } else {
                        direct_fast_probe_candidates_with_predicted_window(
                            &pending_candidates,
                            &preferred,
                        )
                    };
                    let fast_probe_is_allowed = direct_fast_probe_is_allowed(
                        remote_scatter_pool,
                        stable_remote_scatter,
                        !preferred.is_empty(),
                    );
                    let mut direct_committed = peers.is_direct(&peer_id).await;
                    if fast_probe_is_allowed && !fast_candidates.is_empty() && !direct_committed {
                        peers
                        .record_direct_event(
                            &peer_id,
                            "deferred_candidate_fast_probe_started",
                            fast_candidates.first().copied(),
                            Some(fast_candidates.len()),
                            None,
                            format!(
                                "consuming newest-wins candidate refresh before broad sweep session_id={} generation={} pending_candidates={} preferred_candidates={} original_punch_at_ms={punch_at_ms:?}",
                                session.session_id(),
                                generation,
                                pending_candidates.len(),
                                preferred.len(),
                            ),
                        )
                        .await;
                        if session.is_cancelled()
                            || !peers
                                .peer_session_is_current_sync(&peer_id, peer_session_generation)
                        {
                            return;
                        }
                        let commit_seq = peers.direct_commit_seq_sync(&peer_id);
                        match udp
                            .punch_candidates_fast_prefix_until_not_direct_report(
                                &peer_id,
                                fast_candidates.clone(),
                                Duration::ZERO,
                                DIRECT_FAST_PROBE_ATTEMPTS,
                            )
                            .await
                        {
                            Ok(report) => {
                                peers
                                .record_direct_event(
                                    &peer_id,
                                    "deferred_candidate_fast_probe_sent",
                                    fast_candidates.first().copied(),
                                    Some(fast_candidates.len()),
                                    Some(report.packets_sent),
                                    format!(
                                        "session_id={} packets_sent={} actual_first_send_at_ms={:?}",
                                        session.session_id(),
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
                                    "deferred_candidate_fast_probe_failed",
                                    fast_candidates.first().copied(),
                                    Some(fast_candidates.len()),
                                    None,
                                    format!(
                                        "session_id={} newest candidate refresh fast probe failed; continuing broad sweep: {error}",
                                        session.session_id(),
                                    ),
                                )
                                .await;
                            }
                        }
                        direct_committed = peers.is_direct(&peer_id).await;
                        if !direct_committed {
                            direct_committed = peers
                                .wait_for_direct_commit_or_timeout(
                                    &peer_id,
                                    commit_seq,
                                    DIRECT_FAST_PROBE_ACK_WINDOW,
                                )
                                .await;
                        }
                    }
                    if direct_committed {
                        peers
                        .record_direct_event(
                            &peer_id,
                            "deferred_candidate_fast_probe_confirmed",
                            fast_candidates.first().copied(),
                            Some(fast_candidates.len()),
                            None,
                            format!(
                                "session_id={} Direct committed from newest candidate refresh before broad sweep",
                                session.session_id(),
                            ),
                        )
                        .await;
                        return;
                    }

                    let added = merge_unique_socket_addresses(&mut candidates, &pending_candidates);
                    dispatch_snapshot =
                        punch_candidate_snapshot(&peers, &peer_id, candidates.clone()).await;
                    peers
                    .record_direct_event(
                        &peer_id,
                        "deferred_candidate_target_consumed",
                        pending_candidates.first().copied(),
                        Some(pending_candidates.len()),
                        Some(added as u32),
                        format!(
                            "session_id={} appended newest-wins candidate refresh before broad sweep; added={} total_candidates={} original_punch_at_ms={punch_at_ms:?}",
                            session.session_id(),
                            added,
                            candidates.len(),
                        ),
                    )
                    .await;
                }
            }

            if let Some(plan) = birthday_plan.as_ref() {
                peers
                    .record_birthday_probe_plan_started(&peer_id, plan)
                    .await;
            }

            for endpoint in peers.direct_nat_maintainer_targets_for(&peer_id).await {
                if session.is_cancelled()
                    || !peers.peer_session_is_current_sync(&peer_id, peer_session_generation)
                {
                    return;
                }
                udp.spawn_nat_binding_maintainer(
                    &peer_id,
                    endpoint,
                    HARD_NAT_MAINTAINER_CONNECTING_INTERVAL,
                    HARD_NAT_MAINTAINER_CONNECTING_DURATION,
                )
                .await;
            }
            // The relay-backed heartbeat keeps the direct punch windows warm at a
            // low sustained rate for as long as the relay carries the data plane,
            // independent of the recovery epoch's one-time credit/plan quotas.
            if session.is_cancelled()
                || !peers.peer_session_is_current_sync(&peer_id, peer_session_generation)
            {
                return;
            }
            udp.spawn_relay_backoff_heartbeat(&peer_id, RELAY_BACKOFF_HEARTBEAT_INTERVAL)
                .await;

            let success_count_before = peers
                .direct_probe_success_count_for_generation(&peer_id, generation)
                .await;
            let commit_seq_before = peers.direct_commit_seq_sync(&peer_id);
            // Keep the before/after diagnostic delta on the exact signaling
            // session that was active when this owned punch began.  A rekey can
            // legitimately arrive while a still-valid first punch window is
            // preserved; consulting the current session at the end would then
            // make an old-session ACK appear to vanish (or a new-session ACK
            // appear to belong to this task).
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
            // The first ordinary/relay-assisted sweep and the optional
            // fresh-mapping optimization now start together.  The fresh-mapping
            // task can improve later windows, but it is never allowed to delay
            // the first Direct packet or relay-first business continuity.
            let fresh_mapping_task = tokio::spawn(fresh_mapping_future);
            let outcome = run_owned_punch_session_with_deadline(&session, deadline, async {
            if session.is_cancelled()
                || !peers.peer_session_is_current_sync(&peer_id, peer_session_generation)
            {
                return;
            }
            // This synchronous dispatch boundary is immediately before the
            // first outbound sweep. It is paired with the UDP layer's actual
            // send report, and prevents a fresh offer arriving in this tiny
            // interval from cancelling the synchronized first window.
            let first_send_dispatch_ms = session.mark_first_send_started();
            let first_send_dispatch_deviation_ms = punch_at_ms.map(|scheduled| {
                i128::from(first_send_dispatch_ms) - i128::from(scheduled)
            });
            peers
                .record_direct_event(
                    &peer_id,
                    "punch_first_send_dispatch",
                    candidates.first().copied(),
                    Some(candidates.len()),
                    None,
                    format!(
                        "first owned UDP send dispatch session_id={} network_generation={} recovery_epoch={} punch_at_ms={punch_at_ms:?} first_send_dispatch_ms={} first_send_dispatch_deviation_ms={first_send_dispatch_deviation_ms:?} candidate_snapshot_hash={:016x} candidate_source_count={} candidate_source_category_count={} candidate_source_counts={}",
                        session.session_id(),
                        generation,
                        epoch,
                        first_send_dispatch_ms,
                        dispatch_snapshot.hash,
                        dispatch_snapshot.source_count,
                        dispatch_snapshot.source_category_count,
                        dispatch_snapshot.source_summary,
                    ),
                )
                .await;
            if session.is_cancelled()
                || !peers.peer_session_is_current_sync(&peer_id, peer_session_generation)
            {
                return;
            }
            // A prediction window / wide scatter sweep is one CONTROLLED
            // window coverage: every candidate is sent once from every active
            // socket, then the window either matched (ACK / Direct) or the
            // feedback-driven stage machine advances to a DIFFERENT window.
            // Repeating the same window through `attempts` rounds only
            // multiplies physical datagrams on ports that already missed
            // (field evidence: a 96-port fresh prediction window was sent as
            // 512 datagrams with 416 repeated target ports, and the repeat
            // rounds never hit a destination-dependent CGNAT mapping that
            // moved to a completely different port range).  The ACK feedback
            // window after the sweep provides the retry semantics.
            let effective_attempts = if fresh_prediction.is_some()
                || is_frozen_prediction_window
                || remote_scatter_pool
                || stable_remote_scatter
            {
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
                    // Zero-send is NOT a silent success: with a non-empty
                    // candidate set every probe was rejected by the admission
                    // layer.  Record the structured verdict and freeze the
                    // recovery epoch with a controlled backoff so the next
                    // 1-second tick cannot rebuild the same wide plan.
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
                    let actual_first_send_deviation_ms =
                        actual_first_send_at_ms.zip(punch_at_ms).map(|(actual, scheduled)| {
                            i128::from(actual) - i128::from(scheduled)
                        });
                    let per_socket_sent = report
                        .per_socket_sent
                        .iter()
                        .map(|(socket, count)| format!("{socket}:{count}"))
                        .collect::<Vec<_>>()
                        .join(",");
                    // This is deliberately emitted only from the UDP send
                    // report, after a kernel send completed. The earlier
                    // dispatch event is useful scheduling telemetry but must
                    // never be mistaken for the first physical packet.
                    peers
                        .record_direct_event(
                            &peer_id,
                            "punch_first_packet_sent",
                            candidates.first().copied(),
                            Some(candidates.len()),
                            Some(sent),
                            format!(
                                "session_id={} network_generation={} recovery_epoch={} punch_at_ms={punch_at_ms:?} actual_first_send_at_ms={actual_first_send_at_ms:?} first_send_deviation_ms={actual_first_send_deviation_ms:?} per_socket_actual_datagrams={per_socket_sent}",
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
                    info!("Sent {sent} UDP punch probes to peer {peer_id}");
                    peers
                        .record_direct_event(
                            &peer_id,
                            "punch_probes_sent",
                            candidates.first().copied(),
                            Some(candidates.len()),
                        Some(sent),
                        format!(
                            "sent {sent} UDP punch probes session_id={} network_generation={} recovery_epoch={} across {} candidates; candidate_snapshot_hash={:016x} candidate_source_count={} candidate_source_category_count={} candidate_source_counts={}; per-socket coverage is recorded by the paired scan-completed event",
                            session.session_id(),
                            generation,
                            epoch,
                            candidates.len(),
                            dispatch_snapshot.hash,
                            dispatch_snapshot.source_count,
                            dispatch_snapshot.source_category_count,
                            dispatch_snapshot.source_summary,
                        ),
                    )
                        .await;
                    // Bounded feedback window: wait for a matched ACK (or a
                    // Direct commit) instead of a bare sleep, so a promotion
                    // reliably preempts the next sweep stage without relying
                    // on scheduler preemption of `yield_now()`.
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
                                "punch_ack_feedback_commit",
                                candidates.first().copied(),
                                Some(candidates.len()),
                                Some(sent),
                                "Direct commit observed during the ACK feedback window; ending the punch session",
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
                    if sent > 0 && success_count_after == success_count_before {
                        let timeout_detail = format!(
                            "no matched UDP punch ACK after {sent} probes; probe_session_id={} known_peer_ip_rx_delta={} authenticated_probe_rx_delta={} authenticated_probe_ack_observed_delta={} authenticated_probe_ack_unmatched_delta={} legacy_probe_ack_observed_delta={} legacy_probe_ack_unmatched_delta={} matched_probe_ack_rx_delta={}",
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
                    let detail = format!("hole punch failed: {err}");
                    // A real send error is a hard failure: the recovery stage
                    // moves into relay-backoff where the exponential retry
                    // backoff paces further work. The direct-failure commit
                    // itself records the structured traversal event atomically
                    // with the state mutation, so do not emit a second,
                    // unfenced event into a possible same-node replacement.
                    record_hole_punch_send_error_for_lifecycle(
                        &peers,
                        &peer_id,
                        generation,
                        peer_session_generation,
                        &detail,
                    )
                    .await;
                    warn!("Failed to punch peer {peer_id}: {err}");
                }
            }
        })
        .await;

            if let Err(error) = fresh_mapping_task.await {
                peers
                .record_direct_event(
                    &peer_id,
                    "fresh_mapping_worker_failed",
                    None,
                    None,
                    None,
                    format!("fresh-mapping worker failed without changing the first punch outcome: {error}"),
                )
                .await;
            }

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
                    format!(
                        "cancelled stale UDP punch session before replacement session_id={} network_generation={} recovery_epoch={} reason={}",
                        session.session_id(),
                        generation,
                        epoch,
                        session
                            .cancellation_reason()
                            .map(PunchCancellationReason::label)
                            .unwrap_or("unknown"),
                    ),
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
                    "synchronized UDP punch session stopped after {}ms deadline; probe_session_id={} known_peer_ip_rx_delta={} authenticated_probe_rx_delta={} authenticated_probe_ack_observed_delta={} authenticated_probe_ack_unmatched_delta={} legacy_probe_ack_observed_delta={} legacy_probe_ack_unmatched_delta={} matched_probe_ack_rx_delta={}",
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
                            "punch_session_deadline",
                            candidates.first().copied(),
                            Some(candidates.len()),
                            None,
                            timeout_detail.clone(),
                        )
                        .await;
                    if let (true, Some(plan)) = (stable_remote_scatter, birthday_plan.as_ref()) {
                        let covered_all = last_punch_report.as_ref().is_some_and(|report| {
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
                                last_punch_report.as_ref().map(|report| report.packets_sent),
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
        };

        if let Some(shutdown_rx) = invocation_shutdown_rx {
            tokio::select! {
                biased;
                _ = wait_and_cancel_punch_invocation(
                    shutdown_rx,
                    invocation_cancellation,
                ) => {}
                _ = worker => {}
            }
        } else {
            worker.await;
        }
    });
}
