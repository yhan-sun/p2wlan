/// Optional signaling context for a synchronized hole punch.
///
/// When present, the punch task can run a fresh-mapping generation and
/// immediately advertise the predicted port window to the peer so the stable
/// side probes the model's top-1 + successor window first.
#[derive(Clone)]
struct HolePunchSignalContext {
    control: ControlClient,
    candidate_snapshot: Arc<RwLock<Option<CandidateSnapshotLease>>>,
    stun_servers: Vec<SocketAddr>,
    stun_timeout: Duration,
    /// Daemon incarnation epoch embedded in the fresh-prediction label.
    boot_epoch_ms: u64,
}

/// Immutable telemetry captured when a trigger is admitted or folded into an
/// existing rendezvous. The endpoints themselves remain in the peer's normal
/// candidate diagnostics; this record only carries a stable hash and source
/// categories so logs can explain a replacement without exposing additional
/// candidate material.
#[derive(Clone)]
struct PunchCandidateSnapshot {
    candidates: Vec<SocketAddr>,
    hash: u64,
    /// Number of candidate endpoints for which provenance was captured.  An
    /// unknown provenance is deliberately retained as an explicit category
    /// rather than silently omitted, so this is always auditable against the
    /// snapshot's candidate count.
    source_count: usize,
    /// Number of distinct provenance categories represented by `source_count`.
    /// Kept separately because a count of categories is not a count of
    /// candidate endpoints.
    source_category_count: usize,
    source_summary: String,
}

async fn punch_candidate_snapshot(
    peers: &PeerManager,
    peer_id: &str,
    candidates: Vec<SocketAddr>,
) -> PunchCandidateSnapshot {
    let mut canonical = candidates
        .iter()
        .map(ToString::to_string)
        .collect::<Vec<_>>();
    canonical.sort_unstable();
    let mut hash = 0xcbf2_9ce4_8422_2325u64;
    for endpoint in &canonical {
        for byte in endpoint.as_bytes().iter().copied().chain(std::iter::once(0)) {
            hash ^= u64::from(byte);
            hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
        }
    }

    let connection = peers.get_connection(peer_id).await;
    let mut source_counts = HashMap::<String, usize>::new();
    for candidate in &candidates {
        let source = connection
            .as_ref()
            .and_then(|connection| connection.candidate_sources.get(&candidate.to_string()))
            .map(|source| format!("{source:?}"))
            .unwrap_or_else(|| "Unknown".to_string());
        *source_counts.entry(source).or_default() += 1;
    }
    let source_count = source_counts.values().sum();
    let source_category_count = source_counts.len();
    let mut source_summary = source_counts.into_iter().collect::<Vec<_>>();
    source_summary.sort_unstable_by(|left, right| left.0.cmp(&right.0));
    let source_summary = source_summary
        .into_iter()
        .map(|(source, count)| format!("{source}:{count}"))
        .collect::<Vec<_>>()
        .join(",");

    PunchCandidateSnapshot {
        candidates,
        hash,
        source_count,
        source_category_count,
        source_summary,
    }
}

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
    let session = match punch_deduplicator
        .claim_for_epoch_with_rendezvous(
            &peer_id,
            generation,
            epoch,
            PUNCH_PRIORITY_SYNCHRONIZED,
            None,
            Some(punch_at_ms),
        )
        .await
    {
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
    };
    let delay = relay_assisted_punch_delay(Some(punch_at_ms));
    let session_id = session.session_id();
    tokio::spawn(async move {
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
        if session.is_cancelled() || peers.is_direct(&peer_id).await {
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
                    peers.record_direct_event_for_generation_with_socket(
                        &peer_id,
                        generation,
                        "peer_reflexive_micro_window_cancelled",
                        targets.first().copied(),
                        None,
                        Some(targets.len()),
                        None,
                        format!("origin={origin} session_id={session_id} send did not start"),
                    ).await;
                }
            },
        }
    });
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
    let trigger_snapshot = punch_candidate_snapshot(&peers, &peer_id, trigger_candidates).await;
    let network_generation = peers.current_network_generation().await;
    let claimed = punch_deduplicator
        .claim_for_epoch_with_rendezvous(
            &peer_id,
            network_generation,
            epoch,
            claim_priority,
            fresh_prediction,
            punch_at_ms,
        )
        .await;
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
            } else if !peers.try_begin_fresh_generation(&peer_id).await {
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
                            let advertised = if !peers.try_consume_recovery_http_quota(&peer_id).await {
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
                drop(fresh_generation);
            }
        };

        if session.is_cancelled() {
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

        let generation = peers.current_network_generation().await;
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
                            recovery_epoch: u64|
         -> Option<DirectProbeTargetSet> {
            let mut frozen = frozen.unwrap_or_default();
            match ordinary {
                Some(mut ordinary) => {
                    for endpoint in frozen.drain(..) {
                        if !ordinary.candidates.contains(&endpoint) {
                            ordinary.candidates.push(endpoint);
                        }
                    }
                    Some(ordinary)
                }
                None if !frozen.is_empty() => Some(DirectProbeTargetSet {
                    peer_id: peer_id.clone(),
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
                if has_frozen {
                    fast_prediction_candidates = pending.frozen_targets.clone().unwrap_or_default();
                    is_frozen_prediction_window = true;
                } else {
                    // A newer ordinary refresh supersedes the original
                    // prediction target. Never let the old frozen window leak
                    // into the fast prefix of the replacement session.
                    fast_prediction_candidates.clear();
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
                merge_frozen(ordinary, frozen, epoch)
            }
            None => match frozen_targets {
                Some(frozen) => {
                    let ordinary = peers.direct_probe_target_set_for(&peer_id).await;
                    merge_frozen(ordinary, Some(frozen), epoch)
                }
                None => peers.direct_probe_target_set_for(&peer_id).await,
            },
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
        let dispatch_snapshot = punch_candidate_snapshot(&peers, &peer_id, candidates.clone()).await;
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
            && fast_probe_is_allowed
        {
            let fast_candidates = if fast_prediction_candidates.is_empty() {
                direct_fast_probe_candidates(&candidates)
            } else {
                direct_fast_probe_candidates_with_preferred(
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
                match udp
                    .punch_candidates_until_not_direct_report(
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
        // The relay-backed heartbeat keeps the direct punch windows warm at a
        // low sustained rate for as long as the relay carries the data plane,
        // independent of the recovery epoch's one-time credit/plan quotas.
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
            if session.is_cancelled() {
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
                    // A real send error is a hard failure: the recovery stage
                    // moves into relay-backoff where the exponential retry
                    // backoff paces further work.
                    peers
                        .mark_recovery_relay_backoff(&peer_id, &format!("hole punch failed: {err}"))
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
    let snapshot = signal.candidate_snapshot.read().await.clone();
    let (local_candidates, local_candidate_sources) = snapshot
        .map(|snapshot| (snapshot.candidates, snapshot.candidate_sources))
        .unwrap_or_default();
    let (candidates, candidate_sources) = build_fresh_mapping_signal_payload(
        result,
        signal.boot_epoch_ms,
        &local_candidates,
        &local_candidate_sources,
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
