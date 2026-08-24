// ============================================================
// C=0 synchronized fresh-fresh rendezvous
// ============================================================
//
// The bounded C=0 path (dual-APD NATE: both ends `m=address_or_port_dependent`,
// no mutually-admitted endpoint pair) knocks with the two sides' FRESH
// sockets at the SAME canonical `punch_at_ms`.  This module is the "sending"
// half that was missing: the local freshly-measured NAT mapping and the
// remote FRESH predicted endpoints are aligned into the existing synchronized
// rendezvous machinery on the local side, so the local fresh source is
// admitted by the peer's NAT filtering table at the same instant the peer's
// fresh source is admitted by ours.
//
// It REUSES, and never rebuilds:
//   - `claim_for_epoch_with_rendezvous` (PUNCH_PRIORITY_FRESH_PREDICTION) —
//     the shared dedup; multi-epoch retry is made legal by advancing the
//     recovery epoch / canonical `punch_at_ms`,
//   - `relay_assisted_punch_delay(punch_at_ms)` — the same wall-clock lead,
//   - `run_owned_punch_session_with_deadline` — the bounded send + outcome
//     attribution skeleton,
//   - the fresh-frozen target snapshot semantics.
//
// It NEVER touches `run_fresh_mapping_generation`'s own punch loop (that
// function punches the historical `stable_targets` along the legacy path and
// is covered by the 10/10 direct regression suite), and never widens the
// scatter budget.

/// Bounded lifetime of one C=0 synchronized send window (reuses the
/// peer-reflexive micro-window bound).
const C0_RENDEZVOUS_DEADLINE: Duration = PEER_REFLEXIVE_MICRO_WINDOW_DEADLINE;

/// Spawn the local half of a C=0 synchronized fresh-fresh pair.
///
/// `local_fresh_endpoint` is the local daemon's freshly measured NAT mapping
/// (the source the peer must learn as "fresh"); `remote_fresh_targets` are the
/// peer's OWN fresh predicted endpoints (learned from its `peer_offer_fresh`
/// offer), NOT the historical `stable_targets`.  `punch_at_ms` MUST be the
/// canonical deadline propagated by the peer's offer (single wall-clock
/// instant shared by both sides — see c0-design §1 canonical constraint);
/// when the caller has no canonical deadline it falls back to a local
/// `relay_assisted_punch_at_ms()` so the pair is still synchronized on a
/// shared-style deadline rather than an immediate unscoped send.
///
/// The claim uses `PUNCH_PRIORITY_FRESH_PREDICTION` so this window preempts an
/// older ordinary/synchronized session (fresh prediction must not sit behind
/// a stale window) but it still goes through the SAME dedup — a same-epoch
/// duplicate returns `Deferred` and never overlaps.
///
/// Returns `false` when the window could not be scheduled (budget exhausted,
/// no remote fresh targets, already Direct, or deferred behind an active
/// session).  The caller then records the miss via the C=0 ledger; when the
/// send ran to completion the peer's encrypted-validation path decides
/// hit/miss independently.
#[allow(clippy::too_many_arguments)]
async fn spawn_c0_synchronized_fresh_pair(
    udp: UdpTransport,
    peers: Arc<PeerManager>,
    punch_deduplicator: PunchAttemptDeduplicator,
    peer_id: String,
    local_fresh_endpoint: SocketAddr,
    local_fresh_socket_index: usize,
    remote_fresh_targets: Vec<SocketAddr>,
    punch_at_ms: Option<u64>,
    c0_generation: Option<crate::FreshPredictionId>,
) -> bool {
    let Some(punch_at_ms) = punch_at_ms.or_else(|| Some(relay_assisted_punch_at_ms())) else {
        return false;
    };
    let mut targets = Vec::with_capacity(PEER_REFLEXIVE_MICRO_WINDOW_MAX_TARGETS);
    let mut seen = HashSet::new();
    for candidate in remote_fresh_targets {
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
                "c0_rendezvous_skipped",
                None,
                Some(0),
                None,
                "C=0 synchronized fresh-fresh pair skipped: no remote fresh targets available",
            )
            .await;
        return false;
    }
    if peers.is_direct(&peer_id).await {
        return false;
    }
    let Some(peer_session_generation) = peers.peer_session_generation_sync(&peer_id) else {
        return false;
    };

    let RecoveryAdmission::Accepted { epoch } = peers.recovery_epoch_admit(&peer_id).await else {
        peers
            .record_direct_event(
                &peer_id,
                "c0_rendezvous_suppressed",
                targets.first().copied(),
                Some(targets.len()),
                None,
                "C=0 synchronized fresh-fresh pair suppressed: recovery epoch not eligible",
            )
            .await;
        return false;
    };
    let generation = peers.current_network_generation().await;
    let Some(claim) = punch_deduplicator
        .claim_for_epoch_with_rendezvous_for_peer_session(
            &peers,
            &peer_id,
            peer_session_generation,
            generation,
            epoch,
            PUNCH_PRIORITY_FRESH_PREDICTION,
            c0_generation,
            Some(punch_at_ms),
        )
        .await
    else {
        return false;
    };
    let session = match claim {
        RendezvousPunchClaim::Claimed(session) => session,
        RendezvousPunchClaim::Deferred(deferred) => {
            peers
                .record_direct_event_for_generation_with_socket(
                    &peer_id,
                    generation,
                    "c0_rendezvous_deferred",
                    targets.first().copied(),
                    None,
                    Some(targets.len()),
                    None,
                    format!(
                        "C=0 fresh-fresh pair deferred behind active session_id={} active_punch_at_ms={:?} reason={}",
                        deferred.active_session_id,
                        deferred.active_punch_at_ms,
                        deferred.reason.label(),
                    ),
                )
                .await;
            return false;
        }
        RendezvousPunchClaim::RejectedStalePeerSession => return false,
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
                "c0_rendezvous_scheduled",
                local_fresh_endpoint.into(),
                None,
                Some(targets.len()),
                None,
                format!(
                    "C=0 fresh-fresh pair session_id={session_id} recovery_epoch={epoch} punch_at_ms={punch_at_ms} delay_ms={} local_fresh={local_fresh_endpoint} remote_fresh_targets={} attempts={}",
                    delay.as_millis(),
                    targets.len(),
                    C0_RENDEZVOUS_ATTEMPTS,
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
                        "c0_rendezvous_cancelled",
                        local_fresh_endpoint.into(),
                        None,
                        Some(targets.len()),
                        None,
                        format!(
                            "C=0 fresh-fresh pair cancelled while waiting for shared punch_at_ms={punch_at_ms}; reason={}",
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
        let mut send_result = None;
        let outcome =
            run_owned_punch_session_with_deadline(&session, C0_RENDEZVOUS_DEADLINE, async {
                send_result = Some(
                    udp.punch_candidates_from_dynamic_socket_index(
                        &peer_id,
                        local_fresh_socket_index,
                        targets.clone(),
                        PEER_REFLEXIVE_MICRO_WINDOW_INTERVAL,
                        C0_RENDEZVOUS_ATTEMPTS,
                    )
                    .await,
                );
            })
            .await;

        match outcome {
            PunchSessionOutcome::Cancelled | PunchSessionOutcome::DeadlineExceeded => {
                peers.record_direct_event_for_generation_with_socket(
                    &peer_id,
                    generation,
                    "c0_rendezvous_incomplete",
                    targets.first().copied(),
                    None,
                    Some(targets.len()),
                    None,
                    format!(
                        "C=0 fresh-fresh pair session_id={session_id} did not complete its bounded send: {:?}",
                        outcome
                    ),
                )
                .await;
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
                        "c0_rendezvous_first_packet_sent",
                        targets.first().copied(),
                        socket_index,
                        Some(targets.len()),
                        Some(report.packets_sent),
                        format!(
                            "C=0 fresh-fresh pair session_id={session_id} recovery_epoch={epoch} punch_at_ms={punch_at_ms} dispatch_at_ms={dispatch_at_ms} actual_first_send_at_ms={:?} first_send_deviation_ms={first_send_deviation_ms:?} local_fresh={local_fresh_endpoint} per_socket_actual_datagrams={per_socket_sent}",
                            report.first_send_at_ms,
                        ),
                    ).await;
                    peers.record_direct_event_for_generation_with_socket(
                        &peer_id,
                        generation,
                        "c0_rendezvous_completed",
                        targets.first().copied(),
                        socket_index,
                        Some(targets.len()),
                        Some(report.packets_sent),
                        format!(
                            "C=0 fresh-fresh pair session_id={session_id} sent={} unique_target_endpoints={} budget_skipped={} epoch_budget_exhausted={}",
                            report.packets_sent,
                            report.unique_target_endpoints,
                            report.budget_skipped,
                            report.epoch_budget_exhausted,
                        ),
                    ).await;
                }
                Some(Err(error)) => {
                    peers
                        .record_direct_event_for_generation_with_socket(
                            &peer_id,
                            generation,
                            "c0_rendezvous_error",
                            targets.first().copied(),
                            None,
                            Some(targets.len()),
                            None,
                            format!("C=0 fresh-fresh pair bounded send failed: {error}"),
                        )
                        .await;
                }
                None => {
                    peers
                        .record_direct_event_for_generation_with_socket(
                            &peer_id,
                            generation,
                            "c0_rendezvous_error",
                            targets.first().copied(),
                            None,
                            Some(targets.len()),
                            None,
                            "C=0 fresh-fresh pair bounded send did not start".to_string(),
                        )
                        .await;
                }
            },
        }
    });
    true
}

/// Attempt count for one C=0 synchronized send window (reuses the
/// peer-reflexive micro-window bound so the pair stays short-lived).
const C0_RENDEZVOUS_ATTEMPTS: u32 = PEER_REFLEXIVE_MICRO_WINDOW_ATTEMPTS;

/// Snapshot of the inputs the C=0 rendezvous needs, kept pure so the
/// "remote fresh targets / canonical punch_at_ms" contract can be unit-tested
/// without any socket.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct C0FreshPairPlan {
    /// Local freshly-measured NAT mapping (the source the peer must learn).
    pub(crate) local_fresh_endpoint: SocketAddr,
    /// The peer's OWN fresh predicted endpoints — NOT the historical
    /// stable_targets (APD filtering invalidates old sources).
    pub(crate) remote_fresh_targets: Vec<SocketAddr>,
    /// Canonical wall-clock deadline propagated by the peer's offer; both
    /// sides punch at this ONE instant.
    pub(crate) canonical_punch_at_ms: u64,
    /// Bounded target slice taken from the remote fresh targets.
    pub(crate) bounded_targets: Vec<SocketAddr>,
}

impl C0FreshPairPlan {
    /// Build a C=0 fresh-fresh pair plan.  The canonical deadline must come
    /// from the peer's propagated `punch_at_ms`; if the caller supplies `None`
    /// the plan falls back to a local `relay_assisted_punch_at_ms()` so the
    /// pair stays aligned even when the peer's offer carried no deadline.
    /// Targets are the REMOTE fresh predictions, bounded to the same cap the
    /// existing micro-window uses; the local fresh endpoint is never treated
    /// as a punch target.
    pub(crate) fn new(
        local_fresh_endpoint: SocketAddr,
        remote_fresh_targets: &[SocketAddr],
        propagated_punch_at_ms: Option<u64>,
    ) -> Option<Self> {
        let mut bounded = Vec::with_capacity(PEER_REFLEXIVE_MICRO_WINDOW_MAX_TARGETS);
        let mut seen = HashSet::new();
        for target in remote_fresh_targets {
            if seen.insert(*target) {
                bounded.push(*target);
            }
            if bounded.len() == PEER_REFLEXIVE_MICRO_WINDOW_MAX_TARGETS {
                break;
            }
        }
        if bounded.is_empty() {
            return None;
        }
        Some(C0FreshPairPlan {
            local_fresh_endpoint,
            canonical_punch_at_ms: propagated_punch_at_ms
                .unwrap_or_else(relay_assisted_punch_at_ms),
            bounded_targets: bounded,
            remote_fresh_targets: remote_fresh_targets.to_vec(),
        })
    }
}
