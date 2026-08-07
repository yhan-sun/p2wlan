use futures_util::stream::{FuturesUnordered, StreamExt};
use std::future::Future;
use std::pin::Pin;

/// The serial control receiver owns fresh-prediction admission and short
/// state commits.  Slow STUN/HTTP work runs here instead of directly in the
/// receiver, with every producer supplying a per-peer reservation and this
/// global cap providing a hard upper bound during a control-plane burst.
type ControlEventWork<'a> = Pin<Box<dyn Future<Output = ()> + Send + 'a>>;

const MAX_CONTROL_EVENT_SLOW_WORK: usize = 64;

/// A control signal can arrive a few seconds before the corresponding
/// PeerJoined event (REST polling and signal delivery are independent).  Keep
/// one bounded responder worker alive for this interval so the authenticated
/// offer is replayed after the peer identity is installed instead of being
/// rejected as unknown.  The worker is cancelled by the normal peer-lifecycle
/// cleanup path, and repeated offers replace its single queued value.
const UNKNOWN_PEER_OFFER_WAIT: Duration = Duration::from_secs(8);
const UNKNOWN_PEER_OFFER_POLL: Duration = Duration::from_millis(25);

fn candidate_signal_starts_synchronized_punch(
    handshake_payload: &[u8],
    apply_result: CandidateSetApplyResult,
) -> bool {
    !handshake_payload.is_empty() || apply_result == CandidateSetApplyResult::Applied
}

/// Whether an offer/answer carries a fresh-mapping prediction window.
///
/// Ordinary ICE gathering emits `predicted` candidate labels, so only the
/// distinct `predicted_fresh:<boot_epoch>:<punch_generation>` label counts as
/// a fresh prediction.  The embedded incarnation+generation orders
/// predictions by NAT measurement generation instead of by HTTP send time: a
/// superseded task that sends late cannot masquerade as a newer prediction,
/// and a restarted daemon incarnation supersedes the old one.  Signals
/// without the label (old clients, ordinary refreshes) degrade to an ordinary
/// synchronized punch session.
///
/// Every fresh label in one payload must agree: when the payload mixes two
/// different valid identities the signal is inconsistent and is rejected
/// deterministically instead of letting HashMap iteration pick an arbitrary
/// one.
fn fresh_prediction_from_sources(
    candidate_sources: &HashMap<String, String>,
) -> std::result::Result<Option<crate::FreshPredictionId>, ()> {
    let mut found = None;
    for source in candidate_sources.values() {
        let Some(id) = crate::parse_fresh_prediction_source_label(source) else {
            continue;
        };
        match found {
            None => found = Some(id),
            Some(previous) if previous == id => {}
            Some(_) => return Err(()),
        }
    }
    Ok(found)
}

/// Verdict for a signal's fresh-mapping prediction payload.
#[derive(Debug, Clone, Copy)]
enum FreshSignalVerdict {
    /// No fresh prediction label: an ordinary signal.
    None,
    /// The label is newer than the peer's high-water: candidates may be
    /// applied and, once the apply really succeeds, the identity is committed
    /// and a priority-2 punch session may claim.
    Accepted(crate::FreshPredictionId),
    /// The label equals the high-water AND the payload matches the snapshot
    /// the identity was committed with: an idempotent retry.  Candidates are
    /// not re-applied; the fresh punch starts from the COMMITTED snapshot.
    AlreadyRecorded(crate::FreshPredictionId),
    /// The label equals the high-water but the payload differs from the
    /// committed snapshot (or no snapshot exists): a retry must never apply
    /// different candidates under the same identity.
    PayloadMismatch(crate::FreshPredictionId),
    /// The label is older than the high-water: a superseded prediction sent
    /// late.  Its candidates must not be applied and no punch may start from
    /// them.
    Stale,
    /// The payload carried conflicting fresh labels: rejected
    /// deterministically like a stale signal.
    Inconsistent,
}

/// What punch may start from a fresh-prediction signal.
#[derive(Debug, Clone)]
enum FreshPunchDecision {
    /// No fresh prediction: an ordinary signal.
    None,
    /// The committed fresh snapshot is valid (present, unexpired, non-empty):
    /// the immutable targets may be punched at FRESH priority.
    Fresh(crate::FreshPredictionId, Vec<SocketAddr>),
    /// The signal carried a fresh label but its committed snapshot is expired
    /// or empty: it must NOT claim fresh priority and must NOT fall back to
    /// the shared candidate set as if it were a fresh prediction.  Only a
    /// handshake-carrying signal may degrade to an ORDINARY priority punch
    /// over the shared candidates; a candidate-only signal is ignored.
    Degraded,
}

impl Daemon {
    async fn wait_for_peer_offer_identity(
        &self,
        peer_id: &str,
        cancellation: &mut watch::Receiver<bool>,
    ) -> bool {
        let deadline = Instant::now() + UNKNOWN_PEER_OFFER_WAIT;
        loop {
            if self.peers.get_connection(peer_id).await.is_some() {
                return true;
            }
            if *cancellation.borrow() {
                return false;
            }
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                debug!(
                    "Dropping deferred peer offer from {peer_id}: peer identity was not registered within {:?}",
                    UNKNOWN_PEER_OFFER_WAIT
                );
                return false;
            }
            tokio::select! {
                changed = cancellation.changed() => {
                    if changed.is_err() || *cancellation.borrow() {
                        return false;
                    }
                }
                _ = sleep(UNKNOWN_PEER_OFFER_POLL.min(remaining)) => {}
            }
        }
    }

    async fn apply_deferred_peer_offer_punch(
        &self,
        offer: &PendingPeerOffer,
        candidate_apply_result: CandidateSetApplyResult,
        fresh_punch: FreshPunchDecision,
    ) {
        match fresh_punch {
            FreshPunchDecision::Fresh(id, frozen_targets) => {
                self.start_hole_punch_at(
                    &offer.from_node_id,
                    offer.punch_at_ms,
                    Some(id),
                    Some(frozen_targets),
                )
                .await;
            }
            FreshPunchDecision::Degraded => {
                if !offer.handshake_init.is_empty() {
                    self.start_hole_punch_at(&offer.from_node_id, offer.punch_at_ms, None, None)
                        .await;
                }
            }
            FreshPunchDecision::None => {
                if candidate_signal_starts_synchronized_punch(
                    &offer.handshake_init,
                    candidate_apply_result,
                ) {
                    self.start_hole_punch_at(&offer.from_node_id, offer.punch_at_ms, None, None)
                        .await;
                }
            }
        }
    }

    /// Run the slow half of one peer-reflexive control event.
    ///
    /// Updating the candidate set can wait behind a live STUN refresh and the
    /// optional re-advertisement performs HTTP I/O. This must never execute
    /// in the serial control receiver: offers and answers need to keep making
    /// their short candidate/handshake transactions while this work waits.
    /// The caller owns a per-peer newest-wins reservation, so endpoint churn
    /// cannot create more than one active worker for a peer.
    async fn handle_peer_reflexive_work(
        &self,
        work: &PendingPeerReflexive,
        cancellation: &mut watch::Receiver<bool>,
    ) {
        if *cancellation.borrow() {
            return;
        }
        let peer_id = &work.from_node_id;
        let already_direct_at_arrival = self
            .peers
            .should_defer_relay_assisted_punch(peer_id)
            .await;
        let local_candidate_changed = tokio::select! {
            changed = cancellation.changed() => {
                if changed.is_err() || *cancellation.borrow() {
                    return;
                }
                return;
            }
            changed = self.add_local_peer_reflexive_candidate(&work.observed_endpoint) => changed,
        };
        if let Ok(observed_addr) = work.observed_endpoint.parse::<SocketAddr>() {
            self.peers
                .record_fresh_mapping_prediction_result(peer_id, observed_addr)
                .await;
        }
        let punch_at_ms = work
            .punch_at_ms
            .or_else(|| Some(relay_assisted_punch_at_ms()));
        let (candidates, candidate_sources) = tokio::select! {
            changed = cancellation.changed() => {
                if changed.is_err() || *cancellation.borrow() {
                    return;
                }
                return;
            }
            candidates = self.current_local_candidate_set() => candidates,
        };
        let selected_remote_endpoint = self
            .peers
            .selected_direct_endpoint_for_consent(peer_id)
            .await;
        // Re-check after the potentially long candidate-refresh wait. A
        // concurrent inbound ACK/answer may have promoted Direct meanwhile;
        // that must suppress the stale HTTP offer and punch, even when the
        // peer was not Direct at the time this observation arrived.
        let already_direct = self
            .peers
            .should_defer_relay_assisted_punch(peer_id)
            .await;
        let schedule_punch = !already_direct;
        let skip_reason = already_direct.then_some("direct_confirmed_healthy");
        self.peers
            .record_direct_event(
                peer_id,
                "peer_reflexive_received",
                work.observed_endpoint.parse().ok(),
                Some(candidates.len()),
                None,
                format!(
                    "peer observed our UDP source as {}; already_advertised={} already_direct_at_arrival={already_direct_at_arrival} already_direct={already_direct} selected_remote_endpoint={selected_remote_endpoint:?} schedule_punch={schedule_punch} skip_reason={skip_reason:?}",
                    work.observed_endpoint,
                    !local_candidate_changed,
                ),
            )
            .await;
        if already_direct || *cancellation.borrow() {
            return;
        }
        if local_candidate_changed && !candidates.is_empty() {
            let send_result = tokio::select! {
                changed = cancellation.changed() => {
                    if changed.is_err() || *cancellation.borrow() {
                        return;
                    }
                    return;
                }
                result = self.control.send_peer_offer_with_sources_and_punch_at(
                    peer_id,
                    &candidates,
                    &candidate_sources,
                    &[],
                    punch_at_ms,
                    None,
                ) => result,
            };
            if let Err(err) = send_result {
                warn!(
                    "Failed to re-advertise peer-reflexive local candidate to {peer_id}: {err}"
                );
            } else {
                self.peers
                    .record_direct_event(
                        peer_id,
                        "peer_reflexive_offer_sent",
                        work.observed_endpoint.parse().ok(),
                        Some(candidates.len()),
                        None,
                        "re-advertised local candidates after peer-reflexive observation",
                    )
                    .await;
            }
        } else if !local_candidate_changed {
            self.peers
                .record_direct_event(
                    peer_id,
                    "peer_reflexive_offer_skipped",
                    work.observed_endpoint.parse().ok(),
                    Some(candidates.len()),
                    None,
                    "peer-reflexive candidate already advertised; skipped full offer re-advertisement",
                )
                .await;
        }
        if !*cancellation.borrow()
            && !self
                .peers
                .should_defer_relay_assisted_punch(peer_id)
                .await
        {
            self.start_hole_punch_at(peer_id, punch_at_ms, None, None)
                .await;
        }
    }

    /// Consume the newest queued peer-reflexive observation under one owner.
    /// The global control slow-work set caps the number of these workers;
    /// this per-peer owner prevents endpoint churn from consuming that cap.
    async fn run_peer_reflexive_worker(
        &self,
        mut work: PendingPeerReflexive,
        mut reservation: PeerReflexiveWorkReservation,
    ) {
        loop {
            let peer_id = work.from_node_id.clone();
            if *reservation.cancellation.borrow() {
                return;
            }
            self.handle_peer_reflexive_work(&work, &mut reservation.cancellation)
                .await;
            let Some(next) = self
                .pending_handshakes
                .lock()
                .await
                .finish_peer_reflexive_work(&peer_id, reservation.owner)
            else {
                return;
            };
            work = next;
        }
    }

    /// Finish an offer that arrived before PeerJoined.  Candidate/fresh
    /// admission is deliberately repeated after registration, because the
    /// first attempt would return `PeerMissing` and must not consume a fresh
    /// prediction identity.  The same responder owner handles queued retries.
    async fn run_deferred_peer_offer_worker(
        &self,
        mut offer: PendingPeerOffer,
        mut reservation: ResponderWorkReservation,
    ) {
        loop {
            let peer_id = offer.from_node_id.clone();
            if *reservation.cancellation.borrow() {
                return;
            }
            if !self
                .wait_for_peer_offer_identity(
                    &offer.from_node_id,
                    &mut reservation.cancellation,
                )
                .await
            {
                // A newer offer may have replaced the timed-out value while
                // the peer was still unknown.  Consume it under the same
                // owner; otherwise release the owner so a later signal can
                // create a fresh bounded waiter.
                let Some(next) = self
                    .pending_handshakes
                    .lock()
                    .await
                    .finish_responder_work(&peer_id, reservation.owner)
                else {
                    return;
                };
                offer = next;
                continue;
            }
            // Several offers may have arrived while this worker waited for
            // PeerJoined.  Consume the newest one before any candidate or
            // WireGuard state is touched; the same owner remains active so a
            // later arrival races only with the post-work handoff below.
            if let Some(newest) = self
                .pending_handshakes
                .lock()
                .await
                .take_queued_responder_work(&peer_id, reservation.owner)
            {
                offer = newest;
                continue;
            }
            let (_fresh_verdict, candidate_apply_result, fresh_punch) = self
                .fresh_prediction_transaction(
                    &offer.from_node_id,
                    &offer.candidates,
                    &offer.candidate_sources,
                    offer.candidate_generation,
                    offer.candidates_expires_at_ms,
                    offer.sender_public_key.as_deref(),
                )
                .await;
            self.apply_deferred_peer_offer_punch(
                &offer,
                candidate_apply_result,
                fresh_punch,
            )
            .await;

            if !offer.handshake_init.is_empty() {
                if let Err(err) = self
                    .handle_event_peer_offer(
                        offer,
                        reservation.owner,
                        &mut reservation.cancellation,
                    )
                    .await
                {
                    warn!("Failed to handle deferred peer offer from {peer_id}: {err}");
                }
            }

            let Some(next) = self
                .pending_handshakes
                .lock()
                .await
                .finish_responder_work(&peer_id, reservation.owner)
            else {
                return;
            };
            offer = next;
        }
    }

    /// Freeze the immutable candidate snapshot bound to a fresh identity.
    ///
    /// The snapshot is the payload the identity was committed with (stored by
    /// the commit transaction) — never the current ordinary refresh set and
    /// never a retry's possibly-reordered payload: a later ordinary refresh
    /// must never change the targets of a running fresh session.  The
    /// snapshot's own expiry deadline is honored: an idempotent retry of an
    /// already-recorded identity must never punch toward prediction ports
    /// that have expired since the commit.
    async fn freeze_fresh_punch_targets(
        &self,
        from_node_id: &str,
        id: crate::FreshPredictionId,
    ) -> Option<Vec<SocketAddr>> {
        let snapshot = self
            .peers
            .remote_fresh_snapshot_for(from_node_id, id)
            .await?;
        let now_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis()
            .min(u64::MAX as u128) as u64;
        if snapshot
            .candidates_expires_at_ms
            .is_some_and(|expires_at| {
                expires_at.saturating_add(crate::peer::CANDIDATE_EXPIRY_CLOCK_SKEW_GRACE_MS)
                    <= now_ms
            })
        {
            debug!(
                "Fresh-mapping prediction {id:?} from {from_node_id} expired since its commit; no punch starts from it"
            );
            return None;
        }
        let targets = snapshot
            .candidates
            .iter()
            .filter_map(|candidate| candidate.parse::<SocketAddr>().ok())
            .collect::<Vec<_>>();
        if targets.is_empty() {
            return None;
        }
        Some(targets)
    }

    /// Whether a signal's server-bound sender identity fingerprint matches
    /// the peer's CURRENT public key.
    ///
    /// The control server binds every queued signal to the sender's identity
    /// fingerprint at send time.  When the peer later changes its public key
    /// (rejoin as a new identity), signals that were still queued from the
    /// OLD identity carry the old fingerprint: they must never enter the new
    /// identity's fresh-prediction high-water space, so their fresh labels
    /// are treated as stale.  Signals without a fingerprint (old server) or
    /// for a peer without a recorded public key are conservatively treated as
    /// matching (no identity information to contradict them).
    async fn signal_sender_identity_matches_peer(
        &self,
        peer_id: &str,
        sender_public_key: Option<&str>,
    ) -> bool {
        let Some(sender_public_key) = sender_public_key.map(str::trim).filter(|key| !key.is_empty())
        else {
            return true;
        };
        let Some(connection) = self.peers.get_connection(peer_id).await else {
            return false;
        };
        connection.public_key.trim() == sender_public_key
    }

    /// The prepare/apply/commit transaction for one fresh signal, shared by
    /// the offer and answer paths.
    ///
    /// 1. prepare compares the identity against the peer's high-water AND
    ///    verifies an equal-id retry's payload against the committed
    ///    snapshot (payload mismatch is rejected).
    /// 2. apply installs the candidates and records the apply.
    /// 3. commit is a strict CAS (`id > current`): exactly one concurrent
    ///    commit of an identity wins and freezes its immutable snapshot; the
    ///    loser rolls its own apply back and starts no punch.
    #[allow(clippy::too_many_arguments)]
    async fn fresh_prediction_transaction(
        &self,
        from_node_id: &str,
        candidates: &[String],
        candidate_sources: &HashMap<String, String>,
        candidate_generation: u64,
        candidates_expires_at_ms: Option<u64>,
        sender_public_key: Option<&str>,
    ) -> (
        FreshSignalVerdict,
        CandidateSetApplyResult,
        FreshPunchDecision,
    ) {
        let fresh_verdict = match fresh_prediction_from_sources(candidate_sources) {
            Err(()) => {
                self.peers
                    .record_direct_event(
                        from_node_id,
                        "fresh_prediction_inconsistent",
                        None,
                        Some(candidates.len()),
                        None,
                        "offer carried conflicting fresh-mapping prediction labels; candidates ignored",
                    )
                    .await;
                FreshSignalVerdict::Inconsistent
            }
            Ok(None) => FreshSignalVerdict::None,
            Ok(Some(id)) => {
                let signal_identity_matches = self
                    .signal_sender_identity_matches_peer(from_node_id, sender_public_key)
                    .await;
                if !signal_identity_matches {
                    // The signal was bound by the control server to a sender
                    // identity fingerprint that is NOT the peer's current
                    // public key (the peer changed key and this is a stale
                    // queued signal from the old identity): its fresh label
                    // must never enter the NEW identity's high-water space.
                    self.peers
                        .record_direct_event(
                            from_node_id,
                            "fresh_prediction_stale_identity",
                            None,
                            Some(candidates.len()),
                            None,
                            format!(
                                "offer carried fresh-mapping prediction {id:?} from a stale sender identity; fresh candidates ignored"
                            ),
                        )
                        .await;
                    FreshSignalVerdict::Stale
                } else {
                    match self
                        .peers
                        .prepare_remote_fresh_prediction(
                            from_node_id,
                            id,
                            candidates,
                            candidate_sources,
                            candidates_expires_at_ms,
                        )
                        .await
                    {
                        crate::peer::RemoteFreshAdmission::Accepted => FreshSignalVerdict::Accepted(id),
                        crate::peer::RemoteFreshAdmission::AlreadyRecorded => {
                            self.peers
                                .record_direct_event(
                                    from_node_id,
                                    "fresh_prediction_retry",
                                    None,
                                    Some(candidates.len()),
                                    None,
                                    format!(
                                        "offer is an idempotent retry of the committed fresh-mapping prediction {id:?}; candidates are not re-applied"
                                    ),
                                )
                                .await;
                            FreshSignalVerdict::AlreadyRecorded(id)
                        }
                        crate::peer::RemoteFreshAdmission::PayloadMismatch => {
                            self.peers
                                .record_direct_event(
                                    from_node_id,
                                    "fresh_prediction_payload_mismatch",
                                    None,
                                    Some(candidates.len()),
                                    None,
                                    format!(
                                        "offer retries the committed fresh-mapping prediction {id:?} with a different candidate payload/expiry; rejected"
                                    ),
                                )
                                .await;
                            FreshSignalVerdict::PayloadMismatch(id)
                        }
                        crate::peer::RemoteFreshAdmission::Stale => {
                            self.peers
                                .record_direct_event(
                                    from_node_id,
                                    "fresh_prediction_stale",
                                    None,
                                    Some(candidates.len()),
                                    None,
                                    format!(
                                        "offer carried a superseded fresh-mapping prediction {id:?}; candidates ignored"
                                    ),
                                )
                                .await;
                            FreshSignalVerdict::Stale
                        }
                    }
                }
            }
        };
        let (candidate_apply_result, fresh_punch) = match fresh_verdict {
            FreshSignalVerdict::None => (
                self.peers
                    .add_candidates_with_metadata(
                        from_node_id,
                        candidates,
                        candidate_sources,
                        candidate_generation,
                        candidates_expires_at_ms,
                    )
                    .await,
                FreshPunchDecision::None,
            ),
            FreshSignalVerdict::Accepted(id) => {
                let apply_result = self
                    .peers
                    .apply_remote_fresh_candidates(
                        from_node_id,
                        id,
                        candidates,
                        candidate_sources,
                        candidate_generation,
                        candidates_expires_at_ms,
                    )
                    .await;
                if apply_result != CandidateSetApplyResult::Applied {
                    // PeerMissing, empty, expired or a stale candidate
                    // generation: the fresh ID is NOT consumed so the same
                    // signal retried later (after the peer registers, for
                    // example) still applies.
                    self.peers
                        .record_direct_event(
                            from_node_id,
                            "fresh_prediction_not_applied",
                            None,
                            Some(candidates.len()),
                            None,
                            format!(
                                "fresh prediction {id:?} was not applied ({apply_result:?}); the fresh identity stays unconsumed"
                            ),
                        )
                        .await;
                    (apply_result, FreshPunchDecision::None)
                } else if self
                    .peers
                    .commit_remote_fresh_prediction(from_node_id, id)
                    .await
                {
                    // The identity is committed with an immutable snapshot:
                    // the punch targets are frozen from THAT snapshot.
                    let frozen = self
                        .freeze_fresh_punch_targets(from_node_id, id)
                        .await;
                    let decision = match frozen {
                        Some(targets) => FreshPunchDecision::Fresh(id, targets),
                        // The committed snapshot expired or is empty: the
                        // prediction must never claim fresh priority or fall
                        // back to the shared candidates as if it were fresh.
                        None => {
                            self.peers
                                .record_direct_event(
                                    from_node_id,
                                    "fresh_prediction_snapshot_invalid",
                                    None,
                                    Some(candidates.len()),
                                    None,
                                    format!(
                                        "fresh prediction {id:?} committed but its snapshot is expired or empty; the signal degrades to ordinary priority"
                                    ),
                                )
                                .await;
                            FreshPunchDecision::Degraded
                        }
                    };
                    (apply_result, decision)
                } else {
                    // The commit lost the CAS to a newer identity: roll this
                    // apply's candidates back so they cannot pollute the
                    // shared candidate set, and start no punch.
                    self.peers
                        .rollback_remote_fresh_apply(from_node_id, id)
                        .await;
                    self.peers
                        .record_direct_event(
                            from_node_id,
                            "fresh_prediction_superseded",
                            None,
                            Some(candidates.len()),
                            None,
                            format!(
                                "fresh prediction {id:?} was applied but a newer identity committed first; its candidates were rolled back and no punch starts from it"
                            ),
                        )
                        .await;
                    (CandidateSetApplyResult::IgnoredStale, FreshPunchDecision::None)
                }
            }
            FreshSignalVerdict::AlreadyRecorded(id) => {
                // The candidates were applied by the first attempt; the punch
                // may still start from the committed snapshot — but only a
                // valid (unexpired, non-empty) snapshot may claim fresh
                // priority.
                let frozen = self.freeze_fresh_punch_targets(from_node_id, id).await;
                let decision = match frozen {
                    Some(targets) => FreshPunchDecision::Fresh(id, targets),
                    None => {
                        self.peers
                            .record_direct_event(
                                from_node_id,
                                "fresh_prediction_snapshot_invalid",
                                None,
                                Some(candidates.len()),
                                None,
                                format!(
                                    "fresh prediction retry {id:?} has an expired or empty committed snapshot; the signal degrades to ordinary priority"
                                ),
                            )
                            .await;
                        FreshPunchDecision::Degraded
                    }
                };
                (CandidateSetApplyResult::Applied, decision)
            }
            FreshSignalVerdict::PayloadMismatch(id) => {
                debug!(
                    "Fresh-mapping prediction {id:?} from {from_node_id} was rejected: the retry payload differs from the committed snapshot"
                );
                (CandidateSetApplyResult::IgnoredStale, FreshPunchDecision::None)
            }
            FreshSignalVerdict::Stale | FreshSignalVerdict::Inconsistent => {
                // The current candidate set stays authoritative; only the
                // handshake below may proceed.
                (CandidateSetApplyResult::IgnoredStale, FreshPunchDecision::None)
            }
        };
        (fresh_verdict, candidate_apply_result, fresh_punch)
    }

    async fn run_control_event_loop(
        &mut self,
        relay_started: &mut bool,
        network_inbound_tx: mpsc::Sender<ReceivedEncryptedPacket>,
    ) {
        // Process control events until shutdown is requested.
        // Move the receiver out first so the event loop can hold immutable
        // borrows of the daemon in its cooperative slow-work set.  All daemon
        // state is already interior-synchronized; the receiver is the sole
        // field that needs mutable access.
        let (_replacement_tx, replacement_rx) = mpsc::unbounded_channel();
        let mut control_rx = std::mem::replace(&mut self.control_rx, replacement_rx);
        let daemon: &Daemon = &*self;
        let mut slow_work: FuturesUnordered<ControlEventWork<'_>> = FuturesUnordered::new();
        let mut shutdown_rx = self.shutdown_rx.clone();
        let mut task_shutdown_rx = self.task_manager.shutdown_rx();
        loop {
            tokio::select! {
                _ = shutdown_rx.changed() => {
                    if *shutdown_rx.borrow() {
                        info!("Shutdown signal received in main event loop");
                        break;
                    }
                }
                _ = task_shutdown_rx.changed() => {
                    if *task_shutdown_rx.borrow() {
                        warn!("Task manager requested daemon shutdown");
                        break;
                    }
                }
                _ = slow_work.next(), if !slow_work.is_empty() => {
                    // The work item logs its own outcome.  Completion only
                    // frees one bounded slot; no state is committed here.
                }
                event = control_rx.recv() => {
                    let Some(event) = event else {
                        warn!("Control event channel closed");
                        break;
                    };
                    match event {
                ControlEvent::Registered {
                    node_id,
                    virtual_ip: _,
                    cidr: _,
                    relay_servers,
                    relay_catalog,
                } => {
                    self.health.mark_control_success().await;
                    if !*relay_started {
                        let relay_node_id =
                            node_id.unwrap_or_else(|| self.config.node.node_id.clone());
                        let relay_servers = if relay_servers.is_empty() {
                            self.config.relay.servers.clone()
                        } else {
                            relay_servers
                        };
                        let relay_candidates =
                            relay_candidates_from_sources(&relay_catalog, &relay_servers);
                        if relay_candidates.is_empty() {
                            debug!("No relay servers advertised by control plane");
                            continue;
                        }
                        *relay_started = true;
                        let allow_insecure_plaintext = effective_relay_allow_insecure_plaintext(
                            &self.config.control.server_url,
                            &relay_catalog,
                            &relay_servers,
                            self.config.relay.allow_insecure_plaintext,
                        );
                        if allow_insecure_plaintext
                            && !self.config.relay.allow_insecure_plaintext
                        {
                            info!(
                                "Allowing plaintext relay because HTTP control plane supplied legacy relay candidates"
                            );
                        }
        spawn_relay_inbound(RelayInboundSpawnContext {
            task_manager: self.task_manager.clone(),
            relay_candidates,
            preferred_regions: self.config.relay.preferred_regions.clone(),
            selection_timeout: Duration::from_millis(
        self.config.relay.selection_timeout_ms.max(1),
            ),
            node_id: relay_node_id,
            peers: self.peers.clone(),
            relay_transport: self.relay_transport.clone(),
            relay_selection: self.relay_selection.clone(),
            inbound_tx: network_inbound_tx.clone(),
            control: self.control.clone(),
            allow_insecure_plaintext,
            ca_cert_path: self.config.relay.ca_cert_path.clone(),
        })
        .await;
                    }
                }

                ControlEvent::PeerJoined(peer_info) => {
                    info!(
                        "Peer joined: {} ({})",
                        peer_info.node_id, peer_info.virtual_ip
                    );
                    self.peers.add_peer(&peer_info).await;

                    if peer_info.online {
                        if slow_work.len() >= MAX_CONTROL_EVENT_SLOW_WORK {
                            warn!(
                                "Deferring peer-join handshake for {}: control slow-work cap {} is full",
                                peer_info.node_id,
                                MAX_CONTROL_EVENT_SLOW_WORK,
                            );
                        } else if let Some(reservation) = self
                            .reserve_event_initiator_handshake(&peer_info.node_id)
                            .await
                        {
                            let peer_info = peer_info.clone();
                            slow_work.push(Box::pin(async move {
                                daemon
                                    .run_event_initiator_handshake(peer_info, reservation)
                                    .await;
                            }));
                        }

                        if self.dns.is_enabled() {
                            self.dns
                                .register(
                                    &peer_info.node_id,
                                    &peer_info.virtual_ip,
                                    Some(&peer_info.node_id),
                                )
                                .await;
                        }
                    } else {
                        debug!(
                            "Peer {} is currently offline; keeping it in diagnostics without starting traversal",
                            peer_info.node_id
                        );
                    }
                }

                ControlEvent::PeerUpdated(peer_info) => {
                    let previous = self.peers.get_connection(&peer_info.node_id).await;
                    let update = self.peers.add_peer(&peer_info).await;
                    if !peer_info.online {
                        {
                            // Linearize lifecycle cleanup with the short
                            // offer/answer mutation phase.  The handler drops
                            // this arbiter before STUN/HTTP, so offline state
                            // never waits for a slow control-plane request.
                            let _handshake_guard =
                                self.handshake_arbiter.acquire(&peer_info.node_id).await;
                            self.transport.remove_session(&peer_info.node_id).await;
                            self.pending_handshakes
                                .lock()
                                .await
                                .clear_peer(&peer_info.node_id);
                        }
                        self.punch_attempts.cancel(&peer_info.node_id);
                        if let Some(udp) = self.udp_transport.read().await.clone() {
                            // One atomic lifecycle cleanup under the peer's
                            // adoption lock: the pending probes drop and the
                            // cleanup epoch moves on, the dynamic sockets
                            // detach and the affinity clears, all in one
                            // transaction, so a late ACK can neither match,
                            // re-insert nor leave pool affinity behind.
                            udp.cleanup_peer_lifecycle(
                                &peer_info.node_id,
                                "peer_offline",
                                false,
                            )
                            .await;
                        }
                        if self.dns.is_enabled() {
                            if let Some(previous) = previous.as_ref() {
                                self.dns.unregister(&previous.virtual_ip).await;
                            } else {
                                self.dns.unregister(&peer_info.virtual_ip).await;
                            }
                        }
                        debug!(
                            "Peer {} is offline according to control plane; cleared active sessions and skipped traversal",
                            peer_info.node_id
                        );
                        continue;
                    }
                    if update.public_key_changed {
                        {
                            // See the offline path above: a stale worker can
                            // neither stage after this identity cleanup nor
                            // commit once its owner is cancelled.
                            let _handshake_guard =
                                self.handshake_arbiter.acquire(&peer_info.node_id).await;
                            self.transport.remove_session(&peer_info.node_id).await;
                            self.pending_handshakes
                                .lock()
                                .await
                                .clear_peer(&peer_info.node_id);
                        }
                        info!(
                            "Peer {} public key changed; discarded the old WireGuard session",
                            peer_info.node_id
                        );
                        // A changed public key is a new peer incarnation: the
                        // old punch owner, pending probe ownership, fresh
                        // model and every dynamic socket belong to the old
                        // identity and must not keep mutating state or send
                        // to the old binding.
                        self.punch_attempts.cancel(&peer_info.node_id);
                        self.peers
                            .clear_fresh_mapping(&peer_info.node_id, "public_key_changed")
                            .await;
                        if let Some(udp) = self.udp_transport.read().await.clone() {
                            udp.cleanup_peer_lifecycle(
                                &peer_info.node_id,
                                "public_key_changed",
                                false,
                            )
                            .await;
                        }
                    } else if update.endpoint_changed {
                        // The peer moved to a different public endpoint:
                        // fresh generations aimed at the old endpoint must be
                        // invalidated so no old task keeps committing toward
                        // it.  The old dynamic socket itself keeps working as
                        // the peer's current mapping until a new generation
                        // commits or peer-level cleanup runs (the state
                        // machine preserves it on failure).
                        self.punch_attempts.cancel(&peer_info.node_id);
                        self.peers
                            .clear_fresh_mapping(&peer_info.node_id, "endpoint_changed")
                            .await;
                        if let Some(udp) = self.udp_transport.read().await.clone() {
                            udp.clear_pending_probes_for_peer(&peer_info.node_id)
                                .await;
                        }
                    }
                    let was_offline = previous.as_ref().is_some_and(|peer| !peer.online);
                    if (update.virtual_ip_changed || was_offline) && self.dns.is_enabled() {
                        if let Some(previous) = previous {
                            self.dns.unregister(&previous.virtual_ip).await;
                        }
                        self.dns
                            .register(
                                &peer_info.node_id,
                                &peer_info.virtual_ip,
                                Some(&peer_info.node_id),
                            )
                            .await;
                    }
                    if slow_work.len() >= MAX_CONTROL_EVENT_SLOW_WORK {
                        warn!(
                            "Deferring peer-update handshake for {}: control slow-work cap {} is full",
                            peer_info.node_id,
                            MAX_CONTROL_EVENT_SLOW_WORK,
                        );
                    } else if let Some(reservation) = self
                        .reserve_event_initiator_handshake(&peer_info.node_id)
                        .await
                    {
                        let peer_info = peer_info.clone();
                        slow_work.push(Box::pin(async move {
                            daemon
                                .run_event_initiator_handshake(peer_info, reservation)
                                .await;
                        }));
                    }
                }

                ControlEvent::PeerLeft(node_id) => {
                    info!("Peer left: {}", node_id);
                    if let Some(previous) = self.peers.get_connection(&node_id).await {
                        if self.dns.is_enabled() {
                            self.dns.unregister(&previous.virtual_ip).await;
                        }
                    }
                    {
                        // PeerLeft shares the same short state boundary as
                        // offer staging. It never holds the arbiter across the
                        // subsequent UDP lifecycle cleanup.
                        let _handshake_guard = self.handshake_arbiter.acquire(&node_id).await;
                        self.transport.remove_session(&node_id).await;
                        self.pending_handshakes.lock().await.clear_peer(&node_id);
                    }
                    self.punch_attempts.cancel(&node_id);
                    if let Some(udp) = self.udp_transport.read().await.clone() {
                        // One atomic lifecycle cleanup under the peer's
                        // adoption lock: the connection removal, the pending
                        // probe drop with the cleanup-epoch bump, the dynamic
                        // socket detach and the affinity clear form ONE
                        // transaction, linearized against every ACK adoption
                        // for this peer.  A late ACK can neither match, nor
                        // re-insert, nor leave pool affinity / endpoint /
                        // candidate state behind for a new identity that
                        // later rejoins under the same node ID.
                        udp.cleanup_peer_lifecycle(&node_id, "peer_left", true)
                            .await;
                    }
                }

                ControlEvent::PeerOffer {
                    from_node_id,
                    candidates,
                    session_id,
                    probe_ephemeral_public_key,
                    candidate_sources,
                    candidate_generation,
                    candidates_expires_at_ms,
                    handshake_init,
                    punch_at_ms,
                    punch_at_server_ms,
                    sender_public_key,
                } => {
                    info!(
                        "Received peer offer from {} ({} candidates)",
                        from_node_id,
                        candidates.len()
                    );
                    self.peers
                        .record_direct_event(
                            &from_node_id,
                            "peer_offer_received",
                            None,
                            Some(candidates.len()),
                            None,
                            format!(
                                "received offer handshake_bytes={} punch_at_ms={punch_at_ms:?}",
                                handshake_init.len()
                            ),
                        )
                        .await;
                    // Signal delivery can race the peer-list poll: an offer
                    // may be received before PeerJoined has installed the
                    // sender's static public key.  Do not run candidate
                    // admission or consume the responder transaction in that
                    // state.  Enqueue the complete newest offer under the
                    // existing per-peer owner and replay it once registration
                    // becomes visible.
                    if self.peers.get_connection(&from_node_id).await.is_none() {
                        // Wake the peer poll immediately: the regular cadence
                        // can be seconds away and a cold-start handshake must
                        // not wait it out.
                        self.control.refresh_peers_now();
                        self.peers
                            .record_direct_event(
                                &from_node_id,
                                "peer_offer_deferred_unknown",
                                None,
                                Some(candidates.len()),
                                None,
                                "deferred offer until PeerJoined installs peer identity",
                            )
                            .await;
                        let admitted = {
                            let mut state = self.pending_handshakes.lock().await;
                            if !state.has_responder_worker(&from_node_id)
                                && slow_work.len() >= MAX_CONTROL_EVENT_SLOW_WORK
                            {
                                warn!(
                                    "Dropping peer offer from {from_node_id}: control slow-work cap {} is full",
                                    MAX_CONTROL_EVENT_SLOW_WORK,
                                );
                                None
                            } else {
                                state.enqueue_responder_work(PendingPeerOffer {
                                    from_node_id: from_node_id.clone(),
                                    candidates: candidates.clone(),
                                    candidate_sources: candidate_sources.clone(),
                                    candidate_generation,
                                    candidates_expires_at_ms,
                                    sender_public_key: sender_public_key.clone(),
                                    handshake_init: handshake_init.clone(),
                                    punch_at_ms,
                                    punch_at_server_ms,
                                    session_id: session_id.clone(),
                                    probe_ephemeral_public_key: probe_ephemeral_public_key.clone(),
                                })
                            }
                        };
                        if let Some((reservation, offer)) = admitted {
                            slow_work.push(Box::pin(async move {
                                daemon
                                    .run_deferred_peer_offer_worker(offer, reservation)
                                    .await;
                            }));
                        }
                        continue;
                    }
                    // Fresh-prediction verification happens BEFORE any
                    // candidate state is touched: a superseded prediction
                    // must not pollute the candidate set, while the handshake
                    // itself is still handled below.  The prepare/apply/commit
                    // transaction is shared with the answer path.
                    let (_fresh_verdict, candidate_apply_result, fresh_punch) = self
                        .fresh_prediction_transaction(
                            &from_node_id,
                            &candidates,
                            &candidate_sources,
                            candidate_generation,
                            candidates_expires_at_ms,
                            sender_public_key.as_deref(),
                        )
                        .await;
                    if !handshake_init.is_empty() {
                        let admitted = {
                            let mut state = self.pending_handshakes.lock().await;
                            if !state.has_responder_worker(&from_node_id)
                                && slow_work.len() >= MAX_CONTROL_EVENT_SLOW_WORK
                            {
                                warn!(
                                    "Deferring peer offer from {from_node_id}: control slow-work cap {} is full",
                                    MAX_CONTROL_EVENT_SLOW_WORK,
                                );
                                None
                            } else {
                                state.enqueue_responder_work(PendingPeerOffer {
                                    from_node_id: from_node_id.clone(),
                                    candidates: candidates.clone(),
                                    candidate_sources: candidate_sources.clone(),
                                    candidate_generation,
                                    candidates_expires_at_ms,
                                    sender_public_key: sender_public_key.clone(),
                                    handshake_init: handshake_init.clone(),
                                    punch_at_ms,
                                    punch_at_server_ms,
                                    session_id: session_id.clone(),
                                    probe_ephemeral_public_key: probe_ephemeral_public_key.clone(),
                                })
                            }
                        };
                        if let Some((mut reservation, mut offer)) = admitted {
                            slow_work.push(Box::pin(async move {
                                loop {
                                    let peer_id = offer.from_node_id.clone();
                                    if let Err(err) = daemon
                                        .handle_event_peer_offer(
                                            offer,
                                            reservation.owner,
                                            &mut reservation.cancellation,
                                        )
                                        .await
                                    {
                                        warn!("Failed to handle peer offer from {peer_id}: {err}");
                                    }
                                    let Some(next) = daemon
                                        .pending_handshakes
                                        .lock()
                                        .await
                                        .finish_responder_work(&peer_id, reservation.owner)
                                    else {
                                        break;
                                    };
                                    offer = next;
                                }
                            }));
                        }
                    }
                    match fresh_punch {
                        // A valid fresh snapshot punches its frozen targets at
                        // FRESH priority, always.
                        FreshPunchDecision::Fresh(id, frozen_targets) => {
                            self.start_hole_punch_at(
                                &from_node_id,
                                punch_at_ms,
                                Some(id),
                                Some(frozen_targets),
                            )
                            .await;
                        }
                        // An expired or empty committed snapshot must never
                        // claim fresh priority or fall back to the shared
                        // candidates as a fresh signal: only a handshake-
                        // carrying offer degrades to an ordinary priority
                        // punch; a candidate-only offer is ignored.
                        FreshPunchDecision::Degraded => {
                            if !handshake_init.is_empty() {
                                debug!(
                                    "Degrading synchronized punch for {from_node_id}: the fresh snapshot is expired or empty; punching at ordinary priority"
                                );
                                self.start_hole_punch_at(
                                    &from_node_id,
                                    punch_at_ms,
                                    None,
                                    None,
                                )
                                .await;
                            } else {
                                debug!(
                                    "Skipping punch for candidate-only offer from {from_node_id}: its fresh snapshot is expired or empty"
                                );
                            }
                        }
                        FreshPunchDecision::None => {
                            if candidate_signal_starts_synchronized_punch(
                                &handshake_init,
                                candidate_apply_result,
                            ) {
                                self.start_hole_punch_at(
                                    &from_node_id,
                                    punch_at_ms,
                                    None,
                                    None,
                                )
                                .await;
                            } else {
                                debug!(
                                    "Skipping synchronized punch for rejected candidate-only offer from {from_node_id}: {candidate_apply_result:?}"
                                );
                            }
                        }
                    }
                }

                ControlEvent::PeerAnswer {
                    from_node_id,
                    candidates,
                    session_id,
                    probe_ephemeral_public_key,
                    candidate_sources,
                    candidate_generation,
                    candidates_expires_at_ms,
                    handshake_response,
                    punch_at_ms,
                    punch_at_server_ms: _,
                    sender_public_key,
                } => {
                    info!(
                        "Received peer answer from {} ({} candidates)",
                        from_node_id,
                        candidates.len()
                    );
                    // An answer may arrive before the peer-list poll registers
                    // its sender: wake the peer poll so the pending initiator
                    // transaction can be consumed without waiting out the
                    // regular cadence.
                    if self.peers.get_connection(&from_node_id).await.is_none() {
                        self.control.refresh_peers_now();
                    }
                    self.peers
                        .record_direct_event(
                            &from_node_id,
                            "peer_answer_received",
                            None,
                            Some(candidates.len()),
                            None,
                            format!(
                                "received answer handshake_bytes={} punch_at_ms={punch_at_ms:?}",
                                handshake_response.len()
                            ),
                        )
                        .await;
                    // Fresh-prediction verification happens BEFORE any
                    // candidate state is touched (see the offer path).
                    let (_fresh_verdict, candidate_apply_result, fresh_punch) = self
                        .fresh_prediction_transaction(
                            &from_node_id,
                            &candidates,
                            &candidate_sources,
                            candidate_generation,
                            candidates_expires_at_ms,
                            sender_public_key.as_deref(),
                        )
                        .await;
                    if !handshake_response.is_empty() {
                        if let Err(err) = self
                            .handle_peer_answer(
                                &from_node_id,
                                &handshake_response,
                                session_id.clone(),
                                probe_ephemeral_public_key.clone(),
                            )
                            .await
                        {
                            warn!("Failed to handle peer answer from {from_node_id}: {err}");
                        }
                    }
                    match fresh_punch {
                        FreshPunchDecision::Fresh(id, frozen_targets) => {
                            self.start_hole_punch_at(
                                &from_node_id,
                                punch_at_ms,
                                Some(id),
                                Some(frozen_targets),
                            )
                            .await;
                        }
                        FreshPunchDecision::Degraded => {
                            if !handshake_response.is_empty() {
                                debug!(
                                    "Degrading synchronized punch for {from_node_id}: the fresh snapshot is expired or empty; punching at ordinary priority"
                                );
                                self.start_hole_punch_at(
                                    &from_node_id,
                                    punch_at_ms,
                                    None,
                                    None,
                                )
                                .await;
                            } else {
                                debug!(
                                    "Skipping punch for candidate-only answer from {from_node_id}: its fresh snapshot is expired or empty"
                                );
                            }
                        }
                        FreshPunchDecision::None => {
                            if candidate_signal_starts_synchronized_punch(
                                &handshake_response,
                                candidate_apply_result,
                            ) {
                                self.start_hole_punch_at(
                                    &from_node_id,
                                    punch_at_ms,
                                    None,
                                    None,
                                )
                                .await;
                            } else {
                                debug!(
                                    "Skipping synchronized punch for rejected candidate-only answer from {from_node_id}: {candidate_apply_result:?}"
                                );
                            }
                        }
                    }
                }

                ControlEvent::PeerReflexive {
                    from_node_id,
                    observed_endpoint,
                    punch_at_ms,
                } => {
                    // A peer-reflexive observation may arrive before the
                    // peer-list poll registers the sender; wake the poll so a
                    // cold-start handshake is not delayed by the cadence.
                    if self.peers.get_connection(&from_node_id).await.is_none() {
                        self.control.refresh_peers_now();
                    }
                    let work = PendingPeerReflexive {
                        from_node_id: from_node_id.clone(),
                        observed_endpoint,
                        punch_at_ms,
                    };
                    let admitted = {
                        let mut state = self.pending_handshakes.lock().await;
                        if !state.has_peer_reflexive_worker(&from_node_id)
                            && slow_work.len() >= MAX_CONTROL_EVENT_SLOW_WORK
                        {
                            warn!(
                                "Dropping peer-reflexive work for {from_node_id}: control slow-work cap {} is full",
                                MAX_CONTROL_EVENT_SLOW_WORK,
                            );
                            None
                        } else {
                            state.enqueue_peer_reflexive_work(work)
                        }
                    };
                    if let Some((reservation, work)) = admitted {
                        slow_work.push(Box::pin(async move {
                            daemon.run_peer_reflexive_worker(work, reservation).await;
                        }));
                    }
                }

                ControlEvent::PeerRejected {
                    from_node_id,
                    reason,
                } => {
                    warn!("Peer {} rejected connection: {}", from_node_id, reason);
                }

                ControlEvent::TunnelCreated {
                    tunnel_id,
                    public_endpoint,
                } => {
                    info!("Tunnel created: {} → {}", tunnel_id, public_endpoint);
                    self.port_mappings
                        .activate(&tunnel_id, &public_endpoint)
                        .await
                        .ok();
                }

                ControlEvent::ServerError { code, message } => {
                    error!("Control server error: {} - {}", code, message);
                }

                ControlEvent::Disconnected => {
                    // Control loop will re-register; do not shut down the daemon.
                    self.health.set_control_connected(false);
                    warn!("Disconnected from control server; waiting for recovery");
                }

                ControlEvent::ReauthRequired { message } => {
                    error!("Reauthentication required: {message}");
                    self.health.set_reauth_required(true);
                    // Keep running so operator can re-auth; do not exit daemon.
                }

                ControlEvent::ControlRecovered { .. } => {
                    info!("Control plane recovered after disconnection");
                    self.health.mark_control_success().await;
                }
                ControlEvent::ControlHealthy => {
                    self.health.mark_control_success().await;
                }
                    }
                }
            }
        }
        // Drop all borrowed background work before restoring the receiver.
        // Dropping these futures also releases any STUN/HTTP wait promptly on
        // daemon shutdown rather than leaving detached work behind.
        drop(slow_work);
        self.control_rx = control_rx;
    }
}
