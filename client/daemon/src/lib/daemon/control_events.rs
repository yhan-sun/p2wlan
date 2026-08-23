use futures_util::stream::{FuturesUnordered, StreamExt};
use std::future::Future;
use std::pin::Pin;
use std::collections::VecDeque as InitiatorQueue;

/// The serial control receiver owns fresh-prediction admission and short
/// state commits.  Slow STUN/HTTP work runs here instead of directly in the
/// receiver, with every producer supplying a per-peer reservation and this
/// global cap providing a hard upper bound during a control-plane burst.
type ControlEventWork<'a> = Pin<Box<dyn Future<Output = ()> + Send + 'a>>;

const MAX_CONTROL_EVENT_SLOW_WORK: usize = 64;
/// A roster burst may contain more peers than the cooperative slow-work lane
/// can admit at once.  Do not silently lose the initiator handshake for the
/// peers after that boundary: retain one newest-wins entry per peer and drain
/// it whenever a slow-work slot is released.  The bound is deliberately
/// finite so a corrupt control roster cannot grow daemon memory without
/// limit; overflow is an explicit diagnostic event, never an implicit drop.
const MAX_DEFERRED_INITIATOR_HANDSHAKES: usize = 256;

fn enqueue_deferred_initiator_handshake(
    queue: &mut InitiatorQueue<control::PeerInfo>,
    peer_info: control::PeerInfo,
) -> bool {
    if let Some(existing) = queue
        .iter_mut()
        .find(|existing| existing.node_id == peer_info.node_id)
    {
        *existing = peer_info;
        return true;
    }
    if queue.len() >= MAX_DEFERRED_INITIATOR_HANDSHAKES {
        return false;
    }
    queue.push_back(peer_info);
    true
}

fn remove_deferred_initiator_handshake(
    queue: &mut InitiatorQueue<control::PeerInfo>,
    peer_id: &str,
) {
    queue.retain(|peer_info| peer_info.node_id != peer_id);
}

/// Responder offers have their own cooperative lane.  Candidate refresh,
/// peer-reflexive HTTP and event-triggered initiator preparation may occupy
/// the bounded general slow-work set, but a WireGuard answer must still be
/// admitted and processed immediately.  One owner per peer keeps this lane
/// bounded by the number of registered peers and coalesces retransmissions.
const RESPONDER_WORK_RETRY_LIMIT: u8 = 3;
const RESPONDER_WORK_RETRY_BACKOFF: [Duration; 3] = [
    Duration::from_millis(50),
    Duration::from_millis(100),
    Duration::from_millis(250),
];

fn responder_offer_error_is_retryable(error: &DaemonError) -> bool {
    // Control-plane command completion can be lost after the signal was
    // dequeued.  The responder transaction is idempotent through its exact
    // handshake cache, so a bounded retry is safe.  Parsing, identity and
    // role errors are terminal and are never retried.
    matches!(error, DaemonError::ControlPlane(_))
        || matches!(
            error,
            DaemonError::Network(reason)
                if reason == REASON_RESPONDER_HANDSHAKE_ARBITER_TIMEOUT
        )
}

fn responder_offer_error_reason_code(error: &DaemonError) -> &'static str {
    match error {
        DaemonError::ControlPlane(_) => "control_plane_error",
        DaemonError::Network(reason)
            if reason == REASON_RESPONDER_HANDSHAKE_ARBITER_TIMEOUT =>
        {
            REASON_RESPONDER_HANDSHAKE_ARBITER_TIMEOUT
        }
        _ => "responder_offer_error",
    }
}

fn responder_offer_retry_delay(attempt: u8) -> Duration {
    RESPONDER_WORK_RETRY_BACKOFF
        .get(attempt.saturating_sub(1) as usize)
        .copied()
        .unwrap_or_else(|| RESPONDER_WORK_RETRY_BACKOFF[RESPONDER_WORK_RETRY_BACKOFF.len() - 1])
}

/// A control signal can arrive a few seconds before the corresponding
/// PeerJoined event (REST polling and signal delivery are independent).  Keep
/// one bounded responder worker alive for this interval so the authenticated
/// offer is replayed after the peer identity is installed instead of being
/// rejected as unknown.  The worker is cancelled by the normal peer-lifecycle
/// cleanup path, and repeated offers replace its single queued value.
const UNKNOWN_PEER_OFFER_WAIT: Duration = Duration::from_secs(8);
const UNKNOWN_PEER_OFFER_POLL: Duration = Duration::from_millis(25);

/// Offer-ingress deduplication and per-peer rate limiting.
///
/// A duplicate or rate-limited offer must not touch candidate state (no
/// candidate apply, no fresh-prediction transaction, no punch trigger): the
/// exact-duplicate fingerprint within the dedup window is the strongest
/// "nothing changed" signal, and the apply-rate window bounds how often a
/// churning peer (including an old client retransmitting every few seconds)
/// can drive candidate-plane work.  Handshake-carrying offers are still
/// answered: a crossing rekey must never be dropped by the rate limiter.
const OFFER_INGRESS_DEDUP_WINDOW: Duration = Duration::from_secs(2);
const OFFER_INGRESS_APPLY_WINDOW: Duration = Duration::from_secs(5);
const OFFER_INGRESS_MAX_APPLIES: u32 = 4;

/// Per-peer offer-ingress record.
struct OfferIngressRecord {
    /// Payload fingerprint (candidates + sources + expiry).
    fingerprint: [u8; 32],
    /// Sender-identity fingerprint: two offers with an identical payload but
    /// a DIFFERENT sender public key are never duplicates (a key change is a
    /// new incarnation).
    sender_fingerprint: [u8; 32],
    /// Last seen time of any offer (dedup window).
    last_seen_at: Instant,
    /// Candidate-plane applies within the current apply window.
    apply_count: u32,
    apply_window_started_at: Instant,
    /// Whether the last offer was admitted (for diagnostics ordering).
    last_verdict: &'static str,
    /// Whether any offer was recorded before: the first offer of a payload is
    /// never a duplicate, even when its age would be zero.
    seen_once: bool,
}

/// Verdict for an incoming offer, decided BEFORE any candidate-plane state is
/// touched.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum OfferIngressVerdict {
    /// The offer may apply candidates and start a punch session.
    Apply,
    /// Byte-identical payload seen within the dedup window: no candidate
    /// apply, no fresh transaction, no punch (the running session already
    /// covers it).  The handshake part is still handled.
    Duplicate,
    /// The peer exceeded the per-window apply rate: candidate apply and
    /// punch are suppressed; the handshake part is still handled.
    RateLimited,
}

impl Daemon {
    /// A same-node remote restart is identified by the encoded candidate
    /// generation carried in its offer. Keep this narrow: endpoint metadata is
    /// also changed by ordinary NAT churn and is not safe as a lifecycle
    /// signal. The arbiter covers the short state boundary; UDP cleanup then
    /// invalidates late probes and dynamic socket adoption.
    async fn reset_peer_for_remote_incarnation_if_needed(
        &self,
        peer_id: &str,
        candidate_generation: u64,
    ) -> bool {
        let handshake_guard = self.handshake_arbiter.acquire(peer_id).await;
        let changed = self
            .peers
            .reset_peer_session_if_remote_incarnation_changed(
                peer_id,
                candidate_generation,
                "remote_incarnation_changed",
            )
            .await;
        if !changed {
            drop(handshake_guard);
            return false;
        }
        self.transport.remove_session(peer_id).await;
        self.pending_handshakes.lock().await.clear_peer(peer_id);
        drop(handshake_guard);
        self.punch_attempts.cancel(peer_id);
        if let Some(udp) = self.udp_transport.read().await.clone() {
            udp.cleanup_peer_lifecycle(peer_id, "remote_incarnation_changed", false)
                .await;
        }
        true
    }

    /// Decide whether an offer may touch candidate-plane state.
    ///
    /// Runs before `fresh_prediction_transaction` and before the responder
    /// worker enqueue: repeated/old offers from a churning peer can no longer
    /// trigger candidate applies or fresh-prediction transactions.
    async fn offer_ingress_verdict(
        &self,
        from_node_id: &str,
        candidates: &[String],
        candidate_sources: &HashMap<String, String>,
        candidates_expires_at_ms: Option<u64>,
        sender_public_key: Option<&str>,
    ) -> OfferIngressVerdict {
        let now = Instant::now();
        let fingerprint =
            crate::peer::fresh_payload_hash(candidates, candidate_sources, candidates_expires_at_ms);
        let sender_fingerprint = sender_public_key
            .map(|key| crate::peer::fresh_payload_hash(&[key.to_string()], &HashMap::new(), None))
            .unwrap_or([0u8; 32]);
        let mut ingress = self.offer_ingress.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        let record = ingress.entry(from_node_id.to_string()).or_insert(OfferIngressRecord {
            fingerprint,
            sender_fingerprint,
            last_seen_at: now,
            apply_count: 0,
            apply_window_started_at: now,
            last_verdict: "apply",
            seen_once: false,
        });
        if record.seen_once
            && record.fingerprint == fingerprint
            && record.sender_fingerprint == sender_fingerprint
            && now.duration_since(record.last_seen_at) <= OFFER_INGRESS_DEDUP_WINDOW
        {
            record.last_seen_at = now;
            record.last_verdict = "duplicate";
            return OfferIngressVerdict::Duplicate;
        }
        if now.duration_since(record.apply_window_started_at) > OFFER_INGRESS_APPLY_WINDOW {
            record.apply_count = 0;
            record.apply_window_started_at = now;
        }
        if record.apply_count >= OFFER_INGRESS_MAX_APPLIES {
            record.last_seen_at = now;
            record.last_verdict = "rate_limited";
            return OfferIngressVerdict::RateLimited;
        }
        record.fingerprint = fingerprint;
        record.last_seen_at = now;
        record.apply_count = record.apply_count.saturating_add(1);
        record.seen_once = true;
        record.last_verdict = "apply";
        OfferIngressVerdict::Apply
    }
}

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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum HardHardOfferHandling {
    NotHardHard,
    Rejected,
    Started,
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
        let hard_hard_handling = self
            .handle_hard_hard_fresh_offer(
                &offer.from_node_id,
                offer.session_id.as_deref(),
                offer.punch_at_ms,
                fresh_punch.clone(),
            )
            .await;
        if candidate_apply_result == CandidateSetApplyResult::Applied
            && hard_hard_handling != HardHardOfferHandling::Started
        {
            self.peers
                .clear_hard_hard_sessions(Some(&offer.from_node_id))
                .await;
        }
        if hard_hard_handling != HardHardOfferHandling::NotHardHard {
            return;
        }
        match fresh_punch {
            FreshPunchDecision::Fresh(id, frozen_targets) => {
                self.start_hole_punch_at(
                    &offer.from_node_id,
                    offer.punch_at_ms,
                    Some(id),
                    Some(frozen_targets.clone()),
                )
                .await;
                // C=0 (mutual-APD): when we also hold a fresh local mapping,
                // knock back from OUR fresh source at the SAME canonical
                // deadline toward the peer's fresh predicted ports.  This is
                // the fresh-fresh synchronized pair that breaks the
                // no-mutually-admitted-endpoint deadlock; bounded by the
                // per-(peer, generation) budget.
                self.coordinate_c0_fresh_fresh_pair(offer, &frozen_targets, id)
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

    /// Route a well-formed, control-context-admitted `hh1` fresh signal into
    /// the two-sided synchronized rendezvous.  The envelope is an epoch fence,
    /// not a cryptographic authenticator: malformed or mismatched metadata is
    /// consumed and rejected rather than silently degrading into an ordinary
    /// one-sided Hard↔Hard punch.
    async fn handle_hard_hard_fresh_offer(
        &self,
        peer_id: &str,
        session_id: Option<&str>,
        punch_at_ms: Option<u64>,
        fresh_punch: FreshPunchDecision,
    ) -> HardHardOfferHandling {
        let Some(session_id) = session_id else {
            return HardHardOfferHandling::NotHardHard;
        };
        if !HardHardCoordination::looks_like(session_id) {
            return HardHardOfferHandling::NotHardHard;
        }
        let Some(coordination) = HardHardCoordination::parse(session_id) else {
            self.peers
                .record_direct_event(
                    peer_id,
                    "hard_hard_session_rejected",
                    None,
                    None,
                    None,
                    "malformed Hard↔Hard session envelope; no fallback punch started",
                )
                .await;
            return HardHardOfferHandling::Rejected;
        };
        let FreshPunchDecision::Fresh(_id, frozen_targets) = fresh_punch else {
            self.peers
                .record_direct_event(
                    peer_id,
                    "hard_hard_session_rejected",
                    None,
                    None,
                    None,
                    "Hard↔Hard session did not carry an admitted, unexpired fresh prediction window",
                )
                .await;
            return HardHardOfferHandling::Rejected;
        };
        if !self
            .peers
            .bind_remote_nat_profile_to_candidate_epoch(
                peer_id,
                coordination.local_profile_generation,
            )
            .await
        {
            self.peers
                .record_direct_event(
                    peer_id,
                    "hard_hard_session_rejected",
                    frozen_targets.first().copied(),
                    Some(frozen_targets.len()),
                    None,
                    "Hard↔Hard profile generation was not current for the admitted candidate context",
                )
                .await;
            return HardHardOfferHandling::Rejected;
        }
        let Some(punch_at_ms) = punch_at_ms else {
            self.peers
                .record_direct_event(
                    peer_id,
                    "hard_hard_session_rejected",
                    frozen_targets.first().copied(),
                    Some(frozen_targets.len()),
                    None,
                    "Hard↔Hard session had no canonical punch_at_ms; Relay remains usable",
                )
                .await;
            return HardHardOfferHandling::Rejected;
        };
        let Some(udp) = self.udp_transport.read().await.clone() else {
            return HardHardOfferHandling::Rejected;
        };
        let Some(signal) = self.hole_punch_signal_context().await else {
            return HardHardOfferHandling::Rejected;
        };
        match coordination.role {
            HardHardRole::Initiator => {
                // A new remote initiator supersedes any older rendezvous on
                // this peer. Clear it before the new responder measurement is
                // launched; the new record is registered only after that
                // bounded measurement completes.
                self.peers
                    .clear_hard_hard_sessions(Some(peer_id))
                    .await;
                spawn_hard_hard_responder(
                    udp,
                    self.peers.clone(),
                    self.punch_attempts.clone(),
                    signal,
                    peer_id.to_string(),
                    coordination,
                    punch_at_ms,
                    frozen_targets,
                )
                .await;
                HardHardOfferHandling::Started
            }
            HardHardRole::Responder => {
                let current_remote_candidate_epoch = self
                    .peers
                    .current_remote_candidate_epoch(peer_id)
                    .await
                    .unwrap_or_default();
                match self
                    .peers
                    .hard_hard_prepare_response(
                        peer_id,
                        &coordination.token,
                        current_remote_candidate_epoch,
                    )
                    .await
                {
                    crate::peer::HardHardResponseAdmission::Rejected => {
                        self.peers
                            .record_direct_event(
                                peer_id,
                                "hard_hard_response_fenced",
                                frozen_targets.first().copied(),
                                Some(frozen_targets.len()),
                                None,
                                "Hard↔Hard response did not match the one live initiator session or its expected candidate epoch",
                            )
                            .await;
                        return HardHardOfferHandling::Rejected;
                    }
                    crate::peer::HardHardResponseAdmission::AlreadySweeping => {
                        return HardHardOfferHandling::Started;
                    }
                    crate::peer::HardHardResponseAdmission::Ready => {}
                }
                spawn_hard_hard_initiator_response(
                    udp,
                    self.peers.clone(),
                    self.punch_attempts.clone(),
                    peer_id.to_string(),
                    coordination,
                    frozen_targets,
                    punch_at_ms,
                )
                .await;
                HardHardOfferHandling::Started
            }
        }
    }

    /// Coordinate the C=0 fresh-fresh synchronized pair on the receiver side
    /// of a fresh offer.
    ///
    /// The peer advertised its FRESH predicted ports (`frozen_targets`) with a
    /// canonical `punch_at_ms`.  We already punch at that deadline through the
    /// ordinary path (`start_hole_punch_at`); when we ALSO hold a fresh local
    /// mapping for this peer, we additionally knock from OUR fresh source at
    /// the SAME canonical instant toward the peer's fresh ports — the
    /// mutual-APD deadlock breaker.
    ///
    /// Fully bounded: the per-(peer, generation) C=0 ledger caps the number of
    /// distinct fresh-fresh pairs ever attempted, and the C=0 rendezvous
    /// window itself reuses the micro-window target cap and attempt count.
    /// When the budget is exhausted, no further fresh-fresh pairs are
    /// scheduled and the relay keeps carrying the data plane.
    ///
    /// A miss is attributed to the ledger immediately (the pair was
    /// attempted); a hit is decided by the existing encrypted-validation path
    /// and stops further attempts via the ledger.
    async fn coordinate_c0_fresh_fresh_pair(
        &self,
        offer: &PendingPeerOffer,
        frozen_targets: &[SocketAddr],
        id: crate::FreshPredictionId,
    ) {
        let peer_id = &offer.from_node_id;
        let generation = self.peers.current_network_generation().await;
        // Budget gate first: exhausted means we stop scheduling C=0 pairs.
        if !self.peers.c0_pair_admission(peer_id, generation).await {
            self.peers
                .record_direct_event(
                    peer_id,
                    "c0_skipped_budget_exhausted",
                    None,
                    None,
                    None,
                    "C=0 fresh-fresh pair not scheduled: per-(peer, generation) budget exhausted",
                )
                .await;
            return;
        }
        // We must hold a fresh local mapping (the SOURCE the peer must learn)
        // for this pair to be meaningful.
        let Some(local_fresh) = self.peers.fresh_mapping_for_peer(peer_id).await else {
            self.peers
                .record_direct_event(
                    peer_id,
                    "c0_skipped_no_local_fresh",
                    None,
                    None,
                    None,
                    "C=0 fresh-fresh pair not scheduled: no fresh local mapping available",
                )
                .await;
            return;
        };
        // Remote targets = the peer's OWN fresh predicted ports (frozen by
        // the offer's committed snapshot), NOT historical stable_targets.
        let Some(plan) = C0FreshPairPlan::new(
            local_fresh.socket_local_endpoint,
            frozen_targets,
            offer.punch_at_ms,
        ) else {
            self.peers
                .record_direct_event(
                    peer_id,
                    "c0_skipped_no_remote_fresh",
                    None,
                    None,
                    None,
                    "C=0 fresh-fresh pair not scheduled: no remote fresh predicted ports in the offer",
                )
                .await;
            return;
        };
        let Some(udp) = self.udp_transport.read().await.clone() else {
            self.peers
                .record_direct_event(
                    peer_id,
                    "c0_skipped_no_udp",
                    None,
                    None,
                    None,
                    "C=0 fresh-fresh pair not scheduled: UDP transport not ready",
                )
                .await;
            return;
        };
        let scheduled = spawn_c0_synchronized_fresh_pair(
            udp,
            self.peers.clone(),
            self.punch_attempts.clone(),
            peer_id.clone(),
            plan.local_fresh_endpoint,
            local_fresh.socket_index,
            plan.bounded_targets.clone(),
            Some(plan.canonical_punch_at_ms),
            Some(id),
        )
        .await;
        // Attribution: the pair was (or was not) attempted; the ledger
        // counts the attempt regardless of the wire outcome, and a hit is
        // decided by encrypted validation independently.
        self.peers
            .c0_pair_attempt(
                peer_id,
                generation,
                self.peers.recovery_epoch_for(peer_id).await,
                &plan.local_fresh_endpoint.to_string(),
                &plan.bounded_targets
                    .first()
                    .map(ToString::to_string)
                    .unwrap_or_default(),
                Some(plan.canonical_punch_at_ms),
                crate::peer::C0PairOutcome::Miss,
            )
            .await;
        if !scheduled {
            self.peers
                .record_direct_event(
                    peer_id,
                    "c0_rendezvous_not_scheduled",
                    None,
                    None,
                    None,
                    "C=0 fresh-fresh pair could not be scheduled (budget/admission/udp/deferred); attributed as attempted miss",
                )
                .await;
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
        // The peer-reflexive signal carries the observer's relay-normalized
        // rendezvous deadline.  Join it with a tiny trusted remote-target
        // slice before the optional candidate re-offer: this is the receiver
        // half of the shared micro-window, not a replacement for the normal
        // full recovery punch below. Old signals without a deadline retain
        // the legacy full-punch behavior but never invent a one-sided
        // "synchronized" micro-window.
        if let Some(shared_punch_at_ms) = work.punch_at_ms {
            let udp = self.udp_transport.read().await.clone();
            let targets = self.peers.direct_probe_target_set_for(peer_id).await;
            if let (Some(udp), Some(targets)) = (udp, targets) {
                spawn_peer_reflexive_micro_window(
                    udp,
                    self.peers.clone(),
                    self.punch_attempts.clone(),
                    peer_id.to_string(),
                    targets.candidates,
                    Some(shared_punch_at_ms),
                    "peer_reflexive_receiver",
                )
                .await;
            } else {
                self.peers
                    .record_direct_event(
                        peer_id,
                        "peer_reflexive_micro_window_skipped",
                        None,
                        None,
                        None,
                        "receiver could not join shared peer-reflexive micro-window because UDP transport or trusted remote targets were unavailable",
                    )
                    .await;
            }
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

    /// Handle one admitted responder offer with a bounded, idempotent retry.
    ///
    /// The control signal receiver acknowledges after local enqueue, so a
    /// transient failure after dequeue must be repaired by the worker itself.
    /// `handle_event_peer_offer` uses the exact responder cache keyed by the
    /// WireGuard token, therefore retrying the same plaintext offer cannot
    /// create a second response or a second session.  No encrypted data
    /// packet is retained here; this is control-plane handshake material only.
    async fn handle_admitted_responder_offer(
        &self,
        offer: &PendingPeerOffer,
        owner: u64,
        cancellation: &mut tokio::sync::watch::Receiver<bool>,
    ) {
        let peer_id = offer.from_node_id.clone();
        for retry_attempt in 0..=RESPONDER_WORK_RETRY_LIMIT {
            if *cancellation.borrow() {
                debug!(
                    "Peer offer responder worker cancelled before handling: peer={} owner={}",
                    peer_id, owner
                );
                self.peers
                    .record_direct_event(
                        &peer_id,
                        "peer_offer_responder_worker_cancelled",
                        None,
                        None,
                        None,
                        format!("owner={} cancelled before handler", owner),
                    )
                    .await;
                self.timeline.emit(
                    "peer_offer_responder_worker_cancelled",
                    None,
                    Some("generation_cancelled"),
                    Some(format!("peer={} owner={} before_handler=true", peer_id, owner)),
                );
                return;
            }
            self.peers
                .record_direct_event(
                    &peer_id,
                    "peer_offer_responder_handler_entered",
                    None,
                    None,
                    None,
                    format!(
                        "owner={} retry_attempt={} generation={} session_fp={}",
                        owner,
                        retry_attempt,
                        offer.network_generation,
                        handshake_token_fingerprint(offer.session_id.as_deref())
                    ),
                )
                .await;
            debug!(
                "Peer offer responder handler entered: peer={} owner={} retry_attempt={}",
                peer_id, owner, retry_attempt
            );
            self.timeline.emit(
                "peer_offer_responder_handler_entered",
                None,
                None,
                Some(format!(
                    "peer={} owner={} retry_attempt={} generation={} session_fp={}",
                    peer_id,
                    owner,
                    retry_attempt,
                    offer.network_generation,
                    handshake_token_fingerprint(offer.session_id.as_deref())
                )),
            );
            match self
                .handle_event_peer_offer(offer.clone(), owner, cancellation)
                .await
            {
                Ok(()) if *cancellation.borrow() => {
                    self.timeline.emit(
                        "peer_offer_responder_worker_cancelled",
                        None,
                        Some("generation_cancelled"),
                        Some(format!("peer={} owner={} after_handler=true", peer_id, owner)),
                    );
                    return;
                }
                Ok(()) => {
                    debug!(
                        "Peer offer responder handler completed: peer={} owner={}",
                        peer_id, owner
                    );
                    self.peers
                        .record_direct_event(
                            &peer_id,
                            "peer_offer_responder_handler_completed",
                            None,
                            None,
                            None,
                            format!(
                                "owner={} retry_attempt={} generation={} session_fp={}",
                                owner,
                                retry_attempt,
                                offer.network_generation,
                                handshake_token_fingerprint(offer.session_id.as_deref())
                            ),
                        )
                        .await;
                    self.timeline.emit(
                        "peer_offer_responder_handler_completed",
                        None,
                        None,
                        Some(format!(
                            "peer={} owner={} retry_attempt={} generation={} session_fp={}",
                            peer_id,
                            owner,
                            retry_attempt,
                            offer.network_generation,
                            handshake_token_fingerprint(offer.session_id.as_deref())
                        )),
                    );
                    return;
                }
                Err(err)
                    if responder_offer_error_is_retryable(&err)
                        && retry_attempt < RESPONDER_WORK_RETRY_LIMIT =>
                {
                    let next_attempt = retry_attempt.saturating_add(1);
                    let delay = responder_offer_retry_delay(next_attempt);
                    let reason_code = responder_offer_error_reason_code(&err);
                    warn!(
                        "Peer offer responder failed transiently: peer={} owner={} retry_attempt={} delay_ms={} reason_code={} error={}",
                        peer_id,
                        owner,
                        next_attempt,
                        delay.as_millis(),
                        reason_code,
                        err
                    );
                    self.peers
                        .record_direct_event(
                            &peer_id,
                            "peer_offer_responder_retry",
                            None,
                            None,
                            None,
                            format!(
                                "owner={} retry_attempt={} delay_ms={} reason_code={reason_code}",
                                owner,
                                next_attempt,
                                delay.as_millis()
                            ),
                        )
                        .await;
                    self.timeline.emit(
                        "peer_offer_responder_retry",
                        None,
                        Some(reason_code),
                        Some(format!(
                            "peer={} owner={} retry_attempt={} delay_ms={}",
                            peer_id,
                            owner,
                            next_attempt,
                            delay.as_millis()
                        )),
                    );
                    tokio::select! {
                        _ = sleep(delay) => {}
                        changed = cancellation.changed() => {
                            if changed.is_err() || *cancellation.borrow() {
                                return;
                            }
                        }
                    }
                }
                Err(err) => {
                    warn!(
                        "Failed to handle peer offer from {} owner={} reason_code=responder_terminal_error retry_attempt={} error={}",
                        peer_id, owner, retry_attempt, err
                    );
                    self.peers
                        .record_direct_event(
                            &peer_id,
                            "peer_offer_responder_failed",
                            None,
                            None,
                            None,
                            format!(
                                "owner={} reason_code=responder_terminal_error retry_attempt={}",
                                owner, retry_attempt
                            ),
                        )
                        .await;
                    self.timeline.emit(
                        "peer_offer_responder_failed",
                        None,
                        Some("responder_terminal_error"),
                        Some(format!("peer={} owner={} retry_attempt={retry_attempt}", peer_id, owner)),
                    );
                    return;
                }
            }
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
            // PeerJoined. Consume the newest one before any candidate or
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
            self.reset_peer_for_remote_incarnation_if_needed(
                &offer.from_node_id,
                offer.candidate_generation,
            )
            .await;
            // The peer is now registered. Answer the encrypted initiation
            // before candidate/fresh-prediction work, for the same reason as
            // the normal known-peer path: a delayed candidate plane must not
            // turn a delivered control signal into a silent handshake gap.
            if !offer.handshake_init.is_empty() {
                self.handle_admitted_responder_offer(
                    &offer,
                    reservation.owner,
                    &mut reservation.cancellation,
                )
                .await;
            }
            if *reservation.cancellation.borrow() {
                return;
            }
            // The offer-ingress verdict runs before any candidate-plane
            // state: duplicates and rate-limited retransmissions never apply
            // candidates, never run a fresh transaction and never trigger a
            // punch — the handshake part below is still answered.
            let (_fresh_verdict, candidate_apply_result, fresh_punch) = if offer.ingress_suppressed
            {
                (
                    FreshSignalVerdict::None,
                    CandidateSetApplyResult::IgnoredStale,
                    FreshPunchDecision::None,
                )
            } else if self
                .offer_ingress_verdict(
                    &offer.from_node_id,
                    &offer.candidates,
                    &offer.candidate_sources,
                    offer.candidates_expires_at_ms,
                    offer.sender_public_key.as_deref(),
                )
                .await
                == OfferIngressVerdict::Apply
            {
                self.fresh_prediction_transaction(
                    &offer.from_node_id,
                    &offer.candidates,
                    &offer.candidate_sources,
                    offer.candidate_generation,
                    offer.candidates_expires_at_ms,
                    offer.sender_public_key.as_deref(),
                )
                .await
            } else {
                self.peers
                    .record_direct_event(
                        &offer.from_node_id,
                        "peer_offer_ingress_suppressed",
                        None,
                        Some(offer.candidates.len()),
                        None,
                        "offer suppressed by ingress verdict; candidate apply, fresh prediction and punch skipped; handshake still handled",
                    )
                    .await;
                (
                    FreshSignalVerdict::None,
                    CandidateSetApplyResult::IgnoredStale,
                    FreshPunchDecision::None,
                )
            };
            self.apply_deferred_peer_offer_punch(
                &offer,
                candidate_apply_result,
                fresh_punch,
            )
            .await;

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
            .fresh_candidates
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

    /// Admit queued event-triggered initiator work after a cooperative
    /// slow-work slot becomes available.
    ///
    /// A roster burst must not silently lose the initiator handshake for peers
    /// after the global slow-work cap. This drain is newest-wins per peer,
    /// checks the current online state before starting, and leaves the
    /// per-peer reservation as the single-flight boundary for duplicates.
    async fn drain_deferred_initiator_handshakes<'a>(
        &'a self,
        slow_work: &mut FuturesUnordered<ControlEventWork<'a>>,
        deferred: &mut InitiatorQueue<control::PeerInfo>,
    ) {
        // A reservation can be temporarily unavailable because this peer's
        // current handshake owner is still running.  Scan each queued peer at
        // most once per drain pass: keep blocked entries newest-wins while
        // still admitting unrelated peers behind them.  A later completion
        // pass will retry the preserved entry after the owner releases it.
        let initial_queue_len = deferred.len();
        let mut scanned = 0usize;
        while slow_work.len() < MAX_CONTROL_EVENT_SLOW_WORK && scanned < initial_queue_len {
            let Some(peer_info) = deferred.pop_front() else {
                break;
            };
            scanned = scanned.saturating_add(1);
            let peer_id = peer_info.node_id.clone();
            let current_online = self
                .peers
                .get_connection(&peer_id)
                .await
                .is_some_and(|peer| peer.online);
            if !current_online {
                self.peers
                    .record_direct_event(
                        &peer_id,
                        "initiator_handshake_deferred_dropped",
                        None,
                        None,
                        None,
                        "reason_code=peer_offline_or_removed deferred control handshake was not started",
                    )
                    .await;
                self.timeline.emit(
                    "initiator_handshake_deferred_dropped",
                    None,
                    Some("peer_offline_or_removed"),
                    Some(format!("peer={peer_id}")),
                );
                continue;
            }

            if !self.should_start_initiator_handshake(&peer_info) {
                continue;
            }

            let Some(reservation) = self.reserve_event_initiator_handshake(&peer_id).await else {
                // An existing pending handshake or starting worker owns this
                // peer. Keep the newest roster update for the next completion
                // pass; dropping it here would make endpoint/incarnation
                // changes wait for an unrelated future control poll.
                let _ = enqueue_deferred_initiator_handshake(deferred, peer_info);
                continue;
            };
            self.timeline.emit(
                "initiator_handshake_deferred_admitted",
                None,
                None,
                Some(format!(
                    "peer={peer_id} queue_remaining={}",
                    deferred.len()
                )),
            );
            let daemon = self;
            slow_work.push(Box::pin(async move {
                daemon
                    .run_event_initiator_handshake(peer_info, reservation)
                    .await;
            }));
        }
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
        let mut deferred_initiators: InitiatorQueue<control::PeerInfo> = InitiatorQueue::new();
        // Keep responder answers out of the general slow-work budget. A
        // blocked candidate refresh or peer-reflexive HTTP task must not
        // prevent a received WireGuard initiation from producing an answer.
        let mut responder_work: FuturesUnordered<ControlEventWork<'_>> =
            FuturesUnordered::new();
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
                    // Completion frees a bounded slot. Admit the oldest still
                    // live deferred peer immediately instead of waiting for a
                    // later control poll.
                    daemon
                        .drain_deferred_initiator_handshakes(
                            &mut slow_work,
                            &mut deferred_initiators,
                        )
                        .await;
                }
                _ = responder_work.next(), if !responder_work.is_empty() => {
                    // Responder workers own their per-peer pending state and
                    // release it on every terminal/cancellation path.
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
                            self.peers.configure_relay_first(false).await;
                            debug!("No relay servers advertised by control plane");
                            continue;
                        }
                        self.peers.configure_relay_first(true).await;
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
            relay_available_tx: self.relay_available_tx.clone(),
            timeline: self.timeline.clone(),
            inbound_tx: network_inbound_tx.clone(),
            control: self.control.clone(),
            allow_insecure_plaintext,
            ca_cert_path: self.config.relay.ca_cert_path.clone(),
        })
        .await;
                    }
                }

                ControlEvent::PeerJoined(peer_info) => {
                    let peer_join_started = std::time::Instant::now();
                    info!(
                        "Peer joined: {} ({})",
                        peer_info.node_id, peer_info.virtual_ip
                    );
                    self.timeline.emit_first(
                        "peer_roster_ready",
                        None,
                        None,
                        Some(format!(
                            "peer={} virtual_ip={} online={}",
                            peer_info.node_id, peer_info.virtual_ip, peer_info.online
                        )),
                    );
                    self.peers.add_peer(&peer_info).await;
                    let peer_state_elapsed = peer_join_started.elapsed();
                    if peer_state_elapsed >= Duration::from_millis(250) {
                        warn!(
                            "PeerJoined state install was slow: peer={} elapsed_ms={}",
                            peer_info.node_id,
                            peer_state_elapsed.as_millis()
                        );
                    } else {
                        debug!(
                            "PeerJoined state installed: peer={} elapsed_ms={}",
                            peer_info.node_id,
                            peer_state_elapsed.as_millis()
                        );
                    }

                    if peer_info.online {
                        // `peer_roster_ready` is a process-level control-plane
                        // milestone and is intentionally not a usable-path
                        // clock.  Start the per-peer data-plane clock only
                        // after the peer has been installed locally, and bind
                        // it to the current network generation.  This keeps
                        // relay-first measurements from charging relay setup
                        // for time spent waiting for a later roster poll.
                        let session_generation = self.peers.current_network_generation().await;
                        let session_scope = format!(
                            "peer:{}:{session_generation}",
                            peer_info.node_id
                        );
                        self.timeline.emit_first_scoped(
                            &session_scope,
                            "peer_session_started",
                            None,
                            None,
                            Some(format!(
                                "peer={} generation={} virtual_ip={} online=true",
                                peer_info.node_id, session_generation, peer_info.virtual_ip
                            )),
                        );
                        let should_start_initiator =
                            self.should_start_initiator_handshake(&peer_info);
                        if should_start_initiator
                            && slow_work.len() >= MAX_CONTROL_EVENT_SLOW_WORK
                        {
                            let queued = enqueue_deferred_initiator_handshake(
                                &mut deferred_initiators,
                                peer_info.clone(),
                            );
                            let reason_code = if queued {
                                "control_slow_work_full_queued"
                            } else {
                                "control_slow_work_deferred_queue_full"
                            };
                            warn!(
                                "Deferring peer-join handshake for {}: reason_code={} slow_work={} deferred_queue={}",
                                peer_info.node_id,
                                reason_code,
                                slow_work.len(),
                                deferred_initiators.len(),
                            );
                            self.peers
                                .record_direct_event(
                                    &peer_info.node_id,
                                    "initiator_handshake_deferred",
                                    None,
                                    None,
                                    None,
                                    format!(
                                        "reason_code={reason_code} slow_work={} deferred_queue={}",
                                        slow_work.len(),
                                        deferred_initiators.len()
                                    ),
                                )
                                .await;
                            self.timeline.emit(
                                "initiator_handshake_deferred",
                                None,
                                Some(reason_code),
                                Some(format!(
                                    "peer={} slow_work={} deferred_queue={}",
                                    peer_info.node_id,
                                    slow_work.len(),
                                    deferred_initiators.len()
                                )),
                            );
                        } else if should_start_initiator {
                            if let Some(reservation) = self
                                .reserve_event_initiator_handshake(&peer_info.node_id)
                                .await
                            {
                                debug!(
                                    "PeerJoined handshake reserved: peer={} elapsed_ms={}",
                                    peer_info.node_id,
                                    peer_join_started.elapsed().as_millis()
                                );
                                let peer_info = peer_info.clone();
                                slow_work.push(Box::pin(async move {
                                    daemon
                                        .run_event_initiator_handshake(peer_info, reservation)
                                        .await;
                                }));
                            }
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
                        debug!(
                            "PeerJoined event complete: peer={} elapsed_ms={}",
                            peer_info.node_id,
                            peer_join_started.elapsed().as_millis()
                        );
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
                        remove_deferred_initiator_handshake(
                            &mut deferred_initiators,
                            &peer_info.node_id,
                        );
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
                        self.peers
                            .clear_fresh_mapping(&peer_info.node_id, "peer_offline")
                            .await;
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
                        remove_deferred_initiator_handshake(
                            &mut deferred_initiators,
                            &peer_info.node_id,
                        );
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
                        // Endpoint metadata changes are normal NAT/candidate
                        // churn.  They must not tear down a confirmed relay or
                        // WireGuard session. A same-node restart is reset only
                        // when a later peer offer carries a different encoded
                        // candidate-generation incarnation.
                        self.punch_attempts.cancel(&peer_info.node_id);
                        if let Some(udp) = self.udp_transport.read().await.clone() {
                            udp.clear_pending_probes_for_peer(&peer_info.node_id).await;
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
                    let should_start_initiator =
                        self.should_start_initiator_handshake(&peer_info);
                    if should_start_initiator
                        && slow_work.len() >= MAX_CONTROL_EVENT_SLOW_WORK
                    {
                        let queued = enqueue_deferred_initiator_handshake(
                            &mut deferred_initiators,
                            peer_info.clone(),
                        );
                        let reason_code = if queued {
                            "control_slow_work_full_queued"
                        } else {
                            "control_slow_work_deferred_queue_full"
                        };
                        warn!(
                            "Deferring peer-update handshake for {}: reason_code={} slow_work={} deferred_queue={}",
                            peer_info.node_id,
                            reason_code,
                            slow_work.len(),
                            deferred_initiators.len(),
                        );
                        self.peers
                            .record_direct_event(
                                &peer_info.node_id,
                                "initiator_handshake_deferred",
                                None,
                                None,
                                None,
                                format!(
                                    "reason_code={reason_code} slow_work={} deferred_queue={}",
                                    slow_work.len(),
                                    deferred_initiators.len()
                                ),
                            )
                            .await;
                        self.timeline.emit(
                            "initiator_handshake_deferred",
                            None,
                            Some(reason_code),
                            Some(format!(
                                "peer={} slow_work={} deferred_queue={}",
                                peer_info.node_id,
                                slow_work.len(),
                                deferred_initiators.len()
                            )),
                        );
                    } else if should_start_initiator {
                        if let Some(reservation) = self
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
                }

                ControlEvent::PeerLeft(node_id) => {
                    info!("Peer left: {}", node_id);
                    remove_deferred_initiator_handshake(&mut deferred_initiators, &node_id);
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
                    let network_generation = self.peers.current_network_generation_sync();
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
                    self.timeline.emit(
                        "peer_offer_received",
                        None,
                        None,
                        Some(format!(
                            "peer={} candidate_generation={} handshake_bytes={} candidates={}",
                            from_node_id,
                            candidate_generation,
                            handshake_init.len(),
                            candidates.len()
                        )),
                    );
                    // Signal delivery can race the peer-list poll: an offer
                    // may be received before PeerJoined has installed the
                    // sender's static public key.  Do not run candidate
                    // admission or consume the responder transaction in that
                    // state.  Enqueue the complete newest offer under the
                    // existing per-peer owner and replay it once registration
                    // becomes visible.
                    if !self.peers.peer_exists_sync(&from_node_id) {
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
                            state.enqueue_responder_work(PendingPeerOffer {
                                from_node_id: from_node_id.clone(),
                                candidates: candidates.clone(),
                                candidate_sources: candidate_sources.clone(),
                                candidate_generation,
                                network_generation,
                                candidates_expires_at_ms,
                                sender_public_key: sender_public_key.clone(),
                                handshake_init: handshake_init.clone(),
                                punch_at_ms,
                                punch_at_server_ms,
                                session_id: session_id.clone(),
                                probe_ephemeral_public_key: probe_ephemeral_public_key.clone(),
                                ingress_suppressed: false,
                            })
                        };
                        if let Some((reservation, offer)) = admitted {
                            self.timeline.emit(
                                "peer_offer_responder_work_admitted",
                                None,
                                None,
                                Some(format!(
                                    "peer={} owner={} network_generation={} candidate_generation={} session_fp={} deferred_unknown=true",
                                    from_node_id,
                                    reservation.owner,
                                    network_generation,
                                    candidate_generation,
                                    handshake_token_fingerprint(session_id.as_deref())
                                )),
                            );
                            responder_work.push(Box::pin(async move {
                                daemon
                                    .run_deferred_peer_offer_worker(offer, reservation)
                                    .await;
                            }));
                        } else {
                            self.timeline.emit(
                                "peer_offer_responder_work_coalesced",
                                None,
                                Some("newest_wins_coalesced"),
                                Some(format!(
                                    "peer={} network_generation={} candidate_generation={} session_fp={} deferred_unknown=true queued=true",
                                    from_node_id,
                                    network_generation,
                                    candidate_generation,
                                    handshake_token_fingerprint(session_id.as_deref())
                                )),
                            );
                        }
                        continue;
                    }
                    // Candidate-only offers have no latency-critical
                    // WireGuard response to stage.  They still carry remote
                    // candidate state and may need to wait behind the shared
                    // epoch/UDP validation locks, so run them through the
                    // existing per-peer newest-wins responder lane instead of
                    // blocking the serial control receiver.  A later offer
                    // for the same peer is coalesced by the same owner.
                    if handshake_init.is_empty() {
                        let admitted = {
                            let mut state = self.pending_handshakes.lock().await;
                            state.enqueue_responder_work(PendingPeerOffer {
                                from_node_id: from_node_id.clone(),
                                candidates: candidates.clone(),
                                candidate_sources: candidate_sources.clone(),
                                candidate_generation,
                                network_generation,
                                candidates_expires_at_ms,
                                sender_public_key: sender_public_key.clone(),
                                handshake_init: Vec::new(),
                                punch_at_ms,
                                punch_at_server_ms,
                                session_id: session_id.clone(),
                                probe_ephemeral_public_key: probe_ephemeral_public_key.clone(),
                                ingress_suppressed: false,
                            })
                        };
                        if let Some((reservation, offer)) = admitted {
                            self.timeline.emit(
                                "peer_offer_candidate_work_admitted",
                                None,
                                None,
                                Some(format!(
                                    "peer={} owner={} network_generation={} candidate_generation={} candidates={}",
                                    from_node_id,
                                    reservation.owner,
                                    network_generation,
                                    candidate_generation,
                                    candidates.len()
                                )),
                            );
                            responder_work.push(Box::pin(async move {
                                daemon
                                    .run_deferred_peer_offer_worker(offer, reservation)
                                    .await;
                            }));
                        } else {
                            self.timeline.emit(
                                "peer_offer_candidate_work_coalesced",
                                None,
                                Some("newest_wins_coalesced"),
                                Some(format!(
                                    "peer={} network_generation={} candidate_generation={} candidates={}",
                                    from_node_id,
                                    network_generation,
                                    candidate_generation,
                                    candidates.len()
                                )),
                            );
                        }
                        continue;
                    }

                    self.reset_peer_for_remote_incarnation_if_needed(
                        &from_node_id,
                        candidate_generation,
                    )
                    .await;
                    // Admit the latency-critical responder before touching
                    // candidate/fresh-prediction state.  A candidate refresh
                    // may wait on STUN/HTTP or the general slow-work budget;
                    // an already-delivered WireGuard initiation must not be
                    // acknowledged locally and then wait behind that work.
                    if !handshake_init.is_empty() {
                        let admitted = {
                            let mut state = self.pending_handshakes.lock().await;
                            state.enqueue_responder_work(PendingPeerOffer {
                                from_node_id: from_node_id.clone(),
                                candidates: candidates.clone(),
                                candidate_sources: candidate_sources.clone(),
                                candidate_generation,
                                network_generation,
                                candidates_expires_at_ms,
                                sender_public_key: sender_public_key.clone(),
                                handshake_init: handshake_init.clone(),
                                punch_at_ms,
                                punch_at_server_ms,
                                session_id: session_id.clone(),
                                probe_ephemeral_public_key: probe_ephemeral_public_key.clone(),
                                ingress_suppressed: false,
                            })
                        };
                        if let Some((reservation, offer)) = admitted {
                            self.peers
                                .record_direct_event(
                                    &from_node_id,
                                    "peer_offer_responder_work_admitted",
                                    None,
                                    Some(candidates.len()),
                                    None,
                                    format!(
                                        "responder owner={} generation={} session_fp={} admitted before candidate-plane work",
                                        reservation.owner,
                                        offer.network_generation,
                                        handshake_token_fingerprint(offer.session_id.as_deref())
                                    ),
                                )
                                .await;
                            debug!(
                                "Peer offer responder worker admitted: peer={} owner={} candidates={}",
                                from_node_id,
                                reservation.owner,
                                candidates.len()
                            );
                            daemon.timeline.emit(
                                    "peer_offer_responder_work_admitted",
                                None,
                                None,
                                    Some(format!(
                                    "peer={} owner={} network_generation={} candidate_generation={} session_fp={} deferred_unknown=false",
                                    from_node_id,
                                    reservation.owner,
                                    network_generation,
                                    candidate_generation,
                                    handshake_token_fingerprint(session_id.as_deref())
                                )),
                            );
                            responder_work.push(Box::pin(async move {
                                let mut offer = offer;
                                let mut reservation = reservation;
                                loop {
                                    let peer_id = offer.from_node_id.clone();
                                    daemon
                                        .handle_admitted_responder_offer(
                                            &offer,
                                            reservation.owner,
                                            &mut reservation.cancellation,
                                        )
                                        .await;
                                    if *reservation.cancellation.borrow() {
                                        return;
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
                        } else {
                            self.peers
                                .record_direct_event(
                                    &from_node_id,
                                    "peer_offer_responder_work_coalesced",
                                    None,
                                    Some(candidates.len()),
                                    None,
                                    "newest responder offer replaced the per-peer queued offer",
                                )
                                .await;
                            debug!(
                                "Peer offer responder work coalesced: peer={} candidates={}",
                                from_node_id,
                                candidates.len()
                            );
                            self.timeline.emit(
                                "peer_offer_responder_work_coalesced",
                                None,
                                Some("newest_wins_coalesced"),
                                Some(format!(
                                    "peer={} network_generation={} candidate_generation={} session_fp={} queued=true",
                                    from_node_id,
                                    network_generation,
                                    candidate_generation,
                                    handshake_token_fingerprint(session_id.as_deref())
                                )),
                            );
                        }
                    }
                    // Fresh-prediction verification happens BEFORE any
                    // candidate state is touched: a superseded prediction
                    // must not pollute the candidate set, while the handshake
                    // itself is still handled below.  The prepare/apply/commit
                    // transaction is shared with the answer path.
                    //
                    // The offer-ingress verdict runs even earlier: a duplicate
                    // or rate-limited offer never touches the candidate plane
                    // at all (no candidate apply, no fresh transaction, no
                    // punch), while its handshake part is still answered.
                    let ingress = self
                        .offer_ingress_verdict(
                            &from_node_id,
                            &candidates,
                            &candidate_sources,
                            candidates_expires_at_ms,
                            sender_public_key.as_deref(),
                        )
                        .await;
                    let (_fresh_verdict, candidate_apply_result, fresh_punch) = if ingress
                        == OfferIngressVerdict::Apply
                    {
                        self.fresh_prediction_transaction(
                            &from_node_id,
                            &candidates,
                            &candidate_sources,
                            candidate_generation,
                            candidates_expires_at_ms,
                            sender_public_key.as_deref(),
                        )
                        .await
                    } else {
                        self.peers
                            .record_direct_event(
                                &from_node_id,
                                "peer_offer_ingress_suppressed",
                                None,
                                Some(candidates.len()),
                                None,
                                format!(
                                    "offer suppressed by ingress verdict={ingress:?}; candidate apply, fresh prediction and punch skipped; handshake_bytes={}",
                                    handshake_init.len()
                                ),
                            )
                            .await;
                        (
                            FreshSignalVerdict::None,
                            CandidateSetApplyResult::IgnoredStale,
                            FreshPunchDecision::None,
                        )
                    };
                    let hard_hard_handling = self
                        .handle_hard_hard_fresh_offer(
                            &from_node_id,
                            session_id.as_deref(),
                            punch_at_ms,
                            fresh_punch.clone(),
                        )
                        .await;
                    if candidate_apply_result == CandidateSetApplyResult::Applied
                        && hard_hard_handling != HardHardOfferHandling::Started
                    {
                        self.peers
                            .clear_hard_hard_sessions(Some(&from_node_id))
                            .await;
                    }
                    if hard_hard_handling != HardHardOfferHandling::NotHardHard {
                        continue;
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
                    if !self.peers.peer_exists_sync(&from_node_id) {
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
                    // Consume the WireGuard answer before candidate refresh or
                    // fresh-mapping work. Those paths may perform HTTP/STUN
                    // I/O and must remain a background upgrade; delaying the
                    // answer here leaves the responder staged but prevents
                    // the initiator from ever publishing its active session.
                    if !handshake_response.is_empty() {
                        self.peers
                            .record_direct_event(
                                &from_node_id,
                                "peer_answer_dispatch_started",
                                None,
                                Some(candidates.len()),
                                None,
                                format!(
                                    "dispatching handshake response before candidate/fresh work bytes={} session_fp={}",
                                    handshake_response.len(),
                                    handshake_token_fingerprint(session_id.as_deref())
                                ),
                            )
                            .await;
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
                    // Fresh-prediction verification happens after the
                    // handshake transaction and before candidate state is
                    // used for background punching (see the offer path).
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
                    if !self.peers.peer_exists_sync(&from_node_id) {
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
        drop(responder_work);
        self.control_rx = control_rx;
    }
}
