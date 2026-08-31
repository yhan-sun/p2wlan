#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct ResponderHandshakeLifecycle {
    network_generation: u64,
    peer_session_generation: PeerSessionGeneration,
}

#[derive(Clone)]
struct CachedResponderHandshake {
    /// Exact local lifecycle which authenticated and prepared this response.
    /// A token replay after a network handover or same-node leave/rejoin must
    /// not reuse receive keys from the retired responder transaction.
    lifecycle: ResponderHandshakeLifecycle,
    handshake_init: Vec<u8>,
    /// Static Noise/WireGuard public key authenticated by this initiation.
    /// Cache replay is valid only while the node ID still maps to this key.
    initiator_static_public_key: [u8; 32],
    /// Canonicalized Probe-v2 public key from the request. This is part of the
    /// offer fingerprint: the same WireGuard initiation and token must not
    /// replay an answer derived from different Probe key material.
    request_probe_ephemeral_public_key: Option<String>,
    response_bytes: Vec<u8>,
    transport_keys: TransportKeyPair,
    response_probe_ephemeral_public_key: Option<String>,
    probe_ephemeral_shared: Option<[u8; 32]>,
    expires_at: Instant,
}

enum ResponderHandshakeCacheLookup {
    Miss,
    Hit(Box<CachedResponderHandshake>),
    FingerprintMismatch,
    StaleLifecycle,
}

/// A peer offer admitted to the single responder worker for that peer.
///
/// Candidate admission may run after this value has been queued.  The
/// responder worker owns the latency-critical WireGuard response and must not
/// wait behind candidate refresh or fresh-generation work.  When another
/// offer arrives while the worker is active, the newest value replaces the
/// one queued here.
#[derive(Clone)]
struct PendingPeerOffer {
    from_node_id: String,
    candidates: Vec<String>,
    candidate_sources: HashMap<String, String>,
    candidate_generation: u64,
    /// Local generation at signal ingress.  The offer may wait in the
    /// per-peer responder worker while the control-plane answer is sent; a
    /// local handover during that wait makes the old offer terminal.
    network_generation: u64,
    /// Exact online peer lifecycle present when the signal was admitted.
    /// Unknown-peer offers fill this after identity restoration. A queued
    /// offer must match this generation at responder commit.
    peer_session_generation: Option<PeerSessionGeneration>,
    candidates_expires_at_ms: Option<u64>,
    sender_public_key: Option<String>,
    handshake_init: Vec<u8>,
    punch_at_ms: Option<u64>,
    punch_at_server_ms: Option<u64>,
    session_id: Option<String>,
    probe_ephemeral_public_key: Option<String>,
    /// Durable REST delivery is acknowledged only when this exact offer reaches
    /// a terminal responder result. Coalesced offers retain their own receipt.
    delivery_receipt: Option<control::SignalDeliveryReceipt>,
}

impl PendingPeerOffer {
    fn complete_delivery(&self, outcome: control::SignalApplyOutcome) {
        if let Some(receipt) = self.delivery_receipt.as_ref() {
            receipt.complete(outcome);
        }
    }
}

/// A peer-reflexive control-plane observation awaiting its bounded worker.
///
/// Candidate mutation can wait behind a live STUN refresh, and the optional
/// re-advertisement performs HTTP I/O. The serial control receiver therefore
/// owns only admission; one worker per peer consumes the newest endpoint.
struct PendingPeerReflexive {
    from_node_id: String,
    observed_endpoint: String,
    punch_at_ms: Option<u64>,
    peer_session_generation: Option<PeerSessionGeneration>,
    delivery_receipt: Option<control::SignalDeliveryReceipt>,
}

impl PendingPeerReflexive {
    fn complete_delivery(&self, outcome: control::SignalApplyOutcome) {
        if let Some(receipt) = self.delivery_receipt.as_ref() {
            receipt.complete(outcome);
        }
    }
}

/// Owner token for an event-triggered initiator preparation.
///
/// `starting` used to be only a peer-id set.  A late task from a peer's old
/// incarnation could then clear a newer reservation after `PeerLeft`/rejoin.
/// The token and cancellation receiver make the reservation linearizable with
/// lifecycle cleanup.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum HandshakeStartDisposition {
    Active,
    RetryScheduled,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum InitiatorRetryPhase {
    Preparation,
    Publish,
}

impl InitiatorRetryPhase {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Preparation => "preparation",
            Self::Publish => "publish",
        }
    }
}

struct HandshakeStartReservation {
    owner: u64,
    owner_kind: HandshakeOwnerKind,
    network_generation: u64,
    peer_session_generation: PeerSessionGeneration,
    cancellation_generation: u64,
    cancellation: tokio::sync::watch::Receiver<bool>,
    disposition: HandshakeStartDisposition,
    /// Retry lineage survives a claim/remove cycle so repeated contention
    /// cannot reset backoff or extend the phase TTL indefinitely.
    retry_phase: Option<InitiatorRetryPhase>,
    retry_attempt: u32,
    retry_expires_at: Option<Instant>,
    /// Exact old-generation Probe binding removed from pending-handshake
    /// state by admission. The bounded worker, never the serial coordinator,
    /// performs the actor cleanup before preparing the replacement.
    stale_session_id: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct HandshakeRetryIdentity {
    peer_id: String,
    network_generation: u64,
    peer_session_generation: PeerSessionGeneration,
    reservation_owner: u64,
    phase: InitiatorRetryPhase,
    attempt: u32,
    cancellation_generation: u64,
}

struct PendingInitiatorRetry {
    identity: HandshakeRetryIdentity,
    not_before: Instant,
    expires_at: Instant,
}

struct PreparedInitiatorHandshake {
    initiator: HandshakeInitiator,
    initiation_bytes: Vec<u8>,
    candidates: Vec<String>,
    candidate_sources: HashMap<String, String>,
    session_id: String,
    probe_ephemeral: DhKeyPair,
    probe_ephemeral_public_key: String,
}

const MAX_PENDING_INITIATOR_RETRIES: usize = 1024;
const INITIATOR_RETRY_TTL: Duration = Duration::from_secs(30);
const INITIATOR_RETRY_BACKOFF: [Duration; 7] = [
    Duration::ZERO,
    Duration::from_millis(10),
    Duration::from_millis(25),
    Duration::from_millis(50),
    Duration::from_millis(100),
    Duration::from_millis(250),
    Duration::from_millis(500),
];

/// Owner token for the one responder worker admitted for a peer.
struct ResponderWorkReservation {
    owner: u64,
    cancellation: tokio::sync::watch::Receiver<bool>,
}

struct ResponderWorkOwner {
    owner: u64,
    cancellation: tokio::sync::watch::Sender<bool>,
    /// Sender identity of the offer currently owned by the worker. Keeping it
    /// beside the queued slot prevents a late retransmit from the active
    /// (retired) identity from overwriting a queued offer from a replacement
    /// identity before either can be checked against the peer roster.
    active_sender_public_key: Option<String>,
    queued: Option<PendingPeerOffer>,
}

fn same_responder_sender_identity(left: Option<&str>, right: Option<&str>) -> bool {
    match (left, right) {
        (None, None) => true,
        (Some(left), Some(right)) => left.trim() == right.trim(),
        _ => false,
    }
}

/// Owner token for one independently polled candidate-offer worker.
///
/// Candidate application may wait on the network epoch, the connection map,
/// STUN or UDP actors.  It therefore has a separate owner from the responder
/// transaction: a candidate-only signal can never occupy the peer's
/// latency-critical WireGuard responder slot.
struct CandidateOfferWorkReservation {
    owner: u64,
    cancellation: tokio::sync::watch::Receiver<bool>,
}

struct CandidateOfferWorkOwner {
    owner: u64,
    cancellation: tokio::sync::watch::Sender<bool>,
    active_sender_public_key: Option<String>,
    queued: Option<PendingPeerOffer>,
}

enum CandidateOfferWorkAdmission {
    Started(CandidateOfferWorkReservation, Box<PendingPeerOffer>),
    Coalesced,
    RejectedIdentity,
    Capacity,
}

/// A corrupt or hostile control stream must not turn the per-peer candidate
/// ledger into an unbounded process allocation.  The active value plus one
/// newest-wins queued value per admitted peer are the complete retained set.
const MAX_CANDIDATE_OFFER_WORKERS: usize = 1024;

/// Owner token for the one peer-reflexive worker admitted for a peer.
struct PeerReflexiveWorkReservation {
    owner: u64,
    cancellation: tokio::sync::watch::Receiver<bool>,
}

struct PeerReflexiveWorkOwner {
    owner: u64,
    cancellation: tokio::sync::watch::Sender<bool>,
    queued: Option<PendingPeerReflexive>,
}

fn normalize_probe_ephemeral_public_key(value: Option<&str>) -> Option<String> {
    value
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_ascii_lowercase)
}

/// Shared pending-handshake state (timeout-safe).
#[derive(Default)]
struct PendingHandshakeState {
    pending: HashMap<String, HandshakeInitiator>,
    pending_session_ids: HashMap<String, String>,
    /// Local network generation captured when the initiator transaction was
    /// published.  A session answer is useful only for the generation that
    /// created its initiation; without this binding a late answer can arrive
    /// after a network handover and install old key material as if it were a
    /// fresh session.
    pending_network_generations: HashMap<String, u64>,
    pending_peer_session_generations: HashMap<String, PeerSessionGeneration>,
    pending_probe_ephemeral: HashMap<String, DhKeyPair>,
    /// Peers for which a handshake is being prepared.  Candidate gathering and
    /// control-peer lookups await, so a plain `pending` check is not enough to
    /// prevent another trigger from creating and overwriting an initiator in
    /// that window.
    starting: HashSet<String>,
    /// Local network generation captured when an initiator preparation was
    /// reserved. A reservation that survived a network handover is cancelled
    /// before a new-generation attempt is admitted.
    starting_network_generations: HashMap<String, u64>,
    starting_peer_session_generations: HashMap<String, PeerSessionGeneration>,
    starting_owner_kinds: HashMap<String, HandshakeOwnerKind>,
    starting_cancellation_generations: HashMap<String, u64>,
    starting_prepared: HashMap<String, PreparedInitiatorHandshake>,
    /// Owner token for every `starting` reservation.  This is deliberately
    /// separate from `pending_ids`: a preparation has no WireGuard session ID
    /// yet, but it still must not be allowed to clean up a newer reservation.
    starting_ids: HashMap<String, u64>,
    /// Cancellation handles for slow event-triggered preparation work. A peer
    /// leave or identity replacement wakes a pre-commit STUN wait immediately.
    starting_cancellations: HashMap<String, tokio::sync::watch::Sender<bool>>,
    initiator_retries: HashMap<String, PendingInitiatorRetry>,
    /// Cancellation handles transferred from `starting` when an event
    /// initiator commits its pending transaction.  Keeping this sender alive
    /// makes the subsequent control-plane offer wait cancellable by a
    /// PeerLeft, crossing offer, or matching answer.
    pending_cancellations: HashMap<String, tokio::sync::watch::Sender<bool>>,
    next_start_id: u64,
    next_cancellation_generation: u64,
    retry_revision: u64,
    pending_ids: HashMap<String, u64>,
    next_id: u64,
    /// Number of initiation attempts per peer (bounded retries).
    attempts: HashMap<String, u32>,
    /// Exact responder answers keyed by `(peer, handshake token)`. Noise
    /// responder messages are randomized, so duplicate offers must replay the
    /// same bytes and key material rather than generate a second session.
    responder_cache: HashMap<(String, String), CachedResponderHandshake>,
    /// Latest authenticated WireGuard initiation timestamp per peer/static
    /// identity. Responder objects are deliberately short-lived, so replay
    /// state must outlive an individual Noise transaction. Keeping the static
    /// key with the floor lets a legitimate identity rotation start fresh.
    responder_timestamp_floors: HashMap<String, ([u8; 32], [u8; 12])>,
    /// Exactly one event-triggered responder worker may perform slow work for
    /// a peer. Later offers coalesce into a single newest-wins queue slot.
    responder_workers: HashMap<String, ResponderWorkOwner>,
    next_responder_worker_id: u64,
    /// Candidate application is intentionally disjoint from responder work.
    /// Each peer owns at most one active and one newest-wins queued value.
    candidate_offer_workers: HashMap<String, CandidateOfferWorkOwner>,
    next_candidate_offer_worker_id: u64,
    /// A claimed remote incarnation is not current until its old transport
    /// cleanup and peer-session rotation commit. Candidate and responder
    /// owners consult this one-entry-per-peer fence before interpreting the
    /// synchronous incarnation high-water as `NoReset`.
    remote_incarnation_resets: HashMap<String, u64>,
    /// Exactly one slow peer-reflexive worker may wait on candidate refresh
    /// or HTTP for a peer. Later observations replace its one queued value.
    peer_reflexive_workers: HashMap<String, PeerReflexiveWorkOwner>,
    next_peer_reflexive_worker_id: u64,
}

/// All pending-handshake mutations are short, in-memory transactions.  A
/// synchronous store makes that contract explicit: an arbiter lease can use
/// `try_lock` without introducing an async lock edge, and the compiler rejects
/// any attempt to carry the guard through a `Send` future's `.await`.
#[derive(Default)]
struct PendingHandshakeStore {
    state: std::sync::Mutex<PendingHandshakeState>,
}

impl PendingHandshakeStore {
    fn lock(&self) -> std::sync::MutexGuard<'_, PendingHandshakeState> {
        self.state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    fn try_lock(&self) -> Option<std::sync::MutexGuard<'_, PendingHandshakeState>> {
        match self.state.try_lock() {
            Ok(guard) => Some(guard),
            Err(std::sync::TryLockError::Poisoned(poisoned)) => Some(poisoned.into_inner()),
            Err(std::sync::TryLockError::WouldBlock) => None,
        }
    }

    fn try_with<R>(&self, operation: impl FnOnce(&mut PendingHandshakeState) -> R) -> Option<R> {
        let mut state = self.try_lock()?;
        Some(operation(&mut state))
    }
}

impl PendingHandshakeState {
    /// Atomically claim the right to prepare a new initiator for `peer_id`.
    ///
    /// A caller must later either commit it with `insert_reserved` or release
    /// it with `cancel_reservation`.
    #[cfg(test)]
    fn reserve_start(&mut self, peer_id: &str) -> bool {
        self.reserve_start_with_owner(peer_id).is_some()
    }

    #[cfg(test)]
    fn reserve_start_with_owner(&mut self, peer_id: &str) -> Option<HandshakeStartReservation> {
        self.reserve_start_with_owner_at_generation(peer_id, 0, PeerSessionGeneration::for_test(1))
    }

    #[cfg(test)]
    fn reserve_start_with_owner_at_generation(
        &mut self,
        peer_id: &str,
        network_generation: u64,
        peer_session_generation: PeerSessionGeneration,
    ) -> Option<HandshakeStartReservation> {
        self.reserve_start_with_owner_at_generation_and_kind(
            peer_id,
            network_generation,
            peer_session_generation,
            HandshakeOwnerKind::EventInitiatorReserve,
        )
    }

    fn reserve_start_with_owner_at_generation_and_kind(
        &mut self,
        peer_id: &str,
        network_generation: u64,
        peer_session_generation: PeerSessionGeneration,
        owner_kind: HandshakeOwnerKind,
    ) -> Option<HandshakeStartReservation> {
        if self.pending.contains_key(peer_id) {
            // A pending transaction from an older network incarnation can no
            // longer produce a valid session. The caller removes its Probe
            // binding before admitting the replacement.
            if self.pending_network_generations.get(peer_id) != Some(&network_generation)
                || self.pending_peer_session_generations.get(peer_id)
                    != Some(&peer_session_generation)
            {
                self.remove(peer_id);
            } else {
                return None;
            }
        }
        if self.starting.contains(peer_id) {
            if self.starting_network_generations.get(peer_id) != Some(&network_generation)
                || self.starting_peer_session_generations.get(peer_id)
                    != Some(&peer_session_generation)
            {
                self.cancel_reservation(peer_id);
            } else if owner_kind == HandshakeOwnerKind::EventInitiatorReserve
                && self.starting_owner_kinds.get(peer_id)
                    == Some(&HandshakeOwnerKind::MaintenanceInitiator)
            {
                // Event-triggered initiation is latency-critical.  A
                // maintenance owner is allowed to finish only until the next
                // short mutation turn; after that its cancellation receiver
                // makes every slow continuation fail closed.
                self.cancel_reservation(peer_id);
            } else {
                return None;
            }
        }
        if self.pending.contains_key(peer_id) || self.starting.contains(peer_id) {
            return None;
        }
        self.next_start_id = self.next_start_id.saturating_add(1);
        let owner = self.next_start_id;
        self.next_cancellation_generation = self.next_cancellation_generation.saturating_add(1);
        let cancellation_generation = self.next_cancellation_generation;
        let (cancellation_tx, cancellation) = tokio::sync::watch::channel(false);
        self.starting.insert(peer_id.to_string());
        self.starting_network_generations
            .insert(peer_id.to_string(), network_generation);
        self.starting_peer_session_generations
            .insert(peer_id.to_string(), peer_session_generation);
        self.starting_owner_kinds
            .insert(peer_id.to_string(), owner_kind);
        self.starting_cancellation_generations
            .insert(peer_id.to_string(), cancellation_generation);
        self.starting_ids.insert(peer_id.to_string(), owner);
        self.starting_cancellations
            .insert(peer_id.to_string(), cancellation_tx);
        Some(HandshakeStartReservation {
            owner,
            owner_kind,
            network_generation,
            peer_session_generation,
            cancellation_generation,
            cancellation,
            disposition: HandshakeStartDisposition::Active,
            retry_phase: None,
            retry_attempt: 0,
            retry_expires_at: None,
            stale_session_id: None,
        })
    }

    fn cancel_reservation(&mut self, peer_id: &str) {
        self.starting.remove(peer_id);
        self.starting_network_generations.remove(peer_id);
        self.starting_peer_session_generations.remove(peer_id);
        self.starting_owner_kinds.remove(peer_id);
        self.starting_cancellation_generations.remove(peer_id);
        self.starting_prepared.remove(peer_id);
        self.initiator_retries.remove(peer_id);
        self.starting_ids.remove(peer_id);
        if let Some(cancellation) = self.starting_cancellations.remove(peer_id) {
            cancellation.send_replace(true);
        }
    }

    fn cancel_reservation_if_current(&mut self, peer_id: &str, owner: u64) -> bool {
        if self.starting_ids.get(peer_id).copied() != Some(owner) {
            return false;
        }
        self.cancel_reservation(peer_id);
        true
    }

    /// Cancel every initiator owner stamped before `generation` and return the
    /// exact staged Probe bindings which the peer manager must remove while it
    /// owns the same generation/connection transaction.
    fn cancel_before_network_generation(
        &mut self,
        generation: u64,
    ) -> (usize, usize, Vec<(String, String)>) {
        let stale_peers = self
            .starting_network_generations
            .iter()
            .filter(|(_, reserved_generation)| **reserved_generation < generation)
            .map(|(peer_id, _)| peer_id.clone())
            .collect::<Vec<_>>();
        let cancelled_reservations = stale_peers.len();
        for peer_id in stale_peers {
            self.cancel_reservation(&peer_id);
        }

        let stale_pending_peers = self
            .pending_network_generations
            .iter()
            .filter(|(_, pending_generation)| **pending_generation < generation)
            .map(|(peer_id, _)| peer_id.clone())
            .collect::<Vec<_>>();
        let cancelled_pending = stale_pending_peers.len();
        let mut stale_probe_bindings = Vec::with_capacity(cancelled_pending);
        for peer_id in stale_pending_peers {
            if let Some(session_id) = self.session_id(&peer_id).map(str::to_string) {
                stale_probe_bindings.push((peer_id.clone(), session_id));
            }
            // `remove` wakes a control POST which inherited the exact starting
            // reservation cancellation sender. A request that was not yet
            // delivered therefore cannot publish after the generation edge.
            self.remove(&peer_id);
        }
        (
            cancelled_reservations,
            cancelled_pending,
            stale_probe_bindings,
        )
    }

    fn reservation_for_retry(
        &self,
        identity: &HandshakeRetryIdentity,
    ) -> Option<HandshakeStartReservation> {
        if self.starting_ids.get(&identity.peer_id).copied() != Some(identity.reservation_owner)
            || self.starting_network_generations.get(&identity.peer_id)
                != Some(&identity.network_generation)
            || self
                .starting_peer_session_generations
                .get(&identity.peer_id)
                != Some(&identity.peer_session_generation)
            || self
                .starting_cancellation_generations
                .get(&identity.peer_id)
                .copied()
                != Some(identity.cancellation_generation)
        {
            return None;
        }
        let cancellation = self
            .starting_cancellations
            .get(&identity.peer_id)?
            .subscribe();
        Some(HandshakeStartReservation {
            owner: identity.reservation_owner,
            owner_kind: *self.starting_owner_kinds.get(&identity.peer_id)?,
            network_generation: identity.network_generation,
            peer_session_generation: identity.peer_session_generation,
            cancellation_generation: identity.cancellation_generation,
            cancellation,
            disposition: HandshakeStartDisposition::Active,
            retry_phase: None,
            retry_attempt: 0,
            retry_expires_at: None,
            stale_session_id: None,
        })
    }

    fn store_prepared_if_current(
        &mut self,
        peer_id: &str,
        reservation: &HandshakeStartReservation,
        prepared: PreparedInitiatorHandshake,
    ) -> bool {
        if self.starting_ids.get(peer_id).copied() != Some(reservation.owner)
            || self.starting_network_generations.get(peer_id)
                != Some(&reservation.network_generation)
            || self.starting_peer_session_generations.get(peer_id)
                != Some(&reservation.peer_session_generation)
            || self.starting_cancellation_generations.get(peer_id).copied()
                != Some(reservation.cancellation_generation)
        {
            return false;
        }
        self.starting_prepared.insert(peer_id.to_string(), prepared);
        true
    }

    fn take_prepared_if_current(
        &mut self,
        peer_id: &str,
        reservation: &HandshakeStartReservation,
    ) -> Option<PreparedInitiatorHandshake> {
        if self.starting_ids.get(peer_id).copied() != Some(reservation.owner)
            || self.starting_cancellation_generations.get(peer_id).copied()
                != Some(reservation.cancellation_generation)
        {
            return None;
        }
        self.starting_prepared.remove(peer_id)
    }

    fn starting_reservation_is_current(
        &self,
        peer_id: &str,
        reservation: &HandshakeStartReservation,
    ) -> bool {
        self.starting_ids.get(peer_id).copied() == Some(reservation.owner)
            && self.starting_network_generations.get(peer_id)
                == Some(&reservation.network_generation)
            && self.starting_peer_session_generations.get(peer_id)
                == Some(&reservation.peer_session_generation)
            && self.starting_cancellation_generations.get(peer_id).copied()
                == Some(reservation.cancellation_generation)
    }

    fn has_prepared_for_reservation(
        &self,
        peer_id: &str,
        reservation: &HandshakeStartReservation,
    ) -> bool {
        self.starting_ids.get(peer_id).copied() == Some(reservation.owner)
            && self.starting_cancellation_generations.get(peer_id).copied()
                == Some(reservation.cancellation_generation)
            && self.starting_prepared.contains_key(peer_id)
    }

    fn schedule_initiator_retry(
        &mut self,
        peer_id: &str,
        reservation: &HandshakeStartReservation,
        phase: InitiatorRetryPhase,
        now: Instant,
    ) -> Option<(HandshakeRetryIdentity, u64)> {
        if self.starting_ids.get(peer_id).copied() != Some(reservation.owner)
            || self.starting_network_generations.get(peer_id)
                != Some(&reservation.network_generation)
            || self.starting_peer_session_generations.get(peer_id)
                != Some(&reservation.peer_session_generation)
            || self.starting_cancellation_generations.get(peer_id).copied()
                != Some(reservation.cancellation_generation)
            || (phase == InitiatorRetryPhase::Publish
                && !self.starting_prepared.contains_key(peer_id))
        {
            return None;
        }
        if !self.initiator_retries.contains_key(peer_id)
            && self.initiator_retries.len() >= MAX_PENDING_INITIATOR_RETRIES
        {
            return None;
        }
        let matching_retry = self.initiator_retries.get(peer_id).filter(|retry| {
            retry.identity.reservation_owner == reservation.owner
                && retry.identity.phase == phase
                && retry.identity.cancellation_generation == reservation.cancellation_generation
        });
        let claimed_attempt = if reservation.retry_phase == Some(phase) {
            reservation.retry_attempt
        } else {
            0
        };
        let previous_attempt = matching_retry
            .map(|retry| retry.identity.attempt)
            .unwrap_or(0)
            .max(claimed_attempt);
        let attempt = previous_attempt.saturating_add(1);
        // Repeated contention for the same exact phase may increase backoff,
        // but it must not extend the record forever.  A phase transition is
        // meaningful progress and receives its own bounded TTL.
        let expires_at = matching_retry
            .map(|retry| retry.expires_at)
            .or_else(|| {
                (reservation.retry_phase == Some(phase))
                    .then_some(reservation.retry_expires_at)
                    .flatten()
            })
            .unwrap_or(now + INITIATOR_RETRY_TTL);
        if expires_at <= now {
            self.cancel_reservation_if_current(peer_id, reservation.owner);
            return None;
        }
        let backoff_index = (attempt as usize).saturating_sub(1);
        let backoff = INITIATOR_RETRY_BACKOFF
            .get(backoff_index)
            .copied()
            .unwrap_or(*INITIATOR_RETRY_BACKOFF.last().expect("retry backoff"));
        let identity = HandshakeRetryIdentity {
            peer_id: peer_id.to_string(),
            network_generation: reservation.network_generation,
            peer_session_generation: reservation.peer_session_generation,
            reservation_owner: reservation.owner,
            phase,
            attempt,
            cancellation_generation: reservation.cancellation_generation,
        };
        self.initiator_retries.insert(
            peer_id.to_string(),
            PendingInitiatorRetry {
                identity: identity.clone(),
                not_before: now + backoff,
                expires_at,
            },
        );
        self.retry_revision = self.retry_revision.wrapping_add(1);
        Some((identity, self.retry_revision))
    }

    fn expire_initiator_retries(&mut self, now: Instant) {
        // Expiration is terminal for the exact reservation.  Purge before
        // selecting ready work so a delayed maintenance scan can never run a
        // retry after its strict TTL, and so an expired owner cannot leak its
        // prepared initiation indefinitely.
        let expired = self
            .initiator_retries
            .iter()
            .filter(|(_, retry)| retry.expires_at <= now)
            .map(|(peer_id, retry)| {
                (
                    peer_id.clone(),
                    retry.identity.reservation_owner,
                    retry.identity.cancellation_generation,
                )
            })
            .collect::<Vec<_>>();
        for (peer_id, reservation_owner, cancellation_generation) in expired {
            let still_exact = self.starting_ids.get(&peer_id).copied() == Some(reservation_owner)
                && self
                    .starting_cancellation_generations
                    .get(&peer_id)
                    .copied()
                    == Some(cancellation_generation);
            if still_exact {
                self.cancel_reservation(&peer_id);
            } else {
                self.initiator_retries.remove(&peer_id);
            }
        }
    }

    fn claim_ready_initiator_retry(
        &mut self,
        now: Instant,
    ) -> Option<(HandshakeRetryIdentity, HandshakeStartReservation)> {
        self.expire_initiator_retries(now);
        let peer_id = self
            .initiator_retries
            .iter()
            .filter(|(_, retry)| retry.not_before <= now && retry.expires_at > now)
            .min_by_key(|(_, retry)| (retry.expires_at, retry.not_before))
            .map(|(peer_id, _)| peer_id.clone())?;
        let retry = self.initiator_retries.remove(&peer_id)?;
        let Some(mut reservation) = self.reservation_for_retry(&retry.identity) else {
            self.cancel_reservation_if_current(&peer_id, retry.identity.reservation_owner);
            return None;
        };
        reservation.retry_phase = Some(retry.identity.phase);
        reservation.retry_attempt = retry.identity.attempt;
        reservation.retry_expires_at = Some(retry.expires_at);
        Some((retry.identity, reservation))
    }

    fn has_initiator_retries(&self) -> bool {
        !self.initiator_retries.is_empty()
    }

    fn retry_revision(&self) -> u64 {
        self.retry_revision
    }

    #[cfg(test)]
    fn insert_reserved_if_current(
        &mut self,
        peer_id: String,
        owner: u64,
        initiator: HandshakeInitiator,
        session_id: Option<String>,
        probe_ephemeral: Option<DhKeyPair>,
    ) -> Option<u64> {
        self.insert_reserved_if_current_with_generation(
            peer_id,
            owner,
            initiator,
            session_id,
            probe_ephemeral,
            0,
            PeerSessionGeneration::for_test(1),
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn insert_reserved_if_current_with_generation(
        &mut self,
        peer_id: String,
        owner: u64,
        initiator: HandshakeInitiator,
        session_id: Option<String>,
        probe_ephemeral: Option<DhKeyPair>,
        network_generation: u64,
        peer_session_generation: PeerSessionGeneration,
    ) -> Option<u64> {
        if self.starting_ids.get(&peer_id).copied() != Some(owner)
            || self.starting_network_generations.get(&peer_id) != Some(&network_generation)
            || self.starting_peer_session_generations.get(&peer_id)
                != Some(&peer_session_generation)
        {
            return None;
        }
        self.starting.remove(&peer_id);
        self.starting_network_generations.remove(&peer_id);
        self.starting_peer_session_generations.remove(&peer_id);
        self.starting_owner_kinds.remove(&peer_id);
        self.starting_cancellation_generations.remove(&peer_id);
        self.starting_prepared.remove(&peer_id);
        self.initiator_retries.remove(&peer_id);
        self.starting_ids.remove(&peer_id);
        let cancellation = self.starting_cancellations.remove(&peer_id);
        Some(self.insert_with_generation(
            peer_id,
            initiator,
            session_id,
            probe_ephemeral,
            cancellation,
            network_generation,
            peer_session_generation,
        ))
    }

    #[cfg(test)]
    fn insert(
        &mut self,
        peer_id: String,
        initiator: HandshakeInitiator,
        session_id: Option<String>,
        probe_ephemeral: Option<DhKeyPair>,
    ) -> u64 {
        self.insert_with_cancellation(peer_id, initiator, session_id, probe_ephemeral, None)
    }

    #[cfg(test)]
    fn insert_with_cancellation(
        &mut self,
        peer_id: String,
        initiator: HandshakeInitiator,
        session_id: Option<String>,
        probe_ephemeral: Option<DhKeyPair>,
        cancellation: Option<tokio::sync::watch::Sender<bool>>,
    ) -> u64 {
        self.insert_with_generation(
            peer_id,
            initiator,
            session_id,
            probe_ephemeral,
            cancellation,
            0,
            PeerSessionGeneration::for_test(1),
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn insert_with_generation(
        &mut self,
        peer_id: String,
        initiator: HandshakeInitiator,
        session_id: Option<String>,
        probe_ephemeral: Option<DhKeyPair>,
        cancellation: Option<tokio::sync::watch::Sender<bool>>,
        network_generation: u64,
        peer_session_generation: PeerSessionGeneration,
    ) -> u64 {
        // Defend against a direct replacement: wake the old owner before
        // replacing its slot so a late slow POST cannot outlive the new
        // transaction.
        if let Some(previous) = self.pending_cancellations.remove(&peer_id) {
            previous.send_replace(true);
        }
        self.next_id = self.next_id.saturating_add(1);
        let pending_id = self.next_id;
        self.pending.insert(peer_id.clone(), initiator);
        if let Some(session_id) = session_id {
            self.pending_session_ids.insert(peer_id.clone(), session_id);
        } else {
            self.pending_session_ids.remove(&peer_id);
        }
        self.pending_network_generations
            .insert(peer_id.clone(), network_generation);
        self.pending_peer_session_generations
            .insert(peer_id.clone(), peer_session_generation);
        if let Some(probe_ephemeral) = probe_ephemeral {
            self.pending_probe_ephemeral
                .insert(peer_id.clone(), probe_ephemeral);
        } else {
            self.pending_probe_ephemeral.remove(&peer_id);
        }
        self.pending_ids.insert(peer_id.clone(), pending_id);
        if let Some(cancellation) = cancellation {
            self.pending_cancellations.insert(peer_id, cancellation);
        }
        pending_id
    }

    fn remove(&mut self, peer_id: &str) -> Option<HandshakeInitiator> {
        if let Some(cancellation) = self.pending_cancellations.remove(peer_id) {
            cancellation.send_replace(true);
        }
        self.pending_ids.remove(peer_id);
        self.pending_session_ids.remove(peer_id);
        self.pending_network_generations.remove(peer_id);
        self.pending_peer_session_generations.remove(peer_id);
        self.pending_probe_ephemeral.remove(peer_id);
        self.pending.remove(peer_id)
    }

    fn session_id(&self, peer_id: &str) -> Option<&str> {
        self.pending_session_ids.get(peer_id).map(String::as_str)
    }

    fn network_generation(&self, peer_id: &str) -> Option<u64> {
        self.pending_network_generations.get(peer_id).copied()
    }

    fn peer_session_generation(&self, peer_id: &str) -> Option<PeerSessionGeneration> {
        self.pending_peer_session_generations.get(peer_id).copied()
    }

    /// Remove a pending initiator that belongs to an older local network
    /// incarnation and return its Probe token so the connection-level binding
    /// can be removed before a replacement is staged.
    fn remove_stale_pending_for_generation(
        &mut self,
        peer_id: &str,
        network_generation: u64,
        peer_session_generation: PeerSessionGeneration,
    ) -> Option<String> {
        let is_stale = self
            .pending_network_generations
            .get(peer_id)
            .is_some_and(|pending_generation| *pending_generation != network_generation)
            || self
                .pending_peer_session_generations
                .get(peer_id)
                .is_some_and(|pending_generation| *pending_generation != peer_session_generation);
        if !is_stale {
            return None;
        }
        let token = self.session_id(peer_id).map(str::to_string);
        self.remove(peer_id);
        token
    }

    fn probe_ephemeral(&self, peer_id: &str) -> Option<DhKeyPair> {
        self.pending_probe_ephemeral.get(peer_id).cloned()
    }

    fn clear_peer(&mut self, peer_id: &str) {
        self.remove(peer_id);
        self.cancel_reservation(peer_id);
        self.attempts.remove(peer_id);
        self.responder_cache
            .retain(|(cached_peer, _), _| cached_peer != peer_id);
        if let Some(worker) = self.responder_workers.remove(peer_id) {
            if let Some(queued) = worker.queued.as_ref() {
                queued.complete_delivery(control::SignalApplyOutcome::TerminalRejected);
            }
            worker.cancellation.send_replace(true);
        }
        if let Some(worker) = self.candidate_offer_workers.remove(peer_id) {
            worker.cancellation.send_replace(true);
        }
        if let Some(worker) = self.peer_reflexive_workers.remove(peer_id) {
            if let Some(queued) = worker.queued.as_ref() {
                queued.complete_delivery(control::SignalApplyOutcome::TerminalRejected);
            }
            worker.cancellation.send_replace(true);
        }
    }

    /// Clear work owned by a retired remote incarnation while retaining the
    /// exact local initiator transaction that an arriving PeerAnswer completes.
    fn clear_peer_except_pending_initiator(&mut self, peer_id: &str) {
        self.cancel_reservation(peer_id);
        self.responder_cache
            .retain(|(cached_peer, _), _| cached_peer != peer_id);
        if let Some(worker) = self.responder_workers.remove(peer_id) {
            if let Some(queued) = worker.queued.as_ref() {
                queued.complete_delivery(control::SignalApplyOutcome::TerminalRejected);
            }
            worker.cancellation.send_replace(true);
        }
        if let Some(worker) = self.candidate_offer_workers.remove(peer_id) {
            worker.cancellation.send_replace(true);
        }
        if let Some(worker) = self.peer_reflexive_workers.remove(peer_id) {
            if let Some(queued) = worker.queued.as_ref() {
                queued.complete_delivery(control::SignalApplyOutcome::TerminalRejected);
            }
            worker.cancellation.send_replace(true);
        }
    }

    /// Clear retired initiator/reflexive work while retaining the responder
    /// owner that is currently applying the restart offer.
    fn clear_peer_except_responder_owner(&mut self, peer_id: &str) {
        self.remove(peer_id);
        self.cancel_reservation(peer_id);
        self.attempts.remove(peer_id);
        self.responder_cache
            .retain(|(cached_peer, _), _| cached_peer != peer_id);
        if let Some(worker) = self.peer_reflexive_workers.remove(peer_id) {
            if let Some(queued) = worker.queued.as_ref() {
                queued.complete_delivery(control::SignalApplyOutcome::TerminalRejected);
            }
            worker.cancellation.send_replace(true);
        }
    }

    fn is_current(&self, peer_id: &str, pending_id: u64) -> bool {
        self.pending_ids.get(peer_id).copied() == Some(pending_id)
    }

    fn remove_if_current(&mut self, peer_id: &str, pending_id: u64) -> bool {
        if !self.is_current(peer_id, pending_id) {
            return false;
        }
        self.remove(peer_id);
        true
    }

    fn responder_cache_lookup(
        &mut self,
        peer_id: &str,
        token: &str,
        lifecycle: ResponderHandshakeLifecycle,
        handshake_init: &[u8],
        request_probe_ephemeral_public_key: Option<&str>,
        expected_initiator_static_public_key: &[u8; 32],
    ) -> ResponderHandshakeCacheLookup {
        let now = Instant::now();
        self.responder_cache
            .retain(|_, cached| cached.expires_at > now);
        let key = (peer_id.to_string(), token.to_string());
        let Some(cached) = self.responder_cache.get(&key) else {
            return ResponderHandshakeCacheLookup::Miss;
        };
        if cached.lifecycle != lifecycle {
            self.responder_cache.remove(&key);
            return ResponderHandshakeCacheLookup::StaleLifecycle;
        }
        let request_probe_ephemeral_public_key =
            normalize_probe_ephemeral_public_key(request_probe_ephemeral_public_key);
        if cached.handshake_init != handshake_init
            || cached.request_probe_ephemeral_public_key != request_probe_ephemeral_public_key
            || &cached.initiator_static_public_key != expected_initiator_static_public_key
        {
            return ResponderHandshakeCacheLookup::FingerprintMismatch;
        }
        ResponderHandshakeCacheLookup::Hit(Box::new(cached.clone()))
    }

    fn cache_responder_handshake(
        &mut self,
        peer_id: &str,
        token: &str,
        mut cached: CachedResponderHandshake,
    ) {
        cached.request_probe_ephemeral_public_key = normalize_probe_ephemeral_public_key(
            cached.request_probe_ephemeral_public_key.as_deref(),
        );
        self.responder_cache
            .insert((peer_id.to_string(), token.to_string()), cached);
    }

    fn discard_responder_handshake_cache(&mut self, peer_id: &str, token: &str) {
        self.responder_cache
            .remove(&(peer_id.to_string(), token.to_string()));
    }

    fn responder_timestamp_floor(
        &self,
        peer_id: &str,
        initiator_static_public_key: &[u8; 32],
    ) -> Option<[u8; 12]> {
        self.responder_timestamp_floors
            .get(peer_id)
            .filter(|(public_key, _)| public_key == initiator_static_public_key)
            .map(|(_, timestamp)| *timestamp)
    }

    /// Commit a newly authenticated timestamp. False means another responder
    /// generation already committed an equal/newer value, so this initiation
    /// is a replay and must not install another transport session.
    fn commit_responder_timestamp(
        &mut self,
        peer_id: &str,
        initiator_static_public_key: [u8; 32],
        timestamp: [u8; 12],
    ) -> bool {
        if self
            .responder_timestamp_floor(peer_id, &initiator_static_public_key)
            .is_some_and(|floor| timestamp <= floor)
        {
            return false;
        }
        self.responder_timestamp_floors.insert(
            peer_id.to_string(),
            (initiator_static_public_key, timestamp),
        );
        true
    }

    /// Coalesce event-triggered responder work to one active worker per peer.
    /// Repeated control delivery is expected; keeping only the latest offer
    /// avoids an unbounded waiter queue while preserving the peer's retry.
    fn enqueue_responder_work(
        &mut self,
        offer: PendingPeerOffer,
    ) -> Option<(ResponderWorkReservation, PendingPeerOffer)> {
        // A lifecycle cancellation must never leave a dead owner accepting
        // newer offers.  `clear_peer` normally removes the owner atomically,
        // but checking the watch here also closes the boundary where a
        // cancellation notification has become visible before a late event
        // reaches this state machine.
        let cancelled = self
            .responder_workers
            .get(&offer.from_node_id)
            .is_some_and(|worker| *worker.cancellation.borrow());
        if cancelled {
            self.responder_workers.remove(&offer.from_node_id);
        }
        if let Some(worker) = self.responder_workers.get_mut(&offer.from_node_id) {
            let incoming_matches_active = same_responder_sender_identity(
                worker.active_sender_public_key.as_deref(),
                offer.sender_public_key.as_deref(),
            );
            let queued_has_different_identity = worker.queued.as_ref().is_some_and(|queued| {
                !same_responder_sender_identity(
                    queued.sender_public_key.as_deref(),
                    offer.sender_public_key.as_deref(),
                )
            });
            if incoming_matches_active && queued_has_different_identity {
                // The active identity already has one turn. Do not let its
                // later retransmit erase the sole queued turn for a different
                // (typically replacement) identity. Same-queued-identity and
                // third-identity arrivals remain newest-wins below.
                offer.complete_delivery(control::SignalApplyOutcome::TerminalRejected);
                return None;
            }
            if let Some(replaced) = worker.queued.replace(offer) {
                replaced.complete_delivery(control::SignalApplyOutcome::TerminalRejected);
            }
            return None;
        }

        self.next_responder_worker_id = self.next_responder_worker_id.saturating_add(1);
        let owner = self.next_responder_worker_id;
        let peer_id = offer.from_node_id.clone();
        let (cancellation_tx, cancellation) = tokio::sync::watch::channel(false);
        self.responder_workers.insert(
            peer_id,
            ResponderWorkOwner {
                owner,
                cancellation: cancellation_tx,
                active_sender_public_key: offer.sender_public_key.clone(),
                queued: None,
            },
        );
        Some((
            ResponderWorkReservation {
                owner,
                cancellation,
            },
            offer,
        ))
    }

    /// Take a newer offer without releasing the current responder owner.
    ///
    /// A deferred unknown-peer worker calls this immediately after the peer
    /// identity becomes available.  That makes the replay newest-wins even
    /// when several offers arrived during the registration wait: the stale
    /// value never reaches candidate admission or WireGuard processing.
    fn take_queued_responder_work(
        &mut self,
        peer_id: &str,
        owner: u64,
    ) -> Option<PendingPeerOffer> {
        let worker = self.responder_workers.get_mut(peer_id)?;
        if worker.owner != owner || *worker.cancellation.borrow() {
            return None;
        }
        let next = worker.queued.take()?;
        worker.active_sender_public_key = next.sender_public_key.clone();
        Some(next)
    }

    /// Return the newest queued offer, if any, while retaining the same
    /// worker ownership.  If there is no queued offer, release the worker.
    /// A stale worker that was cancelled/cleared cannot release a replacement
    /// because its owner token no longer matches.
    fn finish_responder_work(&mut self, peer_id: &str, owner: u64) -> Option<PendingPeerOffer> {
        let worker = self.responder_workers.get_mut(peer_id)?;
        if worker.owner != owner || *worker.cancellation.borrow() {
            return None;
        }
        if let Some(next) = worker.queued.take() {
            worker.active_sender_public_key = next.sender_public_key.clone();
            return Some(next);
        }
        self.responder_workers.remove(peer_id);
        None
    }

    fn responder_work_is_current(&self, peer_id: &str, owner: u64) -> bool {
        self.responder_workers
            .get(peer_id)
            .is_some_and(|worker| worker.owner == owner && !*worker.cancellation.borrow())
    }

    /// Retain one bounded candidate transaction per peer, with one
    /// newest-wins successor.  The durable signal receipt is deliberately not
    /// stored here: admission itself is the application commit, after which
    /// this owner is responsible for transient retries.
    fn enqueue_candidate_offer_work(
        &mut self,
        offer: PendingPeerOffer,
    ) -> CandidateOfferWorkAdmission {
        debug_assert!(offer.delivery_receipt.is_none());
        let cancelled = self
            .candidate_offer_workers
            .get(&offer.from_node_id)
            .is_some_and(|worker| *worker.cancellation.borrow());
        if cancelled {
            self.candidate_offer_workers.remove(&offer.from_node_id);
        }
        if let Some(worker) = self.candidate_offer_workers.get_mut(&offer.from_node_id) {
            let incoming_matches_active = same_responder_sender_identity(
                worker.active_sender_public_key.as_deref(),
                offer.sender_public_key.as_deref(),
            );
            let queued_has_different_identity = worker.queued.as_ref().is_some_and(|queued| {
                !same_responder_sender_identity(
                    queued.sender_public_key.as_deref(),
                    offer.sender_public_key.as_deref(),
                )
            });
            if incoming_matches_active && queued_has_different_identity {
                return CandidateOfferWorkAdmission::RejectedIdentity;
            }
            worker.queued = Some(offer);
            return CandidateOfferWorkAdmission::Coalesced;
        }
        if self.candidate_offer_workers.len() >= MAX_CANDIDATE_OFFER_WORKERS {
            return CandidateOfferWorkAdmission::Capacity;
        }

        self.next_candidate_offer_worker_id =
            self.next_candidate_offer_worker_id.saturating_add(1);
        let owner = self.next_candidate_offer_worker_id;
        let peer_id = offer.from_node_id.clone();
        let active_sender_public_key = offer.sender_public_key.clone();
        let (cancellation_tx, cancellation) = tokio::sync::watch::channel(false);
        self.candidate_offer_workers.insert(
            peer_id,
            CandidateOfferWorkOwner {
                owner,
                cancellation: cancellation_tx,
                active_sender_public_key,
                queued: None,
            },
        );
        CandidateOfferWorkAdmission::Started(
            CandidateOfferWorkReservation {
                owner,
                cancellation,
            },
            Box::new(offer),
        )
    }

    fn finish_candidate_offer_work(
        &mut self,
        peer_id: &str,
        owner: u64,
    ) -> Option<PendingPeerOffer> {
        let worker = self.candidate_offer_workers.get_mut(peer_id)?;
        if worker.owner != owner || *worker.cancellation.borrow() {
            return None;
        }
        if let Some(next) = worker.queued.take() {
            worker.active_sender_public_key = next.sender_public_key.clone();
            return Some(next);
        }
        self.candidate_offer_workers.remove(peer_id);
        None
    }

    fn take_queued_candidate_offer_work(
        &mut self,
        peer_id: &str,
        owner: u64,
    ) -> Option<PendingPeerOffer> {
        let worker = self.candidate_offer_workers.get_mut(peer_id)?;
        if worker.owner != owner || *worker.cancellation.borrow() {
            return None;
        }
        let next = worker.queued.take()?;
        worker.active_sender_public_key = next.sender_public_key.clone();
        Some(next)
    }

    fn candidate_offer_work_is_current(&self, peer_id: &str, owner: u64) -> bool {
        self.candidate_offer_workers
            .get(peer_id)
            .is_some_and(|worker| worker.owner == owner && !*worker.cancellation.borrow())
    }

    fn remote_incarnation_reset_in_progress(&self, peer_id: &str) -> Option<u64> {
        self.remote_incarnation_resets.get(peer_id).copied()
    }

    fn begin_remote_incarnation_reset(&mut self, peer_id: &str, incarnation: u64) -> bool {
        if self.remote_incarnation_resets.contains_key(peer_id) {
            return false;
        }
        self.remote_incarnation_resets
            .insert(peer_id.to_string(), incarnation);
        true
    }

    fn finish_remote_incarnation_reset(&mut self, peer_id: &str, incarnation: u64) {
        if self
            .remote_incarnation_resets
            .get(peer_id)
            .is_some_and(|pending| *pending == incarnation)
        {
            self.remote_incarnation_resets.remove(peer_id);
        }
    }

    /// Coalesce slow peer-reflexive work to one active worker per peer.
    ///
    /// A new endpoint is valuable only if it is the newest one: repeated NAT
    /// churn replaces the queued value rather than occupying another control
    /// worker or blocking offers/answers behind candidate refresh I/O.
    fn enqueue_peer_reflexive_work(
        &mut self,
        work: PendingPeerReflexive,
    ) -> Option<(PeerReflexiveWorkReservation, PendingPeerReflexive)> {
        if let Some(worker) = self.peer_reflexive_workers.get_mut(&work.from_node_id) {
            if let Some(replaced) = worker.queued.replace(work) {
                replaced.complete_delivery(control::SignalApplyOutcome::TerminalRejected);
            }
            return None;
        }

        self.next_peer_reflexive_worker_id = self.next_peer_reflexive_worker_id.saturating_add(1);
        let owner = self.next_peer_reflexive_worker_id;
        let peer_id = work.from_node_id.clone();
        let (cancellation_tx, cancellation) = tokio::sync::watch::channel(false);
        self.peer_reflexive_workers.insert(
            peer_id,
            PeerReflexiveWorkOwner {
                owner,
                cancellation: cancellation_tx,
                queued: None,
            },
        );
        Some((
            PeerReflexiveWorkReservation {
                owner,
                cancellation,
            },
            work,
        ))
    }

    fn has_peer_reflexive_worker(&self, peer_id: &str) -> bool {
        self.peer_reflexive_workers.contains_key(peer_id)
    }

    /// Return the newest queued peer-reflexive observation or release the
    /// current owner. A cancelled/cleared old worker cannot release a later
    /// owner's slot because the owner token must still match.
    fn finish_peer_reflexive_work(
        &mut self,
        peer_id: &str,
        owner: u64,
    ) -> Option<PendingPeerReflexive> {
        let worker = self.peer_reflexive_workers.get_mut(peer_id)?;
        if worker.owner != owner || *worker.cancellation.borrow() {
            return None;
        }
        if let Some(next) = worker.queued.take() {
            return Some(next);
        }
        self.peer_reflexive_workers.remove(peer_id);
        None
    }
}
