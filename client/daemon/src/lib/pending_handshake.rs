#[derive(Clone)]
struct CachedResponderHandshake {
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
    candidates_expires_at_ms: Option<u64>,
    sender_public_key: Option<String>,
    handshake_init: Vec<u8>,
    punch_at_ms: Option<u64>,
    punch_at_server_ms: Option<u64>,
    session_id: Option<String>,
    probe_ephemeral_public_key: Option<String>,
    /// Set when the offer-ingress verdict suppressed the candidate plane
    /// (duplicate or rate-limited): the worker still answers the handshake
    /// (crossing rekeys must never be dropped) but skips the fresh-prediction
    /// transaction and the punch trigger.
    ingress_suppressed: bool,
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
}

/// Owner token for an event-triggered initiator preparation.
///
/// `starting` used to be only a peer-id set.  A late task from a peer's old
/// incarnation could then clear a newer reservation after `PeerLeft`/rejoin.
/// The token and cancellation receiver make the reservation linearizable with
/// lifecycle cleanup.
struct HandshakeStartReservation {
    owner: u64,
    cancellation: tokio::sync::watch::Receiver<bool>,
}

/// Owner token for the one responder worker admitted for a peer.
struct ResponderWorkReservation {
    owner: u64,
    cancellation: tokio::sync::watch::Receiver<bool>,
}

struct ResponderWorkOwner {
    owner: u64,
    cancellation: tokio::sync::watch::Sender<bool>,
    queued: Option<PendingPeerOffer>,
}

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
    pending_probe_ephemeral: HashMap<String, DhKeyPair>,
    /// Peers for which a handshake is being prepared.  Candidate gathering and
    /// control-peer lookups await, so a plain `pending` check is not enough to
    /// prevent another trigger from creating and overwriting an initiator in
    /// that window.
    starting: HashSet<String>,
    /// Owner token for every `starting` reservation.  This is deliberately
    /// separate from `pending_ids`: a preparation has no WireGuard session ID
    /// yet, but it still must not be allowed to clean up a newer reservation.
    starting_ids: HashMap<String, u64>,
    /// Cancellation handles for slow event-triggered preparation work. A peer
    /// leave or identity replacement wakes a pre-commit STUN wait immediately.
    starting_cancellations: HashMap<String, tokio::sync::watch::Sender<bool>>,
    /// Cancellation handles transferred from `starting` when an event
    /// initiator commits its pending transaction.  Keeping this sender alive
    /// makes the subsequent control-plane offer wait cancellable by a
    /// PeerLeft, crossing offer, or matching answer.
    pending_cancellations: HashMap<String, tokio::sync::watch::Sender<bool>>,
    next_start_id: u64,
    pending_ids: HashMap<String, u64>,
    next_id: u64,
    /// Number of initiation attempts per peer (bounded retries).
    attempts: HashMap<String, u32>,
    /// Exact responder answers keyed by `(peer, handshake token)`. Noise
    /// responder messages are randomized, so duplicate offers must replay the
    /// same bytes and key material rather than generate a second session.
    responder_cache: HashMap<(String, String), CachedResponderHandshake>,
    /// Exactly one event-triggered responder worker may perform slow work for
    /// a peer. Later offers coalesce into a single newest-wins queue slot.
    responder_workers: HashMap<String, ResponderWorkOwner>,
    next_responder_worker_id: u64,
    /// Exactly one slow peer-reflexive worker may wait on candidate refresh
    /// or HTTP for a peer. Later observations replace its one queued value.
    peer_reflexive_workers: HashMap<String, PeerReflexiveWorkOwner>,
    next_peer_reflexive_worker_id: u64,
}

impl PendingHandshakeState {
    /// Atomically claim the right to prepare a new initiator for `peer_id`.
    ///
    /// A caller must later either commit it with `insert_reserved` or release
    /// it with `cancel_reservation`.
    fn reserve_start(&mut self, peer_id: &str) -> bool {
        self.reserve_start_with_owner(peer_id).is_some()
    }

    fn reserve_start_with_owner(&mut self, peer_id: &str) -> Option<HandshakeStartReservation> {
        if self.pending.contains_key(peer_id) || self.starting.contains(peer_id) {
            return None;
        }
        self.next_start_id = self.next_start_id.saturating_add(1);
        let owner = self.next_start_id;
        let (cancellation_tx, cancellation) = tokio::sync::watch::channel(false);
        self.starting.insert(peer_id.to_string());
        self.starting_ids.insert(peer_id.to_string(), owner);
        self.starting_cancellations
            .insert(peer_id.to_string(), cancellation_tx);
        Some(HandshakeStartReservation {
            owner,
            cancellation,
        })
    }

    fn cancel_reservation(&mut self, peer_id: &str) {
        self.starting.remove(peer_id);
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

    fn insert_reserved(
        &mut self,
        peer_id: String,
        initiator: HandshakeInitiator,
        session_id: Option<String>,
        probe_ephemeral: Option<DhKeyPair>,
    ) -> Option<u64> {
        if !self.starting.remove(&peer_id) {
            return None;
        }
        self.starting_ids.remove(&peer_id);
        let cancellation = self.starting_cancellations.remove(&peer_id);
        Some(self.insert_with_cancellation(
            peer_id,
            initiator,
            session_id,
            probe_ephemeral,
            cancellation,
        ))
    }

    fn insert_reserved_if_current(
        &mut self,
        peer_id: String,
        owner: u64,
        initiator: HandshakeInitiator,
        session_id: Option<String>,
        probe_ephemeral: Option<DhKeyPair>,
    ) -> Option<u64> {
        if self.starting_ids.get(&peer_id).copied() != Some(owner) {
            return None;
        }
        self.starting.remove(&peer_id);
        self.starting_ids.remove(&peer_id);
        let cancellation = self.starting_cancellations.remove(&peer_id);
        Some(self.insert_with_cancellation(
            peer_id,
            initiator,
            session_id,
            probe_ephemeral,
            cancellation,
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

    fn insert_with_cancellation(
        &mut self,
        peer_id: String,
        initiator: HandshakeInitiator,
        session_id: Option<String>,
        probe_ephemeral: Option<DhKeyPair>,
        cancellation: Option<tokio::sync::watch::Sender<bool>>,
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
        self.pending_probe_ephemeral.remove(peer_id);
        self.pending.remove(peer_id)
    }

    fn session_id(&self, peer_id: &str) -> Option<&str> {
        self.pending_session_ids.get(peer_id).map(String::as_str)
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
            worker.cancellation.send_replace(true);
        }
        if let Some(worker) = self.peer_reflexive_workers.remove(peer_id) {
            worker.cancellation.send_replace(true);
        }
    }

    fn is_current(&self, peer_id: &str, pending_id: u64) -> bool {
        self.pending_ids.get(peer_id).copied() == Some(pending_id)
    }

    fn responder_cache_lookup(
        &mut self,
        peer_id: &str,
        token: &str,
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
            worker.queued = Some(offer);
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
    fn take_queued_responder_work(&mut self, peer_id: &str, owner: u64) -> Option<PendingPeerOffer> {
        let worker = self.responder_workers.get_mut(peer_id)?;
        if worker.owner != owner || *worker.cancellation.borrow() {
            return None;
        }
        worker.queued.take()
    }

    /// Return the newest queued offer, if any, while retaining the same
    /// worker ownership.  If there is no queued offer, release the worker.
    /// A stale worker that was cancelled/cleared cannot release a replacement
    /// because its owner token no longer matches.
    fn finish_responder_work(
        &mut self,
        peer_id: &str,
        owner: u64,
    ) -> Option<PendingPeerOffer> {
        let worker = self.responder_workers.get_mut(peer_id)?;
        if worker.owner != owner || *worker.cancellation.borrow() {
            return None;
        }
        if let Some(next) = worker.queued.take() {
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
            worker.queued = Some(work);
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
