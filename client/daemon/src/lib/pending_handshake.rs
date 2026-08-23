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
struct HandshakeStartReservation {
    owner: u64,
    network_generation: u64,
    peer_session_generation: PeerSessionGeneration,
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
    /// Latest authenticated WireGuard initiation timestamp per peer/static
    /// identity. Responder objects are deliberately short-lived, so replay
    /// state must outlive an individual Noise transaction. Keeping the static
    /// key with the floor lets a legitimate identity rotation start fresh.
    responder_timestamp_floors: HashMap<String, ([u8; 32], [u8; 12])>,
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
    #[cfg(test)]
    fn reserve_start(&mut self, peer_id: &str) -> bool {
        self.reserve_start_with_owner(peer_id).is_some()
    }

    #[cfg(test)]
    fn reserve_start_with_owner(&mut self, peer_id: &str) -> Option<HandshakeStartReservation> {
        self.reserve_start_with_owner_at_generation(peer_id, 0, PeerSessionGeneration::for_test(1))
    }

    fn reserve_start_with_owner_at_generation(
        &mut self,
        peer_id: &str,
        network_generation: u64,
        peer_session_generation: PeerSessionGeneration,
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
            } else {
                return None;
            }
        }
        if self.pending.contains_key(peer_id) || self.starting.contains(peer_id) {
            return None;
        }
        self.next_start_id = self.next_start_id.saturating_add(1);
        let owner = self.next_start_id;
        let (cancellation_tx, cancellation) = tokio::sync::watch::channel(false);
        self.starting.insert(peer_id.to_string());
        self.starting_network_generations
            .insert(peer_id.to_string(), network_generation);
        self.starting_peer_session_generations
            .insert(peer_id.to_string(), peer_session_generation);
        self.starting_ids.insert(peer_id.to_string(), owner);
        self.starting_cancellations
            .insert(peer_id.to_string(), cancellation_tx);
        Some(HandshakeStartReservation {
            owner,
            network_generation,
            peer_session_generation,
            cancellation,
        })
    }

    fn cancel_reservation(&mut self, peer_id: &str) {
        self.starting.remove(peer_id);
        self.starting_network_generations.remove(peer_id);
        self.starting_peer_session_generations.remove(peer_id);
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
