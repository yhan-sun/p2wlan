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
    pending_ids: HashMap<String, u64>,
    next_id: u64,
    /// Number of initiation attempts per peer (bounded retries).
    attempts: HashMap<String, u32>,
    /// Exact responder answers keyed by `(peer, handshake token)`. Noise
    /// responder messages are randomized, so duplicate offers must replay the
    /// same bytes and key material rather than generate a second session.
    responder_cache: HashMap<(String, String), CachedResponderHandshake>,
}

impl PendingHandshakeState {
    /// Atomically claim the right to prepare a new initiator for `peer_id`.
    ///
    /// A caller must later either commit it with `insert_reserved` or release
    /// it with `cancel_reservation`.
    fn reserve_start(&mut self, peer_id: &str) -> bool {
        if self.pending.contains_key(peer_id) || self.starting.contains(peer_id) {
            return false;
        }
        self.starting.insert(peer_id.to_string());
        true
    }

    fn cancel_reservation(&mut self, peer_id: &str) {
        self.starting.remove(peer_id);
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
        Some(self.insert(peer_id, initiator, session_id, probe_ephemeral))
    }

    fn insert(
        &mut self,
        peer_id: String,
        initiator: HandshakeInitiator,
        session_id: Option<String>,
        probe_ephemeral: Option<DhKeyPair>,
    ) -> u64 {
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
        self.pending_ids.insert(peer_id, pending_id);
        pending_id
    }

    fn remove(&mut self, peer_id: &str) -> Option<HandshakeInitiator> {
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
}
