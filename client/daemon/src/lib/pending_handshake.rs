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
    }

    fn is_current(&self, peer_id: &str, pending_id: u64) -> bool {
        self.pending_ids.get(peer_id).copied() == Some(pending_id)
    }
}
