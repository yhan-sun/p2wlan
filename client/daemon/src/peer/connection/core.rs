// ============================================================
// Peer Connection
// ============================================================

#[derive(Debug, Clone, PartialEq, Eq)]
struct ProbeSessionBinding {
    token: Option<String>,
    session_id: Option<String>,
    ephemeral_shared: Option<[u8; 32]>,
}

#[derive(Debug, Clone)]
struct RetainedProbeSessionBinding {
    binding: ProbeSessionBinding,
    expires_at: Instant,
}

#[derive(Debug, Clone)]
struct PendingProbeSessionBinding {
    binding: ProbeSessionBinding,
    expires_at: Instant,
    promote_on_match: bool,
}

/// A real decrypted relay business packet can arrive a few milliseconds
/// before this daemon receives the matching encrypted relay-probe ACK.  Keep
/// only that bounded evidence tuple so the later confirmation can complete
/// the proof without replaying the WireGuard ciphertext.
#[derive(Debug, Clone)]
pub(crate) struct PendingRelayBusinessEvidence {
    pub generation: u64,
    pub relay_endpoint: String,
    pub relay_connection_id: Option<u64>,
    pub received_at: Instant,
}

/// The relay-first business gate state for one peer connection.
///
/// This is the set of fields that decide whether Direct may win the data plane
/// after a same-generation relay transport is ready and peer-confirmed.  Grouping
/// them here (instead of flat on [`PeerConnection`]) keeps the legal/illegal
/// state combinations locally contained: the gate is one atomic concept with a
/// bounded set of milestones, not N independent booleans scattered across a
/// 60-field struct.
#[derive(Debug, Clone, Default)]
pub(crate) struct RelayFirstBusinessState {
    /// Generation in which the first-business relay gate began waiting.  This
    /// is distinct from `relay_ready_at`: the gate may start as soon as the
    /// shared relay transport exists, before the per-peer session publishes
    /// its ready milestone.
    pub gate_generation: Option<u64>,
    /// Monotonic start of the bounded first-business relay gate.
    pub gate_started_at: Option<Instant>,
    /// Generation for which at least one real business packet was accepted by
    /// the confirmed relay writer.  Direct may be confirmed in the background,
    /// but it cannot become the first data-plane path until both directions
    /// have crossed the confirmed relay.  The receive marker is kept separately
    /// because a peer can send its first packet over relay, promote Direct, and
    /// then deliver the other direction's first packet directly before this
    /// daemon has itself observed relay business.
    pub business_sent_generation: Option<u64>,
    /// Generation for which a normal decrypted business packet was received
    /// through the confirmed relay.  This closes the bidirectional relay-first
    /// race: local relay writer completion alone cannot authorize Direct for
    /// the other direction.
    pub business_received_generation: Option<u64>,
    /// Generation for which a relay business packet was sent locally and a
    /// normal relay business packet was received.  Writer completion is not a
    /// peer-delivery proof; this two-direction marker is the minimum local
    /// evidence that both directions crossed the confirmed relay before a
    /// Direct data-plane promotion may win.  The two component markers may
    /// arrive in either order.
    pub business_exchange_generation: Option<u64>,
    /// Generation for which a synthetic path-commit probe round-tripped over
    /// the confirmed relay, proving bidirectional relay data without natural
    /// traffic (audit P0-4).  An alternative to `..._exchange_generation` for
    /// closing the relay-first business gate; it does not itself activate
    /// Direct.
    pub business_pathcommit_generation: Option<u64>,
    /// Real relay business ingress observed before local RelayPeerConfirmed.
    /// It is promoted only when the later confirmation matches generation,
    /// endpoint and transport incarnation; any lifecycle reset clears it.
    pub(crate) preconfirmation: Option<PendingRelayBusinessEvidence>,
}

/// Information about a connection to a specific peer.
#[derive(Debug, Clone)]
pub struct PeerConnection {
    /// Peer node ID.
    pub node_id: String,
    /// Human-readable peer device name.
    pub device_name: String,
    /// Peer application/daemon version reported by the control plane.
    pub app_version: String,
    /// Peer's static WireGuard/X25519 public key as hex.
    pub public_key: String,
    /// Symmetric MAC key for authenticated UDP Probe v2.
    pub probe_mac_key: Option<ProbeMacKey>,
    /// Current control-plane session ID used to bind Probe v2 MAC keys.
    pub probe_session_id: Option<String>,
    /// Session-local X25519 shared secret used to rotate Probe v2 MAC keys.
    pub probe_ephemeral_shared: Option<[u8; 32]>,
    /// Opaque handshake token associated with the current Probe-v2 binding.
    probe_binding_token: Option<String>,
    /// Replacement Probe-v2 binding staged transactionally during a handshake.
    pending_probe_bindings: HashMap<String, PendingProbeSessionBinding>,
    /// Prior Probe-v2 binding accepted during a rekey overlap or restored when
    /// publishing the replacement offer fails.
    previous_probe_binding: Option<RetainedProbeSessionBinding>,
    /// Peer's virtual IP.
    pub virtual_ip: String,
    /// Peer's public endpoint (ip:port) if known.
    pub endpoint: Option<SocketAddr>,
    /// Endpoint currently advertised by peer metadata. This is kept separate
    /// from an authenticated peer-reflexive endpoint learned on the wire.
    pub signaled_endpoint: Option<SocketAddr>,
    /// Peer's NAT type.
    pub nat_type: String,
    /// Whether the control plane currently reports this peer online.
    pub online: bool,
    /// Last seen timestamp reported by the control plane.
    pub last_seen: u64,
    /// Peer-reported RTT to its selected relay server, in milliseconds.
    pub remote_relay_rtt_ms: Option<u64>,
    /// Current connection state.
    pub state: ConnectionState,
    /// When the connection was established.
    pub connected_at: Option<Instant>,
    /// Bytes sent to this peer.
    pub bytes_sent: u64,
    /// Bytes received from this peer.
    pub bytes_received: u64,
    /// Which relay server is being used (if connected via relay).
    pub relay_server: Option<String>,
    /// ICE candidates for this peer.
    pub candidates: Vec<String>,
    /// Candidate strings from the most recent peer offer/answer.
    signaled_candidates: HashSet<String>,
    /// Newer candidate sets replace older ones; generation 0 remains valid for
    /// legacy peers that have not yet been upgraded.
    last_candidate_generation: u64,
    last_candidates_expires_at_ms: Option<u64>,
    /// Local-only source metadata keyed by candidate endpoint string.
    pub candidate_sources: HashMap<String, CandidatePairSource>,
    /// Direct UDP path health.
    pub direct_health: PathHealth,
    /// Relay path health.
    pub relay_health: PathHealth,
    /// Local network generation in which the direct path was last confirmed.
    pub direct_generation: u64,
    /// Monotonic direct-commit sequence.  Bumped inside the network-epoch
    /// critical section every time the Direct confirmation changes (promotion
    /// or endpoint change); outbound punch loops gate every actual UDP send
    /// on this sequence.
    pub direct_commit_seq: u64,
    /// Local network generation in which a relay transport first became ready
    /// to carry this peer's traffic (the shared relay slot published an
    /// endpoint while the peer had an encrypting WireGuard session).  This is
    /// the per-peer `RelayTransportConnected` milestone: it is strictly weaker
    /// than [`relay_confirmed_generation`] (a TCP/TLS connect or a queued
    /// registration must never count as delivery).
    pub relay_ready_generation: Option<u64>,
    /// Monotonic instant (daemon-local) of the per-peer relay-ready milestone.
    pub relay_ready_at: Option<Instant>,
    /// Relay endpoint that carried the per-peer relay-ready milestone.
    pub relay_ready_endpoint: Option<String>,
    /// Local relay transport incarnation that carried the per-peer
    /// relay-ready milestone.  The endpoint may be reused by a reconnect, so
    /// endpoint + generation alone is not enough to bind readiness to the
    /// current writer/reader pair.
    pub relay_ready_connection_id: Option<u64>,
    /// Local network generation in which the relay path to this peer was
    /// confirmed by a matching forced-relay encrypted probe/ACK (the ACK's real
    /// ingress was relay).  Never set by a local TCP/TLS connect or by a
    /// command-queue accept.
    pub relay_confirmed_generation: Option<u64>,
    /// Monotonic instant (daemon-local) of the relay peer confirmation.
    pub relay_confirmed_at: Option<Instant>,
    /// Relay endpoint whose ingress carried the confirming ACK.
    pub relay_confirmed_endpoint: Option<String>,
    /// Local relay transport incarnation whose encrypted probe ACK confirmed
    /// the endpoint.  A reconnect/renewal can reuse the same endpoint, so an
    /// endpoint string alone cannot identify the connection that was proven.
    pub relay_confirmed_connection_id: Option<u64>,
    /// Relay-first business gate state (when Direct may win the data plane).
    pub(crate) relay_first: RelayFirstBusinessState,
    /// Monotonic relay-confirm sequence.  Bumped (and mirrored in the peer
    /// manager, notified to outbound waiters) every time the peer's relay
    /// confirmation changes, mirroring [`direct_commit_seq`].
    pub relay_confirm_seq: u64,
    /// Local network generation of the first confirmed usable path
    /// (`RelayPeerConfirmed` or `DirectConfirmed`), the first-business-packet
    /// milestone.
    pub first_usable_generation: Option<u64>,
    /// Monotonic instant (daemon-local) of the first usable path milestone.
    pub first_usable_at: Option<Instant>,
    /// Which path became first usable.
    pub first_usable_path: Option<NetworkPath>,
    /// Short window after a local generation change where previous Direct peers
    /// are reprobed aggressively before returning to normal retry backoff.
    direct_reclaim_until: Option<Instant>,
    /// Direct candidate-pair reachability table.
    pub candidate_pairs: Vec<CandidatePair>,
    /// Wide birthday rank committed by the last fully covered stable-side scan.
    /// Candidate source refreshes and Probe-v2 rekeys intentionally preserve it.
    birthday_probe_cursor: usize,
    /// Last selector decision made for outbound peer traffic.
    pub last_path_selection: Option<PathSelection>,
    /// Recent real outbound path-selector transitions.
    pub path_events: Vec<PathSelectionEvent>,
    /// Recent direct traversal timeline events.
    pub direct_events: Vec<DirectTraversalEvent>,
    /// Shared synchronous Direct-set mirror owned by the PeerManager.  Kept in
    /// lockstep from `transition` and `reset_for_identity_change`, so the UDP
    /// dynamic-socket eviction can re-verify "is this peer Direct?" under its
    /// own socket-state lock without awaiting the async manager there.
    direct_cache: Option<Arc<std::sync::Mutex<HashSet<String>>>>,
}

impl PeerConnection {
    /// Create a new peer connection in Idle state.
    pub fn new(node_id: &str, virtual_ip: &str) -> Self {
        Self {
            node_id: node_id.to_string(),
            device_name: String::new(),
            app_version: String::new(),
            public_key: String::new(),
            probe_mac_key: None,
            probe_session_id: None,
            probe_ephemeral_shared: None,
            probe_binding_token: None,
            pending_probe_bindings: HashMap::new(),
            previous_probe_binding: None,
            virtual_ip: virtual_ip.to_string(),
            endpoint: None,
            signaled_endpoint: None,
            nat_type: String::new(),
            online: true,
            last_seen: 0,
            remote_relay_rtt_ms: None,
            state: ConnectionState::Idle,
            connected_at: None,
            bytes_sent: 0,
            bytes_received: 0,
            relay_server: None,
            candidates: Vec::new(),
            signaled_candidates: HashSet::new(),
            last_candidate_generation: 0,
            last_candidates_expires_at_ms: None,
            candidate_sources: HashMap::new(),
            direct_health: PathHealth::default(),
            relay_health: PathHealth::default(),
            direct_generation: 0,
            direct_commit_seq: 0,
            relay_ready_generation: None,
            relay_ready_at: None,
            relay_ready_endpoint: None,
            relay_ready_connection_id: None,
            relay_confirmed_generation: None,
            relay_confirmed_at: None,
            relay_confirmed_endpoint: None,
            relay_confirmed_connection_id: None,
            relay_first: RelayFirstBusinessState::default(),
            relay_confirm_seq: 0,
            first_usable_generation: None,
            first_usable_at: None,
            first_usable_path: None,
            direct_reclaim_until: None,
            candidate_pairs: Vec::new(),
            birthday_probe_cursor: 0,
            last_path_selection: None,
            path_events: Vec::new(),
            direct_events: Vec::new(),
            direct_cache: None,
        }
    }

    fn reset_for_identity_change(&mut self) {
        self.endpoint = self.signaled_endpoint;
        self.probe_session_id = None;
        self.probe_ephemeral_shared = None;
        self.probe_binding_token = None;
        self.pending_probe_bindings.clear();
        self.previous_probe_binding = None;
        self.candidates.clear();
        self.signaled_candidates.clear();
        self.last_candidate_generation = 0;
        self.last_candidates_expires_at_ms = None;
        self.candidate_sources.clear();
        self.state = ConnectionState::Idle;
        self.connected_at = None;
        self.relay_server = None;
        self.direct_health = PathHealth::default();
        self.relay_health = PathHealth::default();
        self.direct_generation = 0;
        self.direct_reclaim_until = None;
        self.relay_ready_generation = None;
        self.relay_ready_at = None;
        self.relay_ready_endpoint = None;
        self.relay_ready_connection_id = None;
        self.relay_confirmed_generation = None;
        self.relay_confirmed_at = None;
        self.relay_confirmed_endpoint = None;
        self.relay_confirmed_connection_id = None;
        self.relay_first = RelayFirstBusinessState::default();
        self.first_usable_generation = None;
        self.first_usable_at = None;
        self.first_usable_path = None;
        self.candidate_pairs.clear();
        self.birthday_probe_cursor = 0;
        self.last_path_selection = None;
        self.path_events.clear();
        self.direct_events.clear();
        self.sync_direct_cache();
    }

    /// Reset all transport/path state for a new remote daemon session while
    /// retaining the peer's long-lived identity and Probe MAC key.
    ///
    /// A control-plane endpoint change is stronger than a candidate refresh:
    /// the old WireGuard session may still contain a high counter and the old
    /// relay confirmation may still be accepted by local path selection, even
    /// though the remote daemon that owned them has gone away.  The caller
    /// must first stop the transport/UDP workers, then use this reset before
    /// starting the replacement handshake.
    pub(crate) fn reset_for_peer_session(&mut self) {
        self.reset_for_identity_change();
    }

    /// Whether the connection is active (direct or relay).
    pub fn is_active(&self) -> bool {
        matches!(self.state, ConnectionState::Direct | ConnectionState::Relay)
    }

    /// Whether the connection is via relay.
    pub fn is_relay(&self) -> bool {
        self.state == ConnectionState::Relay
    }

    /// Transition to a new state.
    pub fn transition(&mut self, new_state: ConnectionState) {
        if self.state != new_state {
            let previous_state = self.state;
            info!(target: "p2pnet_daemon::peer::connection",
                event = "peer_connection_state_changed",
                peer_id = %self.node_id,
                previous_state = ?previous_state,
                new_state = ?new_state,
                direct_generation = self.direct_generation,
                relay_ready_generation = ?self.relay_ready_generation,
                relay_confirmed_generation = ?self.relay_confirmed_generation,
                relay_confirmed_connection_id = ?self.relay_confirmed_connection_id,
                relay_server = ?self.relay_server,
                direct_endpoint = ?self.endpoint,
                "peer connection state changed peer_id={} previous={:?} new={:?}",
                self.node_id,
                previous_state,
                new_state,
            );
            info!(
                "Peer {} state: {} → {}",
                self.node_id, self.state, new_state
            );
        }
        if (new_state == ConnectionState::Direct || new_state == ConnectionState::Relay)
            && self.connected_at.is_none()
        {
            self.connected_at = Some(Instant::now());
        }
        self.state = new_state;
        self.sync_direct_cache();
    }

    /// Keep the manager's synchronous Direct-set mirror in lockstep with this
    /// connection's state, so the UDP layer can re-verify the nonevictable
    /// set inside its socket-state lock.
    fn sync_direct_cache(&self) {
        let Some(cache) = &self.direct_cache else {
            return;
        };
        let mut cache = cache.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        if self.state == ConnectionState::Direct {
            cache.insert(self.node_id.clone());
        } else {
            cache.remove(&self.node_id);
        }
    }

    /// Attach the manager's synchronous Direct-set mirror (manager-owned).
    pub(crate) fn attach_direct_cache(&mut self, cache: Arc<std::sync::Mutex<HashSet<String>>>) {
        self.direct_cache = Some(cache);
        self.sync_direct_cache();
    }

    /// Current selected traffic path, if active.
    pub fn active_path(&self) -> Option<NetworkPath> {
        match self.state {
            ConnectionState::Direct => Some(NetworkPath::Direct),
            ConnectionState::Relay => Some(NetworkPath::Relay),
            _ => None,
        }
    }

    /// Record bytes sent.
    pub fn record_sent(&mut self, n: u64) {
        self.bytes_sent += n;
    }

    /// Record bytes received.
    pub fn record_received(&mut self, n: u64) {
        self.bytes_received += n;
    }

    /// Record the first usable production ingress for this peer + generation.
    ///
    /// `path` is `Direct` or `Relay`.  The manager caller must supply the
    /// authenticated ingress of a normal decrypted overlay business packet;
    /// path confirmation and transport-local events are not substitutes for
    /// that evidence.  The validation harness may impose an additional
    /// bidirectional nonce/echo requirement before calling this method.
    /// Emits exactly once per peer + generation; later calls in the same
    /// generation no-op.
    pub fn record_first_usable(&mut self, path: NetworkPath, generation: u64) -> bool {
        if self.first_usable_generation == Some(generation) && self.first_usable_at.is_some() {
            return false;
        }
        self.first_usable_generation = Some(generation);
        self.first_usable_at = Some(Instant::now());
        self.first_usable_path = Some(path);
        true
    }
}
