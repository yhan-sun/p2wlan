// ============================================================
// Peer Connection
// ============================================================

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
    /// Short window after a local generation change where previous Direct peers
    /// are reprobed aggressively before returning to normal retry backoff.
    direct_reclaim_until: Option<Instant>,
    /// Direct candidate-pair reachability table.
    pub candidate_pairs: Vec<CandidatePair>,
    /// Last selector decision made for outbound peer traffic.
    pub last_path_selection: Option<PathSelection>,
    /// Recent real outbound path-selector transitions.
    pub path_events: Vec<PathSelectionEvent>,
    /// Recent direct traversal timeline events.
    pub direct_events: Vec<DirectTraversalEvent>,
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
            direct_reclaim_until: None,
            candidate_pairs: Vec::new(),
            last_path_selection: None,
            path_events: Vec::new(),
            direct_events: Vec::new(),
        }
    }

    fn reset_for_identity_change(&mut self) {
        self.endpoint = self.signaled_endpoint;
        self.probe_session_id = None;
        self.probe_ephemeral_shared = None;
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
        self.candidate_pairs.clear();
        self.last_path_selection = None;
        self.path_events.clear();
        self.direct_events.clear();
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
}
