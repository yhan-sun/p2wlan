// ============================================================
// Control Plane Messages
// ============================================================

/// A message sent to or received from the control server.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum ControlMessage {
    /// Register this node with the control server.
    #[serde(rename = "register")]
    Register {
        node_id: String,
        public_key: String,
        device_name: String,
        platform: String,
        network_id: String,
    },

    /// Server confirms registration.
    #[serde(rename = "registered")]
    Registered {
        virtual_ip: String,
        relay_servers: Vec<String>,
    },

    /// A new peer has joined the network.
    #[serde(rename = "peer_join")]
    PeerJoin {
        node_id: String,
        public_key: String,
        endpoint: String,
        nat_type: String,
        virtual_ip: String,
    },

    /// A peer has left the network.
    #[serde(rename = "peer_leave")]
    PeerLeave { node_id: String },

    /// Update our endpoint after NAT detection.
    #[serde(rename = "endpoint_update")]
    EndpointUpdate {
        node_id: String,
        endpoint: String,
        nat_type: String,
    },

    /// Offer to establish a P2P connection.
    #[serde(rename = "peer_offer")]
    PeerOffer {
        from_node_id: String,
        to_node_id: String,
        candidates: Vec<String>,
        #[serde(default)]
        session_id: Option<String>,
        #[serde(default)]
        probe_ephemeral_public_key: Option<String>,
        #[serde(default)]
        probe_ephemeral_signature: Option<String>,
        #[serde(default)]
        candidate_sources: HashMap<String, String>,
        #[serde(default)]
        candidate_generation: u64,
        #[serde(default)]
        candidates_expires_at_ms: Option<u64>,
        #[serde(default)]
        handshake_init: Vec<u8>,
        #[serde(default)]
        punch_at_ms: Option<u64>,
    },

    /// Answer to a peer offer.
    #[serde(rename = "peer_answer")]
    PeerAnswer {
        from_node_id: String,
        to_node_id: String,
        candidates: Vec<String>,
        #[serde(default)]
        session_id: Option<String>,
        #[serde(default)]
        probe_ephemeral_public_key: Option<String>,
        #[serde(default)]
        probe_ephemeral_signature: Option<String>,
        #[serde(default)]
        candidate_sources: HashMap<String, String>,
        #[serde(default)]
        candidate_generation: u64,
        #[serde(default)]
        candidates_expires_at_ms: Option<u64>,
        #[serde(default)]
        handshake_response: Vec<u8>,
        #[serde(default)]
        punch_at_ms: Option<u64>,
    },

    /// Relay-assisted peer-reflexive candidate observation.
    ///
    /// Semantics: `from_node_id` observed `to_node_id`'s UDP source as
    /// `observed_endpoint`. The receiver must treat it as a local candidate,
    /// not as the sender's remote endpoint.
    #[serde(rename = "peer_reflexive")]
    PeerReflexive {
        from_node_id: String,
        to_node_id: String,
        observed_endpoint: String,
        #[serde(default)]
        punch_at_ms: Option<u64>,
    },

    /// Reject a peer connection.
    #[serde(rename = "peer_reject")]
    PeerReject {
        from_node_id: String,
        to_node_id: String,
        reason: String,
    },

    /// Heartbeat (keep-alive).
    #[serde(rename = "heartbeat")]
    Heartbeat { node_id: String, timestamp: u64 },

    /// Heartbeat ack.
    #[serde(rename = "heartbeat_ack")]
    HeartbeatAck { timestamp: u64 },

    /// Port mapping request.
    #[serde(rename = "create_tunnel")]
    CreateTunnel {
        protocol: String,
        local_port: u16,
        remote_port: u16,
    },

    /// Port mapping response.
    #[serde(rename = "tunnel_created")]
    TunnelCreated {
        tunnel_id: String,
        public_endpoint: String,
    },

    /// Delete tunnel request.
    #[serde(rename = "delete_tunnel")]
    DeleteTunnel { tunnel_id: String },

    /// Error from server.
    #[serde(rename = "error")]
    Error { code: u16, message: String },
}

// ============================================================
// Peer Info
// ============================================================

/// Information about a known peer.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct PeerInfo {
    /// Peer node ID.
    pub node_id: String,
    /// Human-readable device name from the control plane.
    #[serde(default)]
    pub device_name: String,
    /// Peer application/daemon version reported by the control plane.
    #[serde(default)]
    pub app_version: String,
    /// Peer public key (hex).
    pub public_key: String,
    /// Peer public endpoint (ip:port).
    pub endpoint: String,
    /// Peer NAT type.
    pub nat_type: String,
    /// Peer virtual IP.
    pub virtual_ip: String,
    /// Whether the peer is currently online.
    pub online: bool,
    /// Last seen timestamp.
    pub last_seen: u64,
    /// Peer-reported RTT to its selected relay server, in milliseconds.
    #[serde(default)]
    pub relay_rtt_ms: Option<u64>,
}

// ============================================================
// Control Plane Client
// ============================================================

/// Events emitted by the control plane client.
#[derive(Debug, Clone)]
pub enum ControlEvent {
    /// Registration confirmed. Contains assigned virtual IP and relay servers.
    Registered {
        /// Server-assigned node ID when registration used the REST control plane.
        node_id: Option<String>,
        virtual_ip: String,
        cidr: Option<String>,
        relay_servers: Vec<String>,
        /// A2: structured relay catalog from control plane.
        relay_catalog: Vec<RelayCatalogEntry>,
    },
    /// A new peer has joined.
    PeerJoined(PeerInfo),
    /// Existing peer metadata changed without changing connection presence.
    PeerUpdated(PeerInfo),
    /// A peer has left.
    PeerLeft(String),
    /// Received a peer offer (ICE candidates for hole punching).
    PeerOffer {
        from_node_id: String,
        candidates: Vec<String>,
        session_id: Option<String>,
        probe_ephemeral_public_key: Option<String>,
        candidate_sources: HashMap<String, String>,
        candidate_generation: u64,
        candidates_expires_at_ms: Option<u64>,
        handshake_init: Vec<u8>,
        punch_at_ms: Option<u64>,
        /// Server-clock deadline backing `punch_at_ms`, when supplied by the
        /// REST signaling endpoint. This keeps offer and answer on one window.
        punch_at_server_ms: Option<u64>,
    },
    /// Received a peer answer.
    PeerAnswer {
        from_node_id: String,
        candidates: Vec<String>,
        session_id: Option<String>,
        probe_ephemeral_public_key: Option<String>,
        candidate_sources: HashMap<String, String>,
        candidate_generation: u64,
        candidates_expires_at_ms: Option<u64>,
        handshake_response: Vec<u8>,
        punch_at_ms: Option<u64>,
        punch_at_server_ms: Option<u64>,
    },
    /// A peer relayed back the UDP source endpoint it observed for us.
    PeerReflexive {
        from_node_id: String,
        observed_endpoint: String,
        punch_at_ms: Option<u64>,
    },
    /// Received a peer reject.
    PeerRejected {
        from_node_id: String,
        reason: String,
    },
    /// Tunnel created.
    TunnelCreated {
        tunnel_id: String,
        public_endpoint: String,
    },
    /// Server error.
    ServerError { code: u16, message: String },
    /// Disconnected from control server.
    Disconnected,
    /// Permanent authentication failure — re-authentication required.
    ReauthRequired { message: String },
    /// Control plane recovered after a disconnect / re-registration.
    ControlRecovered {
        node_id: Option<String>,
        virtual_ip: String,
        cidr: Option<String>,
    },
    /// A lightweight control-plane request succeeded.
    ControlHealthy,
}

/// Control plane client state.
#[derive(Debug)]
struct ClientState {
    /// Whether we are registered.
    registered: bool,
    /// Known peers.
    peers: HashMap<String, PeerInfo>,
    /// Assigned virtual IP.
    virtual_ip: Option<String>,
    /// Available relay servers.
    _relay_servers: Vec<String>,
}

/// Relay catalog entry from control plane.
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
pub struct RelayCatalogEntry {
    pub region: String,
    pub audience: String,
    pub endpoint: String,
    #[serde(default)]
    pub udp_observer_endpoint: Option<String>,
    #[serde(default)]
    pub udp_observer_endpoints: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct RegisterDeviceResponse {
    success: bool,
    node_id: Option<String>,
    virtual_ip: Option<String>,
    cidr: Option<String>,
    #[serde(default)]
    relay_servers: Vec<String>,
    #[serde(default)]
    relay_catalog: Vec<RelayCatalogEntry>,
    error: Option<String>,
}

#[derive(Debug, Deserialize)]
struct ControlErrorResponse {
    error: Option<String>,
}

#[derive(Debug, Deserialize)]
struct ListNodesResponse {
    #[serde(default)]
    nodes: Vec<DeviceResponse>,
}

#[derive(Debug, Deserialize)]
struct DeviceResponse {
    id: String,
    #[serde(default)]
    device_name: String,
    #[serde(default)]
    app_version: String,
    public_key: String,
    #[serde(default)]
    endpoint: String,
    #[serde(default)]
    nat_type: String,
    virtual_ip: String,
    #[serde(default)]
    online: bool,
    #[serde(default)]
    last_seen: u64,
    #[serde(default)]
    relay_rtt_ms: Option<u64>,
}

#[derive(Debug, Deserialize)]
struct CreateTunnelResponse {
    success: bool,
    tunnel_id: Option<String>,
    public_endpoint: Option<String>,
    error: Option<String>,
}

#[derive(Debug, Deserialize)]
struct EndpointUpdateResponse {
    success: bool,
    error: Option<String>,
}

#[derive(Debug, Deserialize)]
struct SignalCreateResponse {
    success: bool,
    #[serde(default)]
    protocol_version: Option<u8>,
    error: Option<String>,
}

#[derive(Debug, Deserialize)]
struct ListSignalsResponse {
    #[serde(default)]
    signals: Vec<SignalResponse>,
    #[serde(default)]
    protocol_version: Option<u8>,
    #[serde(default)]
    server_time_ms: Option<u64>,
}

fn default_signal_rest_protocol_version() -> u8 {
    SIGNAL_REST_PROTOCOL_VERSION
}

#[derive(Debug, Deserialize)]
struct SignalResponse {
    from_node_id: String,
    #[serde(rename = "type")]
    signal_type: String,
    #[serde(default = "default_signal_rest_protocol_version")]
    protocol_version: u8,
    #[serde(default)]
    candidates: Vec<String>,
    #[serde(default)]
    session_id: Option<String>,
    #[serde(default)]
    probe_ephemeral_public_key: Option<String>,
    #[serde(default)]
    candidate_sources: HashMap<String, String>,
    #[serde(default)]
    candidate_generation: u64,
    #[serde(default)]
    candidates_expires_at_ms: Option<u64>,
    #[serde(default)]
    handshake: String,
    #[serde(default)]
    punch_at_ms: Option<u64>,
}

/// Control plane client.
///
/// Connects to the Go control server via WebSocket and handles
/// signaling, peer discovery, and configuration updates.
#[derive(Clone)]
pub struct ControlClient {
    /// Channel to send events to the daemon.
    event_tx: mpsc::UnboundedSender<ControlEvent>,
    /// Channel to send commands to the background task.
    cmd_tx: mpsc::UnboundedSender<ControlCommand>,
    /// Shared state.
    state: Arc<RwLock<ClientState>>,
}

/// Response for a relay ticket fetch.
struct FetchRelayTicketResponse {
    ticket: String,
    expires_at: i64,
}

/// Commands sent to the control client background task.
enum ControlCommand {
    /// Update our endpoint (after NAT detection).
    UpdateEndpoint {
        endpoint: String,
        nat_type: String,
        response_tx: oneshot::Sender<Result<()>>,
    },
    /// Send a peer offer.
    SendPeerOffer {
        to_node_id: String,
        candidates: Vec<String>,
        session_id: Option<String>,
        probe_ephemeral_public_key: Option<String>,
        candidate_sources: HashMap<String, String>,
        handshake_init: Vec<u8>,
        punch_at_ms: Option<u64>,
        response_tx: oneshot::Sender<Result<()>>,
    },
    /// Send a peer answer.
    SendPeerAnswer {
        to_node_id: String,
        candidates: Vec<String>,
        session_id: Option<String>,
        probe_ephemeral_public_key: Option<String>,
        candidate_sources: HashMap<String, String>,
        handshake_response: Vec<u8>,
        punch_at_ms: Option<u64>,
        punch_at_server_ms: Option<u64>,
        response_tx: oneshot::Sender<Result<()>>,
    },
    /// Send a relay-assisted peer-reflexive observation.
    SendPeerReflexive {
        to_node_id: String,
        observed_endpoint: String,
        punch_at_ms: Option<u64>,
        response_tx: oneshot::Sender<Result<()>>,
    },
    /// Create a tunnel.
    CreateTunnel {
        protocol: String,
        local_port: u16,
        remote_port: u16,
    },
    /// Delete a tunnel.
    DeleteTunnel { tunnel_id: String },
    /// Fetch a relay ticket.
    FetchRelayTicket {
        audience: String,
        region: String,
        response_tx: tokio::sync::oneshot::Sender<Result<FetchRelayTicketResponse>>,
    },
    /// Shutdown.
    Shutdown,
}
