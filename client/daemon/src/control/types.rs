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
        /// Sender identity fingerprint (public key) bound to the signal at
        /// send time by the control server.  A signal sent by an OLD identity
        /// must never enter a NEW identity's fresh-prediction high-water.
        sender_public_key: Option<String>,
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
        /// Sender identity fingerprint bound to the signal at send time.
        sender_public_key: Option<String>,
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
    /// The durable control-plane receipt.  A successful HTTP response is not
    /// itself a receiver receipt, but this row identity lets both ends prove
    /// which queued signal was created when correlating a later delivery.
    #[serde(default)]
    signal: Option<SignalCreateReceipt>,
    error: Option<String>,
}

#[derive(Debug, Deserialize)]
struct SignalCreateReceipt {
    #[serde(default)]
    id: Option<String>,
    #[serde(default)]
    from_node_id: Option<String>,
    #[serde(default)]
    to_node_id: Option<String>,
    #[serde(rename = "type", default)]
    signal_type: Option<String>,
    #[serde(default)]
    signal_seq: Option<u64>,
}

#[derive(Debug, Deserialize)]
struct ListSignalsResponse {
    #[serde(default)]
    signals: Vec<SignalResponse>,
    #[serde(default)]
    protocol_version: Option<u8>,
    #[serde(default)]
    server_time_ms: Option<u64>,
    /// Present only in ACK mode: the delivery lease metadata of this batch.
    #[serde(default)]
    delivery: Option<SignalDelivery>,
}

#[derive(Debug, Deserialize)]
struct SignalDelivery {
    #[serde(default)]
    batch_token: String,
    #[serde(default)]
    lease_expires_at_ms: Option<u64>,
}

fn default_signal_rest_protocol_version() -> u8 {
    SIGNAL_REST_PROTOCOL_VERSION
}

#[derive(Debug, Deserialize)]
struct SignalResponse {
    #[serde(default)]
    id: Option<String>,
    from_node_id: String,
    /// Older control servers did not expose the target/sequence in their
    /// response.  When present, the receiver validates the target before it
    /// acknowledges a lease; this prevents a server-side routing regression
    /// from being silently turned into a successful delivery.
    #[serde(default)]
    to_node_id: Option<String>,
    #[serde(default)]
    signal_seq: Option<u64>,
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
    #[serde(default)]
    sender_public_key: Option<String>,
    #[serde(default)]
    delivery_token: Option<String>,
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
    /// Bounded lane for initiator offers that carry real WireGuard handshake
    /// bytes.  It is serviced by a separate worker so a slow
    /// candidate-only/peer-reflexive POST can never hold an offer behind the
    /// ordinary FIFO.
    critical_offer_tx: mpsc::Sender<CriticalOfferCommand>,
    /// Bounded, answer-priority lane for responder answers.  Answers have
    /// their own concurrency budget and are dispatched ahead of offers, so a
    /// slow offer or its retries can never delay a later answer.
    critical_answer_tx: mpsc::Sender<CriticalAnswerCommand>,
    /// Bounded lane for the short control transactions a handshake depends on
    /// (endpoint publish) plus worker shutdown.
    critical_ctrl_tx: mpsc::Sender<CriticalControlCommand>,
    /// Bounded lane for candidate-only and fresh-mapping advertisements.
    /// Each target peer gets its own FIFO worker in the independent control
    /// runtime, so a slow candidate POST cannot block roster polling or other
    /// peers.
    candidate_offer_tx: mpsc::Sender<CandidateOfferCommand>,
    /// Shared state.
    state: Arc<RwLock<ClientState>>,
    /// Test-only in-process signaling adapter. It preserves the same
    /// candidate-send API while delivering the resulting control event to a
    /// second real daemon in an end-to-end harness instead of making HTTP.
    #[cfg(test)]
    test_signal_forwarder: Option<Arc<dyn Fn(TestControlSignal) + Send + Sync>>,
    /// Test-only sender identity and monotonic candidate generation used by
    /// the in-process signaling adapter. The production HTTP server owns
    /// these values on the real signaling path.
    #[cfg(test)]
    test_signal_from_node_id: String,
    #[cfg(test)]
    test_signal_public_key: String,
    #[cfg(test)]
    test_signal_generation: Arc<AtomicU64>,
}

/// One signal delivered by the test-only control-plane adapter.
///
/// This is deliberately shaped like the normalized `ControlEvent::PeerOffer`
/// ingress rather than a direct runtime command: two-peer tests still cross
/// the same daemon control-event boundary as a real server delivery.
#[cfg(test)]
#[derive(Debug, Clone)]
pub(crate) struct TestControlSignal {
    pub(crate) from_node_id: String,
    pub(crate) sender_public_key: String,
    pub(crate) to_node_id: String,
    pub(crate) candidates: Vec<String>,
    pub(crate) session_id: Option<String>,
    pub(crate) candidate_sources: HashMap<String, String>,
    pub(crate) candidate_generation: u64,
    pub(crate) candidates_expires_at_ms: Option<u64>,
    pub(crate) punch_at_ms: Option<u64>,
    pub(crate) handshake_init: Vec<u8>,
}

/// Hard cap for handshake work admitted to the independent control lanes.
/// Bounded queues are intentional: cancellation must release a reservation
/// rather than allowing stale answers to accumulate without limit.
const CRITICAL_OFFER_QUEUE_CAPACITY: usize = 32;
const CRITICAL_ANSWER_QUEUE_CAPACITY: usize = 32;
const CRITICAL_CTRL_QUEUE_CAPACITY: usize = 8;
const CANDIDATE_OFFER_QUEUE_CAPACITY: usize = 32;
/// In-flight ceilings per lane.  The answer lane gets a dedicated budget so
/// it is never blocked behind offer traffic; the two lane ceilings together
/// are the global handshake hard cap.
const CRITICAL_ANSWER_MAX_INFLIGHT: usize = 4;
const CRITICAL_OFFER_MAX_INFLIGHT: usize = 4;
const CRITICAL_CTRL_MAX_INFLIGHT: usize = 2;

/// A failed handshake signal is delivery-ambiguous.  Retry a small, fixed
/// number of times with the exact same prepared payload, then return the
/// error to the owner.  This keeps a transient control-plane hiccup from
/// losing the only responder answer without creating an unbounded storm.
const CRITICAL_SIGNAL_MAX_ATTEMPTS: usize = 3;
const CRITICAL_SIGNAL_RETRY_DELAYS: [std::time::Duration; 2] = [
    std::time::Duration::from_millis(100),
    std::time::Duration::from_millis(250),
];
/// Hard wall-clock deadline for the whole critical send including its
/// retries.  A successful round must never become a 3 x 5 s retry sequence:
/// the overall deadline is the binding constraint, per-attempt timeouts are
/// only incidental.
const CRITICAL_SIGNAL_OVERALL_DEADLINE: std::time::Duration =
    std::time::Duration::from_secs(8);

/// Authentication identity published by the registration loop to the
/// latency-sensitive worker.  The server-assigned node id is authoritative;
/// the configured local id is deliberately not used for signal sends.
#[derive(Clone)]
struct CriticalControlAuth {
    base_url: String,
    token: String,
    self_node_id: String,
    signal_signing_identity: Option<SignalSigningIdentity>,
}

impl CriticalControlAuth {
    /// Whether this identity is still the one the registration loop last
    /// published.  A re-registration replaces the auth atomically; stale
    /// owners must never send a new session's signal with an old node id.
    fn same_identity_as(&self, other: &CriticalControlAuth) -> bool {
        self.base_url == other.base_url
            && self.token == other.token
            && self.self_node_id == other.self_node_id
    }
}

/// An initiator offer that carries actual WireGuard handshake bytes.  These
/// bypass the ordinary candidate-only FIFO.
struct CriticalOfferCommand {
    to_node_id: String,
    candidates: Vec<String>,
    session_id: Option<String>,
    probe_ephemeral_public_key: Option<String>,
    candidate_sources: HashMap<String, String>,
    handshake_init: Vec<u8>,
    punch_at_ms: Option<u64>,
    response_tx: oneshot::Sender<PeerOfferSendOutcome>,
}

/// A responder answer carrying actual WireGuard handshake bytes.  The
/// answer-priority lane guarantees a later answer never waits behind an
/// earlier offer or answer; dropping the response receiver (owner cancelled
/// or replaced) aborts queued and in-flight work without affecting a newer
/// owner.
struct CriticalAnswerCommand {
    to_node_id: String,
    candidates: Vec<String>,
    session_id: Option<String>,
    probe_ephemeral_public_key: Option<String>,
    candidate_sources: HashMap<String, String>,
    handshake_response: Vec<u8>,
    punch_at_ms: Option<u64>,
    punch_at_server_ms: Option<u64>,
    response_tx: oneshot::Sender<Result<()>>,
}

/// Short control transactions used by handshake work, plus shutdown.
enum CriticalControlCommand {
    /// Publish the endpoint needed after a responder answer was issued.
    UpdateEndpoint {
        endpoint: String,
        nat_type: String,
        response_tx: oneshot::Sender<Result<()>>,
    },
    /// Stop the worker during daemon shutdown.
    Shutdown,
}

/// Response for a relay ticket fetch.
struct FetchRelayTicketResponse {
    ticket: String,
    expires_at: i64,
}

/// Outcome of one peer-offer send attempt through the control plane.
///
/// The HTTP worker distinguishes "cancelled before anything reached the wire"
/// from a real failure: a caller advertising a fresh-mapping prediction must
/// never finalize a durable handoff for a socket whose prediction was never
/// sent, and never treat a cancellation as a successful send.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PeerOfferSendOutcome {
    /// The HTTP request completed and the control server accepted the signal.
    Sent,
    /// The fresh-mapping ownership was revoked before the request reached the
    /// wire: nothing was sent and nothing must be finalized.
    Cancelled,
    /// The request was attempted but failed (HTTP error, decode failure).
    Failed,
}

/// One candidate-only offer queued in the per-peer ordinary signaling lane.
///
/// Candidate refresh and fresh-mapping advertisements must preserve their
/// order for one peer, but they must not make a slow peer hold up signaling
/// for every other peer.  The registration-scoped worker owns the HTTP
/// context; this value contains only the immutable request data and the
/// caller's completion channel.
struct CandidateOfferCommand {
    to_node_id: String,
    candidates: Vec<String>,
    session_id: Option<String>,
    probe_ephemeral_public_key: Option<String>,
    candidate_sources: HashMap<String, String>,
    handshake_init: Vec<u8>,
    punch_at_ms: Option<u64>,
    fresh_ownership: Option<Arc<crate::PunchSessionCancellation>>,
    response_tx: oneshot::Sender<PeerOfferSendOutcome>,
}

/// Why a peer-offer send did not place the signal on the wire.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PeerOfferSendFailure {
    /// The fresh-mapping ownership was revoked before the HTTP request: the
    /// prediction was never sent and no durable handoff may be finalized.
    Cancelled,
    /// The HTTP request was attempted but the control server did not accept it.
    SendFailed,
    /// The command channel or response channel closed.
    ChannelClosed,
}

impl std::fmt::Display for PeerOfferSendFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Cancelled => write!(f, "peer offer cancelled before send"),
            Self::SendFailed => write!(f, "peer offer send failed"),
            Self::ChannelClosed => write!(f, "peer offer command channel closed"),
        }
    }
}

/// Commands sent to the control client background task.
enum ControlCommand {
    /// Update our endpoint (after NAT detection).
    UpdateEndpoint {
        endpoint: String,
        nat_type: String,
        response_tx: oneshot::Sender<Result<()>>,
    },
    /// Send a relay-assisted peer-reflexive observation.
    SendPeerReflexive {
        to_node_id: String,
        observed_endpoint: String,
        punch_at_ms: Option<u64>,
        response_tx: oneshot::Sender<Result<()>>,
    },
    /// Immediately refresh the peer list.
    ///
    /// Sent when a signal arrives from a peer that is not yet registered:
    /// the regular peer roster poll can be up to one second away,
    /// and a cold-start handshake must not wait out that cadence.
    PollPeersNow,
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
