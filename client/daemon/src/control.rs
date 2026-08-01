//! Control plane client — connects to the Go control server.
//!
//! Handles:
//! - WebSocket/gRPC connection to the control server
//! - Node registration and authentication
//! - Signaling (exchange of peer offers/answers)
//! - Endpoint updates after NAT detection
//! - Heartbeat / keep-alive
//!
//! ## Protocol
//!
//! The control plane uses a simple JSON-over-WebSocket protocol for signaling,
//! with protobuf available for higher performance in production.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use crate::config::Config;
use crate::error::{DaemonError, Result};
use crate::relay::RelaySelectionDiagnostics;
use rand::Rng;
use serde::{Deserialize, Serialize};
use tokio::sync::{mpsc, oneshot, RwLock};
use tokio::time;
use tracing::{debug, error, info, warn};

mod http;
mod websocket;

#[cfg(test)]
use http::register_device_payload;
use http::{
    create_tunnel, fetch_relay_ticket_http, normalize_http_base_url, obtain_device_credential,
    poll_peers, poll_signals, register_device, send_signal, update_endpoint, SignalSigningIdentity,
    SIGNAL_REST_PROTOCOL_VERSION,
};
use websocket::spawn_signal_websocket;

#[cfg(test)]
use futures_util::SinkExt;
#[cfg(test)]
use http::{
    next_candidate_generation, normalize_signal_candidate_expiry, normalize_signal_punch_at,
    peer_metadata_changed, peer_reflexive_endpoint_from_signal,
};
#[cfg(test)]
use tokio_tungstenite::tungstenite::http::header::{AUTHORIZATION, SEC_WEBSOCKET_PROTOCOL};
#[cfg(test)]
use tokio_tungstenite::tungstenite::http::HeaderValue;
#[cfg(test)]
use tokio_tungstenite::tungstenite::Message as WebSocketMessage;
#[cfg(test)]
use websocket::SIGNAL_WS_PROTOCOL;
#[cfg(test)]
use websocket::{run_signal_websocket, signal_websocket_url};

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

impl ControlClient {
    /// Create a new control client.
    ///
    /// When `enabled` is `false`, the background control loop is not spawned
    /// and no HTTP requests will be made even if a token is present. This is
    /// used for manual/offline mode.
    ///
    /// `config_path` is an optional path to save the config file after
    /// obtaining a device credential (so it persists across restarts).
    ///
    /// Returns the client handle and an event receiver.
    pub fn new(
        config: &Config,
        enabled: bool,
        config_path: Option<PathBuf>,
        relay_selection: Option<Arc<RwLock<RelaySelectionDiagnostics>>>,
    ) -> (Self, mpsc::UnboundedReceiver<ControlEvent>) {
        let (event_tx, event_rx) = mpsc::unbounded_channel();
        let (cmd_tx, mut cmd_rx) = mpsc::unbounded_channel();

        let state = Arc::new(RwLock::new(ClientState {
            registered: false,
            peers: HashMap::new(),
            virtual_ip: None,
            _relay_servers: config.relay.servers.clone(),
        }));

        let client = Self {
            event_tx,
            cmd_tx,
            state: state.clone(),
        };

        if enabled && has_control_credential(config) {
            let config = config.clone();
            let event_tx = client.event_tx.clone();
            let cfg_path = config_path.clone();
            tokio::spawn(async move {
                run_control_loop(
                    config,
                    &event_tx,
                    state,
                    &mut cmd_rx,
                    cfg_path,
                    relay_selection,
                )
                .await;
            });
        }

        (client, event_rx)
    }

    /// Get a snapshot of the known peers.
    pub async fn peers(&self) -> HashMap<String, PeerInfo> {
        self.state.read().await.peers.clone()
    }

    /// Get the assigned virtual IP.
    pub async fn virtual_ip(&self) -> Option<String> {
        self.state.read().await.virtual_ip.clone()
    }

    /// Send our updated endpoint to the control server.
    pub async fn update_endpoint(&self, endpoint: &str, nat_type: &str) -> Result<()> {
        let (response_tx, response_rx) = oneshot::channel();
        self.cmd_tx
            .send(ControlCommand::UpdateEndpoint {
                endpoint: endpoint.to_string(),
                nat_type: nat_type.to_string(),
                response_tx,
            })
            .map_err(|_| DaemonError::ControlPlane("command channel closed".into()))?;
        response_rx.await.map_err(|_| {
            DaemonError::ControlPlane("endpoint update response channel closed".into())
        })?
    }

    /// Send a peer offer (initiate P2P connection).
    pub async fn send_peer_offer(
        &self,
        to_node_id: &str,
        candidates: &[String],
        handshake_init: &[u8],
    ) -> Result<()> {
        self.send_peer_offer_with_sources_and_punch_at(
            to_node_id,
            candidates,
            &HashMap::new(),
            handshake_init,
            None,
        )
        .await
    }

    /// Send a peer offer with optional candidate source metadata.
    pub async fn send_peer_offer_with_sources(
        &self,
        to_node_id: &str,
        candidates: &[String],
        candidate_sources: &HashMap<String, String>,
        handshake_init: &[u8],
    ) -> Result<()> {
        self.send_peer_offer_with_sources_and_punch_at(
            to_node_id,
            candidates,
            candidate_sources,
            handshake_init,
            None,
        )
        .await
    }

    /// Send a peer offer with candidate sources and an optional synchronized punch window.
    pub async fn send_peer_offer_with_sources_and_punch_at(
        &self,
        to_node_id: &str,
        candidates: &[String],
        candidate_sources: &HashMap<String, String>,
        handshake_init: &[u8],
        punch_at_ms: Option<u64>,
    ) -> Result<()> {
        let (response_tx, response_rx) = oneshot::channel();
        self.cmd_tx
            .send(ControlCommand::SendPeerOffer {
                to_node_id: to_node_id.to_string(),
                candidates: candidates.to_vec(),
                session_id: None,
                probe_ephemeral_public_key: None,
                candidate_sources: candidate_sources.clone(),
                handshake_init: handshake_init.to_vec(),
                punch_at_ms,
                response_tx,
            })
            .map_err(|_| DaemonError::ControlPlane("command channel closed".into()))?;
        response_rx
            .await
            .map_err(|_| DaemonError::ControlPlane("peer offer response channel closed".into()))?
    }

    /// Send a peer offer with an explicit traversal session ID.
    #[allow(clippy::too_many_arguments)]
    pub async fn send_peer_offer_with_sources_punch_and_session(
        &self,
        to_node_id: &str,
        candidates: &[String],
        candidate_sources: &HashMap<String, String>,
        handshake_init: &[u8],
        punch_at_ms: Option<u64>,
        session_id: Option<String>,
        probe_ephemeral_public_key: Option<String>,
    ) -> Result<()> {
        let (response_tx, response_rx) = oneshot::channel();
        self.cmd_tx
            .send(ControlCommand::SendPeerOffer {
                to_node_id: to_node_id.to_string(),
                candidates: candidates.to_vec(),
                session_id,
                probe_ephemeral_public_key,
                candidate_sources: candidate_sources.clone(),
                handshake_init: handshake_init.to_vec(),
                punch_at_ms,
                response_tx,
            })
            .map_err(|_| DaemonError::ControlPlane("command channel closed".into()))?;
        response_rx
            .await
            .map_err(|_| DaemonError::ControlPlane("peer offer response channel closed".into()))?
    }

    /// Send a peer answer.
    pub async fn send_peer_answer(
        &self,
        to_node_id: &str,
        candidates: &[String],
        handshake_response: &[u8],
    ) -> Result<()> {
        self.send_peer_answer_with_sources_and_punch_at(
            to_node_id,
            candidates,
            &HashMap::new(),
            handshake_response,
            None,
        )
        .await
    }

    /// Send a peer answer with optional candidate source metadata.
    pub async fn send_peer_answer_with_sources(
        &self,
        to_node_id: &str,
        candidates: &[String],
        candidate_sources: &HashMap<String, String>,
        handshake_response: &[u8],
    ) -> Result<()> {
        self.send_peer_answer_with_sources_and_punch_at(
            to_node_id,
            candidates,
            candidate_sources,
            handshake_response,
            None,
        )
        .await
    }

    /// Send a peer answer with candidate sources and an optional synchronized punch window.
    pub async fn send_peer_answer_with_sources_and_punch_at(
        &self,
        to_node_id: &str,
        candidates: &[String],
        candidate_sources: &HashMap<String, String>,
        handshake_response: &[u8],
        punch_at_ms: Option<u64>,
    ) -> Result<()> {
        self.send_peer_answer_with_sources_and_punch_schedule(
            to_node_id,
            candidates,
            candidate_sources,
            handshake_response,
            punch_at_ms,
            None,
        )
        .await
    }

    /// Send a peer answer while preserving a server-selected rendezvous
    /// deadline from the offer when one is available.
    pub async fn send_peer_answer_with_sources_and_punch_schedule(
        &self,
        to_node_id: &str,
        candidates: &[String],
        candidate_sources: &HashMap<String, String>,
        handshake_response: &[u8],
        punch_at_ms: Option<u64>,
        punch_at_server_ms: Option<u64>,
    ) -> Result<()> {
        let (response_tx, response_rx) = oneshot::channel();
        self.cmd_tx
            .send(ControlCommand::SendPeerAnswer {
                to_node_id: to_node_id.to_string(),
                candidates: candidates.to_vec(),
                session_id: None,
                probe_ephemeral_public_key: None,
                candidate_sources: candidate_sources.clone(),
                handshake_response: handshake_response.to_vec(),
                punch_at_ms,
                punch_at_server_ms,
                response_tx,
            })
            .map_err(|_| DaemonError::ControlPlane("command channel closed".into()))?;
        response_rx
            .await
            .map_err(|_| DaemonError::ControlPlane("peer answer response channel closed".into()))?
    }

    /// Send a peer answer with an explicit traversal session ID.
    #[allow(clippy::too_many_arguments)]
    pub async fn send_peer_answer_with_sources_schedule_and_session(
        &self,
        to_node_id: &str,
        candidates: &[String],
        candidate_sources: &HashMap<String, String>,
        handshake_response: &[u8],
        punch_at_ms: Option<u64>,
        punch_at_server_ms: Option<u64>,
        session_id: Option<String>,
        probe_ephemeral_public_key: Option<String>,
    ) -> Result<()> {
        let (response_tx, response_rx) = oneshot::channel();
        self.cmd_tx
            .send(ControlCommand::SendPeerAnswer {
                to_node_id: to_node_id.to_string(),
                candidates: candidates.to_vec(),
                session_id,
                probe_ephemeral_public_key,
                candidate_sources: candidate_sources.clone(),
                handshake_response: handshake_response.to_vec(),
                punch_at_ms,
                punch_at_server_ms,
                response_tx,
            })
            .map_err(|_| DaemonError::ControlPlane("command channel closed".into()))?;
        response_rx
            .await
            .map_err(|_| DaemonError::ControlPlane("peer answer response channel closed".into()))?
    }

    /// Relay a peer-reflexive source address observed for the target peer.
    pub async fn send_peer_reflexive(
        &self,
        to_node_id: &str,
        observed_endpoint: &str,
        punch_at_ms: Option<u64>,
    ) -> Result<()> {
        let (response_tx, response_rx) = oneshot::channel();
        self.cmd_tx
            .send(ControlCommand::SendPeerReflexive {
                to_node_id: to_node_id.to_string(),
                observed_endpoint: observed_endpoint.to_string(),
                punch_at_ms,
                response_tx,
            })
            .map_err(|_| DaemonError::ControlPlane("command channel closed".into()))?;
        response_rx.await.map_err(|_| {
            DaemonError::ControlPlane("peer-reflexive response channel closed".into())
        })?
    }

    /// Request a port mapping tunnel.
    pub async fn create_tunnel(
        &self,
        protocol: &str,
        local_port: u16,
        remote_port: u16,
    ) -> Result<()> {
        self.cmd_tx
            .send(ControlCommand::CreateTunnel {
                protocol: protocol.to_string(),
                local_port,
                remote_port,
            })
            .map_err(|_| DaemonError::ControlPlane("command channel closed".into()))
    }

    /// Delete a port mapping tunnel.
    pub async fn delete_tunnel(&self, tunnel_id: &str) -> Result<()> {
        self.cmd_tx
            .send(ControlCommand::DeleteTunnel {
                tunnel_id: tunnel_id.to_string(),
            })
            .map_err(|_| DaemonError::ControlPlane("command channel closed".into()))
    }

    /// Shutdown the control client.
    pub async fn shutdown(&self) -> Result<()> {
        let _ = self.cmd_tx.send(ControlCommand::Shutdown);
        Ok(())
    }

    /// Fetch a relay ticket from the control plane.
    /// Returns (ticket_jwt, expires_at_unix).
    pub async fn fetch_relay_ticket(&self, audience: &str, region: &str) -> Result<(String, i64)> {
        let (tx, rx) = tokio::sync::oneshot::channel();
        self.cmd_tx
            .send(ControlCommand::FetchRelayTicket {
                audience: audience.to_string(),
                region: region.to_string(),
                response_tx: tx,
            })
            .map_err(|_| DaemonError::ControlPlane("command channel closed".into()))?;
        let resp = rx
            .await
            .map_err(|_| DaemonError::ControlPlane("ticket fetch cancelled".into()))??;
        Ok((resp.ticket, resp.expires_at))
    }

    /// Process a received control message (internal).
    #[cfg(test)]
    async fn handle_message(&self, msg: ControlMessage) {
        match msg {
            ControlMessage::Registered {
                virtual_ip,
                relay_servers,
            } => {
                let mut state = self.state.write().await;
                state.registered = true;
                state.virtual_ip = Some(virtual_ip.clone());
                state._relay_servers = relay_servers.clone();
                drop(state);

                let _ = self.event_tx.send(ControlEvent::Registered {
                    node_id: None,
                    virtual_ip,
                    cidr: Some("10.20.0.0/16".to_string()),
                    relay_servers,
                    relay_catalog: Vec::new(),
                });
            }

            ControlMessage::PeerJoin {
                node_id,
                public_key,
                endpoint,
                nat_type,
                virtual_ip,
            } => {
                let peer = PeerInfo {
                    node_id: node_id.clone(),
                    device_name: String::new(),
                    app_version: String::new(),
                    public_key,
                    endpoint,
                    nat_type,
                    virtual_ip,
                    online: true,
                    last_seen: std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_secs(),
                    relay_rtt_ms: None,
                };

                self.state
                    .write()
                    .await
                    .peers
                    .insert(node_id.clone(), peer.clone());
                let _ = self.event_tx.send(ControlEvent::PeerJoined(peer));
            }

            ControlMessage::PeerLeave { node_id } => {
                if let Some(mut peer) = self.state.write().await.peers.remove(&node_id) {
                    peer.online = false;
                }
                let _ = self.event_tx.send(ControlEvent::PeerLeft(node_id));
            }

            ControlMessage::PeerOffer {
                from_node_id,
                candidates,
                session_id,
                probe_ephemeral_public_key,
                candidate_sources,
                candidate_generation,
                candidates_expires_at_ms,
                handshake_init,
                punch_at_ms,
                ..
            } => {
                let _ = self.event_tx.send(ControlEvent::PeerOffer {
                    from_node_id,
                    candidates,
                    session_id,
                    probe_ephemeral_public_key,
                    candidate_sources,
                    candidate_generation,
                    candidates_expires_at_ms,
                    handshake_init,
                    punch_at_ms,
                    punch_at_server_ms: None,
                });
            }

            ControlMessage::PeerAnswer {
                from_node_id,
                candidates,
                session_id,
                probe_ephemeral_public_key,
                candidate_sources,
                candidate_generation,
                candidates_expires_at_ms,
                handshake_response,
                punch_at_ms,
                ..
            } => {
                let _ = self.event_tx.send(ControlEvent::PeerAnswer {
                    from_node_id,
                    candidates,
                    session_id,
                    probe_ephemeral_public_key,
                    candidate_sources,
                    candidate_generation,
                    candidates_expires_at_ms,
                    handshake_response,
                    punch_at_ms,
                    punch_at_server_ms: None,
                });
            }

            ControlMessage::PeerReflexive {
                from_node_id,
                observed_endpoint,
                punch_at_ms,
                ..
            } => {
                let _ = self.event_tx.send(ControlEvent::PeerReflexive {
                    from_node_id,
                    observed_endpoint,
                    punch_at_ms,
                });
            }

            ControlMessage::PeerReject {
                from_node_id,
                reason,
                ..
            } => {
                let _ = self.event_tx.send(ControlEvent::PeerRejected {
                    from_node_id,
                    reason,
                });
            }

            ControlMessage::TunnelCreated {
                tunnel_id,
                public_endpoint,
            } => {
                let _ = self.event_tx.send(ControlEvent::TunnelCreated {
                    tunnel_id,
                    public_endpoint,
                });
            }

            ControlMessage::Error { code, message } => {
                warn!("Control server error: {} - {}", code, message);
                let _ = self
                    .event_tx
                    .send(ControlEvent::ServerError { code, message });
            }

            ControlMessage::HeartbeatAck { timestamp } => {
                debug!("Heartbeat ack for timestamp {}", timestamp);
            }

            _ => {
                debug!("Unhandled control message: {:?}", msg);
            }
        }
    }
}

fn has_control_credential(config: &Config) -> bool {
    !config.control.auth_token.trim().is_empty()
        || !config.control.device_credential.trim().is_empty()
}

/// Maximum exponential-backoff delay before giving up.
const MAX_BACKOFF_SECS: u64 = 300;
const INITIAL_BACKOFF_SECS: u64 = 2;
/// Signaling carries WireGuard handshake offers/answers. Keep it close to
/// continuous long-polling so early responses do not wait almost a full second
/// for the next tick before scheduling the synchronized UDP punch window.
const SIGNAL_LONG_POLL_WAIT_MS: u64 = 900;
const SIGNAL_FALLBACK_TICK: Duration = Duration::from_secs(1);
const SIGNAL_WS_RECONCILE_INTERVAL: Duration = Duration::from_secs(30);
const SIGNAL_WS_WAKE_QUEUE: usize = 32;
const MIN_PEER_POLL_INTERVAL_SECS: u64 = 5;

/// Compute exponential backoff with jitter, capped at MAX_BACKOFF_SECS.
/// attempt 0 → ~2s, attempt 1 → ~4s, attempt 2 → ~8s, …
fn backoff_delay(attempt: u32) -> Duration {
    let exp = attempt.min(8);
    let base = INITIAL_BACKOFF_SECS
        .saturating_mul(1u64 << exp)
        .min(MAX_BACKOFF_SECS);
    let jitter = rand::thread_rng().gen_range(0.0..=0.5) * base as f64;
    Duration::from_secs_f64(base as f64 + jitter)
}

fn is_permanent_auth_error(err: &str) -> bool {
    // Explicit HTTP 401/403 from our error messages.
    err.contains("HTTP 401")
        || err.contains("HTTP 403")
        || err.contains("register request returned HTTP 401")
        || err.contains("register request returned HTTP 403")
        || err.contains("list nodes request returned HTTP 401")
        || err.contains("list nodes request returned HTTP 403")
        || err.contains("list signals returned HTTP 401")
        || err.contains("list signals returned HTTP 403")
        || err.contains("permanent auth")
}

async fn current_relay_rtt_ms(
    relay_selection: Option<&Arc<RwLock<RelaySelectionDiagnostics>>>,
) -> Option<u64> {
    let relay_selection = relay_selection?;
    let diagnostics = relay_selection.read().await;
    diagnostics
        .selected_rtt_ewma_ms
        .or(diagnostics.selected_last_pong_rtt_ms)
        .or(diagnostics.selected_connect_latency_ms)
}

async fn run_control_loop(
    mut config: Config,
    event_tx: &mpsc::UnboundedSender<ControlEvent>,
    state: Arc<RwLock<ClientState>>,
    cmd_rx: &mut mpsc::UnboundedReceiver<ControlCommand>,
    config_path: Option<PathBuf>,
    relay_selection: Option<Arc<RwLock<RelaySelectionDiagnostics>>>,
) {
    let http = reqwest::Client::new();
    let base_url = normalize_http_base_url(&config.control.server_url);

    // Prefer an existing device credential; fall back to user JWT for first registration.
    let mut token = if !config.control.device_credential.trim().is_empty() {
        config.control.device_credential.clone()
    } else {
        config.control.auth_token.clone()
    };
    let user_token = if !config.control.auth_token.trim().is_empty() {
        config.control.auth_token.clone()
    } else {
        token.clone()
    };
    let signal_signing_identity = SignalSigningIdentity::from_config(&config);

    info!("Connecting to control plane at {base_url}");

    // Outer recovery loop: re-registers after transient disconnects.
    loop {
        // ---- Registration with exponential backoff ----
        let self_node_id = {
            let mut attempt: u32 = 0;
            loop {
                match register_device(&http, &base_url, &token, &config).await {
                    Ok((node_id, virtual_ip, cidr, server_relay_servers, relay_catalog)) => {
                        {
                            let mut s = state.write().await;
                            s.registered = true;
                            s.virtual_ip = Some(virtual_ip.clone());
                        }
                        if !server_relay_servers.is_empty() {
                            config.relay.servers = server_relay_servers.clone();
                        }
                        let mut config_changed = false;
                        if !config.network.manual {
                            if config.network.virtual_ip != virtual_ip {
                                config.network.virtual_ip = virtual_ip.clone();
                                config_changed = true;
                            }
                            if config.network.cidr != cidr {
                                config.network.cidr = cidr.clone();
                                config_changed = true;
                            }
                        }
                        if config_changed {
                            if let Some(ref path) = config_path {
                                if let Err(e) = config.save_to_file(path) {
                                    warn!("Failed to save control-assigned network config: {e}");
                                }
                            }
                        }
                        let relay_servers = if server_relay_servers.is_empty() {
                            config.relay.servers.clone()
                        } else {
                            server_relay_servers
                        };

                        let _ = event_tx.send(ControlEvent::Registered {
                            node_id: Some(node_id.clone()),
                            virtual_ip: virtual_ip.clone(),
                            cidr: Some(cidr.clone()),
                            relay_servers,
                            relay_catalog,
                        });

                        // Attempt Ed25519 challenge for device credential
                        if !config.control.credential_issued
                            && !config.node.ed25519_private_key.is_empty()
                            && !config.node.ed25519_public_key.is_empty()
                        {
                            info!("Attempting Ed25519 challenge for device credential...");
                            match obtain_device_credential(
                                &http,
                                &base_url,
                                &user_token,
                                &node_id,
                                &config.node.ed25519_private_key,
                                &config.node.ed25519_public_key,
                            )
                            .await
                            {
                                Ok(device_credential) => {
                                    info!("Device credential obtained successfully");
                                    config.control.device_credential = device_credential.clone();
                                    config.control.credential_issued = true;
                                    token = device_credential;
                                    if let Some(ref path) = config_path {
                                        if let Err(e) = config.save_to_file(path) {
                                            warn!(
                                                "Failed to save config with device credential: {e}"
                                            );
                                        }
                                    }
                                }
                                Err(e) => {
                                    warn!("Failed to obtain device credential (non-fatal): {e}");
                                }
                            }
                        }

                        break node_id;
                    }
                    Err(err) => {
                        let err_str = err.to_string();
                        if is_permanent_auth_error(&err_str) {
                            if token != user_token && !user_token.trim().is_empty() {
                                warn!(
                                    "Stored device credential was rejected; retrying registration with user token"
                                );
                                token = user_token.clone();
                                config.control.device_credential.clear();
                                config.control.credential_issued = false;
                                continue;
                            }
                            error!(
                                "Control registration permanent auth failure — re-authentication required: {err_str}"
                            );
                            let _ =
                                event_tx.send(ControlEvent::ReauthRequired { message: err_str });
                            // Stop fast retries; wait for Shutdown or a long pause then re-check.
                            loop {
                                tokio::select! {
                                    Some(cmd) = cmd_rx.recv() => {
                                        if matches!(cmd, ControlCommand::Shutdown) {
                                            let _ = event_tx.send(ControlEvent::Disconnected);
                                            return;
                                        }
                                    }
                                    _ = tokio::time::sleep(Duration::from_secs(60)) => {
                                        // Allow operator to fix credentials and retry once per minute.
                                        warn!("Retrying registration after permanent-auth cooldown");
                                        break;
                                    }
                                    else => {
                                        let _ = event_tx.send(ControlEvent::Disconnected);
                                        return;
                                    }
                                }
                            }
                            // After cooldown, try again (outer attempt loop).
                            continue;
                        }

                        attempt = attempt.saturating_add(1);
                        let delay = backoff_delay(attempt.saturating_sub(1));
                        warn!(
                            "Control registration failed (attempt {attempt}); retrying in {delay:?}: {err_str}"
                        );
                        // Interruptible sleep so Shutdown is honoured.
                        tokio::select! {
                            _ = tokio::time::sleep(delay) => {}
                            Some(cmd) = cmd_rx.recv() => {
                                if matches!(cmd, ControlCommand::Shutdown) {
                                    let _ = event_tx.send(ControlEvent::Disconnected);
                                    return;
                                }
                            }
                            else => {
                                let _ = event_tx.send(ControlEvent::Disconnected);
                                return;
                            }
                        }
                    }
                }
            }
        };

        // ---- Polling cycle ----
        // Initial poll
        if let Err(err) = poll_peers(
            &http,
            &base_url,
            &token,
            &config,
            &self_node_id,
            &state,
            event_tx,
        )
        .await
        {
            warn!("Initial peer polling failed: {err}");
            let _ = event_tx.send(ControlEvent::Disconnected);
        } else {
            let _ = event_tx.send(ControlEvent::ControlHealthy);
        }
        if let Err(err) = poll_signals(&http, &base_url, &token, &self_node_id, event_tx, 0).await {
            warn!("Initial signal polling failed: {err}");
            let _ = event_tx.send(ControlEvent::Disconnected);
        } else {
            let _ = event_tx.send(ControlEvent::ControlHealthy);
        }

        let signal_ws_connected = Arc::new(AtomicBool::new(false));
        let (signal_wake_tx, mut signal_wake_rx) = mpsc::channel(SIGNAL_WS_WAKE_QUEUE);
        let signal_ws_task = token.starts_with("dc-").then(|| {
            spawn_signal_websocket(
                &base_url,
                &token,
                &self_node_id,
                &config.network.network_id,
                signal_wake_tx.clone(),
                signal_ws_connected.clone(),
            )
        });
        drop(signal_wake_tx);

        let peer_interval_secs = config
            .control
            .heartbeat_interval_secs
            .max(MIN_PEER_POLL_INTERVAL_SECS);
        let mut peer_tick = time::interval(Duration::from_secs(peer_interval_secs));
        peer_tick.set_missed_tick_behavior(time::MissedTickBehavior::Skip);
        let mut signal_tick = time::interval(SIGNAL_FALLBACK_TICK);
        signal_tick.set_missed_tick_behavior(time::MissedTickBehavior::Skip);
        let mut last_signal_reconcile = Instant::now();

        let mut poll_failures: u32 = 0;
        let mut signal_failures: u32 = 0;
        let mut advertised_endpoint = String::new();
        let mut advertised_nat_type = "unknown".to_string();
        loop {
            tokio::select! {
                _ = peer_tick.tick() => {
                    let relay_rtt_ms = current_relay_rtt_ms(relay_selection.as_ref()).await;
                    if let Err(err) = update_endpoint(
                        &http,
                        &base_url,
                        &token,
                        &self_node_id,
                        &advertised_endpoint,
                        &advertised_nat_type,
                        relay_rtt_ms,
                    )
                    .await
                    {
                        warn!("Device lease refresh failed: {err}");
                    }
                    let poll_result = poll_peers(&http, &base_url, &token, &config, &self_node_id, &state, event_tx).await;
                    match &poll_result {
                        Err(e) => {
                            let err_str = e.to_string();
                            if is_permanent_auth_error(&err_str) {
                                error!("Permanent auth failure during polling: {err_str}");
                                let _ = event_tx.send(ControlEvent::ReauthRequired {
                                    message: err_str,
                                });
                                tokio::select! {
                                    Some(cmd) = cmd_rx.recv() => {
                                        if matches!(cmd, ControlCommand::Shutdown) {
                                            let _ = event_tx.send(ControlEvent::Disconnected);
                                            return;
                                        }
                                    }
                                    _ = tokio::time::sleep(Duration::from_secs(60)) => {}
                                    else => {
                                        let _ = event_tx.send(ControlEvent::Disconnected);
                                        return;
                                    }
                                }
                                break;
                            }
                            poll_failures = poll_failures.saturating_add(1);
                            let delay = backoff_delay(poll_failures.saturating_sub(1));
                            warn!("Polling failed (attempt {poll_failures}); retrying in {delay:?}: {err_str}");
                            let _ = event_tx.send(ControlEvent::Disconnected);
                            // After several consecutive failures, force a full re-register
                            // so device session and peer map are refreshed after control restart.
                            if poll_failures >= 3 {
                                warn!("Polling failed {poll_failures} times; re-registering with control plane");
                                break;
                            }
                            tokio::time::sleep(delay).await;
                        }
                        Ok(_) => {
                            if poll_failures > 0 {
                                info!("Polling recovered after {poll_failures} failures");
                                let vip = state.read().await.virtual_ip.clone().unwrap_or_default();
                                let _ = event_tx.send(ControlEvent::ControlRecovered {
                                    node_id: Some(self_node_id.clone()),
                                    virtual_ip: vip,
                                    cidr: None,
                                });
                            }
                            poll_failures = 0;
                            let _ = event_tx.send(ControlEvent::ControlHealthy);
                        }
                    }
                }
                Some(()) = signal_wake_rx.recv() => {
                    match poll_signals(&http, &base_url, &token, &self_node_id, event_tx, 0).await {
                        Ok(()) => {
                            signal_failures = 0;
                            last_signal_reconcile = Instant::now();
                            let _ = event_tx.send(ControlEvent::ControlHealthy);
                        }
                        Err(e) => {
                            let err_str = e.to_string();
                            if is_permanent_auth_error(&err_str) {
                                error!("Permanent auth failure after WebSocket signal wake: {err_str}");
                                let _ = event_tx.send(ControlEvent::ReauthRequired {
                                    message: err_str,
                                });
                                break;
                            }
                            signal_failures = signal_failures.saturating_add(1);
                            warn!("Signal fetch after WebSocket wake failed: {err_str}");
                            let _ = event_tx.send(ControlEvent::Disconnected);
                        }
                    }
                }
                _ = signal_tick.tick() => {
                    let ws_connected = signal_ws_connected.load(Ordering::Acquire);
                    if ws_connected && last_signal_reconcile.elapsed() < SIGNAL_WS_RECONCILE_INTERVAL {
                        continue;
                    }
                    let wait_ms = if ws_connected { 0 } else { SIGNAL_LONG_POLL_WAIT_MS };
                    match poll_signals(&http, &base_url, &token, &self_node_id, event_tx, wait_ms).await {
                        Ok(()) => {
                            signal_failures = 0;
                            if ws_connected {
                                last_signal_reconcile = Instant::now();
                            }
                            let _ = event_tx.send(ControlEvent::ControlHealthy);
                        }
                        Err(e) => {
                            let err_str = e.to_string();
                            if is_permanent_auth_error(&err_str) {
                                error!("Permanent auth failure during signal polling: {err_str}");
                                let _ = event_tx.send(ControlEvent::ReauthRequired {
                                    message: err_str,
                                });
                                tokio::select! {
                                    Some(cmd) = cmd_rx.recv() => {
                                        if matches!(cmd, ControlCommand::Shutdown) {
                                            let _ = event_tx.send(ControlEvent::Disconnected);
                                            return;
                                        }
                                    }
                                    _ = tokio::time::sleep(Duration::from_secs(60)) => {}
                                    else => {
                                        let _ = event_tx.send(ControlEvent::Disconnected);
                                        return;
                                    }
                                }
                                break;
                            }

                            signal_failures = signal_failures.saturating_add(1);
                            warn!(
                                "Signal polling failed (attempt {signal_failures}); continuing: {err_str}"
                            );
                            let _ = event_tx.send(ControlEvent::Disconnected);
                            if signal_failures >= 3 {
                                warn!("Signal polling failed {signal_failures} times; re-registering with control plane");
                                break;
                            }
                        }
                    }
                }
                Some(cmd) = cmd_rx.recv() => {
                    match cmd {
                        ControlCommand::CreateTunnel { protocol, local_port, remote_port } => {
                            let res = create_tunnel(&http, &base_url, &token, &self_node_id, &protocol, local_port, remote_port).await;
                            match res {
                                Ok((tunnel_id, public_endpoint)) => {
                                    let _ = event_tx.send(ControlEvent::TunnelCreated { tunnel_id, public_endpoint });
                                }
                                Err(err) => {
                                    let err_str = err.to_string();
                                    let code = if is_permanent_auth_error(&err_str) { 401u16 } else { 3000u16 };
                                    let _ = event_tx.send(ControlEvent::ServerError { code, message: err_str });
                                    if code == 401 {
                                        break;
                                    }
                                }
                            }
                        }
                        ControlCommand::UpdateEndpoint { endpoint, nat_type, response_tx } => {
                            let relay_rtt_ms = current_relay_rtt_ms(relay_selection.as_ref()).await;
                            let res = update_endpoint(
                                &http,
                                &base_url,
                                &token,
                                &self_node_id,
                                &endpoint,
                                &nat_type,
                                relay_rtt_ms,
                            )
                            .await;
                            match &res {
                                Ok(()) => {
                                    advertised_endpoint = endpoint;
                                    advertised_nat_type = nat_type;
                                    debug!("Updated endpoint for {self_node_id}: {advertised_endpoint} ({advertised_nat_type})");
                                    let _ = event_tx.send(ControlEvent::ControlHealthy);
                                }
                                Err(err) => {
                                    let err_str = err.to_string();
                                    let _ = event_tx.send(ControlEvent::ServerError { code: 2000, message: err_str.clone() });
                                    if is_permanent_auth_error(&err_str) {
                                        break;
                                    }
                                }
                            }
                            let _ = response_tx.send(res);
                        }
                        ControlCommand::SendPeerOffer { to_node_id, candidates, session_id, probe_ephemeral_public_key, candidate_sources, handshake_init, punch_at_ms, response_tx } => {
                            let res = send_signal(&http, &base_url, &token, &self_node_id, &to_node_id, "peer_offer", &candidates, &candidate_sources, &handshake_init, punch_at_ms, None, session_id.as_deref(), probe_ephemeral_public_key.as_deref(), signal_signing_identity.as_ref()).await;
                            match &res {
                                Ok(()) => { debug!("Sent peer offer to {to_node_id} punch_at_ms={punch_at_ms:?}"); }
                                Err(err) => {
                                    let err_str = err.to_string();
                                    let _ = event_tx.send(ControlEvent::ServerError { code: 4000, message: err_str.clone() });
                                    if is_permanent_auth_error(&err_str) {
                                        break;
                                    }
                                }
                            }
                            let _ = response_tx.send(res);
                        }
                        ControlCommand::SendPeerAnswer { to_node_id, candidates, session_id, probe_ephemeral_public_key, candidate_sources, handshake_response, punch_at_ms, punch_at_server_ms, response_tx } => {
                            let res = send_signal(&http, &base_url, &token, &self_node_id, &to_node_id, "peer_answer", &candidates, &candidate_sources, &handshake_response, punch_at_ms, punch_at_server_ms, session_id.as_deref(), probe_ephemeral_public_key.as_deref(), signal_signing_identity.as_ref()).await;
                            match &res {
                                Ok(()) => { debug!("Sent peer answer to {to_node_id} punch_at_ms={punch_at_ms:?}"); }
                                Err(err) => {
                                    let err_str = err.to_string();
                                    let _ = event_tx.send(ControlEvent::ServerError { code: 4001, message: err_str.clone() });
                                    if is_permanent_auth_error(&err_str) {
                                        break;
                                    }
                                }
                            }
                            let _ = response_tx.send(res);
                        }
                        ControlCommand::SendPeerReflexive { to_node_id, observed_endpoint, punch_at_ms, response_tx } => {
                            let candidates = vec![observed_endpoint.clone()];
                            let candidate_sources = HashMap::from([
                                (observed_endpoint.clone(), "peer_reflexive".to_string())
                            ]);
                            let res = send_signal(&http, &base_url, &token, &self_node_id, &to_node_id, "peer_reflexive", &candidates, &candidate_sources, &[], punch_at_ms, None, None, None, None).await;
                            match &res {
                                Ok(()) => {
                                    debug!(
                                        "Sent peer-reflexive observation to {to_node_id}: {observed_endpoint} punch_at_ms={punch_at_ms:?}"
                                    );
                                }
                                Err(err) => {
                                    let err_str = err.to_string();
                                    let _ = event_tx.send(ControlEvent::ServerError { code: 4002, message: err_str.clone() });
                                    if is_permanent_auth_error(&err_str) {
                                        break;
                                    }
                                }
                            }
                            let _ = response_tx.send(res);
                        }
                        ControlCommand::DeleteTunnel { tunnel_id } => {
                            debug!("Tunnel deletion queued locally for {tunnel_id}");
                        }
                        ControlCommand::FetchRelayTicket { audience, region, response_tx } => {
                            let result = fetch_relay_ticket_http(&http, &base_url, &token, &audience, &region).await;
                            let _ = response_tx.send(result);
                        }
                        ControlCommand::Shutdown => {
                            let _ = event_tx.send(ControlEvent::Disconnected);
                            return;
                        }
                    }
                }
                else => {
                    // Command channel closed — exit.
                    let _ = event_tx.send(ControlEvent::Disconnected);
                    return;
                }
            }
        }

        drop(signal_ws_task);

        // Reached here by breaking the poll loop (auth failure or consecutive poll failures).
        // Mark unregistered so peers are refreshed on next successful register/poll.
        {
            let mut s = state.write().await;
            s.registered = false;
        }
        let _ = event_tx.send(ControlEvent::Disconnected);
        info!("Re-entering control registration cycle");
        // brief pause before re-register to avoid hammering a restarting server
        tokio::time::sleep(Duration::from_secs(1)).await;
    } // end outer loop — will hit the `return` inside on Shutdown, or loop around
}

/// Obtain a device credential via challenge-response.

// ============================================================
// Tests
// ============================================================

#[cfg(test)]
#[path = "control/tests.rs"]
mod tests;
