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
use std::sync::Arc;
use std::time::Duration;

use crate::config::Config;
use crate::error::{DaemonError, Result};
use rand::Rng;
use serde::{Deserialize, Serialize};
use tokio::sync::{mpsc, oneshot, RwLock};
use tokio::time;
use tracing::{debug, error, info, warn};

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
        candidate_sources: HashMap<String, String>,
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
        candidate_sources: HashMap<String, String>,
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
        candidate_sources: HashMap<String, String>,
        handshake_init: Vec<u8>,
        punch_at_ms: Option<u64>,
    },
    /// Received a peer answer.
    PeerAnswer {
        from_node_id: String,
        candidates: Vec<String>,
        candidate_sources: HashMap<String, String>,
        handshake_response: Vec<u8>,
        punch_at_ms: Option<u64>,
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
struct ListNodesResponse {
    #[serde(default)]
    nodes: Vec<DeviceResponse>,
}

#[derive(Debug, Deserialize)]
struct DeviceResponse {
    id: String,
    #[serde(default)]
    device_name: String,
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
    error: Option<String>,
}

#[derive(Debug, Deserialize)]
struct ListSignalsResponse {
    #[serde(default)]
    signals: Vec<SignalResponse>,
}

#[derive(Debug, Deserialize)]
struct SignalResponse {
    from_node_id: String,
    #[serde(rename = "type")]
    signal_type: String,
    #[serde(default)]
    candidates: Vec<String>,
    #[serde(default)]
    candidate_sources: HashMap<String, String>,
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
        candidate_sources: HashMap<String, String>,
        handshake_init: Vec<u8>,
        punch_at_ms: Option<u64>,
        response_tx: oneshot::Sender<Result<()>>,
    },
    /// Send a peer answer.
    SendPeerAnswer {
        to_node_id: String,
        candidates: Vec<String>,
        candidate_sources: HashMap<String, String>,
        handshake_response: Vec<u8>,
        punch_at_ms: Option<u64>,
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
                run_control_loop(config, &event_tx, state, &mut cmd_rx, cfg_path).await;
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
        let (response_tx, response_rx) = oneshot::channel();
        self.cmd_tx
            .send(ControlCommand::SendPeerAnswer {
                to_node_id: to_node_id.to_string(),
                candidates: candidates.to_vec(),
                candidate_sources: candidate_sources.clone(),
                handshake_response: handshake_response.to_vec(),
                punch_at_ms,
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
                    public_key,
                    endpoint,
                    nat_type,
                    virtual_ip,
                    online: true,
                    last_seen: std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_secs(),
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
                candidate_sources,
                handshake_init,
                punch_at_ms,
                ..
            } => {
                let _ = self.event_tx.send(ControlEvent::PeerOffer {
                    from_node_id,
                    candidates,
                    candidate_sources,
                    handshake_init,
                    punch_at_ms,
                });
            }

            ControlMessage::PeerAnswer {
                from_node_id,
                candidates,
                candidate_sources,
                handshake_response,
                punch_at_ms,
                ..
            } => {
                let _ = self.event_tx.send(ControlEvent::PeerAnswer {
                    from_node_id,
                    candidates,
                    candidate_sources,
                    handshake_response,
                    punch_at_ms,
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
/// Signaling carries WireGuard handshake offers/answers. Keep it independent
/// from the slower peer/heartbeat poll so handshakes do not race their timeout.
const SIGNAL_POLL_INTERVAL_SECS: u64 = 1;
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

async fn run_control_loop(
    mut config: Config,
    event_tx: &mpsc::UnboundedSender<ControlEvent>,
    state: Arc<RwLock<ClientState>>,
    cmd_rx: &mut mpsc::UnboundedReceiver<ControlCommand>,
    config_path: Option<PathBuf>,
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
                        let relay_servers = if server_relay_servers.is_empty() {
                            config.relay.servers.clone()
                        } else {
                            server_relay_servers
                        };

                        let _ = event_tx.send(ControlEvent::Registered {
                            node_id: Some(node_id.clone()),
                            virtual_ip: virtual_ip.clone(),
                            cidr: Some(cidr),
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
        }
        if let Err(err) = poll_signals(&http, &base_url, &token, &self_node_id, event_tx).await {
            warn!("Initial signal polling failed: {err}");
        }

        let peer_interval_secs = config
            .control
            .heartbeat_interval_secs
            .max(MIN_PEER_POLL_INTERVAL_SECS);
        let mut peer_tick = time::interval(Duration::from_secs(peer_interval_secs));
        peer_tick.set_missed_tick_behavior(time::MissedTickBehavior::Skip);
        let mut signal_tick = time::interval(Duration::from_secs(SIGNAL_POLL_INTERVAL_SECS));
        signal_tick.set_missed_tick_behavior(time::MissedTickBehavior::Skip);

        let mut poll_failures: u32 = 0;
        let mut signal_failures: u32 = 0;
        let mut advertised_endpoint = String::new();
        let mut advertised_nat_type = "unknown".to_string();
        loop {
            tokio::select! {
                _ = peer_tick.tick() => {
                    if let Err(err) = update_endpoint(
                        &http,
                        &base_url,
                        &token,
                        &self_node_id,
                        &advertised_endpoint,
                        &advertised_nat_type,
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
                        }
                    }
                }
                _ = signal_tick.tick() => {
                    match poll_signals(&http, &base_url, &token, &self_node_id, event_tx).await {
                        Ok(()) => {
                            signal_failures = 0;
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
                            let res = update_endpoint(&http, &base_url, &token, &self_node_id, &endpoint, &nat_type).await;
                            match &res {
                                Ok(()) => {
                                    advertised_endpoint = endpoint;
                                    advertised_nat_type = nat_type;
                                    debug!("Updated endpoint for {self_node_id}: {advertised_endpoint} ({advertised_nat_type})");
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
                        ControlCommand::SendPeerOffer { to_node_id, candidates, candidate_sources, handshake_init, punch_at_ms, response_tx } => {
                            let res = send_signal(&http, &base_url, &token, &self_node_id, &to_node_id, "peer_offer", &candidates, &candidate_sources, &handshake_init, punch_at_ms).await;
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
                        ControlCommand::SendPeerAnswer { to_node_id, candidates, candidate_sources, handshake_response, punch_at_ms, response_tx } => {
                            let res = send_signal(&http, &base_url, &token, &self_node_id, &to_node_id, "peer_answer", &candidates, &candidate_sources, &handshake_response, punch_at_ms).await;
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
                            let res = send_signal(&http, &base_url, &token, &self_node_id, &to_node_id, "peer_reflexive", &candidates, &candidate_sources, &[], punch_at_ms).await;
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
async fn obtain_device_credential(
    http: &reqwest::Client,
    base_url: &str,
    user_token: &str,
    device_id: &str,
    ed25519_private_key_hex: &str,
    ed25519_public_key_hex: &str,
) -> Result<String> {
    // Step 1: Request a challenge
    let challenge_resp = http
        .post(format!("{base_url}/api/v1/challenges"))
        .bearer_auth(user_token)
        .json(&serde_json::json!({
            "device_id": device_id,
        }))
        .send()
        .await
        .map_err(|e| DaemonError::ControlPlane(format!("challenge request failed: {e}")))?;

    if !challenge_resp.status().is_success() {
        return Err(DaemonError::ControlPlane(format!(
            "challenge request returned HTTP {}",
            challenge_resp.status()
        )));
    }

    #[derive(Deserialize)]
    #[allow(dead_code)]
    struct ChallengeResponse {
        challenge_id: String,
        challenge: String,
        expires_at: i64,
    }

    let challenge_body: ChallengeResponse = challenge_resp
        .json()
        .await
        .map_err(|e| DaemonError::ControlPlane(format!("challenge decode failed: {e}")))?;

    let challenge_bytes = hex::decode(&challenge_body.challenge)
        .map_err(|e| DaemonError::ControlPlane(format!("challenge hex decode failed: {e}")))?;

    // Step 2: Sign the challenge with Ed25519
    let ed25519_private_key = hex::decode(ed25519_private_key_hex).map_err(|e| {
        DaemonError::ControlPlane(format!("ed25519 private key hex decode failed: {e}"))
    })?;

    if ed25519_private_key.len() != 32 {
        return Err(DaemonError::ControlPlane(
            "invalid ed25519 private key length".into(),
        ));
    }

    let mut key_bytes = [0u8; 32];
    key_bytes.copy_from_slice(&ed25519_private_key);
    let keypair = p2pnet_crypto::Ed25519KeyPair::from_private_key(&key_bytes);
    let signature = keypair.sign(&challenge_bytes);
    let signature_hex = hex::encode(signature);

    // Step 3: Submit the signed challenge to get a device credential
    let cred_resp = http
        .post(format!("{base_url}/api/v1/devices/credential"))
        .bearer_auth(user_token)
        .json(&serde_json::json!({
            "device_id": device_id,
            "ed25519_public_key": ed25519_public_key_hex,
            "challenge_id": challenge_body.challenge_id,
            "challenge_signature": signature_hex,
        }))
        .send()
        .await
        .map_err(|e| DaemonError::ControlPlane(format!("credential request failed: {e}")))?;

    if !cred_resp.status().is_success() {
        return Err(DaemonError::ControlPlane(format!(
            "credential request returned HTTP {}",
            cred_resp.status()
        )));
    }

    #[derive(Deserialize)]
    struct CredentialResponse {
        success: bool,
        device_credential: Option<String>,
        error: Option<String>,
    }

    let cred_body: CredentialResponse = cred_resp.json().await.map_err(|e| {
        DaemonError::ControlPlane(format!("credential response decode failed: {e}"))
    })?;

    if !cred_body.success {
        return Err(DaemonError::ControlPlane(
            cred_body
                .error
                .unwrap_or_else(|| "credential request failed".to_string()),
        ));
    }

    cred_body.device_credential.ok_or_else(|| {
        DaemonError::ControlPlane("credential response missing device_credential".into())
    })
}

#[derive(Debug, Deserialize)]
struct RelayTicketResponse {
    ticket: Option<String>,
    expires_at: Option<i64>,
    error: Option<String>,
}

async fn fetch_relay_ticket_http(
    http: &reqwest::Client,
    base_url: &str,
    token: &str,
    audience: &str,
    region: &str,
) -> Result<FetchRelayTicketResponse> {
    let resp = http
        .post(format!("{base_url}/api/v1/relay/tickets"))
        .bearer_auth(token)
        .json(&serde_json::json!({
            "audience": audience,
            "region": region,
        }))
        .send()
        .await
        .map_err(|e| DaemonError::ControlPlane(format!("relay ticket request failed: {e}")))?;

    if !resp.status().is_success() {
        let status = resp.status();
        let body: RelayTicketResponse = resp.json().await.unwrap_or(RelayTicketResponse {
            ticket: None,
            expires_at: None,
            error: Some(format!("HTTP {status}")),
        });
        let msg = body.error.unwrap_or_else(|| format!("HTTP {status}"));
        if status == reqwest::StatusCode::UNAUTHORIZED || status == reqwest::StatusCode::FORBIDDEN {
            return Err(DaemonError::ControlPlane(format!("permanent auth: {msg}")));
        }
        return Err(DaemonError::ControlPlane(format!(
            "relay ticket request: {msg}"
        )));
    }

    let body: RelayTicketResponse = resp
        .json()
        .await
        .map_err(|e| DaemonError::ControlPlane(format!("relay ticket decode: {e}")))?;

    let ticket = body
        .ticket
        .ok_or_else(|| DaemonError::ControlPlane("relay ticket response missing ticket".into()))?;
    let expires_at = body.expires_at.unwrap_or(0);

    Ok(FetchRelayTicketResponse { ticket, expires_at })
}

fn normalize_http_base_url(server_url: &str) -> String {
    let trimmed = server_url.trim().trim_end_matches('/');
    if trimmed.starts_with("ws://") {
        format!("http://{}", trimmed.trim_start_matches("ws://"))
    } else if trimmed.starts_with("wss://") {
        format!("https://{}", trimmed.trim_start_matches("wss://"))
    } else {
        trimmed.to_string()
    }
}

async fn register_device(
    http: &reqwest::Client,
    base_url: &str,
    token: &str,
    config: &Config,
) -> Result<(String, String, String, Vec<String>, Vec<RelayCatalogEntry>)> {
    let res = http
        .post(format!("{base_url}/api/v1/devices"))
        .bearer_auth(token)
        .json(&serde_json::json!({
            "public_key": config.node.public_key,
            "device_name": config.node.device_name,
            "platform": config.node.platform,
            "network_id": config.network.network_id,
        }))
        .send()
        .await
        .map_err(|e| DaemonError::ControlPlane(format!("register request failed: {e}")))?;

    if !res.status().is_success() {
        return Err(DaemonError::ControlPlane(format!(
            "register request returned HTTP {}",
            res.status()
        )));
    }

    let body: RegisterDeviceResponse = res
        .json()
        .await
        .map_err(|e| DaemonError::ControlPlane(format!("register response decode failed: {e}")))?;

    if !body.success {
        return Err(DaemonError::ControlPlane(
            body.error
                .unwrap_or_else(|| "device registration failed".to_string()),
        ));
    }

    let node_id = body
        .node_id
        .ok_or_else(|| DaemonError::ControlPlane("register response missing node_id".into()))?;
    let virtual_ip = body
        .virtual_ip
        .ok_or_else(|| DaemonError::ControlPlane("register response missing virtual_ip".into()))?;
    let cidr = body.cidr.unwrap_or_else(|| "10.20.0.0/16".to_string());

    Ok((
        node_id,
        virtual_ip,
        cidr,
        body.relay_servers,
        body.relay_catalog,
    ))
}

async fn update_endpoint(
    http: &reqwest::Client,
    base_url: &str,
    token: &str,
    device_id: &str,
    endpoint: &str,
    nat_type: &str,
) -> Result<()> {
    let res = http
        .patch(format!("{base_url}/api/v1/devices/{device_id}/endpoint"))
        .bearer_auth(token)
        .json(&serde_json::json!({
            "endpoint": endpoint,
            "nat_type": nat_type,
        }))
        .send()
        .await
        .map_err(|e| DaemonError::ControlPlane(format!("endpoint update request failed: {e}")))?;

    if !res.status().is_success() {
        return Err(DaemonError::ControlPlane(format!(
            "endpoint update returned HTTP {}",
            res.status()
        )));
    }

    let body: EndpointUpdateResponse = res
        .json()
        .await
        .map_err(|e| DaemonError::ControlPlane(format!("endpoint update decode failed: {e}")))?;

    if !body.success {
        return Err(DaemonError::ControlPlane(
            body.error
                .unwrap_or_else(|| "endpoint update failed".to_string()),
        ));
    }

    Ok(())
}

#[allow(clippy::too_many_arguments)]
async fn send_signal(
    http: &reqwest::Client,
    base_url: &str,
    token: &str,
    from_node_id: &str,
    to_node_id: &str,
    signal_type: &str,
    candidates: &[String],
    candidate_sources: &HashMap<String, String>,
    handshake: &[u8],
    punch_at_ms: Option<u64>,
) -> Result<()> {
    let res = http
        .post(format!("{base_url}/api/v1/signals"))
        .bearer_auth(token)
        .json(&serde_json::json!({
            "from_node_id": from_node_id,
            "to_node_id": to_node_id,
            "type": signal_type,
            "candidates": candidates,
            "candidate_sources": candidate_sources,
            "handshake": hex::encode(handshake),
            "punch_at_ms": punch_at_ms,
        }))
        .send()
        .await
        .map_err(|e| DaemonError::ControlPlane(format!("send signal request failed: {e}")))?;

    if !res.status().is_success() {
        return Err(DaemonError::ControlPlane(format!(
            "send signal returned HTTP {}",
            res.status()
        )));
    }

    let body: SignalCreateResponse = res
        .json()
        .await
        .map_err(|e| DaemonError::ControlPlane(format!("send signal decode failed: {e}")))?;

    if !body.success {
        return Err(DaemonError::ControlPlane(
            body.error
                .unwrap_or_else(|| "send signal failed".to_string()),
        ));
    }

    Ok(())
}

async fn poll_signals(
    http: &reqwest::Client,
    base_url: &str,
    token: &str,
    self_node_id: &str,
    event_tx: &mpsc::UnboundedSender<ControlEvent>,
) -> Result<()> {
    let res = http
        .get(format!("{base_url}/api/v1/signals?node_id={self_node_id}"))
        .bearer_auth(token)
        .send()
        .await
        .map_err(|e| DaemonError::ControlPlane(format!("list signals request failed: {e}")))?;

    if !res.status().is_success() {
        return Err(DaemonError::ControlPlane(format!(
            "list signals returned HTTP {}",
            res.status()
        )));
    }

    let body: ListSignalsResponse = res
        .json()
        .await
        .map_err(|e| DaemonError::ControlPlane(format!("list signals decode failed: {e}")))?;

    for signal in body.signals {
        let handshake = if signal.handshake.trim().is_empty() {
            Vec::new()
        } else {
            hex::decode(signal.handshake.trim()).map_err(|e| {
                DaemonError::ControlPlane(format!("signal handshake hex decode failed: {e}"))
            })?
        };

        match signal.signal_type.as_str() {
            "peer_offer" => {
                let _ = event_tx.send(ControlEvent::PeerOffer {
                    from_node_id: signal.from_node_id,
                    candidates: signal.candidates,
                    candidate_sources: signal.candidate_sources,
                    handshake_init: handshake,
                    punch_at_ms: signal.punch_at_ms,
                });
            }
            "peer_answer" => {
                let _ = event_tx.send(ControlEvent::PeerAnswer {
                    from_node_id: signal.from_node_id,
                    candidates: signal.candidates,
                    candidate_sources: signal.candidate_sources,
                    handshake_response: handshake,
                    punch_at_ms: signal.punch_at_ms,
                });
            }
            "peer_reflexive" => {
                if let Some(observed_endpoint) = peer_reflexive_endpoint_from_signal(&signal) {
                    let _ = event_tx.send(ControlEvent::PeerReflexive {
                        from_node_id: signal.from_node_id,
                        observed_endpoint,
                        punch_at_ms: signal.punch_at_ms,
                    });
                } else {
                    warn!(
                        "Ignoring peer_reflexive signal from {}; missing observed endpoint",
                        signal.from_node_id
                    );
                }
            }
            other => {
                warn!("Ignoring unsupported signal type from control plane: {other}");
            }
        }
    }

    Ok(())
}

fn peer_reflexive_endpoint_from_signal(signal: &SignalResponse) -> Option<String> {
    signal
        .candidates
        .iter()
        .find(|candidate| {
            signal
                .candidate_sources
                .get(candidate.as_str())
                .is_some_and(|source| source == "peer_reflexive")
        })
        .or_else(|| signal.candidates.first())
        .cloned()
}

async fn poll_peers(
    http: &reqwest::Client,
    base_url: &str,
    token: &str,
    config: &Config,
    self_node_id: &str,
    state: &Arc<RwLock<ClientState>>,
    event_tx: &mpsc::UnboundedSender<ControlEvent>,
) -> Result<()> {
    let res = http
        .get(format!(
            "{base_url}/api/v1/nodes?network_id={}",
            config.network.network_id
        ))
        .bearer_auth(token)
        .send()
        .await
        .map_err(|e| DaemonError::ControlPlane(format!("list nodes request failed: {e}")))?;

    if !res.status().is_success() {
        return Err(DaemonError::ControlPlane(format!(
            "list nodes request returned HTTP {}",
            res.status()
        )));
    }

    let body: ListNodesResponse = res
        .json()
        .await
        .map_err(|e| DaemonError::ControlPlane(format!("list nodes decode failed: {e}")))?;

    let mut seen = HashMap::new();
    let mut joined = Vec::new();
    let mut updated = Vec::new();

    {
        let mut state = state.write().await;

        for node in body.nodes {
            if node.id == self_node_id || node.public_key == config.node.public_key {
                continue;
            }
            if !node.online {
                continue;
            }

            let peer = PeerInfo {
                node_id: node.id.clone(),
                device_name: node.device_name,
                public_key: node.public_key,
                endpoint: node.endpoint,
                nat_type: node.nat_type,
                virtual_ip: node.virtual_ip,
                online: node.online,
                last_seen: node.last_seen,
            };

            seen.insert(peer.node_id.clone(), peer.clone());
            match state.peers.get(&peer.node_id) {
                Some(known) if peer_metadata_changed(known, &peer) => updated.push(peer.clone()),
                None => joined.push(peer.clone()),
                _ => {}
            }
            state.peers.insert(peer.node_id.clone(), peer);
        }

        let departed: Vec<String> = state
            .peers
            .keys()
            .filter(|node_id| !seen.contains_key(*node_id))
            .cloned()
            .collect();

        for node_id in departed {
            state.peers.remove(&node_id);
            let _ = event_tx.send(ControlEvent::PeerLeft(node_id));
        }
    }

    for peer in joined {
        let _ = event_tx.send(ControlEvent::PeerJoined(peer));
    }
    for peer in updated {
        let _ = event_tx.send(ControlEvent::PeerUpdated(peer));
    }

    Ok(())
}

fn peer_metadata_changed(known: &PeerInfo, peer: &PeerInfo) -> bool {
    known.device_name != peer.device_name
        || known.public_key != peer.public_key
        || known.endpoint != peer.endpoint
        || known.nat_type != peer.nat_type
        || known.virtual_ip != peer.virtual_ip
        || known.online != peer.online
}

async fn create_tunnel(
    http: &reqwest::Client,
    base_url: &str,
    token: &str,
    device_id: &str,
    protocol: &str,
    local_port: u16,
    remote_port: u16,
) -> Result<(String, String)> {
    let res = http
        .post(format!("{base_url}/api/v1/tunnels"))
        .bearer_auth(token)
        .json(&serde_json::json!({
            "device_id": device_id,
            "protocol": protocol,
            "local_port": local_port,
            "remote_port": remote_port,
            "local_address": "127.0.0.1",
        }))
        .send()
        .await
        .map_err(|e| DaemonError::ControlPlane(format!("create tunnel request failed: {e}")))?;

    if !res.status().is_success() {
        return Err(DaemonError::ControlPlane(format!(
            "create tunnel request returned HTTP {}",
            res.status()
        )));
    }

    let body: CreateTunnelResponse = res
        .json()
        .await
        .map_err(|e| DaemonError::ControlPlane(format!("create tunnel decode failed: {e}")))?;

    if !body.success {
        return Err(DaemonError::ControlPlane(
            body.error
                .unwrap_or_else(|| "create tunnel failed".to_string()),
        ));
    }

    Ok((
        body.tunnel_id
            .ok_or_else(|| DaemonError::ControlPlane("create tunnel response missing id".into()))?,
        body.public_endpoint.ok_or_else(|| {
            DaemonError::ControlPlane("create tunnel response missing public endpoint".into())
        })?,
    ))
}

// ============================================================
// Tests
// ============================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn test_config() -> Config {
        Config::generate_default("https://ctrl.test", "net1").unwrap()
    }

    #[test]
    fn peer_endpoint_change_is_reported_as_metadata_update() {
        let known = PeerInfo {
            node_id: "peer-a".to_string(),
            device_name: "peer".to_string(),
            public_key: "key".to_string(),
            endpoint: "192.168.1.10:5000".to_string(),
            nat_type: "unknown".to_string(),
            virtual_ip: "10.20.0.2".to_string(),
            online: true,
            last_seen: 1,
        };
        let mut updated = known.clone();
        updated.endpoint = "203.0.113.10:62000".to_string();
        updated.last_seen = 2;

        assert!(peer_metadata_changed(&known, &updated));

        updated.endpoint = known.endpoint.clone();
        assert!(!peer_metadata_changed(&known, &updated));
    }

    #[test]
    fn test_control_message_serialization() {
        let msg = ControlMessage::Register {
            node_id: "node123".to_string(),
            public_key: "pubkey".to_string(),
            device_name: "my-laptop".to_string(),
            platform: "windows".to_string(),
            network_id: "net1".to_string(),
        };

        let json = serde_json::to_string(&msg).unwrap();
        let decoded: ControlMessage = serde_json::from_str(&json).unwrap();

        if let ControlMessage::Register { node_id, .. } = decoded {
            assert_eq!(node_id, "node123");
        } else {
            panic!("Expected Register message");
        }
    }

    #[test]
    fn test_peer_offer_serialization() {
        let msg = ControlMessage::PeerOffer {
            from_node_id: "alice".to_string(),
            to_node_id: "bob".to_string(),
            candidates: vec!["10.0.0.1:5000".to_string()],
            candidate_sources: HashMap::new(),
            handshake_init: vec![0x01, 0x02],
            punch_at_ms: Some(1234),
        };

        let json = serde_json::to_string(&msg).unwrap();
        let decoded: ControlMessage = serde_json::from_str(&json).unwrap();
        assert!(matches!(decoded, ControlMessage::PeerOffer { .. }));
    }

    #[test]
    fn test_peer_reflexive_serialization() {
        let msg = ControlMessage::PeerReflexive {
            from_node_id: "alice".to_string(),
            to_node_id: "bob".to_string(),
            observed_endpoint: "203.0.113.10:51820".to_string(),
            punch_at_ms: Some(42_000),
        };

        let json = serde_json::to_string(&msg).unwrap();
        assert!(json.contains("\"type\":\"peer_reflexive\""));
        assert!(json.contains("\"observed_endpoint\":\"203.0.113.10:51820\""));

        let decoded: ControlMessage = serde_json::from_str(&json).unwrap();
        match decoded {
            ControlMessage::PeerReflexive {
                from_node_id,
                to_node_id,
                observed_endpoint,
                punch_at_ms,
            } => {
                assert_eq!(from_node_id, "alice");
                assert_eq!(to_node_id, "bob");
                assert_eq!(observed_endpoint, "203.0.113.10:51820");
                assert_eq!(punch_at_ms, Some(42_000));
            }
            other => panic!("expected PeerReflexive, got {other:?}"),
        }
    }

    #[test]
    fn test_peer_reflexive_endpoint_prefers_tagged_candidate() {
        let signal = SignalResponse {
            from_node_id: "alice".to_string(),
            signal_type: "peer_reflexive".to_string(),
            candidates: vec![
                "198.51.100.1:40000".to_string(),
                "203.0.113.10:51820".to_string(),
            ],
            candidate_sources: HashMap::from([
                (
                    "198.51.100.1:40000".to_string(),
                    "stun_observed".to_string(),
                ),
                (
                    "203.0.113.10:51820".to_string(),
                    "peer_reflexive".to_string(),
                ),
            ]),
            handshake: String::new(),
            punch_at_ms: Some(77),
        };

        assert_eq!(
            peer_reflexive_endpoint_from_signal(&signal),
            Some("203.0.113.10:51820".to_string())
        );
    }

    #[test]
    fn test_peer_reflexive_endpoint_falls_back_to_first_candidate() {
        let signal = SignalResponse {
            from_node_id: "alice".to_string(),
            signal_type: "peer_reflexive".to_string(),
            candidates: vec!["198.51.100.1:40000".to_string()],
            candidate_sources: HashMap::new(),
            handshake: String::new(),
            punch_at_ms: None,
        };

        assert_eq!(
            peer_reflexive_endpoint_from_signal(&signal),
            Some("198.51.100.1:40000".to_string())
        );
    }

    #[test]
    fn test_control_client_creation() {
        let config = test_config();
        let (client, _rx) = ControlClient::new(&config, true, None);
        // Client created successfully, no events yet
        drop(client);
    }

    #[test]
    fn test_control_client_creation_disabled() {
        let mut config = test_config();
        config.control.auth_token = "test-token".to_string();
        // When disabled, no background control loop is spawned
        let (client, _rx) = ControlClient::new(&config, false, None);
        drop(client);
    }

    #[test]
    fn control_credential_accepts_device_credential_only() {
        let mut config = test_config();
        config.control.auth_token.clear();
        config.control.device_credential = "device-token".to_string();
        assert!(has_control_credential(&config));

        config.control.device_credential.clear();
        assert!(!has_control_credential(&config));
    }

    /// Regression: with token + unreachable control, disabled mode must not
    /// emit ServerError/Disconnected (which would otherwise shut down the daemon).
    #[tokio::test]
    async fn test_control_client_disabled_emits_no_events() {
        let mut config = test_config();
        config.control.auth_token = "test-token".to_string();
        config.control.server_url = "http://127.0.0.1:1".to_string(); // unreachable

        let (client, mut rx) = ControlClient::new(&config, false, None);

        // Give any accidental background task a moment to fire events.
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        assert!(
            rx.try_recv().is_err(),
            "disabled ControlClient must not emit control events"
        );
        drop(client);
    }

    #[tokio::test]
    async fn test_control_client_handle_registered() {
        let config = test_config();
        let (client, mut rx) = ControlClient::new(&config, true, None);

        client
            .handle_message(ControlMessage::Registered {
                virtual_ip: "10.20.0.5".to_string(),
                relay_servers: vec!["relay1:8080".to_string()],
            })
            .await;

        assert_eq!(client.virtual_ip().await, Some("10.20.0.5".to_string()));

        let event = rx.recv().await.unwrap();
        if let ControlEvent::Registered {
            node_id,
            virtual_ip,
            cidr: _,
            relay_servers,
            relay_catalog: _,
        } = event
        {
            assert_eq!(node_id, None);
            assert_eq!(virtual_ip, "10.20.0.5");
            assert_eq!(relay_servers.len(), 1);
        } else {
            panic!("Expected Registered event");
        }
    }

    #[tokio::test]
    async fn test_control_client_handle_peer_join_leave() {
        let config = test_config();
        let (client, _rx) = ControlClient::new(&config, true, None);

        client
            .handle_message(ControlMessage::PeerJoin {
                node_id: "peer1".to_string(),
                public_key: "pk1".to_string(),
                endpoint: "1.2.3.4:5000".to_string(),
                nat_type: "FullCone".to_string(),
                virtual_ip: "10.20.0.2".to_string(),
            })
            .await;

        let peers = client.peers().await;
        assert!(peers.contains_key("peer1"));

        client
            .handle_message(ControlMessage::PeerLeave {
                node_id: "peer1".to_string(),
            })
            .await;

        let peers = client.peers().await;
        assert!(!peers.contains_key("peer1"));
    }

    #[test]
    fn test_heartbeat_message() {
        let msg = ControlMessage::Heartbeat {
            node_id: "node1".to_string(),
            timestamp: 12345,
        };
        let json = serde_json::to_string(&msg).unwrap();
        assert!(json.contains("heartbeat"));
    }

    #[test]
    fn test_peer_info_default() {
        let info = PeerInfo::default();
        assert!(info.node_id.is_empty());
        assert!(!info.online);
    }
}
