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
use std::sync::Arc;
use std::time::Duration;

use serde::{Deserialize, Serialize};
use tokio::sync::{mpsc, RwLock};
use tokio::time;
use tracing::{debug, info, warn};

use crate::config::Config;
use crate::error::{DaemonError, Result};

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
        handshake_init: Vec<u8>,
    },

    /// Answer to a peer offer.
    #[serde(rename = "peer_answer")]
    PeerAnswer {
        from_node_id: String,
        to_node_id: String,
        candidates: Vec<String>,
        #[serde(default)]
        handshake_response: Vec<u8>,
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
    },
    /// A new peer has joined.
    PeerJoined(PeerInfo),
    /// A peer has left.
    PeerLeft(String),
    /// Received a peer offer (ICE candidates for hole punching).
    PeerOffer {
        from_node_id: String,
        candidates: Vec<String>,
        handshake_init: Vec<u8>,
    },
    /// Received a peer answer.
    PeerAnswer {
        from_node_id: String,
        candidates: Vec<String>,
        handshake_response: Vec<u8>,
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

#[derive(Debug, Deserialize)]
struct RegisterDeviceResponse {
    success: bool,
    node_id: Option<String>,
    virtual_ip: Option<String>,
    cidr: Option<String>,
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
    handshake: String,
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

/// Commands sent to the control client background task.
enum ControlCommand {
    /// Update our endpoint (after NAT detection).
    UpdateEndpoint { endpoint: String, nat_type: String },
    /// Send a peer offer.
    SendPeerOffer {
        to_node_id: String,
        candidates: Vec<String>,
        handshake_init: Vec<u8>,
    },
    /// Send a peer answer.
    SendPeerAnswer {
        to_node_id: String,
        candidates: Vec<String>,
        handshake_response: Vec<u8>,
    },
    /// Create a tunnel.
    CreateTunnel {
        protocol: String,
        local_port: u16,
        remote_port: u16,
    },
    /// Delete a tunnel.
    DeleteTunnel { tunnel_id: String },
    /// Shutdown.
    Shutdown,
}

impl ControlClient {
    /// Create a new control client (not yet connected).
    ///
    /// Returns the client handle and an event receiver.
    pub fn new(config: &Config) -> (Self, mpsc::UnboundedReceiver<ControlEvent>) {
        let (event_tx, event_rx) = mpsc::unbounded_channel();
        let (cmd_tx, cmd_rx) = mpsc::unbounded_channel();

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

        if !config.control.auth_token.trim().is_empty() {
            let config = config.clone();
            let event_tx = client.event_tx.clone();
            tokio::spawn(async move {
                run_control_loop(config, event_tx, state, cmd_rx).await;
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
        self.cmd_tx
            .send(ControlCommand::UpdateEndpoint {
                endpoint: endpoint.to_string(),
                nat_type: nat_type.to_string(),
            })
            .map_err(|_| DaemonError::ControlPlane("command channel closed".into()))
    }

    /// Send a peer offer (initiate P2P connection).
    pub async fn send_peer_offer(
        &self,
        to_node_id: &str,
        candidates: &[String],
        handshake_init: &[u8],
    ) -> Result<()> {
        self.cmd_tx
            .send(ControlCommand::SendPeerOffer {
                to_node_id: to_node_id.to_string(),
                candidates: candidates.to_vec(),
                handshake_init: handshake_init.to_vec(),
            })
            .map_err(|_| DaemonError::ControlPlane("command channel closed".into()))
    }

    /// Send a peer answer.
    pub async fn send_peer_answer(
        &self,
        to_node_id: &str,
        candidates: &[String],
        handshake_response: &[u8],
    ) -> Result<()> {
        self.cmd_tx
            .send(ControlCommand::SendPeerAnswer {
                to_node_id: to_node_id.to_string(),
                candidates: candidates.to_vec(),
                handshake_response: handshake_response.to_vec(),
            })
            .map_err(|_| DaemonError::ControlPlane("command channel closed".into()))
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
                handshake_init,
                ..
            } => {
                let _ = self.event_tx.send(ControlEvent::PeerOffer {
                    from_node_id,
                    candidates,
                    handshake_init,
                });
            }

            ControlMessage::PeerAnswer {
                from_node_id,
                candidates,
                handshake_response,
                ..
            } => {
                let _ = self.event_tx.send(ControlEvent::PeerAnswer {
                    from_node_id,
                    candidates,
                    handshake_response,
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

async fn run_control_loop(
    config: Config,
    event_tx: mpsc::UnboundedSender<ControlEvent>,
    state: Arc<RwLock<ClientState>>,
    mut cmd_rx: mpsc::UnboundedReceiver<ControlCommand>,
) {
    let http = reqwest::Client::new();
    let base_url = normalize_http_base_url(&config.control.server_url);
    let token = config.control.auth_token.clone();

    info!("Connecting to control plane at {base_url}");

    let self_node_id = match register_device(&http, &base_url, &token, &config).await {
        Ok((node_id, virtual_ip, cidr)) => {
            {
                let mut state = state.write().await;
                state.registered = true;
                state.virtual_ip = Some(virtual_ip.clone());
            }

            let _ = event_tx.send(ControlEvent::Registered {
                node_id: Some(node_id.clone()),
                virtual_ip,
                cidr: Some(cidr),
                relay_servers: config.relay.servers.clone(),
            });
            node_id
        }
        Err(err) => {
            warn!("Control registration failed: {err}");
            let _ = event_tx.send(ControlEvent::ServerError {
                code: 1000,
                message: err.to_string(),
            });
            let _ = event_tx.send(ControlEvent::Disconnected);
            return;
        }
    };

    if let Err(err) = poll_peers(
        &http,
        &base_url,
        &token,
        &config,
        &self_node_id,
        &state,
        &event_tx,
    )
    .await
    {
        warn!("Initial peer polling failed: {err}");
    }

    if let Err(err) = poll_signals(&http, &base_url, &token, &self_node_id, &event_tx).await {
        warn!("Initial signal polling failed: {err}");
    }

    let interval_secs = config.control.heartbeat_interval_secs.max(5);
    let mut tick = time::interval(Duration::from_secs(interval_secs));

    loop {
        tokio::select! {
            _ = tick.tick() => {
                if let Err(err) = poll_peers(&http, &base_url, &token, &config, &self_node_id, &state, &event_tx).await {
                    warn!("Peer polling failed: {err}");
                }
                if let Err(err) = poll_signals(&http, &base_url, &token, &self_node_id, &event_tx).await {
                    warn!("Signal polling failed: {err}");
                }
            }
            Some(cmd) = cmd_rx.recv() => {
                match cmd {
                    ControlCommand::CreateTunnel { protocol, local_port, remote_port } => {
                        match create_tunnel(&http, &base_url, &token, &self_node_id, &protocol, local_port, remote_port).await {
                            Ok((tunnel_id, public_endpoint)) => {
                                let _ = event_tx.send(ControlEvent::TunnelCreated { tunnel_id, public_endpoint });
                            }
                            Err(err) => {
                                let _ = event_tx.send(ControlEvent::ServerError { code: 3000, message: err.to_string() });
                            }
                        }
                    }
                    ControlCommand::UpdateEndpoint { endpoint, nat_type } => {
                        match update_endpoint(&http, &base_url, &token, &self_node_id, &endpoint, &nat_type).await {
                            Ok(()) => {
                                debug!("Updated endpoint for {self_node_id}: {endpoint} ({nat_type})");
                            }
                            Err(err) => {
                                let _ = event_tx.send(ControlEvent::ServerError { code: 2000, message: err.to_string() });
                            }
                        }
                    }
                    ControlCommand::SendPeerOffer { to_node_id, candidates, handshake_init } => {
                        match send_signal(&http, &base_url, &token, &self_node_id, &to_node_id, "peer_offer", &candidates, &handshake_init).await {
                            Ok(()) => {
                                debug!("Sent peer offer to {to_node_id}: {} candidates, {} handshake bytes", candidates.len(), handshake_init.len());
                            }
                            Err(err) => {
                                let _ = event_tx.send(ControlEvent::ServerError { code: 4000, message: err.to_string() });
                            }
                        }
                    }
                    ControlCommand::SendPeerAnswer { to_node_id, candidates, handshake_response } => {
                        match send_signal(&http, &base_url, &token, &self_node_id, &to_node_id, "peer_answer", &candidates, &handshake_response).await {
                            Ok(()) => {
                                debug!("Sent peer answer to {to_node_id}: {} candidates, {} handshake bytes", candidates.len(), handshake_response.len());
                            }
                            Err(err) => {
                                let _ = event_tx.send(ControlEvent::ServerError { code: 4001, message: err.to_string() });
                            }
                        }
                    }
                    ControlCommand::DeleteTunnel { tunnel_id } => {
                        debug!("Tunnel deletion queued locally for {tunnel_id}");
                    }
                    ControlCommand::Shutdown => {
                        let _ = event_tx.send(ControlEvent::Disconnected);
                        break;
                    }
                }
            }
            else => break,
        }
    }
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
) -> Result<(String, String, String)> {
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
    let cidr = body
        .cidr
        .unwrap_or_else(|| "10.20.0.0/16".to_string());

    Ok((node_id, virtual_ip, cidr))
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
    handshake: &[u8],
) -> Result<()> {
    let res = http
        .post(format!("{base_url}/api/v1/signals"))
        .bearer_auth(token)
        .json(&serde_json::json!({
            "from_node_id": from_node_id,
            "to_node_id": to_node_id,
            "type": signal_type,
            "candidates": candidates,
            "handshake": hex::encode(handshake),
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
                    handshake_init: handshake,
                });
            }
            "peer_answer" => {
                let _ = event_tx.send(ControlEvent::PeerAnswer {
                    from_node_id: signal.from_node_id,
                    candidates: signal.candidates,
                    handshake_response: handshake,
                });
            }
            other => {
                warn!("Ignoring unsupported signal type from control plane: {other}");
            }
        }
    }

    Ok(())
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

    {
        let mut state = state.write().await;

        for node in body.nodes {
            if node.id == self_node_id || node.public_key == config.node.public_key {
                continue;
            }

            let peer = PeerInfo {
                node_id: node.id.clone(),
                public_key: node.public_key,
                endpoint: node.endpoint,
                nat_type: node.nat_type,
                virtual_ip: node.virtual_ip,
                online: node.online,
                last_seen: node.last_seen,
            };

            seen.insert(peer.node_id.clone(), peer.clone());
            if !state.peers.contains_key(&peer.node_id) {
                joined.push(peer.clone());
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

    Ok(())
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
            handshake_init: vec![0x01, 0x02],
        };

        let json = serde_json::to_string(&msg).unwrap();
        let decoded: ControlMessage = serde_json::from_str(&json).unwrap();
        assert!(matches!(decoded, ControlMessage::PeerOffer { .. }));
    }

    #[test]
    fn test_control_client_creation() {
        let config = test_config();
        let (client, _rx) = ControlClient::new(&config);
        // Client created successfully, no events yet
        drop(client);
    }

    #[tokio::test]
    async fn test_control_client_handle_registered() {
        let config = test_config();
        let (client, mut rx) = ControlClient::new(&config);

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
        let (client, _rx) = ControlClient::new(&config);

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
