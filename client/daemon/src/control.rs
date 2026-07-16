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

use serde::{Deserialize, Serialize};
use tokio::sync::{mpsc, RwLock};
use tracing::{debug, warn};

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
#[derive(Debug, Clone, Serialize, Deserialize)]
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

impl Default for PeerInfo {
    fn default() -> Self {
        Self {
            node_id: String::new(),
            public_key: String::new(),
            endpoint: String::new(),
            nat_type: String::new(),
            virtual_ip: String::new(),
            online: false,
            last_seen: 0,
        }
    }
}

// ============================================================
// Control Plane Client
// ============================================================

/// Events emitted by the control plane client.
#[derive(Debug, Clone)]
pub enum ControlEvent {
    /// Registration confirmed. Contains assigned virtual IP and relay servers.
    Registered {
        virtual_ip: String,
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
    relay_servers: Vec<String>,
}

/// Control plane client.
///
/// Connects to the Go control server via WebSocket and handles
/// signaling, peer discovery, and configuration updates.
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
    /// Send a message to the server.
    Send(ControlMessage),
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
        let (cmd_tx, _cmd_rx) = mpsc::unbounded_channel();

        let state = Arc::new(RwLock::new(ClientState {
            registered: false,
            peers: HashMap::new(),
            virtual_ip: None,
            relay_servers: config.relay.servers.clone(),
        }));

        let client = Self {
            event_tx,
            cmd_tx,
            state,
        };

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
    async fn handle_message(&self, msg: ControlMessage) {
        match msg {
            ControlMessage::Registered {
                virtual_ip,
                relay_servers,
            } => {
                let mut state = self.state.write().await;
                state.registered = true;
                state.virtual_ip = Some(virtual_ip.clone());
                state.relay_servers = relay_servers.clone();
                drop(state);

                let _ = self.event_tx.send(ControlEvent::Registered {
                    virtual_ip,
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
        let (client, mut rx) = ControlClient::new(&config);
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
            virtual_ip,
            relay_servers,
        } = event
        {
            assert_eq!(virtual_ip, "10.20.0.5");
            assert_eq!(relay_servers.len(), 1);
        } else {
            panic!("Expected Registered event");
        }
    }

    #[tokio::test]
    async fn test_control_client_handle_peer_join_leave() {
        let config = test_config();
        let (client, mut rx) = ControlClient::new(&config);

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
