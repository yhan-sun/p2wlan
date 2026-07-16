//! Relay transport adapter for encrypted peer packets.
//!
//! This layer bridges the daemon's WireGuard packet model to the DERP-like
//! relay client. Relay payloads remain encrypted WireGuard datagrams; the relay
//! server only sees source/destination node IDs and opaque bytes.

use std::sync::Arc;

use p2pnet_relay::{RelayClient, RelayMessage};
use tokio::sync::{mpsc, Mutex};
use tracing::{debug, warn};

use crate::error::{DaemonError, Result};
use crate::peer::PeerManager;
use crate::transport::{EncryptedPeerPacket, ReceivedEncryptedPacket};

/// Sends and receives encrypted WireGuard datagrams through a relay server.
#[derive(Clone)]
pub struct RelayTransport {
    relay_endpoint: String,
    client: Arc<Mutex<RelayClient>>,
    peers: Arc<PeerManager>,
}

impl RelayTransport {
    /// Connect to a relay server and register this node ID.
    pub async fn connect(
        relay_endpoint: &str,
        node_id: &str,
        peers: Arc<PeerManager>,
    ) -> Result<(Self, mpsc::UnboundedReceiver<RelayMessage>)> {
        let (client, relay_rx) = RelayClient::connect(relay_endpoint, node_id)
            .await
            .map_err(|e| {
                DaemonError::Relay(format!("failed to connect to relay {relay_endpoint}: {e}"))
            })?;

        Ok((
            Self {
                relay_endpoint: relay_endpoint.to_string(),
                client: Arc::new(Mutex::new(client)),
                peers,
            },
            relay_rx,
        ))
    }

    /// Send a single encrypted packet through the relay.
    pub async fn send_packet(&self, packet: &EncryptedPeerPacket) -> Result<()> {
        self.client
            .lock()
            .await
            .send_data(&packet.peer_id, &packet.wire_bytes)
            .await
            .map_err(|e| {
                DaemonError::Relay(format!(
                    "relay send to peer {} via {} failed: {e}",
                    packet.peer_id, self.relay_endpoint
                ))
            })?;

        self.peers
            .set_relay(&packet.peer_id, &self.relay_endpoint)
            .await;
        debug!(
            "Sent {} encrypted bytes to peer {} through relay {}",
            packet.wire_bytes.len(),
            packet.peer_id,
            self.relay_endpoint
        );
        Ok(())
    }

    /// Convert relay messages into inbound encrypted datagrams for WireGuard.
    pub async fn run_inbound(
        self,
        mut relay_rx: mpsc::UnboundedReceiver<RelayMessage>,
        inbound_tx: mpsc::Sender<ReceivedEncryptedPacket>,
    ) -> Result<()> {
        while let Some(message) = relay_rx.recv().await {
            if message.from_node.is_empty() {
                debug!(
                    "Ignoring relay control message from {}: {} bytes",
                    self.relay_endpoint,
                    message.data.len()
                );
                continue;
            }

            self.peers
                .set_relay(&message.from_node, &self.relay_endpoint)
                .await;
            inbound_tx
                .send(ReceivedEncryptedPacket {
                    source: None,
                    wire_bytes: message.data,
                })
                .await
                .map_err(|_| {
                    DaemonError::Network("relay inbound packet channel closed".to_string())
                })?;
        }

        warn!("Relay inbound stream from {} ended", self.relay_endpoint);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::time::Duration;

    use p2pnet_relay::RelayServer;
    use tokio::sync::mpsc;
    use tokio::time::timeout;

    use super::*;
    use crate::config::Config;
    use crate::control::PeerInfo;
    use crate::peer::{ConnectionState, PeerManager};

    fn peer(node_id: &str, virtual_ip: &str) -> PeerInfo {
        PeerInfo {
            node_id: node_id.to_string(),
            public_key: "pk".to_string(),
            endpoint: String::new(),
            nat_type: "Unknown".to_string(),
            virtual_ip: virtual_ip.to_string(),
            online: true,
            last_seen: 0,
        }
    }

    fn peer_manager() -> Arc<PeerManager> {
        Arc::new(PeerManager::new(
            Config::generate_default("http://ctrl.test", "default").unwrap(),
        ))
    }

    #[tokio::test]
    async fn relay_transport_sends_encrypted_datagrams() {
        let server = RelayServer::start_random().await.unwrap();
        let relay_endpoint = server.addr.to_string();

        let peers_a = peer_manager();
        let peers_b = peer_manager();
        peers_a.add_peer(&peer("node-b", "10.20.0.2")).await;
        peers_b.add_peer(&peer("node-a", "10.20.0.1")).await;

        let (relay_a, _rx_a) = RelayTransport::connect(&relay_endpoint, "node-a", peers_a.clone())
            .await
            .unwrap();
        let (relay_b, rx_b) = RelayTransport::connect(&relay_endpoint, "node-b", peers_b.clone())
            .await
            .unwrap();

        let (inbound_tx, mut inbound_rx) = mpsc::channel(4);
        let inbound_worker = tokio::spawn(relay_b.run_inbound(rx_b, inbound_tx));

        let payload = vec![4, 1, 2, 3, 4, 5];
        relay_a
            .send_packet(&EncryptedPeerPacket {
                peer_id: "node-b".to_string(),
                dst_ip: "10.20.0.2".to_string(),
                wire_bytes: payload.clone(),
            })
            .await
            .unwrap();

        let received = timeout(Duration::from_secs(2), inbound_rx.recv())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(received.source, None);
        assert_eq!(received.wire_bytes, payload);

        let conn_a = peers_a.get_connection("node-b").await.unwrap();
        assert_eq!(conn_a.state, ConnectionState::Relay);
        assert_eq!(conn_a.relay_server, Some(relay_endpoint.clone()));

        let conn_b = peers_b.get_connection("node-a").await.unwrap();
        assert_eq!(conn_b.state, ConnectionState::Relay);
        assert_eq!(conn_b.relay_server, Some(relay_endpoint));

        inbound_worker.abort();
        server.shutdown().await;
    }
}
