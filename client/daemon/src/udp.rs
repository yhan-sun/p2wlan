//! UDP transport for encrypted peer packets.
//!
//! The WireGuard adapter produces serialized transport messages keyed by peer
//! ID. This module is the direct UDP sink: it resolves each peer endpoint from
//! `PeerManager` and sends the encrypted datagram to that socket address.

use std::net::SocketAddr;
use std::sync::Arc;

use tokio::net::UdpSocket;
use tokio::sync::mpsc;
use tracing::{debug, trace, warn};

use crate::error::{DaemonError, Result};
use crate::peer::PeerManager;
use crate::transport::EncryptedPeerPacket;

/// Sends encrypted WireGuard packets over direct UDP endpoints.
#[derive(Clone)]
pub struct UdpTransport {
    socket: Arc<UdpSocket>,
    peers: Arc<PeerManager>,
}

impl UdpTransport {
    /// Bind a UDP socket for direct peer traffic.
    pub async fn bind(bind_addr: SocketAddr, peers: Arc<PeerManager>) -> Result<Self> {
        let socket = UdpSocket::bind(bind_addr).await.map_err(|e| {
            DaemonError::Network(format!("failed to bind UDP socket at {bind_addr}: {e}"))
        })?;

        Ok(Self {
            socket: Arc::new(socket),
            peers,
        })
    }

    /// Return the local UDP socket address.
    pub fn local_addr(&self) -> Result<SocketAddr> {
        self.socket
            .local_addr()
            .map_err(|e| DaemonError::Network(format!("failed to read UDP local addr: {e}")))
    }

    /// Send a single encrypted packet.
    ///
    /// Returns `Ok(Some(bytes))` when sent, `Ok(None)` when no endpoint is known
    /// for the destination peer, and `Err` for socket-level failures.
    pub async fn send_packet(&self, packet: &EncryptedPeerPacket) -> Result<Option<usize>> {
        let Some(conn) = self.peers.get_connection(&packet.peer_id).await else {
            trace!(
                "No peer connection for {}; dropping {} byte encrypted packet",
                packet.peer_id,
                packet.wire_bytes.len()
            );
            return Ok(None);
        };

        let Some(endpoint) = conn.endpoint else {
            trace!(
                "No UDP endpoint for {}; dropping {} byte encrypted packet",
                packet.peer_id,
                packet.wire_bytes.len()
            );
            return Ok(None);
        };

        let sent = self
            .socket
            .send_to(&packet.wire_bytes, endpoint)
            .await
            .map_err(|e| {
                DaemonError::Network(format!(
                    "UDP send to {} for peer {} failed: {}",
                    endpoint, packet.peer_id, e
                ))
            })?;

        if sent != packet.wire_bytes.len() {
            return Err(DaemonError::Network(format!(
                "short UDP send to {} for peer {}: sent {} of {} bytes",
                endpoint,
                packet.peer_id,
                sent,
                packet.wire_bytes.len()
            )));
        }

        debug!(
            "Sent {} encrypted bytes to peer {} at {} (dst={})",
            sent, packet.peer_id, endpoint, packet.dst_ip
        );
        Ok(Some(sent))
    }

    /// Consume encrypted packets until the channel closes.
    pub async fn run_outbound(self, mut encrypted_rx: mpsc::Receiver<EncryptedPeerPacket>) {
        while let Some(packet) = encrypted_rx.recv().await {
            match self.send_packet(&packet).await {
                Ok(Some(_)) => {}
                Ok(None) => {
                    debug!(
                        "Encrypted packet for peer {} has no UDP endpoint yet",
                        packet.peer_id
                    );
                }
                Err(err) => {
                    warn!("UDP transport send failed: {err}");
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;
    use std::time::Duration;

    use p2pnet_crypto::NodeIdentity;
    use p2pnet_tun::Ipv4Packet;
    use p2pnet_wireguard::{HandshakeInitiator, HandshakeResponder, TransportSession};
    use tokio::sync::mpsc;
    use tokio::time::timeout;

    use super::*;
    use crate::config::Config;
    use crate::control::PeerInfo;

    fn peer(node_id: &str, virtual_ip: &str, endpoint: Option<SocketAddr>) -> PeerInfo {
        PeerInfo {
            node_id: node_id.to_string(),
            public_key: "pk".to_string(),
            endpoint: endpoint.map(|addr| addr.to_string()).unwrap_or_default(),
            nat_type: "FullCone".to_string(),
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

    fn establish_sessions() -> (TransportSession, TransportSession) {
        let node_a = NodeIdentity::generate();
        let node_b = NodeIdentity::generate();

        let mut initiator = HandshakeInitiator::new(node_a, node_b.public_key(), None);
        let mut responder = HandshakeResponder::new(node_b, None);

        let init = initiator.create_initiation().unwrap();
        let (response, node_b_keys) = responder.consume_initiation_and_respond(&init).unwrap();
        let node_a_keys = initiator.consume_response(&response).unwrap();

        (
            TransportSession::new(node_a_keys),
            TransportSession::new(node_b_keys),
        )
    }

    #[tokio::test]
    async fn sends_encrypted_packet_to_peer_endpoint() {
        let receiver = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let receiver_addr = receiver.local_addr().unwrap();

        let peers = peer_manager();
        peers
            .add_peer(&peer("peer-b", "10.20.0.2", Some(receiver_addr)))
            .await;

        let transport = UdpTransport::bind("127.0.0.1:0".parse().unwrap(), peers)
            .await
            .unwrap();
        let payload = vec![4, 1, 2, 3, 4, 5, 6, 7];

        let sent = transport
            .send_packet(&EncryptedPeerPacket {
                peer_id: "peer-b".to_string(),
                dst_ip: "10.20.0.2".to_string(),
                wire_bytes: payload.clone(),
            })
            .await
            .unwrap();
        assert_eq!(sent, Some(payload.len()));

        let mut buf = [0u8; 128];
        let (n, _from) = timeout(Duration::from_secs(1), receiver.recv_from(&mut buf))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(&buf[..n], payload.as_slice());
    }

    #[tokio::test]
    async fn drops_packet_when_endpoint_is_unknown() {
        let peers = peer_manager();
        peers.add_peer(&peer("peer-b", "10.20.0.2", None)).await;

        let transport = UdpTransport::bind("127.0.0.1:0".parse().unwrap(), peers)
            .await
            .unwrap();

        let sent = transport
            .send_packet(&EncryptedPeerPacket {
                peer_id: "peer-b".to_string(),
                dst_ip: "10.20.0.2".to_string(),
                wire_bytes: vec![4, 1, 2, 3],
            })
            .await
            .unwrap();

        assert_eq!(sent, None);
    }

    #[tokio::test]
    async fn run_outbound_sends_wireguard_datagram_that_peer_can_decrypt() {
        let receiver = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let receiver_addr = receiver.local_addr().unwrap();

        let peers = peer_manager();
        peers
            .add_peer(&peer("peer-b", "10.20.0.2", Some(receiver_addr)))
            .await;

        let transport = UdpTransport::bind("127.0.0.1:0".parse().unwrap(), peers)
            .await
            .unwrap();
        let (tx, rx) = mpsc::channel(4);
        let worker = tokio::spawn(transport.run_outbound(rx));

        let (mut node_a_session, mut node_b_session) = establish_sessions();
        let ip_packet = Ipv4Packet::build_icmp_echo_request(
            Ipv4Addr::new(10, 20, 0, 1),
            Ipv4Addr::new(10, 20, 0, 2),
            0x1234,
            1,
            b"ping",
        );
        let wire_bytes = node_a_session.encrypt_to_bytes(&ip_packet).unwrap();

        tx.send(EncryptedPeerPacket {
            peer_id: "peer-b".to_string(),
            dst_ip: "10.20.0.2".to_string(),
            wire_bytes,
        })
        .await
        .unwrap();

        let mut buf = [0u8; 2048];
        let (n, _from) = timeout(Duration::from_secs(1), receiver.recv_from(&mut buf))
            .await
            .unwrap()
            .unwrap();
        let decrypted = node_b_session.decrypt_from_bytes(&buf[..n]).unwrap();
        assert_eq!(decrypted, ip_packet);

        worker.abort();
    }
}
