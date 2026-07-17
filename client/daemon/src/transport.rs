//! WireGuard transport adapter for daemon data plane packets.
//!
//! `DataPlane` resolves raw TUN packets to a peer ID. This module is the next
//! hop: it takes routed peer packets, encrypts them with an established
//! WireGuard transport session, and emits encrypted wire bytes for the UDP or
//! relay transport layer.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;

use p2pnet_wireguard::{MessageTransport, TransportSession};
use tokio::sync::{mpsc, Mutex};
use tracing::{debug, warn};

use crate::dataplane::{InboundPacket, OutboundPacket};
use crate::error::{DaemonError, Result};

/// A WireGuard transport packet addressed to a peer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EncryptedPeerPacket {
    /// Destination peer node ID.
    pub peer_id: String,
    /// Destination virtual IP, retained for diagnostics.
    pub dst_ip: String,
    /// Serialized WireGuard transport message.
    pub wire_bytes: Vec<u8>,
}

/// An encrypted WireGuard packet received from UDP or relay transport.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReceivedEncryptedPacket {
    /// Source socket address when known.
    pub source: Option<SocketAddr>,
    /// Serialized WireGuard transport message.
    pub wire_bytes: Vec<u8>,
}

/// Encrypts routed TUN packets with peer WireGuard sessions.
#[derive(Clone)]
pub struct WireGuardTransport {
    sessions: Arc<Mutex<HashMap<String, TransportSession>>>,
    encrypted_tx: mpsc::Sender<EncryptedPeerPacket>,
}

impl WireGuardTransport {
    /// Create a transport adapter and a receiver for encrypted peer packets.
    pub fn new() -> (Self, mpsc::Receiver<EncryptedPeerPacket>) {
        let (encrypted_tx, encrypted_rx) = mpsc::channel(1024);
        (
            Self {
                sessions: Arc::new(Mutex::new(HashMap::new())),
                encrypted_tx,
            },
            encrypted_rx,
        )
    }

    /// Install or replace an established transport session for a peer.
    pub async fn add_session(&self, peer_id: impl Into<String>, session: TransportSession) {
        self.sessions.lock().await.insert(peer_id.into(), session);
    }

    /// Remove a peer session.
    pub async fn remove_session(&self, peer_id: &str) {
        self.sessions.lock().await.remove(peer_id);
    }

    /// Return whether a peer has an encrypting session.
    pub async fn has_session(&self, peer_id: &str) -> bool {
        self.sessions.lock().await.contains_key(peer_id)
    }

    /// Return whether a peer's session needs rekey.
    pub async fn session_needs_rekey(&self, peer_id: &str) -> bool {
        self.sessions
            .lock()
            .await
            .get(peer_id)
            .map(|s| s.needs_rekey())
            .unwrap_or(false)
    }

    /// Return whether a peer's session has expired (reject threshold exceeded).
    pub async fn session_is_expired(&self, peer_id: &str) -> bool {
        self.sessions
            .lock()
            .await
            .get(peer_id)
            .map(|s| s.is_expired())
            .unwrap_or(false)
    }

    /// Encrypt one outbound packet.
    pub async fn encrypt_outbound(
        &self,
        packet: OutboundPacket,
    ) -> Result<Option<EncryptedPeerPacket>> {
        let mut sessions = self.sessions.lock().await;
        let Some(session) = sessions.get_mut(&packet.peer_id) else {
            debug!(
                "No WireGuard session for peer {}; dropping {} byte packet",
                packet.peer_id,
                packet.packet.len()
            );
            return Ok(None);
        };

        let wire_bytes = session
            .encrypt_to_bytes(&packet.packet)
            .map_err(|e| DaemonError::Peer(format!("WireGuard encrypt failed: {e}")))?;

        Ok(Some(EncryptedPeerPacket {
            peer_id: packet.peer_id,
            dst_ip: packet.dst_ip,
            wire_bytes,
        }))
    }

    /// Decrypt one inbound WireGuard transport packet.
    pub async fn decrypt_inbound(&self, wire_bytes: &[u8]) -> Result<Option<InboundPacket>> {
        let msg = MessageTransport::from_bytes(wire_bytes)
            .map_err(|e| DaemonError::Peer(format!("WireGuard packet parse failed: {e}")))?;
        let receiver_index = msg.receiver_index;

        let mut sessions = self.sessions.lock().await;
        let Some((peer_id, session)) = sessions
            .iter_mut()
            .find(|(_, session)| session.our_index() == receiver_index)
        else {
            debug!(
                "No WireGuard session for receiver index {}; dropping inbound packet",
                receiver_index
            );
            return Ok(None);
        };

        let packet = session
            .decrypt(&msg)
            .map_err(|e| DaemonError::Peer(format!("WireGuard decrypt failed: {e}")))?;

        Ok(Some(InboundPacket {
            peer_id: peer_id.clone(),
            packet,
        }))
    }

    /// Consume routed packets and emit encrypted WireGuard packets.
    pub async fn run_outbound(
        &self,
        mut outbound_rx: mpsc::Receiver<OutboundPacket>,
    ) -> Result<()> {
        while let Some(packet) = outbound_rx.recv().await {
            if let Some(encrypted) = self.encrypt_outbound(packet).await? {
                self.encrypted_tx.send(encrypted).await.map_err(|_| {
                    DaemonError::Network("encrypted packet channel closed".to_string())
                })?;
            }
        }

        Ok(())
    }

    /// Consume encrypted network packets, decrypt them, and emit raw inbound IP packets.
    pub async fn run_inbound(
        &self,
        mut encrypted_rx: mpsc::Receiver<ReceivedEncryptedPacket>,
        inbound_tx: mpsc::Sender<InboundPacket>,
    ) -> Result<()> {
        while let Some(packet) = encrypted_rx.recv().await {
            match self.decrypt_inbound(&packet.wire_bytes).await {
                Ok(Some(inbound)) => {
                    inbound_tx.send(inbound).await.map_err(|_| {
                        DaemonError::Network("inbound packet channel closed".to_string())
                    })?;
                }
                Ok(None) => {
                    debug!("Inbound encrypted packet has no matching WireGuard session");
                }
                Err(err) => {
                    warn!(
                        "Dropping inbound encrypted packet from {:?}: {err}",
                        packet.source
                    );
                }
            }
        }

        Ok(())
    }
}

/// Drain and log encrypted packets until UDP/relay transport is attached.
pub async fn log_encrypted_packets(mut encrypted_rx: mpsc::Receiver<EncryptedPeerPacket>) {
    while let Some(packet) = encrypted_rx.recv().await {
        debug!(
            "Encrypted packet ready for peer {} (dst={}, {} bytes)",
            packet.peer_id,
            packet.dst_ip,
            packet.wire_bytes.len()
        );
    }
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use p2pnet_crypto::NodeIdentity;
    use p2pnet_tun::Ipv4Packet;
    use p2pnet_wireguard::{
        HandshakeInitiator, HandshakeResponder, TransportSession, TYPE_TRANSPORT,
    };
    use tokio::sync::mpsc;

    use super::*;

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
    async fn encrypts_outbound_packet_with_peer_session() {
        let (node_a_session, mut node_b_session) = establish_sessions();
        let (transport, mut encrypted_rx) = WireGuardTransport::new();
        transport.add_session("peer-b", node_a_session).await;

        let packet = Ipv4Packet::build_icmp_echo_request(
            Ipv4Addr::new(10, 20, 0, 1),
            Ipv4Addr::new(10, 20, 0, 2),
            0x1234,
            1,
            b"ping",
        );

        let (outbound_tx, outbound_rx) = mpsc::channel(4);
        let worker = {
            let transport = transport.clone();
            tokio::spawn(async move { transport.run_outbound(outbound_rx).await })
        };

        outbound_tx
            .send(OutboundPacket {
                peer_id: "peer-b".to_string(),
                dst_ip: "10.20.0.2".to_string(),
                packet: packet.clone(),
            })
            .await
            .unwrap();

        let encrypted = encrypted_rx.recv().await.unwrap();
        assert_eq!(encrypted.peer_id, "peer-b");
        assert_eq!(encrypted.dst_ip, "10.20.0.2");
        assert_eq!(encrypted.wire_bytes[0], TYPE_TRANSPORT);

        let decrypted = node_b_session
            .decrypt_from_bytes(&encrypted.wire_bytes)
            .unwrap();
        assert_eq!(decrypted, packet);

        worker.abort();
    }

    #[tokio::test]
    async fn drops_outbound_packet_without_session() {
        let (transport, mut encrypted_rx) = WireGuardTransport::new();

        let dropped = transport
            .encrypt_outbound(OutboundPacket {
                peer_id: "missing-peer".to_string(),
                dst_ip: "10.20.0.9".to_string(),
                packet: vec![0x45, 0x00, 0x00, 0x14],
            })
            .await
            .unwrap();

        assert!(dropped.is_none());
        assert!(encrypted_rx.try_recv().is_err());
    }

    #[tokio::test]
    async fn decrypts_inbound_packet_with_matching_receiver_index() {
        let (mut node_a_session, node_b_session) = establish_sessions();
        let (transport, _encrypted_rx) = WireGuardTransport::new();
        transport.add_session("peer-a", node_b_session).await;

        let packet = Ipv4Packet::build_icmp_echo_request(
            Ipv4Addr::new(10, 20, 0, 1),
            Ipv4Addr::new(10, 20, 0, 2),
            0x1234,
            1,
            b"ping",
        );
        let wire_bytes = node_a_session.encrypt_to_bytes(&packet).unwrap();

        let inbound = transport
            .decrypt_inbound(&wire_bytes)
            .await
            .unwrap()
            .unwrap();

        assert_eq!(inbound.peer_id, "peer-a");
        assert_eq!(inbound.packet, packet);
    }

    #[tokio::test]
    async fn drops_inbound_packet_without_matching_session() {
        let (mut node_a_session, _node_b_session) = establish_sessions();
        let (transport, _encrypted_rx) = WireGuardTransport::new();

        let packet = Ipv4Packet::build_icmp_echo_request(
            Ipv4Addr::new(10, 20, 0, 1),
            Ipv4Addr::new(10, 20, 0, 2),
            0x1234,
            1,
            b"ping",
        );
        let wire_bytes = node_a_session.encrypt_to_bytes(&packet).unwrap();

        let inbound = transport.decrypt_inbound(&wire_bytes).await.unwrap();
        assert!(inbound.is_none());
    }
}
