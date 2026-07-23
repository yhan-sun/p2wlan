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
use crate::peer::PeerManager;

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
    /// Relay endpoint that delivered this packet, when received through Relay.
    pub relay_endpoint: Option<String>,
    /// Relay-authenticated source node ID, checked against the decrypted session owner.
    pub relay_peer_id: Option<String>,
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

    /// Replace a session and return the previous value for transactional rollback.
    pub async fn replace_session(
        &self,
        peer_id: impl Into<String>,
        session: TransportSession,
    ) -> Option<TransportSession> {
        self.sessions.lock().await.insert(peer_id.into(), session)
    }

    /// Restore the session state captured before a transactional replacement.
    pub async fn restore_session(&self, peer_id: &str, previous: Option<TransportSession>) {
        let mut sessions = self.sessions.lock().await;
        if let Some(previous) = previous {
            sessions.insert(peer_id.to_string(), previous);
        } else {
            sessions.remove(peer_id);
        }
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
        // Session expiry is an expected boundary during a rekey.  It must not
        // terminate the long-lived TUN-to-WireGuard worker: the handshake
        // maintenance loop will notice the missing session and establish a
        // replacement.  Dropping this one packet is preferable to tearing
        // down the entire overlay (and the diagnostics endpoint) while a
        // replacement handshake is in flight.
        if sessions
            .get(&packet.peer_id)
            .is_some_and(TransportSession::is_expired)
        {
            sessions.remove(&packet.peer_id);
            debug!(
                "WireGuard session for peer {} expired; dropping {} byte packet until rekey completes",
                packet.peer_id,
                packet.packet.len()
            );
            return Ok(None);
        }
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
        encrypted_rx: mpsc::Receiver<ReceivedEncryptedPacket>,
        inbound_tx: mpsc::Sender<InboundPacket>,
    ) -> Result<()> {
        self.run_inbound_with_peers(encrypted_rx, inbound_tx, None)
            .await
    }

    /// Consume encrypted network packets and confirm direct UDP only after
    /// successful WireGuard decryption.
    pub async fn run_inbound_with_peers(
        &self,
        mut encrypted_rx: mpsc::Receiver<ReceivedEncryptedPacket>,
        inbound_tx: mpsc::Sender<InboundPacket>,
        peers: Option<Arc<PeerManager>>,
    ) -> Result<()> {
        while let Some(packet) = encrypted_rx.recv().await {
            let source = packet.source;
            let relay_endpoint = packet.relay_endpoint;
            let relay_peer_id = packet.relay_peer_id;
            match self.decrypt_inbound(&packet.wire_bytes).await {
                Ok(Some(inbound)) => {
                    if relay_peer_id
                        .as_deref()
                        .is_some_and(|relay_peer_id| relay_peer_id != inbound.peer_id)
                    {
                        warn!(
                            "Dropping relay packet whose registered source {:?} does not match decrypted peer {}",
                            relay_peer_id, inbound.peer_id
                        );
                        continue;
                    }
                    if let Some(peers) = peers.as_ref() {
                        if let Some(source) = source {
                            peers
                                .learn_authenticated_endpoint(&inbound.peer_id, source)
                                .await;
                            peers
                                .record_direct_success(&inbound.peer_id, Some(source))
                                .await;
                            debug!(
                                "Confirmed direct UDP data path from {source} for peer {}",
                                inbound.peer_id
                            );
                        } else if let Some(relay_endpoint) = relay_endpoint {
                            peers
                                .record_relay_success(&inbound.peer_id, &relay_endpoint, true)
                                .await;
                            debug!(
                                "Confirmed relay data path through {relay_endpoint} for peer {}",
                                inbound.peer_id
                            );
                        }
                    }
                    inbound_tx.send(inbound).await.map_err(|_| {
                        DaemonError::Network("inbound packet channel closed".to_string())
                    })?;
                }
                Ok(None) => {
                    debug!("Inbound encrypted packet has no matching WireGuard session");
                }
                Err(err) => {
                    warn!("Dropping inbound encrypted packet from {:?}: {err}", source);
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
    use std::time::Duration;

    use p2pnet_crypto::NodeIdentity;
    use p2pnet_tun::Ipv4Packet;
    use p2pnet_wireguard::{
        HandshakeInitiator, HandshakeResponder, TransportSession, TYPE_TRANSPORT,
    };
    use tokio::sync::mpsc;

    use super::*;
    use crate::config::Config;
    use crate::control::PeerInfo;
    use crate::peer::{ConnectionState, NetworkPath};

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
    async fn drops_expired_outbound_session_without_stopping_transport() {
        let (_remote, local) = establish_sessions();
        let (transport, mut encrypted_rx) = WireGuardTransport::new();
        transport
            .add_session(
                "peer-a",
                local.with_thresholds(u64::MAX, Duration::MAX, 0, Duration::MAX),
            )
            .await;

        let dropped = transport
            .encrypt_outbound(OutboundPacket {
                peer_id: "peer-a".to_string(),
                dst_ip: "10.20.0.1".to_string(),
                packet: vec![0x45, 0x00, 0x00, 0x14],
            })
            .await
            .unwrap();

        assert!(dropped.is_none());
        assert!(!transport.has_session("peer-a").await);
        assert!(encrypted_rx.try_recv().is_err());
    }

    #[tokio::test]
    async fn transactional_session_replacement_can_restore_previous_session() {
        let (mut old_remote, old_local) = establish_sessions();
        let (_new_remote, new_local) = establish_sessions();
        let (transport, _encrypted_rx) = WireGuardTransport::new();
        transport.add_session("peer-a", old_local).await;

        let previous = transport.replace_session("peer-a", new_local).await;
        assert!(previous.is_some());
        transport.restore_session("peer-a", previous).await;

        let packet = Ipv4Packet::build_icmp_echo_request(
            Ipv4Addr::new(10, 20, 0, 1),
            Ipv4Addr::new(10, 20, 0, 2),
            0x1234,
            1,
            b"old-session",
        );
        let wire_bytes = old_remote.encrypt_to_bytes(&packet).unwrap();
        let inbound = transport
            .decrypt_inbound(&wire_bytes)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(inbound.peer_id, "peer-a");
        assert_eq!(inbound.packet, packet);
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
    async fn confirms_relay_only_after_wireguard_decryption() {
        let (mut remote_session, local_session) = establish_sessions();
        let (transport, _encrypted_rx) = WireGuardTransport::new();
        transport.add_session("peer-a", local_session).await;

        let peers = Arc::new(PeerManager::new(
            Config::generate_default("http://ctrl.test", "default").unwrap(),
        ));
        peers
            .add_peer(&PeerInfo {
                node_id: "peer-a".to_string(),
                virtual_ip: "10.20.0.1".to_string(),
                online: true,
                ..PeerInfo::default()
            })
            .await;

        let packet = Ipv4Packet::build_icmp_echo_request(
            Ipv4Addr::new(10, 20, 0, 1),
            Ipv4Addr::new(10, 20, 0, 2),
            0x1234,
            1,
            b"ping",
        );
        let wire_bytes = remote_session.encrypt_to_bytes(&packet).unwrap();
        let (encrypted_tx, encrypted_rx) = mpsc::channel(1);
        let (inbound_tx, mut inbound_rx) = mpsc::channel(1);
        let worker = tokio::spawn({
            let transport = transport.clone();
            let peers = peers.clone();
            async move {
                transport
                    .run_inbound_with_peers(encrypted_rx, inbound_tx, Some(peers))
                    .await
            }
        });

        encrypted_tx
            .send(ReceivedEncryptedPacket {
                source: None,
                relay_endpoint: Some("tls://relay.test:443".to_string()),
                relay_peer_id: Some("peer-a".to_string()),
                wire_bytes,
            })
            .await
            .unwrap();
        let inbound = inbound_rx.recv().await.unwrap();
        assert_eq!(inbound.peer_id, "peer-a");

        let conn = peers.get_connection("peer-a").await.unwrap();
        assert_eq!(conn.state, ConnectionState::Relay);
        assert_eq!(conn.active_path(), Some(NetworkPath::Relay));
        assert_eq!(conn.relay_server.as_deref(), Some("tls://relay.test:443"));

        drop(encrypted_tx);
        worker.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn rejects_relay_source_that_does_not_match_decrypted_peer() {
        let (mut remote_session, local_session) = establish_sessions();
        let (transport, _encrypted_rx) = WireGuardTransport::new();
        transport.add_session("peer-a", local_session).await;

        let peers = Arc::new(PeerManager::new(
            Config::generate_default("http://ctrl.test", "default").unwrap(),
        ));
        peers
            .add_peer(&PeerInfo {
                node_id: "peer-a".to_string(),
                virtual_ip: "10.20.0.1".to_string(),
                online: true,
                ..PeerInfo::default()
            })
            .await;

        let packet = Ipv4Packet::build_icmp_echo_request(
            Ipv4Addr::new(10, 20, 0, 1),
            Ipv4Addr::new(10, 20, 0, 2),
            0x1234,
            1,
            b"ping",
        );
        let wire_bytes = remote_session.encrypt_to_bytes(&packet).unwrap();
        let (encrypted_tx, encrypted_rx) = mpsc::channel(1);
        let (inbound_tx, mut inbound_rx) = mpsc::channel(1);
        let worker = tokio::spawn({
            let transport = transport.clone();
            let peers = peers.clone();
            async move {
                transport
                    .run_inbound_with_peers(encrypted_rx, inbound_tx, Some(peers))
                    .await
            }
        });

        encrypted_tx
            .send(ReceivedEncryptedPacket {
                source: None,
                relay_endpoint: Some("tls://relay.test:443".to_string()),
                relay_peer_id: Some("different-peer".to_string()),
                wire_bytes,
            })
            .await
            .unwrap();
        assert!(
            tokio::time::timeout(Duration::from_millis(50), inbound_rx.recv())
                .await
                .is_err()
        );

        let conn = peers.get_connection("peer-a").await.unwrap();
        assert_eq!(conn.state, ConnectionState::Idle);
        assert_eq!(conn.relay_server, None);

        drop(encrypted_tx);
        worker.await.unwrap().unwrap();
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
