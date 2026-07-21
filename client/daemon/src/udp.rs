//! UDP transport for encrypted peer packets.
//!
//! The WireGuard adapter produces serialized transport messages keyed by peer
//! ID. This module is the direct UDP sink: it resolves each peer endpoint from
//! `PeerManager` and sends the encrypted datagram to that socket address.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use p2pnet_nat::{
    build_authenticated_punch_ack, build_authenticated_punch_packet, build_punch_ack,
    build_punch_packet, decode_authenticated_punch_packet, decode_punch_packet,
    gather_candidate_report, peek_authenticated_punch_identity, CandidateGatherReport, IceConfig,
    PunchPacketKind,
};
use tokio::net::UdpSocket;
use tokio::sync::{mpsc, Mutex};
use tokio::time::{interval, sleep};
use tracing::{debug, trace, warn};

use crate::error::{DaemonError, Result};
use crate::peer::{PeerManager, REASON_DIRECT_SEND_FAILED};
use crate::transport::{EncryptedPeerPacket, ReceivedEncryptedPacket};

type ProbeNonce = [u8; 8];
type PendingProbes = Arc<Mutex<HashMap<ProbeNonce, PendingProbe>>>;

#[derive(Debug, Clone)]
struct PendingProbe {
    sent_at: Instant,
    endpoint: SocketAddr,
    generation: u64,
    peer_id: Option<String>,
    authenticated: bool,
}

/// Sends encrypted WireGuard packets over direct UDP endpoints.
#[derive(Clone)]
pub struct UdpTransport {
    socket: Arc<UdpSocket>,
    peers: Arc<PeerManager>,
    pending_probes: PendingProbes,
    local_node_id: Option<String>,
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
            pending_probes: Arc::new(Mutex::new(HashMap::new())),
            local_node_id: None,
        })
    }

    /// Attach the local control-plane node ID used by authenticated UDP Probe v2.
    pub fn with_local_node_id(mut self, node_id: impl Into<String>) -> Self {
        self.local_node_id = Some(node_id.into());
        self
    }

    async fn send_probe(&self, peer_id: Option<&str>, peer_addr: SocketAddr) -> Result<()> {
        let generation = self.peers.current_network_generation().await;
        let authenticated_probe = match (peer_id, self.local_node_id.as_deref()) {
            (Some(peer_id), Some(local_node_id))
                if local_node_id.len() <= u8::MAX as usize && peer_id.len() <= u8::MAX as usize =>
            {
                self.peers.probe_key_for_peer(peer_id).await.map(|key| {
                    let (bytes, nonce) =
                        build_authenticated_punch_packet(local_node_id, peer_id, generation, &key);
                    (bytes, nonce)
                })
            }
            _ => None,
        };

        let (bytes, nonce, authenticated) = if let Some((bytes, nonce)) = authenticated_probe {
            (bytes, nonce, true)
        } else {
            let bytes = build_punch_packet();
            let nonce = decode_punch_packet(&bytes)
                .map(|packet| packet.nonce)
                .ok_or_else(|| DaemonError::Network("failed to create UDP probe".to_string()))?;
            (bytes.to_vec(), nonce, false)
        };

        {
            let mut pending = self.pending_probes.lock().await;
            pending.retain(|_, pending| {
                pending.sent_at.elapsed() < Duration::from_secs(60)
                    && pending.generation == generation
            });
            pending.insert(
                nonce,
                PendingProbe {
                    sent_at: Instant::now(),
                    endpoint: peer_addr,
                    generation,
                    peer_id: peer_id.map(str::to_string),
                    authenticated,
                },
            );
        }

        if let Err(error) = self.socket.send_to(&bytes, peer_addr).await {
            self.pending_probes.lock().await.remove(&nonce);
            return Err(DaemonError::Network(format!(
                "UDP probe send to {peer_addr} failed: {error}"
            )));
        }
        Ok(())
    }

    /// Return the local UDP socket address.
    pub fn local_addr(&self) -> Result<SocketAddr> {
        self.socket
            .local_addr()
            .map_err(|e| DaemonError::Network(format!("failed to read UDP local addr: {e}")))
    }

    /// Gather ICE-style candidate endpoints for this UDP socket.
    pub async fn gather_candidates(
        &self,
        stun_servers: Vec<SocketAddr>,
        stun_timeout: Duration,
    ) -> Result<Vec<String>> {
        let report = self
            .gather_candidate_report(stun_servers, stun_timeout)
            .await?;

        Ok(report
            .candidates
            .into_iter()
            .map(|candidate| candidate.endpoint.to_string())
            .collect())
    }

    /// Gather ICE-style candidates plus STUN/NAT behavior diagnostics.
    pub async fn gather_candidate_report(
        &self,
        stun_servers: Vec<SocketAddr>,
        stun_timeout: Duration,
    ) -> Result<CandidateGatherReport> {
        let config = IceConfig {
            stun_servers,
            stun_timeout,
            gather_host: true,
            gather_srflx: true,
        };

        gather_candidate_report(&self.socket, &config)
            .await
            .map_err(|e| DaemonError::Network(format!("ICE candidate gathering failed: {e}")))
    }

    /// Send active UDP probes to every candidate for a peer.
    pub async fn punch_candidates(
        &self,
        peer_id: &str,
        candidates: Vec<SocketAddr>,
        probe_interval: Duration,
        attempts: u32,
    ) -> Result<u32> {
        if candidates.is_empty() || attempts == 0 {
            return Ok(0);
        }

        let mut packets_sent = 0;
        for attempt in 0..attempts {
            for &candidate in &candidates {
                match self.send_probe(Some(peer_id), candidate).await {
                    Ok(()) => {
                        packets_sent += 1;
                        trace!(
                            "Sent punch probe {} to peer {} candidate {}",
                            attempt + 1,
                            peer_id,
                            candidate
                        );
                    }
                    Err(err) => {
                        debug!(
                            "Failed to send punch probe to peer {} candidate {}: {}",
                            peer_id, candidate, err
                        );
                    }
                }
            }

            if attempt + 1 < attempts {
                sleep(probe_interval).await;
            }
        }

        Ok(packets_sent)
    }

    /// Send a single encrypted packet.
    ///
    /// Returns `Ok(Some(bytes))` when sent, `Ok(None)` when no endpoint is known
    /// for the destination peer, and `Err` for socket-level failures.
    pub async fn send_packet(&self, packet: &EncryptedPeerPacket) -> Result<Option<usize>> {
        let Some(endpoint) = self.peers.direct_endpoint_for_send(&packet.peer_id).await else {
            trace!(
                "No UDP endpoint for {}; dropping {} byte encrypted packet",
                packet.peer_id,
                packet.wire_bytes.len()
            );
            return Ok(None);
        };

        self.send_packet_to(packet, endpoint).await.map(Some)
    }

    /// Send a single encrypted packet to a selector-provided direct endpoint.
    pub async fn send_packet_to(
        &self,
        packet: &EncryptedPeerPacket,
        endpoint: SocketAddr,
    ) -> Result<usize> {
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
        self.peers.record_sent(&packet.peer_id, sent as u64).await;
        Ok(sent)
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

    /// Periodically refresh direct UDP NAT mappings.
    pub async fn run_keepalives(self, keepalive_interval: Duration) {
        if keepalive_interval.is_zero() {
            return;
        }

        let mut ticker = interval(keepalive_interval);
        loop {
            ticker.tick().await;

            for (peer_id, endpoint) in self.peers.direct_endpoints().await {
                match self.send_probe(Some(&peer_id), endpoint).await {
                    Ok(()) => {
                        trace!("Sent direct UDP keepalive to peer {peer_id} at {endpoint}");
                    }
                    Err(err) => {
                        self.peers
                            .record_direct_failure_with_code(
                                &peer_id,
                                REASON_DIRECT_SEND_FAILED,
                                format!("direct keepalive to {endpoint} failed: {err}"),
                            )
                            .await;
                        debug!(
                            "Failed to send direct UDP keepalive to peer {peer_id} at {endpoint}: {err}"
                        );
                    }
                }
            }
        }
    }

    /// Receive encrypted UDP datagrams until the socket or channel closes.
    pub async fn run_inbound(
        self,
        inbound_tx: mpsc::Sender<ReceivedEncryptedPacket>,
    ) -> Result<()> {
        let mut buf = vec![0u8; 65_535];

        loop {
            let (n, source) = match self.socket.recv_from(&mut buf).await {
                Ok(packet) => packet,
                Err(err) if is_ignorable_udp_receive_error(&err) => {
                    debug!("Ignoring transient UDP receive error on direct transport: {err}");
                    continue;
                }
                Err(err) => {
                    return Err(DaemonError::Network(format!(
                        "UDP receive on direct transport failed: {err}"
                    )));
                }
            };

            if n == 0 {
                continue;
            }

            let data = &buf[..n];

            if is_authenticated_punch_candidate(data) {
                let Some(identity) = peek_authenticated_punch_identity(data) else {
                    trace!("Ignored malformed authenticated UDP probe from {source}");
                    continue;
                };
                let Some(local_node_id) = self.local_node_id.as_deref() else {
                    trace!(
                        "Ignored authenticated UDP probe from {source}; local node ID is unknown"
                    );
                    continue;
                };
                if identity.target_node_id != local_node_id {
                    trace!(
                        "Ignored authenticated UDP probe from {} for target {}",
                        identity.source_node_id,
                        identity.target_node_id
                    );
                    continue;
                }
                let Some(key) = self
                    .peers
                    .probe_key_for_peer(&identity.source_node_id)
                    .await
                else {
                    trace!(
                        "Ignored authenticated UDP probe from {}; no Probe v2 MAC key",
                        identity.source_node_id
                    );
                    continue;
                };
                let Some(packet) = decode_authenticated_punch_packet(data, &key) else {
                    trace!(
                        "Ignored authenticated UDP probe from {}; invalid MAC",
                        identity.source_node_id
                    );
                    continue;
                };

                match packet.kind {
                    PunchPacketKind::Punch => {
                        let learned = self
                            .peers
                            .learn_authenticated_endpoint(&identity.source_node_id, source)
                            .await;
                        if !learned {
                            trace!(
                                "Ignored authenticated UDP punch from {}; peer disappeared before endpoint learning",
                                identity.source_node_id
                            );
                            continue;
                        }
                        self.peers
                            .record_direct_probe_success(&identity.source_node_id, source)
                            .await;

                        let generation = self.peers.current_network_generation().await;
                        let ack = build_authenticated_punch_ack(
                            packet.nonce,
                            local_node_id,
                            &identity.source_node_id,
                            generation,
                            &key,
                        );
                        match self.socket.send_to(&ack, source).await {
                            Ok(_) => {
                                debug!(
                                    "Received authenticated UDP punch from peer {} at {}; sent ACK",
                                    identity.source_node_id, source
                                );
                            }
                            Err(err) => warn!(
                                "Failed to ACK authenticated UDP punch from peer {} at {}: {}",
                                identity.source_node_id, source, err
                            ),
                        }
                    }
                    PunchPacketKind::Ack => {
                        let ack_match = {
                            let generation = self.peers.current_network_generation().await;
                            let mut pending = self.pending_probes.lock().await;
                            pending
                                .remove(&packet.nonce)
                                .filter(|pending| {
                                    pending.generation == generation
                                        && pending.peer_id.as_deref()
                                            == Some(identity.source_node_id.as_str())
                                        && pending.authenticated
                                })
                                .map(|pending| (pending.sent_at.elapsed(), pending.generation))
                        };

                        if let Some((latency, generation)) = ack_match {
                            self.peers
                                .learn_authenticated_endpoint(&identity.source_node_id, source)
                                .await;
                            let accepted = self
                                .peers
                                .record_direct_probe_success_with_latency_for_generation(
                                    &identity.source_node_id,
                                    source,
                                    Some(latency),
                                    generation,
                                )
                                .await;
                            if accepted {
                                debug!(
                                    "Received authenticated UDP punch ACK from peer {} at {} (rtt={latency:?})",
                                    identity.source_node_id, source
                                );
                            } else {
                                trace!(
                                    "Ignored stale authenticated UDP punch ACK from peer {} at {}",
                                    identity.source_node_id,
                                    source
                                );
                            }
                        } else {
                            trace!(
                                "Ignored unmatched authenticated UDP punch ACK from peer {} at {}",
                                identity.source_node_id,
                                source
                            );
                        }
                    }
                }
                continue;
            }

            if let Some(packet) = decode_punch_packet(data) {
                match packet.kind {
                    PunchPacketKind::Punch => {
                        let ack = build_punch_ack(packet.nonce);
                        match self.socket.send_to(&ack, source).await {
                            Ok(_) => {
                                debug!("Received UDP punch from {source}; sent ACK");
                                if let Some(peer_id) =
                                    self.peers.learn_endpoint_from_addr(source).await
                                {
                                    self.peers
                                        .record_direct_probe_success(&peer_id, source)
                                        .await;
                                    debug!(
                                        "Recorded direct UDP probe success from peer {peer_id} at {source}"
                                    );
                                }
                            }
                            Err(err) => warn!("Failed to ACK UDP punch from {source}: {err}"),
                        }
                    }
                    PunchPacketKind::Ack => {
                        let ack_match = {
                            let generation = self.peers.current_network_generation().await;
                            let mut pending = self.pending_probes.lock().await;
                            pending
                                .remove(&packet.nonce)
                                .filter(|pending| {
                                    pending.endpoint == source
                                        && pending.generation == generation
                                        && !pending.authenticated
                                })
                                .map(|pending| (pending.sent_at.elapsed(), pending.generation))
                        };
                        if let Some(peer_id) = self.peers.learn_endpoint_from_addr(source).await {
                            if let Some((latency, generation)) = ack_match {
                                let accepted = self
                                    .peers
                                    .record_direct_probe_success_with_latency_for_generation(
                                        &peer_id,
                                        source,
                                        Some(latency),
                                        generation,
                                    )
                                    .await;
                                if accepted {
                                    debug!(
                                        "Received UDP punch ACK from peer {peer_id} at {source} (rtt={latency:?})"
                                    );
                                } else {
                                    trace!(
                                        "Ignored stale UDP punch ACK from peer {peer_id} at {source}"
                                    );
                                }
                            } else {
                                trace!("Ignored stale or unmatched UDP punch ACK from {source}");
                            }
                        } else {
                            trace!("Received UDP punch ACK from unknown candidate {source}");
                        }
                    }
                }
                continue;
            }

            if let Some(peer_id) = self.peers.learn_endpoint_from_addr(source).await {
                trace!("Learned encrypted UDP source {source} for peer {peer_id}");
            }

            inbound_tx
                .send(ReceivedEncryptedPacket {
                    source: Some(source),
                    wire_bytes: data.to_vec(),
                })
                .await
                .map_err(|_| {
                    DaemonError::Network("received encrypted packet channel closed".to_string())
                })?;

            debug!("Received {n} encrypted UDP bytes from {source}");
        }
    }
}

fn is_ignorable_udp_receive_error(error: &std::io::Error) -> bool {
    #[cfg(target_os = "windows")]
    {
        error.raw_os_error() == Some(10054) || error.kind() == std::io::ErrorKind::ConnectionReset
    }

    #[cfg(not(target_os = "windows"))]
    {
        let _ = error;
        false
    }
}

fn is_authenticated_punch_candidate(data: &[u8]) -> bool {
    data.len() >= 5 && data.starts_with(&[0x50, 0x4e, 0x43, 0x48]) && data[4] == 2
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;
    use std::time::Duration;

    use p2pnet_crypto::NodeIdentity;
    use p2pnet_tun::{Ipv4Packet, MockTunDevice};
    use p2pnet_wireguard::{HandshakeInitiator, HandshakeResponder, TransportSession};
    use tokio::sync::mpsc;
    use tokio::time::timeout;

    use super::*;
    use crate::config::Config;
    use crate::control::PeerInfo;
    use crate::dataplane::DataPlane;
    use crate::peer::ConnectionState;
    use crate::transport::WireGuardTransport;

    fn peer(node_id: &str, virtual_ip: &str, endpoint: Option<SocketAddr>) -> PeerInfo {
        PeerInfo {
            node_id: node_id.to_string(),
            device_name: String::new(),
            public_key: "pk".to_string(),
            endpoint: endpoint.map(|addr| addr.to_string()).unwrap_or_default(),
            nat_type: "FullCone".to_string(),
            virtual_ip: virtual_ip.to_string(),
            online: true,
            last_seen: 0,
        }
    }

    fn peer_with_public_key(
        node_id: &str,
        virtual_ip: &str,
        public_key: String,
        endpoint: Option<SocketAddr>,
    ) -> PeerInfo {
        PeerInfo {
            node_id: node_id.to_string(),
            device_name: String::new(),
            public_key,
            endpoint: endpoint.map(|addr| addr.to_string()).unwrap_or_default(),
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

    fn config_for_identity(identity: &NodeIdentity, node_id: &str) -> Config {
        let mut config = Config::generate_default("http://ctrl.test", "default").unwrap();
        config.node.node_id = node_id.to_string();
        config.node.public_key = hex::encode(identity.public_key());
        config.node.private_key = hex::encode(identity.private_key());
        config
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
    async fn gathers_host_candidates_for_bound_udp_port() {
        let peers = peer_manager();
        let transport = UdpTransport::bind("127.0.0.1:0".parse().unwrap(), peers)
            .await
            .unwrap();
        let local_port = transport.local_addr().unwrap().port();

        let candidates = transport
            .gather_candidates(Vec::new(), Duration::from_millis(100))
            .await
            .unwrap();

        assert!(!candidates.is_empty());
        assert!(candidates
            .iter()
            .any(|candidate| candidate.ends_with(&format!(":{local_port}"))));
    }

    #[tokio::test]
    async fn punch_candidates_sends_probe_datagrams() {
        let receiver = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let receiver_addr = receiver.local_addr().unwrap();

        let peers = peer_manager();
        let transport = UdpTransport::bind("127.0.0.1:0".parse().unwrap(), peers)
            .await
            .unwrap();

        let sent = transport
            .punch_candidates("peer-b", vec![receiver_addr], Duration::from_millis(10), 2)
            .await
            .unwrap();

        assert_eq!(sent, 2);

        let mut buf = [0u8; 64];
        let (n, _from) = timeout(Duration::from_secs(1), receiver.recv_from(&mut buf))
            .await
            .unwrap()
            .unwrap();
        let packet = decode_punch_packet(&buf[..n]).unwrap();
        assert_eq!(packet.kind, PunchPacketKind::Punch);
    }

    #[tokio::test]
    async fn send_probe_uses_authenticated_v2_when_key_is_available() {
        let local_identity = NodeIdentity::generate();
        let peer_identity = NodeIdentity::generate();
        let receiver = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let receiver_addr = receiver.local_addr().unwrap();

        let peers = Arc::new(PeerManager::new(config_for_identity(
            &local_identity,
            "peer-a",
        )));
        peers
            .add_peer(&peer_with_public_key(
                "peer-b",
                "10.20.0.2",
                hex::encode(peer_identity.public_key()),
                Some(receiver_addr),
            ))
            .await;

        let transport = UdpTransport::bind("127.0.0.1:0".parse().unwrap(), peers.clone())
            .await
            .unwrap()
            .with_local_node_id("peer-a");
        transport
            .send_probe(Some("peer-b"), receiver_addr)
            .await
            .unwrap();

        let mut buf = [0u8; 512];
        let (n, _from) = timeout(Duration::from_secs(1), receiver.recv_from(&mut buf))
            .await
            .unwrap()
            .unwrap();

        assert!(decode_punch_packet(&buf[..n]).is_none());
        let identity = peek_authenticated_punch_identity(&buf[..n]).unwrap();
        assert_eq!(identity.kind, PunchPacketKind::Punch);
        assert_eq!(identity.source_node_id, "peer-a");
        assert_eq!(identity.target_node_id, "peer-b");

        let key = peers.probe_key_for_peer("peer-b").await.unwrap();
        let packet = decode_authenticated_punch_packet(&buf[..n], &key).unwrap();
        assert_eq!(packet.kind, PunchPacketKind::Punch);
        assert_eq!(packet.source_node_id.as_deref(), Some("peer-a"));
        assert_eq!(packet.target_node_id.as_deref(), Some("peer-b"));
        assert!(packet.authenticated);
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

    #[tokio::test]
    async fn run_inbound_emits_received_encrypted_datagram() {
        let peers = peer_manager();
        let transport = UdpTransport::bind("127.0.0.1:0".parse().unwrap(), peers)
            .await
            .unwrap();
        let local_addr = transport.local_addr().unwrap();
        let (tx, mut rx) = mpsc::channel(4);
        let worker = tokio::spawn(transport.run_inbound(tx));

        let sender = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let payload = vec![4, 9, 8, 7, 6, 5];
        sender.send_to(&payload, local_addr).await.unwrap();

        let received = timeout(Duration::from_secs(1), rx.recv())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(received.source, Some(sender.local_addr().unwrap()));
        assert_eq!(received.wire_bytes, payload);

        worker.abort();
    }

    #[tokio::test]
    async fn run_inbound_acks_punch_and_does_not_forward_to_wireguard() {
        let peers = peer_manager();
        let sender = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let sender_addr = sender.local_addr().unwrap();

        peers.add_peer(&peer("peer-b", "10.20.0.2", None)).await;
        peers
            .add_candidates("peer-b", &[sender_addr.to_string()])
            .await;

        let transport = UdpTransport::bind("127.0.0.1:0".parse().unwrap(), peers.clone())
            .await
            .unwrap();
        let local_addr = transport.local_addr().unwrap();
        let (tx, mut rx) = mpsc::channel(4);
        let worker = tokio::spawn(transport.run_inbound(tx));

        sender
            .send_to(&p2pnet_nat::build_punch_packet(), local_addr)
            .await
            .unwrap();

        let mut buf = [0u8; 64];
        let (n, _from) = timeout(Duration::from_secs(1), sender.recv_from(&mut buf))
            .await
            .unwrap()
            .unwrap();
        let ack = decode_punch_packet(&buf[..n]).unwrap();
        assert_eq!(ack.kind, PunchPacketKind::Ack);

        assert!(timeout(Duration::from_millis(100), rx.recv())
            .await
            .is_err());

        let conn = peers.get_connection("peer-b").await.unwrap();
        assert_eq!(conn.endpoint, Some(sender_addr));
        assert_eq!(conn.state.to_string(), "hole_punching");
        assert!(conn.direct_health.last_success_at.is_some());

        worker.abort();
    }

    #[tokio::test]
    async fn run_inbound_accepts_authenticated_peer_reflexive_probe() {
        let local_identity = NodeIdentity::generate();
        let peer_identity = NodeIdentity::generate();
        let peers = Arc::new(PeerManager::new(config_for_identity(
            &local_identity,
            "peer-a",
        )));
        peers
            .add_peer(&peer_with_public_key(
                "peer-b",
                "10.20.0.2",
                hex::encode(peer_identity.public_key()),
                None,
            ))
            .await;

        let key = peers.probe_key_for_peer("peer-b").await.unwrap();
        let transport = UdpTransport::bind("127.0.0.1:0".parse().unwrap(), peers.clone())
            .await
            .unwrap()
            .with_local_node_id("peer-a");
        let local_addr = transport.local_addr().unwrap();
        let (tx, mut rx) = mpsc::channel(4);
        let worker = tokio::spawn(transport.run_inbound(tx));

        let sender = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let sender_addr = sender.local_addr().unwrap();
        let (probe, nonce) = build_authenticated_punch_packet("peer-b", "peer-a", 7, &key);
        sender.send_to(&probe, local_addr).await.unwrap();

        let mut buf = [0u8; 512];
        let (n, _from) = timeout(Duration::from_secs(1), sender.recv_from(&mut buf))
            .await
            .unwrap()
            .unwrap();
        let ack = decode_authenticated_punch_packet(&buf[..n], &key).unwrap();
        assert_eq!(ack.kind, PunchPacketKind::Ack);
        assert_eq!(ack.nonce, nonce);
        assert_eq!(ack.source_node_id.as_deref(), Some("peer-a"));
        assert_eq!(ack.target_node_id.as_deref(), Some("peer-b"));

        assert!(timeout(Duration::from_millis(100), rx.recv())
            .await
            .is_err());

        let conn = peers.get_connection("peer-b").await.unwrap();
        assert_eq!(conn.endpoint, Some(sender_addr));
        assert!(conn.candidates.contains(&sender_addr.to_string()));
        assert_eq!(conn.state.to_string(), "hole_punching");
        assert!(conn.direct_health.last_success_at.is_some());

        worker.abort();
    }

    #[tokio::test]
    async fn run_inbound_rejects_authenticated_probe_with_invalid_mac() {
        let local_identity = NodeIdentity::generate();
        let peer_identity = NodeIdentity::generate();
        let peers = Arc::new(PeerManager::new(config_for_identity(
            &local_identity,
            "peer-a",
        )));
        peers
            .add_peer(&peer_with_public_key(
                "peer-b",
                "10.20.0.2",
                hex::encode(peer_identity.public_key()),
                None,
            ))
            .await;

        let key = peers.probe_key_for_peer("peer-b").await.unwrap();
        let transport = UdpTransport::bind("127.0.0.1:0".parse().unwrap(), peers.clone())
            .await
            .unwrap()
            .with_local_node_id("peer-a");
        let local_addr = transport.local_addr().unwrap();
        let (tx, mut rx) = mpsc::channel(4);
        let worker = tokio::spawn(transport.run_inbound(tx));

        let sender = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let (mut probe, _nonce) = build_authenticated_punch_packet("peer-b", "peer-a", 7, &key);
        let last = probe.last_mut().unwrap();
        *last ^= 0x80;
        sender.send_to(&probe, local_addr).await.unwrap();

        let mut buf = [0u8; 512];
        assert!(
            timeout(Duration::from_millis(150), sender.recv_from(&mut buf))
                .await
                .is_err()
        );
        assert!(timeout(Duration::from_millis(100), rx.recv())
            .await
            .is_err());

        let conn = peers.get_connection("peer-b").await.unwrap();
        assert_eq!(conn.endpoint, None);
        assert!(conn.candidates.is_empty());

        worker.abort();
    }

    #[tokio::test]
    async fn probe_ack_records_peer_round_trip_latency() {
        let peers = peer_manager();
        let remote = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let remote_addr = remote.local_addr().unwrap();

        peers
            .add_peer(&peer("peer-b", "10.20.0.2", Some(remote_addr)))
            .await;

        let transport = UdpTransport::bind("127.0.0.1:0".parse().unwrap(), peers.clone())
            .await
            .unwrap();
        let local_addr = transport.local_addr().unwrap();
        let (tx, _rx) = mpsc::channel(4);
        let worker = tokio::spawn(transport.clone().run_inbound(tx));

        transport
            .send_probe(Some("peer-b"), remote_addr)
            .await
            .unwrap();
        let mut buf = [0u8; 64];
        let (n, _from) = timeout(Duration::from_secs(1), remote.recv_from(&mut buf))
            .await
            .unwrap()
            .unwrap();
        let probe = decode_punch_packet(&buf[..n]).unwrap();
        remote
            .send_to(&build_punch_ack(probe.nonce), local_addr)
            .await
            .unwrap();

        timeout(Duration::from_secs(1), async {
            loop {
                let diagnostics = peers.diagnostics().await;
                if diagnostics[0].direct.latency_ms.is_some() {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();

        let diagnostics = peers.diagnostics().await;
        assert!(diagnostics[0].direct.latency_ms.is_some());
        assert_eq!(diagnostics[0].direct.consecutive_failures, 0);

        worker.abort();
    }

    #[tokio::test]
    async fn authenticated_probe_ack_can_confirm_peer_reflexive_source() {
        let local_identity = NodeIdentity::generate();
        let peer_identity = NodeIdentity::generate();
        let remote_candidate = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let remote_candidate_addr = remote_candidate.local_addr().unwrap();

        let peers = Arc::new(PeerManager::new(config_for_identity(
            &local_identity,
            "peer-a",
        )));
        peers
            .add_peer(&peer_with_public_key(
                "peer-b",
                "10.20.0.2",
                hex::encode(peer_identity.public_key()),
                Some(remote_candidate_addr),
            ))
            .await;
        let key = peers.probe_key_for_peer("peer-b").await.unwrap();

        let transport = UdpTransport::bind("127.0.0.1:0".parse().unwrap(), peers.clone())
            .await
            .unwrap()
            .with_local_node_id("peer-a");
        let local_addr = transport.local_addr().unwrap();
        let (tx, _rx) = mpsc::channel(4);
        let worker = tokio::spawn(transport.clone().run_inbound(tx));

        transport
            .send_probe(Some("peer-b"), remote_candidate_addr)
            .await
            .unwrap();
        let mut probe_buf = [0u8; 512];
        let (n, _from) = timeout(
            Duration::from_secs(1),
            remote_candidate.recv_from(&mut probe_buf),
        )
        .await
        .unwrap()
        .unwrap();
        let probe = decode_authenticated_punch_packet(&probe_buf[..n], &key).unwrap();

        let peer_reflexive = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let peer_reflexive_addr = peer_reflexive.local_addr().unwrap();
        let ack = build_authenticated_punch_ack(probe.nonce, "peer-b", "peer-a", 11, &key);
        peer_reflexive.send_to(&ack, local_addr).await.unwrap();

        timeout(Duration::from_secs(1), async {
            loop {
                let conn = peers.get_connection("peer-b").await.unwrap();
                if conn.endpoint == Some(peer_reflexive_addr)
                    && conn.state == ConnectionState::Direct
                {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();

        let conn = peers.get_connection("peer-b").await.unwrap();
        assert_eq!(conn.endpoint, Some(peer_reflexive_addr));
        assert!(conn.candidates.contains(&peer_reflexive_addr.to_string()));
        assert_eq!(conn.state, ConnectionState::Direct);

        worker.abort();
    }

    #[tokio::test]
    async fn udp_inbound_decrypts_and_writes_packet_to_tun() {
        let peers = peer_manager();
        peers.add_peer(&peer("peer-a", "10.20.0.1", None)).await;

        let (tun, mut ctrl) = MockTunDevice::new_pair("test0", 1420, "10.20.0.2");
        let (mut dataplane, _outbound_rx, inbound_tx) =
            DataPlane::new_bidirectional(tun, peers.clone());
        let dataplane_worker = tokio::spawn(async move { dataplane.run().await });

        let (mut node_a_session, node_b_session) = establish_sessions();
        let (wireguard, _encrypted_rx) = WireGuardTransport::new();
        wireguard.add_session("peer-a", node_b_session).await;
        let (udp_inbound_tx, udp_inbound_rx) = mpsc::channel(4);
        let wireguard_worker = {
            let wireguard = wireguard.clone();
            let peers = peers.clone();
            tokio::spawn(async move {
                wireguard
                    .run_inbound_with_peers(udp_inbound_rx, inbound_tx, Some(peers))
                    .await
            })
        };

        let udp = UdpTransport::bind("127.0.0.1:0".parse().unwrap(), peers.clone())
            .await
            .unwrap();
        let udp_addr = udp.local_addr().unwrap();
        let udp_worker = tokio::spawn(udp.run_inbound(udp_inbound_tx));

        let ip_packet = Ipv4Packet::build_icmp_echo_request(
            Ipv4Addr::new(10, 20, 0, 1),
            Ipv4Addr::new(10, 20, 0, 2),
            0x1234,
            1,
            b"ping",
        );
        let wire_bytes = node_a_session.encrypt_to_bytes(&ip_packet).unwrap();
        let sender = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        sender.send_to(&wire_bytes, udp_addr).await.unwrap();

        let written = timeout(Duration::from_secs(1), ctrl.recv_written())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(written, ip_packet);

        let conn = peers.get_connection("peer-a").await.unwrap();
        assert_eq!(conn.bytes_received, written.len() as u64);
        assert_eq!(conn.state.to_string(), "direct");
        assert_eq!(conn.endpoint, Some(sender.local_addr().unwrap()));

        udp_worker.abort();
        wireguard_worker.abort();
        dataplane_worker.abort();
    }
}
