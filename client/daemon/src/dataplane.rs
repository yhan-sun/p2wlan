//! Data plane packet pump.
//!
//! This module is the seam between the virtual interface and the peer routing
//! table. It reads raw IP packets from TUN, resolves the destination virtual IP
//! to a peer, and emits outbound peer packets. The outbound side is intentionally
//! a channel today; the next layer can consume it with WireGuard + UDP/relay
//! transport without changing TUN packet handling.

use std::sync::Arc;

use p2pnet_tun::{IpPacket, VirtualInterface};
use tokio::sync::mpsc;
use tracing::{debug, trace, warn};

use crate::error::{DaemonError, Result};
use crate::peer::PeerManager;

/// A raw IP packet routed to a specific virtual-network peer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OutboundPacket {
    /// Destination peer node ID.
    pub peer_id: String,
    /// Destination virtual IP.
    pub dst_ip: String,
    /// Raw IP packet bytes read from TUN.
    pub packet: Vec<u8>,
}

/// A raw IP packet decrypted from a peer and ready to write into TUN.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InboundPacket {
    /// Source peer node ID.
    pub peer_id: String,
    /// Raw IP packet bytes decrypted from the peer transport session.
    pub packet: Vec<u8>,
}

/// Reads packets from a virtual interface and routes them by destination IP.
pub struct DataPlane<T> {
    tun: T,
    peers: Arc<PeerManager>,
    outbound_tx: mpsc::Sender<OutboundPacket>,
    inbound_rx: Option<mpsc::Receiver<InboundPacket>>,
}

impl<T> DataPlane<T>
where
    T: VirtualInterface + Send + 'static,
{
    /// Create a data plane and a receiver for routed outbound packets.
    pub fn new(tun: T, peers: Arc<PeerManager>) -> (Self, mpsc::Receiver<OutboundPacket>) {
        let (outbound_tx, outbound_rx) = mpsc::channel(1024);
        (
            Self {
                tun,
                peers,
                outbound_tx,
                inbound_rx: None,
            },
            outbound_rx,
        )
    }

    /// Create a bidirectional data plane.
    ///
    /// Returns the data plane, outbound routed-packet receiver, and an inbound
    /// packet sender used by the decrypting transport layer.
    pub fn new_bidirectional(
        tun: T,
        peers: Arc<PeerManager>,
    ) -> (
        Self,
        mpsc::Receiver<OutboundPacket>,
        mpsc::Sender<InboundPacket>,
    ) {
        let (outbound_tx, outbound_rx) = mpsc::channel(1024);
        let (inbound_tx, inbound_rx) = mpsc::channel(1024);
        (
            Self {
                tun,
                peers,
                outbound_tx,
                inbound_rx: Some(inbound_rx),
            },
            outbound_rx,
            inbound_tx,
        )
    }

    /// Run the packet pump until the TUN device closes or an unrecoverable error occurs.
    pub async fn run(&mut self) -> Result<()> {
        let mut buf = vec![0u8; 65_535];

        if let Some(mut inbound_rx) = self.inbound_rx.take() {
            loop {
                tokio::select! {
                    result = self.read_and_route_once(&mut buf) => {
                        result?;
                    }
                    inbound = inbound_rx.recv() => {
                        let Some(packet) = inbound else {
                            warn!("Inbound data plane channel closed; continuing outbound-only");
                            break;
                        };
                        self.write_inbound(packet).await?;
                    }
                }
            }
        }

        loop {
            self.read_and_route_once(&mut buf).await?;
        }
    }

    async fn read_and_route_once(&mut self, buf: &mut [u8]) -> Result<()> {
        let n = self
            .tun
            .read(buf)
            .await
            .map_err(|e| DaemonError::Network(format!("TUN read failed: {e}")))?;

        if n == 0 {
            return Ok(());
        }

        let packet = &buf[..n];
        let parsed = match IpPacket::new(packet) {
            Ok(parsed) => parsed,
            Err(err) => {
                warn!("Dropping invalid IP packet from TUN: {err}");
                return Ok(());
            }
        };

        let dst_ip = parsed.dst_addr_string();
        let total_len = parsed.total_len().min(n);
        let protocol = parsed.protocol();

        let Some(peer_id) = self.peers.resolve_virtual_ip(&dst_ip).await else {
            trace!("Dropping packet for unknown virtual IP {dst_ip} ({protocol})");
            return Ok(());
        };

        let routed = OutboundPacket {
            peer_id: peer_id.clone(),
            dst_ip: dst_ip.clone(),
            packet: packet[..total_len].to_vec(),
        };

        self.outbound_tx
            .send(routed)
            .await
            .map_err(|_| DaemonError::Network("outbound packet channel closed".to_string()))?;
        self.peers.record_sent(&peer_id, total_len as u64).await;

        debug!("Routed {total_len} byte {protocol} packet to {peer_id} ({dst_ip})");
        Ok(())
    }

    async fn write_inbound(&mut self, packet: InboundPacket) -> Result<()> {
        let parsed = match IpPacket::new(&packet.packet) {
            Ok(parsed) => parsed,
            Err(err) => {
                warn!(
                    "Dropping invalid inbound IP packet from peer {}: {err}",
                    packet.peer_id
                );
                return Ok(());
            }
        };

        let total_len = parsed.total_len().min(packet.packet.len());
        let protocol = parsed.protocol();
        let src_ip = parsed.src_addr_string();
        let dst_ip = parsed.dst_addr_string();

        let written = self
            .tun
            .write(&packet.packet[..total_len])
            .await
            .map_err(|e| DaemonError::Network(format!("TUN write failed: {e}")))?;

        if written != total_len {
            return Err(DaemonError::Network(format!(
                "short TUN write for inbound packet from peer {}: wrote {} of {} bytes",
                packet.peer_id, written, total_len
            )));
        }

        self.peers
            .record_received(&packet.peer_id, total_len as u64)
            .await;

        debug!(
            "Wrote {total_len} byte {protocol} packet from peer {} to TUN ({src_ip} -> {dst_ip})",
            packet.peer_id
        );
        Ok(())
    }
}

/// Drain and log routed packets until a real WireGuard/UDP transport is attached.
pub async fn log_outbound_packets(mut outbound_rx: mpsc::Receiver<OutboundPacket>) {
    while let Some(packet) = outbound_rx.recv().await {
        debug!(
            "Outbound packet ready for peer {} (dst={}, {} bytes)",
            packet.peer_id,
            packet.dst_ip,
            packet.packet.len()
        );
    }
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;
    use std::time::Duration;

    use p2pnet_tun::{Ipv4Packet, MockTunDevice};
    use tokio::time::timeout;

    use super::*;
    use crate::config::Config;
    use crate::control::PeerInfo;

    fn peer(node_id: &str, virtual_ip: &str) -> PeerInfo {
        PeerInfo {
            node_id: node_id.to_string(),
            public_key: "pk".to_string(),
            endpoint: String::new(),
            nat_type: String::new(),
            virtual_ip: virtual_ip.to_string(),
            online: true,
            last_seen: 0,
        }
    }

    #[tokio::test]
    async fn routes_tun_packet_to_peer_by_virtual_ip() {
        let peers = Arc::new(PeerManager::new(
            Config::generate_default("http://ctrl.test", "default").unwrap(),
        ));
        peers.add_peer(&peer("peer-b", "10.20.0.2")).await;

        let (tun, ctrl) = MockTunDevice::new_pair("test0", 1420, "10.20.0.1");
        let (mut dataplane, mut outbound_rx) = DataPlane::new(tun, peers.clone());
        let task = tokio::spawn(async move { dataplane.run().await });

        let packet = Ipv4Packet::build_icmp_echo_request(
            Ipv4Addr::new(10, 20, 0, 1),
            Ipv4Addr::new(10, 20, 0, 2),
            0x1234,
            1,
            b"ping",
        );
        ctrl.inject(packet.clone()).await.unwrap();

        let routed = timeout(Duration::from_secs(1), outbound_rx.recv())
            .await
            .unwrap()
            .unwrap();

        assert_eq!(routed.peer_id, "peer-b");
        assert_eq!(routed.dst_ip, "10.20.0.2");
        assert_eq!(routed.packet, packet);

        let conn = peers.get_connection("peer-b").await.unwrap();
        assert_eq!(conn.bytes_sent, routed.packet.len() as u64);

        task.abort();
    }

    #[tokio::test]
    async fn drops_packet_for_unknown_virtual_ip() {
        let peers = Arc::new(PeerManager::new(
            Config::generate_default("http://ctrl.test", "default").unwrap(),
        ));

        let (tun, ctrl) = MockTunDevice::new_pair("test0", 1420, "10.20.0.1");
        let (mut dataplane, mut outbound_rx) = DataPlane::new(tun, peers);
        let task = tokio::spawn(async move { dataplane.run().await });

        let packet = Ipv4Packet::build_icmp_echo_request(
            Ipv4Addr::new(10, 20, 0, 1),
            Ipv4Addr::new(10, 20, 0, 99),
            0x1234,
            1,
            b"ping",
        );
        ctrl.inject(packet).await.unwrap();

        let no_packet = timeout(Duration::from_millis(200), outbound_rx.recv()).await;
        assert!(no_packet.is_err());

        task.abort();
    }

    #[tokio::test]
    async fn writes_inbound_peer_packet_to_tun() {
        let peers = Arc::new(PeerManager::new(
            Config::generate_default("http://ctrl.test", "default").unwrap(),
        ));
        peers.add_peer(&peer("peer-b", "10.20.0.2")).await;

        let (tun, mut ctrl) = MockTunDevice::new_pair("test0", 1420, "10.20.0.1");
        let (mut dataplane, _outbound_rx, inbound_tx) =
            DataPlane::new_bidirectional(tun, peers.clone());
        let task = tokio::spawn(async move { dataplane.run().await });

        let packet = Ipv4Packet::build_icmp_echo_request(
            Ipv4Addr::new(10, 20, 0, 2),
            Ipv4Addr::new(10, 20, 0, 1),
            0x1234,
            1,
            b"pong",
        );

        inbound_tx
            .send(InboundPacket {
                peer_id: "peer-b".to_string(),
                packet: packet.clone(),
            })
            .await
            .unwrap();

        let written = timeout(Duration::from_secs(1), ctrl.recv_written())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(written, packet);

        let conn = peers.get_connection("peer-b").await.unwrap();
        assert_eq!(conn.bytes_received, written.len() as u64);

        task.abort();
    }
}
