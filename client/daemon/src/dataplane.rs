//! Data plane packet pump.
//!
//! This module is the seam between the virtual interface and the peer routing
//! table. It reads raw IP packets from TUN, resolves the destination virtual IP
//! to a peer, and emits outbound peer packets. The outbound side is intentionally
//! a channel today; the next layer can consume it with WireGuard + UDP/relay
//! transport without changing TUN packet handling.

use std::net::Ipv4Addr;
use std::sync::Arc;

use p2pnet_tun::{IpPacket, VirtualInterface};
use tokio::sync::mpsc;
use tokio::sync::RwLock;
use tracing::{debug, trace, warn};

use crate::acl::AclEngine;
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
    acl: Option<Arc<RwLock<AclEngine>>>,
    local_node_id: Option<String>,
    overlay_v4: Option<Ipv4Cidr>,
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
                acl: None,
                local_node_id: None,
                overlay_v4: None,
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
                acl: None,
                local_node_id: None,
                overlay_v4: None,
            },
            outbound_rx,
            inbound_tx,
        )
    }

    /// Attach the live ACL used for both outbound and inbound overlay traffic.
    pub fn with_acl(
        mut self,
        acl: Arc<RwLock<AclEngine>>,
        local_node_id: impl Into<String>,
    ) -> Self {
        self.acl = Some(acl);
        self.local_node_id = Some(local_node_id.into());
        self
    }

    /// Attach the overlay IPv4 CIDR used to distinguish harmless OS source-address
    /// pollution from an actual attempt to impersonate another overlay node.
    pub fn with_overlay_cidr(mut self, cidr: &str) -> Self {
        self.overlay_v4 = Ipv4Cidr::parse(cidr);
        if self.overlay_v4.is_none() {
            warn!("Invalid or unsupported overlay CIDR {cidr}; strict source validation remains enabled");
        }
        self
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

        let total_len = parsed.total_len().min(n);
        let protocol = parsed.protocol();
        let dst_ip = parsed.dst_addr_string();
        let src_ip = parsed.src_addr_string();

        let Some(peer_id) = self.peers.resolve_virtual_ip(&dst_ip).await else {
            trace!("Dropping packet for unknown virtual IP {dst_ip} ({protocol})");
            return Ok(());
        };

        let routed_packet = if src_ip == self.tun.address() {
            packet[..total_len].to_vec()
        } else {
            match self.normalize_outbound_source(&packet[..total_len], &src_ip, &dst_ip, protocol) {
                Some(normalized) => normalized,
                None => return Ok(()),
            }
        };

        let parsed = match IpPacket::new(&routed_packet) {
            Ok(parsed) => parsed,
            Err(err) => {
                warn!("Dropping normalized outbound packet that no longer parses: {err}");
                return Ok(());
            }
        };

        if !self
            .acl_allows(
                self.local_node_id.as_deref().unwrap_or("local"),
                &peer_id,
                &parsed,
            )
            .await
        {
            warn!("ACL denied outbound {protocol} packet to peer {peer_id}");
            return Ok(());
        }

        let routed = OutboundPacket {
            peer_id: peer_id.clone(),
            dst_ip: dst_ip.clone(),
            packet: routed_packet,
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

        let protocol = parsed.protocol();
        let total_len = parsed.total_len().min(packet.packet.len());
        let mut inbound_packet = packet.packet[..total_len].to_vec();
        let src_ip = parsed.src_addr_string();
        let dst_ip = parsed.dst_addr_string();

        let Some(peer) = self.peers.get_connection(&packet.peer_id).await else {
            warn!(
                "Dropping inbound packet from unknown peer {}",
                packet.peer_id
            );
            return Ok(());
        };
        if dst_ip != self.tun.address() {
            warn!(
                "Dropping inbound packet from peer {} for unexpected destination {}; local TUN address is {}",
                packet.peer_id,
                dst_ip,
                self.tun.address()
            );
            return Ok(());
        }

        if src_ip != peer.virtual_ip {
            match self.normalize_inbound_source(
                &inbound_packet,
                &packet.peer_id,
                &src_ip,
                &peer.virtual_ip,
                &dst_ip,
                protocol,
            ) {
                Some(normalized) => inbound_packet = normalized,
                None => return Ok(()),
            }
        }

        let parsed = match IpPacket::new(&inbound_packet) {
            Ok(parsed) => parsed,
            Err(err) => {
                warn!(
                    "Dropping normalized inbound packet from peer {} that no longer parses: {err}",
                    packet.peer_id
                );
                return Ok(());
            }
        };

        if !self
            .acl_allows(
                &packet.peer_id,
                self.local_node_id.as_deref().unwrap_or("local"),
                &parsed,
            )
            .await
        {
            warn!(
                "ACL denied inbound {protocol} packet from peer {}",
                packet.peer_id
            );
            return Ok(());
        }

        let written = self
            .tun
            .write(&inbound_packet)
            .await
            .map_err(|e| DaemonError::Network(format!("TUN write failed: {e}")))?;

        if written != inbound_packet.len() {
            return Err(DaemonError::Network(format!(
                "short TUN write for inbound packet from peer {}: wrote {} of {} bytes",
                packet.peer_id,
                written,
                inbound_packet.len()
            )));
        }

        self.peers
            .record_received(&packet.peer_id, inbound_packet.len() as u64)
            .await;

        debug!(
            "Wrote {} byte {protocol} packet from peer {} to TUN ({} -> {dst_ip})",
            inbound_packet.len(),
            packet.peer_id,
            IpPacket::new(&inbound_packet)
                .map(|packet| packet.src_addr_string())
                .unwrap_or(src_ip)
        );
        Ok(())
    }

    async fn acl_allows(&self, src_node: &str, dst_node: &str, packet: &IpPacket<'_>) -> bool {
        let Some(acl) = self.acl.as_ref() else {
            return true;
        };
        let protocol = packet.protocol().to_string().to_ascii_lowercase();
        let port = match protocol.as_str() {
            "tcp" | "udp" if packet.payload().len() >= 4 => {
                u16::from_be_bytes([packet.payload()[2], packet.payload()[3]])
            }
            _ => 0,
        };
        acl.read().await.check(src_node, dst_node, &protocol, port)
    }

    fn normalize_outbound_source(
        &self,
        packet: &[u8],
        src_ip: &str,
        dst_ip: &str,
        protocol: impl std::fmt::Display,
    ) -> Option<Vec<u8>> {
        let local_ip = self.tun.address();
        match normalize_overlay_source(packet, src_ip, local_ip, self.overlay_v4) {
            SourceNormalization::Normalized(normalized) => {
                debug!(
                    "Normalized outbound {protocol} source IP {src_ip} -> {local_ip} for {dst_ip}"
                );
                Some(normalized)
            }
            SourceNormalization::BlockedOverlaySpoof => {
                warn!(
                    "Dropping outbound {protocol} packet with overlay-spoofed source IP {src_ip}; local TUN address is {local_ip}, destination is {dst_ip}"
                );
                None
            }
            SourceNormalization::Unsupported => {
                warn!(
                    "Dropping outbound {protocol} packet with unexpected source IP {src_ip}; local TUN address is {local_ip}"
                );
                None
            }
        }
    }

    fn normalize_inbound_source(
        &self,
        packet: &[u8],
        peer_id: &str,
        src_ip: &str,
        peer_virtual_ip: &str,
        dst_ip: &str,
        protocol: impl std::fmt::Display,
    ) -> Option<Vec<u8>> {
        match normalize_overlay_source(packet, src_ip, peer_virtual_ip, self.overlay_v4) {
            SourceNormalization::Normalized(normalized) => {
                debug!(
                    "Normalized inbound {protocol} source IP {src_ip} -> {peer_virtual_ip} for peer {peer_id} ({dst_ip})"
                );
                Some(normalized)
            }
            SourceNormalization::BlockedOverlaySpoof => {
                warn!(
                    "Dropping inbound {protocol} packet from peer {peer_id} with overlay-spoofed source IP {src_ip}; expected {peer_virtual_ip}"
                );
                None
            }
            SourceNormalization::Unsupported => {
                warn!(
                    "Dropping inbound {protocol} packet from peer {peer_id} with spoofed source IP {src_ip}; expected {peer_virtual_ip}"
                );
                None
            }
        }
    }
}

#[derive(Debug, Clone, Copy)]
struct Ipv4Cidr {
    network: u32,
    mask: u32,
}

impl Ipv4Cidr {
    fn parse(cidr: &str) -> Option<Self> {
        let (ip, prefix) = cidr.split_once('/')?;
        let ip = ip.parse::<Ipv4Addr>().ok()?;
        let prefix = prefix.parse::<u32>().ok()?;
        if prefix > 32 {
            return None;
        }
        let mask = if prefix == 0 {
            0
        } else {
            u32::MAX << (32 - prefix)
        };
        let network = u32::from(ip) & mask;
        Some(Self { network, mask })
    }

    fn contains(self, ip: Ipv4Addr) -> bool {
        (u32::from(ip) & self.mask) == self.network
    }
}

enum SourceNormalization {
    Normalized(Vec<u8>),
    BlockedOverlaySpoof,
    Unsupported,
}

fn normalize_overlay_source(
    packet: &[u8],
    old_src: &str,
    new_src: &str,
    overlay_v4: Option<Ipv4Cidr>,
) -> SourceNormalization {
    let Some(overlay_v4) = overlay_v4 else {
        return SourceNormalization::Unsupported;
    };
    let Ok(old_src) = old_src.parse::<Ipv4Addr>() else {
        return SourceNormalization::Unsupported;
    };
    let Ok(new_src) = new_src.parse::<Ipv4Addr>() else {
        return SourceNormalization::Unsupported;
    };

    if overlay_v4.contains(old_src) {
        return SourceNormalization::BlockedOverlaySpoof;
    }

    normalize_ipv4_source(packet, old_src, new_src)
        .map(SourceNormalization::Normalized)
        .unwrap_or(SourceNormalization::Unsupported)
}

fn normalize_ipv4_source(packet: &[u8], old_src: Ipv4Addr, new_src: Ipv4Addr) -> Option<Vec<u8>> {
    if packet.len() < 20 || (packet[0] >> 4) != 4 {
        return None;
    }
    let ihl = usize::from(packet[0] & 0x0f) * 4;
    if ihl < 20 || packet.len() < ihl {
        return None;
    }
    let total_len = usize::from(u16::from_be_bytes([packet[2], packet[3]]));
    if total_len < ihl || packet.len() < total_len {
        return None;
    }
    if ipv4_is_fragment(packet) {
        return None;
    }
    if Ipv4Addr::new(packet[12], packet[13], packet[14], packet[15]) != old_src {
        return None;
    }

    let mut normalized = packet[..total_len].to_vec();
    normalized[12..16].copy_from_slice(&new_src.octets());
    rewrite_ipv4_header_checksum(&mut normalized, ihl);
    rewrite_transport_checksum_for_ipv4_source(&mut normalized, ihl, old_src, new_src);
    Some(normalized)
}

fn ipv4_is_fragment(packet: &[u8]) -> bool {
    let flags_fragment = u16::from_be_bytes([packet[6], packet[7]]);
    (flags_fragment & 0x3fff) != 0
}

fn rewrite_ipv4_header_checksum(packet: &mut [u8], ihl: usize) {
    packet[10] = 0;
    packet[11] = 0;
    let checksum = internet_checksum(&packet[..ihl]);
    packet[10..12].copy_from_slice(&checksum.to_be_bytes());
}

fn rewrite_transport_checksum_for_ipv4_source(
    packet: &mut [u8],
    ihl: usize,
    old_src: Ipv4Addr,
    new_src: Ipv4Addr,
) {
    let Some(offset) = transport_checksum_offset(packet, ihl) else {
        return;
    };
    let current = u16::from_be_bytes([packet[offset], packet[offset + 1]]);
    if packet[9] == 17 && current == 0 {
        return;
    }
    let updated = checksum_replace_ipv4_addr(current, old_src, new_src);
    let updated = if packet[9] == 17 && updated == 0 {
        0xffff
    } else {
        updated
    };
    packet[offset..offset + 2].copy_from_slice(&updated.to_be_bytes());
}

fn transport_checksum_offset(packet: &[u8], ihl: usize) -> Option<usize> {
    let transport_len = packet.len().checked_sub(ihl)?;
    match packet[9] {
        6 if transport_len >= 20 => Some(ihl + 16),
        17 if transport_len >= 8 => Some(ihl + 6),
        _ => None,
    }
}

fn checksum_replace_ipv4_addr(checksum: u16, old_src: Ipv4Addr, new_src: Ipv4Addr) -> u16 {
    let old = old_src.octets();
    let new = new_src.octets();
    let mut sum = u32::from(!checksum);
    for (old_word, new_word) in [
        (
            u16::from_be_bytes([old[0], old[1]]),
            u16::from_be_bytes([new[0], new[1]]),
        ),
        (
            u16::from_be_bytes([old[2], old[3]]),
            u16::from_be_bytes([new[2], new[3]]),
        ),
    ] {
        sum += u32::from(!old_word);
        sum += u32::from(new_word);
        sum = fold_checksum_sum(sum);
    }
    !fold_checksum_sum(sum) as u16
}

fn internet_checksum(data: &[u8]) -> u16 {
    let mut sum = 0u32;
    let mut chunks = data.chunks_exact(2);
    for chunk in &mut chunks {
        sum += u32::from(u16::from_be_bytes([chunk[0], chunk[1]]));
        sum = fold_checksum_sum(sum);
    }
    if let [last] = chunks.remainder() {
        sum += u32::from(*last) << 8;
    }
    !fold_checksum_sum(sum) as u16
}

fn fold_checksum_sum(mut sum: u32) -> u32 {
    while sum > 0xffff {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    sum
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
    use crate::config::{AclConfig, AclRule, Config};
    use crate::control::PeerInfo;

    fn peer(node_id: &str, virtual_ip: &str) -> PeerInfo {
        PeerInfo {
            node_id: node_id.to_string(),
            device_name: String::new(),
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

    #[tokio::test]
    async fn drops_inbound_packet_with_spoofed_peer_virtual_ip() {
        let peers = Arc::new(PeerManager::new(
            Config::generate_default("http://ctrl.test", "default").unwrap(),
        ));
        peers.add_peer(&peer("peer-b", "10.20.0.2")).await;

        let (tun, mut ctrl) = MockTunDevice::new_pair("test0", 1420, "10.20.0.1");
        let (mut dataplane, _outbound_rx, inbound_tx) =
            DataPlane::new_bidirectional(tun, peers.clone());
        let task = tokio::spawn(async move { dataplane.run().await });
        let packet = Ipv4Packet::build_icmp_echo_request(
            Ipv4Addr::new(10, 20, 0, 99),
            Ipv4Addr::new(10, 20, 0, 1),
            0x1234,
            1,
            b"spoofed",
        );

        inbound_tx
            .send(InboundPacket {
                peer_id: "peer-b".to_string(),
                packet,
            })
            .await
            .unwrap();

        assert!(timeout(Duration::from_millis(100), ctrl.recv_written())
            .await
            .is_err());
        assert_eq!(
            peers.get_connection("peer-b").await.unwrap().bytes_received,
            0
        );
        task.abort();
    }

    #[tokio::test]
    async fn normalizes_inbound_non_overlay_source_pollution() {
        let peers = Arc::new(PeerManager::new(
            Config::generate_default("http://ctrl.test", "default").unwrap(),
        ));
        peers.add_peer(&peer("peer-b", "10.20.0.2")).await;

        let (tun, mut ctrl) = MockTunDevice::new_pair("test0", 1420, "10.20.0.1");
        let (dataplane, _outbound_rx, inbound_tx) =
            DataPlane::new_bidirectional(tun, peers.clone());
        let mut dataplane = dataplane.with_overlay_cidr("10.20.0.0/16");
        let task = tokio::spawn(async move { dataplane.run().await });

        let packet = Ipv4Packet::build_icmp_echo_request(
            Ipv4Addr::new(100, 84, 190, 40),
            Ipv4Addr::new(10, 20, 0, 1),
            0x1234,
            1,
            b"vpn-polluted",
        );

        inbound_tx
            .send(InboundPacket {
                peer_id: "peer-b".to_string(),
                packet,
            })
            .await
            .unwrap();

        let written = timeout(Duration::from_secs(1), ctrl.recv_written())
            .await
            .unwrap()
            .unwrap();
        let parsed = Ipv4Packet::new(&written).unwrap();
        assert_eq!(parsed.src_addr(), Ipv4Addr::new(10, 20, 0, 2));
        assert_eq!(parsed.dst_addr(), Ipv4Addr::new(10, 20, 0, 1));
        assert!(parsed.verify_checksum());
        assert_eq!(
            peers.get_connection("peer-b").await.unwrap().bytes_received,
            written.len() as u64
        );
        task.abort();
    }

    #[tokio::test]
    async fn keeps_blocking_inbound_overlay_source_spoofing() {
        let peers = Arc::new(PeerManager::new(
            Config::generate_default("http://ctrl.test", "default").unwrap(),
        ));
        peers.add_peer(&peer("peer-b", "10.20.0.2")).await;

        let (tun, mut ctrl) = MockTunDevice::new_pair("test0", 1420, "10.20.0.1");
        let (dataplane, _outbound_rx, inbound_tx) =
            DataPlane::new_bidirectional(tun, peers.clone());
        let mut dataplane = dataplane.with_overlay_cidr("10.20.0.0/16");
        let task = tokio::spawn(async move { dataplane.run().await });

        let packet = Ipv4Packet::build_icmp_echo_request(
            Ipv4Addr::new(10, 20, 0, 99),
            Ipv4Addr::new(10, 20, 0, 1),
            0x1234,
            1,
            b"overlay-spoofed",
        );

        inbound_tx
            .send(InboundPacket {
                peer_id: "peer-b".to_string(),
                packet,
            })
            .await
            .unwrap();

        assert!(timeout(Duration::from_millis(100), ctrl.recv_written())
            .await
            .is_err());
        assert_eq!(
            peers.get_connection("peer-b").await.unwrap().bytes_received,
            0
        );
        task.abort();
    }

    #[tokio::test]
    async fn normalizes_outbound_non_overlay_source_pollution() {
        let peers = Arc::new(PeerManager::new(
            Config::generate_default("http://ctrl.test", "default").unwrap(),
        ));
        peers.add_peer(&peer("peer-b", "10.20.0.2")).await;

        let (tun, ctrl) = MockTunDevice::new_pair("test0", 1420, "10.20.0.1");
        let (dataplane, mut outbound_rx) = DataPlane::new(tun, peers.clone());
        let mut dataplane = dataplane.with_overlay_cidr("10.20.0.0/16");
        let task = tokio::spawn(async move { dataplane.run().await });

        let packet = Ipv4Packet::build_icmp_echo_request(
            Ipv4Addr::new(100, 84, 190, 40),
            Ipv4Addr::new(10, 20, 0, 2),
            0x1234,
            1,
            b"vpn-polluted",
        );
        ctrl.inject(packet).await.unwrap();

        let routed = timeout(Duration::from_secs(1), outbound_rx.recv())
            .await
            .unwrap()
            .unwrap();
        let parsed = Ipv4Packet::new(&routed.packet).unwrap();
        assert_eq!(routed.peer_id, "peer-b");
        assert_eq!(parsed.src_addr(), Ipv4Addr::new(10, 20, 0, 1));
        assert_eq!(parsed.dst_addr(), Ipv4Addr::new(10, 20, 0, 2));
        assert!(parsed.verify_checksum());
        assert_eq!(
            peers.get_connection("peer-b").await.unwrap().bytes_sent,
            routed.packet.len() as u64
        );
        task.abort();
    }

    #[tokio::test]
    async fn keeps_blocking_outbound_overlay_source_spoofing() {
        let peers = Arc::new(PeerManager::new(
            Config::generate_default("http://ctrl.test", "default").unwrap(),
        ));
        peers.add_peer(&peer("peer-b", "10.20.0.2")).await;

        let (tun, ctrl) = MockTunDevice::new_pair("test0", 1420, "10.20.0.1");
        let (dataplane, mut outbound_rx) = DataPlane::new(tun, peers.clone());
        let mut dataplane = dataplane.with_overlay_cidr("10.20.0.0/16");
        let task = tokio::spawn(async move { dataplane.run().await });

        let packet = Ipv4Packet::build_icmp_echo_request(
            Ipv4Addr::new(10, 20, 0, 99),
            Ipv4Addr::new(10, 20, 0, 2),
            0x1234,
            1,
            b"overlay-spoofed",
        );
        ctrl.inject(packet).await.unwrap();

        assert!(timeout(Duration::from_millis(100), outbound_rx.recv())
            .await
            .is_err());
        assert_eq!(peers.get_connection("peer-b").await.unwrap().bytes_sent, 0);
        task.abort();
    }

    #[tokio::test]
    async fn live_acl_denies_matching_inbound_packet() {
        let peers = Arc::new(PeerManager::new(
            Config::generate_default("http://ctrl.test", "default").unwrap(),
        ));
        peers.add_peer(&peer("peer-b", "10.20.0.2")).await;
        let acl = Arc::new(RwLock::new(AclEngine::from_config(&AclConfig {
            enabled: true,
            rules: vec![AclRule {
                action: "deny".to_string(),
                src: "peer-b".to_string(),
                dst: "local-node".to_string(),
                proto: "icmp".to_string(),
                port: "*".to_string(),
            }],
        })));

        let (tun, mut ctrl) = MockTunDevice::new_pair("test0", 1420, "10.20.0.1");
        let (dataplane, _outbound_rx, inbound_tx) =
            DataPlane::new_bidirectional(tun, peers.clone());
        let mut dataplane = dataplane.with_acl(acl, "local-node");
        let task = tokio::spawn(async move { dataplane.run().await });
        let packet = Ipv4Packet::build_icmp_echo_request(
            Ipv4Addr::new(10, 20, 0, 2),
            Ipv4Addr::new(10, 20, 0, 1),
            0x1234,
            1,
            b"denied",
        );

        inbound_tx
            .send(InboundPacket {
                peer_id: "peer-b".to_string(),
                packet,
            })
            .await
            .unwrap();

        assert!(timeout(Duration::from_millis(100), ctrl.recv_written())
            .await
            .is_err());
        assert_eq!(
            peers.get_connection("peer-b").await.unwrap().bytes_received,
            0
        );
        task.abort();
    }
}
