//! Local PMTU feedback for business packets rejected before Direct UDP handoff.
//!
//! The advertised MTU is the complete inner-IP-packet budget.  These packets
//! are injected into the local TUN receive side; they are never encrypted and
//! can therefore never recursively consume a Direct business budget.

use std::collections::{HashMap, VecDeque};
use std::net::{Ipv4Addr, Ipv6Addr};

use tokio::time::{Duration, Instant};

pub(crate) const LOCAL_MTU_FEEDBACK_RATE_PER_PEER: usize = 8;
pub(crate) const LOCAL_MTU_FEEDBACK_WINDOW: Duration = Duration::from_secs(1);
pub(crate) const MAX_LOCAL_MTU_FEEDBACK_PEERS: usize = 256;
pub(crate) const IPV6_MINIMUM_MTU: u32 = 1280;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum LocalMtuFeedbackKind {
    PacketTooBig { inner_ip_mtu: u32 },
    Unreachable,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum LocalMtuFeedbackSuppression {
    Malformed,
    RecursiveIcmpError,
    Ipv6PacketTooBigBelowMinimumMtu,
    InvalidAddress,
    RateLimited,
    NoTunConsumer,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum LocalMtuFeedbackOutcome {
    Published,
    Suppressed(LocalMtuFeedbackSuppression),
}

#[derive(Default)]
pub(crate) struct LocalMtuFeedbackRateLimiter {
    peers: HashMap<String, VecDeque<Instant>>,
    order: VecDeque<String>,
}

impl LocalMtuFeedbackRateLimiter {
    pub(crate) fn admit(&mut self, peer_id: &str, now: Instant) -> bool {
        self.peers.retain(|_, sent| {
            while sent.front().is_some_and(|sent_at| {
                now.saturating_duration_since(*sent_at) >= LOCAL_MTU_FEEDBACK_WINDOW
            }) {
                sent.pop_front();
            }
            !sent.is_empty()
        });
        self.order.retain(|peer| self.peers.contains_key(peer));

        if !self.peers.contains_key(peer_id) {
            while self.peers.len() >= MAX_LOCAL_MTU_FEEDBACK_PEERS {
                let Some(oldest) = self.order.pop_front() else {
                    return false;
                };
                self.peers.remove(&oldest);
            }
            self.order.push_back(peer_id.to_string());
        }

        let sent = self.peers.entry(peer_id.to_string()).or_default();
        if sent.len() >= LOCAL_MTU_FEEDBACK_RATE_PER_PEER {
            return false;
        }
        sent.push_back(now);
        true
    }

    #[cfg(test)]
    pub(crate) fn tracked_peers(&self) -> usize {
        self.peers.len()
    }
}

pub(crate) fn build_local_mtu_feedback(
    original: &[u8],
    kind: LocalMtuFeedbackKind,
) -> Result<Vec<u8>, LocalMtuFeedbackSuppression> {
    let version = original
        .first()
        .map(|byte| byte >> 4)
        .ok_or(LocalMtuFeedbackSuppression::Malformed)?;
    match version {
        4 => build_ipv4_feedback(original, kind),
        6 => build_ipv6_feedback(original, kind),
        _ => Err(LocalMtuFeedbackSuppression::Malformed),
    }
}

fn build_ipv4_feedback(
    original: &[u8],
    kind: LocalMtuFeedbackKind,
) -> Result<Vec<u8>, LocalMtuFeedbackSuppression> {
    let packet = p2pnet_tun::Ipv4Packet::new(original)
        .map_err(|_| LocalMtuFeedbackSuppression::Malformed)?;
    let header_len = packet.header_len();
    let total_len = usize::from(packet.total_len());
    if total_len < header_len || total_len > original.len() || packet.is_fragment() {
        return Err(LocalMtuFeedbackSuppression::Malformed);
    }
    let source = packet.src_addr();
    let destination = packet.dst_addr();
    if !valid_ipv4_feedback_pair(source, destination) {
        return Err(LocalMtuFeedbackSuppression::InvalidAddress);
    }
    if packet.protocol() == p2pnet_tun::Protocol::Icmp {
        let icmp = packet.payload();
        if icmp
            .first()
            .is_some_and(|kind| matches!(*kind, 3 | 4 | 5 | 11 | 12))
        {
            return Err(LocalMtuFeedbackSuppression::RecursiveIcmpError);
        }
    }

    let quoted_len = total_len.min(header_len.saturating_add(8));
    let generated_len = 20usize.saturating_add(8).saturating_add(quoted_len);
    let generated_len_u16 =
        u16::try_from(generated_len).map_err(|_| LocalMtuFeedbackSuppression::Malformed)?;
    let mut feedback = vec![0u8; generated_len];
    feedback[0] = 0x45;
    feedback[2..4].copy_from_slice(&generated_len_u16.to_be_bytes());
    feedback[6..8].copy_from_slice(&0x4000u16.to_be_bytes());
    feedback[8] = 64;
    feedback[9] = p2pnet_tun::Protocol::Icmp as u8;
    feedback[12..16].copy_from_slice(&destination.octets());
    feedback[16..20].copy_from_slice(&source.octets());

    feedback[20] = 3;
    match kind {
        LocalMtuFeedbackKind::PacketTooBig { inner_ip_mtu } => {
            feedback[21] = 4;
            let mtu = u16::try_from(inner_ip_mtu.clamp(68, u32::from(u16::MAX)))
                .expect("clamped IPv4 MTU fits u16");
            feedback[26..28].copy_from_slice(&mtu.to_be_bytes());
        }
        LocalMtuFeedbackKind::Unreachable => {
            feedback[21] = 1;
        }
    }
    feedback[28..].copy_from_slice(&original[..quoted_len]);
    let icmp_checksum = internet_checksum(&feedback[20..]);
    feedback[22..24].copy_from_slice(&icmp_checksum.to_be_bytes());
    let ip_checksum = internet_checksum(&feedback[..20]);
    feedback[10..12].copy_from_slice(&ip_checksum.to_be_bytes());
    Ok(feedback)
}

fn build_ipv6_feedback(
    original: &[u8],
    kind: LocalMtuFeedbackKind,
) -> Result<Vec<u8>, LocalMtuFeedbackSuppression> {
    let packet = p2pnet_tun::Ipv6Packet::new(original)
        .map_err(|_| LocalMtuFeedbackSuppression::Malformed)?;
    let total_len = packet.total_len();
    if total_len > original.len() {
        return Err(LocalMtuFeedbackSuppression::Malformed);
    }
    let source = packet.src_addr();
    let destination = packet.dst_addr();
    if !valid_ipv6_feedback_pair(source, destination) {
        return Err(LocalMtuFeedbackSuppression::InvalidAddress);
    }
    if packet.next_header() == 58
        && packet
            .payload()
            .first()
            .is_some_and(|icmp_type| *icmp_type < 128)
    {
        return Err(LocalMtuFeedbackSuppression::RecursiveIcmpError);
    }
    // Extension-header traversal is not implemented in this phase. Fail
    // closed rather than risk hiding an ICMPv6 error behind an extension and
    // recursively generating another error response.
    if matches!(packet.next_header(), 0 | 43 | 44 | 50 | 51 | 60) {
        return Err(LocalMtuFeedbackSuppression::Malformed);
    }
    if matches!(
        kind,
        LocalMtuFeedbackKind::PacketTooBig { inner_ip_mtu }
            if inner_ip_mtu < IPV6_MINIMUM_MTU
    ) {
        return Err(LocalMtuFeedbackSuppression::Ipv6PacketTooBigBelowMinimumMtu);
    }

    // Keep the generated ICMPv6 error within IPv6's 1280-byte minimum MTU.
    let quoted_len = total_len.min(IPV6_MINIMUM_MTU as usize - (40 + 8));
    let payload_len = 8usize.saturating_add(quoted_len);
    let payload_len_u16 =
        u16::try_from(payload_len).map_err(|_| LocalMtuFeedbackSuppression::Malformed)?;
    let mut feedback = vec![0u8; 40 + payload_len];
    feedback[0] = 0x60;
    feedback[4..6].copy_from_slice(&payload_len_u16.to_be_bytes());
    feedback[6] = 58;
    feedback[7] = 64;
    feedback[8..24].copy_from_slice(&destination.octets());
    feedback[24..40].copy_from_slice(&source.octets());
    match kind {
        LocalMtuFeedbackKind::PacketTooBig { inner_ip_mtu } => {
            feedback[40] = 2;
            feedback[41] = 0;
            feedback[44..48].copy_from_slice(&inner_ip_mtu.to_be_bytes());
        }
        LocalMtuFeedbackKind::Unreachable => {
            feedback[40] = 1;
            feedback[41] = 0;
        }
    }
    feedback[48..].copy_from_slice(&original[..quoted_len]);
    let checksum = icmpv6_checksum(destination, source, &feedback[40..]);
    feedback[42..44].copy_from_slice(&checksum.to_be_bytes());
    Ok(feedback)
}

fn valid_ipv4_feedback_pair(source: Ipv4Addr, destination: Ipv4Addr) -> bool {
    !source.is_unspecified()
        && !source.is_broadcast()
        && !source.is_multicast()
        && !destination.is_unspecified()
        && !destination.is_broadcast()
        && !destination.is_multicast()
}

fn valid_ipv6_feedback_pair(source: Ipv6Addr, destination: Ipv6Addr) -> bool {
    !source.is_unspecified()
        && !source.is_multicast()
        && !destination.is_unspecified()
        && !destination.is_multicast()
}

pub(crate) fn icmpv6_checksum(source: Ipv6Addr, destination: Ipv6Addr, icmp: &[u8]) -> u16 {
    let mut pseudo = Vec::with_capacity(40 + icmp.len());
    pseudo.extend_from_slice(&source.octets());
    pseudo.extend_from_slice(&destination.octets());
    pseudo.extend_from_slice(&(icmp.len() as u32).to_be_bytes());
    pseudo.extend_from_slice(&[0, 0, 0, 58]);
    pseudo.extend_from_slice(icmp);
    internet_checksum(&pseudo)
}

pub(crate) fn internet_checksum(bytes: &[u8]) -> u16 {
    let mut sum = 0u32;
    let (chunks, remainder) = bytes.as_chunks::<2>();
    for chunk in chunks {
        sum = sum.saturating_add(u32::from(u16::from_be_bytes(*chunk)));
    }
    if let Some(last) = remainder.first() {
        sum = sum.saturating_add(u32::from(*last) << 8);
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ipv4_fragmentation_needed_has_valid_checksums_quote_and_mtu() {
        let original = p2pnet_tun::Ipv4Packet::build_icmp_echo_request(
            "10.20.0.1".parse().unwrap(),
            "10.20.0.2".parse().unwrap(),
            7,
            9,
            &[0x5a; 64],
        );
        let feedback = build_local_mtu_feedback(
            &original,
            LocalMtuFeedbackKind::PacketTooBig { inner_ip_mtu: 1168 },
        )
        .unwrap();
        let ip = p2pnet_tun::Ipv4Packet::new(&feedback).unwrap();
        assert!(ip.verify_checksum());
        assert_eq!(ip.src_addr(), "10.20.0.2".parse::<Ipv4Addr>().unwrap());
        assert_eq!(ip.dst_addr(), "10.20.0.1".parse::<Ipv4Addr>().unwrap());
        assert_eq!(&ip.payload()[..2], &[3, 4]);
        assert_eq!(u16::from_be_bytes([ip.payload()[6], ip.payload()[7]]), 1168);
        assert_eq!(internet_checksum(ip.payload()), 0);
        assert_eq!(&ip.payload()[8..], &original[..28]);
    }

    #[test]
    fn feedback_does_not_recurse_on_generated_icmp_error() {
        let original = p2pnet_tun::Ipv4Packet::build_icmp_echo_request(
            "10.20.0.1".parse().unwrap(),
            "10.20.0.2".parse().unwrap(),
            7,
            9,
            &[],
        );
        let generated = build_local_mtu_feedback(
            &original,
            LocalMtuFeedbackKind::PacketTooBig { inner_ip_mtu: 1168 },
        )
        .unwrap();
        assert_eq!(
            build_local_mtu_feedback(
                &generated,
                LocalMtuFeedbackKind::PacketTooBig { inner_ip_mtu: 1000 },
            ),
            Err(LocalMtuFeedbackSuppression::RecursiveIcmpError)
        );
    }

    #[test]
    fn ipv6_packet_too_big_below_minimum_is_suppressed_without_clamping() {
        let source: Ipv6Addr = "fd00::1".parse().unwrap();
        let destination: Ipv6Addr = "fd00::2".parse().unwrap();
        let mut original = vec![0u8; 48];
        original[0] = 0x60;
        original[4..6].copy_from_slice(&8u16.to_be_bytes());
        original[6] = 17;
        original[7] = 64;
        original[8..24].copy_from_slice(&source.octets());
        original[24..40].copy_from_slice(&destination.octets());

        assert_eq!(
            build_local_mtu_feedback(
                &original,
                LocalMtuFeedbackKind::PacketTooBig { inner_ip_mtu: 1168 },
            ),
            Err(LocalMtuFeedbackSuppression::Ipv6PacketTooBigBelowMinimumMtu)
        );
    }

    #[test]
    fn ipv6_packet_too_big_has_valid_checksum_quote_and_minimum_inner_mtu() {
        let source: Ipv6Addr = "fd00::1".parse().unwrap();
        let destination: Ipv6Addr = "fd00::2".parse().unwrap();
        let mut original = vec![0u8; 48];
        original[0] = 0x60;
        original[4..6].copy_from_slice(&8u16.to_be_bytes());
        original[6] = 17;
        original[7] = 64;
        original[8..24].copy_from_slice(&source.octets());
        original[24..40].copy_from_slice(&destination.octets());
        original[40..].copy_from_slice(&[0x5a; 8]);

        let feedback = build_local_mtu_feedback(
            &original,
            LocalMtuFeedbackKind::PacketTooBig {
                inner_ip_mtu: IPV6_MINIMUM_MTU,
            },
        )
        .unwrap();
        let ip = p2pnet_tun::Ipv6Packet::new(&feedback).unwrap();
        assert_eq!(ip.src_addr(), destination);
        assert_eq!(ip.dst_addr(), source);
        assert_eq!(ip.next_header(), 58);
        assert_eq!(&ip.payload()[..2], &[2, 0]);
        assert_eq!(
            u32::from_be_bytes(ip.payload()[4..8].try_into().unwrap()),
            IPV6_MINIMUM_MTU
        );
        assert_eq!(&ip.payload()[8..], original.as_slice());
        assert_eq!(
            icmpv6_checksum(ip.src_addr(), ip.dst_addr(), ip.payload()),
            0
        );
        assert_eq!(
            build_local_mtu_feedback(
                &feedback,
                LocalMtuFeedbackKind::PacketTooBig {
                    inner_ip_mtu: IPV6_MINIMUM_MTU,
                },
            ),
            Err(LocalMtuFeedbackSuppression::RecursiveIcmpError)
        );
    }

    #[tokio::test(start_paused = true)]
    async fn feedback_rate_limit_is_bounded_and_uses_tokio_time() {
        let mut limiter = LocalMtuFeedbackRateLimiter::default();
        for _ in 0..LOCAL_MTU_FEEDBACK_RATE_PER_PEER {
            assert!(limiter.admit("peer", Instant::now()));
        }
        assert!(!limiter.admit("peer", Instant::now()));
        tokio::time::advance(LOCAL_MTU_FEEDBACK_WINDOW).await;
        assert!(limiter.admit("peer", Instant::now()));
        for index in 0..(MAX_LOCAL_MTU_FEEDBACK_PEERS + 10) {
            assert!(limiter.admit(&format!("peer-{index}"), Instant::now()));
        }
        assert!(limiter.tracked_peers() <= MAX_LOCAL_MTU_FEEDBACK_PEERS);
    }
}
