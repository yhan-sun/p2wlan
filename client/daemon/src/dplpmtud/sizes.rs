use serde::{Deserialize, Serialize};
use std::net::IpAddr;

/// WireGuard transport header (16 bytes) plus ChaCha20-Poly1305 tag (16 bytes).
pub(crate) const WIREGUARD_UDP_DATAGRAM_OVERHEAD: u32 = 32;

/// Outer IPv4 + UDP framing, excluded from [`UdpDatagramSize`].
pub(crate) const IPV4_OUTER_IP_UDP_OVERHEAD: u32 = 20 + 8;

/// Outer IPv6 + UDP framing, excluded from [`UdpDatagramSize`].
pub(crate) const IPV6_OUTER_IP_UDP_OVERHEAD: u32 = 40 + 8;

/// Conservative UDP datagram baseline for an authenticated Direct path.
pub(crate) const DPLPMTUD_BASE_UDP_DATAGRAM_SIZE: u32 = 1200;

/// Ethernet-sized IPv4 UDP datagram ceiling: 1500 - IPv4(20) - UDP(8).
pub(crate) const DPLPMTUD_IPV4_UDP_DATAGRAM_CEILING: u32 = 1472;

/// Ethernet-sized IPv6 UDP datagram ceiling: 1500 - IPv6(40) - UDP(8).
pub(crate) const DPLPMTUD_IPV6_UDP_DATAGRAM_CEILING: u32 = 1452;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(transparent)]
pub(crate) struct OuterIpPacketSize(pub(crate) u32);

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub(crate) struct UdpDatagramSize(pub(crate) u32);

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(transparent)]
pub(crate) struct OverlayPayloadBudget(pub(crate) u32);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum OuterIpFamily {
    Ipv4,
    Ipv6,
}

impl OuterIpFamily {
    pub(crate) const fn from_ip(ip: IpAddr) -> Self {
        match ip {
            IpAddr::V4(_) => Self::Ipv4,
            IpAddr::V6(_) => Self::Ipv6,
        }
    }

    pub(crate) const fn outer_ip_udp_overhead(self) -> u32 {
        match self {
            Self::Ipv4 => IPV4_OUTER_IP_UDP_OVERHEAD,
            Self::Ipv6 => IPV6_OUTER_IP_UDP_OVERHEAD,
        }
    }

    pub(crate) const fn ceiling_udp_datagram_size(self) -> UdpDatagramSize {
        match self {
            Self::Ipv4 => UdpDatagramSize(DPLPMTUD_IPV4_UDP_DATAGRAM_CEILING),
            Self::Ipv6 => UdpDatagramSize(DPLPMTUD_IPV6_UDP_DATAGRAM_CEILING),
        }
    }
}

impl UdpDatagramSize {
    pub(crate) const fn outer_ip_packet_size(self, family: OuterIpFamily) -> OuterIpPacketSize {
        OuterIpPacketSize(self.0 + family.outer_ip_udp_overhead())
    }

    pub(crate) const fn overlay_payload_budget(self) -> Option<OverlayPayloadBudget> {
        match self.0.checked_sub(WIREGUARD_UDP_DATAGRAM_OVERHEAD) {
            Some(value) => Some(OverlayPayloadBudget(value)),
            None => None,
        }
    }
}
