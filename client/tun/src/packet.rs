//! IP packet parsing and inspection.
//!
//! Provides zero-copy parsing of IPv4 and IPv6 packets read from the
//! virtual interface. This is used for routing decisions, logging,
//! and protocol-level handling.

use std::net::{Ipv4Addr, Ipv6Addr};

use crate::error::{Error, Result};

/// IP protocol numbers (from IANA).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Protocol {
    /// ICMP (1)
    Icmp = 1,
    /// IGMP (2)
    Igmp = 2,
    /// TCP (6)
    Tcp = 6,
    /// UDP (17)
    Udp = 17,
    /// ICMPv6 (58)
    Icmpv6 = 58,
    /// Unknown protocol
    Unknown = 255,
}

impl From<u8> for Protocol {
    fn from(value: u8) -> Self {
        match value {
            1 => Protocol::Icmp,
            2 => Protocol::Igmp,
            6 => Protocol::Tcp,
            17 => Protocol::Udp,
            58 => Protocol::Icmpv6,
            _ => Protocol::Unknown,
        }
    }
}

impl std::fmt::Display for Protocol {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Protocol::Icmp => write!(f, "ICMP"),
            Protocol::Igmp => write!(f, "IGMP"),
            Protocol::Tcp => write!(f, "TCP"),
            Protocol::Udp => write!(f, "UDP"),
            Protocol::Icmpv6 => write!(f, "ICMPv6"),
            Protocol::Unknown => write!(f, "Unknown({})", *self as u8),
        }
    }
}

/// A parsed IP packet (either IPv4 or IPv6).
#[derive(Debug)]
pub enum IpPacket<'a> {
    /// An IPv4 packet.
    V4(Ipv4Packet<'a>),
    /// An IPv6 packet.
    V6(Ipv6Packet<'a>),
}

impl<'a> IpPacket<'a> {
    /// Parse a raw byte buffer as an IP packet.
    ///
    /// The buffer should contain a complete IP packet (no link-layer header).
    /// This is zero-copy: the parsed packet borrows from the original buffer.
    pub fn new(buf: &'a [u8]) -> Result<Self> {
        if buf.is_empty() {
            return Err(Error::PacketTooShort(0, 1));
        }

        let version = (buf[0] >> 4) & 0x0F;

        match version {
            4 => Ok(IpPacket::V4(Ipv4Packet::new(buf)?)),
            6 => Ok(IpPacket::V6(Ipv6Packet::new(buf)?)),
            v => Err(Error::InvalidIpVersion(v)),
        }
    }

    /// Get the IP version (4 or 6).
    pub fn version(&self) -> u8 {
        match self {
            IpPacket::V4(_) => 4,
            IpPacket::V6(_) => 6,
        }
    }

    /// Get the transport-layer protocol.
    pub fn protocol(&self) -> Protocol {
        match self {
            IpPacket::V4(p) => p.protocol(),
            IpPacket::V6(p) => p.protocol(),
        }
    }

    /// Get the total packet length (including IP header).
    pub fn total_len(&self) -> usize {
        match self {
            IpPacket::V4(p) => p.total_len() as usize,
            IpPacket::V6(p) => p.total_len(),
        }
    }

    /// Get the payload (everything after the IP header).
    pub fn payload(&self) -> &[u8] {
        match self {
            IpPacket::V4(p) => p.payload(),
            IpPacket::V6(p) => p.payload(),
        }
    }

    /// Get the source address as a string.
    pub fn src_addr_string(&self) -> String {
        match self {
            IpPacket::V4(p) => p.src_addr().to_string(),
            IpPacket::V6(p) => p.src_addr().to_string(),
        }
    }

    /// Get the destination address as a string.
    pub fn dst_addr_string(&self) -> String {
        match self {
            IpPacket::V4(p) => p.dst_addr().to_string(),
            IpPacket::V6(p) => p.dst_addr().to_string(),
        }
    }
}

/// A parsed IPv4 packet (zero-copy).
#[derive(Debug)]
pub struct Ipv4Packet<'a> {
    buf: &'a [u8],
}

impl<'a> Ipv4Packet<'a> {
    /// Parse a buffer as an IPv4 packet.
    pub fn new(buf: &'a [u8]) -> Result<Self> {
        if buf.len() < 20 {
            return Err(Error::PacketTooShort(buf.len(), 20));
        }

        let version = (buf[0] >> 4) & 0x0F;
        if version != 4 {
            return Err(Error::InvalidIpVersion(version));
        }

        let ihl = (buf[0] & 0x0F) as usize * 4;
        if ihl < 20 {
            return Err(Error::InvalidHeaderLength(ihl));
        }
        if buf.len() < ihl {
            return Err(Error::PacketTooShort(buf.len(), ihl));
        }

        Ok(Self { buf })
    }

    /// IP version (always 4).
    pub fn version(&self) -> u8 {
        4
    }

    /// Header length in bytes (IHL * 4).
    pub fn header_len(&self) -> usize {
        (self.buf[0] & 0x0F) as usize * 4
    }

    /// Type of Service / DSCP field.
    pub fn tos(&self) -> u8 {
        self.buf[1]
    }

    /// Total length of the packet (header + payload) as specified in the header.
    pub fn total_len(&self) -> u16 {
        u16::from_be_bytes([self.buf[2], self.buf[3]])
    }

    /// Identification field.
    pub fn identification(&self) -> u16 {
        u16::from_be_bytes([self.buf[4], self.buf[5]])
    }

    /// Flags (3 bits) + Fragment Offset (13 bits).
    pub fn flags_fragment(&self) -> u16 {
        u16::from_be_bytes([self.buf[6], self.buf[7]])
    }

    /// True if the Don't Fragment flag is set.
    pub fn dont_fragment(&self) -> bool {
        (self.buf[6] & 0x40) != 0
    }

    /// True if this is a fragment (fragment offset > 0 or More Fragments flag set).
    pub fn is_fragment(&self) -> bool {
        let flags = self.flags_fragment();
        (flags & 0x1FFF) != 0 || (flags & 0x2000) != 0
    }

    /// Time to Live.
    pub fn ttl(&self) -> u8 {
        self.buf[8]
    }

    /// Transport-layer protocol.
    pub fn protocol(&self) -> Protocol {
        Protocol::from(self.buf[9])
    }

    /// Header checksum (raw, before verification).
    pub fn header_checksum(&self) -> u16 {
        u16::from_be_bytes([self.buf[10], self.buf[11]])
    }

    /// Source IPv4 address.
    pub fn src_addr(&self) -> Ipv4Addr {
        Ipv4Addr::new(self.buf[12], self.buf[13], self.buf[14], self.buf[15])
    }

    /// Destination IPv4 address.
    pub fn dst_addr(&self) -> Ipv4Addr {
        Ipv4Addr::new(self.buf[16], self.buf[17], self.buf[18], self.buf[19])
    }

    /// Packet payload (everything after the IP header).
    pub fn payload(&self) -> &[u8] {
        let hdr_len = self.header_len();
        let total = self.total_len() as usize;
        let end = total.min(self.buf.len());
        if hdr_len < end {
            &self.buf[hdr_len..end]
        } else {
            &[]
        }
    }

    /// Raw packet bytes.
    pub fn raw(&self) -> &[u8] {
        self.buf
    }

    /// Verify the IPv4 header checksum.
    pub fn verify_checksum(&self) -> bool {
        let hdr_len = self.header_len();
        if hdr_len < 20 || self.buf.len() < hdr_len {
            return false;
        }

        let mut sum: u32 = 0;
        for i in (0..hdr_len).step_by(2) {
            if i + 1 < hdr_len {
                sum += u16::from_be_bytes([self.buf[i], self.buf[i + 1]]) as u32;
            } else {
                sum += (self.buf[i] as u32) << 8;
            }
        }

        // Fold carries
        while (sum >> 16) != 0 {
            sum = (sum & 0xFFFF) + (sum >> 16);
        }

        sum == 0xFFFF
    }

    /// Build a minimal ICMP Echo Request packet.
    ///
    /// Utility for testing: creates a valid IPv4 ICMP packet
    /// that can be written to the TUN device.
    pub fn build_icmp_echo_request(
        src: Ipv4Addr,
        dst: Ipv4Addr,
        id: u16,
        seq: u16,
        payload: &[u8],
    ) -> Vec<u8> {
        let total_len = 20 + 8 + payload.len();

        let mut packet = Vec::with_capacity(total_len);

        // IPv4 header (20 bytes, no options)
        packet.push(0x45); // version=4, IHL=5
        packet.push(0x00); // TOS
        packet.extend_from_slice(&(total_len as u16).to_be_bytes()); // total length
        packet.extend_from_slice(&id.to_be_bytes()); // identification (IP id = ICMP id for testability)
        packet.extend_from_slice(&0x4000u16.to_be_bytes()); // flags=DF, offset=0
        packet.push(64); // TTL
        packet.push(1); // protocol = ICMP
        packet.extend_from_slice(&0u16.to_be_bytes()); // checksum (placeholder)
        packet.extend_from_slice(&src.octets()); // source address
        packet.extend_from_slice(&dst.octets()); // destination address

        // ICMP Echo Request header (8 bytes)
        packet.push(8); // type = Echo Request
        packet.push(0); // code = 0
        packet.extend_from_slice(&0u16.to_be_bytes()); // checksum (placeholder)
        packet.extend_from_slice(&id.to_be_bytes()); // identifier
        packet.extend_from_slice(&seq.to_be_bytes()); // sequence number

        // ICMP payload
        packet.extend_from_slice(payload);

        // Fixup IPv4 header checksum
        let checksum = compute_checksum(&packet[0..20]);
        packet[10] = (checksum >> 8) as u8;
        packet[11] = (checksum & 0xFF) as u8;

        // Fixup ICMP checksum
        let icmp_checksum = compute_checksum(&packet[20..]);
        packet[22] = (icmp_checksum >> 8) as u8;
        packet[23] = (icmp_checksum & 0xFF) as u8;

        packet
    }
}

/// A parsed IPv6 packet (zero-copy).
#[derive(Debug)]
pub struct Ipv6Packet<'a> {
    buf: &'a [u8],
}

impl<'a> Ipv6Packet<'a> {
    /// Parse a buffer as an IPv6 packet.
    pub fn new(buf: &'a [u8]) -> Result<Self> {
        if buf.len() < 40 {
            return Err(Error::PacketTooShort(buf.len(), 40));
        }

        let version = (buf[0] >> 4) & 0x0F;
        if version != 6 {
            return Err(Error::InvalidIpVersion(version));
        }

        Ok(Self { buf })
    }

    /// IP version (always 6).
    pub fn version(&self) -> u8 {
        6
    }

    /// Header length (always 40 for IPv6 base header).
    pub fn header_len(&self) -> usize {
        40
    }

    /// Traffic class (8 bits extracted from the first 4 bytes).
    pub fn traffic_class(&self) -> u8 {
        ((self.buf[0] & 0x0F) << 4) | (self.buf[1] >> 4)
    }

    /// Flow label (20 bits).
    pub fn flow_label(&self) -> u32 {
        ((self.buf[1] as u32 & 0x0F) << 16) | ((self.buf[2] as u32) << 8) | (self.buf[3] as u32)
    }

    /// Payload length (excluding the 40-byte base header).
    pub fn payload_len(&self) -> u16 {
        u16::from_be_bytes([self.buf[4], self.buf[5]])
    }

    /// Total length of the packet (40 + payload_len).
    pub fn total_len(&self) -> usize {
        40 + self.payload_len() as usize
    }

    /// Next header (protocol). May indicate an extension header.
    pub fn next_header(&self) -> u8 {
        self.buf[6]
    }

    /// Transport-layer protocol. Note: this is the next_header field,
    /// which may indicate an extension header rather than a transport protocol.
    pub fn protocol(&self) -> Protocol {
        Protocol::from(self.buf[6])
    }

    /// Hop limit (equivalent to IPv4 TTL).
    pub fn hop_limit(&self) -> u8 {
        self.buf[7]
    }

    /// Source IPv6 address.
    pub fn src_addr(&self) -> Ipv6Addr {
        let mut octets = [0u8; 16];
        octets.copy_from_slice(&self.buf[8..24]);
        Ipv6Addr::from(octets)
    }

    /// Destination IPv6 address.
    pub fn dst_addr(&self) -> Ipv6Addr {
        let mut octets = [0u8; 16];
        octets.copy_from_slice(&self.buf[24..40]);
        Ipv6Addr::from(octets)
    }

    /// Packet payload (everything after the 40-byte base header).
    pub fn payload(&self) -> &[u8] {
        let total = self.total_len().min(self.buf.len());
        if 40 < total {
            &self.buf[40..total]
        } else {
            &[]
        }
    }

    /// Raw packet bytes.
    pub fn raw(&self) -> &[u8] {
        self.buf
    }
}

/// Compute the Internet checksum (RFC 1071) for a byte slice.
fn compute_checksum(data: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    let mut i = 0;

    while i + 1 < data.len() {
        sum += u16::from_be_bytes([data[i], data[i + 1]]) as u32;
        i += 2;
    }

    // Handle odd-length data
    if i < data.len() {
        sum += (data[i] as u32) << 8;
    }

    // Fold carries
    while (sum >> 16) != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }

    !sum as u16
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ipv4_packet_parsing() {
        // Build a test packet
        let src = Ipv4Addr::new(10, 20, 0, 1);
        let dst = Ipv4Addr::new(10, 20, 0, 2);
        let packet_data = Ipv4Packet::build_icmp_echo_request(src, dst, 0x1234, 1, b"hello");

        // Parse it back
        let parsed = Ipv4Packet::new(&packet_data).unwrap();

        assert_eq!(parsed.version(), 4);
        assert_eq!(parsed.header_len(), 20);
        assert_eq!(parsed.total_len(), packet_data.len() as u16);
        assert_eq!(parsed.protocol(), Protocol::Icmp);
        assert_eq!(parsed.src_addr(), src);
        assert_eq!(parsed.dst_addr(), dst);
        assert_eq!(parsed.ttl(), 64);
        assert!(parsed.verify_checksum());
    }

    #[test]
    fn test_ip_packet_dispatch() {
        let src = Ipv4Addr::new(10, 20, 0, 1);
        let dst = Ipv4Addr::new(10, 20, 0, 2);
        let packet_data = Ipv4Packet::build_icmp_echo_request(src, dst, 0x1234, 1, b"test");

        let packet = IpPacket::new(&packet_data).unwrap();

        assert_eq!(packet.version(), 4);
        assert_eq!(packet.protocol(), Protocol::Icmp);
        assert_eq!(packet.src_addr_string(), "10.20.0.1");
        assert_eq!(packet.dst_addr_string(), "10.20.0.2");
    }

    #[test]
    fn test_protocol_from_u8() {
        assert_eq!(Protocol::from(1), Protocol::Icmp);
        assert_eq!(Protocol::from(6), Protocol::Tcp);
        assert_eq!(Protocol::from(17), Protocol::Udp);
        assert_eq!(Protocol::from(99), Protocol::Unknown);
    }

    #[test]
    fn test_protocol_display() {
        assert_eq!(Protocol::Tcp.to_string(), "TCP");
        assert_eq!(Protocol::Udp.to_string(), "UDP");
        assert_eq!(Protocol::Icmp.to_string(), "ICMP");
    }

    #[test]
    fn test_packet_too_short() {
        let short_buf = [0x45, 0x00, 0x00];
        assert!(Ipv4Packet::new(&short_buf).is_err());
    }

    #[test]
    fn test_invalid_version() {
        let mut buf = vec![0xFF; 20];
        buf[0] = 0x70; // version 7
        assert!(IpPacket::new(&buf).is_err());
    }

    #[test]
    fn test_empty_buffer() {
        assert!(IpPacket::new(&[]).is_err());
    }

    #[test]
    fn test_checksum_verification() {
        let packet = Ipv4Packet::build_icmp_echo_request(
            Ipv4Addr::new(10, 20, 0, 1),
            Ipv4Addr::new(10, 20, 0, 2),
            0x1234,
            1,
            b"data",
        );
        let parsed = Ipv4Packet::new(&packet).unwrap();
        assert!(parsed.verify_checksum());

        // Corrupt a byte and check that checksum fails
        let mut corrupted = packet.clone();
        corrupted[10] ^= 0xFF;
        let parsed_corrupt = Ipv4Packet::new(&corrupted).unwrap();
        assert!(!parsed_corrupt.verify_checksum());
    }

    #[test]
    fn test_ipv6_packet_parsing() {
        // Build a minimal IPv6 packet
        let mut buf = vec![0u8; 48];

        // version=6, traffic_class=0, flow_label=0
        buf[0] = 0x60;
        // payload length = 8
        buf[4] = 0x00;
        buf[5] = 0x08;
        // next header = UDP (17)
        buf[6] = 17;
        // hop limit = 64
        buf[7] = 64;

        // src addr: fd00::1 (16 bytes at offset 8-23)
        buf[8] = 0xfd;
        buf[9] = 0x00;
        buf[23] = 0x01; // last byte of src addr

        // dst addr: fd00::2 (16 bytes at offset 24-39)
        buf[24] = 0xfd;
        buf[25] = 0x00;
        buf[39] = 0x02; // last byte of dst addr

        // 8 bytes of payload
        buf[40..48].fill(0xAA);

        let parsed = Ipv6Packet::new(&buf).unwrap();
        assert_eq!(parsed.version(), 6);
        assert_eq!(parsed.header_len(), 40);
        assert_eq!(parsed.payload_len(), 8);
        assert_eq!(parsed.total_len(), 48);
        assert_eq!(parsed.next_header(), 17);
        assert_eq!(parsed.hop_limit(), 64);
        assert_eq!(parsed.protocol(), Protocol::Udp);
        assert_eq!(
            parsed.src_addr(),
            Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 1)
        );
        assert_eq!(
            parsed.dst_addr(),
            Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 2)
        );
        assert_eq!(parsed.payload().len(), 8);
    }

    #[test]
    fn test_fragment_detection() {
        let src = Ipv4Addr::new(10, 20, 0, 1);
        let dst = Ipv4Addr::new(10, 20, 0, 2);
        let packet_data = Ipv4Packet::build_icmp_echo_request(src, dst, 0x1234, 1, b"hello");

        let parsed = Ipv4Packet::new(&packet_data).unwrap();
        // DF flag is set by our builder
        assert!(parsed.dont_fragment());
        assert!(!parsed.is_fragment());
    }
}
