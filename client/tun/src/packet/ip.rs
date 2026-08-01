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
