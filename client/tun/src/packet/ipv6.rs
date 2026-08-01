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
