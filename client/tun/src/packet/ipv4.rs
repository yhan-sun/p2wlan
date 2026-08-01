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
