use super::*;

/// A parsed punch packet.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct PunchPacket {
    pub(super) packet_type: u8,
    pub(super) nonce: [u8; 8],
}

impl PunchPacket {
    /// Create a new punch packet with a random nonce.
    pub(super) fn new_punch() -> Self {
        use rand::RngCore;
        let mut nonce = [0u8; 8];
        rand::thread_rng().fill_bytes(&mut nonce);
        Self {
            packet_type: TYPE_PUNCH,
            nonce,
        }
    }

    /// Create an ACK packet echoing the nonce.
    pub(super) fn new_ack(nonce: [u8; 8]) -> Self {
        Self {
            packet_type: TYPE_ACK,
            nonce,
        }
    }

    /// Encode to 14 bytes.
    pub(super) fn encode(&self) -> [u8; PUNCH_PACKET_SIZE] {
        let mut buf = [0u8; PUNCH_PACKET_SIZE];
        buf[..4].copy_from_slice(&PUNCH_MAGIC);
        buf[4] = PUNCH_VERSION;
        buf[5] = self.packet_type;
        buf[6..14].copy_from_slice(&self.nonce);
        buf
    }

    /// Decode from raw bytes.
    pub(super) fn decode(data: &[u8]) -> Option<Self> {
        if data.len() < PUNCH_PACKET_SIZE {
            return None;
        }
        if data[..4] != PUNCH_MAGIC {
            return None;
        }
        if data[4] != PUNCH_VERSION {
            return None;
        }
        let packet_type = data[5];
        if packet_type != TYPE_PUNCH && packet_type != TYPE_ACK {
            return None;
        }
        let mut nonce = [0u8; 8];
        nonce.copy_from_slice(&data[6..14]);
        Some(Self { packet_type, nonce })
    }

    pub(super) fn is_punch(&self) -> bool {
        self.packet_type == TYPE_PUNCH
    }

    pub(super) fn is_ack(&self) -> bool {
        self.packet_type == TYPE_ACK
    }
}

impl From<PunchPacket> for DecodedPunchPacket {
    fn from(packet: PunchPacket) -> Self {
        let kind = if packet.is_punch() {
            PunchPacketKind::Punch
        } else {
            PunchPacketKind::Ack
        };

        Self {
            kind,
            nonce: packet.nonce,
            version: PUNCH_VERSION,
            source_node_id: None,
            target_node_id: None,
            generation: None,
            use_candidate: false,
            authenticated: false,
        }
    }
}

/// Decode a punch protocol datagram, returning `None` for unrelated traffic.
pub fn decode_punch_packet(data: &[u8]) -> Option<DecodedPunchPacket> {
    PunchPacket::decode(data).map(Into::into)
}

/// Build a fresh PUNCH datagram.
pub fn build_punch_packet() -> [u8; PUNCH_PACKET_SIZE] {
    PunchPacket::new_punch().encode()
}

/// Build a legacy v1 PUNCH datagram using an existing nonce.
///
/// This is used by newer clients when they also send an authenticated v2
/// probe: old clients can ACK the legacy packet while new clients can verify
/// the authenticated packet, and both ACK variants correlate to the same
/// pending probe.
pub fn build_punch_packet_with_nonce(nonce: [u8; 8]) -> [u8; PUNCH_PACKET_SIZE] {
    PunchPacket {
        packet_type: TYPE_PUNCH,
        nonce,
    }
    .encode()
}

/// Build an ACK datagram for a received PUNCH nonce.
pub fn build_punch_ack(nonce: [u8; 8]) -> [u8; PUNCH_PACKET_SIZE] {
    PunchPacket::new_ack(nonce).encode()
}
