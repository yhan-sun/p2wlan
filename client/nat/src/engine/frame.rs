use ring::hmac;
use subtle::ConstantTimeEq;

pub const FRAME_SIZE: usize = 36;
const MAGIC: [u8; 2] = *b"P3";
const MAC_START: usize = 20;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FrameKind {
    Request = 1,
    Response = 2,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CompactFrame {
    pub kind: FrameKind,
    pub nominate: bool,
    pub epoch: u32,
    pub nonce: u32,
}

impl CompactFrame {
    /// This identifier is only an index into negotiated sessions. It is
    /// authenticated along with the rest of the header before any response.
    pub fn session_hint(packet: &[u8]) -> Option<u64> {
        if packet.len() != FRAME_SIZE || !packet.starts_with(&MAGIC) {
            return None;
        }
        Some(u64::from_be_bytes(packet[4..12].try_into().ok()?))
    }

    pub fn correlation(self) -> [u8; 8] {
        let mut bytes = [0; 8];
        bytes[..4].copy_from_slice(&self.epoch.to_be_bytes());
        bytes[4..].copy_from_slice(&self.nonce.to_be_bytes());
        bytes
    }
}

/// Different send and receive keys prevent an initiator's own reflected
/// request from being accepted as a challenge from its peer.
#[derive(Clone)]
pub struct CompactSession {
    pub id: u64,
    outbound: hmac::Key,
    inbound: hmac::Key,
}

impl CompactSession {
    pub fn new(secret: &[u8; 32], session: &str, local: &str, peer: &str) -> Option<Self> {
        if local == peer
            || [local, peer, session]
                .iter()
                .any(|v| v.is_empty() || v.len() > 1024)
        {
            return None;
        }
        let root = hmac::Key::new(hmac::HMAC_SHA256, secret);
        let (low, high) = if local < peer {
            (local, peer)
        } else {
            (peer, local)
        };
        let mut binding = hmac::Context::with_key(&root);
        binding.update(b"p2wlan punch v3 session");
        for value in [session, low, high] {
            binding.update(&(value.len() as u16).to_be_bytes());
            binding.update(value.as_bytes());
        }
        let binding = binding.sign();
        let root = hmac::Key::new(hmac::HMAC_SHA256, binding.as_ref());
        let id = u64::from_be_bytes(hmac::sign(&root, b"id").as_ref()[..8].try_into().ok()?);
        let key =
            |label: &[u8]| hmac::Key::new(hmac::HMAC_SHA256, hmac::sign(&root, label).as_ref());
        let (from_low, from_high) = (key(b"low to high"), key(b"high to low"));
        let (outbound, inbound) = if local == low {
            (from_low, from_high)
        } else {
            (from_high, from_low)
        };
        Some(Self {
            id,
            outbound,
            inbound,
        })
    }

    pub fn encode(&self, frame: CompactFrame) -> [u8; FRAME_SIZE] {
        let mut bytes = [0; FRAME_SIZE];
        bytes[..2].copy_from_slice(&MAGIC);
        bytes[2] = frame.kind as u8;
        bytes[3] = u8::from(frame.nominate);
        bytes[4..12].copy_from_slice(&self.id.to_be_bytes());
        bytes[12..16].copy_from_slice(&frame.epoch.to_be_bytes());
        bytes[16..20].copy_from_slice(&frame.nonce.to_be_bytes());
        let tag = hmac::sign(&self.outbound, &bytes[..MAC_START]);
        bytes[MAC_START..].copy_from_slice(&tag.as_ref()[..16]);
        bytes
    }

    /// Verify that a buffered datagram still belongs to this sender's key.
    pub fn authenticates_outbound(&self, bytes: &[u8]) -> bool {
        if CompactFrame::session_hint(bytes) != Some(self.id) {
            return false;
        }
        let tag = hmac::sign(&self.outbound, &bytes[..MAC_START]);
        bool::from(tag.as_ref()[..16].ct_eq(&bytes[MAC_START..]))
    }

    pub fn decode(&self, bytes: &[u8]) -> Option<CompactFrame> {
        if CompactFrame::session_hint(bytes)? != self.id {
            return None;
        }
        let tag = hmac::sign(&self.inbound, &bytes[..MAC_START]);
        if !bool::from(tag.as_ref()[..16].ct_eq(&bytes[MAC_START..])) {
            return None;
        }
        let kind = match bytes[2] {
            1 => FrameKind::Request,
            2 => FrameKind::Response,
            _ => return None,
        };
        if bytes[3] > 1 || (kind == FrameKind::Response && bytes[3] != 0) {
            return None;
        }
        Some(CompactFrame {
            kind,
            nominate: bytes[3] != 0,
            epoch: u32::from_be_bytes(bytes[12..16].try_into().ok()?),
            nonce: u32::from_be_bytes(bytes[16..20].try_into().ok()?),
        })
    }
}
