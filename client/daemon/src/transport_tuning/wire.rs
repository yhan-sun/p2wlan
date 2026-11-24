use super::SessionKey;
use p2pnet_tun::Ipv4Packet;

const PREFIX: &[u8; 7] = b"P2WTUN1";
pub(super) const DATA: usize = 6;
pub(super) const MAX_PARITY: usize = 3;
pub(super) const MAX_CIPHERTEXT: usize = 4096 + 32;
pub(super) const CHUNK: usize = 1024;
const HEADER: usize = 20;

const STAMP: usize = HEADER + PREFIX.len();
const BODY: usize = STAMP + 16;
pub(super) const COMPRESSED_OVERHEAD: usize = BODY + 3;

#[derive(Clone, Copy)]
pub(crate) enum Message<'a> {
    Compressed {
        length: usize,
        data: &'a [u8],
    },
    Feedback {
        loss_bp: u16,
        through_counter: u64,
    },
    Hello {
        acknowledgement: bool,
        fixed_fec: bool,
        accept_fec: bool,
    },
    Parity(Parity<'a>),
}

#[derive(Clone, Copy)]
pub(crate) struct Parity<'a> {
    pub(super) ids: [u64; DATA],
    pub(super) lengths: [usize; DATA],
    pub(super) rows: usize,
    pub(super) row: usize,
    pub(super) offset: usize,
    pub(super) data: &'a [u8],
}

pub(crate) fn is_internal(packet: &[u8]) -> bool {
    packet.get(9) == Some(&253)
        && packet.get(12..20) == Some(&[0; 8])
        && packet.get(HEADER..HEADER + PREFIX.len()) == Some(PREFIX)
}

pub(crate) fn decode(packet: &[u8]) -> Option<Message<'_>> {
    if !is_internal(packet) {
        return None;
    }
    let ip = Ipv4Packet::new(packet).ok()?;
    if ip.header_len() != HEADER || ip.is_fragment() || usize::from(ip.total_len()) != packet.len()
    {
        return None;
    }
    let (kind, data) = packet.get(BODY..)?.split_first()?;
    match kind {
        1 => {
            let length = usize::from(u16::from_be_bytes(data.get(..2)?.try_into().ok()?));
            let compressed = data.get(2..)?;
            (length >= 128 && compressed.len() < length).then_some(Message::Compressed {
                length,
                data: compressed,
            })
        }
        2 if data.len() == 10 => {
            let loss_bp = u16::from_be_bytes([data[0], data[1]]);
            let through_counter = u64::from_be_bytes(data[2..].try_into().ok()?);
            (loss_bp <= 10_000).then_some(Message::Feedback {
                loss_bp,
                through_counter,
            })
        }
        3 => decode_parity(data).map(Message::Parity),
        4 if data.len() == 2 && data[0] <= 1 && data[1] <= 3 => Some(Message::Hello {
            acknowledgement: data[0] != 0,
            fixed_fec: data[1] & 1 != 0,
            accept_fec: data[1] & 2 != 0,
        }),
        _ => None,
    }
}

fn decode_parity(data: &[u8]) -> Option<Parity<'_>> {
    let rows = usize::from(*data.first()?);
    let row = usize::from(*data.get(1)?);
    let offset = usize::from(u16::from_be_bytes(data.get(2..4)?.try_into().ok()?));
    if !matches!(rows, 1 | MAX_PARITY) || row >= rows || offset % CHUNK != 0 {
        return None;
    }
    let mut ids = [0; DATA];
    let mut lengths = [0; DATA];
    let (descriptors, data) = data.get(4..)?.split_at_checked(DATA * 10)?;
    let (entries, _) = descriptors.as_chunks::<10>();
    for (index, item) in entries.iter().enumerate() {
        ids[index] = u64::from_be_bytes(item[..8].try_into().ok()?);
        lengths[index] = usize::from(u16::from_be_bytes(item[8..10].try_into().ok()?));
        if !(32..=MAX_CIPHERTEXT).contains(&lengths[index])
            || (index > 0 && ids[index] <= ids[index - 1])
        {
            return None;
        }
    }
    let width = lengths.iter().copied().max()?;
    if offset >= width || data.len() != CHUNK.min(width - offset) {
        return None;
    }
    Some(Parity {
        ids,
        lengths,
        rows,
        row,
        offset,
        data,
    })
}

pub(super) fn envelope(kind: u8, data: usize) -> Vec<u8> {
    let size = BODY + 1 + data;
    let mut bytes = Vec::with_capacity(size);
    bytes.resize(HEADER, 0);
    bytes[0] = 0x45;
    bytes[2..4].copy_from_slice(&(size as u16).to_be_bytes());
    bytes[8] = 64;
    bytes[9] = 253;
    // Both endpoints consume this private authenticated record before TUN.
    let sum = 0x4500u32 + size as u32 + 0x40fd;
    let sum = !(((sum & 0xffff) + (sum >> 16)) as u16);
    bytes[10..12].copy_from_slice(&sum.to_be_bytes());
    bytes.extend_from_slice(PREFIX);
    bytes.resize(BODY, 0);
    bytes.push(kind);
    bytes
}

pub(super) fn encode_feedback(loss_bp: u16, through_counter: u64) -> Vec<u8> {
    let mut output = envelope(2, 10);
    output.extend_from_slice(&loss_bp.to_be_bytes());
    output.extend_from_slice(&through_counter.to_be_bytes());
    output
}

/// The local session stamp fences queued control records. A receiver never
/// interprets the remote process's generation or instance numbers.
pub(crate) fn stamp(packet: &mut [u8], key: SessionKey) {
    packet[STAMP..STAMP + 8].copy_from_slice(&key.generation.to_be_bytes());
    packet[STAMP + 8..BODY].copy_from_slice(&key.instance.to_be_bytes());
}

pub(crate) fn queued_key(packet: &[u8]) -> Option<SessionKey> {
    Some(SessionKey {
        generation: u64::from_be_bytes(packet.get(STAMP..STAMP + 8)?.try_into().ok()?),
        instance: u64::from_be_bytes(packet.get(STAMP + 8..BODY)?.try_into().ok()?),
    })
}

pub(super) fn hello(acknowledgement: bool, fixed_fec: bool, accept_fec: bool) -> Vec<u8> {
    let mut output = envelope(4, 2);
    output.extend_from_slice(&[
        u8::from(acknowledgement),
        u8::from(fixed_fec) | (u8::from(accept_fec) << 1),
    ]);
    output
}

pub(super) fn encode_parity(parity: Parity<'_>) -> Vec<u8> {
    let mut output = envelope(3, 4 + DATA * 10 + parity.data.len());
    output.push(parity.rows as u8);
    output.push(parity.row as u8);
    output.extend_from_slice(&(parity.offset as u16).to_be_bytes());
    for (id, len) in parity.ids.into_iter().zip(parity.lengths) {
        output.extend_from_slice(&id.to_be_bytes());
        output.extend_from_slice(&(len as u16).to_be_bytes());
    }
    output.extend_from_slice(parity.data);
    output
}
