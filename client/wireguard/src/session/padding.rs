//! Optional length buckets for complete IP packets; no wire header extension.

pub(super) const IP_PADDING_BUCKET: usize = 16;

/// Only structural IP lengths are interpreted. IPv6 jumbograms are not
/// supported: a zero payload length cannot identify their original size.
pub(super) fn complete_ip_len(packet: &[u8]) -> Option<usize> {
    match packet.first()? >> 4 {
        4 if packet.len() >= 20 => {
            let header = usize::from(packet[0] & 0x0f) * 4;
            let total = usize::from(u16::from_be_bytes([packet[2], packet[3]]));
            (header >= 20 && total >= header && total <= packet.len()).then_some(total)
        }
        6 if packet.len() >= 40 => {
            let payload = usize::from(u16::from_be_bytes([packet[4], packet[5]]));
            let total = 40 + payload;
            (payload > 0 && total <= packet.len()).then_some(total)
        }
        _ => None,
    }
}

pub(super) fn strip_ip_padding(plaintext: &mut Vec<u8>) {
    let Some(total) = complete_ip_len(plaintext) else {
        return;
    };
    let extra = plaintext.len() - total;
    if extra > 0
        && extra < IP_PADDING_BUCKET
        && plaintext.len().is_multiple_of(IP_PADDING_BUCKET)
        && plaintext[total..].iter().all(|byte| *byte == 0)
    {
        plaintext.truncate(total);
    }
}
