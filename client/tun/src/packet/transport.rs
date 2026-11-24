//! Inspect the inner transport headers before encryption.

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TrafficClass {
    Control,
    Interactive,
    Bulk,
}

#[derive(Clone, Copy)]
struct Segment {
    protocol: u8,
    start: usize,
    end: usize,
}

fn segment(packet: &[u8]) -> Option<Segment> {
    match packet.first()? >> 4 {
        4 if packet.len() >= 20 => {
            let start = usize::from(packet[0] & 15) * 4;
            let end = usize::from(u16::from_be_bytes([packet[2], packet[3]]));
            let fragmented = u16::from_be_bytes([packet[6], packet[7]]) & 0x3fff != 0;
            (start >= 20 && start <= end && end <= packet.len() && !fragmented).then_some(Segment {
                protocol: packet[9],
                start,
                end,
            })
        }
        6 if packet.len() >= 40 => {
            let end = 40 + usize::from(u16::from_be_bytes([packet[4], packet[5]]));
            if end > packet.len() {
                return None;
            }
            let (mut start, mut protocol) = (40, packet[6]);
            for _ in 0..8 {
                match protocol {
                    0 | 43 | 60 => {
                        let extension = packet.get(start..end)?.get(..2)?;
                        protocol = extension[0];
                        start += (usize::from(extension[1]) + 1) * 8;
                    }
                    // Do not rewrite fragments or packets protected by inner IPsec.
                    44 | 50 | 51 => return None,
                    _ if start <= end => {
                        return Some(Segment {
                            protocol,
                            start,
                            end,
                        });
                    }
                    _ => return None,
                }
            }
            None
        }
        _ => None,
    }
}

fn tcp_header_len(tcp: &[u8]) -> Option<usize> {
    let len = usize::from(tcp.get(12)? >> 4) * 4;
    (len >= 20 && len <= tcp.len()).then_some(len)
}

pub fn is_tcp_syn(packet: &[u8]) -> bool {
    segment(packet).is_some_and(
        |Segment {
             protocol,
             start,
             end,
         }| {
            let tcp = &packet[start..end];
            protocol == 6 && tcp_header_len(tcp).is_some() && tcp[13] & 2 != 0
        },
    )
}

pub fn traffic_class(packet: &[u8]) -> TrafficClass {
    let Some(Segment {
        protocol,
        start,
        end,
    }) = segment(packet)
    else {
        return TrafficClass::Bulk;
    };
    let transport = &packet[start..end];
    if matches!(protocol, 1 | 58) {
        return TrafficClass::Control;
    }
    if (protocol == 6 && tcp_header_len(transport).is_some())
        || (protocol == 17 && transport.len() >= 8)
    {
        if [transport[0], transport[1]] == [0, 53] || [transport[2], transport[3]] == [0, 53] {
            return TrafficClass::Control;
        }
        if protocol == 6
            && tcp_header_len(transport) == Some(transport.len())
            && transport[13] & 0x17 != 0
        {
            return TrafficClass::Control;
        }
        if end <= 256 {
            return TrafficClass::Interactive;
        }
    }
    TrafficClass::Bulk
}

/// Clamp a SYN or SYN-ACK to the complete inner IP packet budget. Apply the
/// RFC 1624 delta to the existing TCP checksum, including unaligned options.
pub fn clamp_tcp_mss(packet: &mut [u8], inner_mtu: u32) -> bool {
    let Some(Segment {
        protocol: 6,
        start,
        end,
    }) = segment(packet)
    else {
        return false;
    };
    let tcp = &mut packet[start..end];
    let Some(header_len) = tcp_header_len(tcp) else {
        return false;
    };
    let max_mss = (inner_mtu as usize).saturating_sub(start + header_len);
    if tcp[13] & 0x02 == 0 || max_mss == 0 || max_mss >= usize::from(u16::MAX) {
        return false;
    }
    let Some(offset) = mss_offset(&tcp[..header_len]) else {
        return false;
    };
    let old = u16::from_be_bytes([tcp[offset], tcp[offset + 1]]);
    let new = max_mss as u16;
    if old <= new {
        return false;
    }
    let (old_word, new_word) = if offset % 2 == 0 {
        (old, new)
    } else {
        (old.swap_bytes(), new.swap_bytes())
    };
    let checksum = u16::from_be_bytes([tcp[16], tcp[17]]);
    let sum = u32::from(!checksum) + u32::from(!old_word) + u32::from(new_word);
    let folded = (sum & 0xffff) + (sum >> 16);
    let updated = !(((folded & 0xffff) + (folded >> 16)) as u16);
    tcp[16..18].copy_from_slice(&updated.to_be_bytes());
    tcp[offset..offset + 2].copy_from_slice(&new.to_be_bytes());
    true
}

fn mss_offset(tcp: &[u8]) -> Option<usize> {
    let mut cursor = 20;
    let mut mss = None;
    while cursor < tcp.len() {
        match tcp[cursor] {
            0 => break,
            1 => cursor += 1,
            kind => {
                let len = usize::from(*tcp.get(cursor + 1)?);
                if len < 2 || len > tcp.len() - cursor {
                    return None;
                }
                if kind == 2 {
                    if len != 4 || mss.is_some() {
                        return None;
                    }
                    mss = Some(cursor + 2);
                }
                cursor += len;
            }
        }
    }
    mss
}

#[cfg(test)]
mod tests;
