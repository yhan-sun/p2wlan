use super::*;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ParseErrorKind {
    NotIpv4Udp,
    Fragmented,
    Length,
    Magic,
    Kind,
    Filler,
    Checksum,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ParsedOsUdp {
    pub(crate) key: OsUdpReqKey,
    pub(crate) flow: RegisteredFlow,
    pub(crate) payload_bytes: u16,
    pub(crate) ip_packet_len: u16,
}

/// Reads the same complete 128-bit fields as the OS UDP tool. No allocation.
pub(crate) fn parse_os_udp(raw: &[u8]) -> Result<ParsedOsUdp, ParseErrorKind> {
    if raw.len() < 28 || raw[0] >> 4 != 4 || raw[9] != 17 {
        return Err(ParseErrorKind::NotIpv4Udp);
    }
    let ihl = usize::from(raw[0] & 15) * 4;
    let total = usize::from(u16::from_be_bytes([raw[2], raw[3]]));
    if ihl < 20 || total != raw.len() || ihl + 8 > total {
        return Err(ParseErrorKind::Length);
    }
    // DF is permitted; reserved/MF bits and any fragment offset are not.
    if u16::from_be_bytes([raw[6], raw[7]]) & 0xbfff != 0 {
        return Err(ParseErrorKind::Fragmented);
    }
    if fold_sum(word_sum(&raw[..ihl])) != 0xffff {
        return Err(ParseErrorKind::Checksum);
    }
    let udp = &raw[ihl..];
    let udp_len = usize::from(u16::from_be_bytes([udp[4], udp[5]]));
    if udp_len != total - ihl || udp_len < 8 + OS_UDP_HEADER_BYTES {
        return Err(ParseErrorKind::Length);
    }
    let body = &udp[8..];
    if body.len() > MAX_OS_UDP_BYTES {
        return Err(ParseErrorKind::Length);
    }
    if &body[..8] != b"P2WUDE1\0" {
        return Err(ParseErrorKind::Magic);
    }
    let kind = match body[8] {
        0 => RequestKind::Request,
        1 => RequestKind::Response,
        _ => return Err(ParseErrorKind::Kind),
    };
    let payload_bytes = u16::from_be_bytes([body[61], body[62]]);
    if usize::from(payload_bytes) != body.len() - OS_UDP_HEADER_BYTES {
        return Err(ParseErrorKind::Length);
    }
    if body[OS_UDP_HEADER_BYTES..].iter().any(|byte| *byte != 0xa5) {
        return Err(ParseErrorKind::Filler);
    }
    // IPv4 permits an omitted UDP checksum. When present, validate the
    // complete pseudo-header/datagram without allocating a payload copy.
    if udp[6..8] != [0, 0]
        && fold_sum(word_sum(&raw[12..20]) + 17 + udp_len as u32 + word_sum(udp)) != 0xffff
    {
        return Err(ParseErrorKind::Checksum);
    }
    let mut run = [0; 16];
    let mut round = [0; 16];
    let mut nonce = [0; 16];
    run.copy_from_slice(&body[9..25]);
    round.copy_from_slice(&body[25..41]);
    nonce.copy_from_slice(&body[45..61]);
    Ok(ParsedOsUdp {
        key: OsUdpReqKey {
            run,
            round,
            sequence: u32::from_be_bytes([body[41], body[42], body[43], body[44]]),
            request_nonce: nonce,
            kind,
        },
        flow: RegisteredFlow {
            src_v4: Ipv4Addr::new(raw[12], raw[13], raw[14], raw[15]),
            dst_v4: Ipv4Addr::new(raw[16], raw[17], raw[18], raw[19]),
            src_port: u16::from_be_bytes([udp[0], udp[1]]),
            dst_port: u16::from_be_bytes([udp[2], udp[3]]),
        },
        payload_bytes,
        ip_packet_len: total as u16,
    })
}

fn word_sum(bytes: &[u8]) -> u32 {
    bytes
        .chunks(2)
        .map(|pair| u32::from(pair[0]) * 256 + u32::from(pair.get(1).copied().unwrap_or(0)))
        .sum()
}

fn fold_sum(mut sum: u32) -> u32 {
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    sum
}
