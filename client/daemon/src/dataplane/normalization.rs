#[derive(Debug, Clone, Copy)]
struct Ipv4Cidr {
    network: u32,
    mask: u32,
}

impl Ipv4Cidr {
    fn parse(cidr: &str) -> Option<Self> {
        let (ip, prefix) = cidr.split_once('/')?;
        let ip = ip.parse::<Ipv4Addr>().ok()?;
        let prefix = prefix.parse::<u32>().ok()?;
        if prefix > 32 {
            return None;
        }
        let mask = if prefix == 0 {
            0
        } else {
            u32::MAX << (32 - prefix)
        };
        let network = u32::from(ip) & mask;
        Some(Self { network, mask })
    }

    fn contains(self, ip: Ipv4Addr) -> bool {
        (u32::from(ip) & self.mask) == self.network
    }
}

enum SourceNormalization {
    Normalized(Vec<u8>),
    BlockedOverlaySpoof,
    Unsupported,
}

fn normalize_overlay_source(
    packet: &[u8],
    old_src: &str,
    new_src: &str,
    overlay_v4: Option<Ipv4Cidr>,
) -> SourceNormalization {
    let Some(overlay_v4) = overlay_v4 else {
        return SourceNormalization::Unsupported;
    };
    let Ok(old_src) = old_src.parse::<Ipv4Addr>() else {
        return SourceNormalization::Unsupported;
    };
    let Ok(new_src) = new_src.parse::<Ipv4Addr>() else {
        return SourceNormalization::Unsupported;
    };

    if overlay_v4.contains(old_src) {
        return SourceNormalization::BlockedOverlaySpoof;
    }

    normalize_ipv4_source(packet, old_src, new_src)
        .map(SourceNormalization::Normalized)
        .unwrap_or(SourceNormalization::Unsupported)
}

fn normalize_ipv4_source(packet: &[u8], old_src: Ipv4Addr, new_src: Ipv4Addr) -> Option<Vec<u8>> {
    if packet.len() < 20 || (packet[0] >> 4) != 4 {
        return None;
    }
    let ihl = usize::from(packet[0] & 0x0f) * 4;
    if ihl < 20 || packet.len() < ihl {
        return None;
    }
    let total_len = usize::from(u16::from_be_bytes([packet[2], packet[3]]));
    if total_len < ihl || packet.len() < total_len {
        return None;
    }
    if ipv4_is_fragment(packet) {
        return None;
    }
    if Ipv4Addr::new(packet[12], packet[13], packet[14], packet[15]) != old_src {
        return None;
    }

    let mut normalized = packet[..total_len].to_vec();
    normalized[12..16].copy_from_slice(&new_src.octets());
    rewrite_ipv4_header_checksum(&mut normalized, ihl);
    rewrite_transport_checksum_for_ipv4_source(&mut normalized, ihl, old_src, new_src);
    Some(normalized)
}

fn ipv4_is_fragment(packet: &[u8]) -> bool {
    let flags_fragment = u16::from_be_bytes([packet[6], packet[7]]);
    (flags_fragment & 0x3fff) != 0
}

fn rewrite_ipv4_header_checksum(packet: &mut [u8], ihl: usize) {
    packet[10] = 0;
    packet[11] = 0;
    let checksum = internet_checksum(&packet[..ihl]);
    packet[10..12].copy_from_slice(&checksum.to_be_bytes());
}

fn rewrite_transport_checksum_for_ipv4_source(
    packet: &mut [u8],
    ihl: usize,
    old_src: Ipv4Addr,
    new_src: Ipv4Addr,
) {
    let Some(offset) = transport_checksum_offset(packet, ihl) else {
        return;
    };
    let current = u16::from_be_bytes([packet[offset], packet[offset + 1]]);
    if packet[9] == 17 && current == 0 {
        return;
    }
    let updated = checksum_replace_ipv4_addr(current, old_src, new_src);
    let updated = if packet[9] == 17 && updated == 0 {
        0xffff
    } else {
        updated
    };
    packet[offset..offset + 2].copy_from_slice(&updated.to_be_bytes());
}

fn transport_checksum_offset(packet: &[u8], ihl: usize) -> Option<usize> {
    let transport_len = packet.len().checked_sub(ihl)?;
    match packet[9] {
        6 if transport_len >= 20 => Some(ihl + 16),
        17 if transport_len >= 8 => Some(ihl + 6),
        _ => None,
    }
}

fn checksum_replace_ipv4_addr(checksum: u16, old_src: Ipv4Addr, new_src: Ipv4Addr) -> u16 {
    let old = old_src.octets();
    let new = new_src.octets();
    let mut sum = u32::from(!checksum);
    for (old_word, new_word) in [
        (
            u16::from_be_bytes([old[0], old[1]]),
            u16::from_be_bytes([new[0], new[1]]),
        ),
        (
            u16::from_be_bytes([old[2], old[3]]),
            u16::from_be_bytes([new[2], new[3]]),
        ),
    ] {
        sum += u32::from(!old_word);
        sum += u32::from(new_word);
        sum = fold_checksum_sum(sum);
    }
    !fold_checksum_sum(sum) as u16
}

fn internet_checksum(data: &[u8]) -> u16 {
    let mut sum = 0u32;
    let mut chunks = data.chunks_exact(2);
    for chunk in &mut chunks {
        sum += u32::from(u16::from_be_bytes([chunk[0], chunk[1]]));
        sum = fold_checksum_sum(sum);
    }
    if let [last] = chunks.remainder() {
        sum += u32::from(*last) << 8;
    }
    !fold_checksum_sum(sum) as u16
}

fn fold_checksum_sum(mut sum: u32) -> u32 {
    while sum > 0xffff {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    sum
}
