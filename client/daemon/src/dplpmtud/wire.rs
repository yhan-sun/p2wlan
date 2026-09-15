use super::{
    DplpmtudPathIdentity, DplpmtudProbeIdentity, DplpmtudProbePlan, OuterIpFamily, UdpDatagramSize,
    DPLPMTUD_BASE_UDP_DATAGRAM_SIZE, WIREGUARD_UDP_DATAGRAM_OVERHEAD,
};
use p2pnet_tun::{Ipv4Packet, Protocol};
use std::net::Ipv4Addr;

pub(super) const DIRECT_VALIDATION_TOKEN_BYTES: usize = 8 + 2 + 1 + 8;
pub(super) const DIRECT_VALIDATION_CAPABILITY_EXTENSION: [u8; 6] = [b'D', b'P', b'M', b'1', 1, 1];
pub(super) const DPLPMTUD_PROBE_PREFIX: &[u8] = b"p2wlan-dplpmtud-probe-v1";
pub(super) const DPLPMTUD_ACK_PREFIX: &[u8] = b"p2wlan-dplpmtud-ack-v1";
pub(super) const DPLPMTUD_TOKEN_BYTES: usize = 8 + 16 + 16 + 8 + 8 + 8 + 8 + 2 + 4 + 1;
pub(super) const INNER_IPV4_ICMP_OVERHEAD: usize = 20 + 8;

/// Additive capability bytes inserted before the existing fixed Direct-
/// validation tail token. Old peers locate that token from the end and safely
/// ignore these bytes.
pub(crate) const fn direct_validation_capability_extension() -> [u8; 6] {
    DIRECT_VALIDATION_CAPABILITY_EXTENSION
}

/// Capability negotiation is fail-closed: legacy or malformed extensions are
/// treated as unsupported and therefore never receive a size Probe.
pub(crate) fn direct_validation_supports_dplpmtud(packet: &[u8]) -> bool {
    let Ok(ip) = Ipv4Packet::new(packet) else {
        return false;
    };
    if ip.protocol() != Protocol::Icmp {
        return false;
    }
    let Some(payload) = ip.payload().get(8..) else {
        return false;
    };
    let prefix_len = if payload.starts_with(crate::DIRECT_VALIDATION_REQUEST_PAYLOAD) {
        crate::DIRECT_VALIDATION_REQUEST_PAYLOAD.len()
    } else if payload.starts_with(crate::DIRECT_VALIDATION_ACK_PAYLOAD) {
        crate::DIRECT_VALIDATION_ACK_PAYLOAD.len()
    } else {
        return false;
    };
    let Some(token_start) = payload.len().checked_sub(DIRECT_VALIDATION_TOKEN_BYTES) else {
        return false;
    };
    token_start >= prefix_len
        && payload[prefix_len..token_start] == DIRECT_VALIDATION_CAPABILITY_EXTENSION
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct DplpmtudWireToken {
    pub(crate) sequence: u64,
    pub(crate) nonce: [u8; 16],
    pub(crate) path_cookie: [u8; 16],
    pub(crate) network_generation: u64,
    pub(crate) peer_session_generation: u64,
    pub(crate) remote_candidate_epoch: u64,
    pub(crate) direct_validation_owner_token: u64,
    pub(crate) direct_validation_request_id: u16,
    pub(crate) candidate_udp_datagram_size: UdpDatagramSize,
    pub(crate) outer_ip_family: OuterIpFamily,
}

impl DplpmtudWireToken {
    pub(crate) fn probe_identity(self) -> DplpmtudProbeIdentity {
        DplpmtudProbeIdentity {
            sequence: self.sequence,
            nonce: self.nonce,
            path_cookie: self.path_cookie,
            candidate_udp_datagram_size: self.candidate_udp_datagram_size,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum DplpmtudControlKind {
    Probe,
    Ack,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct DplpmtudControlPacket {
    pub(crate) kind: DplpmtudControlKind,
    pub(crate) token: DplpmtudWireToken,
}

pub(crate) fn build_probe_inner_packet(
    local_virtual_ip: Ipv4Addr,
    peer_virtual_ip: Ipv4Addr,
    token: DplpmtudWireToken,
) -> Result<Vec<u8>, String> {
    let target_plaintext = usize::try_from(token.candidate_udp_datagram_size.0)
        .ok()
        .and_then(|target| target.checked_sub(WIREGUARD_UDP_DATAGRAM_OVERHEAD as usize))
        .ok_or_else(|| "candidate UDP datagram is smaller than WireGuard overhead".to_string())?;
    let target_payload = target_plaintext
        .checked_sub(INNER_IPV4_ICMP_OVERHEAD)
        .ok_or_else(|| "candidate UDP datagram cannot carry IPv4/ICMP framing".to_string())?;
    let fixed_payload = DPLPMTUD_PROBE_PREFIX.len() + DPLPMTUD_TOKEN_BYTES;
    if target_payload < fixed_payload {
        return Err(format!(
            "candidate UDP datagram {} is smaller than DPLPMTUD fixed framing {}",
            token.candidate_udp_datagram_size.0,
            fixed_payload + INNER_IPV4_ICMP_OVERHEAD + WIREGUARD_UDP_DATAGRAM_OVERHEAD as usize,
        ));
    }
    let mut payload = Vec::with_capacity(target_payload);
    payload.extend_from_slice(DPLPMTUD_PROBE_PREFIX);
    encode_wire_token(&mut payload, token);
    payload.resize(target_payload, 0);
    let packet = Ipv4Packet::build_icmp_echo_request(
        local_virtual_ip,
        peer_virtual_ip,
        (token.sequence as u16).max(1),
        (token.sequence as u16).wrapping_add(1),
        &payload,
    );
    if packet.len() != target_plaintext {
        return Err(format!(
            "DPLPMTUD plaintext size mismatch: built={} expected={target_plaintext}",
            packet.len(),
        ));
    }
    Ok(packet)
}

pub(crate) fn build_ack_inner_packet(
    local_virtual_ip: Ipv4Addr,
    peer_virtual_ip: Ipv4Addr,
    token: DplpmtudWireToken,
) -> Vec<u8> {
    let mut payload = Vec::with_capacity(DPLPMTUD_ACK_PREFIX.len() + DPLPMTUD_TOKEN_BYTES);
    payload.extend_from_slice(DPLPMTUD_ACK_PREFIX);
    encode_wire_token(&mut payload, token);
    Ipv4Packet::build_icmp_echo_request(
        local_virtual_ip,
        peer_virtual_ip,
        (token.sequence as u16).max(1),
        (token.sequence as u16).wrapping_add(1),
        &payload,
    )
}

pub(crate) fn parse_control_packet(packet: &[u8]) -> Option<DplpmtudControlPacket> {
    let ip = Ipv4Packet::new(packet).ok()?;
    if ip.protocol() != Protocol::Icmp {
        return None;
    }
    let icmp = ip.payload();
    if icmp.len() < 8 || icmp[0] != 8 || icmp[1] != 0 {
        return None;
    }
    let payload = &icmp[8..];
    let (kind, token_bytes) = if let Some(bytes) = payload.strip_prefix(DPLPMTUD_PROBE_PREFIX) {
        (DplpmtudControlKind::Probe, bytes)
    } else {
        let bytes = payload.strip_prefix(DPLPMTUD_ACK_PREFIX)?;
        (DplpmtudControlKind::Ack, bytes)
    };
    let token = decode_wire_token(token_bytes)?;
    let ceiling = token.outer_ip_family.ceiling_udp_datagram_size().0;
    if token.candidate_udp_datagram_size.0 < DPLPMTUD_BASE_UDP_DATAGRAM_SIZE
        || token.candidate_udp_datagram_size.0 > ceiling
    {
        return None;
    }
    Some(DplpmtudControlPacket { kind, token })
}

pub(super) fn encode_wire_token(output: &mut Vec<u8>, token: DplpmtudWireToken) {
    output.extend_from_slice(&token.sequence.to_be_bytes());
    output.extend_from_slice(&token.nonce);
    output.extend_from_slice(&token.path_cookie);
    output.extend_from_slice(&token.network_generation.to_be_bytes());
    output.extend_from_slice(&token.peer_session_generation.to_be_bytes());
    output.extend_from_slice(&token.remote_candidate_epoch.to_be_bytes());
    output.extend_from_slice(&token.direct_validation_owner_token.to_be_bytes());
    output.extend_from_slice(&token.direct_validation_request_id.to_be_bytes());
    output.extend_from_slice(&token.candidate_udp_datagram_size.0.to_be_bytes());
    output.push(match token.outer_ip_family {
        OuterIpFamily::Ipv4 => 4,
        OuterIpFamily::Ipv6 => 6,
    });
}

pub(super) fn decode_wire_token(bytes: &[u8]) -> Option<DplpmtudWireToken> {
    if bytes.len() < DPLPMTUD_TOKEN_BYTES {
        return None;
    }
    let mut cursor = 0usize;
    let sequence = take_u64(bytes, &mut cursor)?;
    let nonce = take_array::<16>(bytes, &mut cursor)?;
    let path_cookie = take_array::<16>(bytes, &mut cursor)?;
    let network_generation = take_u64(bytes, &mut cursor)?;
    let peer_session_generation = take_u64(bytes, &mut cursor)?;
    let remote_candidate_epoch = take_u64(bytes, &mut cursor)?;
    let direct_validation_owner_token = take_u64(bytes, &mut cursor)?;
    let direct_validation_request_id = take_u16(bytes, &mut cursor)?;
    let candidate_udp_datagram_size = UdpDatagramSize(take_u32(bytes, &mut cursor)?);
    let outer_ip_family = match *bytes.get(cursor)? {
        4 => OuterIpFamily::Ipv4,
        6 => OuterIpFamily::Ipv6,
        _ => return None,
    };
    Some(DplpmtudWireToken {
        sequence,
        nonce,
        path_cookie,
        network_generation,
        peer_session_generation,
        remote_candidate_epoch,
        direct_validation_owner_token,
        direct_validation_request_id,
        candidate_udp_datagram_size,
        outer_ip_family,
    })
}

pub(super) fn take_array<const N: usize>(bytes: &[u8], cursor: &mut usize) -> Option<[u8; N]> {
    let end = cursor.checked_add(N)?;
    let value = bytes.get(*cursor..end)?.try_into().ok()?;
    *cursor = end;
    Some(value)
}

pub(super) fn take_u64(bytes: &[u8], cursor: &mut usize) -> Option<u64> {
    Some(u64::from_be_bytes(take_array(bytes, cursor)?))
}

pub(super) fn take_u32(bytes: &[u8], cursor: &mut usize) -> Option<u32> {
    Some(u32::from_be_bytes(take_array(bytes, cursor)?))
}

pub(super) fn take_u16(bytes: &[u8], cursor: &mut usize) -> Option<u16> {
    Some(u16::from_be_bytes(take_array(bytes, cursor)?))
}

/// Build a compatibility-shaped Direct-validation packet carrying a DPLPMTUD
/// Probe. The fixed Direct-validation tail remains at the end for old decoders.
pub(crate) fn build_encrypted_probe_plaintext(
    local_virtual_ip: Ipv4Addr,
    peer_virtual_ip: Ipv4Addr,
    identity: &DplpmtudPathIdentity,
    plan: &DplpmtudProbePlan,
) -> Result<Vec<u8>, String> {
    let dplpmtud = build_probe_inner_packet(local_virtual_ip, peer_virtual_ip, plan.wire_token)?;
    // The DPLPMTUD inner packet itself is the authenticated WireGuard
    // plaintext. It is parsed before ordinary Direct-validation handling.
    debug_assert_eq!(identity.peer_id, plan.peer_id);
    Ok(dplpmtud)
}
