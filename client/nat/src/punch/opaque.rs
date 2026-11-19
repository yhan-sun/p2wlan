//! Session-scoped labels reuse the existing authenticated Probe session key.
//! They reduce stable device correlation; addresses and timing remain visible.

use super::*;

pub fn opaque_probe_identity(key: &ProbeMacKey, node_id: &str) -> String {
    let mut input = b"p2wlan-udp-probe-opaque-id-v1\0".to_vec();
    input.extend_from_slice(node_id.as_bytes());
    let digest = hmac(key, &input);
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut label = String::with_capacity(32);
    for byte in &digest[..16] {
        label.push(HEX[(byte >> 4) as usize] as char);
        label.push(HEX[(byte & 15) as usize] as char);
    }
    label
}

pub(super) fn valid_opaque_identity(label: &str) -> bool {
    label.len() == 32
        && label
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

pub fn build_opaque_punch_packet_with_nomination(
    source_node_id: &str,
    target_node_id: &str,
    generation: u64,
    use_candidate: bool,
    identity_key: &ProbeMacKey,
    authentication_key: &ProbeMacKey,
) -> (Vec<u8>, [u8; 8]) {
    use rand::RngCore;
    let mut nonce = [0; 8];
    rand::thread_rng().fill_bytes(&mut nonce);
    let frame = authenticated::encode_punch_with_version(
        PunchPacketKind::Punch,
        nonce,
        (
            &opaque_probe_identity(identity_key, source_node_id),
            &opaque_probe_identity(identity_key, target_node_id),
        ),
        generation,
        use_candidate,
        authentication_key,
        OPAQUE_PUNCH_VERSION,
    );
    (frame, nonce)
}

/// Reply only to a successfully authenticated frame, retaining its wire mode.
/// Opaque labels are reversed, so scoped HH2 authentication never changes
/// the unscoped session labels used for routing.
pub fn build_authenticated_punch_ack_for_received(
    packet: &DecodedPunchPacket,
    local_node_id: &str,
    peer_node_id: &str,
    generation: u64,
    key: &ProbeMacKey,
) -> Option<Vec<u8>> {
    if !packet.authenticated {
        return None;
    }
    match packet.version {
        AUTH_PUNCH_VERSION => Some(build_authenticated_punch_ack(
            packet.nonce,
            local_node_id,
            peer_node_id,
            generation,
            key,
        )),
        OPAQUE_PUNCH_VERSION => Some(authenticated::encode_punch_with_version(
            PunchPacketKind::Ack,
            packet.nonce,
            (
                packet.target_node_id.as_deref()?,
                packet.source_node_id.as_deref()?,
            ),
            generation,
            false,
            key,
            OPAQUE_PUNCH_VERSION,
        )),
        _ => None,
    }
}

#[cfg(test)]
mod tests;
