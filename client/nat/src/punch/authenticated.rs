use super::*;

pub fn build_authenticated_punch_packet(
    source_node_id: &str,
    target_node_id: &str,
    generation: u64,
    key: &ProbeMacKey,
) -> (Vec<u8>, [u8; 8]) {
    build_authenticated_punch_packet_with_nomination(
        source_node_id,
        target_node_id,
        generation,
        false,
        key,
    )
}

/// Build a fresh authenticated v2 PUNCH datagram with an ICE-style nomination bit.
pub fn build_authenticated_punch_packet_with_nomination(
    source_node_id: &str,
    target_node_id: &str,
    generation: u64,
    use_candidate: bool,
    key: &ProbeMacKey,
) -> (Vec<u8>, [u8; 8]) {
    use rand::RngCore;

    let mut nonce = [0u8; 8];
    rand::thread_rng().fill_bytes(&mut nonce);
    let bytes = encode_authenticated_punch(
        PunchPacketKind::Punch,
        nonce,
        source_node_id,
        target_node_id,
        generation,
        use_candidate,
        key,
    );
    (bytes, nonce)
}

/// Build an authenticated v2 PUNCH datagram using a caller-provided nonce.
///
/// This is primarily used for protocol fixtures and cross-language golden
/// vectors. Runtime probing should normally use
/// [`build_authenticated_punch_packet_with_nomination`] so nonces remain fresh.
pub fn build_authenticated_punch_packet_with_nonce(
    nonce: [u8; 8],
    source_node_id: &str,
    target_node_id: &str,
    generation: u64,
    use_candidate: bool,
    key: &ProbeMacKey,
) -> Vec<u8> {
    encode_authenticated_punch(
        PunchPacketKind::Punch,
        nonce,
        source_node_id,
        target_node_id,
        generation,
        use_candidate,
        key,
    )
}

/// Build an authenticated v2 ACK datagram for a received v2 PUNCH nonce.
pub fn build_authenticated_punch_ack(
    nonce: [u8; 8],
    source_node_id: &str,
    target_node_id: &str,
    generation: u64,
    key: &ProbeMacKey,
) -> Vec<u8> {
    encode_authenticated_punch(
        PunchPacketKind::Ack,
        nonce,
        source_node_id,
        target_node_id,
        generation,
        false,
        key,
    )
}

/// Read claimed identity fields from a v2 probe before validating its MAC.
pub fn peek_authenticated_punch_identity(data: &[u8]) -> Option<AuthenticatedPunchIdentity> {
    let parsed = parse_authenticated_punch(data)?;
    Some(AuthenticatedPunchIdentity {
        kind: parsed.kind,
        source_node_id: parsed.source_node_id,
        target_node_id: parsed.target_node_id,
        generation: parsed.generation,
        use_candidate: parsed.use_candidate,
    })
}

/// Decode and verify an authenticated v2 probe datagram.
pub fn decode_authenticated_punch_packet(
    data: &[u8],
    key: &ProbeMacKey,
) -> Option<DecodedPunchPacket> {
    let parsed = parse_authenticated_punch(data)?;
    let mac_start = data.len().checked_sub(AUTH_PUNCH_MAC_SIZE)?;
    let expected = punch_v2_mac(&data[..mac_start], key);
    if !constant_time_eq(&expected, &data[mac_start..]) {
        return None;
    }

    Some(DecodedPunchPacket {
        kind: parsed.kind,
        nonce: parsed.nonce,
        version: AUTH_PUNCH_VERSION,
        source_node_id: Some(parsed.source_node_id),
        target_node_id: Some(parsed.target_node_id),
        generation: Some(parsed.generation),
        use_candidate: parsed.use_candidate,
        authenticated: true,
    })
}

fn encode_authenticated_punch(
    kind: PunchPacketKind,
    nonce: [u8; 8],
    source_node_id: &str,
    target_node_id: &str,
    generation: u64,
    use_candidate: bool,
    key: &ProbeMacKey,
) -> Vec<u8> {
    let source = source_node_id.as_bytes();
    let target = target_node_id.as_bytes();
    assert!(
        source.len() <= u8::MAX as usize && target.len() <= u8::MAX as usize,
        "node IDs must fit in one-byte length fields"
    );

    let mut frame = Vec::with_capacity(
        4 + 1 + 1 + 8 + 8 + 1 + 1 + 1 + source.len() + target.len() + AUTH_PUNCH_MAC_SIZE,
    );
    frame.extend_from_slice(&PUNCH_MAGIC);
    frame.push(AUTH_PUNCH_VERSION);
    frame.push(match kind {
        PunchPacketKind::Punch => TYPE_PUNCH,
        PunchPacketKind::Ack => TYPE_ACK,
    });
    frame.extend_from_slice(&nonce);
    frame.extend_from_slice(&generation.to_be_bytes());
    frame.push(if use_candidate {
        AUTH_PUNCH_FLAG_USE_CANDIDATE
    } else {
        0
    });
    frame.push(source.len() as u8);
    frame.push(target.len() as u8);
    frame.extend_from_slice(source);
    frame.extend_from_slice(target);
    let mac = punch_v2_mac(&frame, key);
    frame.extend_from_slice(&mac);
    frame
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ParsedAuthenticatedPunch {
    kind: PunchPacketKind,
    nonce: [u8; 8],
    generation: u64,
    use_candidate: bool,
    source_node_id: String,
    target_node_id: String,
}

fn parse_authenticated_punch(data: &[u8]) -> Option<ParsedAuthenticatedPunch> {
    parse_authenticated_punch_with_flags(data).or_else(|| parse_authenticated_punch_legacy(data))
}

fn parse_authenticated_punch_with_flags(data: &[u8]) -> Option<ParsedAuthenticatedPunch> {
    parse_authenticated_punch_inner(data, true)
}

fn parse_authenticated_punch_legacy(data: &[u8]) -> Option<ParsedAuthenticatedPunch> {
    parse_authenticated_punch_inner(data, false)
}

fn parse_authenticated_punch_inner(
    data: &[u8],
    has_flags: bool,
) -> Option<ParsedAuthenticatedPunch> {
    let minimum = 4 + 1 + 1 + 8 + 8 + usize::from(has_flags) + 1 + 1 + AUTH_PUNCH_MAC_SIZE;
    if data.len() < minimum {
        return None;
    }
    if data[..4] != PUNCH_MAGIC || data[4] != AUTH_PUNCH_VERSION {
        return None;
    }
    let kind = match data[5] {
        TYPE_PUNCH => PunchPacketKind::Punch,
        TYPE_ACK => PunchPacketKind::Ack,
        _ => return None,
    };
    let mut nonce = [0u8; 8];
    nonce.copy_from_slice(&data[6..14]);
    let mut generation_bytes = [0u8; 8];
    generation_bytes.copy_from_slice(&data[14..22]);
    let generation = u64::from_be_bytes(generation_bytes);
    let mut cursor: usize = 22;
    let flags = if has_flags {
        let flags = data[cursor];
        if flags & !AUTH_PUNCH_FLAG_USE_CANDIDATE != 0 {
            return None;
        }
        cursor += 1;
        flags
    } else {
        0
    };
    let source_len = data[cursor] as usize;
    cursor += 1;
    let target_len = data[cursor] as usize;
    cursor += 1;
    let source_start = cursor;
    let target_start = source_start.checked_add(source_len)?;
    let mac_start = data.len().checked_sub(AUTH_PUNCH_MAC_SIZE)?;
    let target_end = target_start.checked_add(target_len)?;
    if target_end != mac_start {
        return None;
    }
    let source_node_id = std::str::from_utf8(&data[source_start..target_start])
        .ok()?
        .to_string();
    let target_node_id = std::str::from_utf8(&data[target_start..target_end])
        .ok()?
        .to_string();
    if source_node_id.is_empty() || target_node_id.is_empty() {
        return None;
    }

    Some(ParsedAuthenticatedPunch {
        kind,
        nonce,
        generation,
        use_candidate: flags & AUTH_PUNCH_FLAG_USE_CANDIDATE != 0,
        source_node_id,
        target_node_id,
    })
}

pub(super) fn punch_v2_mac(
    frame_without_mac: &[u8],
    key: &ProbeMacKey,
) -> [u8; AUTH_PUNCH_MAC_SIZE] {
    let mut input = Vec::with_capacity(AUTH_PUNCH_MAC_DOMAIN.len() + frame_without_mac.len());
    input.extend_from_slice(AUTH_PUNCH_MAC_DOMAIN);
    input.extend_from_slice(frame_without_mac);
    let full = hmac(key, &input);
    let mut truncated = [0u8; AUTH_PUNCH_MAC_SIZE];
    truncated.copy_from_slice(&full[..AUTH_PUNCH_MAC_SIZE]);
    truncated
}

fn constant_time_eq(expected: &[u8; AUTH_PUNCH_MAC_SIZE], actual: &[u8]) -> bool {
    if actual.len() != AUTH_PUNCH_MAC_SIZE {
        return false;
    }
    expected
        .iter()
        .zip(actual.iter())
        .fold(0u8, |acc, (a, b)| acc | (a ^ b))
        == 0
}
