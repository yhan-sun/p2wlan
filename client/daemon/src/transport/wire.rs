use super::*;

/// Stable, non-reversible diagnostic fingerprint for an opaque encrypted
/// datagram. This is only used in local debug traces to correlate the same
/// ciphertext at transport boundaries; it is not exposed in status/metrics.
pub(crate) fn wire_fingerprint(bytes: &[u8]) -> u64 {
    // FNV-1a is adequate for correlation, not authentication. Keeping this
    // allocation-free also makes the diagnostic safe on the hot path.
    let mut hash = 0xcbf2_9ce4_8422_2325u64;
    for byte in bytes {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
    }
    hash
}

/// Extract the WireGuard transport counter from an already serialized
/// transport message for local diagnostics.  The counter is authenticated by
/// WireGuard and is never sent as a separate diagnostic field on the network;
/// this helper only avoids putting opaque `wire_fp` values in a trace where a
/// replay/order incident needs to be reconstructed.
pub(crate) fn wire_counter(bytes: &[u8]) -> Option<u64> {
    // MessageTransport::to_bytes() starts with the little-endian type-4
    // header, then receiver_index (4 bytes), then counter (8 bytes).
    if bytes.len() < 16 || bytes.get(..4) != Some(&[4, 0, 0, 0]) {
        return None;
    }
    Some(u64::from_le_bytes(bytes.get(8..16)?.try_into().ok()?))
}

pub(crate) fn wire_receiver_index(bytes: &[u8]) -> Option<u32> {
    if bytes.len() < 8 || bytes.get(..4) != Some(&[4, 0, 0, 0]) {
        return None;
    }
    Some(u32::from_le_bytes(bytes.get(4..8)?.try_into().ok()?))
}

#[cfg(test)]
pub(crate) fn build_relay_validation_payload(sent_at_ms: u64) -> Vec<u8> {
    let mut payload = Vec::with_capacity(
        RELAY_VALIDATION_PAYLOAD_PREFIX.len() + RELAY_VALIDATION_TIMESTAMP_BYTES,
    );
    payload.extend_from_slice(RELAY_VALIDATION_PAYLOAD_PREFIX);
    payload.extend_from_slice(&sent_at_ms.to_be_bytes());
    payload
}

/// Recognize the daemon-internal relay health echo in either direction.  It
/// is encrypted and may traverse the relay, but it is not user/TUN business
/// traffic and must never become `first_usable` evidence.
pub(super) fn is_relay_validation_packet(packet: &[u8]) -> bool {
    let Ok(ip) = Ipv4Packet::new(packet) else {
        return false;
    };
    if ip.protocol() != Protocol::Icmp {
        return false;
    }
    let icmp = ip.payload();
    if icmp.len() < 8 + RELAY_VALIDATION_PAYLOAD_PREFIX.len() + RELAY_VALIDATION_TIMESTAMP_BYTES {
        return false;
    }
    if !matches!(icmp[0], 0 | 8) || icmp[1] != 0 {
        return false;
    }
    let payload = &icmp[8..];
    payload
        .strip_prefix(RELAY_VALIDATION_PAYLOAD_PREFIX)
        .and_then(|payload| payload.get(..RELAY_VALIDATION_TIMESTAMP_BYTES))
        .is_some()
}

pub(super) fn is_rekey_confirmation_packet(packet: &[u8]) -> bool {
    let Ok(ip) = Ipv4Packet::new(packet) else {
        return false;
    };
    if ip.protocol() != Protocol::Icmp {
        return false;
    }
    let icmp = ip.payload();
    icmp.len() >= 8
        && icmp[0] == 8
        && icmp[1] == 0
        && icmp.get(8..) == Some(crate::REKEY_CONFIRMATION_PAYLOAD)
}

/// Decide whether a successfully decrypted UDP packet should schedule the
/// owned encrypted Direct request/ACK validation worker.
///
/// A rekey confirmation is authenticated endpoint evidence, but never Direct
/// proof on its own. It therefore follows this path exactly like ordinary
/// decrypted UDP data: learn/remember the endpoint and ask the bounded
/// validation worker to prove the reverse direction. Direct-validation packets
/// are excluded so their request/ACK exchange cannot recursively enqueue more
/// validation sessions.
pub(super) fn should_request_direct_validation_after_decrypt(
    owns_direct_packet: bool,
    source: Option<SocketAddr>,
    direct_validation: Option<DirectValidationToken>,
) -> bool {
    owns_direct_packet && source.is_some() && direct_validation.is_none()
}

/// Pick the reverse destination for one authenticated DPLPMTUD Probe.
///
/// A port-dependent NAT can expose a different source mapping for the Probe
/// than the endpoint which the peer previously authenticated. Replying to that
/// transient source would make the ACK originate from another transient
/// mapping and the initiator would correctly reject it as the wrong exact
/// path. When this UDP publication still owns an exact current path on the
/// receiving socket, send the ACK to the session-bound endpoint recorded from
/// the peer's authenticated Direct-validation Request. This makes the reverse
/// datagram originate from the responder mapping the initiator already
/// committed, while preserving strict ACK ingress matching. Without both
/// bindings, retain the historical reply-to-source behavior; it is safe but
/// may be rejected fail-closed by the initiator.
pub(super) fn dplpmtud_ack_destination(
    current_path: Option<&crate::dplpmtud::DplpmtudPathIdentity>,
    authenticated_reverse_endpoint: Option<SocketAddr>,
    transport_instance_id: u64,
    probe_source: SocketAddr,
    local_endpoint: SocketAddr,
    socket_index: usize,
) -> SocketAddr {
    current_path
        .filter(|identity| {
            identity.local_endpoint == local_endpoint
                && identity.socket.transport_instance_id == transport_instance_id
                && identity.socket.socket_index == socket_index
                && identity.authenticated_remote_endpoint.is_ipv4() == probe_source.is_ipv4()
        })
        .and(authenticated_reverse_endpoint)
        .filter(|endpoint| endpoint.is_ipv4() == probe_source.is_ipv4())
        .unwrap_or(probe_source)
}

/// Build the ICMP echo-request payload of one direct-validation packet: the
/// fixed prefix plus the big-endian token (generation, request id, sequence,
/// owner token).
/// The prefix length is fixed so the parser can slice the token deterministically.
pub(crate) fn build_direct_validation_payload(
    kind: DirectValidationKind,
    generation: u64,
    request_id: u16,
    sequence: u8,
    owner_token: u64,
) -> Vec<u8> {
    let prefix = match kind {
        DirectValidationKind::Request => crate::DIRECT_VALIDATION_REQUEST_PAYLOAD,
        DirectValidationKind::Ack => crate::DIRECT_VALIDATION_ACK_PAYLOAD,
    };
    let capability = crate::dplpmtud::direct_validation_capability_extension();
    let mut payload =
        Vec::with_capacity(prefix.len() + capability.len() + DIRECT_VALIDATION_TOKEN_BYTES);
    payload.extend_from_slice(prefix);
    payload.extend_from_slice(&capability);
    payload.extend_from_slice(&generation.to_be_bytes());
    payload.extend_from_slice(&request_id.to_be_bytes());
    payload.push(sequence);
    payload.extend_from_slice(&owner_token.to_be_bytes());
    payload
}

/// Parse the direct-validation token out of a decrypted WireGuard datagram,
/// or `None` when the packet is not a daemon-internal validation packet.
///
/// The framing mirrors the rekey-confirmation packets: an ICMP echo request
/// (type 8) carrying the validation prefix — the daemon consumes these
/// packets, so neither the TUN device nor an OS echo reply is ever involved.
pub(crate) fn parse_direct_validation_token(packet: &[u8]) -> Option<DirectValidationToken> {
    let ip = Ipv4Packet::new(packet).ok()?;
    if ip.protocol() != Protocol::Icmp {
        return None;
    }
    let icmp = ip.payload();
    if icmp.len() < 8 {
        return None;
    }
    if icmp[0] != 8 || icmp[1] != 0 {
        return None;
    }
    let payload = &icmp[8..];
    let kind = if payload.starts_with(crate::DIRECT_VALIDATION_REQUEST_PAYLOAD) {
        DirectValidationKind::Request
    } else if payload.starts_with(crate::DIRECT_VALIDATION_ACK_PAYLOAD) {
        DirectValidationKind::Ack
    } else {
        return None;
    };
    let prefix_len = match kind {
        DirectValidationKind::Request => crate::DIRECT_VALIDATION_REQUEST_PAYLOAD.len(),
        DirectValidationKind::Ack => crate::DIRECT_VALIDATION_ACK_PAYLOAD.len(),
    };
    // The full token must follow the prefix: a truncated payload is not a
    // validation packet.
    let token_start = payload
        .len()
        .checked_sub(DIRECT_VALIDATION_TOKEN_BYTES)
        .filter(|start| *start >= prefix_len)?;
    let token = payload.get(token_start..)?;
    let generation = u64::from_be_bytes(token[..8].try_into().ok()?);
    let request_id = u16::from_be_bytes(token[8..10].try_into().ok()?);
    let sequence = *token.get(10)?;
    let owner_token = u64::from_be_bytes(token[11..19].try_into().ok()?);
    Some(DirectValidationToken {
        kind,
        generation,
        request_id,
        sequence,
        owner_token,
    })
}

/// Whether a decrypted IP packet looks like an overlay business payload (UDP
/// with the overlay magic right after the UDP header).  The overlay validation
/// loop re-verifies fully (magic, checksum, nonce/seq, sender); this is only a
/// cheap transport-layer pre-filter so ordinary keepalive/user traffic is not
/// forwarded to the harness.
pub(crate) fn is_overlay_payload_candidate(packet: &[u8]) -> bool {
    let Ok(ip) = Ipv4Packet::new(packet) else {
        return false;
    };
    if ip.protocol() != Protocol::Udp {
        return false;
    }
    let payload = ip.payload();
    payload.len() > 8 + crate::OVERLAY_PAYLOAD_MAGIC.len()
        && payload[8..8 + crate::OVERLAY_PAYLOAD_MAGIC.len()] == crate::OVERLAY_PAYLOAD_MAGIC[..]
}

/// A decrypted WireGuard keepalive has no inner IP packet.  Only a valid
/// overlay IPv4 packet is production business ingress evidence; otherwise the
/// initial session/rekey traffic could falsely set `first_usable` before the
/// TUN has delivered a real packet.  This predicate intentionally accepts all
/// IPv4 protocols (ICMP, TCP, UDP, etc.) so it is not tied to the harness-only
/// overlay echo format.
pub(crate) fn is_real_overlay_business_packet(packet: &[u8]) -> bool {
    Ipv4Packet::new(packet).is_ok()
        && !is_relay_validation_packet(packet)
        && !is_rekey_confirmation_packet(packet)
        && parse_direct_validation_token(packet).is_none()
        && crate::dplpmtud::parse_control_packet(packet).is_none()
        && crate::relay_probe::parse_relay_probe_token(packet).is_none()
        && crate::path_commit::parse_path_commit_token(packet).is_none()
}
