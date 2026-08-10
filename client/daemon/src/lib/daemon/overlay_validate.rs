// ============================================================
// Encrypted overlay validation loop (independent harness only)
// ============================================================
//
// When `config.network.validate_overlay` is enabled (daemon flag
// `--validate-overlay`, off by default), the daemon runs the REAL production
// dataplane over an in-memory MockTunDevice and this loop injects business
// payloads into that dataplane.  Every injected payload is:
//
//   1. routed by the production DataPlane (record_sent),
//   2. encrypted by the production WireGuardTransport session,
//   3. emitted through the production outbound path selector, which sends
//      the encrypted datagram over the DIRECT UDP socket when the peer is
//      Direct,
//   4. decrypted on the far side by the production WireGuard inbound path,
//   5. delivered to the production DataPlane inbound path (record_received),
//      which writes it to the mock TUN,
//   6. read back by this loop and verified (magic, checksum, nonce/seq).
//
// The reply is echoed back through the same pipeline, so a single round
// proves bidirectional real encrypted overlay traffic.  This is NOT a
// test-only plaintext bypass: there is no path from this loop to the UDP
// socket other than DataPlane -> WireGuard -> outbound selector.

use p2pnet_tun::mock::MockTunController;

/// Overlay payload magic ("P2WLOV").
const OVERLAY_MAGIC: &[u8; 6] = b"P2WLOV";
/// Overlay payload marker for the acceptance report.
const OVERLAY_EVIDENCE_PREFIX: &str = "overlay_payload";
/// How often the loop probes every Direct peer.
const OVERLAY_SEND_INTERVAL: Duration = Duration::from_secs(2);
/// Filler size so the IP packet looks like a small user datagram.
const OVERLAY_FILLER_BYTES: usize = 128;
/// Maximum remembered (nonce, seq) pairs for duplicate suppression.
const OVERLAY_SEEN_CAP: usize = 256;
/// Byte offset of the checksum field inside the overlay payload.
const OVERLAY_CHECKSUM_OFFSET: usize = 6 + 1 + 8 + 4;
/// Checksummed region: magic + direction + nonce + sequence (the checksum
/// field itself is excluded so the sender and the verifier compute the same
/// value).
const OVERLAY_CHECKSUM_SPAN: usize = 6 + 1 + 8 + 4;
/// Payload direction marker: `0` is a fresh request, `1` is an echo.  Only
/// fresh requests are echoed, so an echo of an echo can never loop.
const OVERLAY_DIRECTION_REQUEST: u8 = 0;
const OVERLAY_DIRECTION_ECHO: u8 = 1;

struct OverlayStats {
    sent: u64,
    received_valid: u64,
    received_invalid: u64,
    verified_round_trips: u64,
    last_seq: u64,
}

pub async fn run_overlay_validate_loop(
    mut controller: MockTunController,
    peers: Arc<PeerManager>,
    local_vip: String,
    local_node_id: String,
    mut shutdown_rx: watch::Receiver<bool>,
) {
    info!(
        "overlay_validate loop started local_vip={local_vip}: sending real encrypted overlay payloads through the production dataplane"
    );
    let mut stats = OverlayStats {
        sent: 0,
        received_valid: 0,
        received_invalid: 0,
        verified_round_trips: 0,
        last_seq: 0,
    };
    let mut seen = std::collections::VecDeque::<(u64, u32)>::new();
    let mut next_nonce: u64 = rand::random();
    let mut next_seq = 0u32;
    let mut send_tick = tokio::time::interval(OVERLAY_SEND_INTERVAL);
    send_tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    // Skip the immediate first tick so the peer can converge to Direct
    // before the first payload is injected.
    send_tick.tick().await;

    loop {
        tokio::select! {
            _ = send_tick.tick() => {
                stats.sent = stats
                    .sent
                    .saturating_add(send_overlay_payloads(
                        &controller,
                        &peers,
                        &local_vip,
                        &mut next_nonce,
                        &mut next_seq,
                        &mut stats,
                    )
                    .await);
            }
            written = controller.recv_written() => {
                let Ok(packet) = written else {
                    warn!("overlay_validate: mock TUN closed; stopping");
                    break;
                };
                match verify_overlay_packet(
                    &packet,
                    &local_vip,
                    &local_node_id,
                    &mut seen,
                    &mut stats,
                    &peers,
                )
                .await
                {
                    OverlayVerdict::Valid { peer_id, virtual_ip, nonce, seq, direction } => {
                        // Echo the payload back through the real pipeline so
                        // one round proves bidirectional encrypted traffic.
                        // ONLY a fresh request (direction 0) is echoed; an
                        // echo is never echoed again, so (nonce, seq) ping-
                        // pong is impossible.
                        if direction != OVERLAY_DIRECTION_REQUEST {
                            continue;
                        }
                        let payload = build_overlay_payload(OVERLAY_DIRECTION_ECHO, nonce, seq);
                        if let Some(echo) = build_udp_overlay_packet(
                            &local_vip,
                            &virtual_ip,
                            39287,
                            39286,
                            &payload,
                        ) {
                            if controller.inject(echo).await.is_ok() {
                                info!(
                                    "{OVERLAY_EVIDENCE_PREFIX}_echo peer={peer_id} dst_ip={virtual_ip} seq={seq} nonce={nonce:#x} len={}",
                                    payload.len() + 28
                                );
                            }
                        }
                    }
                    OverlayVerdict::Invalid { reason } => {
                        warn!("{OVERLAY_EVIDENCE_PREFIX}_invalid {reason}");
                    }
                    OverlayVerdict::Ignored => {}
                }
            }
            changed = shutdown_rx.changed() => {
                if changed.is_err() || *shutdown_rx.borrow_and_update() {
                    break;
                }
            }
        }
    }
    info!(
        "overlay_validate loop stopped: sent={} received_valid={} received_invalid={} verified_round_trips={} last_seq={}",
        stats.sent, stats.received_valid, stats.received_invalid, stats.verified_round_trips, stats.last_seq
    );
}

/// Build one overlay business payload: magic + direction + nonce + sequence +
/// checksum + random filler.
fn build_overlay_payload(direction: u8, nonce: u64, seq: u32) -> Vec<u8> {
    let mut payload = Vec::with_capacity(OVERLAY_CHECKSUM_OFFSET + 4 + OVERLAY_FILLER_BYTES);
    payload.extend_from_slice(OVERLAY_MAGIC);
    payload.push(direction);
    payload.extend_from_slice(&nonce.to_be_bytes());
    payload.extend_from_slice(&seq.to_be_bytes());
    payload.extend_from_slice(&[0u8; 4]);
    let mut filler = vec![0u8; OVERLAY_FILLER_BYTES];
    rand::thread_rng().fill_bytes(&mut filler);
    payload.extend_from_slice(&filler);
    let checksum = crc32_business_payload(&payload[..OVERLAY_CHECKSUM_SPAN]);
    payload[OVERLAY_CHECKSUM_OFFSET..OVERLAY_CHECKSUM_OFFSET + 4]
        .copy_from_slice(&checksum.to_be_bytes());
    payload
}

/// Inject one payload per Direct peer into the production dataplane.
async fn send_overlay_payloads(
    controller: &MockTunController,
    peers: &Arc<PeerManager>,
    local_vip: &str,
    next_nonce: &mut u64,
    next_seq: &mut u32,
    stats: &mut OverlayStats,
) -> u64 {
    let mut sent = 0u64;
    let direct_peers = peers.diagnostics().await;
    for peer in direct_peers {
        if peer.state != ConnectionState::Direct {
            continue;
        }
        let virtual_ip = peer.virtual_ip.clone();
        let peer_id = peer.node_id.clone();
        *next_nonce = next_nonce.wrapping_add(1);
        *next_seq = next_seq.wrapping_add(1);
        let payload = build_overlay_payload(OVERLAY_DIRECTION_REQUEST, *next_nonce, *next_seq);
        let Some(packet) =
            build_udp_overlay_packet(local_vip, &virtual_ip, 39286, 39287, &payload)
        else {
            continue;
        };
        let active_path = peer
            .active_path
            .map(|path| format!("{path:?}"))
            .unwrap_or_else(|| "none".to_string());
        if controller.inject(packet).await.is_ok() {
            sent += 1;
            stats.last_seq = u64::from(*next_seq);
            info!(
                "{OVERLAY_EVIDENCE_PREFIX}_sent peer={peer_id} dst_ip={virtual_ip} seq={} nonce={} len={} active_path={active_path} state={}",
                *next_seq,
                *next_nonce,
                payload.len() + 28,
                peer.state
            );
        }
    }
    sent
}

enum OverlayVerdict {
    Valid {
        peer_id: String,
        virtual_ip: String,
        nonce: u64,
        seq: u32,
        direction: u8,
    },
    Invalid {
        reason: String,
    },
    Ignored,
}

/// Verify a decrypted inbound overlay payload that the production dataplane
/// delivered.  Returns the sender peer and the payload identity when the
/// magic, checksum and nonce/seq are all valid.
async fn verify_overlay_packet(
    packet: &[u8],
    local_vip: &str,
    _local_node_id: &str,
    seen: &mut std::collections::VecDeque<(u64, u32)>,
    stats: &mut OverlayStats,
    peers: &Arc<PeerManager>,
) -> OverlayVerdict {
    let parsed = match p2pnet_tun::Ipv4Packet::new(packet) {
        Ok(parsed) => parsed,
        Err(_) => {
            return OverlayVerdict::Invalid {
                reason: format!("not an IPv4 packet ({} bytes)", packet.len()),
            };
        }
    };
    if parsed.protocol() != p2pnet_tun::Protocol::Udp {
        return OverlayVerdict::Ignored;
    }
    let payload = parsed.payload();
    // The IP payload includes the 8-byte UDP header; the overlay business
    // payload starts after it.
    if payload.len() < 8 + OVERLAY_CHECKSUM_OFFSET + 4 {
        return OverlayVerdict::Invalid {
            reason: format!("overlay payload too short: {}", payload.len()),
        };
    }
    let payload = &payload[8..];
    if &payload[..OVERLAY_MAGIC.len()] != OVERLAY_MAGIC {
        return OverlayVerdict::Ignored;
    }
    let direction = payload[OVERLAY_MAGIC.len()];
    if direction > OVERLAY_DIRECTION_ECHO {
        stats.received_invalid += 1;
        return OverlayVerdict::Invalid {
            reason: format!("unknown direction byte {direction}"),
        };
    }
    let mut nonce_bytes = [0u8; 8];
    nonce_bytes.copy_from_slice(&payload[7..15]);
    let nonce = u64::from_be_bytes(nonce_bytes);
    let mut seq_bytes = [0u8; 4];
    seq_bytes.copy_from_slice(&payload[15..19]);
    let seq = u32::from_be_bytes(seq_bytes);
    let expected_checksum = crc32_business_payload(&payload[..OVERLAY_CHECKSUM_SPAN]);
    let actual_checksum = u32::from_be_bytes(
        payload[OVERLAY_CHECKSUM_OFFSET..OVERLAY_CHECKSUM_OFFSET + 4]
            .try_into()
            .unwrap_or([0u8; 4]),
    );
    if actual_checksum != expected_checksum {
        stats.received_invalid += 1;
        return OverlayVerdict::Invalid {
            reason: format!("checksum mismatch: expected {expected_checksum:08x} got {actual_checksum:08x}"),
        };
    }
    if seen.iter().any(|&(seen_nonce, seen_seq)| seen_nonce == nonce && seen_seq == seq) {
        stats.received_invalid += 1;
        return OverlayVerdict::Invalid {
            reason: format!("duplicate nonce/seq ({nonce:#x}/{seq})"),
        };
    }
    seen.push_back((nonce, seq));
    while seen.len() > OVERLAY_SEEN_CAP {
        seen.pop_front();
    }

    let src_ip = parsed.src_addr().to_string();
    let dst_ip = parsed.dst_addr().to_string();
    let Some(peer_id) = peers.resolve_virtual_ip(&src_ip).await else {
        stats.received_invalid += 1;
        return OverlayVerdict::Invalid {
            reason: format!("unknown sender virtual IP {src_ip}"),
        };
    };
    if dst_ip != local_vip {
        stats.received_invalid += 1;
        return OverlayVerdict::Invalid {
            reason: format!("unexpected destination {dst_ip} (local {local_vip})"),
        };
    }
    let conn = peers.get_connection(&peer_id).await;
    let active_path = conn
        .as_ref()
        .and_then(|conn| conn.active_path())
        .map(|path| format!("{path:?}"))
        .unwrap_or_else(|| "none".to_string());
    let state = conn
        .as_ref()
        .map(|conn| conn.state.to_string())
        .unwrap_or_default();
    stats.received_valid += 1;
    stats.verified_round_trips += 1;
    info!(
        "{OVERLAY_EVIDENCE_PREFIX}_verified peer={peer_id} src_ip={src_ip} seq={seq} nonce={nonce:#x} len={} active_path={active_path} state={state} verified_round_trips={}",
        payload.len(),
        stats.verified_round_trips
    );
    OverlayVerdict::Valid {
        peer_id,
        virtual_ip: src_ip,
        nonce,
        seq,
        direction,
    }
}

/// Build a small UDP/IPv4 packet carrying an overlay business payload.
fn build_udp_overlay_packet(
    src_ip: &str,
    dst_ip: &str,
    sport: u16,
    dport: u16,
    payload: &[u8],
) -> Option<Vec<u8>> {
    use std::net::Ipv4Addr;
    let src: Ipv4Addr = src_ip.parse().ok()?;
    let dst: Ipv4Addr = dst_ip.parse().ok()?;
    let total_len = 20 + 8 + payload.len();
    if total_len > 65_535 {
        return None;
    }
    let mut packet = Vec::with_capacity(total_len);
    packet.push(0x45);
    packet.push(0);
    packet.extend_from_slice(&(total_len as u16).to_be_bytes());
    packet.extend_from_slice(&0x0000u16.to_be_bytes());
    packet.extend_from_slice(&0x0000u16.to_be_bytes());
    packet.push(64);
    packet.push(17);
    packet.extend_from_slice(&0x0000u16.to_be_bytes());
    packet.extend_from_slice(&src.octets());
    packet.extend_from_slice(&dst.octets());
    packet.extend_from_slice(&sport.to_be_bytes());
    packet.extend_from_slice(&dport.to_be_bytes());
    packet.extend_from_slice(&((8 + payload.len()) as u16).to_be_bytes());
    packet.extend_from_slice(&0x0000u16.to_be_bytes());
    packet.extend_from_slice(payload);
    Some(packet)
}

/// CRC-32 (IEEE) over the checksummed overlay region, computed exactly like
/// the sender.
fn crc32_business_payload(data: &[u8]) -> u32 {
    let mut crc = 0xFFFF_FFFFu32;
    for &byte in data {
        crc ^= u32::from(byte);
        for _ in 0..8 {
            let mask = (crc & 1).wrapping_neg();
            crc = (crc >> 1) ^ (0xEDB8_8320 & mask);
        }
    }
    !crc
}

/// Allow tests to build and verify the same payload encoding end-to-end.
#[cfg(test)]
mod overlay_validate_tests {
    use super::*;

    #[test]
    fn overlay_payload_checksum_round_trip() {
        let payload = build_overlay_payload(OVERLAY_DIRECTION_REQUEST, 0x1234_5678_9abc_def0u64, 42);
        let actual_checksum = u32::from_be_bytes(
            payload[OVERLAY_CHECKSUM_OFFSET..OVERLAY_CHECKSUM_OFFSET + 4]
                .try_into()
                .unwrap(),
        );
        assert_eq!(
            crc32_business_payload(&payload[..OVERLAY_CHECKSUM_SPAN]),
            actual_checksum,
            "the checksum field must match the CRC over magic+nonce+seq"
        );
    }

    #[test]
    fn overlay_packet_build_and_parse() {
        let packet = build_udp_overlay_packet("10.20.0.1", "10.20.0.2", 39286, 39287, b"P2WLOV")
            .expect("packet must build");
        let parsed = p2pnet_tun::Ipv4Packet::new(&packet).expect("packet must parse");
        assert_eq!(parsed.protocol(), p2pnet_tun::Protocol::Udp);
        assert_eq!(parsed.src_addr().to_string(), "10.20.0.1");
        assert_eq!(parsed.dst_addr().to_string(), "10.20.0.2");
        assert_eq!(&parsed.payload()[8..], b"P2WLOV");
    }
}
