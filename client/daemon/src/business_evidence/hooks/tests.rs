//! Constructed-byte controls call the production hooks. They do not claim
//! a real authentication, platform-device write, or lifecycle race occurred.

use super::*;
use std::time::Duration;

const PAYLOAD_BYTES: usize = 9;

fn key() -> OsUdpReqKey {
    OsUdpReqKey {
        run: [0x91; 16],
        round: [0x92; 16],
        sequence: 7,
        request_nonce: [0x93; 16],
        kind: RequestKind::Request,
    }
}

fn flow() -> RegisteredFlow {
    RegisteredFlow {
        src_v4: Ipv4Addr::new(10, 30, 0, 1),
        dst_v4: Ipv4Addr::new(10, 30, 0, 2),
        src_port: 43023,
        dst_port: 43123,
    }
}

fn checksum(bytes: &[u8]) -> u16 {
    let mut sum = bytes
        .chunks(2)
        .map(|chunk| {
            u32::from(u16::from_be_bytes([
                chunk[0],
                chunk.get(1).copied().unwrap_or(0),
            ]))
        })
        .sum::<u32>();
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

fn packet(key: OsUdpReqKey, flow: RegisteredFlow, payload_bytes: usize) -> Vec<u8> {
    let total = 28 + OS_UDP_HEADER_BYTES + payload_bytes;
    let mut raw = vec![0; total];
    raw[0] = 0x45;
    raw[2..4].copy_from_slice(&(total as u16).to_be_bytes());
    raw[6..8].copy_from_slice(&0x4000_u16.to_be_bytes());
    raw[8] = 64;
    raw[9] = 17;
    raw[12..16].copy_from_slice(&flow.src_v4.octets());
    raw[16..20].copy_from_slice(&flow.dst_v4.octets());
    raw[20..22].copy_from_slice(&flow.src_port.to_be_bytes());
    raw[22..24].copy_from_slice(&flow.dst_port.to_be_bytes());
    raw[24..26].copy_from_slice(&((total - 20) as u16).to_be_bytes());
    let body = &mut raw[28..];
    body[..8].copy_from_slice(b"P2WUDE1\0");
    body[8] = match key.kind {
        RequestKind::Request => 0,
        RequestKind::Response => 1,
    };
    body[9..25].copy_from_slice(&key.run);
    body[25..41].copy_from_slice(&key.round);
    body[41..45].copy_from_slice(&key.sequence.to_be_bytes());
    body[45..61].copy_from_slice(&key.request_nonce);
    body[61..63].copy_from_slice(&(payload_bytes as u16).to_be_bytes());
    body[63..].fill(0xa5);
    let ip_sum = checksum(&raw[..20]);
    raw[10..12].copy_from_slice(&ip_sum.to_be_bytes());
    let mut pseudo = Vec::with_capacity(12 + total - 20);
    pseudo.extend_from_slice(&raw[12..20]);
    pseudo.extend_from_slice(&[0, 17]);
    pseudo.extend_from_slice(&raw[24..26]);
    pseudo.extend_from_slice(&raw[20..]);
    let udp_sum = checksum(&pseudo);
    raw[26..28].copy_from_slice(&if udp_sum == 0 { u16::MAX } else { udp_sum }.to_be_bytes());
    raw
}

struct Fixture {
    owner: Arc<CaptureOwner>,
    raw: Vec<u8>,
    registered: RegisteredObservation,
    physical: PhysicalIngressContext,
    wire: WireTuple,
    wg_owner: WgEvidenceOwnerId,
    target: TunEvidenceIdentity,
}

impl Fixture {
    fn new() -> Self {
        let raw = packet(key(), flow(), PAYLOAD_BYTES);
        let parsed = parse_os_udp(&raw).unwrap();
        let owner = CaptureOwner::arm(
            CaptureScope {
                capture_id: [0xa1; 16],
                producer_scope: [0xa2; 16],
            },
            &["peer-a"],
            &[Registration {
                key: parsed.key,
                flow: parsed.flow,
                expected_payload_bytes: parsed.payload_bytes,
                peer_slot: 0,
            }],
            Duration::from_secs(10),
        )
        .unwrap();
        let registered = owner.lookup_registered(&raw, "peer-a").unwrap();
        let now = Instant::now();
        Self {
            owner,
            raw,
            registered,
            physical: PhysicalIngressContext::direct_udp(
                Some(4),
                NonZeroU64::new(11).unwrap(),
                0,
                SocketOwner::FixedPool { index: 0 },
                PublicationObservation::EnqueueObserved {
                    owner: NonZeroU64::new(13),
                },
                "127.0.0.1:44023".parse().unwrap(),
                "127.0.0.1:44123".parse().unwrap(),
                now,
                now,
            ),
            wire: WireTuple {
                receiver_index: 17,
                counter: 19,
                wire_len: 132,
            },
            wg_owner: WgEvidenceOwnerId::allocate(),
            target: TunEvidenceIdentity {
                instance: NonZeroU64::new(23).unwrap(),
                backend: TunBackend::MockDelivered,
            },
        }
    }

    fn authenticated(&self) -> Arc<AuthenticatedIngressContext> {
        self.owner
            .capture_authenticated(
                &self.raw,
                "peer-a",
                Some(&self.physical),
                self.wg_owner,
                Some(29),
                true,
                Some(self.wire),
                Instant::now(),
            )
            .unwrap()
    }

    fn snapshot(&self) -> SlotSnapshot {
        self.owner
            .try_read_registered(self.registered.slot())
            .unwrap()
    }
}

#[test]
fn hook_normalized_source_preserves_original_and_written_flows() {
    let fixture = Fixture::new();
    let authenticated = fixture.authenticated();
    let normalized_source = Ipv4Addr::new(10, 30, 1, 1);
    let normalized_flow = RegisteredFlow {
        src_v4: normalized_source,
        ..flow()
    };
    // This rebuild repairs both checksums; metadata alone cannot pass parsing.
    let normalized = packet(key(), normalized_flow, PAYLOAD_BYTES);
    assert_eq!(parse_os_udp(&normalized).unwrap().flow, normalized_flow);
    assert_eq!(
        fixture.owner.capture_tun_full(
            &authenticated,
            fixture.target,
            &normalized,
            normalized.len(),
            Some(normalized_source),
            Instant::now(),
        ),
        RecordDisposition::Stored
    );
    let snapshot = fixture.snapshot();
    let full = snapshot.tun_full.unwrap();
    assert_eq!(snapshot.authenticated, Some(*authenticated));
    assert_eq!(full.authenticated(), *authenticated);
    assert_eq!(
        full.authenticated().registered().registration().flow,
        flow()
    );
    assert_eq!(full.normalized_flow(), normalized_flow);
    assert_eq!(full.current_fence(), CurrentFence::Unknown);
    assert!(full.authenticated().auth_prev_session());
    assert!(!snapshot.ambiguous);
}

#[test]
fn hook_wrong_key_ports_payload_or_source_store_no_tun_receipt() {
    let fixture = Fixture::new();
    let authenticated = fixture.authenticated();
    let mut wrong_key = key();
    wrong_key.request_nonce[15] ^= 1;
    let wrong_port = RegisteredFlow {
        dst_port: 43124,
        ..flow()
    };
    let wrong_destination = RegisteredFlow {
        dst_v4: Ipv4Addr::new(10, 30, 0, 3),
        ..flow()
    };
    let wrong_source = RegisteredFlow {
        src_v4: Ipv4Addr::new(10, 30, 1, 1),
        ..flow()
    };
    let candidates = [
        packet(wrong_key, flow(), PAYLOAD_BYTES),
        packet(key(), wrong_port, PAYLOAD_BYTES),
        packet(key(), wrong_destination, PAYLOAD_BYTES),
        packet(key(), flow(), PAYLOAD_BYTES + 1),
        packet(key(), wrong_source, PAYLOAD_BYTES),
    ];
    for candidate in candidates {
        assert!(
            parse_os_udp(&candidate).is_ok(),
            "negative bytes have valid checksums"
        );
        assert_eq!(
            fixture.owner.capture_tun_full(
                &authenticated,
                fixture.target,
                &candidate,
                candidate.len(),
                None,
                Instant::now()
            ),
            RecordDisposition::FlowMismatch
        );
        let snapshot = fixture.snapshot();
        assert_eq!(snapshot.authenticated, Some(*authenticated));
        assert!(snapshot.tun_full.is_none());
        assert!(!snapshot.ambiguous);
    }
}

#[test]
fn hook_short_zero_overlong_or_malformed_write_has_typed_gap() {
    let fixture = Fixture::new();
    let authenticated = fixture.authenticated();
    for written in [0, fixture.raw.len() - 1, fixture.raw.len() + 1] {
        assert_eq!(
            fixture.owner.capture_tun_full(
                &authenticated,
                fixture.target,
                &fixture.raw,
                written,
                None,
                Instant::now()
            ),
            RecordDisposition::IdentityMissing
        );
        assert!(fixture.snapshot().tun_full.is_none());
    }
    let mut malformed = fixture.raw.clone();
    malformed[12] ^= 1; // The changed byte has deliberately unrepaired checksums.
    assert_eq!(
        fixture.owner.capture_tun_full(
            &authenticated,
            fixture.target,
            &malformed,
            malformed.len(),
            None,
            Instant::now()
        ),
        RecordDisposition::Malformed
    );
    assert_eq!(fixture.snapshot().authenticated, Some(*authenticated));
    assert!(fixture.snapshot().tun_full.is_none());
}

#[test]
fn hook_missing_auth_identity_remains_unknown_without_receipts() {
    let fixture = Fixture::new();
    for (physical, sid, wire) in [
        (None, Some(29), Some(fixture.wire)),
        (Some(&fixture.physical), None, Some(fixture.wire)),
        (Some(&fixture.physical), Some(29), None),
    ] {
        assert!(fixture
            .owner
            .capture_authenticated(
                &fixture.raw,
                "peer-a",
                physical,
                fixture.wg_owner,
                sid,
                false,
                wire,
                Instant::now()
            )
            .is_none());
    }
    let snapshot = fixture.snapshot();
    assert!(snapshot.authenticated.is_none());
    assert!(snapshot.tun_full.is_none());
    assert_eq!(
        fixture
            .owner
            .coverage()
            .count(RecordDisposition::IdentityMissing),
        3
    );
    // A failed observation did not unregister the original request.
    assert_eq!(
        fixture
            .owner
            .lookup_registered(&fixture.raw, "peer-a")
            .unwrap(),
        fixture.registered
    );
}
