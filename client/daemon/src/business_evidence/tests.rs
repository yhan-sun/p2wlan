//! Pure parser/recorder controls. Constructed contexts do not prove a socket
//! receive, WireGuard authentication, or a backend TUN delivery occurred.

use super::*;
use std::mem::size_of;
use std::sync::Arc;
use std::time::Duration;

const FILLER_BYTES: usize = 37;

fn scope() -> CaptureScope {
    CaptureScope {
        capture_id: [0x11; 16],
        producer_scope: [0x22; 16],
    }
}

fn request_key(sequence: u32) -> OsUdpReqKey {
    let mut request_nonce = [0x63; 16];
    request_nonce[12..].copy_from_slice(&sequence.to_be_bytes());
    OsUdpReqKey {
        run: [0x19; 16],
        round: [0x37; 16],
        sequence,
        request_nonce,
        kind: RequestKind::Request,
    }
}

fn flow() -> RegisteredFlow {
    RegisteredFlow {
        src_v4: Ipv4Addr::new(10, 21, 1, 2),
        dst_v4: Ipv4Addr::new(10, 21, 1, 3),
        src_port: 32123,
        dst_port: 43210,
    }
}

fn checksum(bytes: &[u8]) -> u16 {
    let mut sum = 0_u32;
    for chunk in bytes.chunks(2) {
        sum += u32::from(u16::from_be_bytes([
            chunk[0],
            chunk.get(1).copied().unwrap_or(0),
        ]));
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

fn udp_checksum(raw: &[u8]) -> u16 {
    let mut pseudo = Vec::with_capacity(12 + raw.len() - 20);
    pseudo.extend_from_slice(&raw[12..20]);
    pseudo.extend_from_slice(&[0, 17]);
    pseudo.extend_from_slice(&raw[24..26]);
    pseudo.extend_from_slice(&raw[20..]);
    checksum(&pseudo)
}

/// Complete IPv4 and UDP headers, including both checksums, and P2WUDE1 body.
fn ipv4_udp(key: OsUdpReqKey, flow: RegisteredFlow, filler_bytes: usize) -> Vec<u8> {
    let total = 28 + OS_UDP_HEADER_BYTES + filler_bytes;
    assert!(total <= usize::from(u16::MAX));
    let mut raw = vec![0; total];
    raw[0] = 0x45;
    raw[2..4].copy_from_slice(&(total as u16).to_be_bytes());
    raw[4..6].copy_from_slice(&0x1020_u16.to_be_bytes());
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
    body[61..63].copy_from_slice(&(filler_bytes as u16).to_be_bytes());
    body[63..].fill(0xa5);
    let ip_checksum = checksum(&raw[..20]);
    raw[10..12].copy_from_slice(&ip_checksum.to_be_bytes());
    let udp_checksum = udp_checksum(&raw);
    let encoded_checksum = if udp_checksum == 0 {
        u16::MAX
    } else {
        udp_checksum
    };
    raw[26..28].copy_from_slice(&encoded_checksum.to_be_bytes());
    raw
}

fn registration(raw: &[u8], peer_slot: u16) -> Registration {
    let parsed = parse_os_udp(raw).unwrap();
    Registration {
        key: parsed.key,
        flow: parsed.flow,
        expected_payload_bytes: parsed.payload_bytes,
        peer_slot,
    }
}

struct Fixture {
    owner: Arc<CaptureOwner>,
    raw: Vec<u8>,
    observed: RegisteredObservation,
}

impl Fixture {
    fn new() -> Self {
        let raw = ipv4_udp(request_key(7), flow(), FILLER_BYTES);
        let owner = CaptureOwner::arm(
            scope(),
            &["peer-a"],
            &[registration(&raw, 0)],
            Duration::from_secs(MAX_TTL_SECS),
        )
        .unwrap();
        let observed = owner.lookup_registered(&raw, "peer-a").unwrap();
        Self {
            owner,
            raw,
            observed,
        }
    }

    fn authenticated(&self, previous: bool) -> AuthenticatedIngressContext {
        let now = Instant::now();
        let physical = PhysicalIngressContext::direct_udp(
            None,
            NonZeroU64::new(11).unwrap(),
            2,
            SocketOwner::Unknown,
            PublicationObservation::Unknown,
            "198.51.100.7:40123".parse().unwrap(),
            "192.0.2.9:50123".parse().unwrap(),
            now,
            now,
        );
        AuthenticatedIngressContext::new(
            self.observed,
            physical,
            WgEvidenceOwnerId::allocate(),
            NonZeroU64::new(17).unwrap(),
            previous,
            WireTuple {
                receiver_index: 31,
                counter: 41,
                wire_len: (self.raw.len() + 32) as u32,
            },
            now,
        )
        .unwrap()
    }

    fn full(
        &self,
        authenticated: AuthenticatedIngressContext,
        current_fence: CurrentFence,
    ) -> TunFullReceipt {
        TunFullReceipt::new(
            authenticated,
            self.observed.registration().flow,
            self.raw.len() as u32,
            self.raw.len() as u32,
            TunEvidenceIdentity {
                instance: NonZeroU64::new(23).unwrap(),
                backend: TunBackend::Unknown,
            },
            Instant::now(),
            current_fence,
        )
        .unwrap()
    }
}

#[test]
fn pure_parser_preserves_all_128_bit_request_fields() {
    let key = request_key(0x10203040);
    let raw = ipv4_udp(key, flow(), FILLER_BYTES);
    assert_eq!(checksum(&raw[..20]), 0);
    assert_eq!(udp_checksum(&raw), 0);
    let parsed = parse_os_udp(&raw).unwrap();
    assert_eq!(parsed.key, key);
    assert_eq!(parsed.flow, flow());
    assert_eq!(parsed.payload_bytes, FILLER_BYTES as u16);
    assert_eq!(usize::from(parsed.ip_packet_len), raw.len());

    for field in 0..3 {
        let mut changed = key;
        match field {
            0 => changed.run[15] ^= 1,
            1 => changed.round[15] ^= 1,
            _ => changed.request_nonce[15] ^= 1,
        }
        let changed = parse_os_udp(&ipv4_udp(changed, flow(), FILLER_BYTES)).unwrap();
        assert_ne!(changed.key, parsed.key, "128-bit tail field {field}");
    }
}

#[test]
fn pure_parser_requires_valid_ip_and_present_udp_checksums() {
    let base = ipv4_udp(request_key(7), flow(), FILLER_BYTES);
    let mut bad_ip = base.clone();
    bad_ip[8] -= 1;
    assert_eq!(parse_os_udp(&bad_ip), Err(ParseErrorKind::Checksum));
    let mut bad_udp = base.clone();
    bad_udp[26] ^= 0x80;
    if bad_udp[26..28] == [0, 0] {
        bad_udp[27] = 1;
    }
    assert_eq!(parse_os_udp(&bad_udp), Err(ParseErrorKind::Checksum));
    let mut omitted_udp = base;
    omitted_udp[26..28].fill(0);
    assert!(
        parse_os_udp(&omitted_udp).is_ok(),
        "IPv4 permits no UDP checksum"
    );
}

#[test]
fn pure_response_reverse_flow_has_a_distinct_registered_slot() {
    let key = request_key(9);
    let request = ipv4_udp(key, flow(), FILLER_BYTES);
    let response = ipv4_udp(
        OsUdpReqKey {
            kind: RequestKind::Response,
            ..key
        },
        flow().reverse(),
        FILLER_BYTES,
    );
    let request_registration = registration(&request, 0);
    let response_registration = registration(&response, 0);
    assert_eq!(
        response_registration.flow,
        request_registration.flow.reverse()
    );
    assert_eq!(response_registration.key.kind, RequestKind::Response);
    assert_eq!(response_registration.key.request_nonce, key.request_nonce);
    let owner = CaptureOwner::arm(
        scope(),
        &["peer-a"],
        &[response_registration, request_registration],
        Duration::from_secs(MAX_TTL_SECS),
    )
    .unwrap();
    let request = owner.lookup_registered(&request, "peer-a").unwrap();
    let response = owner.lookup_registered(&response, "peer-a").unwrap();
    assert_ne!(request.slot(), response.slot());
    assert_eq!(request.registration(), request_registration);
    assert_eq!(response.registration(), response_registration);
    assert_eq!(
        owner
            .try_read_registered(response.slot())
            .unwrap()
            .registration,
        response_registration
    );
}

#[test]
fn pure_parser_rejects_fragment_length_magic_kind_and_filler_with_typed_errors() {
    let base = ipv4_udp(request_key(1), flow(), FILLER_BYTES);
    let mut cases = vec![("short-ip", vec![0; 27], ParseErrorKind::NotIpv4Udp)];
    for (name, offset, value, error) in [
        ("version", 0, 0x65, ParseErrorKind::NotIpv4Udp),
        ("protocol", 9, 6, ParseErrorKind::NotIpv4Udp),
        ("ihl", 0, 0x44, ParseErrorKind::Length),
        ("reserved", 6, 0x80, ParseErrorKind::Fragmented),
        ("more-fragments", 6, 0x20, ParseErrorKind::Fragmented),
        ("offset", 7, 1, ParseErrorKind::Fragmented),
        ("udp-length", 25, 1, ParseErrorKind::Length),
        ("body-length", 90, 1, ParseErrorKind::Length),
        ("magic", 28, 0, ParseErrorKind::Magic),
        ("kind", 36, 2, ParseErrorKind::Kind),
        ("filler", 91, 0, ParseErrorKind::Filler),
    ] {
        let mut raw = base.clone();
        raw[offset] = value;
        cases.push((name, raw, error));
    }
    let mut truncated = base.clone();
    truncated.pop();
    cases.push(("truncated", truncated, ParseErrorKind::Length));
    let mut trailing = base;
    trailing.push(0);
    cases.push(("trailing", trailing, ParseErrorKind::Length));
    cases.push((
        "oversized-body",
        ipv4_udp(
            request_key(1),
            flow(),
            MAX_OS_UDP_BYTES - OS_UDP_HEADER_BYTES + 1,
        ),
        ParseErrorKind::Length,
    ));
    for (name, raw, expected) in cases {
        assert_eq!(parse_os_udp(&raw), Err(expected), "{name}");
    }
    assert!(parse_os_udp(&ipv4_udp(request_key(1), flow(), 0)).is_ok());
    assert!(parse_os_udp(&ipv4_udp(
        request_key(1),
        flow(),
        MAX_OS_UDP_BYTES - OS_UDP_HEADER_BYTES,
    ))
    .is_ok());
}

#[test]
fn pure_lookup_requires_registered_key_flow_payload_and_peer() {
    let fixture = Fixture::new();
    let parsed = parse_os_udp(&fixture.raw).unwrap();
    let mut wrong_flow = parsed.flow;
    wrong_flow.src_port += 1;
    let mut malformed = fixture.raw.clone();
    malformed[36] = 2;
    for (raw, peer, expected) in [
        (
            ipv4_udp(request_key(8), parsed.flow, FILLER_BYTES),
            "peer-a",
            RecordDisposition::Unregistered,
        ),
        (
            ipv4_udp(parsed.key, wrong_flow, FILLER_BYTES),
            "peer-a",
            RecordDisposition::FlowMismatch,
        ),
        (
            ipv4_udp(parsed.key, parsed.flow, FILLER_BYTES + 1),
            "peer-a",
            RecordDisposition::FlowMismatch,
        ),
        (
            fixture.raw.clone(),
            "peer-b",
            RecordDisposition::PeerMismatch,
        ),
        (malformed, "peer-a", RecordDisposition::Malformed),
    ] {
        assert_eq!(fixture.owner.lookup_registered(&raw, peer), Err(expected));
    }
    let snapshot = fixture
        .owner
        .try_read_registered(fixture.observed.slot())
        .unwrap();
    assert_eq!(snapshot.authenticated, None);
    assert_eq!(snapshot.tun_full, None);
    assert!(!snapshot.ambiguous);
    let coverage = fixture.owner.coverage();
    assert_eq!(coverage.count(RecordDisposition::Unregistered), 1);
    assert_eq!(coverage.count(RecordDisposition::FlowMismatch), 2);
    assert_eq!(coverage.count(RecordDisposition::PeerMismatch), 1);
    assert_eq!(coverage.count(RecordDisposition::Malformed), 1);
    assert_eq!(coverage.count(RecordDisposition::Stored), 0);
    assert!(!coverage.overflow);
}

#[test]
fn pure_recorder_stores_and_reads_authentication_and_tun_as_distinct_stages() {
    let fixture = Fixture::new();
    let authenticated = fixture.authenticated(false);
    let before = fixture
        .owner
        .try_read_registered(fixture.observed.slot())
        .unwrap();
    assert_eq!(before.authenticated, None);
    assert_eq!(before.tun_full, None);
    assert_eq!(
        fixture
            .owner
            .try_record(StageReceipt::AuthenticatedReceive(authenticated)),
        RecordDisposition::Stored
    );
    let after_auth = fixture
        .owner
        .try_read_registered(fixture.observed.slot())
        .unwrap();
    assert_eq!(after_auth.authenticated, Some(authenticated));
    assert_eq!(after_auth.tun_full, None);
    let full = fixture.full(authenticated, CurrentFence::Current);
    assert_eq!(
        fixture.owner.try_record(StageReceipt::TunWriteFull(full)),
        RecordDisposition::Stored
    );
    let complete = fixture
        .owner
        .try_read_registered(fixture.observed.slot())
        .unwrap();
    assert_eq!(complete.registration, fixture.observed.registration());
    assert_eq!(complete.authenticated, Some(authenticated));
    assert_eq!(complete.tun_full, Some(full));
    assert!(!complete.ambiguous);
    assert_eq!(fixture.owner.coverage().count(RecordDisposition::Stored), 2);
}

#[test]
fn pure_duplicate_and_conflict_preserve_first_receipts_and_mark_ambiguity() {
    let fixture = Fixture::new();
    let authenticated = fixture.authenticated(false);
    let full = fixture.full(authenticated, CurrentFence::Current);
    for receipt in [
        StageReceipt::AuthenticatedReceive(authenticated),
        StageReceipt::TunWriteFull(full),
    ] {
        assert_eq!(fixture.owner.try_record(receipt), RecordDisposition::Stored);
        assert_eq!(
            fixture.owner.try_record(receipt),
            RecordDisposition::DuplicateSameIdentity
        );
    }
    let mut different_wire = authenticated.wire();
    different_wire.counter += 1;
    let conflicting_auth = AuthenticatedIngressContext::new(
        fixture.observed,
        authenticated.physical(),
        authenticated.wg_owner(),
        authenticated.session_instance(),
        authenticated.auth_prev_session(),
        different_wire,
        authenticated.authenticated_at,
    )
    .unwrap();
    let conflicting_tun = TunFullReceipt::new(
        authenticated,
        full.normalized_flow(),
        fixture.raw.len() as u32,
        full.written(),
        TunEvidenceIdentity {
            instance: NonZeroU64::new(24).unwrap(),
            backend: TunBackend::Unknown,
        },
        Instant::now(),
        CurrentFence::Current,
    )
    .unwrap();
    assert_eq!(
        fixture
            .owner
            .try_record(StageReceipt::AuthenticatedReceive(conflicting_auth)),
        RecordDisposition::Conflict
    );
    assert_eq!(
        fixture
            .owner
            .try_record(StageReceipt::TunWriteFull(conflicting_tun)),
        RecordDisposition::Conflict
    );
    let snapshot = fixture
        .owner
        .try_read_registered(fixture.observed.slot())
        .unwrap();
    assert_eq!(snapshot.authenticated, Some(authenticated));
    assert_eq!(snapshot.tun_full, Some(full));
    assert!(snapshot.ambiguous);
    let coverage = fixture.owner.coverage();
    assert_eq!(coverage.count(RecordDisposition::Stored), 2);
    assert_eq!(coverage.count(RecordDisposition::DuplicateSameIdentity), 2);
    assert_eq!(coverage.count(RecordDisposition::Conflict), 2);
    assert!(!coverage.overflow);
}

#[test]
fn pure_cross_stage_context_conflict_cannot_join_different_authenticated_identity() {
    let fixture = Fixture::new();
    let authenticated = fixture.authenticated(false);
    assert_eq!(
        fixture
            .owner
            .try_record(StageReceipt::AuthenticatedReceive(authenticated)),
        RecordDisposition::Stored
    );
    let mut different_wire = authenticated.wire();
    different_wire.counter += 1;
    // Both contexts are pure fixtures; constructing one performs no actual
    // authentication or TUN write and cannot join distinct wire identities.
    let tun_authenticated = AuthenticatedIngressContext::new(
        fixture.observed,
        authenticated.physical(),
        authenticated.wg_owner(),
        authenticated.session_instance(),
        authenticated.auth_prev_session(),
        different_wire,
        authenticated.authenticated_at,
    )
    .unwrap();
    let full = fixture.full(tun_authenticated, CurrentFence::Current);
    assert_eq!(
        fixture.owner.try_record(StageReceipt::TunWriteFull(full)),
        RecordDisposition::Conflict
    );
    let snapshot = fixture
        .owner
        .try_read_registered(fixture.observed.slot())
        .unwrap();
    assert_eq!(snapshot.authenticated, Some(authenticated));
    assert_eq!(snapshot.tun_full, Some(full));
    assert_eq!(
        snapshot.tun_full.unwrap().authenticated(),
        tun_authenticated
    );
    assert_ne!(authenticated, tun_authenticated);
    assert!(snapshot.ambiguous);
    let coverage = fixture.owner.coverage();
    assert_eq!(coverage.count(RecordDisposition::Stored), 1);
    assert_eq!(coverage.count(RecordDisposition::Conflict), 1);
    assert_eq!(coverage.count(RecordDisposition::DuplicateSameIdentity), 0);
    assert!(!coverage.overflow);
}

#[test]
fn pure_unknown_fence_and_previous_session_remain_historical_markers() {
    let fixture = Fixture::new();
    let authenticated = fixture.authenticated(true);
    let full = fixture.full(authenticated, CurrentFence::Unknown);
    assert_eq!(
        fixture
            .owner
            .try_record(StageReceipt::AuthenticatedReceive(authenticated)),
        RecordDisposition::Stored
    );
    assert_eq!(
        fixture.owner.try_record(StageReceipt::TunWriteFull(full)),
        RecordDisposition::Stored
    );
    let snapshot = fixture
        .owner
        .try_read_registered(fixture.observed.slot())
        .unwrap();
    let context = snapshot.authenticated.unwrap();
    assert!(context.auth_prev_session());
    assert_eq!(context.physical().network_generation, None);
    assert_eq!(context.physical().socket_owner, SocketOwner::Unknown);
    assert_eq!(
        context.physical().publication(),
        PublicationObservation::Unknown
    );
    assert_eq!(
        snapshot.tun_full.unwrap().current_fence(),
        CurrentFence::Unknown
    );
    assert_eq!(
        snapshot.tun_full.unwrap().target().backend,
        TunBackend::Unknown
    );
    assert!(!snapshot.ambiguous);
}

#[test]
fn pure_short_or_zero_tun_write_constructs_no_full_receipt() {
    let fixture = Fixture::new();
    let authenticated = fixture.authenticated(false);
    assert_eq!(
        fixture
            .owner
            .try_record(StageReceipt::AuthenticatedReceive(authenticated)),
        RecordDisposition::Stored
    );
    let len = fixture.raw.len() as u32;
    for (normalized_len, written) in [(0, 0), (len, 0), (len, len - 1), (len, len + 1)] {
        assert_eq!(
            TunFullReceipt::new(
                authenticated,
                fixture.observed.registration().flow,
                normalized_len,
                written,
                TunEvidenceIdentity {
                    instance: NonZeroU64::new(23).unwrap(),
                    backend: TunBackend::Unknown,
                },
                Instant::now(),
                CurrentFence::Current,
            ),
            None
        );
    }
    let snapshot = fixture
        .owner
        .try_read_registered(fixture.observed.slot())
        .unwrap();
    assert_eq!(snapshot.authenticated, Some(authenticated));
    assert_eq!(snapshot.tun_full, None);
    assert_eq!(fixture.owner.coverage().count(RecordDisposition::Stored), 1);
}

#[test]
fn pure_receipts_and_slot_refs_cannot_cross_capture_scope() {
    let fixture = Fixture::new();
    let mut other_scope = scope();
    other_scope.capture_id[15] ^= 1;
    let other = CaptureOwner::arm(
        other_scope,
        &["peer-a"],
        &[registration(&fixture.raw, 0)],
        Duration::from_secs(MAX_TTL_SECS),
    )
    .unwrap();
    assert_eq!(
        other.try_record(StageReceipt::AuthenticatedReceive(
            fixture.authenticated(false)
        )),
        RecordDisposition::Unregistered
    );
    assert_eq!(
        other.try_read_registered(fixture.observed.slot()),
        Err(SnapshotDisposition::Unregistered)
    );
    let other_observed = other.lookup_registered(&fixture.raw, "peer-a").unwrap();
    let snapshot = other.try_read_registered(other_observed.slot()).unwrap();
    assert_eq!(snapshot.authenticated, None);
    assert_eq!(snapshot.tun_full, None);
    assert!(!snapshot.ambiguous);
    assert_eq!(other.coverage().count(RecordDisposition::Unregistered), 1);
}

fn assert_arm_error(peers: &[&str], registrations: &[Registration], expected: ArmError) {
    assert_eq!(
        CaptureOwner::arm(
            scope(),
            peers,
            registrations,
            Duration::from_secs(MAX_TTL_SECS),
        )
        .err(),
        Some(expected)
    );
}

#[test]
fn pure_arm_rejects_invalid_peers_registrations_and_incompatible_plans() {
    let first = registration(&ipv4_udp(request_key(7), flow(), FILLER_BYTES), 0);
    assert_arm_error(&[], &[first], ArmError::Empty);
    assert_arm_error(&["peer-a"], &[], ArmError::Empty);
    assert_arm_error(&[""], &[first], ArmError::Peer);
    assert_arm_error(&["peer-a", "peer-a"], &[first], ArmError::Peer);
    let too_long_peer = "p".repeat(MAX_PEER_ID_BYTES + 1);
    assert_arm_error(&[too_long_peer.as_str()], &[first], ArmError::Peer);
    assert_arm_error(&["peer-a"], &[first, first], ArmError::DuplicateKey);
    for invalid in [
        Registration {
            peer_slot: 1,
            ..first
        },
        Registration {
            expected_payload_bytes: (MAX_OS_UDP_BYTES - OS_UDP_HEADER_BYTES + 1) as u16,
            ..first
        },
        Registration {
            flow: RegisteredFlow {
                src_port: 0,
                ..first.flow
            },
            ..first
        },
        Registration {
            flow: RegisteredFlow {
                dst_port: 0,
                ..first.flow
            },
            ..first
        },
        Registration {
            flow: RegisteredFlow {
                src_v4: Ipv4Addr::UNSPECIFIED,
                ..first.flow
            },
            ..first
        },
        Registration {
            flow: RegisteredFlow {
                dst_v4: Ipv4Addr::new(224, 0, 0, 1),
                ..first.flow
            },
            ..first
        },
        Registration {
            flow: RegisteredFlow {
                src_v4: Ipv4Addr::BROADCAST,
                ..first.flow
            },
            ..first
        },
    ] {
        assert_arm_error(&["peer-a"], &[invalid], ArmError::Registration);
    }
    let mut different_run = first;
    different_run.key.run[15] ^= 1;
    let mut different_round = first;
    different_round.key.round[15] ^= 1;
    let mut response = first;
    response.key.kind = RequestKind::Response;
    response.flow = first.flow.reverse();
    let mut different_nonce = response;
    different_nonce.key.request_nonce[15] ^= 1;
    for incompatible in [
        different_run,
        different_round,
        different_nonce,
        Registration {
            flow: first.flow,
            ..response
        },
        Registration {
            peer_slot: 1,
            ..response
        },
        Registration {
            expected_payload_bytes: first.expected_payload_bytes + 1,
            ..response
        },
    ] {
        assert_arm_error(
            &["peer-a", "peer-b"],
            &[first, incompatible],
            ArmError::IncompatiblePlan,
        );
    }
    assert_arm_error(
        &["peer-a"],
        &[first, response, response],
        ArmError::DuplicateKey,
    );
}

#[test]
fn pure_ttl_bounds_and_disarm_close_existing_owner_without_new_evidence() {
    let fixture = Fixture::new();
    let registration = fixture.observed.registration();
    for ttl in [
        Duration::ZERO,
        Duration::from_millis(999),
        Duration::from_secs(MAX_TTL_SECS) + Duration::from_nanos(1),
    ] {
        assert_eq!(
            CaptureOwner::arm(scope(), &["peer-a"], &[registration], ttl).err(),
            Some(ArmError::Ttl)
        );
    }
    for ttl in [Duration::from_secs(1), Duration::from_secs(MAX_TTL_SECS)] {
        assert!(CaptureOwner::arm(scope(), &["peer-a"], &[registration], ttl).is_ok());
    }
    let authenticated = fixture.authenticated(false);
    assert_eq!(
        fixture
            .owner
            .try_record(StageReceipt::AuthenticatedReceive(authenticated)),
        RecordDisposition::Stored
    );
    assert_eq!(fixture.owner.disarm(), RecordDisposition::Disabled);
    assert_eq!(
        fixture.owner.lookup_registered(&fixture.raw, "peer-a"),
        Err(RecordDisposition::Disabled)
    );
    assert_eq!(
        fixture
            .owner
            .try_record(StageReceipt::AuthenticatedReceive(authenticated)),
        RecordDisposition::Disabled
    );
    assert_eq!(
        fixture.owner.try_read_registered(fixture.observed.slot()),
        Err(SnapshotDisposition::Disabled)
    );
    assert_eq!(fixture.owner.seal_expired(), RecordDisposition::Disabled);
    let coverage = fixture.owner.coverage();
    assert_eq!(coverage.count(RecordDisposition::Stored), 1);
    assert_eq!(coverage.count(RecordDisposition::Disabled), 4);
    assert!(!coverage.overflow);
}

#[test]
fn pure_maximum_plan_has_2000_real_slots_with_bounded_contexts_and_carriers() {
    assert_eq!(MAX_REQUESTS, 1000);
    assert_eq!(MAX_SLOTS, 2000);
    assert_eq!(MAX_CONTEXT_BYTES, 512);
    assert!(size_of::<PhysicalIngressContext>() <= MAX_CONTEXT_BYTES);
    assert!(size_of::<AuthenticatedIngressContext>() <= MAX_CONTEXT_BYTES);
    assert!(size_of::<TunFullReceipt>() <= MAX_CONTEXT_BYTES);
    assert!(size_of::<SlotSnapshot>() <= MAX_SLOT_BYTES);
    assert!(
        MAX_SLOTS * MAX_SLOT_BYTES
            + MAX_PEERS * (MAX_PEER_ID_BYTES + size_of::<u16>())
            + size_of::<CaptureOwner>()
            <= MAX_CAPTURE_BYTES
    );
    assert_eq!(
        size_of::<Option<Arc<PhysicalIngressContext>>>(),
        size_of::<usize>()
    );
    assert_eq!(
        size_of::<Option<Arc<AuthenticatedIngressContext>>>(),
        size_of::<usize>()
    );
    assert!(size_of::<crate::transport::ReceivedEncryptedPacket>() <= 1024);
    assert!(size_of::<crate::dataplane::InboundPacket>() <= 512);
    let disabled_physical: Option<Arc<PhysicalIngressContext>> = None;
    let disabled_authenticated: Option<Arc<AuthenticatedIngressContext>> = None;
    assert!(disabled_physical.is_none());
    assert!(disabled_authenticated.is_none());

    let mut registrations = Vec::with_capacity(MAX_SLOTS);
    for sequence in 0..MAX_REQUESTS as u32 {
        let key = request_key(sequence);
        registrations.push(registration(&ipv4_udp(key, flow(), 0), 0));
        registrations.push(registration(
            &ipv4_udp(
                OsUdpReqKey {
                    kind: RequestKind::Response,
                    ..key
                },
                flow().reverse(),
                0,
            ),
            0,
        ));
    }
    assert_eq!(registrations.len(), MAX_SLOTS);
    let owner = CaptureOwner::arm(
        scope(),
        &["peer-a"],
        &registrations,
        Duration::from_secs(MAX_TTL_SECS),
    )
    .unwrap();
    for expected in &registrations {
        let raw = ipv4_udp(expected.key, expected.flow, 0);
        let observed = owner.lookup_registered(&raw, "peer-a").unwrap();
        let snapshot = owner.try_read_registered(observed.slot()).unwrap();
        assert_eq!(snapshot.registration, *expected);
        assert_eq!(snapshot.authenticated, None);
        assert_eq!(snapshot.tun_full, None);
        assert!(!snapshot.ambiguous);
    }
    let mut too_many_slots = registrations.clone();
    too_many_slots.push(registrations[0]);
    assert_arm_error(&["peer-a"], &too_many_slots, ArmError::Capacity);
    let too_many_requests = (0..=MAX_REQUESTS as u32)
        .map(|sequence| registration(&ipv4_udp(request_key(sequence), flow(), 0), 0))
        .collect::<Vec<_>>();
    assert_arm_error(&["peer-a"], &too_many_requests, ArmError::Capacity);
    let too_many_peers = vec!["peer-a"; MAX_PEERS + 1];
    assert_arm_error(&too_many_peers, &registrations[..1], ArmError::Capacity);
    assert_eq!(owner.coverage().count(RecordDisposition::Stored), 0);
    assert!(!owner.coverage().overflow);
}
