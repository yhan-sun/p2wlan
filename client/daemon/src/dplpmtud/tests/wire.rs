use super::*;
use crate::transport::DirectValidationKind;
use std::net::Ipv4Addr;

#[test]
fn wire_format_vector_is_fixed_and_padding_follows_token() {
    let token = DplpmtudWireToken {
        sequence: 0x0102_0304_0506_0708,
        nonce: [
            0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d,
            0x1e, 0x1f,
        ],
        path_cookie: [
            0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d,
            0x2e, 0x2f,
        ],
        network_generation: 0x3132_3334_3536_3738,
        peer_session_generation: 0x4142_4344_4546_4748,
        remote_candidate_epoch: 0x5152_5354_5556_5758,
        direct_validation_owner_token: 0x6162_6364_6566_6768,
        direct_validation_request_id: 0x1234,
        candidate_udp_datagram_size: UdpDatagramSize(0x578),
        outer_ip_family: OuterIpFamily::Ipv4,
    };
    let mut encoded = Vec::new();
    encode_wire_token(&mut encoded, token);
    assert_eq!(
            hex::encode(&encoded),
            "0102030405060708101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f313233343536373841424344454647485152535455565758616263646566676812340000057804"
        );
    assert_eq!(decode_wire_token(&encoded), Some(token));

    let packet = build_probe_inner_packet(
        Ipv4Addr::new(10, 0, 0, 1),
        Ipv4Addr::new(10, 0, 0, 2),
        token,
    )
    .unwrap();
    let ip_packet = Ipv4Packet::new(&packet).unwrap();
    let icmp_payload = ip_packet.payload();
    let payload = &icmp_payload[8..];
    assert!(payload.starts_with(DPLPMTUD_PROBE_PREFIX));
    assert_eq!(
        &payload[DPLPMTUD_PROBE_PREFIX.len()..][..DPLPMTUD_TOKEN_BYTES],
        encoded.as_slice()
    );
    assert!(
        payload[DPLPMTUD_PROBE_PREFIX.len() + DPLPMTUD_TOKEN_BYTES..]
            .iter()
            .all(|byte| *byte == 0)
    );
}

#[test]
fn capability_extension_is_additive_and_legacy_packets_remain_decodable() {
    let prefix = crate::DIRECT_VALIDATION_REQUEST_PAYLOAD;
    let capability = direct_validation_capability_extension();
    let modern_payload = crate::transport::build_direct_validation_payload(
        DirectValidationKind::Request,
        7,
        9,
        1,
        11,
    );
    let modern_packet = Ipv4Packet::build_icmp_echo_request(
        Ipv4Addr::new(10, 20, 0, 1),
        Ipv4Addr::new(10, 20, 0, 2),
        9,
        1,
        &modern_payload,
    );
    assert!(crate::transport::parse_direct_validation_token(&modern_packet).is_some());
    assert!(direct_validation_supports_dplpmtud(&modern_packet));

    let mut legacy_payload = Vec::new();
    legacy_payload.extend_from_slice(prefix);
    legacy_payload.extend_from_slice(&modern_payload[prefix.len() + capability.len()..]);
    let legacy_packet = Ipv4Packet::build_icmp_echo_request(
        Ipv4Addr::new(10, 20, 0, 1),
        Ipv4Addr::new(10, 20, 0, 2),
        9,
        1,
        &legacy_payload,
    );
    assert!(crate::transport::parse_direct_validation_token(&legacy_packet).is_some());
    assert!(!direct_validation_supports_dplpmtud(&legacy_packet));

    let mut unknown_payload = modern_payload.clone();
    unknown_payload[prefix.len() + 4] = 99;
    let unknown_packet = Ipv4Packet::build_icmp_echo_request(
        Ipv4Addr::new(10, 20, 0, 1),
        Ipv4Addr::new(10, 20, 0, 2),
        9,
        1,
        &unknown_payload,
    );
    assert!(!direct_validation_supports_dplpmtud(&unknown_packet));
}

#[test]
fn codec_round_trip_uses_exact_udp_datagram_budget_and_compact_ack() {
    let token = DplpmtudWireToken {
        sequence: 7,
        nonce: [1; 16],
        path_cookie: [2; 16],
        network_generation: 3,
        peer_session_generation: 4,
        remote_candidate_epoch: 5,
        direct_validation_owner_token: 6,
        direct_validation_request_id: 7,
        candidate_udp_datagram_size: UdpDatagramSize(1400),
        outer_ip_family: OuterIpFamily::Ipv4,
    };
    let probe = build_probe_inner_packet(
        Ipv4Addr::new(10, 20, 0, 1),
        Ipv4Addr::new(10, 20, 0, 2),
        token,
    )
    .unwrap();
    assert_eq!(
        probe.len() + WIREGUARD_UDP_DATAGRAM_OVERHEAD as usize,
        token.candidate_udp_datagram_size.0 as usize
    );
    assert_eq!(parse_control_packet(&probe).unwrap().token, token);
    let ack = build_ack_inner_packet(
        Ipv4Addr::new(10, 20, 0, 2),
        Ipv4Addr::new(10, 20, 0, 1),
        token,
    );
    assert_eq!(
        parse_control_packet(&ack).unwrap(),
        DplpmtudControlPacket {
            kind: DplpmtudControlKind::Ack,
            token,
        }
    );
    assert!(ack.len() < probe.len());
    assert!(parse_control_packet(b"legacy-or-business-packet").is_none());
}
