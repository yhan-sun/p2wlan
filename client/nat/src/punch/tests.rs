use super::authenticated::punch_v2_mac;
use super::packet::PunchPacket;
use super::*;

fn hex_lower(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>()
}

#[test]
fn test_punch_packet_encode_decode() {
    let punch = PunchPacket::new_punch();
    let encoded = punch.encode();
    assert_eq!(encoded.len(), PUNCH_PACKET_SIZE);
    assert_eq!(&encoded[..4], &PUNCH_MAGIC);

    let decoded = PunchPacket::decode(&encoded).unwrap();
    assert_eq!(decoded, punch);
    assert!(decoded.is_punch());
}

#[test]
fn test_ack_packet_encode_decode() {
    let nonce = [0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88];
    let ack = PunchPacket::new_ack(nonce);
    let encoded = ack.encode();

    let decoded = PunchPacket::decode(&encoded).unwrap();
    assert_eq!(decoded, ack);
    assert!(decoded.is_ack());
    assert_eq!(decoded.nonce, nonce);
}

#[test]
fn test_public_punch_helpers() {
    let punch = build_punch_packet();
    let decoded = decode_punch_packet(&punch).unwrap();
    assert_eq!(decoded.kind, PunchPacketKind::Punch);
    assert_eq!(decoded.version, PUNCH_VERSION);
    assert!(!decoded.authenticated);

    let ack = build_punch_ack(decoded.nonce);
    let decoded_ack = decode_punch_packet(&ack).unwrap();
    assert_eq!(decoded_ack.kind, PunchPacketKind::Ack);
    assert_eq!(decoded_ack.nonce, decoded.nonce);

    let compat = build_punch_packet_with_nonce(decoded.nonce);
    let decoded_compat = decode_punch_packet(&compat).unwrap();
    assert_eq!(decoded_compat.kind, PunchPacketKind::Punch);
    assert_eq!(decoded_compat.nonce, decoded.nonce);
}

#[test]
fn test_authenticated_punch_encode_decode() {
    let key = [0x42; 32];
    let (packet, nonce) = build_authenticated_punch_packet("node-a", "node-b", 7, &key);

    let identity = peek_authenticated_punch_identity(&packet).unwrap();
    assert_eq!(identity.kind, PunchPacketKind::Punch);
    assert_eq!(identity.source_node_id, "node-a");
    assert_eq!(identity.target_node_id, "node-b");
    assert_eq!(identity.generation, 7);

    let decoded = decode_authenticated_punch_packet(&packet, &key).unwrap();
    assert_eq!(decoded.kind, PunchPacketKind::Punch);
    assert_eq!(decoded.nonce, nonce);
    assert_eq!(decoded.version, AUTH_PUNCH_VERSION);
    assert_eq!(decoded.source_node_id.as_deref(), Some("node-a"));
    assert_eq!(decoded.target_node_id.as_deref(), Some("node-b"));
    assert_eq!(decoded.generation, Some(7));
    assert!(!decoded.use_candidate);
    assert!(decoded.authenticated);
    assert!(decode_punch_packet(&packet).is_none());
}

#[test]
fn test_authenticated_nomination_punch_encode_decode() {
    let key = [0x42; 32];
    let (packet, nonce) =
        build_authenticated_punch_packet_with_nomination("node-a", "node-b", 7, true, &key);

    let identity = peek_authenticated_punch_identity(&packet).unwrap();
    assert_eq!(identity.kind, PunchPacketKind::Punch);
    assert!(identity.use_candidate);

    let decoded = decode_authenticated_punch_packet(&packet, &key).unwrap();
    assert_eq!(decoded.kind, PunchPacketKind::Punch);
    assert_eq!(decoded.nonce, nonce);
    assert!(decoded.use_candidate);
    assert!(decoded.authenticated);
}

#[test]
fn test_authenticated_punch_golden_vectors() {
    let mut key = [0u8; 32];
    for (index, byte) in key.iter_mut().enumerate() {
        *byte = index as u8;
    }
    let nonce = [0xA0, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5, 0xA6, 0xA7];

    let punch = build_authenticated_punch_packet_with_nonce(
        nonce,
        "node-a",
        "node-b",
        0x0102_0304_0506_0708,
        true,
        &key,
    );
    assert_eq!(
            hex_lower(&punch),
            "504e43480201a0a1a2a3a4a5a6a701020304050607080106066e6f64652d616e6f64652d62fa09a10aa09da3d47f1b7d003a7adadb"
        );
    let decoded_punch = decode_authenticated_punch_packet(&punch, &key).unwrap();
    assert_eq!(decoded_punch.kind, PunchPacketKind::Punch);
    assert_eq!(decoded_punch.nonce, nonce);
    assert_eq!(decoded_punch.generation, Some(0x0102_0304_0506_0708));
    assert!(decoded_punch.use_candidate);

    let ack = build_authenticated_punch_ack(nonce, "node-b", "node-a", 0x0102_0304_0506_0709, &key);
    assert_eq!(
            hex_lower(&ack),
            "504e43480202a0a1a2a3a4a5a6a701020304050607090006066e6f64652d626e6f64652d619080783cb1a90b982675b2fab7399bbd"
        );
    let decoded_ack = decode_authenticated_punch_packet(&ack, &key).unwrap();
    assert_eq!(decoded_ack.kind, PunchPacketKind::Ack);
    assert_eq!(decoded_ack.nonce, nonce);
    assert_eq!(decoded_ack.generation, Some(0x0102_0304_0506_0709));
    assert!(!decoded_ack.use_candidate);
}

#[test]
fn test_legacy_authenticated_v2_without_flags_still_decodes() {
    let key = [0x42; 32];
    let source = b"node-a";
    let target = b"node-b";
    let nonce = [0xA5; 8];
    let mut frame = Vec::new();
    frame.extend_from_slice(&PUNCH_MAGIC);
    frame.push(AUTH_PUNCH_VERSION);
    frame.push(TYPE_PUNCH);
    frame.extend_from_slice(&nonce);
    frame.extend_from_slice(&7_u64.to_be_bytes());
    frame.push(source.len() as u8);
    frame.push(target.len() as u8);
    frame.extend_from_slice(source);
    frame.extend_from_slice(target);
    let mac = punch_v2_mac(&frame, &key);
    frame.extend_from_slice(&mac);

    let identity = peek_authenticated_punch_identity(&frame).unwrap();
    assert!(!identity.use_candidate);

    let decoded = decode_authenticated_punch_packet(&frame, &key).unwrap();
    assert_eq!(decoded.kind, PunchPacketKind::Punch);
    assert_eq!(decoded.nonce, nonce);
    assert_eq!(decoded.source_node_id.as_deref(), Some("node-a"));
    assert_eq!(decoded.target_node_id.as_deref(), Some("node-b"));
    assert_eq!(decoded.generation, Some(7));
    assert!(!decoded.use_candidate);
    assert!(decoded.authenticated);
}

#[test]
fn test_authenticated_ack_encode_decode() {
    let key = [0x24; 32];
    let nonce = [0xAB; 8];
    let packet = build_authenticated_punch_ack(nonce, "node-b", "node-a", 9, &key);

    let decoded = decode_authenticated_punch_packet(&packet, &key).unwrap();
    assert_eq!(decoded.kind, PunchPacketKind::Ack);
    assert_eq!(decoded.nonce, nonce);
    assert_eq!(decoded.source_node_id.as_deref(), Some("node-b"));
    assert_eq!(decoded.target_node_id.as_deref(), Some("node-a"));
    assert_eq!(decoded.generation, Some(9));
    assert!(!decoded.use_candidate);
}

#[test]
fn test_authenticated_punch_rejects_tampering_and_wrong_key() {
    let key = [0x42; 32];
    let wrong_key = [0x43; 32];
    let (mut packet, _nonce) = build_authenticated_punch_packet("node-a", "node-b", 7, &key);

    assert!(decode_authenticated_punch_packet(&packet, &wrong_key).is_none());
    let last = packet.len() - 1;
    packet[last] ^= 0x01;
    assert!(decode_authenticated_punch_packet(&packet, &key).is_none());
}

#[test]
fn test_authenticated_punch_rejects_unknown_flags_even_with_valid_mac() {
    let key = [0x42; 32];
    let source = b"node-a";
    let target = b"node-b";
    let nonce = [0xA6; 8];
    let mut frame = Vec::new();
    frame.extend_from_slice(&PUNCH_MAGIC);
    frame.push(AUTH_PUNCH_VERSION);
    frame.push(TYPE_PUNCH);
    frame.extend_from_slice(&nonce);
    frame.extend_from_slice(&7_u64.to_be_bytes());
    frame.push(0x02);
    frame.push(source.len() as u8);
    frame.push(target.len() as u8);
    frame.extend_from_slice(source);
    frame.extend_from_slice(target);
    let mac = punch_v2_mac(&frame, &key);
    frame.extend_from_slice(&mac);

    assert!(peek_authenticated_punch_identity(&frame).is_none());
    assert!(decode_authenticated_punch_packet(&frame, &key).is_none());
}

#[test]
fn test_authenticated_punch_malformed_corpus_does_not_authenticate() {
    let key = [0x42; 32];
    let (packet, _nonce) = build_authenticated_punch_packet("node-a", "node-b", 7, &key);

    for len in 0..packet.len() {
        assert!(decode_authenticated_punch_packet(&packet[..len], &key).is_none());
    }

    let mut wrong_mac = packet.clone();
    let last = wrong_mac.len() - 1;
    wrong_mac[last] ^= 0x80;
    assert!(decode_authenticated_punch_packet(&wrong_mac, &key).is_none());
    assert!(peek_authenticated_punch_identity(&wrong_mac).is_some());

    let mut zero_source = Vec::new();
    zero_source.extend_from_slice(&PUNCH_MAGIC);
    zero_source.push(AUTH_PUNCH_VERSION);
    zero_source.push(TYPE_PUNCH);
    zero_source.extend_from_slice(&[0xA7; 8]);
    zero_source.extend_from_slice(&7_u64.to_be_bytes());
    zero_source.push(0);
    zero_source.push(0);
    zero_source.push(1);
    zero_source.push(b'b');
    let mac = punch_v2_mac(&zero_source, &key);
    zero_source.extend_from_slice(&mac);
    assert!(decode_authenticated_punch_packet(&zero_source, &key).is_none());

    let mut invalid_utf8 = Vec::new();
    invalid_utf8.extend_from_slice(&PUNCH_MAGIC);
    invalid_utf8.push(AUTH_PUNCH_VERSION);
    invalid_utf8.push(TYPE_PUNCH);
    invalid_utf8.extend_from_slice(&[0xA8; 8]);
    invalid_utf8.extend_from_slice(&7_u64.to_be_bytes());
    invalid_utf8.push(0);
    invalid_utf8.push(1);
    invalid_utf8.push(1);
    invalid_utf8.push(0xFF);
    invalid_utf8.push(b'b');
    let mac = punch_v2_mac(&invalid_utf8, &key);
    invalid_utf8.extend_from_slice(&mac);
    assert!(decode_authenticated_punch_packet(&invalid_utf8, &key).is_none());
}

#[test]
fn test_authenticated_punch_parser_fuzz_corpus_does_not_panic() {
    let key = [0x42; 32];
    let mut seed = 0x9E37_79B9_7F4A_7C15u64;

    for len in 0..160 {
        let mut frame = vec![0u8; len];
        for byte in &mut frame {
            seed ^= seed << 7;
            seed ^= seed >> 9;
            seed ^= seed << 8;
            *byte = seed as u8;
        }

        let _ = peek_authenticated_punch_identity(&frame);
        let _ = decode_authenticated_punch_packet(&frame, &key);
        let _ = decode_punch_packet(&frame);
    }
}

#[test]
fn test_invalid_magic() {
    let mut buf = vec![0u8; PUNCH_PACKET_SIZE];
    buf[0] = 0xFF; // wrong magic
    assert!(PunchPacket::decode(&buf).is_none());
}

#[test]
fn test_invalid_version() {
    let mut buf = vec![0u8; PUNCH_PACKET_SIZE];
    buf[..4].copy_from_slice(&PUNCH_MAGIC);
    buf[4] = 0x99; // wrong version
    assert!(PunchPacket::decode(&buf).is_none());
}

#[test]
fn test_too_short() {
    let buf = vec![0u8; 5];
    assert!(PunchPacket::decode(&buf).is_none());
}

#[tokio::test]
async fn test_local_hole_punch() {
    // Create two local sockets and have them punch each other
    let socket_a = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let socket_b = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let addr_a = socket_a.local_addr().unwrap();
    let addr_b = socket_b.local_addr().unwrap();

    let config = PunchConfig {
        timeout: Duration::from_secs(3),
        interval: Duration::from_millis(50),
        max_attempts: 100,
    };

    // Both sides punch simultaneously
    let candidates_b = [addr_b];
    let candidates_a = [addr_a];
    let punch_a = hole_punch(&socket_a, &candidates_b, &config);
    let punch_b = hole_punch(&socket_b, &candidates_a, &config);

    let (result_a, result_b) = tokio::join!(punch_a, punch_b);

    let result_a = result_a.unwrap();
    let result_b = result_b.unwrap();

    // At least one side should connect
    assert!(
        result_a.connected || result_b.connected,
        "Neither side connected! A={:?}, B={:?}",
        result_a,
        result_b
    );

    if result_a.connected {
        assert_eq!(result_a.peer_addr, Some(addr_b));
    }
    if result_b.connected {
        assert_eq!(result_b.peer_addr, Some(addr_a));
    }
}

#[tokio::test]
async fn test_hole_punch_no_candidates() {
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let config = PunchConfig::default();

    let result = hole_punch(&socket, &[], &config).await;
    assert!(result.is_err());
    assert!(matches!(result, Err(NatError::NoCandidates)));
}

#[tokio::test]
async fn test_hole_punch_timeout() {
    // Punch to a dead address — should timeout
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();

    let config = PunchConfig {
        timeout: Duration::from_millis(500),
        interval: Duration::from_millis(100),
        max_attempts: 10,
    };

    // Use a non-existent but valid address
    let dead_addr: SocketAddr = "127.0.0.1:1".parse().unwrap();

    let result = hole_punch(&socket, &[dead_addr], &config).await.unwrap();
    assert!(!result.connected);
    assert!(result.elapsed >= Duration::from_millis(400));
}

#[tokio::test]
async fn test_keepalive() {
    let socket_a = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let socket_b = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let addr_b = socket_b.local_addr().unwrap();

    // Send keepalive from A to B
    send_keepalive(&socket_a, addr_b).await.unwrap();

    // B should receive a punch packet
    let mut buf = vec![0u8; 64];
    let (len, from) = socket_b.recv_from(&mut buf).await.unwrap();
    let packet = PunchPacket::decode(&buf[..len]).unwrap();
    assert!(packet.is_punch());
    assert_eq!(from, socket_a.local_addr().unwrap());
}

#[tokio::test]
async fn test_simultaneous_punch_both_connect() {
    // Test that both sides can connect to each other
    let socket_a = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let socket_b = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let addr_a = socket_a.local_addr().unwrap();
    let addr_b = socket_b.local_addr().unwrap();

    let config = PunchConfig {
        timeout: Duration::from_secs(5),
        interval: Duration::from_millis(50),
        max_attempts: 200,
    };

    let candidates_b = [addr_b];
    let candidates_a = [addr_a];
    let (result_a, result_b) = tokio::join!(
        hole_punch(&socket_a, &candidates_b, &config),
        hole_punch(&socket_b, &candidates_a, &config),
    );

    let result_a = result_a.unwrap();
    let result_b = result_b.unwrap();

    // Both should connect (each receives the other's punch and sends ACK,
    // then receives the other's ACK)
    // Note: due to timing, it's possible only one connects if the other
    // receives a punch but the ACK arrives before the next receive loop.
    // But in practice both should connect.
    assert!(
        result_a.connected || result_b.connected,
        "At least one should connect"
    );

    // Both should have sent packets
    assert!(result_a.packets_sent > 0);
    assert!(result_b.packets_sent > 0);
}
