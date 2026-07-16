//! Two-node direct connection integration test.
//!
//! Simulates a complete WireGuard tunnel between two nodes:
//! 1. Handshake (Noise IK)
//! 2. Bidirectional encrypted transport
//! 3. IP packet (ICMP Echo) through the tunnel

use p2pnet_crypto::NodeIdentity;
use p2pnet_tun::packet::Ipv4Packet;
use p2pnet_wireguard::{
    HandshakeInitiator, HandshakeResponder, TransportSession, TYPE_INITIALIZATION, TYPE_RESPONSE,
    TYPE_TRANSPORT,
};
use std::net::Ipv4Addr;

/// Simulate a two-node WireGuard tunnel:
///
/// Node A (10.20.0.1) ←── WireGuard Tunnel ──→ Node B (10.20.0.2)
///
/// Both nodes generate identities, perform a Noise IK handshake,
/// then exchange encrypted IP packets through the tunnel.
#[test]
fn test_two_node_direct_connection() {
    // === Step 1: Generate node identities ===
    let node_a_identity = NodeIdentity::generate();
    let node_b_identity = NodeIdentity::generate();

    let node_a_ip = Ipv4Addr::new(10, 20, 0, 1);
    let node_b_ip = Ipv4Addr::new(10, 20, 0, 2);

    let node_a_pub = node_a_identity.public_key();

    // === Step 2: Node A initiates handshake ===
    let mut initiator = HandshakeInitiator::new(
        node_a_identity,
        node_b_identity.public_key(),
        None, // No preshared key
    );

    let init_msg = initiator.create_initiation().unwrap();

    // Verify message type
    let init_bytes = init_msg.to_bytes();
    assert_eq!(init_bytes[0], TYPE_INITIALIZATION);
    assert_eq!(init_bytes.len(), 148); // 4 + 4 + 32 + 48 + 28 + 16 + 16

    // === Step 3: Node B receives initiation and responds ===
    let mut responder = HandshakeResponder::new(node_b_identity, None);

    let (response_msg, node_b_keys) = responder.consume_initiation_and_respond(&init_msg).unwrap();

    // Verify response message
    let resp_bytes = response_msg.to_bytes();
    assert_eq!(resp_bytes[0], TYPE_RESPONSE);
    assert_eq!(resp_bytes.len(), 92); // 4 + 4 + 4 + 32 + 16 + 16 + 16

    // Verify Node B learned Node A's public key
    assert_eq!(responder.initiator_public_key().unwrap(), &node_a_pub);

    // === Step 4: Node A processes response ===
    let node_a_keys = initiator.consume_response(&response_msg).unwrap();

    // Verify keys match across both sides
    assert!(
        node_a_keys.keys_match(&node_b_keys),
        "Transport keys don't match! Alice send != Bob recv or vice versa"
    );

    // === Step 5: Create transport sessions ===
    let mut node_a_session = TransportSession::new(node_a_keys);
    let mut node_b_session = TransportSession::new(node_b_keys);

    // === Step 6: Node A sends ICMP Echo Request to Node B ===
    let icmp_request =
        Ipv4Packet::build_icmp_echo_request(node_a_ip, node_b_ip, 0x1234, 1, b"ping-data-payload");

    // Encrypt and "send" over the tunnel
    let encrypted_msg = node_a_session.encrypt(&icmp_request).unwrap();
    let wire_bytes = encrypted_msg.to_bytes();

    assert_eq!(wire_bytes[0], TYPE_TRANSPORT);
    assert!(wire_bytes.len() > 32); // Header + tag + payload

    // Node B "receives" and decrypts
    let decrypted = node_b_session.decrypt(&encrypted_msg).unwrap();

    // Verify the IP packet is intact
    assert_eq!(decrypted, icmp_request);

    // Parse the decrypted packet
    let parsed = Ipv4Packet::new(&decrypted).unwrap();
    assert_eq!(parsed.src_addr(), node_a_ip);
    assert_eq!(parsed.dst_addr(), node_b_ip);
    assert_eq!(parsed.protocol(), p2pnet_tun::packet::Protocol::Icmp);

    // === Step 7: Node B sends ICMP Echo Reply back to Node A ===
    let icmp_reply = Ipv4Packet::build_icmp_echo_request(
        node_b_ip,
        node_a_ip,
        0x1234,
        1, // Same ID/seq as the request (simulating echo reply)
        b"ping-data-payload",
    );

    let encrypted_reply = node_b_session.encrypt(&icmp_reply).unwrap();
    let decrypted_reply = node_a_session.decrypt(&encrypted_reply).unwrap();

    assert_eq!(decrypted_reply, icmp_reply);

    let parsed_reply = Ipv4Packet::new(&decrypted_reply).unwrap();
    assert_eq!(parsed_reply.src_addr(), node_b_ip);
    assert_eq!(parsed_reply.dst_addr(), node_a_ip);

    // === Step 8: Exchange multiple packets ===
    for seq in 2..=10 {
        // A → B
        let req = Ipv4Packet::build_icmp_echo_request(node_a_ip, node_b_ip, 0x1234, seq, b"data");
        let enc = node_a_session.encrypt(&req).unwrap();
        let dec = node_b_session.decrypt(&enc).unwrap();
        assert_eq!(dec, req);

        // B → A
        let rep = Ipv4Packet::build_icmp_echo_request(node_b_ip, node_a_ip, 0x1234, seq, b"data");
        let enc = node_b_session.encrypt(&rep).unwrap();
        let dec = node_a_session.decrypt(&enc).unwrap();
        assert_eq!(dec, rep);
    }

    // === Step 9: Verify counters ===
    // Node A sent: 1 (step 6) + 9 (loop seq 2..=10) = 10 packets
    assert_eq!(node_a_session.send_counter(), 10);
    // Node B sent: 1 (step 7) + 9 (loop seq 2..=10) = 10 packets
    assert_eq!(node_b_session.send_counter(), 10);
}

/// Test that a handshake with a preshared key works end-to-end.
#[test]
fn test_direct_connection_with_psk() {
    let node_a = NodeIdentity::generate();
    let node_b = NodeIdentity::generate();
    let psk = [0xAA; 32]; // Non-zero PSK

    let mut init = HandshakeInitiator::new(node_a, node_b.public_key(), Some(psk));
    let mut resp = HandshakeResponder::new(node_b, Some(psk));

    let msg = init.create_initiation().unwrap();
    let (resp_msg, resp_keys) = resp.consume_initiation_and_respond(&msg).unwrap();
    let init_keys = init.consume_response(&resp_msg).unwrap();

    assert!(init_keys.keys_match(&resp_keys));

    // Exchange data
    let mut a_sess = TransportSession::new(init_keys);
    let mut b_sess = TransportSession::new(resp_keys);

    let data = b"Secret data over PSK-protected tunnel";
    let enc = a_sess.encrypt(data).unwrap();
    let dec = b_sess.decrypt(&enc).unwrap();
    assert_eq!(&dec, data);
}

/// Test that replay attacks are detected.
#[test]
fn test_replay_attack_blocked() {
    let node_a = NodeIdentity::generate();
    let node_b = NodeIdentity::generate();

    let mut init = HandshakeInitiator::new(node_a, node_b.public_key(), None);
    let mut resp = HandshakeResponder::new(node_b, None);

    let msg = init.create_initiation().unwrap();
    let (resp_msg, resp_keys) = resp.consume_initiation_and_respond(&msg).unwrap();
    let init_keys = init.consume_response(&resp_msg).unwrap();

    let mut a_sess = TransportSession::new(init_keys);
    let mut b_sess = TransportSession::new(resp_keys);

    // Send a valid packet
    let data = b"Important packet";
    let enc = a_sess.encrypt(data).unwrap();

    // First receive: OK
    let dec = b_sess.decrypt(&enc).unwrap();
    assert_eq!(&dec, data);

    // Replay: should fail
    assert!(b_sess.decrypt(&enc).is_err());
}

/// Test that a man-in-the-middle attack is detected (wrong key).
#[test]
fn test_mitm_attack_blocked() {
    let node_a = NodeIdentity::generate();
    let node_b = NodeIdentity::generate();
    let attacker = NodeIdentity::generate(); // MITM with wrong key

    // Node A thinks it's talking to the attacker (wrong responder key)
    let mut init = HandshakeInitiator::new(node_a, attacker.public_key(), None);
    let mut resp = HandshakeResponder::new(node_b, None); // But actually talks to Node B

    let msg = init.create_initiation().unwrap();

    // Node B should fail to decrypt because the DH doesn't match
    let result = resp.consume_initiation_and_respond(&msg);
    assert!(result.is_err(), "MITM attack should be blocked");
}

/// Test large packet transmission (MTU-sized).
#[test]
fn test_large_packet_through_tunnel() {
    let node_a = NodeIdentity::generate();
    let node_b = NodeIdentity::generate();

    let mut init = HandshakeInitiator::new(node_a, node_b.public_key(), None);
    let mut resp = HandshakeResponder::new(node_b, None);

    let msg = init.create_initiation().unwrap();
    let (resp_msg, resp_keys) = resp.consume_initiation_and_respond(&msg).unwrap();
    let init_keys = init.consume_response(&resp_msg).unwrap();

    let mut a_sess = TransportSession::new(init_keys);
    let mut b_sess = TransportSession::new(resp_keys);

    // 1400 bytes (typical WireGuard MTU payload)
    let large_packet = vec![0x42u8; 1400];
    let enc = a_sess.encrypt(&large_packet).unwrap();
    let dec = b_sess.decrypt(&enc).unwrap();
    assert_eq!(dec, large_packet);

    // 65535 bytes (max IP packet)
    let max_packet = vec![0xFFu8; 65535];
    let enc = a_sess.encrypt(&max_packet).unwrap();
    let dec = b_sess.decrypt(&enc).unwrap();
    assert_eq!(dec, max_packet);
}

/// Test handshake message serialization round-trips.
#[test]
fn test_wire_format_roundtrip() {
    let node_a = NodeIdentity::generate();
    let node_b = NodeIdentity::generate();

    let mut init = HandshakeInitiator::new(node_a, node_b.public_key(), None);
    let init_msg = init.create_initiation().unwrap();

    // Serialize → Deserialize → should be identical
    let bytes = init_msg.to_bytes();
    let decoded = p2pnet_wireguard::MessageInitiation::from_bytes(&bytes).unwrap();

    assert_eq!(decoded.sender_index, init_msg.sender_index);
    assert_eq!(decoded.ephemeral, init_msg.ephemeral);
    assert_eq!(decoded.encrypted_static, init_msg.encrypted_static);
    assert_eq!(decoded.encrypted_timestamp, init_msg.encrypted_timestamp);
    assert_eq!(decoded.mac1, init_msg.mac1);
    assert_eq!(decoded.mac2, init_msg.mac2);

    // Verify the decoded message produces the same bytes
    assert_eq!(decoded.to_bytes(), bytes);
}
