#[cfg(test)]
mod tests {
    use super::*;
    use crate::handshake::{HandshakeInitiator, HandshakeResponder};
    use crate::types::AEAD_TAG_SIZE;
    use p2pnet_crypto::NodeIdentity;

    fn establish_session() -> (TransportSession, TransportSession) {
        let init_id = NodeIdentity::generate();
        let resp_id = NodeIdentity::generate();

        let mut initiator = HandshakeInitiator::new(init_id, resp_id.public_key(), None);
        let mut responder = HandshakeResponder::new(resp_id, None);

        let init_msg = initiator.create_initiation().unwrap();
        let (resp_msg, resp_keys) = responder.consume_initiation_and_respond(&init_msg).unwrap();
        let init_keys = initiator.consume_response(&resp_msg).unwrap();

        (
            TransportSession::new(init_keys),
            TransportSession::new(resp_keys),
        )
    }

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let (mut sender, mut receiver) = establish_session();

        let packet = b"Hello, WireGuard transport!";
        let msg = sender.encrypt(packet).unwrap();

        let decrypted = receiver.decrypt(&msg).unwrap();
        assert_eq!(&decrypted, packet);
    }

    #[test]
    fn test_multiple_packets() {
        let (mut sender, mut receiver) = establish_session();

        for i in 0..10 {
            let packet = format!("Packet number {i}");
            let msg = sender.encrypt(packet.as_bytes()).unwrap();
            let decrypted = receiver.decrypt(&msg).unwrap();
            assert_eq!(&decrypted, packet.as_bytes());
        }
    }

    #[test]
    fn test_bidirectional() {
        let (mut alice, mut bob) = establish_session();

        // Alice → Bob
        let packet1 = b"Hello from Alice";
        let msg1 = alice.encrypt(packet1).unwrap();
        let decrypted1 = bob.decrypt(&msg1).unwrap();
        assert_eq!(&decrypted1, packet1);

        // Bob → Alice
        let packet2 = b"Hello from Bob";
        let msg2 = bob.encrypt(packet2).unwrap();
        let decrypted2 = alice.decrypt(&msg2).unwrap();
        assert_eq!(&decrypted2, packet2);
    }

    #[test]
    fn test_counter_increments() {
        let (mut sender, _) = establish_session();

        let msg0 = sender.encrypt(b"a").unwrap();
        assert_eq!(msg0.counter, 0);

        let msg1 = sender.encrypt(b"b").unwrap();
        assert_eq!(msg1.counter, 1);

        let msg2 = sender.encrypt(b"c").unwrap();
        assert_eq!(msg2.counter, 2);
    }

    #[test]
    fn test_replay_detection() {
        let (mut sender, mut receiver) = establish_session();

        let packet = b"Important data";
        let msg = sender.encrypt(packet).unwrap();

        // First receive should succeed
        let decrypted = receiver.decrypt(&msg).unwrap();
        assert_eq!(&decrypted, packet);

        // Replay the same message → should fail
        let result = receiver.decrypt(&msg);
        assert!(result.is_err());
        match result {
            Err(WireGuardError::ReplayDetected(_)) => {}
            Err(e) => panic!("Expected ReplayDetected, got {e}"),
            Ok(_) => panic!("Expected error, got success"),
        }
    }

    #[test]
    fn test_out_of_order_delivery() {
        let (mut sender, mut receiver) = establish_session();

        let msg0 = sender.encrypt(b"first").unwrap();
        let msg1 = sender.encrypt(b"second").unwrap();
        let msg2 = sender.encrypt(b"third").unwrap();

        // Deliver out of order: msg1, msg0, msg2
        let d1 = receiver.decrypt(&msg1).unwrap();
        assert_eq!(&d1, b"second");

        // msg0 is now a replay (below highest), but should still work if in window
        // Actually, msg0 has counter=0 which is below the window when highest=1
        // Wait, with window=64, counter=0 should still be within window of highest=1
        let d0 = receiver.decrypt(&msg0);
        // counter 0 < highest 1, offset=1, within window → should decrypt OK
        assert!(d0.is_ok());

        let d2 = receiver.decrypt(&msg2).unwrap();
        assert_eq!(&d2, b"third");
    }

    #[test]
    fn test_replay_window_accepts_edge_and_rejects_old_counter() {
        let (mut sender, mut receiver) = establish_session();
        let messages: Vec<_> = (0..=64)
            .map(|counter| {
                sender
                    .encrypt(format!("packet-{counter}").as_bytes())
                    .unwrap()
            })
            .collect();

        let newest = receiver.decrypt(&messages[64]).unwrap();
        assert_eq!(&newest, b"packet-64");

        let edge = receiver.decrypt(&messages[1]).unwrap();
        assert_eq!(&edge, b"packet-1");

        let too_old = receiver.decrypt(&messages[0]);
        assert!(matches!(too_old, Err(WireGuardError::ReplayDetected(0))));
    }

    #[test]
    fn test_wrong_receiver_index() {
        let (mut sender, mut receiver) = establish_session();

        let mut msg = sender.encrypt(b"test").unwrap();
        msg.receiver_index = 0xDEADBEEF; // Wrong index

        assert!(receiver.decrypt(&msg).is_err());
    }

    #[test]
    fn test_encrypt_to_bytes_roundtrip() {
        let (mut sender, mut receiver) = establish_session();

        let packet = b"Wire format test";
        let wire_bytes = sender.encrypt_to_bytes(packet).unwrap();
        let decrypted = receiver.decrypt_from_bytes(&wire_bytes).unwrap();
        assert_eq!(&decrypted, packet);
    }

    #[test]
    fn test_large_packet() {
        let (mut sender, mut receiver) = establish_session();

        // 1400 bytes (typical MTU payload)
        let packet = vec![0xAB; 1400];
        let msg = sender.encrypt(&packet).unwrap();
        let decrypted = receiver.decrypt(&msg).unwrap();
        assert_eq!(decrypted, packet);

        // Verify ciphertext size = plaintext + 16-byte tag
        assert_eq!(msg.encrypted_payload.len(), packet.len() + AEAD_TAG_SIZE);
    }

    #[test]
    fn test_empty_packet() {
        let (mut sender, mut receiver) = establish_session();

        let packet = b"";
        let msg = sender.encrypt(packet).unwrap();
        let decrypted = receiver.decrypt(&msg).unwrap();
        assert_eq!(decrypted, packet);
    }

    #[test]
    fn test_nonce_uniqueness() {
        let (mut sender, _) = establish_session();

        // Send multiple packets and verify each has a unique nonce
        let mut nonces = std::collections::HashSet::new();
        for _ in 0..100 {
            let msg = sender.encrypt(b"data").unwrap();
            assert!(nonces.insert(msg.counter), "Duplicate nonce detected!");
        }
    }

    #[test]
    fn test_decrypt_tampered_ciphertext() {
        let (mut sender, mut receiver) = establish_session();

        let msg = sender.encrypt(b"sensitive data").unwrap();
        let mut tampered = msg.clone();
        tampered.encrypted_payload[0] ^= 0xFF;

        assert!(receiver.decrypt(&tampered).is_err());
    }

    #[test]
    fn test_decrypt_wrong_counter() {
        let (mut sender, mut receiver) = establish_session();

        let msg = sender.encrypt(b"data").unwrap();
        let mut wrong = msg.clone();
        wrong.counter = 999; // Wrong counter (wrong nonce)

        // This will either fail decryption (wrong nonce) or be a replay
        // Either way, it should not produce valid plaintext
        let result = receiver.decrypt(&wrong);
        assert!(result.is_err());
    }

    #[test]
    fn test_needs_rekey_by_message_threshold() {
        let (sender, _) = establish_session();
        let mut session =
            sender.with_thresholds(3, Duration::from_secs(3600), 10, Duration::from_secs(7200));
        assert!(!session.needs_rekey());
        session.encrypt(b"a").unwrap();
        session.encrypt(b"b").unwrap();
        session.encrypt(b"c").unwrap();
        assert!(session.needs_rekey());
        assert!(!session.is_expired());
    }

    #[test]
    fn test_session_expires_by_reject_threshold() {
        let (sender, _) = establish_session();
        let mut session =
            sender.with_thresholds(1, Duration::from_secs(3600), 2, Duration::from_secs(7200));
        session.encrypt(b"a").unwrap();
        assert!(session.needs_rekey());
        session.encrypt(b"b").unwrap();
        assert!(session.is_expired());
    }
}
