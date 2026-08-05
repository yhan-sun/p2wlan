#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_full_handshake() {
        // Generate identities
        let initiator_identity = NodeIdentity::generate();
        let initiator_identity_clone = initiator_identity.clone();
        let responder_identity = NodeIdentity::generate();

        // Create initiator (knows responder's public key)
        let mut initiator =
            HandshakeInitiator::new(initiator_identity, responder_identity.public_key(), None);

        // Create responder (doesn't know initiator yet)
        let mut responder = HandshakeResponder::new(responder_identity, None);

        // Message 1: Initiator → Responder
        let init_msg = initiator.create_initiation().unwrap();

        // Responder processes message 1 and creates response
        let (response, responder_keys) =
            responder.consume_initiation_and_respond(&init_msg).unwrap();

        // Verify responder learned the initiator's public key
        assert_eq!(
            responder.initiator_public_key().unwrap(),
            &initiator_identity_clone.public_key()
        );

        // Message 2: Responder → Initiator
        let initiator_keys = initiator.consume_response(&response).unwrap();

        // Verify keys match: initiator's send = responder's recv and vice versa
        assert_eq!(initiator_keys.send_key, responder_keys.recv_key);
        assert_eq!(initiator_keys.recv_key, responder_keys.send_key);

        // Verify indices
        assert_eq!(initiator_keys.our_index, responder_keys.peer_index);
        assert_eq!(initiator_keys.peer_index, responder_keys.our_index);
    }

    #[test]
    fn invalid_response_does_not_poison_pending_initiator() {
        let initiator_identity = NodeIdentity::generate();
        let responder_identity = NodeIdentity::generate();
        let mut initiator = HandshakeInitiator::new(
            initiator_identity,
            responder_identity.public_key(),
            None,
        );
        let initiation = initiator.create_initiation().unwrap();
        let mut responder = HandshakeResponder::new(responder_identity, None);
        let (valid_response, _) = responder
            .consume_initiation_and_respond(&initiation)
            .unwrap();

        let mut invalid_response = valid_response.clone();
        invalid_response.encrypted_empty[0] ^= 0x80;
        assert_eq!(invalid_response.receiver_index, initiator.sender_index);
        assert!(initiator.consume_response(&invalid_response).is_err());
        assert!(initiator.consume_response(&valid_response).is_ok());
    }

    #[test]
    fn test_transport_key_pair_debug_redacts_keys() {
        let keys = TransportKeyPair {
            send_key: [0xAB; 32],
            recv_key: [0xCD; 32],
            our_index: 1,
            peer_index: 2,
        };

        let debug = format!("{keys:?}");
        assert!(debug.contains("[redacted]"));
        assert!(!debug.contains(&hex::encode(keys.send_key)));
        assert!(!debug.contains(&hex::encode(keys.recv_key)));
        assert!(debug.contains("our_index"));
        assert!(debug.contains("peer_index"));
    }

    #[test]
    fn test_handshake_with_psk() {
        let initiator_identity = NodeIdentity::generate();
        let responder_identity = NodeIdentity::generate();
        let psk = [0x42u8; 32];

        let mut initiator = HandshakeInitiator::new(
            initiator_identity,
            responder_identity.public_key(),
            Some(psk),
        );
        let mut responder = HandshakeResponder::new(responder_identity, Some(psk));

        let init_msg = initiator.create_initiation().unwrap();
        let (response, responder_keys) =
            responder.consume_initiation_and_respond(&init_msg).unwrap();
        let initiator_keys = initiator.consume_response(&response).unwrap();

        // Keys should match
        assert!(initiator_keys.keys_match(&responder_keys));
    }

    #[test]
    fn test_handshake_none_psk_works() {
        // Verify that a handshake with None PSK completes successfully
        // (internally treated as all-zeros PSK)
        let init_id = NodeIdentity::generate();
        let resp_id = NodeIdentity::generate();

        let mut init = HandshakeInitiator::new(init_id, resp_id.public_key(), None);
        let mut resp = HandshakeResponder::new(resp_id, None);

        let msg = init.create_initiation().unwrap();
        let (resp_msg, resp_keys) = resp.consume_initiation_and_respond(&msg).unwrap();
        let init_keys = init.consume_response(&resp_msg).unwrap();

        // Keys must match across both sides
        assert!(init_keys.keys_match(&resp_keys));
    }

    #[test]
    fn test_wrong_responder_key_fails() {
        let initiator_identity = NodeIdentity::generate();
        let wrong_responder = NodeIdentity::generate();
        let actual_responder = NodeIdentity::generate();

        // Initiator thinks the responder has the wrong key
        let mut initiator =
            HandshakeInitiator::new(initiator_identity, wrong_responder.public_key(), None);
        let mut responder = HandshakeResponder::new(actual_responder, None);

        let init_msg = initiator.create_initiation().unwrap();

        // Responder should fail to decrypt (wrong key)
        let result = responder.consume_initiation_and_respond(&init_msg);
        assert!(result.is_err());
    }

    #[test]
    fn test_random_index_nonzero() {
        let indices: Vec<u32> = (0..10).map(|_| random_index()).collect();
        for idx in &indices {
            assert_ne!(*idx, 0);
        }
    }

    #[test]
    fn test_timestamp_size() {
        let ts = build_timestamp();
        assert_eq!(ts.len(), TIMESTAMP_SIZE);
    }

    #[test]
    fn test_mac1_computation() {
        let responder_pub = NodeIdentity::generate().public_key();
        let data = b"test message for mac1";
        let mac1 = compute_mac1(&responder_pub, data);

        // Same inputs should produce same MAC
        let mac1_2 = compute_mac1(&responder_pub, data);
        assert_eq!(mac1, mac1_2);

        // Different responder should produce different MAC
        let other_pub = NodeIdentity::generate().public_key();
        let mac1_3 = compute_mac1(&other_pub, data);
        assert_ne!(mac1, mac1_3);
    }
}
