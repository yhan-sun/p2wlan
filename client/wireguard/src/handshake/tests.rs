#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn initiator_rejects_response_before_initiation_without_panicking() {
        let initiator_identity = NodeIdentity::generate();
        let responder_identity = NodeIdentity::generate();
        let mut initiator =
            HandshakeInitiator::new(initiator_identity, responder_identity.public_key(), None);
        let response = MessageResponse {
            sender_index: 1,
            receiver_index: 1,
            ephemeral: [1u8; 32],
            encrypted_empty: [0u8; 16],
            mac1: [0u8; MAC_SIZE],
            mac2: [0u8; MAC_SIZE],
        };
        let error = initiator
            .consume_response(&response)
            .expect_err("response before initiation must be rejected");
        assert!(error.to_string().contains("before creating an initiation"));
    }

    #[test]
    fn initiator_rejects_duplicate_initiation() {
        let initiator_identity = NodeIdentity::generate();
        let responder_identity = NodeIdentity::generate();
        let mut initiator =
            HandshakeInitiator::new(initiator_identity, responder_identity.public_key(), None);
        initiator.create_initiation().unwrap();
        let error = initiator
            .create_initiation()
            .expect_err("a pending initiation must not be overwritten");
        assert!(error.to_string().contains("already created"));
    }

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
        let initiator_public = initiator_identity.public_key();
        let responder_identity = NodeIdentity::generate();
        let mut initiator =
            HandshakeInitiator::new(initiator_identity, responder_identity.public_key(), None);
        let initiation = initiator.create_initiation().unwrap();
        let mut responder = HandshakeResponder::new(responder_identity, None);
        let (valid_response, _) = responder
            .consume_initiation_and_respond(&initiation)
            .unwrap();

        let mut invalid_response = valid_response.clone();
        invalid_response.encrypted_empty[0] ^= 0x80;
        invalid_response.mac1 = compute_mac1(&initiator_public, &invalid_response.bytes_for_mac1());
        assert_eq!(invalid_response.receiver_index, initiator.sender_index);
        assert!(initiator.consume_response(&invalid_response).is_err());
        assert!(initiator.consume_response(&valid_response).is_ok());
    }

    #[test]
    fn invalid_initiation_does_not_poison_reusable_responder() {
        let initiator_identity = NodeIdentity::generate();
        let responder_identity = NodeIdentity::generate();
        let responder_public = responder_identity.public_key();
        let mut initiator = HandshakeInitiator::new(initiator_identity, responder_public, None);
        let valid = initiator.create_initiation().unwrap();
        let mut invalid = valid.clone();
        invalid.encrypted_static[0] ^= 0x80;
        invalid.mac1 = compute_mac1(&responder_public, &invalid.bytes_for_mac1());

        let mut responder = HandshakeResponder::new(responder_identity, None);
        assert!(responder.consume_initiation_and_respond(&invalid).is_err());
        assert!(responder.consume_initiation_and_respond(&valid).is_ok());
    }

    #[test]
    fn handshake_mac1_is_verified_on_both_messages() {
        let initiator_identity = NodeIdentity::generate();
        let responder_identity = NodeIdentity::generate();
        let mut initiator =
            HandshakeInitiator::new(initiator_identity, responder_identity.public_key(), None);
        let initiation = initiator.create_initiation().unwrap();

        let mut bad_initiation = initiation.clone();
        bad_initiation.mac1[0] ^= 1;
        let mut rejecting_responder = HandshakeResponder::new(responder_identity.clone(), None);
        assert!(matches!(
            rejecting_responder.consume_initiation_and_respond(&bad_initiation),
            Err(WireGuardError::InvalidMac(_))
        ));

        let mut responder = HandshakeResponder::new(responder_identity, None);
        let (response, _) = responder
            .consume_initiation_and_respond(&initiation)
            .unwrap();
        let mut bad_response = response;
        bad_response.mac1[0] ^= 1;
        assert!(matches!(
            initiator.consume_response(&bad_response),
            Err(WireGuardError::InvalidMac(_))
        ));
    }

    #[test]
    fn initiator_accepts_legacy_response_mac_during_rolling_upgrade() {
        let initiator_identity = NodeIdentity::generate();
        let responder_identity = NodeIdentity::generate();
        let responder_public = responder_identity.public_key();
        let mut initiator = HandshakeInitiator::new(initiator_identity, responder_public, None);
        let initiation = initiator.create_initiation().unwrap();
        let mut responder = HandshakeResponder::new(responder_identity, None);
        let (mut response, _) = responder
            .consume_initiation_and_respond(&initiation)
            .unwrap();
        response.mac1 = compute_mac1(&responder_public, &response.bytes_for_mac1());
        assert!(initiator.consume_response(&response).is_ok());
    }

    #[test]
    fn timestamp_floor_rejects_replayed_initiation_across_responder_objects() {
        let initiator_identity = NodeIdentity::generate();
        let responder_identity = NodeIdentity::generate();
        let mut initiator =
            HandshakeInitiator::new(initiator_identity, responder_identity.public_key(), None);
        let initiation = initiator.create_initiation().unwrap();
        let mut first = HandshakeResponder::new(responder_identity.clone(), None);
        first.consume_initiation_and_respond(&initiation).unwrap();
        let floor = first.latest_timestamp().expect("authenticated timestamp");

        let mut second =
            HandshakeResponder::new_with_timestamp_floor(responder_identity, None, Some(floor));
        assert!(second.consume_initiation_and_respond(&initiation).is_err());
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
        assert_eq!(ts[0], 0x40, "canonical TAI64N must use 8-byte seconds");
        assert_eq!(normalize_timestamp(&ts).unwrap(), ts);
        let nanos = u32::from_be_bytes(ts[8..12].try_into().unwrap());
        assert!(nanos < 1_000_000_000);
    }

    #[test]
    fn legacy_timestamp_layout_is_normalized_for_rolling_upgrade() {
        let unix_seconds = 1_700_000_000u32;
        let nanos = 123_456_789u64;
        let mut legacy = [0u8; TIMESTAMP_SIZE];
        legacy[0..4].copy_from_slice(&(unix_seconds + 10).to_be_bytes());
        legacy[4..12].copy_from_slice(&nanos.to_be_bytes());

        let normalized = normalize_timestamp(&legacy).unwrap();
        assert_eq!(
            u64::from_be_bytes(normalized[0..8].try_into().unwrap()),
            TAI64N_BASE + u64::from(unix_seconds)
        );
        assert_eq!(
            u32::from_be_bytes(normalized[8..12].try_into().unwrap()),
            nanos as u32
        );
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
