use super::*;
    use ed25519_dalek::SigningKey;
    use jsonwebtoken::{EncodingKey, Header};
    use rand::rngs::OsRng;
    use rand::RngCore;

    /// Generate a test Ed25519 key pair and return (kid, private_key_hex, public_key_hex).
    fn generate_test_key(kid: &str) -> (String, String, String) {
        let mut seed = [0u8; 32];
        OsRng.fill_bytes(&mut seed);
        let signing_key = SigningKey::from_bytes(&seed);
        let verifying_key = signing_key.verifying_key();
        let private_hex = hex::encode(signing_key.to_bytes());
        let public_hex = hex::encode(verifying_key.to_bytes());
        (kid.to_string(), private_hex, public_hex)
    }

    /// Sign a set of claims with the given key and kid.
    fn sign_test_ticket(claims: &RelayTicketClaims, kid: &str, private_key_hex: &str) -> String {
        let private_bytes = hex::decode(private_key_hex).unwrap();
        let mut key_bytes = [0u8; 32];
        key_bytes.copy_from_slice(&private_bytes);
        let signing_key = SigningKey::from_bytes(&key_bytes);

        // Encode to PKCS#8 DER format required by jsonwebtoken
        use ed25519_dalek::pkcs8::EncodePrivateKey;
        let der = signing_key.to_pkcs8_der().unwrap();

        let mut header = Header::new(Algorithm::EdDSA);
        header.kid = Some(kid.to_string());
        header.typ = Some(JWT_TYP.to_string());

        let encoding_key = EncodingKey::from_ed_der(der.as_bytes());
        jsonwebtoken::encode(&header, claims, &encoding_key).unwrap()
    }

    fn make_test_claims(audience: &str, region: &str) -> RelayTicketClaims {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;
        RelayTicketClaims {
            device_id: "test-device".into(),
            network_id: "default".into(),
            node_id: "test-device".into(),
            relay_region: region.into(),
            relay_protocol: RELAY_PROTOCOL_VERSION,
            iss: JWT_ISSUER.into(),
            sub: "test-device".into(),
            aud: serde_json::Value::String(audience.into()),
            iat: Some(now),
            nbf: Some(now - 1),
            exp: Some(now + 300),
            jti: Some(hex::encode(rand::random::<[u8; 16]>())),
        }
    }

    #[test]
    fn test_auth_register_encode_decode_roundtrip() {
        let node_id = "my-node-123";
        let ticket = "eyJhbGciOiJFZERTQSJ9.eyJzdWIiOiJ0ZXN0In0.signature";

        let encoded = encode_auth_register(node_id, ticket).unwrap();
        let (decoded_node, decoded_ticket) = decode_auth_register(&encoded).unwrap();

        assert_eq!(decoded_node, node_id);
        assert_eq!(decoded_ticket, ticket);
    }

    #[test]
    fn test_auth_register_encode_decode_golden_vector() {
        // Golden vector for cross-language testing
        let node_id = "node-golden";
        let ticket = "test-jwt-token-value";
        let ticket_len = ticket.len(); // 20

        let encoded = encode_auth_register(node_id, ticket).unwrap();

        // Manual verification of the binary layout
        assert_eq!(encoded[0], 11); // node_id_len = "node-golden".len() = 11
        assert_eq!(&encoded[1..12], b"node-golden"); // node_id bytes
        assert_eq!(
            u16::from_be_bytes([encoded[12], encoded[13]]) as usize,
            ticket_len
        );
        assert_eq!(&encoded[14..], ticket.as_bytes()); // ticket bytes
    }

    #[test]
    fn test_auth_register_rejects_truncated() {
        let node_id = "node";
        let ticket = "ticket";
        let encoded = encode_auth_register(node_id, ticket).unwrap();

        // Truncate various amounts and verify they all fail
        for trim in 1..encoded.len() {
            assert!(
                decode_auth_register(&encoded[..trim]).is_err(),
                "should fail with {trim} bytes"
            );
        }
    }

    #[test]
    fn test_auth_register_rejects_trailing_bytes() {
        let node_id = "node";
        let ticket = "ticket";
        let mut encoded = encode_auth_register(node_id, ticket).unwrap();
        encoded.push(0x00); // trailing byte

        assert!(decode_auth_register(&encoded).is_err());
    }

    #[test]
    fn test_auth_register_rejects_empty_ticket() {
        assert!(encode_auth_register("node", "").is_err());
    }

    #[test]
    fn test_auth_register_rejects_oversized_ticket() {
        let big_ticket = "x".repeat(MAX_TICKET_LEN + 1);
        assert!(encode_auth_register("node", &big_ticket).is_err());
    }

    #[test]
    fn test_auth_register_rejects_invalid_utf8_node_id() {
        let invalid_utf8 = vec![0xFF, 0xFE, 0xFD];
        // Direct binary construction with invalid UTF-8
        let mut payload = Vec::new();
        payload.push(invalid_utf8.len() as u8);
        payload.extend_from_slice(&invalid_utf8);
        payload.extend_from_slice(&6u16.to_be_bytes());
        payload.extend_from_slice(b"ticket");

        assert!(decode_auth_register(&payload).is_err());
    }

    #[test]
    fn test_ticket_verify_valid() {
        let (kid, priv_hex, pub_hex) = generate_test_key("key-1");

        let mut keys = HashMap::new();
        keys.insert(kid.clone(), pub_hex);

        let verifier =
            TicketVerifier::new(keys, DEFAULT_CLOCK_SKEW, "relay-sg-1".into(), "sg".into())
                .unwrap();

        let claims = make_test_claims("relay-sg-1", "sg");
        let ticket = sign_test_ticket(&claims, &kid, &priv_hex);

        let verified = verifier.verify(&ticket).unwrap();
        assert_eq!(verified.claims.device_id, "test-device");
        assert_eq!(verified.claims.network_id, "default");
        assert_eq!(verified.kid, "key-1");
    }

    #[test]
    fn test_ticket_verify_rejects_wrong_algorithm() {
        // A token with HS256 algorithm should be rejected
        let ticket = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ0ZXN0In0.invalid";
        let (kid, _priv, pub_hex) = generate_test_key("key-1");
        let mut keys = HashMap::new();
        keys.insert(kid, pub_hex);

        let verifier =
            TicketVerifier::new(keys, DEFAULT_CLOCK_SKEW, "relay-sg-1".into(), "sg".into())
                .unwrap();

        // Should fail because algorithm is not EdDSA
        let result = verifier.verify(ticket);
        assert!(result.is_err());
    }

    #[test]
    fn test_ticket_verify_rejects_unknown_kid() {
        let (kid, priv_hex, _pub_hex) = generate_test_key("key-1");
        let (_kid2, _priv2, pub_hex2) = generate_test_key("key-2");

        let mut keys = HashMap::new();
        keys.insert("key-2".to_string(), pub_hex2); // different kid than signer

        let verifier =
            TicketVerifier::new(keys, DEFAULT_CLOCK_SKEW, "relay-sg-1".into(), "sg".into())
                .unwrap();

        let claims = make_test_claims("relay-sg-1", "sg");
        let ticket = sign_test_ticket(&claims, &kid, &priv_hex); // signed with key-1

        let result = verifier.verify(&ticket);
        assert!(result.is_err());
        match result {
            Err(RelayError::AuthError(code, _)) => {
                assert_eq!(code, RelayErrorCode::UNKNOWN_TICKET_KEY);
            }
            other => panic!("expected AuthError(UNKNOWN_TICKET_KEY), got: {other:?}"),
        }
    }

    #[test]
    fn test_ticket_verify_rejects_wrong_audience() {
        let (kid, priv_hex, pub_hex) = generate_test_key("key-1");
        let mut keys = HashMap::new();
        keys.insert(kid.clone(), pub_hex);

        // Verifier expects "relay-us-1" but ticket is for "relay-sg-1"
        let verifier =
            TicketVerifier::new(keys, DEFAULT_CLOCK_SKEW, "relay-us-1".into(), "us".into())
                .unwrap();

        let claims = make_test_claims("relay-sg-1", "sg");
        let ticket = sign_test_ticket(&claims, &kid, &priv_hex);

        let result = verifier.verify(&ticket);
        assert!(result.is_err());
    }

    #[test]
    fn test_ticket_verify_rejects_wrong_region() {
        let (kid, priv_hex, pub_hex) = generate_test_key("key-1");
        let mut keys = HashMap::new();
        keys.insert(kid.clone(), pub_hex);

        let verifier =
            TicketVerifier::new(keys, DEFAULT_CLOCK_SKEW, "relay-sg-1".into(), "us".into())
                .unwrap();

        let claims = make_test_claims("relay-sg-1", "sg");
        let ticket = sign_test_ticket(&claims, &kid, &priv_hex);

        let result = verifier.verify(&ticket);
        assert!(result.is_err());
    }

    #[test]
    fn test_ticket_verify_rejects_array_audience() {
        let (kid, priv_hex, pub_hex) = generate_test_key("key-1");
        let mut keys = HashMap::new();
        keys.insert(kid.clone(), pub_hex);

        let verifier =
            TicketVerifier::new(keys, DEFAULT_CLOCK_SKEW, "relay-sg-1".into(), "sg".into())
                .unwrap();

        let mut claims = make_test_claims("relay-sg-1", "sg");
        claims.aud = serde_json::json!(["aud-1", "aud-2"]);
        let ticket = sign_test_ticket(&claims, &kid, &priv_hex);

        let result = verifier.verify(&ticket);
        match result {
            Err(RelayError::AuthError(code, _)) => {
                assert_eq!(code, RelayErrorCode::AUDIENCE_MISMATCH);
            }
            other => panic!("expected AUDIENCE_MISMATCH for array audience, got: {other:?}"),
        }
    }

    #[test]
    fn test_ticket_verify_rejects_empty_audience() {
        let (kid, priv_hex, pub_hex) = generate_test_key("key-1");
        let mut keys = HashMap::new();
        keys.insert(kid.clone(), pub_hex);

        let verifier =
            TicketVerifier::new(keys, DEFAULT_CLOCK_SKEW, "relay-sg-1".into(), "sg".into())
                .unwrap();

        let mut claims = make_test_claims("relay-sg-1", "sg");
        claims.aud = serde_json::Value::String(String::new());
        let ticket = sign_test_ticket(&claims, &kid, &priv_hex);

        let result = verifier.verify(&ticket);
        assert!(result.is_err());
    }

    #[test]
    fn test_ticket_verify_rejects_expired() {
        let (kid, priv_hex, pub_hex) = generate_test_key("key-1");
        let mut keys = HashMap::new();
        keys.insert(kid.clone(), pub_hex);

        let verifier =
            TicketVerifier::new(keys, DEFAULT_CLOCK_SKEW, "relay-sg-1".into(), "sg".into())
                .unwrap();

        let mut claims = make_test_claims("relay-sg-1", "sg");
        // Set expiry in the past
        claims.exp = Some(
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs() as i64
                - 3600,
        );
        let ticket = sign_test_ticket(&claims, &kid, &priv_hex);

        let result = verifier.verify(&ticket);
        assert!(result.is_err());
    }

    #[test]
    fn test_ticket_verify_rejects_identity_mismatch() {
        let (kid, priv_hex, pub_hex) = generate_test_key("key-1");
        let mut keys = HashMap::new();
        keys.insert(kid.clone(), pub_hex);

        let verifier =
            TicketVerifier::new(keys, DEFAULT_CLOCK_SKEW, "relay-sg-1".into(), "sg".into())
                .unwrap();

        let mut claims = make_test_claims("relay-sg-1", "sg");
        claims.sub = "different-device".to_string(); // doesn't match device_id
        let ticket = sign_test_ticket(&claims, &kid, &priv_hex);

        let result = verifier.verify(&ticket);
        assert!(result.is_err());
    }

    #[test]
    fn test_key_rotation_current_and_previous() {
        let (kid_curr, priv_curr, pub_curr) = generate_test_key("key-2");
        let (kid_prev, priv_prev, pub_prev) = generate_test_key("key-1");

        let mut keys = HashMap::new();
        keys.insert(kid_curr.clone(), pub_curr);
        keys.insert(kid_prev.clone(), pub_prev);

        let verifier =
            TicketVerifier::new(keys, DEFAULT_CLOCK_SKEW, "relay-sg-1".into(), "sg".into())
                .unwrap();

        // Ticket signed with current key works
        let claims = make_test_claims("relay-sg-1", "sg");
        let ticket = sign_test_ticket(&claims, &kid_curr, &priv_curr);
        assert!(verifier.verify(&ticket).is_ok());

        // Ticket signed with previous key works
        let claims2 = make_test_claims("relay-sg-1", "sg");
        let ticket2 = sign_test_ticket(&claims2, &kid_prev, &priv_prev);
        assert!(verifier.verify(&ticket2).is_ok());

        // Unknown key fails
        let (kid_unknown, priv_unknown, _) = generate_test_key("key-unknown");
        let claims3 = make_test_claims("relay-sg-1", "sg");
        let ticket3 = sign_test_ticket(&claims3, &kid_unknown, &priv_unknown);
        assert!(verifier.verify(&ticket3).is_err());
    }

    #[test]
    fn test_network_node_key() {
        let k1 = NetworkNodeKey::new("net-a".into(), "node-1".into());
        let k2 = NetworkNodeKey::new("net-a".into(), "node-2".into());
        let k3 = NetworkNodeKey::new("net-b".into(), "node-1".into());
        let k4 = NetworkNodeKey::new("net-a".into(), "node-1".into());

        assert_eq!(k1, k4);
        assert_ne!(k1, k2);
        assert_ne!(k1, k3);
        assert_ne!(k2, k3);

        let mut map = HashMap::new();
        map.insert(k1.clone(), 1);
        map.insert(k2.clone(), 2);
        map.insert(k3.clone(), 3);

        assert_eq!(map.get(&k1), Some(&1));
        assert_eq!(map.get(&k4), Some(&1)); // same key
        assert_eq!(
            map.get(&NetworkNodeKey::new("net-b".into(), "node-1".into())),
            Some(&3)
        );
    }

    #[test]
    fn test_ticket_verifier_rejects_empty_keyring() {
        let result = TicketVerifier::new(
            HashMap::new(),
            DEFAULT_CLOCK_SKEW,
            "relay-sg-1".into(),
            "sg".into(),
        );
        assert!(result.is_err());
    }

    #[test]
    fn test_new_error_codes() {
        // Verify new A2 error codes are distinct and in expected range
        let codes = [
            RelayErrorCode::AUTH_REQUIRED,
            RelayErrorCode::INVALID_TICKET,
            RelayErrorCode::TICKET_EXPIRED,
            RelayErrorCode::AUDIENCE_MISMATCH,
            RelayErrorCode::IDENTITY_MISMATCH,
            RelayErrorCode::NETWORK_MISMATCH,
            RelayErrorCode::TICKET_NOT_YET_VALID,
            RelayErrorCode::UNKNOWN_TICKET_KEY,
        ];

        let mut seen = std::collections::HashSet::new();
        for &code in &codes {
            assert!(seen.insert(code), "duplicate error code: {code}");
            assert!(
                (4011..=4018).contains(&code),
                "error code {code} outside expected range 4011-4018"
            );
        }
    }
