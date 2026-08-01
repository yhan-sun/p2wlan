#[test]
fn test_control_message_serialization() {
    let msg = ControlMessage::Register {
        node_id: "node123".to_string(),
        public_key: "pubkey".to_string(),
        device_name: "my-laptop".to_string(),
        platform: "windows".to_string(),
        network_id: "net1".to_string(),
    };

    let json = serde_json::to_string(&msg).unwrap();
    let decoded: ControlMessage = serde_json::from_str(&json).unwrap();

    if let ControlMessage::Register { node_id, .. } = decoded {
        assert_eq!(node_id, "node123");
    } else {
        panic!("Expected Register message");
    }
}

#[test]
fn test_peer_offer_serialization() {
    let msg = ControlMessage::PeerOffer {
        from_node_id: "alice".to_string(),
        to_node_id: "bob".to_string(),
        candidates: vec!["10.0.0.1:5000".to_string()],
        session_id: Some("sess-test".to_string()),
        probe_ephemeral_public_key: Some(
            "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f".to_string(),
        ),
        probe_ephemeral_signature: None,
        candidate_sources: HashMap::new(),
        candidate_generation: 7,
        candidates_expires_at_ms: Some(42_000),
        handshake_init: vec![0x01, 0x02],
        punch_at_ms: Some(1234),
    };

    let json = serde_json::to_string(&msg).unwrap();
    let decoded: ControlMessage = serde_json::from_str(&json).unwrap();
    assert!(matches!(decoded, ControlMessage::PeerOffer { .. }));
}

#[test]
fn test_peer_reflexive_serialization() {
    let msg = ControlMessage::PeerReflexive {
        from_node_id: "alice".to_string(),
        to_node_id: "bob".to_string(),
        observed_endpoint: "203.0.113.10:51820".to_string(),
        punch_at_ms: Some(42_000),
    };

    let json = serde_json::to_string(&msg).unwrap();
    assert!(json.contains("\"type\":\"peer_reflexive\""));
    assert!(json.contains("\"observed_endpoint\":\"203.0.113.10:51820\""));

    let decoded: ControlMessage = serde_json::from_str(&json).unwrap();
    match decoded {
        ControlMessage::PeerReflexive {
            from_node_id,
            to_node_id,
            observed_endpoint,
            punch_at_ms,
        } => {
            assert_eq!(from_node_id, "alice");
            assert_eq!(to_node_id, "bob");
            assert_eq!(observed_endpoint, "203.0.113.10:51820");
            assert_eq!(punch_at_ms, Some(42_000));
        }
        other => panic!("expected PeerReflexive, got {other:?}"),
    }
}

#[test]
fn rest_signal_response_defaults_to_v1_for_legacy_servers() {
    let signal: SignalResponse = serde_json::from_str(
        r#"{
                "from_node_id": "alice",
                "type": "peer_offer",
                "candidates": ["203.0.113.10:51820"]
            }"#,
    )
    .unwrap();

    assert_eq!(signal.protocol_version, SIGNAL_REST_PROTOCOL_VERSION);
}

#[test]
fn test_peer_reflexive_endpoint_prefers_tagged_candidate() {
    let signal = SignalResponse {
        from_node_id: "alice".to_string(),
        signal_type: "peer_reflexive".to_string(),
        protocol_version: SIGNAL_REST_PROTOCOL_VERSION,
        candidates: vec![
            "198.51.100.1:40000".to_string(),
            "203.0.113.10:51820".to_string(),
        ],
        session_id: None,
        probe_ephemeral_public_key: None,
        candidate_sources: HashMap::from([
            (
                "198.51.100.1:40000".to_string(),
                "stun_observed".to_string(),
            ),
            (
                "203.0.113.10:51820".to_string(),
                "peer_reflexive".to_string(),
            ),
        ]),
        candidate_generation: 0,
        candidates_expires_at_ms: None,
        handshake: String::new(),
        punch_at_ms: Some(77),
    };

    assert_eq!(
        peer_reflexive_endpoint_from_signal(&signal),
        Some("203.0.113.10:51820".to_string())
    );
}

#[test]
fn test_peer_reflexive_endpoint_falls_back_to_first_candidate() {
    let signal = SignalResponse {
        from_node_id: "alice".to_string(),
        signal_type: "peer_reflexive".to_string(),
        protocol_version: SIGNAL_REST_PROTOCOL_VERSION,
        candidates: vec!["198.51.100.1:40000".to_string()],
        session_id: None,
        probe_ephemeral_public_key: None,
        candidate_sources: HashMap::new(),
        candidate_generation: 0,
        candidates_expires_at_ms: None,
        handshake: String::new(),
        punch_at_ms: None,
    };

    assert_eq!(
        peer_reflexive_endpoint_from_signal(&signal),
        Some("198.51.100.1:40000".to_string())
    );
}

#[test]
fn signal_punch_time_uses_server_clock_offset() {
    assert_eq!(
        normalize_signal_punch_at(Some(11_500), Some(10_000), 50_000),
        Some(51_500)
    );
    assert_eq!(
        normalize_signal_punch_at(Some(9_000), Some(10_000), 50_000),
        Some(50_000)
    );
    assert_eq!(
        normalize_signal_punch_at(Some(11_500), None, 50_000),
        Some(11_500)
    );
    assert_eq!(normalize_signal_punch_at(None, Some(10_000), 50_000), None);
}

#[test]
fn candidate_expiry_uses_the_server_clock_offset() {
    assert_eq!(
        normalize_signal_candidate_expiry(Some(55_000), Some(10_000), 80_000),
        Some(125_000)
    );
    assert_eq!(
        normalize_signal_candidate_expiry(Some(9_000), Some(10_000), 80_000),
        Some(80_000)
    );
    assert_eq!(
        normalize_signal_candidate_expiry(Some(55_000), None, 80_000),
        Some(55_000)
    );
}

#[test]
fn candidate_generations_are_strictly_monotonic() {
    let first = next_candidate_generation();
    let second = next_candidate_generation();
    assert!(second > first);
}
