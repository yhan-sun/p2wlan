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
        to_node_id: None,
        signal_seq: None,
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
        sender_public_key: None,
        id: None,
        delivery_token: None,
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
        to_node_id: None,
        signal_seq: None,
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
        sender_public_key: None,
        id: None,
        delivery_token: None,
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
    crate::incarnation::set_local_incarnation(1_742_987_654_321);
    let first = next_candidate_generation().unwrap();
    let second = next_candidate_generation().unwrap();
    assert!(second > first);
}

#[test]
fn candidate_generations_embed_the_incarnation_in_the_high_bits() {
    let incarnation = 1_742_987_654_321;
    let first = next_candidate_generation_for_incarnation(incarnation, 0).unwrap();
    let second = next_candidate_generation_for_incarnation(incarnation, first).unwrap();
    assert!(second > first);
    // The incarnation-encoded space lives above the legacy wall-clock space.
    assert!(first > 1_752_000_000_000);
    // Clock rollback between calls must never produce a smaller generation.
    let after_rollback = next_candidate_generation_for_incarnation(incarnation, second).unwrap();
    assert!(after_rollback > second);

    // A newer incarnation dominates every counter of an older incarnation:
    // a late request from an old process (lower high bits) compares smaller
    // even when its low counter wrapped higher.
    let old_process_late = CANDIDATE_GENERATION_INCARNATION_FLAG
        | (1_742_987_654_321u64 << CANDIDATE_GENERATION_COUNTER_BITS)
        | CANDIDATE_GENERATION_COUNTER_MASK;
    let new_process_first =
        next_candidate_generation_for_incarnation(1_742_987_654_322, 0).unwrap();
    assert!(new_process_first > old_process_late);
    assert_eq!(
        candidate_generation_incarnation(first),
        Some(incarnation)
    );
    assert_eq!(candidate_generation_incarnation(7), None);
}

#[test]
fn candidate_generation_incarnation_values_stay_within_positive_int64() {
    let incarnation = 1_742_987_654_321;
    let value = next_candidate_generation_for_incarnation(incarnation, 0).unwrap();
    assert!(value < i64::MAX as u64);
    // The most extreme encodable generation also stays within i64.
    let value =
        next_candidate_generation_for_incarnation(incarnation, CANDIDATE_GENERATION_COUNTER_MASK - 1)
            .unwrap();
    assert!(value < i64::MAX as u64);
    // The maximum encodable incarnation still fits the signed int64 JSON path
    // (the all-ones 63-bit pattern is exactly i64::MAX).
    let max_incarnation = (1u64 << CANDIDATE_GENERATION_INCARNATION_BITS) - 1;
    let value =
        next_candidate_generation_for_incarnation(max_incarnation, CANDIDATE_GENERATION_COUNTER_MASK - 1)
            .unwrap();
    assert!(value <= i64::MAX as u64);
}

#[test]
fn candidate_generation_degrades_to_legacy_zero_when_incarnation_outgrows_field() {
    // A wall-clock-seeded incarnation above the 41-bit field limit must
    // degrade to the legacy no-metadata generation (0), never be masked
    // (masking would let a boot from the year 2040 encode as a *smaller*
    // high half than a boot today) and never fail the whole signal: ordinary
    // offer/answer signaling keeps working; only fresh prediction is
    // disabled (the fresh label path refuses to encode it).
    assert_eq!(
        next_candidate_generation_for_incarnation(1u64 << CANDIDATE_GENERATION_INCARNATION_BITS, 0)
            .unwrap(),
        0,
        "an out-of-range incarnation must degrade to the legacy no-metadata value instead of failing signaling"
    );
    assert_eq!(
        next_candidate_generation_for_incarnation(1u64 << CANDIDATE_GENERATION_INCARNATION_BITS, 7)
            .unwrap(),
        0,
        "the degradation is independent of the previous generation"
    );
    // Just below the limit still encodes.
    assert!(
        next_candidate_generation_for_incarnation(
            (1u64 << CANDIDATE_GENERATION_INCARNATION_BITS) - 1,
            0,
        )
        .is_ok()
    );
    // The encodability gate used by the fresh label path agrees.
    assert!(!super::incarnation_fits_candidate_generation_encoding(
        1u64 << CANDIDATE_GENERATION_INCARNATION_BITS
    ));
    assert!(!super::incarnation_fits_candidate_generation_encoding(0));
    assert!(super::incarnation_fits_candidate_generation_encoding(
        (1u64 << CANDIDATE_GENERATION_INCARNATION_BITS) - 1
    ));
}

#[test]
fn candidate_generation_refuses_to_wrap_the_per_boot_counter() {
    let incarnation = 1_742_987_654_321;
    // The counter at its field maximum refuses to advance (wrapping to 0
    // would collide with the boot's first generation).
    assert!(matches!(
        next_candidate_generation_for_incarnation(incarnation, CANDIDATE_GENERATION_COUNTER_MASK),
        Err(CandidateGenerationError::CounterExhausted(_))
    ));
    // One below the maximum still advances.
    let value =
        next_candidate_generation_for_incarnation(incarnation, CANDIDATE_GENERATION_COUNTER_MASK - 1)
            .unwrap();
    assert_eq!(value & CANDIDATE_GENERATION_COUNTER_MASK, CANDIDATE_GENERATION_COUNTER_MASK);
}

/// An untrustworthy incarnation (0: corrupt state, lost state, or no config
/// path) must NEVER be encoded under the flag: a flagged value with a zero
/// incarnation field is lower than every real incarnation-encoded value, so
/// a receiver whose high-water saw a real incarnation would judge this
/// boot's ordinary candidates stale forever.  The compat value is 0 — the
/// legacy "no ordering metadata" value the receiver's stale check never
/// rejects (`candidate_generation != 0` gates the comparison).
#[test]
fn candidate_generation_with_untrustworthy_incarnation_is_legacy_compat_zero() {
    let value = next_candidate_generation_for_incarnation(0, 0).unwrap();
    assert_eq!(value, 0, "incarnation 0 must degrade to the legacy no-metadata value");
    assert_eq!(
        value & CANDIDATE_GENERATION_INCARNATION_FLAG,
        0,
        "the compat value must never carry the incarnation flag"
    );
    // The process-level entry point is a thin wrapper over the pure rule
    // (`next_candidate_generation_for_incarnation(local_incarnation(), ..)`),
    // so a daemon booted without a trustworthy incarnation never emits
    // flagged values.
    // Once a real incarnation is available again the flagged space resumes
    // from a value that dominates every legacy generation the boot sent.
    let resumed = next_candidate_generation_for_incarnation(1_742_987_654_321, 0).unwrap();
    assert!(resumed > 1_752_000_000_000, "the resumed incarnation space must be strictly above legacy values");
}

/// Old-client -> new-client and new-client -> old-client ordering semantics:
/// a legacy (pre-incarnation) wall-clock generation sent by an old client is
/// always below the incarnation-encoded space, so a NEW client that already
/// recorded an incarnation-encoded generation never accepts the old
/// client's stale numbers — while the old client's fresh predictions (which
/// carry no incarnation) simply never preempt a real prediction.
#[test]
fn legacy_generations_never_cross_the_incarnation_flag() {
    // The highest legacy wall-clock value a pre-incarnation client can send
    // (~year 2250 in ms) stays strictly below every incarnation-encoded
    // value, including the very first one of a fresh incarnation.
    let legacy_max = 9_999_999_999_999u64; // legacy space is well below 2^62
    let first_encoded = next_candidate_generation_for_incarnation(1_742_987_654_321, 0).unwrap();
    assert!(legacy_max < CANDIDATE_GENERATION_INCARNATION_FLAG);
    assert!(legacy_max < first_encoded);
    // Downgrade: a NEW client receiving from an OLD client (legacy values)
    // after having recorded an incarnation-encoded high-water must keep
    // judging the legacy numbers stale — the old client's compat generation
    // 0 is the only one that still applies.
    let old_client_value = 1_752_000_000_000u64;
    assert!(old_client_value < first_encoded);
}
