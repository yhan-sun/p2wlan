#[test]
fn capabilities_require_both_explicit_bits_and_never_infer_app_version() {
    assert!(PeerCapabilities::current().supports_hh2());
    let legacy: PeerInfo = serde_json::from_value(serde_json::json!({
        "node_id": "legacy", "app_version": "999.0.0", "public_key": "key",
        "endpoint": "", "nat_type": "unknown", "virtual_ip": "10.20.0.2",
        "online": true, "last_seen": 1
    }))
    .unwrap();
    assert!(!legacy.capabilities.supports_hh2());
    assert_eq!(legacy.registration_seq, 0);
    for json in [
        serde_json::json!({}),
        serde_json::json!({"hh2_pair_nomination": true}),
        serde_json::json!({"hh2_plan_v2": true}),
    ] {
        let capabilities: PeerCapabilities = serde_json::from_value(json).unwrap();
        assert!(!capabilities.supports_hh2());
    }
    assert!(PeerCapabilities {
        hh2_pair_nomination: true,
        hh2_plan_v2: true,
    }
    .supports_hh2());
    let mut upgraded = legacy.clone();
    upgraded.capabilities = PeerCapabilities::current();
    upgraded.registration_seq = 2;
    assert!(peer_metadata_changed(&legacy, &upgraded));
    let payload = register_device_payload_with_incarnation(&test_config(), 42);
    assert_eq!(
        payload["capabilities"],
        serde_json::to_value(PeerCapabilities::current()).unwrap()
    );
}

#[tokio::test]
async fn local_hh2_eligibility_requires_current_server_accepted_registration() {
    let client = ControlClient::disabled_for_test();
    assert!(client.local_registration_seq().is_none());
    client.set_local_registration_for_test(Some(7), PeerCapabilities::default());
    assert_eq!(client.local_registration_seq(), Some(7));
    assert!(!client.local_supports_hh2());
    client.set_local_registration_for_test(
        Some(8),
        PeerCapabilities {
            hh2_pair_nomination: true,
            hh2_plan_v2: true,
        },
    );
    assert_eq!(client.local_hh2_registration_seq(), Some(8));
    assert!(client.local_supports_hh2());
    client.set_local_registration_for_test(None, PeerCapabilities::default());
    assert!(client.local_registration_seq().is_none());
    assert!(!client.local_supports_hh2());
    client.set_local_registration_for_test(
        Some(0),
        PeerCapabilities {
            hh2_pair_nomination: true,
            hh2_plan_v2: true,
        },
    );
    assert!(client.local_hh2_registration_seq().is_none());
    client.set_local_registration_for_test(None, PeerCapabilities::default());
    assert!(client.local_registration_seq().is_none());
}

#[tokio::test]
async fn legacy_server_features_never_authorize_local_peer_capabilities() {
    // Existing server feature flags are a different field and wire type from
    // the accepted peer declaration. A rolling upgrade must preserve both.
    let response: RegisterDeviceResponse = serde_json::from_value(serde_json::json!({
        "success": true,
        "node_id": "local",
        "virtual_ip": "10.20.0.1",
        "registration_seq": 9,
        "registration_incarnation": 42,
        "capabilities": ["hh2_pair_nomination", "hh2_plan_v2"]
    }))
    .unwrap();
    assert!(!response.accepted_peer_capabilities.peer.supports_hh2());
    let client = ControlClient::disabled_for_test();
    client.set_local_registration_for_test(Some(8), PeerCapabilities::current());
    assert!(client.local_supports_hh2());
    client.set_local_registration_for_test(
        response.registration_seq,
        response.accepted_peer_capabilities.peer,
    );
    assert_eq!(client.local_registration_seq(), Some(9));
    assert!(!client.local_supports_hh2());
}
