#[test]
fn room_diagnostics_separate_lease_state_from_transport_state() {
    let auth = RoomAuthorization::new("room-diagnostics");
    assert_eq!(
        auth.diagnostics("10.21.1.2").unwrap().authorization_state,
        "missing"
    );
    assert!(auth.replace(
        "10.21.1.2",
        [("b".into(), "10.21.1.3".into())],
        Instant::now(),
        30
    ));
    assert_eq!(
        auth.diagnostics("10.21.1.2").unwrap().authorization_state,
        "valid"
    );
    assert_eq!(
        auth.diagnostics("10.21.2.2").unwrap().authorization_state,
        "local_ip_mismatch"
    );
    auth.snapshot.lock().unwrap().as_mut().unwrap().expires_at =
        Instant::now() - Duration::from_millis(1);
    assert_eq!(
        auth.diagnostics("10.21.1.2").unwrap().authorization_state,
        "expired"
    );
    assert_eq!(
        auth.denial_reason("b", "10.21.1.3", "10.21.1.2"),
        Some(RoomDropReason::AuthorizationExpired)
    );
    assert!(auth.send_permit("b", "10.21.1.3", "10.21.1.2").is_none());
    assert!(!auth.allows("b", "10.21.1.3", "10.21.1.2"));
}

#[test]
fn room_diagnostics_count_attributable_drops_and_bound_untrusted_peer_ids() {
    let auth = RoomAuthorization::new("room-drops");
    assert!(auth.replace(
        "10.21.1.2",
        [("b".into(), "10.21.1.3".into())],
        Instant::now(),
        30
    ));
    for _ in 0..1000 {
        auth.record_drop(
            RoomDropReason::PeerIpMismatch,
            "rx",
            &"x".repeat(1000),
            "10.21.2.3",
            "10.21.1.2",
        );
        auth.record_packet("not-in-roster", true);
    }
    let diagnostics = auth.diagnostics("10.21.1.2").unwrap();
    assert_eq!(diagnostics.drops["peer_ip_mismatch"], 1000);
    assert_eq!(diagnostics.last_drop.unwrap().peer_id.len(), 128);
    assert!(auth.traffic.lock().unwrap().peers.is_empty());
    assert_eq!(
        auth.denial_reason("c", "10.21.1.3", "10.21.1.2"),
        Some(RoomDropReason::PeerMissing)
    );
    assert_eq!(
        auth.denial_reason("b", "10.21.1.4", "10.21.1.2"),
        Some(RoomDropReason::PeerIpMismatch)
    );
    assert_eq!(
        auth.denial_reason("b", "10.21.1.3", "192.168.0.2"),
        Some(RoomDropReason::LocalIpMismatch)
    );
}

#[test]
fn room_renewal_retains_counters_but_readdress_cannot_inherit_traffic_evidence() {
    let auth = RoomAuthorization::new("room-renewal");
    let roster = || [("b".into(), "10.21.1.3".into())];
    assert!(auth.replace("10.21.1.2", roster(), Instant::now(), 30));
    let old_permit = auth.send_permit("b", "10.21.1.3", "10.21.1.2").unwrap();
    auth.record_packet("b", false);
    auth.record_packet("b", true);
    assert!(auth.replace("10.21.1.2", roster(), Instant::now(), 30));
    assert_eq!(
        auth.diagnostics("10.21.1.2").unwrap().peers[0].rx_delivered_packets,
        1
    );
    assert!(auth.replace(
        "10.21.1.2",
        [("b".into(), "10.21.1.4".into())],
        Instant::now(),
        30
    ));
    assert!(!old_permit.is_valid());
    let diagnostics = auth.diagnostics("10.21.1.2").unwrap();
    assert_eq!(diagnostics.peers[0].virtual_ip, "10.21.1.4");
    assert_eq!(diagnostics.peers[0].rx_delivered_packets, 0);
    assert_eq!(diagnostics.peers[0].tx_queued_packets, 0);
    auth.invalidate();
    assert_eq!(
        auth.diagnostics("10.21.1.2").unwrap().authorization_state,
        "missing"
    );
}

#[test]
fn room_re_registration_cannot_silently_retain_an_old_tun_address() {
    let mut config =
        crate::config::Config::generate_default("http://ctrl.test", "room-test").unwrap();
    config.network.virtual_ip = "10.21.1.2".into();
    config.network.cidr = "10.21.1.0/24".into();
    assert!(!registration_requires_room_restart(
        &config,
        Some(&config.node.node_id),
        "10.21.1.2",
        Some("10.21.1.0/24")
    ));
    assert!(registration_requires_room_restart(
        &config,
        Some(&config.node.node_id),
        "10.21.1.9",
        Some("10.21.1.0/24")
    ));
    assert!(registration_requires_room_restart(
        &config,
        Some("replacement"),
        "10.21.1.2",
        Some("10.21.1.0/24")
    ));
    assert!(registration_requires_room_restart(
        &config,
        None,
        "10.21.1.2",
        Some("10.21.2.0/24")
    ));
    config.network.network_id = "default".into();
    assert!(!registration_requires_room_restart(
        &config,
        Some("replacement"),
        "10.20.0.5",
        None
    ));
}
