#[test]
fn remote_nat_profile_generation_is_monotonic_and_fresh() {
    let mut connection = PeerConnection::new("peer-nat-profile", "10.20.0.2");
    let current =
        "p2v2:m=address_or_port_dependent;a=linear;d=4;c=90;f=address_dependent;h=unknown;g=7";
    let stale =
        "p2v2:m=address_or_port_dependent;a=random;d=?;c=40;f=address_dependent;h=unknown;g=6";
    let endpoint = Some("203.0.113.20:41000".parse().unwrap());

    assert!(connection.update_remote_nat_profile(current, endpoint));
    assert_eq!(
        connection
            .remote_nat_profile
            .as_ref()
            .and_then(|profile| profile.generation),
        Some(7)
    );
    assert!(connection.remote_nat_profile_is_fresh());

    assert!(!connection.update_remote_nat_profile(stale, endpoint));
    let profile = connection.remote_nat_profile.as_ref().unwrap();
    assert_eq!(profile.generation, Some(7));
    assert!(profile.capabilities.prediction_candidate);
}

#[test]
fn legacy_remote_nat_label_cannot_downgrade_versioned_profile() {
    let mut connection = PeerConnection::new("peer-legacy-nat", "10.20.0.3");
    let versioned = "p2v2:m=open;a=stable;d=?;c=80;f=endpoint_independent;h=unknown;g=2";
    let legacy = "p2v2:m=address_or_port_dependent;a=random;d=?;c=20;f=address_dependent;h=unknown";

    assert!(connection.update_remote_nat_profile(versioned, None));
    assert!(!connection.update_remote_nat_profile(legacy, None));
    assert_eq!(
        connection
            .remote_nat_profile
            .as_ref()
            .and_then(|profile| profile.generation),
        Some(2)
    );
}

#[test]
fn same_generation_real_observation_renews_freshness_but_cached_or_stale_metadata_does_not() {
    let mut connection = PeerConnection::new("peer-observation-freshness", "10.20.0.31");
    let base =
        "p2v2:m=address_or_port_dependent;a=linear;d=4;c=90;f=address_dependent;h=unknown;g=7;l=11";
    let endpoint = Some("203.0.113.31:41000".parse().unwrap());

    assert!(connection.update_remote_nat_profile(&format!("{base};o=1"), endpoint));
    connection
        .remote_nat_profile
        .as_mut()
        .unwrap()
        .received_at_ms = nat_profile_now_ms().saturating_sub(61_000);
    assert!(
        !connection.remote_nat_profile_is_fresh(),
        "the test must begin with an expired observation"
    );

    // A heartbeat replays the exact cached label. It is accepted as metadata
    // but deliberately retains the old timestamp.
    assert!(connection.update_remote_nat_profile(&format!("{base};o=1"), endpoint));
    assert!(
        !connection.remote_nat_profile_is_fresh(),
        "repeated cached observation must not manufacture freshness"
    );

    // Neither an older observation nor a missing observation fence may erase
    // the accepted o=1 profile.
    assert!(!connection.update_remote_nat_profile(&format!("{base};o=0"), endpoint));
    assert!(!connection.update_remote_nat_profile(base, endpoint));
    assert_eq!(
        connection
            .remote_nat_profile
            .as_ref()
            .and_then(|profile| profile.observation_sequence),
        Some(1)
    );

    assert!(connection.update_remote_nat_profile(&format!("{base};o=2"), endpoint));
    assert!(
        connection.remote_nat_profile_is_fresh(),
        "a newer real observation at the same capability generation must renew freshness"
    );

    // An older registration cannot override a newer profile, even if it
    // carries an apparently newer local observation counter.
    let stale_lifecycle = base.replacen("l=11", "l=10", 1);
    assert!(!connection.update_remote_nat_profile(&format!("{stale_lifecycle};o=99"), endpoint));
    assert_eq!(
        connection
            .remote_nat_profile
            .as_ref()
            .and_then(|profile| profile.registration_lifecycle),
        Some(11)
    );
}

#[test]
fn remote_profile_is_invalidated_by_candidate_epoch_and_rebound_only_by_hh1_context() {
    let mut connection = PeerConnection::new("peer-profile-context", "10.20.0.4");
    let profile =
        "p2v2:m=address_or_port_dependent;a=linear;d=4;c=90;f=address_dependent;h=unknown;g=7";

    assert!(connection.update_remote_nat_profile(profile, None));
    assert!(connection.remote_nat_profile_matches_candidate_epoch());

    connection.mark_remote_transport_handover(
        1,
        PeerSessionGeneration::for_test(1),
        "test remote handover",
    );
    assert!(!connection.remote_nat_profile_matches_candidate_epoch());
    assert!(!connection.bind_remote_nat_profile_to_candidate_epoch(8));
    assert!(connection.bind_remote_nat_profile_to_candidate_epoch(7));
    assert!(connection.remote_nat_profile_matches_candidate_epoch());
}

#[tokio::test]
async fn remote_nat_profile_generation_advance_reopens_recovery_budget_and_zero_send_does_not_burn_network_failures(
) {
    let manager = PeerManager::new(test_config());
    let mut info = PeerInfo {
        node_id: "peer-recovery".to_string(),
        device_name: "test-device".to_string(),
        app_version: "1.0.0".to_string(),
        public_key: "pk-recovery-1".to_string(),
        endpoint: "203.0.113.50:50000".to_string(),
        nat_type:
            "p2v2:m=address_or_port_dependent;a=linear;d=4;c=90;f=address_dependent;h=unknown;g=1"
                .to_string(),
        virtual_ip: "10.20.0.50".to_string(),
        online: true,
        last_seen: 0,
        relay_rtt_ms: None,
    };
    manager.add_peer(&info).await;
    manager.recovery_epoch_admit("peer-recovery").await;

    // Exhaust remaining probe credit, plan builds and sessions
    while manager
        .try_consume_recovery_probe_credit("peer-recovery")
        .await
    {}
    for _ in 0..RECOVERY_EPOCH_PLAN_BUILDS {
        assert!(
            manager
                .try_consume_recovery_plan_build("peer-recovery")
                .await
        );
    }
    for _ in 0..RECOVERY_EPOCH_SESSIONS {
        assert!(manager.try_consume_recovery_session("peer-recovery").await);
    }

    // Zero-send session occurs: all candidates rejected by budget.
    manager
        .record_zero_send_recovery_session(
            "peer-recovery",
            10,
            10,
            10,
            "all_probes_rejected_by_budget",
        )
        .await;

    // 1. Recovery budget is frozen.
    assert!(manager.recovery_budget_frozen("peer-recovery").await);

    // 2. Failure count and consecutive_failures are NOT incremented!
    let conn = manager.get_connection("peer-recovery").await.unwrap();
    assert_eq!(
        conn.direct_health.failure_count, 0,
        "sent=0 must not increment network failure count"
    );
    assert_eq!(
        conn.direct_health.consecutive_failures, 0,
        "sent=0 must not increment consecutive failures"
    );

    // 3. Stale or duplicate remote profile update does NOT reopen the recovery budget.
    info.nat_type =
        "p2v2:m=address_or_port_dependent;a=linear;d=4;c=90;f=address_dependent;h=unknown;g=1"
            .to_string();
    manager.add_peer(&info).await;
    assert!(
        manager.recovery_budget_frozen("peer-recovery").await,
        "duplicate profile generation must not reopen budget"
    );

    // 4. Authoritative generation advance (g=2) reopens the recovery budget with small retry credit!
    info.nat_type =
        "p2v2:m=address_or_port_dependent;a=linear;d=4;c=90;f=address_dependent;h=unknown;g=2"
            .to_string();
    manager.add_peer(&info).await;
    assert!(
        !manager.recovery_budget_frozen("peer-recovery").await,
        "generation advance must reopen recovery budget"
    );

    let report = manager
        .recovery_epoch_work_budget_report("peer-recovery")
        .await
        .expect("epoch must exist");
    assert_eq!(
        report.probe_credit_remaining,
        RECOVERY_EVIDENCE_RETRY_CREDIT
    );
    assert_eq!(
        report.plan_builds_remaining,
        RECOVERY_EVIDENCE_REGRANT_PLAN_BUILDS
    );
    assert_eq!(
        report.sessions_remaining,
        RECOVERY_EVIDENCE_REGRANT_SESSIONS
    );
    assert_eq!(report.zero_send_streak, 0);
    assert_eq!(report.stage, RecoveryStage::Initial);
}

#[tokio::test]
async fn newer_same_generation_nat_observation_reopens_only_the_bounded_recovery_epoch() {
    let manager = PeerManager::new(test_config());
    let mut info = PeerInfo {
        node_id: "peer-observation-recovery".to_string(),
        device_name: "test-device".to_string(),
        app_version: "1.0.0".to_string(),
        public_key: "pk-observation-recovery".to_string(),
        endpoint: "203.0.113.51:50000".to_string(),
        nat_type: "p2v2:m=address_or_port_dependent;a=linear;d=4;c=90;f=address_dependent;h=unknown;g=1;o=1;l=3".to_string(),
        virtual_ip: "10.20.0.51".to_string(),
        online: true,
        last_seen: 0,
        relay_rtt_ms: None,
    };
    manager.add_peer(&info).await;
    manager.recovery_epoch_admit(&info.node_id).await;
    while manager
        .try_consume_recovery_probe_credit(&info.node_id)
        .await
    {}
    for _ in 0..RECOVERY_EPOCH_PLAN_BUILDS {
        assert!(manager.try_consume_recovery_plan_build(&info.node_id).await);
    }
    for _ in 0..RECOVERY_EPOCH_SESSIONS {
        assert!(manager.try_consume_recovery_session(&info.node_id).await);
    }
    manager
        .record_zero_send_recovery_session(
            &info.node_id,
            10,
            10,
            10,
            "all_probes_rejected_by_budget",
        )
        .await;
    assert!(manager.recovery_budget_frozen(&info.node_id).await);

    // A replayed heartbeat o=1 cannot unfreeze work.
    manager.add_peer(&info).await;
    assert!(manager.recovery_budget_frozen(&info.node_id).await);

    // o=2 is a new successful remote STUN observation at unchanged g=1. It
    // grants only the existing evidence-bound recovery allowance; it does not
    // rotate a peer session or create an unlimited retry loop.
    info.nat_type = info.nat_type.replacen("o=1", "o=2", 1);
    manager.add_peer(&info).await;
    let report = manager
        .recovery_epoch_work_budget_report(&info.node_id)
        .await
        .expect("epoch must exist");
    assert_eq!(
        report.probe_credit_remaining,
        RECOVERY_EVIDENCE_RETRY_CREDIT
    );
    assert_eq!(
        report.plan_builds_remaining,
        RECOVERY_EVIDENCE_REGRANT_PLAN_BUILDS
    );
    assert_eq!(
        report.sessions_remaining,
        RECOVERY_EVIDENCE_REGRANT_SESSIONS
    );
}
