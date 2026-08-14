#[tokio::test]
async fn very_slow_confirmed_direct_is_not_duplicated_to_relay() {
    let config = test_config();
    let manager = PeerManager::new(config);
    let endpoint: SocketAddr = "8.8.8.8:51842".parse().unwrap();

    manager.add_peer(&test_peer("peer1", endpoint)).await;
    manager
        .record_direct_probe_success_with_latency(
            "peer1",
            endpoint,
            Some(Duration::from_millis(570)),
        )
        .await;
    manager.record_direct_success("peer1", Some(endpoint)).await;
    {
        let mut conns = manager.connections.write().await;
        let conn = conns.get_mut("peer1").unwrap();
        conn.direct_health.rtt_ewma_ms = Some(570);
        conn.direct_health.jitter_ms = Some(0);
        conn.direct_health.success_count = 100;
        conn.direct_health.failure_count = 0;
        conn.direct_health.consecutive_failures = 0;
    }

    let selected = manager.select_path_for_data("peer1", true, true).await;
    assert_eq!(selected.path, Some(NetworkPath::Direct));
    assert!(selected.direct_confirmed);
    assert!(!selected.relay_hedged);
    // A low score can still be historical probe telemetry.  The encrypted
    // validation ACK is the admission proof, so the selected path remains
    // Direct and is not reported as degraded until a current consent/ACK
    // failure is observed.
    assert_eq!(selected.reason_code, REASON_PATH_DIRECT_CONFIRMED);
    assert!(
        selected.direct_score.as_ref().unwrap().score
            < selected.relay_score.as_ref().unwrap().score
    );
}

#[tokio::test]
async fn path_selector_keeps_relay_until_direct_is_encrypted_confirmed() {
    let config = test_config();
    let manager = PeerManager::new(config);
    let endpoint: SocketAddr = "127.0.0.1:51839".parse().unwrap();

    manager.add_peer(&test_peer("peer1", endpoint)).await;
    manager.set_relay("peer1", "relay.test:443").await;
    manager
        .record_direct_probe_success_with_latency(
            "peer1",
            endpoint,
            Some(Duration::from_millis(18)),
        )
        .await;
    {
        let mut conns = manager.connections.write().await;
        let conn = conns.get_mut("peer1").unwrap();
        conn.relay_health.rtt_ewma_ms = Some(10);
        conn.relay_health.success_count = 5;
    }

    let selected = manager.select_path_for_data("peer1", true, true).await;
    assert_eq!(selected.path, Some(NetworkPath::Relay));
    assert_eq!(selected.reason_code, REASON_PATH_DIRECT_NOT_CONFIRMED);
    assert!(!selected.relay_hedged);
    assert!(!selected.direct_confirmed);
    assert!(
        selected.direct_score.as_ref().unwrap().score
            < selected.relay_score.as_ref().unwrap().score
    );
}

#[tokio::test]
async fn path_selector_keeps_relay_for_inbound_only_probe_without_ack() {
    let config = test_config();
    let manager = PeerManager::new(config);
    let endpoint: SocketAddr = "127.0.0.1:51840".parse().unwrap();

    manager.add_peer(&test_peer("peer1", endpoint)).await;
    manager.set_relay("peer1", "relay.test:443").await;
    manager.record_direct_probe_success("peer1", endpoint).await;

    let selected = manager.select_path_for_data("peer1", true, true).await;
    assert_eq!(selected.path, Some(NetworkPath::Relay));
    assert_eq!(selected.reason_code, REASON_PATH_DIRECT_NOT_CONFIRMED);
    assert!(!selected.direct_confirmed);

    let diagnostics = manager
        .diagnostics_with_path_selection(true, true, Duration::from_secs(5), None)
        .await;
    let pair = diagnostics[0].current_direct_pair.as_ref().unwrap();
    assert_eq!(diagnostics[0].active_path, None);
    assert_eq!(diagnostics[0].direct_type, DirectPathType::Probing);
    assert!(!diagnostics[0].is_relay);
    assert_eq!(pair.pair_state, CandidatePairState::Probing);
    assert!(!pair.nominated);
    assert!(!pair.selected);
    assert_ne!(pair.direct_type, DirectPathType::PublicUdp);
}

#[tokio::test]
async fn recent_public_probe_success_stays_trial_candidate_after_single_timeout() {
    let config = test_config();
    let manager = PeerManager::new(config);
    let stable_endpoint: SocketAddr = "8.8.8.8:60207".parse().unwrap();
    let birthday_endpoint: SocketAddr = "8.8.8.8:60183".parse().unwrap();

    manager.add_peer(&test_peer("peer1", stable_endpoint)).await;
    manager.set_relay("peer1", "relay.test:443").await;
    manager
        .add_candidates_with_sources(
            "peer1",
            &[stable_endpoint.to_string()],
            &HashMap::from([(stable_endpoint.to_string(), "peer_reflexive".to_string())]),
        )
        .await;
    manager
        .record_direct_probe_success_with_latency(
            "peer1",
            stable_endpoint,
            Some(Duration::from_millis(45)),
        )
        .await;

    {
        let mut conns = manager.connections.write().await;
        let conn = conns.get_mut("peer1").unwrap();
        conn.ensure_candidate_pair_with_source(birthday_endpoint, 0, CandidatePairSource::Birthday)
            .record_probing(None);
        let stable_pair = conn
            .candidate_pairs
            .iter_mut()
            .find(|pair| pair.remote_endpoint == stable_endpoint)
            .unwrap();
        stable_pair.record_failure(REASON_DIRECT_PROBE_FAILED, "one missed batch", None);
        conn.direct_health
            .record_failure(REASON_DIRECT_PROBE_FAILED, "one missed batch");
    }

    assert_eq!(
        manager.direct_endpoint_for_send("peer1").await,
        Some(stable_endpoint),
        "a recently successful public endpoint should stay ahead of speculative birthday ports"
    );

    let selected = manager.select_path_for_data("peer1", true, true).await;
    assert_eq!(selected.path, Some(NetworkPath::Relay));
    assert_eq!(selected.reason_code, REASON_PATH_DIRECT_NOT_CONFIRMED);
    assert_eq!(selected.direct_endpoint, None);
    assert!(!selected.relay_hedged);
    assert!(!selected.direct_confirmed);

    let diagnostics = manager.diagnostics().await;
    let current = diagnostics[0].current_direct_pair.as_ref().unwrap();
    assert_eq!(current.remote_endpoint, stable_endpoint.to_string());
    assert!(!current.nominated);
}

#[tokio::test]
async fn path_selector_does_not_treat_unselected_succeeded_pair_as_confirmed_direct() {
    let config = test_config();
    let manager = PeerManager::new(config);
    let selected_endpoint: SocketAddr = "8.8.8.8:12293".parse().unwrap();
    let trial_endpoint: SocketAddr = "1.1.1.1:41000".parse().unwrap();

    manager
        .add_peer(&test_peer("peer1", selected_endpoint))
        .await;
    manager
        .add_candidates_with_sources(
            "peer1",
            &[selected_endpoint.to_string(), trial_endpoint.to_string()],
            &HashMap::from([
                (selected_endpoint.to_string(), "stun_observed".to_string()),
                (trial_endpoint.to_string(), "peer_reflexive".to_string()),
            ]),
        )
        .await;
    manager
        .record_direct_probe_success_with_latency(
            "peer1",
            selected_endpoint,
            Some(Duration::from_millis(18)),
        )
        .await;
    manager
        .record_direct_success("peer1", Some(selected_endpoint))
        .await;
    manager
        .record_direct_probe_success_with_latency(
            "peer1",
            trial_endpoint,
            Some(Duration::from_millis(12)),
        )
        .await;
    manager
        .record_relay_success("peer1", "relay.test:443", false)
        .await;

    {
        let mut conns = manager.connections.write().await;
        let conn = conns.get_mut("peer1").unwrap();
        let pair = conn
            .candidate_pairs
            .iter_mut()
            .find(|pair| pair.remote_endpoint == selected_endpoint)
            .unwrap();
        pair.record_failure(REASON_DIRECT_KEEPALIVE_TIMEOUT, "selected pair stale", None);
    }

    let selection = manager.select_path_for_data("peer1", true, true).await;
    assert_eq!(selection.path, Some(NetworkPath::Relay));
    assert_eq!(selection.direct_endpoint, None);
    assert_eq!(selection.reason_code, REASON_PATH_DIRECT_NOT_CONFIRMED);
    assert!(!selection.direct_confirmed);
    assert!(!selection.relay_hedged);

    let diagnostics = manager
        .diagnostics_with_path_selection(true, true, Duration::from_secs(5), None)
        .await;
    assert_ne!(diagnostics[0].direct_type, DirectPathType::PublicUdp);
    assert!(!diagnostics[0].is_public_udp_direct);
    assert_eq!(diagnostics[0].direct_type, DirectPathType::Probing);
    assert_eq!(
        diagnostics[0]
            .current_direct_pair
            .as_ref()
            .unwrap()
            .pair_state,
        CandidatePairState::Succeeded
    );
    assert_eq!(
        diagnostics[0]
            .current_direct_pair
            .as_ref()
            .unwrap()
            .direct_type,
        DirectPathType::Probing
    );
}

#[tokio::test]
async fn direct_keepalive_targets_selected_pair_not_unselected_trial_pair() {
    let config = test_config();
    let manager = PeerManager::new(config);
    let selected_endpoint: SocketAddr = "8.8.8.8:12293".parse().unwrap();
    let trial_endpoint: SocketAddr = "1.1.1.1:41000".parse().unwrap();

    manager
        .add_peer(&test_peer("peer1", selected_endpoint))
        .await;
    manager
        .add_candidates_with_sources(
            "peer1",
            &[selected_endpoint.to_string(), trial_endpoint.to_string()],
            &HashMap::from([
                (selected_endpoint.to_string(), "stun_observed".to_string()),
                (trial_endpoint.to_string(), "peer_reflexive".to_string()),
            ]),
        )
        .await;
    manager
        .record_direct_probe_success_with_latency(
            "peer1",
            selected_endpoint,
            Some(Duration::from_millis(18)),
        )
        .await;
    manager
        .record_direct_success("peer1", Some(selected_endpoint))
        .await;
    manager
        .record_direct_probe_success_with_latency(
            "peer1",
            trial_endpoint,
            Some(Duration::from_millis(12)),
        )
        .await;

    assert_eq!(
        manager.direct_endpoints().await,
        vec![("peer1".to_string(), selected_endpoint)]
    );

    assert!(
        manager
            .record_direct_keepalive_timeout_for_generation("peer1", selected_endpoint, 0,)
            .await
    );
    assert_eq!(
        manager.direct_endpoint_for_send("peer1").await,
        Some(trial_endpoint)
    );
    assert_eq!(
        manager.direct_endpoints().await,
        vec![("peer1".to_string(), selected_endpoint)]
    );
}

#[tokio::test]
async fn path_selection_timeline_records_only_real_changes() {
    let config = test_config();
    let manager = PeerManager::new(config);
    let endpoint: SocketAddr = "127.0.0.1:51837".parse().unwrap();

    manager.add_peer(&test_peer("peer1", endpoint)).await;

    let first = manager.select_path_for_data("peer1", true, true).await;
    assert_eq!(first.path, Some(NetworkPath::Relay));
    let repeated = manager.select_path_for_data("peer1", true, true).await;
    assert_eq!(repeated.path, Some(NetworkPath::Relay));

    let diagnostics = manager.diagnostics().await;
    assert_eq!(diagnostics[0].path_events.len(), 1);
    assert_eq!(diagnostics[0].path_events[0].previous_path, None);
    assert_eq!(
        diagnostics[0].path_events[0].selected_path,
        Some(NetworkPath::Relay)
    );
    assert_eq!(
        diagnostics[0].path_events[0].reason_code,
        REASON_PATH_DIRECT_NOT_CONFIRMED
    );

    manager
        .record_direct_probe_success_with_latency("peer1", endpoint, Some(Duration::from_millis(9)))
        .await;
    manager.record_direct_success("peer1", Some(endpoint)).await;
    let direct = manager.select_path_for_data("peer1", true, true).await;
    assert_eq!(direct.path, Some(NetworkPath::Direct));

    let diagnostics = manager.diagnostics().await;
    assert_eq!(diagnostics[0].path_events.len(), 2);
    assert_eq!(
        diagnostics[0].path_events[1].previous_path,
        Some(NetworkPath::Relay)
    );
    assert_eq!(
        diagnostics[0].path_events[1].selected_path,
        Some(NetworkPath::Direct)
    );
    assert_eq!(
        diagnostics[0].path_events[1].reason_code,
        REASON_PATH_DIRECT_CONFIRMED
    );

    let json = serde_json::to_value(&diagnostics[0]).unwrap();
    assert_eq!(json["path_events"].as_array().unwrap().len(), 2);
    assert!(json["path_events"][1]["direct_score"]["score"].is_i64());
}

#[tokio::test]
async fn repeated_relay_fallback_selection_records_single_path_event() {
    let config = test_config();
    let manager = PeerManager::new(config);
    let endpoint: SocketAddr = "203.0.113.10:51839".parse().unwrap();
    manager.add_peer(&test_peer("peer1", endpoint)).await;
    manager.set_relay("peer1", "relay.test:443").await;

    for _ in 0..5 {
        let selection = manager.select_path_for_data("peer1", true, true).await;
        assert_eq!(selection.path, Some(NetworkPath::Relay));
    }
    let diagnostics = manager.diagnostics().await;
    assert_eq!(diagnostics[0].path_events.len(), 1);
    assert_eq!(
        diagnostics[0].path_events[0].selected_path,
        Some(NetworkPath::Relay)
    );
    assert_eq!(
        diagnostics[0].path_events[0].relay_server.as_deref(),
        Some("relay.test:443")
    );

    manager.set_relay("peer1", "relay2.test:443").await;
    for _ in 0..3 {
        let selection = manager.select_path_for_data("peer1", true, true).await;
        assert_eq!(selection.path, Some(NetworkPath::Relay));
    }
    let diagnostics = manager.diagnostics().await;
    assert_eq!(diagnostics[0].path_events.len(), 2);
    assert_eq!(
        diagnostics[0].path_events[1].relay_server.as_deref(),
        Some("relay2.test:443")
    );
}

#[tokio::test]
async fn repeated_relay_success_records_relay_fallback_selected_once() {
    let config = test_config();
    let manager = PeerManager::new(config);
    let endpoint: SocketAddr = "203.0.113.10:51839".parse().unwrap();
    manager.add_peer(&test_peer("peer1", endpoint)).await;

    manager
        .record_relay_success("peer1", "relay.test:443", true)
        .await;
    manager
        .record_relay_success("peer1", "relay.test:443", true)
        .await;
    manager
        .record_relay_success("peer1", "relay.test:443", true)
        .await;
    {
        let conn = manager.get_connection("peer1").await.unwrap();
        assert_eq!(conn.state, ConnectionState::Relay);
        assert_eq!(
            conn.direct_events
                .iter()
                .filter(|event| event.stage == "relay_fallback_selected")
                .count(),
            1
        );
    }

    manager
        .record_relay_success("peer1", "relay2.test:443", true)
        .await;
    {
        let conn = manager.get_connection("peer1").await.unwrap();
        assert_eq!(conn.relay_server.as_deref(), Some("relay2.test:443"));
        assert_eq!(
            conn.direct_events
                .iter()
                .filter(|event| event.stage == "relay_fallback_selected")
                .count(),
            2
        );
    }
}
