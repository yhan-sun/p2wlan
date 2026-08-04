#[tokio::test]
async fn direct_probe_targets_due_respects_backoff_without_false_probing() {
    let config = test_config();
    let manager = PeerManager::new(config);
    let endpoint: SocketAddr = "127.0.0.1:51834".parse().unwrap();

    manager.add_peer(&test_peer("peer1", endpoint)).await;

    let first_targets = manager
        .direct_probe_targets_due(Duration::from_secs(5))
        .await;
    assert_eq!(first_targets.len(), 1);
    assert_eq!(first_targets[0].peer_id, "peer1");
    assert_eq!(first_targets[0].candidates, vec![endpoint]);

    manager
        .record_direct_failure_with_code("peer1", REASON_DIRECT_PROBE_FAILED, "no ACK")
        .await;
    manager
        .record_direct_failure_with_code("peer1", REASON_DIRECT_PROBE_FAILED, "still no ACK")
        .await;

    let suppressed = manager
        .direct_probe_targets_due(Duration::from_secs(5))
        .await;
    assert!(suppressed.is_empty());

    let diagnostics = manager
        .diagnostics_with_path_selection(true, true, Duration::from_secs(5), None)
        .await;
    assert_eq!(diagnostics[0].direct_retry_after_ms, Some(10_000));
    assert!(diagnostics[0].direct_retry_remaining_ms.unwrap() > 0);
    assert_eq!(diagnostics[0].direct.failure_count, 2);
    assert!(diagnostics[0].candidate_pairs.iter().all(|pair| {
        pair.state != CandidatePairState::Probing
            && pair.failure_count == 2
            && pair.last_error_code.as_deref() == Some(REASON_DIRECT_PROBE_FAILED)
    }));
}

#[tokio::test]
async fn confirmed_direct_ignores_background_probe_batch_timeout() {
    let config = test_config();
    let manager = PeerManager::new(config);
    let endpoint: SocketAddr = "8.8.8.8:51844".parse().unwrap();

    manager.add_peer(&test_peer("peer1", endpoint)).await;
    manager
        .record_direct_probe_success_with_latency("peer1", endpoint, Some(Duration::from_millis(42)))
        .await;
    manager.record_direct_success("peer1", Some(endpoint)).await;
    let generation = manager.current_network_generation().await;

    assert!(
        manager
            .record_direct_probe_batch_failure_for_generation(
                "peer1",
                generation,
                "no matched direct probe ACK after 72 background UDP retry probes",
            )
            .await
    );

    let conn = manager.get_connection("peer1").await.unwrap();
    assert_eq!(conn.state, ConnectionState::Direct);
    assert_eq!(conn.direct_generation, generation);
    assert_eq!(conn.direct_health.consecutive_failures, 0);
    assert_eq!(conn.direct_health.last_error_code, None);
    let pair = conn
        .candidate_pairs
        .iter()
        .find(|pair| pair.local_generation == generation && pair.remote_endpoint == endpoint)
        .expect("selected direct pair should remain present");
    assert_eq!(pair.state, CandidatePairState::Selected);
    assert_eq!(pair.consecutive_failures, 0);
    assert!(conn
        .direct_events
        .iter()
        .any(|event| event.stage == "direct_probe_batch_timeout_ignored"));
    assert!(
        manager
            .should_use_direct_for_data("peer1", true, true)
            .await
    );

    for _ in 0..DIRECT_KEEPALIVE_FAILURE_THRESHOLD {
        manager
            .record_direct_keepalive_timeout_for_generation("peer1", endpoint, generation)
            .await;
    }
    let conn = manager.get_connection("peer1").await.unwrap();
    assert_eq!(conn.state, ConnectionState::FallbackToRelay);
    assert_eq!(
        conn.direct_health.last_error_code.as_deref(),
        Some(REASON_DIRECT_KEEPALIVE_TIMEOUT)
    );
}

#[tokio::test]
async fn probe_batch_timeout_marks_probed_transient_birthday_pairs_failed() {
    let config = test_config();
    let manager = PeerManager::new(config);
    let signaled_endpoint: SocketAddr = "8.8.8.8:41000".parse().unwrap();
    let birthday_endpoint: SocketAddr = "8.8.8.8:41251".parse().unwrap();

    manager
        .add_peer(&test_peer("peer1", signaled_endpoint))
        .await;
    let generation = manager.current_network_generation().await;

    {
        let mut conns = manager.connections.write().await;
        let conn = conns.get_mut("peer1").unwrap();
        conn.ensure_candidate_pair_with_source(
            birthday_endpoint,
            generation,
            CandidatePairSource::Birthday,
        );
    }
    assert!(
        manager
            .record_direct_probe_sent("peer1", birthday_endpoint)
            .await
    );

    assert!(
        manager
            .record_direct_probe_batch_failure_for_generation(
                "peer1",
                generation,
                "no matched direct probe ACK after remote scatter sweep",
            )
            .await
    );

    let conn = manager.get_connection("peer1").await.unwrap();
    let signaled_pair = conn
        .candidate_pairs
        .iter()
        .find(|pair| pair.remote_endpoint == signaled_endpoint)
        .expect("signaled pair should remain present");
    assert_eq!(signaled_pair.failure_count, 0);
    assert!(signaled_pair.last_error_code.is_none());

    let birthday_pair = conn
        .candidate_pairs
        .iter()
        .find(|pair| pair.remote_endpoint == birthday_endpoint)
        .expect("probed birthday pair should remain present");
    assert_eq!(birthday_pair.source, CandidatePairSource::Birthday);
    assert_eq!(birthday_pair.state, CandidatePairState::Failed);
    assert_eq!(birthday_pair.failure_count, 1);
    assert_eq!(
        birthday_pair.last_error_code.as_deref(),
        Some(REASON_DIRECT_PROBE_FAILED)
    );
}

#[tokio::test]
async fn direct_path_latency_tracks_ewma_and_jitter() {
    let config = test_config();
    let manager = PeerManager::new(config);
    let endpoint: SocketAddr = "127.0.0.1:51835".parse().unwrap();

    manager.add_peer(&test_peer("peer1", endpoint)).await;
    manager
        .record_direct_probe_success_with_latency("peer1", endpoint, Some(Duration::from_millis(8)))
        .await;
    manager
        .record_direct_probe_success_with_latency(
            "peer1",
            endpoint,
            Some(Duration::from_millis(24)),
        )
        .await;

    let diagnostics = manager.diagnostics().await;
    assert_eq!(diagnostics[0].direct.success_count, 2);
    assert_eq!(diagnostics[0].direct.latency_ms, Some(24));
    assert_eq!(diagnostics[0].direct.rtt_ewma_ms, Some(10));
    assert_eq!(diagnostics[0].direct.jitter_ms, Some(4));
    assert_eq!(diagnostics[0].candidate_pairs[0].success_count, 2);
    assert_eq!(diagnostics[0].candidate_pairs[0].rtt_ewma_ms, Some(10));
    assert_eq!(diagnostics[0].candidate_pairs[0].jitter_ms, Some(4));
}

#[tokio::test]
async fn test_peer_manager_path_health_drives_data_path() {
    let config = test_config();
    let manager = PeerManager::new(config);
    let endpoint: SocketAddr = "127.0.0.1:51822".parse().unwrap();

    manager
        .add_peer(&PeerInfo {
            node_id: "peer1".to_string(),
            device_name: String::new(),
            app_version: String::new(),
            public_key: "pk".to_string(),
            endpoint: endpoint.to_string(),
            nat_type: "Unknown".to_string(),
            virtual_ip: "10.20.0.2".to_string(),
            online: true,
            last_seen: 0,
            relay_rtt_ms: None,
        })
        .await;

    assert!(
        !manager
            .should_use_direct_for_data("peer1", true, true)
            .await
    );
    assert!(
        manager
            .should_use_direct_for_data("peer1", true, false)
            .await
    );

    manager
        .record_direct_failure("peer1", "probe timeout")
        .await;
    let conn = manager.get_connection("peer1").await.unwrap();
    assert_eq!(conn.state, ConnectionState::FallbackToRelay);
    assert_eq!(conn.direct_health.consecutive_failures, 1);
    assert_eq!(
        conn.direct_health.last_error.as_deref(),
        Some("probe timeout")
    );
    assert_eq!(
        conn.direct_health.last_error_code.as_deref(),
        Some(REASON_DIRECT_PROBE_FAILED)
    );

    manager.set_relay("peer1", "127.0.0.1:9000").await;
    let conn = manager.get_connection("peer1").await.unwrap();
    assert_eq!(conn.state, ConnectionState::Relay);
    assert_eq!(conn.active_path(), Some(NetworkPath::Relay));
    assert!(conn.relay_health.last_success_at.is_some());

    manager.record_direct_probe_success("peer1", endpoint).await;
    let conn = manager.get_connection("peer1").await.unwrap();
    assert_eq!(conn.state, ConnectionState::Relay);
    assert_eq!(conn.active_path(), Some(NetworkPath::Relay));
    assert!(conn.direct_health.last_success_at.is_some());
    let trial = manager.select_path_for_data("peer1", true, true).await;
    assert_eq!(trial.path, Some(NetworkPath::Relay));
    assert_eq!(trial.reason_code, REASON_PATH_DIRECT_NOT_CONFIRMED);
    assert!(!trial.direct_confirmed);
    assert!(
        !manager
            .should_use_direct_for_data("peer1", true, true)
            .await
    );

    manager
        .record_direct_probe_success_with_latency(
            "peer1",
            endpoint,
            Some(Duration::from_millis(12)),
        )
        .await;
    let trial = manager.select_path_for_data("peer1", true, true).await;
    assert_eq!(trial.path, Some(NetworkPath::Direct));
    assert_eq!(trial.reason_code, REASON_PATH_DIRECT_TRIAL);
    assert!(trial.relay_hedged);
    assert!(!trial.direct_confirmed);
    assert!(
        manager
            .should_use_direct_for_data("peer1", true, true)
            .await
    );

    manager.record_direct_success("peer1", Some(endpoint)).await;
    let conn = manager.get_connection("peer1").await.unwrap();
    assert_eq!(conn.state, ConnectionState::Direct);
    assert_eq!(conn.active_path(), Some(NetworkPath::Direct));
    assert_eq!(conn.direct_health.consecutive_failures, 0);
    assert!(
        manager
            .should_use_direct_for_data("peer1", true, true)
            .await
    );
}

#[tokio::test]
async fn network_generation_invalidates_direct_and_ignores_stale_results() {
    let config = test_config();
    let manager = PeerManager::new(config);
    let old_endpoint: SocketAddr = "127.0.0.1:51824".parse().unwrap();
    let new_endpoint: SocketAddr = "127.0.0.1:51825".parse().unwrap();

    manager
        .add_peer(&PeerInfo {
            node_id: "peer1".to_string(),
            device_name: String::new(),
            app_version: String::new(),
            public_key: "pk".to_string(),
            endpoint: old_endpoint.to_string(),
            nat_type: "Unknown".to_string(),
            virtual_ip: "10.20.0.2".to_string(),
            online: true,
            last_seen: 0,
            relay_rtt_ms: None,
        })
        .await;

    assert_eq!(manager.current_network_generation().await, 0);
    assert!(
        manager
            .record_direct_probe_success_with_latency_for_generation(
                "peer1",
                old_endpoint,
                Some(Duration::from_millis(8)),
                0,
            )
            .await
    );
    manager
        .record_direct_success("peer1", Some(old_endpoint))
        .await;
    assert!(manager.is_direct_for_generation("peer1", 0).await);

    let generation = manager.advance_network_generation("wifi_to_hotspot").await;
    assert_eq!(generation, 1);
    let conn = manager.get_connection("peer1").await.unwrap();
    assert_eq!(conn.state, ConnectionState::FallbackToRelay);
    assert_eq!(
        conn.direct_health.last_error_code.as_deref(),
        Some(REASON_NETWORK_GENERATION_CHANGED)
    );
    assert!(
        !manager
            .should_use_direct_for_data("peer1", true, true)
            .await
    );

    assert!(
        !manager
            .record_direct_probe_success_with_latency_for_generation(
                "peer1",
                old_endpoint,
                Some(Duration::from_millis(5)),
                0,
            )
            .await
    );
    assert_eq!(
        manager.get_connection("peer1").await.unwrap().state,
        ConnectionState::FallbackToRelay
    );

    assert!(
        manager
            .record_direct_probe_success_with_latency_for_generation(
                "peer1",
                new_endpoint,
                Some(Duration::from_millis(7)),
                generation,
            )
            .await
    );
    assert_eq!(
        manager.get_connection("peer1").await.unwrap().state,
        ConnectionState::HolePunching
    );
    manager
        .record_direct_success_for_generation("peer1", Some(new_endpoint), generation)
        .await;
    let conn = manager.get_connection("peer1").await.unwrap();
    assert_eq!(conn.state, ConnectionState::Direct);
    assert_eq!(conn.endpoint, Some(new_endpoint));
    assert_eq!(conn.direct_generation, generation);
}

#[test]
fn test_diagnostics_enums_serialize_as_snake_case() {
    assert_eq!(
        serde_json::to_string(&ConnectionState::HolePunching).unwrap(),
        "\"hole_punching\""
    );
    assert_eq!(
        serde_json::to_string(&NetworkPath::Direct).unwrap(),
        "\"direct\""
    );
}

#[tokio::test]
async fn test_peer_manager_direct_probe_targets_exclude_direct_peers() {
    let config = test_config();
    let manager = PeerManager::new(config);
    let endpoint: SocketAddr = "127.0.0.1:51823".parse().unwrap();

    manager
        .add_peer(&PeerInfo {
            node_id: "peer1".to_string(),
            device_name: String::new(),
            app_version: String::new(),
            public_key: "pk".to_string(),
            endpoint: endpoint.to_string(),
            nat_type: "Unknown".to_string(),
            virtual_ip: "10.20.0.2".to_string(),
            online: true,
            last_seen: 0,
            relay_rtt_ms: None,
        })
        .await;

    assert_eq!(
        manager.direct_probe_targets().await,
        vec![("peer1".to_string(), vec![endpoint])]
    );

    manager.record_direct_success("peer1", Some(endpoint)).await;
    assert!(manager.direct_probe_targets().await.is_empty());
}

#[tokio::test]
async fn test_peer_manager_stats() {
    let config = test_config();
    let manager = PeerManager::new(config);

    // Add two peers
    for (id, ip) in [("p1", "10.20.0.2"), ("p2", "10.20.0.3")] {
        let peer_info = PeerInfo {
            node_id: id.to_string(),
            device_name: String::new(),
            app_version: String::new(),
            public_key: "pk".to_string(),
            endpoint: "1.2.3.4:5000".to_string(),
            nat_type: "FullCone".to_string(),
            virtual_ip: ip.to_string(),
            online: true,
            last_seen: 0,
            relay_rtt_ms: None,
        };
        manager.add_peer(&peer_info).await;
    }

    manager.update_state("p1", ConnectionState::Direct).await;
    manager.update_state("p2", ConnectionState::Relay).await;

    manager.record_sent("p1", 1000).await;
    manager.record_received("p2", 500).await;

    let stats = manager.stats().await;
    assert_eq!(stats.total_peers, 2);
    assert_eq!(stats.direct_connections, 1);
    assert_eq!(stats.relay_connections, 1);
    assert_eq!(stats.total_bytes_sent, 1000);
    assert_eq!(stats.total_bytes_received, 500);
}
