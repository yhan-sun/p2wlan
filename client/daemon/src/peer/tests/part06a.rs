#[tokio::test]
async fn direct_traversal_timeline_records_probe_flow() {
    let config = test_config();
    let manager = PeerManager::new(config);
    let endpoint: SocketAddr = "203.0.113.10:60207".parse().unwrap();

    manager.add_peer(&test_peer("peer1", endpoint)).await;
    let candidates = vec![endpoint.to_string()];
    let sources = HashMap::from([(endpoint.to_string(), "stun_observed".to_string())]);
    manager
        .add_candidates_with_sources("peer1", &candidates, &sources)
        .await;

    let targets = manager.direct_probe_targets_for("peer1").await;
    assert_eq!(targets, vec![endpoint]);

    manager
        .record_direct_event(
            "peer1",
            "punch_probes_sent",
            Some(endpoint),
            Some(targets.len()),
            Some(3),
            "sent test probes",
        )
        .await;

    let generation = manager.current_network_generation().await;
    assert!(
        manager
            .record_direct_probe_success_with_latency_for_generation(
                "peer1",
                endpoint,
                Some(Duration::from_millis(42)),
                generation,
            )
            .await
    );

    let diagnostics = manager.diagnostics().await;
    let stages = diagnostics[0]
        .direct_events
        .iter()
        .map(|event| event.stage.as_str())
        .collect::<Vec<_>>();

    assert!(stages.contains(&"candidates_received"));
    assert!(stages.contains(&"probe_targets_selected"));
    assert!(stages.contains(&"punch_probes_sent"));
    assert!(stages.contains(&"probe_ack_received"));
    assert_eq!(
        diagnostics[0]
            .direct_events
            .iter()
            .find(|event| event.stage == "probe_ack_received")
            .and_then(|event| event.endpoint.as_deref()),
        Some("203.0.113.10:60207")
    );
}

#[tokio::test]
async fn path_selector_honors_relay_policy_and_reports_no_path() {
    let config = test_config();
    let manager = PeerManager::new(config);
    let endpoint: SocketAddr = "127.0.0.1:51832".parse().unwrap();

    manager.add_peer(&test_peer("peer1", endpoint)).await;
    let relay_policy = manager.select_path_for_data("peer1", false, true).await;
    assert_eq!(relay_policy.path, Some(NetworkPath::Relay));
    assert_eq!(relay_policy.reason_code, REASON_PATH_DIRECT_DISABLED);

    let no_state = manager.select_path_for_data("missing", true, false).await;
    assert_eq!(no_state.path, None);
    assert_eq!(no_state.reason_code, REASON_PATH_UNAVAILABLE);
}

#[tokio::test]
async fn first_usable_rejects_stale_generation_and_retired_peer_packets() {
    let manager = PeerManager::new(test_config());
    manager
        .add_peer(&test_peer("peer1", "127.0.0.1:51834".parse().unwrap()))
        .await;

    let old_generation = manager.current_network_generation().await;
    manager
        .mark_relay_transport_ready("peer1", "relay.test:443", old_generation)
        .await;
    assert!(manager
        .confirm_relay_peer("peer1", "relay.test:443", old_generation)
        .await);
    assert!(manager
        .record_verified_first_usable(
            "peer1",
            old_generation,
            NetworkPath::Relay,
            "relay:relay.test:443",
        )
        .await);

    let new_generation = manager.advance_network_generation("air_restart").await;
    assert!(new_generation > old_generation);
    assert!(!manager
        .record_verified_first_usable(
            "peer1",
            old_generation,
            NetworkPath::Relay,
            "relay:relay.test:443",
        )
        .await);

    {
        let mut connections = manager.connections.write().await;
        connections.get_mut("peer1").unwrap().online = false;
    }
    assert!(!manager
        .record_verified_first_usable(
            "peer1",
            new_generation,
            NetworkPath::Relay,
            "relay:relay.test:443",
        )
        .await);

    {
        let mut connections = manager.connections.write().await;
        let connection = connections.get_mut("peer1").unwrap();
        connection.online = true;
        connection.transition(ConnectionState::Closed);
    }
    assert!(!manager
        .record_verified_first_usable(
            "peer1",
            new_generation,
            NetworkPath::Relay,
            "relay:relay.test:443",
        )
        .await);
}

#[tokio::test]
async fn first_usable_commit_is_serialized_with_generation_advance() {
    let manager = std::sync::Arc::new(PeerManager::new(test_config()));
    manager
        .add_peer(&test_peer("peer1", "127.0.0.1:51835".parse().unwrap()))
        .await;
    let generation = manager.current_network_generation().await;
    manager
        .mark_relay_transport_ready("peer1", "relay.test:443", generation)
        .await;
    assert!(manager
        .confirm_relay_peer("peer1", "relay.test:443", generation)
        .await);

    // Hold the same gate as Air/network restart. A stale evidence writer may
    // not pass its generation check and mutate the connection until the
    // lifecycle transition has released the gate.
    let epoch_gate = manager.network_epoch_gate();
    let epoch_guard = epoch_gate.lock().await;
    let record_task = tokio::spawn({
        let manager = manager.clone();
        async move {
            manager
                .record_verified_first_usable(
                    "peer1",
                    generation,
                    NetworkPath::Relay,
                    "relay:relay.test:443",
                )
                .await
        }
    });
    tokio::time::sleep(Duration::from_millis(10)).await;
    assert!(!record_task.is_finished());
    drop(epoch_guard);
    assert!(record_task.await.unwrap());

    let next_generation = manager.advance_network_generation("serialized_restart").await;
    assert!(next_generation > generation);
    assert_eq!(
        manager
            .get_connection("peer1")
            .await
            .unwrap()
            .first_usable_generation,
        None
    );
}

#[tokio::test]
async fn relay_confirmation_and_business_markers_reject_retired_generation() {
    let manager = PeerManager::new(test_config());
    manager
        .add_peer(&test_peer("peer1", "127.0.0.1:51836".parse().unwrap()))
        .await;

    let old_generation = manager.current_network_generation().await;
    manager
        .mark_relay_transport_ready("peer1", "relay.test:443", old_generation)
        .await;
    assert!(manager
        .confirm_relay_peer("peer1", "relay.test:443", old_generation)
        .await);

    let new_generation = manager.advance_network_generation("retire_relay_state").await;
    assert!(new_generation > old_generation);

    // Every relay state writer must fail closed after the generation advance;
    // none may recreate READY, confirmation, or first-business evidence for
    // the retired generation.
    manager
        .mark_relay_transport_ready("peer1", "relay.test:443", old_generation)
        .await;
    assert!(!manager
        .confirm_relay_peer("peer1", "relay.test:443", old_generation)
        .await);
    assert!(!manager
        .mark_relay_first_business_sent_for_generation("peer1", old_generation)
        .await);
    assert!(!manager
        .mark_relay_first_business_received_for_generation(
            "peer1",
            "relay.test:443",
            old_generation,
        )
        .await);

    let connection = manager.get_connection("peer1").await.unwrap();
    assert_eq!(connection.relay_ready_generation, None);
    assert_eq!(connection.relay_confirmed_generation, None);
    assert_eq!(connection.relay_first_business_sent_generation, None);
    assert_eq!(connection.relay_first_business_received_generation, None);
    assert_eq!(connection.relay_first_business_exchange_generation, None);
}

#[tokio::test]
async fn generation_advance_wins_over_queued_relay_confirmation() {
    let manager = std::sync::Arc::new(PeerManager::new(test_config()));
    manager
        .add_peer(&test_peer("peer1", "127.0.0.1:51837".parse().unwrap()))
        .await;

    let old_generation = manager.current_network_generation().await;
    manager
        .mark_relay_transport_ready("peer1", "relay.test:443", old_generation)
        .await;

    // Queue the lifecycle transition ahead of the stale confirmation while
    // the epoch gate is held. Tokio's mutex is FIFO, so releasing the gate
    // deterministically lets the generation advance retire the state before
    // the old ACK's commit attempt runs.
    let epoch_gate = manager.network_epoch_gate();
    let epoch_guard = epoch_gate.lock().await;
    let advance_task = tokio::spawn({
        let manager = manager.clone();
        async move { manager.advance_network_generation("queued_before_old_ack").await }
    });
    tokio::time::sleep(Duration::from_millis(10)).await;
    assert!(!advance_task.is_finished());

    let confirm_task = tokio::spawn({
        let manager = manager.clone();
        async move {
            manager
                .confirm_relay_peer("peer1", "relay.test:443", old_generation)
                .await
        }
    });
    tokio::time::sleep(Duration::from_millis(10)).await;
    assert!(!confirm_task.is_finished());
    drop(epoch_guard);

    let new_generation = advance_task.await.unwrap();
    assert!(new_generation > old_generation);
    assert!(!confirm_task.await.unwrap());
    let connection = manager.get_connection("peer1").await.unwrap();
    assert_eq!(connection.relay_confirmed_generation, None);
    assert_eq!(connection.relay_ready_generation, None);
}

#[tokio::test]
async fn path_selection_diagnostics_exposes_current_and_last_selection() {
    let config = test_config();
    let manager = PeerManager::new(config);
    let endpoint: SocketAddr = "127.0.0.1:51833".parse().unwrap();

    manager.add_peer(&test_peer("peer1", endpoint)).await;

    let diagnostics = manager
        .diagnostics_with_path_selection(true, true, Duration::from_secs(5), None)
        .await;
    assert_eq!(diagnostics.len(), 1);
    assert_eq!(diagnostics[0].active_path, None);
    let current = diagnostics[0].current_path_selection.as_ref().unwrap();
    assert_eq!(current.path, Some(NetworkPath::Relay));
    assert_eq!(current.direct_endpoint, None);
    assert_eq!(current.reason_code, REASON_PATH_DIRECT_NOT_CONFIRMED);
    assert!(
        current.direct_score.as_ref().unwrap().score < current.relay_score.as_ref().unwrap().score
    );
    assert_eq!(diagnostics[0].last_path_selection, None);

    let selected = manager.select_path_for_data("peer1", true, true).await;
    assert_eq!(selected.reason_code, REASON_PATH_DIRECT_NOT_CONFIRMED);

    let diagnostics = manager
        .diagnostics_with_path_selection(true, true, Duration::from_secs(5), None)
        .await;
    assert_eq!(diagnostics[0].active_path, None);
    let current = diagnostics[0].current_path_selection.as_ref().unwrap();
    let last = diagnostics[0].last_path_selection.as_ref().unwrap();
    assert_eq!(current.reason_code, REASON_PATH_DIRECT_NOT_CONFIRMED);
    assert_eq!(last.reason_code, REASON_PATH_DIRECT_NOT_CONFIRMED);

    let json = serde_json::to_value(&diagnostics[0]).unwrap();
    assert_eq!(
        json["current_path_selection"]["reason_code"],
        REASON_PATH_DIRECT_NOT_CONFIRMED
    );
    assert_eq!(
        json["last_path_selection"]["reason_code"],
        REASON_PATH_DIRECT_NOT_CONFIRMED
    );
    assert!(json["current_path_selection"]["direct_score"]["score"].is_i64());
    assert!(json["current_path_selection"]["relay_score"]["score"].is_i64());
}

#[tokio::test]
async fn relay_failure_clears_confirmed_active_path() {
    let config = test_config();
    let manager = PeerManager::new(config);
    let endpoint: SocketAddr = "127.0.0.1:51841".parse().unwrap();

    manager.add_peer(&test_peer("peer1", endpoint)).await;
    manager.set_relay("peer1", "relay.test:443").await;
    let generation = manager.current_network_generation().await;
    assert!(
        manager
            .confirm_relay_peer("peer1", "relay.test:443", generation)
            .await
    );
    let before = manager
        .diagnostics_with_path_selection(true, true, Duration::from_secs(5), None)
        .await;
    assert_eq!(before[0].active_path, Some(NetworkPath::Relay));

    manager
        .record_relay_failure("peer1", "peer_not_found", "peer not found: peer1")
        .await;

    let conn = manager.get_connection("peer1").await.unwrap();
    assert_eq!(conn.state, ConnectionState::FallbackToRelay);
    let after = manager
        .diagnostics_with_path_selection(true, true, Duration::from_secs(5), None)
        .await;
    assert_eq!(after[0].active_path, None);
    assert_eq!(
        after[0].relay.last_error_code.as_deref(),
        Some("peer_not_found")
    );
}

#[tokio::test]
async fn stale_relay_confirmation_is_not_reported_active_but_remains_available() {
    let config = test_config();
    let manager = PeerManager::new(config);
    let endpoint: SocketAddr = "127.0.0.1:51844".parse().unwrap();

    manager.add_peer(&test_peer("peer1", endpoint)).await;
    manager.set_relay("peer1", "relay.test:443").await;
    {
        let mut conns = manager.connections.write().await;
        let conn = conns.get_mut("peer1").unwrap();
        conn.relay_health.last_success_at =
            Some(Instant::now() - RELAY_PEER_CONFIRMATION_MAX_AGE - Duration::from_secs(1));
    }

    let diagnostics = manager.diagnostics().await;
    assert_eq!(diagnostics[0].state, ConnectionState::Relay);
    assert_eq!(diagnostics[0].active_path, None);
    assert!(diagnostics[0]
        .relay
        .last_success_age_ms
        .is_some_and(|age| age > duration_millis(RELAY_PEER_CONFIRMATION_MAX_AGE)));

    let selection = manager.select_path_for_data("peer1", true, true).await;
    assert_eq!(selection.path, Some(NetworkPath::Relay));

    let diagnostics = manager
        .diagnostics_with_path_selection(true, true, Duration::from_secs(5), None)
        .await;
    assert_eq!(diagnostics[0].active_path, None);
    assert_eq!(
        diagnostics[0]
            .current_path_selection
            .as_ref()
            .and_then(|selection| selection.path),
        Some(NetworkPath::Relay)
    );
}

#[tokio::test]
async fn relay_validation_targets_include_slow_direct_but_skip_fast_direct() {
    let manager = PeerManager::new(test_config());
    let fast_endpoint: SocketAddr = "127.0.0.1:51845".parse().unwrap();
    let slow_endpoint: SocketAddr = "127.0.0.1:51846".parse().unwrap();

    manager.add_peer(&test_peer("fast", fast_endpoint)).await;
    manager.add_peer(&test_peer("slow", slow_endpoint)).await;
    manager.add_peer(&test_peer("offline", "127.0.0.1:51847".parse().unwrap())).await;
    {
        let mut conns = manager.connections.write().await;
        let fast = conns.get_mut("fast").unwrap();
        fast.transition(ConnectionState::Direct);
        fast.direct_health
            .record_success_with_latency(Duration::from_millis(20));

        let slow = conns.get_mut("slow").unwrap();
        slow.transition(ConnectionState::Direct);
        slow.direct_health
            .record_success_with_latency(Duration::from_millis(
                SLOW_DIRECT_RELAY_VALIDATION_RTT_MS,
            ));
        conns.get_mut("offline").unwrap().online = false;
    }

    let targets = manager
        .relay_validation_targets(Duration::from_secs(15))
        .await;

    assert!(!targets.iter().any(|(node_id, _)| node_id == "fast"));
    assert!(targets.iter().any(|(node_id, _)| node_id == "slow"));
    assert!(!targets.iter().any(|(node_id, _)| node_id == "offline"));
}

#[tokio::test]
async fn relay_transport_invalidation_clears_all_matching_peer_confirmations() {
    let manager = PeerManager::new(test_config());
    let endpoint: SocketAddr = "127.0.0.1:51843".parse().unwrap();
    manager.add_peer(&test_peer("peer1", endpoint)).await;
    manager.set_relay("peer1", "relay-a.test:443").await;

    manager
        .invalidate_relay_transport(
            "relay-a.test:443",
            "relay_transport_closed",
            "relay disconnected",
        )
        .await;

    let conn = manager.get_connection("peer1").await.unwrap();
    assert_eq!(conn.state, ConnectionState::FallbackToRelay);
    assert_eq!(conn.relay_server, None);
    assert!(!conn.relay_health.is_confirmed());
    assert_eq!(
        conn.relay_health.last_error_code.as_deref(),
        Some("relay_transport_closed")
    );
}

#[tokio::test]
async fn peer_manager_stats_can_follow_selected_path_not_stale_state() {
    let config = test_config();
    let manager = PeerManager::new(config);
    let endpoint: SocketAddr = "127.0.0.1:51840".parse().unwrap();

    manager.add_peer(&test_peer("peer1", endpoint)).await;
    manager
        .record_direct_probe_success_with_latency(
            "peer1",
            endpoint,
            Some(Duration::from_millis(700)),
        )
        .await;
    manager.record_direct_success("peer1", Some(endpoint)).await;
    manager
        .record_relay_success("peer1", "relay.test:443", false)
        .await;
    let generation = manager.current_network_generation().await;
    assert!(
        manager
            .confirm_relay_peer("peer1", "relay.test:443", generation)
            .await
    );

    {
        let mut conns = manager.connections.write().await;
        let conn = conns.get_mut("peer1").unwrap();
        conn.direct_health.consecutive_failures = 1;
        conn.direct_health.failure_count = 1;
        conn.direct_health.rtt_ewma_ms = Some(650);
        conn.direct_health.jitter_ms = Some(120);
    }

    let stale_stats = manager.stats().await;
    assert_eq!(stale_stats.direct_connections, 1);

    let diagnostics = manager
        .diagnostics_with_path_selection(true, true, Duration::from_secs(5), None)
        .await;
    assert_eq!(diagnostics[0].state, ConnectionState::Direct);
    assert_eq!(diagnostics[0].active_path, Some(NetworkPath::Relay));

    let selected_stats = PeerManagerStats::from_diagnostics(&diagnostics);
    assert_eq!(selected_stats.direct_connections, 0);
    assert_eq!(selected_stats.relay_connections, 1);
}
