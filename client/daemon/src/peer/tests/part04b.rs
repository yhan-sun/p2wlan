#[tokio::test]
async fn hard_local_and_scattered_peer_without_history_skip_background_retry() {
    let manager = PeerManager::new(test_config());
    let endpoint_a: SocketAddr = "203.0.113.10:40000".parse().unwrap();
    let endpoint_b: SocketAddr = "203.0.113.10:40037".parse().unwrap();

    manager.add_peer(&test_peer("peer1", endpoint_a)).await;
    manager
        .add_candidates("peer1", &[endpoint_b.to_string()])
        .await;
    manager.update_nat_profile(birthday_nat_profile()).await;

    let targets = manager
        .direct_probe_targets_due(DIRECT_RETRY_BASE_INTERVAL)
        .await;
    assert!(targets.is_empty());

    let conn = manager.get_connection("peer1").await.unwrap();
    assert!(conn.direct_events.iter().any(|event| {
        event.stage == "retry_skipped_no_viable_nat_window" && event.network_generation == 0
    }));
}

#[tokio::test]
async fn previous_direct_success_fast_retries_even_when_nat_now_looks_hard() {
    let manager = PeerManager::new(test_config());
    let endpoint_a: SocketAddr = "203.0.113.10:40000".parse().unwrap();
    let endpoint_b: SocketAddr = "203.0.113.10:40037".parse().unwrap();

    manager.add_peer(&test_peer("peer1", endpoint_a)).await;
    manager
        .add_candidates("peer1", &[endpoint_b.to_string()])
        .await;
    manager.update_nat_profile(birthday_nat_profile()).await;
    manager
        .record_direct_success("peer1", Some(endpoint_a))
        .await;
    manager
        .record_direct_failure_with_code("peer1", REASON_DIRECT_PROBE_FAILED, "lost direct")
        .await;

    {
        let mut conns = manager.connections.write().await;
        let conn = conns.get_mut("peer1").unwrap();
        conn.direct_health.last_failure_at =
            Some(Instant::now() - DIRECT_RETRY_BASE_INTERVAL - Duration::from_millis(10));
        for pair in &mut conn.candidate_pairs {
            pair.last_failure_at = Some(
                Instant::now() - CANDIDATE_PAIR_FAILURE_COOLDOWN_BASE - Duration::from_millis(10),
            );
        }
    }

    let targets = manager
        .direct_probe_targets_due(DIRECT_RETRY_BASE_INTERVAL)
        .await;
    assert_eq!(targets.len(), 1);
    assert_eq!(targets[0].0, "peer1");
    assert!(targets[0].1.contains(&endpoint_a));
}

#[tokio::test]
async fn generation_change_opens_immediate_direct_reclaim_window() {
    let manager = PeerManager::new(test_config());
    let endpoint: SocketAddr = "203.0.113.20:41000".parse().unwrap();

    manager.add_peer(&test_peer("peer1", endpoint)).await;
    manager.record_direct_success("peer1", Some(endpoint)).await;

    let generation = manager.advance_network_generation("hotspot_handover").await;
    assert_eq!(generation, 1);
    assert!(manager.direct_reclaim_active("peer1").await);

    let conn = manager.get_connection("peer1").await.unwrap();
    assert_eq!(conn.state, ConnectionState::FallbackToRelay);
    assert_eq!(
        conn.direct_health.last_error_code.as_deref(),
        Some(REASON_NETWORK_GENERATION_CHANGED)
    );
    assert!(conn
        .direct_events
        .iter()
        .any(|event| event.stage == "direct_reclaim_window_started"));

    let targets = manager
        .direct_probe_targets_due(DIRECT_RETRY_BASE_INTERVAL)
        .await;
    assert_eq!(targets.len(), 1);
    assert_eq!(targets[0].0, "peer1");
    assert!(targets[0].1.contains(&endpoint));
}

#[tokio::test]
async fn direct_reclaim_window_bypasses_retry_and_pair_cooldowns() {
    let manager = PeerManager::new(test_config());
    let endpoint: SocketAddr = "203.0.113.21:41000".parse().unwrap();

    manager.add_peer(&test_peer("peer1", endpoint)).await;
    manager.record_direct_success("peer1", Some(endpoint)).await;
    let generation = manager.advance_network_generation("hotspot_handover").await;

    let first_targets = manager
        .direct_probe_targets_due(DIRECT_RETRY_BASE_INTERVAL)
        .await;
    assert_eq!(first_targets.len(), 1);

    assert!(
        manager
            .record_direct_failure_for_generation(
                "peer1",
                generation,
                REASON_DIRECT_PROBE_FAILED,
                "no reclaim ACK yet",
            )
            .await
    );

    let second_targets = manager
        .direct_probe_targets_due(DIRECT_RETRY_BASE_INTERVAL)
        .await;
    assert_eq!(second_targets.len(), 1);
    assert_eq!(second_targets[0].0, "peer1");
    assert!(second_targets[0].1.contains(&endpoint));

    let conn = manager.get_connection("peer1").await.unwrap();
    assert!(conn
        .direct_events
        .iter()
        .any(|event| event.stage == "direct_reclaim_targets_due"));
}

#[tokio::test]
async fn diagnostics_reports_candidate_pair_probe_cooldown_remaining() {
    let config = test_config();
    let manager = PeerManager::new(config);
    let failed_endpoint: SocketAddr = "127.0.0.1:51847".parse().unwrap();

    manager.add_peer(&test_peer("peer1", failed_endpoint)).await;
    {
        let mut conns = manager.connections.write().await;
        let conn = conns.get_mut("peer1").unwrap();
        conn.ensure_candidate_pair_with_source(
            failed_endpoint,
            0,
            CandidatePairSource::PeerReflexive,
        )
        .record_failure(REASON_DIRECT_PROBE_FAILED, "recent failure", None);
    }

    let diagnostics = manager.diagnostics().await;
    let pair = diagnostics[0]
        .candidate_pairs
        .iter()
        .find(|pair| pair.remote_endpoint == failed_endpoint.to_string())
        .unwrap();
    assert!(!pair.probe_due);
    assert_eq!(pair.probe_retry_after_ms, Some(1_000));
    assert!(pair.probe_retry_remaining_ms.unwrap() > 0);
    assert!(pair.probe_retry_remaining_ms.unwrap() <= 1_000);

    {
        let mut conns = manager.connections.write().await;
        let conn = conns.get_mut("peer1").unwrap();
        let pair = conn
            .candidate_pairs
            .iter_mut()
            .find(|pair| pair.remote_endpoint == failed_endpoint)
            .unwrap();
        pair.last_failure_at =
            Some(Instant::now() - CANDIDATE_PAIR_FAILURE_COOLDOWN_BASE - Duration::from_secs(1));
    }

    let diagnostics = manager.diagnostics().await;
    let pair = diagnostics[0]
        .candidate_pairs
        .iter()
        .find(|pair| pair.remote_endpoint == failed_endpoint.to_string())
        .unwrap();
    assert!(pair.probe_due);
    assert_eq!(pair.probe_retry_after_ms, Some(1_000));
    assert_eq!(pair.probe_retry_remaining_ms, Some(0));
}

#[tokio::test]
async fn candidate_pair_probe_targets_promote_authenticated_peer_reflexive() {
    let config = test_config();
    let manager = PeerManager::new(config);
    let signaled_endpoint: SocketAddr = "8.8.8.8:51830".parse().unwrap();
    let peer_reflexive_endpoint: SocketAddr = "127.0.0.1:51831".parse().unwrap();

    manager
        .add_peer(&PeerInfo {
            node_id: "peer1".to_string(),
            device_name: String::new(),
            app_version: String::new(),
            public_key: "pk".to_string(),
            endpoint: signaled_endpoint.to_string(),
            nat_type: "Unknown".to_string(),
            virtual_ip: "10.20.0.2".to_string(),
            online: true,
            last_seen: 0,
            relay_rtt_ms: None,
        })
        .await;

    assert!(
        manager
            .learn_authenticated_endpoint("peer1", peer_reflexive_endpoint)
            .await
    );

    let targets = manager.direct_probe_targets().await;
    assert_eq!(targets.len(), 1);
    assert_eq!(
        targets[0].1,
        vec![peer_reflexive_endpoint, signaled_endpoint]
    );
    for endpoint in &targets[0].1 {
        assert!(manager.record_direct_probe_sent("peer1", *endpoint).await);
    }

    let conn = manager.get_connection("peer1").await.unwrap();
    let peer_reflexive_pair = conn
        .candidate_pairs
        .iter()
        .find(|pair| pair.remote_endpoint == peer_reflexive_endpoint)
        .unwrap();
    assert_eq!(
        peer_reflexive_pair.source,
        CandidatePairSource::PeerReflexive
    );
    assert_eq!(peer_reflexive_pair.probe_count, 2);
    assert!(peer_reflexive_pair.last_probe_at.is_some());

    let diagnostics = manager.diagnostics().await;
    let diagnostic_pair = diagnostics[0]
        .candidate_pairs
        .iter()
        .find(|pair| pair.remote_endpoint == peer_reflexive_endpoint.to_string())
        .unwrap();
    assert_eq!(diagnostic_pair.source, CandidatePairSource::PeerReflexive);
    assert_eq!(diagnostic_pair.probe_count, 2);
    assert!(diagnostic_pair.last_probe_age_ms.is_some());
}

#[tokio::test]
async fn direct_send_prefers_fresh_authenticated_peer_reflexive_endpoint() {
    let manager = PeerManager::new(test_config());
    let signaled_endpoint: SocketAddr = "127.0.0.1:51841".parse().unwrap();
    let peer_reflexive_endpoint: SocketAddr = "127.0.0.1:51842".parse().unwrap();
    manager
        .add_peer(&test_peer("peer1", signaled_endpoint))
        .await;

    manager
        .record_direct_probe_success_with_latency(
            "peer1",
            signaled_endpoint,
            Some(Duration::from_millis(1)),
        )
        .await;
    assert!(
        manager
            .learn_authenticated_endpoint("peer1", peer_reflexive_endpoint)
            .await
    );

    assert_eq!(
        manager.direct_endpoint_for_send("peer1").await,
        Some(peer_reflexive_endpoint)
    );
}

#[tokio::test]
async fn test_peer_manager_selects_endpoint_from_candidates() {
    let config = test_config();
    let manager = PeerManager::new(config);

    let peer_info = PeerInfo {
        node_id: "peer1".to_string(),
        device_name: String::new(),
        app_version: String::new(),
        public_key: "pk".to_string(),
        endpoint: String::new(),
        nat_type: "Unknown".to_string(),
        virtual_ip: "10.20.0.2".to_string(),
        online: true,
        last_seen: 0,
        relay_rtt_ms: None,
    };

    manager.add_peer(&peer_info).await;
    manager
        .add_candidates(
            "peer1",
            &[
                "not-a-socket".to_string(),
                "127.0.0.1:51820".to_string(),
                "10.0.0.1:51820".to_string(),
            ],
        )
        .await;

    let conn = manager.get_connection("peer1").await.unwrap();
    assert_eq!(conn.endpoint, Some("127.0.0.1:51820".parse().unwrap()));
}

#[tokio::test]
async fn test_peer_manager_learns_endpoint_from_probe_source_without_confirming_direct() {
    let config = test_config();
    let manager = PeerManager::new(config);

    let peer_info = PeerInfo {
        node_id: "peer1".to_string(),
        device_name: String::new(),
        app_version: String::new(),
        public_key: "pk".to_string(),
        endpoint: String::new(),
        nat_type: "Unknown".to_string(),
        virtual_ip: "10.20.0.2".to_string(),
        online: true,
        last_seen: 0,
        relay_rtt_ms: None,
    };
    let selected_endpoint: SocketAddr = "127.0.0.1:51821".parse().unwrap();

    manager.add_peer(&peer_info).await;
    manager
        .add_candidates("peer1", &[selected_endpoint.to_string()])
        .await;

    let selected = manager.learn_endpoint_from_addr(selected_endpoint).await;
    assert_eq!(selected, Some("peer1".to_string()));

    let conn = manager.get_connection("peer1").await.unwrap();
    assert_eq!(conn.endpoint, Some(selected_endpoint));
    assert_eq!(conn.state, ConnectionState::Idle);
    assert!(manager.direct_endpoints().await.is_empty());
}
