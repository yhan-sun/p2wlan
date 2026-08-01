#[tokio::test]
async fn stable_public_candidate_precedes_birthday_budget_in_due_targets() {
    let mut history = TraversalHistory::default();
    history.record_success(CandidatePairSource::Birthday);
    let birthday_budget = birthday_probe_budget_for_base_count(&history, 2);
    let manager = PeerManager::new_with_history(test_config(), None, history);
    let stable_endpoint: SocketAddr = "8.8.4.4:40000".parse().unwrap();
    let second_observed: SocketAddr = "8.8.4.4:40037".parse().unwrap();

    manager.add_peer(&test_peer("peer1", stable_endpoint)).await;
    manager
        .add_candidates_with_sources(
            "peer1",
            &[stable_endpoint.to_string(), second_observed.to_string()],
            &HashMap::from([
                (stable_endpoint.to_string(), "stun_observed".to_string()),
                (second_observed.to_string(), "stun_observed".to_string()),
            ]),
        )
        .await;

    let due_targets = manager
        .direct_probe_targets_due(Duration::from_secs(0))
        .await;
    assert_eq!(due_targets.len(), 1);
    assert_eq!(due_targets[0].0, "peer1");

    let targets = &due_targets[0].1;
    let birthday_count = targets
        .iter()
        .filter(|target| {
            **target != stable_endpoint
                && **target != second_observed
                && target.ip() == stable_endpoint.ip()
        })
        .count();
    let expected_birthday_count = birthday_probe_endpoints_for_bases(
        &[stable_endpoint, second_observed],
        birthday_budget,
    )
    .into_iter()
    .filter(|target| *target != stable_endpoint && *target != second_observed)
    .count();

    assert_eq!(targets.first().copied(), Some(stable_endpoint));
    assert!(targets.contains(&stable_endpoint));
    assert_eq!(birthday_count, expected_birthday_count);
}

#[tokio::test]
async fn failed_stable_public_candidate_gets_short_background_retry() {
    let manager = PeerManager::new(test_config());
    let stable_endpoint: SocketAddr = "8.8.4.4:40000".parse().unwrap();
    let peer = PeerInfo {
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

    manager.add_peer(&peer).await;
    manager
        .add_candidates_with_sources(
            "peer1",
            &[stable_endpoint.to_string()],
            &HashMap::from([(stable_endpoint.to_string(), "stun_observed".to_string())]),
        )
        .await;

    {
        let mut conns = manager.connections.write().await;
        let conn = conns.get_mut("peer1").unwrap();
        let pair = conn
            .candidate_pairs
            .iter_mut()
            .find(|pair| pair.remote_endpoint == stable_endpoint)
            .unwrap();
        for _ in 0..4 {
            pair.record_failure(REASON_DIRECT_PROBE_FAILED, "old failure", None);
        }
        pair.last_failure_at = Some(
            Instant::now() - PRIORITY_OUTBOUND_PROBE_FAILURE_COOLDOWN - Duration::from_secs(1),
        );
    }

    let due_targets = manager
        .direct_probe_targets_due(Duration::from_secs(5))
        .await;
    assert_eq!(due_targets.len(), 1);
    assert_eq!(due_targets[0].1, vec![stable_endpoint]);
}

#[tokio::test]
async fn failed_speculative_candidate_keeps_exponential_background_cooldown() {
    let manager = PeerManager::new(test_config());
    let predicted_endpoint: SocketAddr = "8.8.4.4:41000".parse().unwrap();
    let peer = PeerInfo {
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

    manager.add_peer(&peer).await;
    manager
        .add_candidates_with_sources(
            "peer1",
            &[predicted_endpoint.to_string()],
            &HashMap::from([(predicted_endpoint.to_string(), "predicted".to_string())]),
        )
        .await;

    {
        let mut conns = manager.connections.write().await;
        let conn = conns.get_mut("peer1").unwrap();
        let pair = conn
            .candidate_pairs
            .iter_mut()
            .find(|pair| pair.remote_endpoint == predicted_endpoint)
            .unwrap();
        for _ in 0..4 {
            pair.record_failure(REASON_DIRECT_PROBE_FAILED, "old failure", None);
        }
        pair.last_failure_at = Some(
            Instant::now() - PRIORITY_OUTBOUND_PROBE_FAILURE_COOLDOWN - Duration::from_secs(1),
        );
    }

    let due_targets = manager
        .direct_probe_targets_due(Duration::from_secs(5))
        .await;
    assert!(due_targets.is_empty());
}

#[tokio::test]
async fn candidate_pair_probe_targets_use_source_success_feedback() {
    let config = test_config();
    let manager = PeerManager::new(config);
    let signaled_endpoint: SocketAddr = "8.8.8.8:51838".parse().unwrap();
    let peer_reflexive_endpoint: SocketAddr = "127.0.0.1:51839".parse().unwrap();

    manager
        .add_peer(&test_peer("peer1", signaled_endpoint))
        .await;
    assert!(
        manager
            .learn_authenticated_endpoint("peer1", peer_reflexive_endpoint)
            .await
    );

    {
        let mut conns = manager.connections.write().await;
        let conn = conns.get_mut("peer1").unwrap();
        let signaled = conn.ensure_candidate_pair_with_source(
            signaled_endpoint,
            0,
            CandidatePairSource::Signaled,
        );
        signaled.success_count = 2;
        signaled.state = CandidatePairState::Waiting;

        let peer_reflexive = conn.ensure_candidate_pair_with_source(
            peer_reflexive_endpoint,
            0,
            CandidatePairSource::PeerReflexive,
        );
        peer_reflexive.failure_count = 2;
        peer_reflexive.state = CandidatePairState::Waiting;
    }

    let targets = manager.direct_probe_targets().await;
    assert_eq!(targets.len(), 1);
    assert_eq!(targets[0].0, "peer1");
    assert_eq!(
        targets[0].1,
        vec![signaled_endpoint, peer_reflexive_endpoint]
    );
}

#[tokio::test]
async fn candidate_pair_probe_targets_prioritize_non_failed_pairs() {
    let config = test_config();
    let manager = PeerManager::new(config);
    let failed_endpoint: SocketAddr = "127.0.0.1:51829".parse().unwrap();
    let waiting_endpoint: SocketAddr = "127.0.0.1:51830".parse().unwrap();

    manager
        .add_peer(&PeerInfo {
            node_id: "peer1".to_string(),
            device_name: String::new(),
            app_version: String::new(),
            public_key: "pk".to_string(),
            endpoint: failed_endpoint.to_string(),
            nat_type: "Unknown".to_string(),
            virtual_ip: "10.20.0.2".to_string(),
            online: true,
            last_seen: 0,
            relay_rtt_ms: None,
        })
        .await;
    manager
        .add_candidates("peer1", &[waiting_endpoint.to_string()])
        .await;

    {
        let mut conns = manager.connections.write().await;
        let conn = conns.get_mut("peer1").unwrap();
        conn.ensure_candidate_pair(failed_endpoint, 0)
            .record_failure(REASON_DIRECT_PROBE_FAILED, "no ACK", None);
    }

    let targets = manager.direct_probe_targets().await;
    assert_eq!(targets.len(), 1);
    assert_eq!(targets[0].0, "peer1");
    assert_eq!(targets[0].1, vec![waiting_endpoint]);
}

#[tokio::test]
async fn candidate_pair_probe_targets_reallow_failed_pair_after_cooldown() {
    let config = test_config();
    let manager = PeerManager::new(config);
    let failed_endpoint: SocketAddr = "127.0.0.1:51845".parse().unwrap();

    manager.add_peer(&test_peer("peer1", failed_endpoint)).await;

    {
        let mut conns = manager.connections.write().await;
        let conn = conns.get_mut("peer1").unwrap();
        let pair = conn.ensure_candidate_pair_with_source(
            failed_endpoint,
            0,
            CandidatePairSource::PeerReflexive,
        );
        pair.record_failure(REASON_DIRECT_PROBE_FAILED, "old failure", None);
        pair.last_failure_at =
            Some(Instant::now() - CANDIDATE_PAIR_FAILURE_COOLDOWN_BASE - Duration::from_secs(1));
    }

    let targets = manager.direct_probe_targets_for("peer1").await;
    assert_eq!(targets, vec![failed_endpoint]);
}

#[tokio::test]
async fn synchronized_probe_targets_bypass_failure_cooldown() {
    let config = test_config();
    let manager = PeerManager::new(config);
    let failed_endpoint: SocketAddr = "127.0.0.1:51846".parse().unwrap();

    manager.add_peer(&test_peer("peer1", failed_endpoint)).await;
    manager
        .record_direct_failure_with_code("peer1", REASON_DIRECT_PROBE_FAILED, "no ACK")
        .await;
    manager
        .record_direct_failure_with_code("peer1", REASON_DIRECT_PROBE_FAILED, "still no ACK")
        .await;

    let background_targets = manager
        .direct_probe_targets_due(Duration::from_secs(5))
        .await;
    assert!(background_targets.is_empty());

    let synchronized_targets = manager.direct_probe_targets_for("peer1").await;
    assert_eq!(synchronized_targets, vec![failed_endpoint]);
}

#[test]
fn direct_retry_backoff_reaches_sixty_four_seconds() {
    let mut health = PathHealth::default();
    let base = DIRECT_RETRY_BASE_INTERVAL;

    health.record_failure(REASON_DIRECT_PROBE_FAILED, "first failure");
    assert_eq!(health.retry_after(base), Duration::from_secs(1));

    health.record_failure(REASON_DIRECT_PROBE_FAILED, "second failure");
    assert_eq!(health.retry_after(base), Duration::from_secs(2));

    health.record_failure(REASON_DIRECT_PROBE_FAILED, "third failure");
    assert_eq!(health.retry_after(base), Duration::from_secs(4));

    health.record_failure(REASON_DIRECT_PROBE_FAILED, "fourth failure");
    assert_eq!(health.retry_after(base), Duration::from_secs(8));

    health.record_failure(REASON_DIRECT_PROBE_FAILED, "fifth failure");
    assert_eq!(health.retry_after(base), Duration::from_secs(16));

    health.record_failure(REASON_DIRECT_PROBE_FAILED, "sixth failure");
    assert_eq!(health.retry_after(base), Duration::from_secs(32));

    health.record_failure(REASON_DIRECT_PROBE_FAILED, "seventh failure");
    assert_eq!(health.retry_after(base), Duration::from_secs(64));

    health.record_failure(REASON_DIRECT_PROBE_FAILED, "eighth failure");
    assert_eq!(health.retry_after(base), Duration::from_secs(64));
}
