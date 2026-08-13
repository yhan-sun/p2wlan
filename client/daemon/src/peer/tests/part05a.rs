#[tokio::test]
async fn path_selector_prefers_relay_until_direct_is_confirmed() {
    let config = test_config();
    let manager = PeerManager::new(config);
    let endpoint: SocketAddr = "127.0.0.1:51831".parse().unwrap();

    manager.add_peer(&test_peer("peer1", endpoint)).await;

    let waiting = manager.select_path_for_data("peer1", true, true).await;
    assert_eq!(waiting.path, Some(NetworkPath::Relay));
    assert_eq!(waiting.reason_code, REASON_PATH_DIRECT_NOT_CONFIRMED);
    assert_eq!(waiting.direct_endpoint, None);

    let no_relay = manager.select_path_for_data("peer1", true, false).await;
    assert_eq!(no_relay.path, None);
    assert_eq!(no_relay.reason_code, REASON_PATH_UNAVAILABLE);
    assert_eq!(no_relay.direct_endpoint, None);
    assert!(!no_relay.direct_confirmed);

    manager
        .record_direct_probe_success_with_latency("peer1", endpoint, Some(Duration::from_millis(6)))
        .await;
    let provisional = manager.select_path_for_data("peer1", true, true).await;
    assert_eq!(provisional.path, Some(NetworkPath::Relay));
    assert!(!provisional.direct_confirmed);
    assert_eq!(
        manager.get_connection("peer1").await.unwrap().active_path(),
        None
    );
    manager.record_direct_success("peer1", Some(endpoint)).await;
    let confirmed = manager.select_path_for_data("peer1", true, true).await;
    assert_eq!(confirmed.path, Some(NetworkPath::Direct));
    assert_eq!(confirmed.reason_code, REASON_PATH_DIRECT_CONFIRMED);
    assert_eq!(confirmed.direct_endpoint, Some(endpoint));
    assert!(confirmed.direct_confirmed);
    assert!(
        confirmed.direct_score.as_ref().unwrap().score
            > confirmed.relay_score.as_ref().unwrap().score
    );
}

#[tokio::test]
async fn path_selector_uses_scores_and_hysteresis_for_degraded_direct() {
    let config = test_config();
    let manager = PeerManager::new(config);
    let endpoint: SocketAddr = "127.0.0.1:51836".parse().unwrap();

    manager.add_peer(&test_peer("peer1", endpoint)).await;
    manager
        .record_direct_probe_success_with_latency(
            "peer1",
            endpoint,
            Some(Duration::from_millis(18)),
        )
        .await;
    manager.record_direct_success("peer1", Some(endpoint)).await;
    manager
        .record_relay_success("peer1", "relay.test:443", false)
        .await;

    let healthy = manager.select_path_for_data("peer1", true, true).await;
    assert_eq!(healthy.path, Some(NetworkPath::Direct));
    assert_eq!(healthy.reason_code, REASON_PATH_DIRECT_CONFIRMED);

    {
        let mut conns = manager.connections.write().await;
        let conn = conns.get_mut("peer1").unwrap();
        conn.direct_health.consecutive_failures = 3;
        conn.direct_health.failure_count = 3;
        conn.direct_health.rtt_ewma_ms = Some(650);
        conn.direct_health.jitter_ms = Some(120);
    }

    let degraded = manager.select_path_for_data("peer1", true, true).await;
    assert_eq!(degraded.path, Some(NetworkPath::Relay));
    assert_eq!(degraded.reason_code, REASON_PATH_DIRECT_DEGRADED);
    assert!(!degraded.direct_confirmed);
    assert!(!degraded.relay_hedged);
    assert!(
        degraded.direct_score.as_ref().unwrap().score + DIRECT_TO_RELAY_HYSTERESIS_MARGIN
            < degraded.relay_score.as_ref().unwrap().score
    );
}

#[tokio::test]
async fn path_selector_retains_low_latency_private_direct_over_relay() {
    let config = test_config();
    let manager = PeerManager::new(config);
    let endpoint: SocketAddr = "192.168.2.11:51839".parse().unwrap();

    manager.add_peer(&test_peer("peer1", endpoint)).await;
    manager
        .record_direct_probe_success_with_latency("peer1", endpoint, Some(Duration::from_millis(6)))
        .await;
    manager.record_direct_success("peer1", Some(endpoint)).await;
    manager
        .record_relay_success("peer1", "relay.test:443", false)
        .await;

    {
        let mut conns = manager.connections.write().await;
        let conn = conns.get_mut("peer1").unwrap();
        conn.direct_health.consecutive_failures = 3;
        conn.direct_health.failure_count = 5;
        conn.direct_health.rtt_ewma_ms = Some(650);
        conn.direct_health.jitter_ms = Some(120);
    }

    let selected = manager.select_path_for_data("peer1", true, true).await;
    assert_eq!(selected.path, Some(NetworkPath::Direct));
    assert_eq!(selected.reason_code, REASON_PATH_DIRECT_CONFIRMED);
    assert!(selected.direct_confirmed);
    let direct_score = selected.direct_score.as_ref().unwrap().score;
    let relay_score = selected.relay_score.as_ref().unwrap().score;
    assert!(direct_score < DIRECT_CONFIRMED_MIN_SCORE);
    assert!(direct_score < relay_score);
}

#[tokio::test]
async fn candidate_refresh_retains_low_latency_private_direct() {
    let config = test_config();
    let manager = PeerManager::new(config);
    let endpoint: SocketAddr = "192.168.2.11:51840".parse().unwrap();

    manager.add_peer(&test_peer("peer1", endpoint)).await;
    manager
        .record_direct_probe_success_with_latency("peer1", endpoint, Some(Duration::from_millis(7)))
        .await;
    manager.record_direct_success("peer1", Some(endpoint)).await;
    assert_eq!(manager.current_network_generation().await, 0);

    let generation = manager
        .advance_candidate_refresh_generation("refreshed UDP candidates")
        .await;
    assert_eq!(generation, 1);

    let conn = manager.get_connection("peer1").await.unwrap();
    assert_eq!(conn.state, ConnectionState::Direct);
    assert_eq!(conn.direct_generation, generation);
    assert_eq!(conn.endpoint, Some(endpoint));
    assert!(conn.candidate_pairs.iter().any(|pair| {
        pair.local_generation == 0
            && pair.remote_endpoint == endpoint
            && pair.state == CandidatePairState::Degraded
            && pair.last_error_code.as_deref() == Some(REASON_NETWORK_GENERATION_CHANGED)
    }));
    assert!(conn.candidate_pairs.iter().any(|pair| {
        pair.local_generation == generation
            && pair.remote_endpoint == endpoint
            && pair.state == CandidatePairState::Selected
            && pair.rtt_ewma_ms.or(pair.rtt_ms) == Some(7)
    }));
    assert_eq!(
        manager.direct_endpoint_for_send("peer1").await,
        Some(endpoint)
    );
    assert!(
        manager
            .should_use_direct_for_data("peer1", true, true)
            .await
    );
}

#[tokio::test]
async fn candidate_refresh_retains_confirmed_public_direct() {
    let config = test_config();
    let manager = PeerManager::new(config);
    let endpoint: SocketAddr = "8.8.8.8:51841".parse().unwrap();

    manager.add_peer(&test_peer("peer1", endpoint)).await;
    manager
        .record_direct_probe_success_with_latency("peer1", endpoint, Some(Duration::from_millis(7)))
        .await;
    manager.record_direct_success("peer1", Some(endpoint)).await;

    let generation = manager
        .advance_candidate_refresh_generation("refreshed UDP candidates")
        .await;

    let conn = manager.get_connection("peer1").await.unwrap();
    assert_eq!(generation, 1);
    assert_eq!(conn.state, ConnectionState::Direct);
    assert_eq!(conn.direct_generation, generation);
    assert_eq!(conn.endpoint, Some(endpoint));
    assert!(conn.candidate_pairs.iter().any(|pair| {
        pair.local_generation == generation
            && pair.remote_endpoint == endpoint
            && pair.state == CandidatePairState::Selected
            && pair.source == CandidatePairSource::Signaled
    }));
    assert!(
        manager
            .should_use_direct_for_data("peer1", true, true)
            .await
    );
}

#[tokio::test]
async fn candidate_refresh_retains_confirmed_peer_reflexive_direct() {
    let config = test_config();
    let manager = PeerManager::new(config);
    let endpoint: SocketAddr = "8.8.4.4:51842".parse().unwrap();
    let candidates = vec![endpoint.to_string()];
    let sources = HashMap::from([(endpoint.to_string(), "peer_reflexive".to_string())]);

    manager.add_peer(&test_peer("peer1", endpoint)).await;
    manager
        .add_candidates_with_sources("peer1", &candidates, &sources)
        .await;
    manager
        .record_direct_probe_success_with_latency("peer1", endpoint, Some(Duration::from_millis(42)))
        .await;
    manager.record_direct_success("peer1", Some(endpoint)).await;

    let generation = manager
        .advance_candidate_refresh_generation("refreshed UDP candidates")
        .await;

    let conn = manager.get_connection("peer1").await.unwrap();
    assert_eq!(conn.state, ConnectionState::Direct);
    assert_eq!(conn.direct_generation, generation);
    assert_eq!(conn.endpoint, Some(endpoint));
    assert!(conn.candidate_pairs.iter().any(|pair| {
        pair.local_generation == generation
            && pair.remote_endpoint == endpoint
            && pair.state == CandidatePairState::Selected
            && pair.source == CandidatePairSource::PeerReflexive
            && pair.rtt_ewma_ms.or(pair.rtt_ms) == Some(42)
    }));
}

#[tokio::test]
async fn confirmed_public_peer_reflexive_direct_survives_peer_updated() {
    let manager = PeerManager::new(test_config());
    let public: SocketAddr = "8.8.4.4:51843".parse().unwrap();
    let private: SocketAddr = "192.168.0.159:51843".parse().unwrap();
    manager.add_peer(&test_peer("peer1", public)).await;
    manager
        .learn_authenticated_endpoint("peer1", public)
        .await;
    manager
        .record_direct_probe_success_with_latency("peer1", public, Some(Duration::from_millis(9)))
        .await;
    manager.record_direct_success("peer1", Some(public)).await;
    let before = manager.get_connection("peer1").await.unwrap();
    let mut update = test_peer("peer1", private);
    update.last_seen = 1;
    manager.add_peer(&update).await;

    let after = manager.get_connection("peer1").await.unwrap();
    assert_eq!(after.state, ConnectionState::Direct);
    assert_eq!(after.endpoint, Some(public));
    assert_eq!(after.direct_generation, before.direct_generation);
    assert_eq!(after.direct_commit_seq, before.direct_commit_seq);
    assert!(after.direct_events.len() >= before.direct_events.len());
    assert!(after.candidate_pairs.iter().any(|pair| {
        pair.remote_endpoint == public
            && pair.state == CandidatePairState::Selected
            && pair.source == CandidatePairSource::PeerReflexive
    }));
}

#[tokio::test]
async fn stale_hole_punch_transition_cannot_overwrite_direct() {
    let manager = PeerManager::new(test_config());
    let endpoint: SocketAddr = "8.8.8.8:51844".parse().unwrap();
    manager.add_peer(&test_peer("peer1", endpoint)).await;
    let stale_generation = manager.current_network_generation().await;
    let stale_commit_seq = manager.direct_commit_seq_sync("peer1");
    manager
        .record_direct_probe_success_with_latency("peer1", endpoint, Some(Duration::from_millis(7)))
        .await;
    manager.record_direct_success("peer1", Some(endpoint)).await;

    assert!(!manager
        .begin_hole_punch_if_current("peer1", stale_generation, stale_commit_seq)
        .await);
    let conn = manager.get_connection("peer1").await.unwrap();
    assert_eq!(conn.state, ConnectionState::Direct);
    assert_eq!(conn.active_path(), Some(NetworkPath::Direct));
    assert_eq!(conn.endpoint, Some(endpoint));
    assert!(conn.direct_commit_seq > stale_commit_seq.unwrap_or(0));
}

#[tokio::test]
async fn diagnostics_current_pair_prefers_confirmed_public_pair() {
    let manager = PeerManager::new(test_config());
    let public: SocketAddr = "8.8.8.8:51845".parse().unwrap();
    let private: SocketAddr = "192.168.0.159:51845".parse().unwrap();
    manager.add_peer(&test_peer("peer1", public)).await;
    manager
        .learn_authenticated_endpoint("peer1", public)
        .await;
    manager.record_direct_success("peer1", Some(public)).await;
    manager.learn_authenticated_endpoint("peer1", private).await;

    let peer = manager.diagnostics().await.pop().unwrap();
    assert_eq!(peer.state, ConnectionState::Direct);
    assert_eq!(peer.active_path, Some(NetworkPath::Direct));
    assert_eq!(
        peer.current_direct_pair.unwrap().remote_endpoint,
        public.to_string()
    );
}

#[tokio::test]
async fn diagnostics_direct_state_overrides_stale_relay_selection() {
    let manager = PeerManager::new(test_config());
    let public: SocketAddr = "8.8.8.8:51846".parse().unwrap();
    manager.add_peer(&test_peer("peer1", public)).await;
    manager.record_direct_success("peer1", Some(public)).await;
    {
        let mut conns = manager.connections.write().await;
        conns.get_mut("peer1").unwrap().last_path_selection =
            Some(PathSelection::relay("stale", "stale relay selector snapshot"));
    }

    let peer = manager
        .diagnostics_with_path_selection(true, true, Duration::from_secs(5), None)
        .await
        .pop()
        .unwrap();
    assert_eq!(peer.state, ConnectionState::Direct);
    assert_eq!(peer.active_path, Some(NetworkPath::Direct));
    assert!(matches!(peer.direct_type, DirectPathType::PublicUdp | DirectPathType::PeerReflexive));
    assert_eq!(peer.selected_pair.as_ref().unwrap().remote_endpoint, public.to_string());
    assert_eq!(peer.current_direct_pair.as_ref().unwrap().remote_endpoint, public.to_string());
    assert_eq!(peer.last_path_selection.as_ref().unwrap().path, Some(NetworkPath::Direct));
}

#[tokio::test]
async fn direct_promotion_updates_selection_atomically() {
    let manager = PeerManager::new(test_config());
    let public: SocketAddr = "8.8.8.8:51847".parse().unwrap();
    manager.add_peer(&test_peer("peer1", public)).await;
    manager.record_direct_success("peer1", Some(public)).await;
    let conn = manager.get_connection("peer1").await.unwrap();
    let selection = conn.last_path_selection.expect("promotion selector snapshot");
    assert_eq!(selection.path, Some(NetworkPath::Direct));
    assert!(selection.direct_confirmed);
    assert_eq!(selection.direct_endpoint, Some(public));
}

#[tokio::test]
async fn path_selector_prefers_relay_when_confirmed_direct_quality_is_poor() {
    let config = test_config();
    let manager = PeerManager::new(config);
    let endpoint: SocketAddr = "127.0.0.1:51838".parse().unwrap();

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

    {
        let mut conns = manager.connections.write().await;
        let conn = conns.get_mut("peer1").unwrap();
        conn.direct_health.consecutive_failures = 1;
        conn.direct_health.failure_count = 1;
        conn.direct_health.rtt_ewma_ms = Some(650);
        conn.direct_health.jitter_ms = Some(120);
    }

    let selected = manager.select_path_for_data("peer1", true, true).await;
    assert_eq!(selected.path, Some(NetworkPath::Relay));
    assert_eq!(selected.reason_code, REASON_PATH_DIRECT_DEGRADED);
    assert!(!selected.direct_confirmed);
    assert!(!selected.relay_hedged);
    let direct_score = selected.direct_score.as_ref().unwrap().score;
    let relay_score = selected.relay_score.as_ref().unwrap().score;
    assert!(direct_score < DIRECT_CONFIRMED_MIN_SCORE);
    assert!(direct_score < relay_score);
}

#[tokio::test]
async fn degraded_direct_is_retained_until_relay_peer_path_is_confirmed() {
    let config = test_config();
    let manager = PeerManager::new(config);
    let endpoint: SocketAddr = "127.0.0.1:51842".parse().unwrap();

    manager.add_peer(&test_peer("peer1", endpoint)).await;
    manager
        .record_direct_probe_success_with_latency(
            "peer1",
            endpoint,
            Some(Duration::from_millis(700)),
        )
        .await;
    manager.record_direct_success("peer1", Some(endpoint)).await;
    {
        let mut conns = manager.connections.write().await;
        let conn = conns.get_mut("peer1").unwrap();
        conn.direct_health.consecutive_failures = 2;
        conn.direct_health.failure_count = 2;
        conn.direct_health.rtt_ewma_ms = Some(650);
        conn.direct_health.jitter_ms = Some(120);
    }

    let selected = manager.select_path_for_data("peer1", true, true).await;
    assert_eq!(selected.path, Some(NetworkPath::Direct));
    assert!(selected.direct_confirmed);
    assert!(!selected.relay_hedged);
    assert_eq!(selected.reason_code, REASON_PATH_DIRECT_DEGRADED);

    let diagnostics = manager
        .diagnostics_with_path_selection(true, true, Duration::from_secs(5), None)
        .await;
    assert_eq!(diagnostics[0].active_path, Some(NetworkPath::Direct));
    assert!(!diagnostics[0]
        .current_path_selection
        .as_ref()
        .unwrap()
        .relay_hedged);
}

#[tokio::test]
async fn in_flight_hole_punch_completion_after_direct_promotion_is_refused() {
    // Chained regression for the stale hole-punch transition: a hole-punch
    // task captures (generation, commit_seq) before setup, enters HolePunching
    // through the gate, then Direct is confirmed while the task is in flight.
    // Every later write-back attempt using the pre-promotion observations must
    // be refused: no state demotion, no selection change, no recovery restart.
    let manager = PeerManager::new(test_config());
    let endpoint: SocketAddr = "8.8.8.8:51850".parse().unwrap();
    manager.add_peer(&test_peer("peer1", endpoint)).await;
    let task_generation = manager.current_network_generation().await;
    let task_commit_seq = manager.direct_commit_seq_sync("peer1");
    manager
        .record_direct_probe_success_with_latency("peer1", endpoint, Some(Duration::from_millis(4)))
        .await;
    assert!(manager
        .begin_hole_punch_if_current("peer1", task_generation, task_commit_seq)
        .await);
    let started = manager.get_connection("peer1").await.unwrap();
    assert_eq!(started.state, ConnectionState::HolePunching);

    manager.record_direct_success("peer1", Some(endpoint)).await;
    let promoted = manager.get_connection("peer1").await.unwrap();
    assert_eq!(promoted.state, ConnectionState::Direct);
    assert_eq!(promoted.active_path(), Some(NetworkPath::Direct));
    let promoted_seq = promoted.direct_commit_seq;
    assert!(!manager.recovery_epoch_active("peer1").await);
    drop(promoted);

    assert!(!manager
        .begin_hole_punch_if_current("peer1", task_generation, task_commit_seq)
        .await);
    let conn = manager.get_connection("peer1").await.unwrap();
    assert_eq!(conn.state, ConnectionState::Direct);
    assert_eq!(conn.active_path(), Some(NetworkPath::Direct));
    assert_eq!(conn.endpoint, Some(endpoint));
    assert_eq!(conn.direct_commit_seq, promoted_seq);
    assert!(conn.direct_commit_seq > task_commit_seq.unwrap_or(0));
    assert!(!manager.recovery_epoch_active("peer1").await);
}

#[tokio::test]
async fn relay_connection_metadata_survives_direct_promotion_for_recovery() {
    // The relay path must remain available as a recovery mechanism after
    // Direct is confirmed: the relay server binding and relay health are
    // retained, relay keepalives keep refreshing relay bookkeeping, and none
    // of that may demote the confirmed Direct path or change the endpoint.
    let manager = PeerManager::new(test_config());
    let endpoint: SocketAddr = "8.8.8.8:51851".parse().unwrap();
    manager.add_peer(&test_peer("peer1", endpoint)).await;
    manager
        .record_relay_success("peer1", "tcp://relay.test:18081", true)
        .await;
    let relay = manager.get_connection("peer1").await.unwrap();
    assert_eq!(relay.state, ConnectionState::Relay);
    assert_eq!(relay.relay_server.as_deref(), Some("tcp://relay.test:18081"));

    manager.record_direct_success("peer1", Some(endpoint)).await;
    let promoted = manager.get_connection("peer1").await.unwrap();
    assert_eq!(promoted.state, ConnectionState::Direct);
    assert_eq!(promoted.active_path(), Some(NetworkPath::Direct));
    assert_eq!(promoted.endpoint, Some(endpoint));
    assert_eq!(
        promoted.relay_server.as_deref(),
        Some("tcp://relay.test:18081"),
        "relay binding must survive Direct promotion"
    );

    manager
        .record_relay_success_with_latency(
            "peer1",
            "tcp://relay.test:18081",
            false,
            Duration::from_millis(3),
        )
        .await;
    let keepalive = manager.get_connection("peer1").await.unwrap();
    assert_eq!(keepalive.state, ConnectionState::Direct);
    assert_eq!(keepalive.active_path(), Some(NetworkPath::Direct));
    assert_eq!(keepalive.endpoint, Some(endpoint));
    assert_eq!(
        keepalive.relay_server.as_deref(),
        Some("tcp://relay.test:18081")
    );
    assert!(
        keepalive
            .relay_health
            .rtt_ewma_ms
            .or(keepalive.relay_health.latency_ms)
            .is_some(),
        "relay health must keep refreshing while Direct is confirmed"
    );

    let diagnostics = manager
        .diagnostics_with_path_selection(true, true, Duration::from_secs(5), None)
        .await;
    assert_eq!(diagnostics[0].state, ConnectionState::Direct);
    assert_eq!(diagnostics[0].active_path, Some(NetworkPath::Direct));
}
