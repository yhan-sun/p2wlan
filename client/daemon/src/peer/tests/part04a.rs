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

    // The recovery stage machine gates wide scatter: the first due pass (the
    // epoch's Initial stage) must NOT build a birthday plan.  Only after
    // explicit no-ACK feedback reaches the ScatterExtended stage may the
    // due targets include the birthday window.
    let initial_targets = manager
        .direct_probe_targets_due(Duration::from_secs(0))
        .await;
    assert_eq!(initial_targets.len(), 1);
    assert_eq!(initial_targets[0].peer_id, "peer1");
    assert!(
        initial_targets[0].birthday_plan.is_none(),
        "the Initial recovery stage must not build a birthday plan"
    );
    assert!(
        initial_targets[0].candidates.iter().all(|target| {
            *target == stable_endpoint || *target == second_observed
        }),
        "the Initial recovery stage only probes trusted endpoints"
    );

    manager
        .advance_recovery_stage_after_no_ack("peer1", "test: no ack -> predicted")
        .await;
    manager
        .advance_recovery_stage_after_no_ack("peer1", "test: no ack -> scatter_small")
        .await;
    manager
        .advance_recovery_stage_after_no_ack("peer1", "test: no ack -> scatter_extended")
        .await;

    let due_targets = manager
        .direct_probe_targets_due(Duration::from_secs(0))
        .await;
    assert_eq!(due_targets.len(), 1);
    assert_eq!(due_targets[0].peer_id, "peer1");

    let targets = &due_targets[0].candidates;
    let birthday_count = targets
        .iter()
        .filter(|target| {
            **target != stable_endpoint
                && **target != second_observed
                && target.ip() == stable_endpoint.ip()
        })
        .count();
    // The wide window is generated in bounded per-plan slices: the expected
    // set mirrors the sliced budget exactly.  v0.1.116 also bounds every
    // ActivePool stage (ScatterExtended included) by the 192-datagram session
    // ceiling so one session can fully cover a planned window without the
    // mid-window truncation that stalled the birthday cursor (a 384-candidate
    // plan was cut at 171 endpoints by the old 512-datagram session cap).
    let stage_window = RECOVERY_STAGE_SCATTER_EXTENDED_MAX_PROBES as usize;
    let sliced_budget = birthday_budget.min(
        stage_window
            .saturating_sub([stable_endpoint, second_observed].len())
            .min(BIRTHDAY_PLAN_SLICE.saturating_sub([stable_endpoint, second_observed].len())),
    );
    let expected_birthday_count = birthday_probe_endpoints_for_bases(
        &[stable_endpoint, second_observed],
        sliced_budget,
    )
    .into_iter()
    .filter(|target| *target != stable_endpoint && *target != second_observed)
    .count();

    assert_eq!(targets.first().copied(), Some(stable_endpoint));
    assert!(targets.contains(&stable_endpoint));
    assert_eq!(birthday_count, expected_birthday_count);
}

#[tokio::test]
async fn probe_target_sort_uses_single_time_snapshot_for_freshness() {
    let manager = PeerManager::new(test_config());
    let base_ip = "8.8.8.8";
    let candidates = (0..128)
        .map(|index| format!("{base_ip}:{}", 40_000 + index))
        .collect::<Vec<_>>();
    let candidate_sources = candidates
        .iter()
        .map(|candidate| (candidate.clone(), "stun_observed".to_string()))
        .collect::<HashMap<_, _>>();
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
        .add_candidates_with_sources("peer1", &candidates, &candidate_sources)
        .await;

    {
        let mut conns = manager.connections.write().await;
        let conn = conns.get_mut("peer1").unwrap();
        let threshold = Instant::now() - Duration::from_secs(3);
        for pair in &mut conn.candidate_pairs {
            pair.source_observed_at = Some(threshold);
        }
    }

    for _ in 0..8 {
        let due_targets = manager
            .direct_probe_targets_due(Duration::from_secs(0))
            .await;
        assert_eq!(due_targets.len(), 1);
        assert_eq!(due_targets[0].peer_id, "peer1");
        assert!(!due_targets[0].candidates.is_empty());
    }
}

#[tokio::test]
async fn healthy_selected_peer_reflexive_direct_suppresses_background_full_scatter() {
    let manager = PeerManager::new(test_config());
    let selected_endpoint: SocketAddr = "8.8.8.8:41000".parse().unwrap();
    let local: SocketAddr = "192.168.1.10:51820".parse().unwrap();
    let mut candidates = vec![selected_endpoint.to_string()];
    candidates.extend(
        (0..96)
            .map(|index| format!("9.9.9.9:{}", 40_000 + index))
            .collect::<Vec<_>>(),
    );
    let candidate_sources = candidates
        .iter()
        .map(|candidate| {
            let source = if candidate == &selected_endpoint.to_string() {
                "peer_reflexive"
            } else {
                "stun_observed"
            };
            (candidate.clone(), source.to_string())
        })
        .collect::<HashMap<_, _>>();

    manager.add_peer(&test_peer("peer1", selected_endpoint)).await;
    manager
        .add_candidates_with_sources("peer1", &candidates, &candidate_sources)
        .await;
    manager
        .record_direct_success_with_local_endpoint("peer1", Some(selected_endpoint), Some(local))
        .await;

    assert!(manager.direct_probe_targets().await.is_empty());
    assert!(manager.direct_probe_targets_for("peer1").await.is_empty());
    assert_eq!(
        manager.direct_endpoints().await,
        vec![("peer1".to_string(), selected_endpoint)]
    );

    for _ in 0..DIRECT_KEEPALIVE_FAILURE_THRESHOLD {
        manager
            .record_direct_keepalive_timeout_for_generation("peer1", selected_endpoint, 0)
            .await;
    }
    assert!(!manager.direct_probe_targets().await.is_empty());
}

#[tokio::test]
async fn relay_assisted_punch_deferred_until_direct_stops_being_healthy() {
    let manager = PeerManager::new(test_config());
    let selected_endpoint: SocketAddr = "8.8.8.8:41000".parse().unwrap();
    let local: SocketAddr = "192.168.1.10:51820".parse().unwrap();
    manager.add_peer(&test_peer("peer1", selected_endpoint)).await;
    manager
        .add_candidates_with_sources(
            "peer1",
            &[selected_endpoint.to_string()],
            &HashMap::from([(selected_endpoint.to_string(), "peer_reflexive".to_string())]),
        )
        .await;
    manager
        .record_direct_success_with_local_endpoint("peer1", Some(selected_endpoint), Some(local))
        .await;
    assert!(manager.should_defer_relay_assisted_punch("peer1").await);

    for _ in 0..DIRECT_KEEPALIVE_FAILURE_THRESHOLD {
        manager
            .record_direct_keepalive_timeout_for_generation("peer1", selected_endpoint, 0)
            .await;
    }
    assert!(!manager.should_defer_relay_assisted_punch("peer1").await);
}

#[tokio::test]
async fn direct_confirmed_retires_speculative_probing_pairs_from_stats() {
    let manager = PeerManager::new(test_config());
    let selected_endpoint: SocketAddr = "8.8.8.8:41000".parse().unwrap();
    let local: SocketAddr = "192.168.1.10:51820".parse().unwrap();
    let mut candidates = vec![selected_endpoint.to_string()];
    candidates.extend((0..88).map(|index| format!("9.9.9.9:{}", 40_000 + index)));
    candidates.extend((0..32).map(|index| format!("9.9.9.9:{}", 41_000 + index)));
    let candidate_sources = candidates
        .iter()
        .enumerate()
        .map(|(index, candidate)| {
            let source = if index == 0 {
                "peer_reflexive"
            } else if index <= 88 {
                "predicted"
            } else {
                "stun_observed"
            };
            (candidate.clone(), source.to_string())
        })
        .collect::<HashMap<_, _>>();
    manager.add_peer(&test_peer("peer1", selected_endpoint)).await;
    manager
        .add_candidates_with_sources("peer1", &candidates, &candidate_sources)
        .await;
    manager
        .record_direct_success_with_local_endpoint("peer1", Some(selected_endpoint), Some(local))
        .await;

    assert!(manager.direct_probe_targets().await.is_empty());

    let diagnostics = manager.diagnostics().await;
    let stats = &diagnostics[0].candidate_pair_stats;
    let predicted = stats
        .iter()
        .find(|stats| stats.source == CandidatePairSource::Predicted)
        .unwrap();
    assert_eq!(predicted.pair_count, 88);
    assert_eq!(predicted.probing_count, 0);
    assert_eq!(predicted.frozen_count, 88);
    let stun = stats
        .iter()
        .find(|stats| stats.source == CandidatePairSource::StunObserved)
        .unwrap();
    assert_eq!(stun.pair_count, 32);
    assert_eq!(stun.probing_count, 0);
    assert_eq!(stun.frozen_count, 32);
    let peer_reflexive = stats
        .iter()
        .find(|stats| stats.source == CandidatePairSource::PeerReflexive)
        .unwrap();
    assert_eq!(peer_reflexive.selected_count, 1);

    for _ in 0..DIRECT_KEEPALIVE_FAILURE_THRESHOLD {
        manager
            .record_direct_keepalive_timeout_for_generation("peer1", selected_endpoint, 0)
            .await;
    }
    assert!(!manager.direct_probe_targets().await.is_empty());
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
    assert_eq!(due_targets[0].candidates, vec![stable_endpoint]);
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
fn direct_retry_backoff_is_capped_for_fast_recovery() {
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
    assert_eq!(health.retry_after(base), Duration::from_secs(8));

    health.record_failure(REASON_DIRECT_PROBE_FAILED, "sixth failure");
    assert_eq!(health.retry_after(base), Duration::from_secs(8));

    health.record_failure(REASON_DIRECT_PROBE_FAILED, "seventh failure");
    assert_eq!(health.retry_after(base), Duration::from_secs(8));

    health.record_failure(REASON_DIRECT_PROBE_FAILED, "eighth failure");
    assert_eq!(health.retry_after(base), Duration::from_secs(8));
}
