#[tokio::test]
async fn candidate_pairs_record_predicted_source_from_signal_metadata() {
    let config = test_config();
    let manager = PeerManager::new(config);
    let endpoint: SocketAddr = "127.0.0.1:51840".parse().unwrap();

    manager.add_peer(&test_peer("peer1", endpoint)).await;
    manager
        .add_candidates_with_sources(
            "peer1",
            &["203.0.113.10:40007".to_string()],
            &HashMap::from([("203.0.113.10:40007".to_string(), "predicted".to_string())]),
        )
        .await;

    let diagnostics = manager.diagnostics().await;
    let predicted = diagnostics[0]
        .candidate_pair_stats
        .iter()
        .find(|stats| stats.source == CandidatePairSource::Predicted)
        .unwrap();
    assert_eq!(predicted.current_pair_count, 1);
    assert!(diagnostics[0].candidate_pairs.iter().any(|pair| {
        pair.remote_endpoint == "203.0.113.10:40007"
            && pair.source == CandidatePairSource::Predicted
    }));
}

#[tokio::test]
async fn candidate_pair_stats_include_history_budget_diagnostics() {
    let mut history = TraversalHistory::default();
    history.record_failure(CandidatePairSource::Predicted);
    history.record_failure(CandidatePairSource::Predicted);
    history.record_failure(CandidatePairSource::Predicted);
    let manager = PeerManager::new_with_history(test_config(), None, history);
    let endpoint: SocketAddr = "127.0.0.1:51848".parse().unwrap();
    let predicted_endpoint = "203.0.113.10:40007".to_string();

    manager.add_peer(&test_peer("peer1", endpoint)).await;
    manager
        .add_candidates_with_sources(
            "peer1",
            std::slice::from_ref(&predicted_endpoint),
            &HashMap::from([(predicted_endpoint.clone(), "predicted".to_string())]),
        )
        .await;

    let diagnostics = manager.diagnostics().await;
    let predicted = diagnostics[0]
        .candidate_pair_stats
        .iter()
        .find(|stats| stats.source == CandidatePairSource::Predicted)
        .unwrap();

    assert_eq!(predicted.current_pair_count, 1);
    assert_eq!(predicted.history_success_count, Some(0));
    assert_eq!(predicted.history_failure_count, Some(3));
    assert_eq!(predicted.history_consecutive_failures, Some(3));
    assert_eq!(predicted.history_success_rate_per_mille, Some(0));
    assert!(predicted
        .history_cooldown_remaining_ms
        .is_some_and(|remaining| remaining > 0));
    assert_eq!(predicted.source_quality_rank, Some(1100));
    assert_eq!(
        predicted.probe_budget_per_cycle,
        Some(PREDICTED_PROBE_COOLDOWN_BUDGET_PER_CYCLE)
    );
    assert_eq!(
        predicted.probe_budget_reason.as_deref(),
        Some("history_cooldown")
    );

    let json = serde_json::to_value(&diagnostics[0]).unwrap();
    let predicted_json = json["candidate_pair_stats"]
        .as_array()
        .unwrap()
        .iter()
        .find(|stats| stats["source"] == "predicted")
        .unwrap();
    assert_eq!(predicted_json["probe_budget_reason"], "history_cooldown");
}

#[tokio::test]
async fn fresh_candidate_signal_replaces_stale_registry_endpoint() {
    let manager = PeerManager::new(test_config());
    let stale: SocketAddr = "203.0.113.10:41000".parse().unwrap();
    let fresh: SocketAddr = "203.0.113.10:42000".parse().unwrap();
    manager.add_peer(&test_peer("peer1", stale)).await;

    manager
        .add_candidates("peer1", &["203.0.113.10:41500".to_string()])
        .await;
    manager.add_candidates("peer1", &[fresh.to_string()]).await;

    let conn = manager.get_connection("peer1").await.unwrap();
    assert_eq!(conn.signaled_endpoint, None);
    assert!(!conn.candidates.contains(&stale.to_string()));
    assert!(conn.candidates.contains(&fresh.to_string()));
    assert_eq!(conn.endpoint, Some(fresh));
}

#[tokio::test]
async fn versioned_candidates_reject_stale_and_expired_sets() {
    let manager = PeerManager::new(test_config());
    let initial: SocketAddr = "203.0.113.10:42000".parse().unwrap();
    let stale: SocketAddr = "203.0.113.10:41000".parse().unwrap();
    let expired: SocketAddr = "203.0.113.10:43000".parse().unwrap();
    manager.add_peer(&test_peer("peer1", initial)).await;

    manager
        .add_candidates_with_metadata(
            "peer1",
            &[initial.to_string()],
            &HashMap::new(),
            10,
            Some(u64::MAX),
        )
        .await;
    manager
        .add_candidates_with_metadata(
            "peer1",
            &[stale.to_string()],
            &HashMap::new(),
            9,
            Some(u64::MAX),
        )
        .await;
    manager
        .add_candidates_with_metadata(
            "peer1",
            &[expired.to_string()],
            &HashMap::new(),
            11,
            Some(1),
        )
        .await;

    let conn = manager.get_connection("peer1").await.unwrap();
    assert_eq!(conn.last_candidate_generation, 10);
    assert!(conn.candidates.contains(&initial.to_string()));
    assert!(!conn.candidates.contains(&stale.to_string()));
    assert!(!conn.candidates.contains(&expired.to_string()));
    assert!(conn
        .direct_events
        .iter()
        .any(|event| event.stage == "candidates_stale"));
    assert!(conn
        .direct_events
        .iter()
        .any(|event| event.stage == "candidates_expired"));
}

#[tokio::test]
async fn punch_rounds_follow_observed_nat_behavior() {
    let manager = PeerManager::new(test_config());
    assert_eq!(manager.recommended_punch_attempts(10).await, 6);

    let mut endpoint_independent = birthday_nat_profile();
    endpoint_independent.mapping_behavior = MappingBehavior::EndpointIndependent;
    manager.update_nat_profile(endpoint_independent).await;
    assert_eq!(manager.recommended_punch_attempts(10).await, 4);

    manager.update_nat_profile(birthday_nat_profile()).await;
    assert_eq!(manager.recommended_punch_attempts(10).await, 8);
}

#[tokio::test]
async fn predicted_candidates_have_independent_probe_budget() {
    let config = test_config();
    let manager = PeerManager::new(config);
    let endpoint: SocketAddr = "127.0.0.1:51841".parse().unwrap();

    manager.add_peer(&test_peer("peer1", endpoint)).await;
    let candidates = (0..24)
        .map(|index| format!("203.0.113.10:{}", 40_007 + index * 2))
        .collect::<Vec<_>>();
    let sources = candidates
        .iter()
        .map(|candidate| (candidate.clone(), "predicted".to_string()))
        .collect::<HashMap<_, _>>();
    manager
        .add_candidates_with_sources("peer1", &candidates, &sources)
        .await;

    let targets = manager.direct_probe_targets_for("peer1").await;
    let predicted_count = targets
        .iter()
        .filter(|endpoint| endpoint.ip().to_string() == "203.0.113.10")
        .count();
    assert_eq!(predicted_count, PREDICTED_PROBE_BUDGET_PER_CYCLE);
}

#[tokio::test]
async fn stable_public_candidate_precedes_predicted_budget_in_synchronized_punch() {
    let mut history = TraversalHistory::default();
    history.record_success(CandidatePairSource::Predicted);
    history.record_success(CandidatePairSource::Predicted);
    let manager = PeerManager::new_with_history(test_config(), None, history);
    let stable_endpoint: SocketAddr = "8.8.8.8:40000".parse().unwrap();

    manager.add_peer(&test_peer("peer1", stable_endpoint)).await;
    let candidates = (0..24)
        .map(|index| format!("8.8.8.8:{}", 41_000 + index))
        .collect::<Vec<_>>();
    let sources = candidates
        .iter()
        .map(|candidate| (candidate.clone(), "predicted".to_string()))
        .collect::<HashMap<_, _>>();
    let predicted_endpoints = candidates
        .iter()
        .map(|candidate| candidate.parse::<SocketAddr>().unwrap())
        .collect::<HashSet<_>>();
    manager
        .add_candidates_with_sources("peer1", &candidates, &sources)
        .await;

    let targets = manager.direct_probe_targets_for("peer1").await;
    let predicted_count = targets
        .iter()
        .filter(|target| predicted_endpoints.contains(target))
        .count();

    assert_eq!(targets.first().copied(), Some(stable_endpoint));
    assert!(targets.contains(&stable_endpoint));
    assert_eq!(predicted_count, PREDICTED_PROBE_SUCCESS_BUDGET_PER_CYCLE);
}

#[tokio::test]
async fn synchronized_punch_keeps_predicted_budget_during_history_cooldown() {
    let mut history = TraversalHistory::default();
    history.record_failure(CandidatePairSource::Predicted);
    history.record_failure(CandidatePairSource::Predicted);
    history.record_failure(CandidatePairSource::Predicted);
    let manager = PeerManager::new_with_history(test_config(), None, history);
    let stable_endpoint: SocketAddr = "8.8.8.8:40000".parse().unwrap();

    manager.add_peer(&test_peer("peer1", stable_endpoint)).await;
    manager.update_nat_profile(birthday_nat_profile()).await;

    let predicted_candidates = (0..24)
        .map(|index| format!("8.8.8.8:{}", 41_000 + index))
        .collect::<Vec<_>>();
    let predicted_endpoints = predicted_candidates
        .iter()
        .map(|candidate| candidate.parse::<SocketAddr>().unwrap())
        .collect::<HashSet<_>>();
    let sources = predicted_candidates
        .iter()
        .map(|candidate| (candidate.clone(), "predicted".to_string()))
        .collect::<HashMap<_, _>>();
    manager
        .add_candidates_with_sources("peer1", &predicted_candidates, &sources)
        .await;

    let targets = manager.direct_probe_targets_for("peer1").await;
    let predicted_positions = targets
        .iter()
        .enumerate()
        .filter_map(|(index, target)| predicted_endpoints.contains(target).then_some(index))
        .collect::<Vec<_>>();
    let first_birthday_position = targets
        .iter()
        .position(|target| {
            target.ip() == stable_endpoint.ip()
                && !predicted_endpoints.contains(target)
                && *target != stable_endpoint
        })
        .expect("birthday target should still be present");

    assert_eq!(predicted_positions.len(), PREDICTED_PROBE_BUDGET_PER_CYCLE);
    assert!(predicted_positions
        .iter()
        .all(|position| *position < first_birthday_position));

    let diagnostics = manager.diagnostics().await;
    let predicted = diagnostics[0]
        .candidate_pair_stats
        .iter()
        .find(|stats| stats.source == CandidatePairSource::Predicted)
        .unwrap();
    assert_eq!(
        predicted.probe_budget_per_cycle,
        Some(PREDICTED_PROBE_COOLDOWN_BUDGET_PER_CYCLE)
    );
    assert_eq!(
        predicted.probe_budget_reason.as_deref(),
        Some("history_cooldown")
    );
}

#[tokio::test]
async fn synchronized_punch_prioritizes_failed_predicted_before_birthday() {
    let manager = PeerManager::new(test_config());
    let stable_endpoint: SocketAddr = "8.8.8.8:40000".parse().unwrap();

    manager.add_peer(&test_peer("peer1", stable_endpoint)).await;
    manager.update_nat_profile(birthday_nat_profile()).await;

    let predicted_candidates = (0..24)
        .map(|index| format!("8.8.8.8:{}", 41_000 + index))
        .collect::<Vec<_>>();
    let predicted_endpoints = predicted_candidates
        .iter()
        .map(|candidate| candidate.parse::<SocketAddr>().unwrap())
        .collect::<HashSet<_>>();
    let sources = predicted_candidates
        .iter()
        .map(|candidate| (candidate.clone(), "predicted".to_string()))
        .collect::<HashMap<_, _>>();
    manager
        .add_candidates_with_sources("peer1", &predicted_candidates, &sources)
        .await;

    {
        let mut conns = manager.connections.write().await;
        let conn = conns.get_mut("peer1").unwrap();
        for endpoint in &predicted_endpoints {
            conn.ensure_candidate_pair_with_source(*endpoint, 0, CandidatePairSource::Predicted)
                .record_failure(REASON_DIRECT_PROBE_FAILED, "recent predicted miss", None);
        }
    }

    let targets = manager.direct_probe_targets_for("peer1").await;
    let predicted_positions = targets
        .iter()
        .enumerate()
        .filter_map(|(index, target)| predicted_endpoints.contains(target).then_some(index))
        .collect::<Vec<_>>();
    let first_birthday_position = targets
        .iter()
        .position(|target| {
            target.ip() == stable_endpoint.ip()
                && !predicted_endpoints.contains(target)
                && *target != stable_endpoint
        })
        .expect("birthday target should still be present");

    assert_eq!(predicted_positions.len(), PREDICTED_PROBE_BUDGET_PER_CYCLE);
    assert!(predicted_positions
        .iter()
        .all(|position| *position < first_birthday_position));
}
