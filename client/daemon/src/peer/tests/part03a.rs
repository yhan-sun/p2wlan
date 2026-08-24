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
async fn fresh_mapping_prediction_result_is_deduplicated_per_generation_and_port() {
    let manager = PeerManager::new(test_config());
    let endpoint: SocketAddr = "127.0.0.1:51841".parse().unwrap();
    manager.add_peer(&test_peer("peer1", endpoint)).await;

    let model = p2pnet_nat::mapping::build_model(
        &[45390, 45391, 45392],
        Some("203.0.113.10".parse().unwrap()),
        1_000,
    );
    manager
        .record_fresh_mapping(
            "peer1",
            model,
            vec![45393, 45394, 45395, 45396],
            "0.0.0.0:58980".parse().unwrap(),
            Some("203.0.113.10".parse().unwrap()),
            39,
            0,
        )
        .await;

    let actual = "203.0.113.10:45395".parse().unwrap();
    manager
        .record_fresh_mapping_prediction_result("peer1", actual)
        .await;
    // Retransmitted peer-reflexive notifications repeat the same mapping.
    manager
        .record_fresh_mapping_prediction_result("peer1", actual)
        .await;
    manager
        .record_fresh_mapping_prediction_result("peer1", actual)
        .await;
    // A different observed port is a genuinely new result.
    manager
        .record_fresh_mapping_prediction_result("peer1", "203.0.113.10:45396".parse().unwrap())
        .await;

    let history = manager
        .fresh_mapping_history
        .lock()
        .unwrap()
        .get("peer1")
        .cloned()
        .unwrap();
    assert_eq!(history.len(), 2, "duplicate results must be suppressed");
    assert_eq!(history[0].punch_generation, 39);
    assert_eq!(history[0].actual_port, 45395);
    assert!(history[0].hit_window);
    assert_eq!(history[1].actual_port, 45396);
}

#[tokio::test]
async fn fresh_mapping_prediction_result_records_hit_rank() {
    let manager = PeerManager::new(test_config());
    let endpoint: SocketAddr = "127.0.0.1:51843".parse().unwrap();
    manager.add_peer(&test_peer("peer1", endpoint)).await;

    let model = p2pnet_nat::mapping::build_model(
        &[45390, 45391, 45392],
        Some("203.0.113.10".parse().unwrap()),
        1_000,
    );
    // Rank-ordered prediction window: rank0=45393, rank1=45394, rank2=45395,
    // rank3=45396.  Recording the actually-learned peer port must capture WHICH
    // position it hit (the calibration metric), not just in-window/miss.
    manager
        .record_fresh_mapping(
            "peer1",
            model,
            vec![45393, 45394, 45395, 45396],
            "0.0.0.0:58980".parse().unwrap(),
            Some("203.0.113.10".parse().unwrap()),
            41,
            0,
        )
        .await;

    // A hit at rank 2.
    manager
        .record_fresh_mapping_prediction_result("peer1", "203.0.113.10:45395".parse().unwrap())
        .await;
    // A miss: port 45398 is outside the predicted window.
    manager
        .record_fresh_mapping_prediction_result("peer1", "203.0.113.10:45398".parse().unwrap())
        .await;

    let history = manager
        .fresh_mapping_history
        .lock()
        .unwrap()
        .get("peer1")
        .cloned()
        .unwrap();
    let hit = history.iter().find(|r| r.actual_port == 45395).unwrap();
    assert!(hit.hit_window);
    assert_eq!(
        hit.hit_rank,
        Some(2),
        "45395 is the 3rd (rank 2) prediction"
    );
    // Top-K calibration (P1-C): rank 2 is inside top-6/top-24/top-96 but not
    // top-1.
    assert!(!hit.hit_top1, "rank 2 is not a top-1 hit");
    assert!(hit.hit_top6, "rank 2 is within top-6");
    assert!(hit.hit_top24, "rank 2 is within top-24");
    assert!(hit.hit_top96, "rank 2 is within top-96");

    let miss = history.iter().find(|r| r.actual_port == 45398).unwrap();
    assert!(!miss.hit_window);
    assert_eq!(miss.hit_rank, None, "an out-of-window port has no hit rank");
    assert!(
        !miss.hit_top1 && !miss.hit_top6 && !miss.hit_top24 && !miss.hit_top96,
        "a miss hits no calibration prefix"
    );
}

#[tokio::test]
async fn fresh_mapping_prediction_result_records_top1_hit() {
    // P1-C: a top-1 hit (rank 0) must be flagged in every prefix, so the
    // calibration consumer can distinguish a clean top-1 from a deep window hit.
    let manager = PeerManager::new(test_config());
    let endpoint: SocketAddr = "127.0.0.1:51844".parse().unwrap();
    manager.add_peer(&test_peer("peer1", endpoint)).await;

    let model = p2pnet_nat::mapping::build_model(
        &[45390, 45391, 45392],
        Some("203.0.113.10".parse().unwrap()),
        1_000,
    );
    manager
        .record_fresh_mapping(
            "peer1",
            model,
            vec![45393, 45394, 45395, 45396],
            "0.0.0.0:58980".parse().unwrap(),
            Some("203.0.113.10".parse().unwrap()),
            42,
            0,
        )
        .await;

    // A hit at rank 0 (the top prediction).
    manager
        .record_fresh_mapping_prediction_result("peer1", "203.0.113.10:45393".parse().unwrap())
        .await;

    let history = manager
        .fresh_mapping_history
        .lock()
        .unwrap()
        .get("peer1")
        .cloned()
        .unwrap();
    let hit = history.iter().find(|r| r.actual_port == 45393).unwrap();
    assert_eq!(
        hit.hit_rank,
        Some(0),
        "45393 is the top (rank 0) prediction"
    );
    assert!(hit.hit_top1, "rank 0 is a top-1 hit");
    assert!(hit.hit_top6 && hit.hit_top24 && hit.hit_top96);
}

#[tokio::test]
async fn fresh_prediction_label_classifies_as_predicted_with_rank() {
    let manager = PeerManager::new(test_config());
    let endpoint: SocketAddr = "127.0.0.1:51842".parse().unwrap();
    manager.add_peer(&test_peer("peer1", endpoint)).await;

    let predicted = "203.0.113.10:40007".to_string();
    let signaled = "203.0.113.10:40001".to_string();
    manager
        .add_candidates_with_sources(
            "peer1",
            &[signaled.clone(), predicted.clone()],
            &HashMap::from([
                (signaled.clone(), "stun_observed".to_string()),
                (
                    predicted.clone(),
                    format!("{}39", crate::FRESH_PREDICTION_SOURCE_LABEL_PREFIX),
                ),
            ]),
        )
        .await;

    let generation = manager.current_network_generation().await;
    let conns = manager.connections.read().await;
    let conn = conns.get("peer1").unwrap();
    let pair = conn
        .candidate_pairs
        .iter()
        .find(|pair| pair.remote_endpoint.to_string() == predicted)
        .expect("predicted endpoint must have a candidate pair");
    assert_eq!(pair.source, CandidatePairSource::Predicted);
    assert_eq!(pair.local_generation, generation);
    assert_eq!(
        pair.signal_rank,
        Some(1),
        "predicted window order must be preserved"
    );
    let ordinary = conn
        .candidate_pairs
        .iter()
        .find(|pair| pair.remote_endpoint.to_string() == signaled)
        .unwrap();
    assert_eq!(ordinary.source, CandidatePairSource::StunObserved);
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
async fn remote_candidate_refresh_invalidates_old_direct_pair_and_ack() {
    let manager = PeerManager::new(test_config());
    let old_endpoint: SocketAddr = "203.0.113.10:41000".parse().unwrap();
    let fresh_endpoint: SocketAddr = "203.0.113.10:42000".parse().unwrap();
    manager.add_peer(&test_peer("peer1", old_endpoint)).await;

    assert_eq!(
        manager
            .add_candidates_with_metadata(
                "peer1",
                &[old_endpoint.to_string()],
                &HashMap::new(),
                10,
                Some(u64::MAX),
            )
            .await,
        CandidateSetApplyResult::Applied
    );
    manager
        .record_direct_probe_success_with_latency(
            "peer1",
            old_endpoint,
            Some(Duration::from_millis(7)),
        )
        .await;
    manager
        .record_direct_success("peer1", Some(old_endpoint))
        .await;
    assert_eq!(
        manager.direct_endpoint_for_send("peer1").await,
        Some(old_endpoint)
    );

    assert_eq!(
        manager
            .add_candidates_with_metadata(
                "peer1",
                &[fresh_endpoint.to_string()],
                &HashMap::new(),
                11,
                Some(u64::MAX),
            )
            .await,
        CandidateSetApplyResult::Applied
    );

    // A remote candidate handover must fence both the selected pair and any
    // delayed ACK from the old candidate set.  The old endpoint may remain in
    // diagnostics/history, but it must not remain an active Direct target.
    assert_ne!(
        manager.direct_endpoint_for_send("peer1").await,
        Some(old_endpoint)
    );
    assert_eq!(
        manager
            .get_connection("peer1")
            .await
            .expect("peer must remain present")
            .state,
        ConnectionState::FallbackToRelay,
        "remote handover must retain relay fallback while Direct is invalidated"
    );
    assert!(
        !manager
            .record_direct_success_for_generation(
                "peer1",
                Some(old_endpoint),
                manager.current_network_generation().await,
            )
            .await
    );
    let conn = manager.get_connection("peer1").await.unwrap();
    let old_pair = conn
        .candidate_pairs
        .iter()
        .find(|pair| pair.remote_endpoint == old_endpoint)
        .expect("old pair should remain available for diagnostics");
    assert_ne!(old_pair.state, CandidatePairState::Selected);
    assert_ne!(conn.endpoint, Some(old_endpoint));
    assert_eq!(conn.signaled_endpoint, None);
    assert!(conn.candidates.contains(&fresh_endpoint.to_string()));
    let diagnostics = manager
        .diagnostics_with_path_selection(true, false, Duration::from_secs(5), None)
        .await
        .into_iter()
        .find(|diagnostics| diagnostics.node_id == "peer1")
        .expect("peer diagnostics must remain available after handover");
    assert_ne!(
        diagnostics.active_path,
        Some(NetworkPath::Direct),
        "diagnostics must not expose the retired Direct path"
    );
    assert!(diagnostics
        .selected_pair
        .as_ref()
        .is_none_or(|pair| pair.remote_endpoint != old_endpoint.to_string()));
}

#[tokio::test]
async fn identical_versioned_candidate_refresh_advances_only_freshness_revision() {
    let manager = PeerManager::new(test_config());
    let endpoint: SocketAddr = "203.0.113.10:41030".parse().unwrap();
    let initial_sources = HashMap::from([(endpoint.to_string(), "predicted".to_string())]);
    let refreshed_sources = HashMap::from([(endpoint.to_string(), "stun_observed".to_string())]);
    manager.add_peer(&test_peer("peer1", endpoint)).await;
    assert_eq!(
        manager
            .add_candidates_with_metadata(
                "peer1",
                &[endpoint.to_string()],
                &initial_sources,
                30,
                Some(u64::MAX),
            )
            .await,
        CandidateSetApplyResult::Applied
    );
    manager
        .record_direct_probe_success_with_latency("peer1", endpoint, Some(Duration::from_millis(5)))
        .await;
    manager.record_direct_success("peer1", Some(endpoint)).await;

    let before = manager.get_connection("peer1").await.unwrap();
    let remote_epoch = before.remote_candidate_epoch();
    let direct_commit_seq = before.direct_commit_seq;
    let invalidation_count = before
        .direct_events
        .iter()
        .filter(|event| event.stage == "remote_candidates_invalidated")
        .count();
    assert_eq!(before.state, ConnectionState::Direct);

    // Production emits a new candidate generation for every signal, including
    // a routine WireGuard rekey. Reusing the same candidate set is freshness,
    // not evidence that the remote UDP transport changed. Source metadata can
    // be refined independently without turning the refresh into a handover.
    assert_eq!(
        manager
            .add_candidates_with_metadata(
                "peer1",
                &[endpoint.to_string()],
                &refreshed_sources,
                31,
                Some(u64::MAX),
            )
            .await,
        CandidateSetApplyResult::Applied
    );

    let after = manager.get_connection("peer1").await.unwrap();
    assert_eq!(after.last_candidate_generation, 31);
    assert_eq!(after.remote_candidate_epoch(), remote_epoch);
    assert_eq!(after.direct_commit_seq, direct_commit_seq);
    assert_eq!(after.state, ConnectionState::Direct);
    assert_eq!(after.endpoint, Some(endpoint));
    assert!(after.candidate_pairs.iter().any(|pair| {
        pair.remote_endpoint == endpoint
            && pair.source == CandidatePairSource::StunObserved
            && pair.state == CandidatePairState::Selected
    }));
    assert_eq!(
        manager.direct_endpoint_for_send("peer1").await,
        Some(endpoint)
    );
    assert!(after
        .direct_events
        .iter()
        .any(|event| event.stage == "candidate_revision_refreshed"));
    assert_eq!(
        after
            .direct_events
            .iter()
            .filter(|event| event.stage == "remote_candidates_invalidated")
            .count(),
        invalidation_count,
        "an identical candidate revision must not invalidate the transport epoch",
    );
}

#[tokio::test]
async fn rekey_candidate_change_retains_encrypted_confirmed_endpoint() {
    let manager = PeerManager::new(test_config());
    let selected: SocketAddr = "203.0.113.10:41100".parse().unwrap();
    let retired_alternate: SocketAddr = "203.0.113.10:41101".parse().unwrap();
    let new_alternate: SocketAddr = "203.0.113.10:41102".parse().unwrap();
    manager.add_peer(&test_peer("peer1", selected)).await;
    assert_eq!(
        manager
            .add_candidates_with_metadata(
                "peer1",
                &[selected.to_string(), retired_alternate.to_string()],
                &HashMap::new(),
                40,
                Some(u64::MAX),
            )
            .await,
        CandidateSetApplyResult::Applied
    );
    manager
        .record_direct_probe_success_with_latency("peer1", selected, Some(Duration::from_millis(4)))
        .await;
    manager.record_direct_success("peer1", Some(selected)).await;

    let before = manager.get_connection("peer1").await.unwrap();
    let remote_epoch = before.remote_candidate_epoch();
    let direct_commit_seq = before.direct_commit_seq;
    assert_eq!(before.state, ConnectionState::Direct);

    assert_eq!(
        manager
            .add_candidates_with_metadata(
                "peer1",
                &[selected.to_string(), new_alternate.to_string()],
                &HashMap::new(),
                41,
                Some(u64::MAX),
            )
            .await,
        CandidateSetApplyResult::Applied
    );

    let after = manager.get_connection("peer1").await.unwrap();
    assert_eq!(after.last_candidate_generation, 41);
    assert_eq!(after.remote_candidate_epoch(), remote_epoch);
    assert_eq!(after.direct_commit_seq, direct_commit_seq);
    assert_eq!(after.state, ConnectionState::Direct);
    assert_eq!(after.endpoint, Some(selected));
    assert!(after.candidates.contains(&selected.to_string()));
    assert!(after.candidates.contains(&new_alternate.to_string()));
    assert!(!after.candidates.contains(&retired_alternate.to_string()));
    assert!(!after
        .candidate_pairs
        .iter()
        .any(|pair| pair.remote_endpoint == retired_alternate
            && pair.remote_candidate_epoch == remote_epoch));
    assert!(after
        .direct_events
        .iter()
        .any(|event| event.stage == "remote_candidate_revision_direct_retained"));

    // A delayed confirmation for the withdrawn alternate cannot replace the
    // make-before-break endpoint merely because the transport epoch stayed up.
    assert!(
        !manager
            .record_direct_success_for_generation(
                "peer1",
                Some(retired_alternate),
                manager.current_network_generation().await,
            )
            .await
    );
    assert!(
        !manager
            .record_direct_probe_success_with_latency_for_generation_and_local_endpoint(
                "peer1",
                retired_alternate,
                Some(Duration::from_millis(3)),
                manager.current_network_generation().await,
                None,
            )
            .await
    );
    assert_eq!(
        manager.direct_endpoint_for_send("peer1").await,
        Some(selected)
    );
}

#[tokio::test]
async fn remote_candidate_refresh_drops_stale_pending_probe_target() {
    let manager = PeerManager::new(test_config());
    let old_endpoint: SocketAddr = "203.0.113.10:41000".parse().unwrap();
    let fresh_endpoint: SocketAddr = "203.0.113.10:41001".parse().unwrap();
    manager.add_peer(&test_peer("peer1", old_endpoint)).await;
    manager
        .add_candidates_with_metadata(
            "peer1",
            &[old_endpoint.to_string()],
            &HashMap::new(),
            10,
            Some(u64::MAX),
        )
        .await;

    manager.recovery_epoch_admit("peer1").await;
    manager
        .stash_recovery_target(PendingRecoveryTarget {
            peer_id: "peer1".to_string(),
            candidates: vec![old_endpoint],
            preferred_fast_candidates: vec![old_endpoint],
            frozen_targets: Some(vec![old_endpoint]),
            fresh_prediction: None,
            punch_at_ms: None,
            seen_at: Instant::now(),
        })
        .await;

    manager
        .add_candidates_with_metadata(
            "peer1",
            &[fresh_endpoint.to_string()],
            &HashMap::new(),
            11,
            Some(u64::MAX),
        )
        .await;

    assert!(
        manager.take_recovery_target("peer1").await.is_none(),
        "a pending target from the retired remote candidate set must not be sent"
    );
}

#[tokio::test]
async fn remote_candidate_refresh_does_not_resurrect_retired_endpoint_from_raw_udp() {
    let manager = PeerManager::new(test_config());
    let old_endpoint: SocketAddr = "203.0.113.10:41010".parse().unwrap();
    let fresh_endpoint: SocketAddr = "203.0.113.10:42010".parse().unwrap();
    manager.add_peer(&test_peer("peer1", old_endpoint)).await;
    manager
        .add_candidates_with_metadata(
            "peer1",
            &[old_endpoint.to_string()],
            &HashMap::new(),
            10,
            Some(u64::MAX),
        )
        .await;

    // Model a historical candidate that was previously observed on the wire
    // and therefore remains in the bounded candidate registry.
    assert!(manager
        .learn_endpoint_from_addr(old_endpoint)
        .await
        .is_some());
    manager
        .add_candidates_with_metadata(
            "peer1",
            &[fresh_endpoint.to_string()],
            &HashMap::new(),
            11,
            Some(u64::MAX),
        )
        .await;

    assert_eq!(
        manager.learn_endpoint_from_addr(old_endpoint).await,
        None,
        "raw UDP from a retired candidate must not restore endpoint affinity"
    );
    assert_eq!(
        manager.learn_endpoint_from_addr(fresh_endpoint).await,
        Some("peer1".to_string())
    );
    assert_eq!(
        manager.get_connection("peer1").await.unwrap().endpoint,
        Some(fresh_endpoint)
    );
}

#[tokio::test]
async fn stale_direct_validation_result_cannot_promote_reused_endpoint_after_remote_handover() {
    let manager = PeerManager::new(test_config());
    let reused_endpoint: SocketAddr = "203.0.113.10:41020".parse().unwrap();
    let replacement_endpoint: SocketAddr = "203.0.113.10:42020".parse().unwrap();
    manager.add_peer(&test_peer("peer1", reused_endpoint)).await;
    manager
        .add_candidates_with_metadata(
            "peer1",
            &[reused_endpoint.to_string()],
            &HashMap::new(),
            10,
            Some(u64::MAX),
        )
        .await;
    let retired_remote_epoch = manager
        .current_remote_candidate_epoch("peer1")
        .await
        .unwrap();

    // A real handover removes the endpoint before a later revision reuses its
    // literal address. Equality alone must not make the old in-flight
    // validation look like proof for the replacement transport epoch.
    manager
        .add_candidates_with_metadata(
            "peer1",
            &[replacement_endpoint.to_string()],
            &HashMap::new(),
            11,
            Some(u64::MAX),
        )
        .await;
    manager
        .add_candidates_with_metadata(
            "peer1",
            &[reused_endpoint.to_string()],
            &HashMap::new(),
            12,
            Some(u64::MAX),
        )
        .await;
    let current_remote_epoch = manager
        .current_remote_candidate_epoch("peer1")
        .await
        .unwrap();
    assert_ne!(retired_remote_epoch, current_remote_epoch);

    let epoch_gate = manager.network_epoch_gate();
    let epoch_guard = epoch_gate.lock().await;
    assert!(!manager
        .record_direct_success_for_generation_with_local_endpoint_and_latency_in_epoch_for_remote_epoch(
            &epoch_guard,
            "peer1",
            Some(reused_endpoint),
            manager.current_network_generation_sync(),
            None,
            Some(Duration::from_millis(4)),
            Some(retired_remote_epoch),
        )
        .await);
    drop(epoch_guard);

    let connection = manager.get_connection("peer1").await.unwrap();
    assert_ne!(connection.state, ConnectionState::Direct);
    assert_eq!(connection.endpoint, Some(reused_endpoint));
}

#[tokio::test]
async fn stale_probe_result_cannot_promote_reused_endpoint_after_remote_handover() {
    let manager = PeerManager::new(test_config());
    let reused_endpoint: SocketAddr = "203.0.113.10:41021".parse().unwrap();
    let replacement_endpoint: SocketAddr = "203.0.113.10:42021".parse().unwrap();
    manager.add_peer(&test_peer("peer1", reused_endpoint)).await;
    manager
        .add_candidates_with_metadata(
            "peer1",
            &[reused_endpoint.to_string()],
            &HashMap::new(),
            20,
            Some(u64::MAX),
        )
        .await;
    let retired_remote_epoch = manager
        .current_remote_candidate_epoch("peer1")
        .await
        .unwrap();
    manager
        .add_candidates_with_metadata(
            "peer1",
            &[replacement_endpoint.to_string()],
            &HashMap::new(),
            21,
            Some(u64::MAX),
        )
        .await;
    manager
        .add_candidates_with_metadata(
            "peer1",
            &[reused_endpoint.to_string()],
            &HashMap::new(),
            22,
            Some(u64::MAX),
        )
        .await;

    let epoch_gate = manager.network_epoch_gate();
    let epoch_guard = epoch_gate.lock().await;
    assert!(!manager
        .record_direct_probe_success_with_latency_for_generation_and_local_endpoint_for_remote_epoch(
            "peer1",
            reused_endpoint,
            Some(Duration::from_millis(3)),
            manager.current_network_generation_sync(),
            None,
            Some(retired_remote_epoch),
        )
        .await);
    drop(epoch_guard);

    let connection = manager.get_connection("peer1").await.unwrap();
    assert_ne!(connection.state, ConnectionState::Direct);
}

#[tokio::test]
async fn versioned_candidates_reject_stale_and_expired_sets() {
    let manager = PeerManager::new(test_config());
    let initial: SocketAddr = "203.0.113.10:42000".parse().unwrap();
    let stale: SocketAddr = "203.0.113.10:41000".parse().unwrap();
    let expired: SocketAddr = "203.0.113.10:43000".parse().unwrap();
    manager.add_peer(&test_peer("peer1", initial)).await;

    assert_eq!(
        manager
            .add_candidates_with_metadata(
                "peer1",
                &[initial.to_string()],
                &HashMap::new(),
                10,
                Some(u64::MAX),
            )
            .await,
        CandidateSetApplyResult::Applied
    );
    let accepted_epoch = manager
        .current_remote_candidate_epoch("peer1")
        .await
        .unwrap();
    assert_eq!(
        manager
            .add_candidates_with_metadata(
                "peer1",
                &[stale.to_string()],
                &HashMap::new(),
                9,
                Some(u64::MAX),
            )
            .await,
        CandidateSetApplyResult::IgnoredStale
    );
    assert_eq!(
        manager
            .add_candidates_with_metadata(
                "peer1",
                &[expired.to_string()],
                &HashMap::new(),
                11,
                Some(1),
            )
            .await,
        CandidateSetApplyResult::IgnoredExpired
    );

    let conn = manager.get_connection("peer1").await.unwrap();
    assert_eq!(conn.last_candidate_generation, 10);
    assert_eq!(conn.remote_candidate_epoch(), accepted_epoch);
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
async fn empty_invalid_and_missing_candidate_sets_do_not_replace_live_state() {
    let manager = PeerManager::new(test_config());
    let initial: SocketAddr = "203.0.113.10:42000".parse().unwrap();
    manager.add_peer(&test_peer("peer1", initial)).await;
    assert_eq!(
        manager
            .add_candidates_with_metadata(
                "peer1",
                &[initial.to_string()],
                &HashMap::new(),
                10,
                Some(u64::MAX),
            )
            .await,
        CandidateSetApplyResult::Applied
    );

    assert_eq!(
        manager
            .add_candidates_with_metadata("peer1", &[], &HashMap::new(), 11, Some(u64::MAX))
            .await,
        CandidateSetApplyResult::IgnoredEmpty
    );
    assert_eq!(
        manager
            .add_candidates_with_metadata(
                "peer1",
                &["not-a-socket".to_string()],
                &HashMap::new(),
                12,
                Some(u64::MAX),
            )
            .await,
        CandidateSetApplyResult::IgnoredEmpty
    );
    assert_eq!(
        manager
            .add_candidates_with_metadata(
                "missing",
                &[initial.to_string()],
                &HashMap::new(),
                1,
                Some(u64::MAX),
            )
            .await,
        CandidateSetApplyResult::PeerMissing
    );

    let conn = manager.get_connection("peer1").await.unwrap();
    assert_eq!(conn.last_candidate_generation, 10);
    assert!(conn.candidates.contains(&initial.to_string()));
    assert!(conn
        .direct_events
        .iter()
        .any(|event| event.stage == "candidates_empty"));
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
    let candidates = (0..PREDICTED_PROBE_BUDGET_PER_CYCLE)
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
    let mut candidates = vec![stable_endpoint.to_string()];
    candidates.extend(
        (0..PREDICTED_PROBE_SUCCESS_BUDGET_PER_CYCLE)
            .map(|index| format!("8.8.8.8:{}", 41_000 + index)),
    );
    let sources = candidates
        .iter()
        .map(|candidate| {
            let source = if candidate == &stable_endpoint.to_string() {
                "stun_observed"
            } else {
                "predicted"
            };
            (candidate.clone(), source.to_string())
        })
        .collect::<HashMap<_, _>>();
    let predicted_endpoints = candidates
        .iter()
        .filter(|candidate| **candidate != stable_endpoint.to_string())
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
async fn fresh_mapping_harness_uses_loopback_stun_target_not_predicted_target() {
    let mut config = test_config();
    config.network.fresh_mapping_harness_loopback = true;
    let manager = PeerManager::new(config);
    let stable_endpoint: SocketAddr = "127.0.0.1:46000".parse().unwrap();
    let predicted_endpoint: SocketAddr = "127.0.0.1:46001".parse().unwrap();
    let candidates = vec![predicted_endpoint.to_string(), stable_endpoint.to_string()];
    let sources = HashMap::from([
        (predicted_endpoint.to_string(), "predicted".to_string()),
        (stable_endpoint.to_string(), "stun_observed".to_string()),
    ]);

    manager.add_peer(&test_peer("peer1", stable_endpoint)).await;
    manager
        .add_candidates_with_sources("peer1", &candidates, &sources)
        .await;

    assert_eq!(
        manager.stable_remote_punch_targets_for("peer1").await,
        vec![stable_endpoint],
        "the harness must retain the authoritative loopback STUN endpoint while excluding speculative predictions"
    );
}

#[tokio::test]
async fn synchronized_punch_uses_only_predicted_window_during_history_cooldown() {
    let mut history = TraversalHistory::default();
    history.record_failure(CandidatePairSource::Predicted);
    history.record_failure(CandidatePairSource::Predicted);
    history.record_failure(CandidatePairSource::Predicted);
    let manager = PeerManager::new_with_history(test_config(), None, history);
    let stable_endpoint: SocketAddr = "8.8.8.8:40000".parse().unwrap();

    manager.add_peer(&test_peer("peer1", stable_endpoint)).await;
    manager.update_nat_profile(birthday_nat_profile()).await;

    let mut predicted_candidates = vec![stable_endpoint.to_string()];
    predicted_candidates.extend(
        (0..PREDICTED_PROBE_BUDGET_PER_CYCLE).map(|index| format!("8.8.8.8:{}", 41_000 + index)),
    );
    let predicted_endpoints = predicted_candidates
        .iter()
        .filter(|candidate| **candidate != stable_endpoint.to_string())
        .map(|candidate| candidate.parse::<SocketAddr>().unwrap())
        .collect::<HashSet<_>>();
    let sources = predicted_candidates
        .iter()
        .map(|candidate| {
            let source = if candidate == &stable_endpoint.to_string() {
                "stun_observed"
            } else {
                "predicted"
            };
            (candidate.clone(), source.to_string())
        })
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
    assert_eq!(predicted_positions.len(), PREDICTED_PROBE_BUDGET_PER_CYCLE);
    assert_eq!(targets.len(), 1 + PREDICTED_PROBE_BUDGET_PER_CYCLE);
    assert!(targets
        .iter()
        .all(|target| { *target == stable_endpoint || predicted_endpoints.contains(target) }));

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
async fn synchronized_punch_retries_failed_predicted_without_birthday_expansion() {
    let manager = PeerManager::new(test_config());
    let stable_endpoint: SocketAddr = "8.8.8.8:40000".parse().unwrap();

    manager.add_peer(&test_peer("peer1", stable_endpoint)).await;
    manager.update_nat_profile(birthday_nat_profile()).await;

    let mut predicted_candidates = vec![stable_endpoint.to_string()];
    predicted_candidates.extend(
        (0..PREDICTED_PROBE_BUDGET_PER_CYCLE).map(|index| format!("8.8.8.8:{}", 41_000 + index)),
    );
    let predicted_endpoints = predicted_candidates
        .iter()
        .filter(|candidate| **candidate != stable_endpoint.to_string())
        .map(|candidate| candidate.parse::<SocketAddr>().unwrap())
        .collect::<HashSet<_>>();
    let sources = predicted_candidates
        .iter()
        .map(|candidate| {
            let source = if candidate == &stable_endpoint.to_string() {
                "stun_observed"
            } else {
                "predicted"
            };
            (candidate.clone(), source.to_string())
        })
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
    assert_eq!(predicted_positions.len(), PREDICTED_PROBE_BUDGET_PER_CYCLE);
    assert_eq!(targets.len(), 1 + PREDICTED_PROBE_BUDGET_PER_CYCLE);
    assert!(targets
        .iter()
        .all(|target| { *target == stable_endpoint || predicted_endpoints.contains(target) }));

    let background = manager.direct_probe_targets().await;
    assert_eq!(background.len(), 1);
    assert!(background[0]
        .1
        .iter()
        .all(|target| { *target == stable_endpoint || predicted_endpoints.contains(target) }));
}

#[tokio::test]
async fn remote_fresh_prediction_high_water_orders_incarnations_and_generations() {
    let manager = PeerManager::new(test_config());
    let endpoint: SocketAddr = "127.0.0.1:51860".parse().unwrap();
    manager.add_peer(&test_peer("peer1", endpoint)).await;

    let boot = 1_742_987_654_321u64;
    let id = |boot_epoch: u64, generation: u64| crate::FreshPredictionId {
        boot_epoch,
        generation,
    };
    let payload = (vec!["203.0.113.10:45393".to_string()], HashMap::new(), None);
    // Admit = prepare + apply + commit (the real transaction order).
    async fn admit(
        manager: &PeerManager,
        peer_id: &str,
        identity: crate::FreshPredictionId,
        payload: &(Vec<String>, HashMap<String, String>, Option<u64>),
    ) -> RemoteFreshAdmission {
        match manager
            .prepare_remote_fresh_prediction(peer_id, identity, &payload.0, &payload.1, payload.2)
            .await
        {
            RemoteFreshAdmission::Accepted => {
                assert_eq!(
                    manager
                        .apply_remote_fresh_candidates(
                            peer_id,
                            identity,
                            &payload.0,
                            &payload.1,
                            identity
                                .boot_epoch
                                .saturating_mul(2)
                                .saturating_add(identity.generation),
                            payload.2,
                        )
                        .await,
                    CandidateSetApplyResult::Applied,
                    "accepted identity must apply: {identity:?}"
                );
                assert!(
                    manager
                        .commit_remote_fresh_prediction(peer_id, identity)
                        .await,
                    "accepted identity must commit"
                );
                RemoteFreshAdmission::Accepted
            }
            other => other,
        }
    }

    // 1. Same incarnation: G2 supersedes G1.
    assert_eq!(
        admit(&manager, "peer1", id(boot, 1), &payload).await,
        RemoteFreshAdmission::Accepted
    );
    assert_eq!(
        admit(&manager, "peer1", id(boot, 2), &payload).await,
        RemoteFreshAdmission::Accepted
    );
    // 2. After G2 was accepted, a late G1 must be refused.
    assert_eq!(
        manager
            .prepare_remote_fresh_prediction(
                "peer1",
                id(boot, 1),
                &payload.0,
                &payload.1,
                payload.2
            )
            .await,
        RemoteFreshAdmission::Stale
    );
    // 3. A new daemon incarnation may replace the old one with generation 1.
    let new_boot = boot + 1;
    assert_eq!(
        admit(&manager, "peer1", id(new_boot, 1), &payload).await,
        RemoteFreshAdmission::Accepted
    );
    // 4. After the new boot was accepted, the old boot's late signals are
    // refused even with a higher generation.
    assert_eq!(
        manager
            .prepare_remote_fresh_prediction(
                "peer1",
                id(boot, 40),
                &payload.0,
                &payload.1,
                payload.2
            )
            .await,
        RemoteFreshAdmission::Stale
    );
    assert_eq!(
        manager
            .prepare_remote_fresh_prediction(
                "peer1",
                id(new_boot, 1),
                &payload.0,
                &payload.1,
                payload.2
            )
            .await,
        RemoteFreshAdmission::AlreadyRecorded,
        "equal identity with an identical payload is an idempotent retry and must not re-apply"
    );
    // An equal identity with a DIFFERENT payload is a payload mismatch: a
    // retry must never apply different candidates under the same identity.
    assert_eq!(
        manager
            .prepare_remote_fresh_prediction(
                "peer1",
                id(new_boot, 1),
                &["203.0.113.10:99999".to_string()],
                &HashMap::new(),
                None,
            )
            .await,
        RemoteFreshAdmission::PayloadMismatch,
        "an equal-id retry with a different candidate payload must be rejected"
    );
    // An equal-id retry with a different expiry is also a payload mismatch.
    assert_eq!(
        manager
            .prepare_remote_fresh_prediction(
                "peer1",
                id(new_boot, 1),
                &payload.0,
                &payload.1,
                Some(123_456),
            )
            .await,
        RemoteFreshAdmission::PayloadMismatch,
        "an equal-id retry with a different expiry must be rejected"
    );
    // An equal-id commit is refused by the strict CAS: the identity was
    // already committed by the first winner, so a retry's commit must report
    // "not the winner" instead of claiming success twice.
    assert!(
        !manager
            .commit_remote_fresh_prediction("peer1", id(new_boot, 1))
            .await,
        "an already-committed identity must not commit twice"
    );

    // 5. PeerLeft does NOT reset the high-water: the peer re-joins (same
    // public key, same incarnation space) and a late old-incarnation signal
    // stays rejected; only a strictly newer incarnation is admitted.
    manager.remove_peer("peer1").await;
    manager.add_peer(&test_peer("peer1", endpoint)).await;
    assert_eq!(
        manager
            .prepare_remote_fresh_prediction("peer1", id(boot, 40), &payload.0, &payload.1, payload.2)
            .await,
        RemoteFreshAdmission::Stale,
        "PeerLeft must not clear the high-water: a late old-incarnation signal stays rejected after the rejoin"
    );
    assert_eq!(
        admit(&manager, "peer1", id(new_boot + 1, 1), &payload).await,
        RemoteFreshAdmission::Accepted,
        "a strictly newer incarnation is admitted after the rejoin"
    );
}

#[tokio::test]
async fn remote_fresh_prediction_commit_only_wins_once_under_concurrency() {
    let manager = Arc::new(PeerManager::new(test_config()));
    let endpoint: SocketAddr = "127.0.0.1:51863".parse().unwrap();
    manager.add_peer(&test_peer("peer1", endpoint)).await;

    let id = |generation: u64| crate::FreshPredictionId {
        boot_epoch: 1_742_987_654_321,
        generation,
    };
    let payload = (vec!["203.0.113.10:45393".to_string()], HashMap::new(), None);
    // Two concurrent FULL transactions (prepare -> apply -> commit) of the
    // same identity: both prepare as Accepted and both really apply, but the
    // strict compare-and-swap commit lets exactly ONE win.  Each task uses
    // its own candidate generation (as two racing signals would), so the
    // second apply is not judged stale by the peer's generation high-water.
    let mut handles = Vec::new();
    for task in 0..2 {
        let manager = manager.clone();
        let payload = payload.clone();
        handles.push(tokio::spawn(async move {
            let prepared = manager
                .prepare_remote_fresh_prediction("peer1", id(1), &payload.0, &payload.1, payload.2)
                .await;
            tokio::task::yield_now().await;
            let applied = manager
                .apply_remote_fresh_candidates(
                    "peer1",
                    id(1),
                    &payload.0,
                    &payload.1,
                    id(1)
                        .boot_epoch
                        .saturating_mul(2)
                        .saturating_add(id(1).generation)
                        .saturating_add(task as u64),
                    payload.2,
                )
                .await;
            tokio::task::yield_now().await;
            let committed = manager.commit_remote_fresh_prediction("peer1", id(1)).await;
            if !committed {
                // The loser rolls its own apply back.
                manager.rollback_remote_fresh_apply("peer1", id(1)).await;
            }
            (prepared, applied, committed)
        }));
    }
    let outcomes = futures_util::future::join_all(handles).await;
    let outcomes = outcomes
        .into_iter()
        .collect::<std::result::Result<Vec<_>, _>>()
        .expect("both concurrent transactions must complete");
    assert!(outcomes
        .iter()
        .all(|(prepared, _, _)| *prepared == RemoteFreshAdmission::Accepted));
    // The apply REALLY runs in this concurrent test, and at least one apply
    // wins the candidate-generation race: the lower-generation task can be
    // judged stale by the higher one (the peer's ordinary high-water), which
    // is a legitimate outcome, not a skipped apply.
    assert!(
        outcomes
            .iter()
            .any(|(_, applied, _)| *applied == CandidateSetApplyResult::Applied),
        "the concurrent applies must really run and at least one must apply"
    );
    assert_eq!(
        outcomes
            .iter()
            .filter(|(_, _, committed)| *committed)
            .count(),
        1,
        "exactly one concurrent commit of an identity may win (never both)"
    );
    // A stale commit (older identity) never wins once G2 is committed.
    let id2 = id(2);
    let id1 = id(1);
    let prepared = manager
        .prepare_remote_fresh_prediction("peer1", id2, &payload.0, &payload.1, payload.2)
        .await;
    assert_eq!(prepared, RemoteFreshAdmission::Accepted);
    assert_eq!(
        manager
            .apply_remote_fresh_candidates(
                "peer1",
                id2,
                &payload.0,
                &payload.1,
                id2.boot_epoch.saturating_mul(2).saturating_add(3),
                payload.2,
            )
            .await,
        CandidateSetApplyResult::Applied
    );
    assert!(manager.commit_remote_fresh_prediction("peer1", id2).await);
    assert!(
        !manager.commit_remote_fresh_prediction("peer1", id1).await,
        "a stale identity must never overwrite a newer committed one"
    );
    // The committed identity's snapshot is immutable: the idempotent retry of
    // id(2) with the SAME payload is admitted, and the punch targets come
    // from the committed snapshot, never from the current refresh set.
    assert_eq!(
        manager
            .prepare_remote_fresh_prediction("peer1", id2, &payload.0, &payload.1, payload.2)
            .await,
        RemoteFreshAdmission::AlreadyRecorded,
        "an identical-payload retry of the committed identity is idempotent"
    );
    let snapshot = manager.remote_fresh_snapshot_for("peer1", id2).await;
    assert_eq!(
        snapshot
            .as_ref()
            .map(|snapshot| snapshot.candidates.clone()),
        Some(vec!["203.0.113.10:45393".to_string()]),
        "the committed snapshot is the first-applied payload"
    );
}

#[tokio::test]
async fn delayed_older_fresh_transaction_cannot_replace_newer_committed_candidates() {
    let manager = Arc::new(PeerManager::new(test_config()));
    let endpoint: SocketAddr = "127.0.0.1:51879".parse().unwrap();
    manager.add_peer(&test_peer("peer1", endpoint)).await;

    let prediction = |generation: u64| crate::FreshPredictionId {
        boot_epoch: 1_742_987_654_321,
        generation,
    };
    let old_id = prediction(1);
    let winner_id = prediction(2);
    let old_candidate = "203.0.113.10:45407".to_string();
    let winner_candidate = "203.0.113.10:45406".to_string();
    let old_candidates = vec![old_candidate.clone()];
    let winner_candidates = vec![winner_candidate.clone()];
    let old_sources = HashMap::from([(
        old_candidate.clone(),
        crate::fresh_prediction_source_label(old_id),
    )]);
    let winner_sources = HashMap::from([(
        winner_candidate.clone(),
        crate::fresh_prediction_source_label(winner_id),
    )]);

    // The older worker passes its optimistic prepare first, then stalls.  The
    // newer identity applies and commits while that old transaction is still
    // alive.  Its candidate revision is deliberately lower: a late old signal
    // can receive a newer ordinary candidate revision when its HTTP task sends
    // out of order, which was the destructive rollback ordering.
    let old_prepared = Arc::new(tokio::sync::Notify::new());
    let release_old = Arc::new(tokio::sync::Notify::new());
    let old_task = {
        let manager = manager.clone();
        let old_prepared = old_prepared.clone();
        let release_old = release_old.clone();
        tokio::spawn(async move {
            assert_eq!(
                manager
                    .prepare_remote_fresh_prediction(
                        "peer1",
                        old_id,
                        &old_candidates,
                        &old_sources,
                        None,
                    )
                    .await,
                RemoteFreshAdmission::Accepted,
            );
            old_prepared.notify_one();
            release_old.notified().await;
            manager
                .apply_and_commit_remote_fresh_prediction_for_identity(
                    "peer1",
                    old_id,
                    &old_candidates,
                    &old_sources,
                    7,
                    None,
                    None,
                )
                .await
        })
    };
    old_prepared.notified().await;

    assert_eq!(
        manager
            .prepare_remote_fresh_prediction(
                "peer1",
                winner_id,
                &winner_candidates,
                &winner_sources,
                None,
            )
            .await,
        RemoteFreshAdmission::Accepted,
    );
    assert_eq!(
        manager
            .apply_and_commit_remote_fresh_prediction_for_identity(
                "peer1",
                winner_id,
                &winner_candidates,
                &winner_sources,
                6,
                None,
                None,
            )
            .await,
        RemoteFreshTransactionOutcome::Committed,
    );
    release_old.notify_one();
    assert_eq!(
        old_task.await.unwrap(),
        RemoteFreshTransactionOutcome::Superseded,
        "the late older transaction must be rejected before candidate mutation",
    );

    let conn = manager.get_connection("peer1").await.unwrap();
    assert!(conn.candidates.contains(&winner_candidate));
    assert!(!conn.candidates.contains(&old_candidate));
    assert_eq!(
        conn.last_candidate_generation, 6,
        "the loser must not advance and then roll the candidate high-water backwards",
    );
    assert_eq!(
        manager
            .remote_fresh_snapshot_for("peer1", winner_id)
            .await
            .map(|snapshot| snapshot.candidates),
        Some(vec![winner_candidate]),
    );
}

#[tokio::test]
async fn remote_fresh_prediction_high_water_resets_on_public_key_change() {
    let manager = PeerManager::new(test_config());
    let endpoint: SocketAddr = "127.0.0.1:51861".parse().unwrap();
    let boot = 1_742_987_654_321u64;
    let id = |boot_epoch: u64, generation: u64| crate::FreshPredictionId {
        boot_epoch,
        generation,
    };
    let mut peer = test_peer("peer1", endpoint);
    manager.add_peer(&peer).await;
    let payload = (vec!["203.0.113.10:45393".to_string()], HashMap::new(), None);
    // The real transaction: prepare -> apply -> commit.
    assert_eq!(
        manager
            .prepare_remote_fresh_prediction(
                "peer1",
                id(boot, 9),
                &payload.0,
                &payload.1,
                payload.2
            )
            .await,
        RemoteFreshAdmission::Accepted
    );
    assert_eq!(
        manager
            .apply_remote_fresh_candidates(
                "peer1",
                id(boot, 9),
                &payload.0,
                &payload.1,
                boot.saturating_mul(2).saturating_add(9),
                payload.2,
            )
            .await,
        CandidateSetApplyResult::Applied
    );
    assert!(
        manager
            .commit_remote_fresh_prediction("peer1", id(boot, 9))
            .await
    );

    // The peer rotates its public key: a new incarnation's prediction space
    // starts fresh, so generation 1 of the new key is admitted even though
    // the old key had reached generation 9.
    peer.public_key = "rotated-public-key".to_string();
    manager.add_peer(&peer).await;
    assert_eq!(
        manager
            .prepare_remote_fresh_prediction(
                "peer1",
                id(boot, 1),
                &payload.0,
                &payload.1,
                payload.2
            )
            .await,
        RemoteFreshAdmission::Accepted,
        "public-key identity change must reset the remote high-water"
    );
    assert_eq!(
        manager
            .apply_remote_fresh_candidates(
                "peer1",
                id(boot, 1),
                &payload.0,
                &payload.1,
                boot.saturating_mul(2).saturating_add(1),
                payload.2,
            )
            .await,
        CandidateSetApplyResult::Applied,
        "the new identity's apply must really apply"
    );
    assert!(
        manager
            .commit_remote_fresh_prediction("peer1", id(boot, 1))
            .await,
        "the new identity's commit must win after the key rotation reset"
    );
}

#[tokio::test]
async fn stale_fresh_prediction_never_overwrites_fresh_mapping_state() {
    let manager = PeerManager::new(test_config());
    let endpoint: SocketAddr = "127.0.0.1:51862".parse().unwrap();
    manager.add_peer(&test_peer("peer1", endpoint)).await;

    let model = p2pnet_nat::mapping::build_model(
        &[45390, 45391, 45392],
        Some("203.0.113.10".parse().unwrap()),
        1_000,
    );
    // G2 records first.
    manager
        .record_fresh_mapping(
            "peer1",
            p2pnet_nat::mapping::PortModel::clone(&model),
            vec![45394, 45395, 45396],
            "0.0.0.0:58980".parse().unwrap(),
            Some("203.0.113.10".parse().unwrap()),
            2,
            0,
        )
        .await;
    // A late G1 must not overwrite the newer state.
    manager
        .record_fresh_mapping(
            "peer1",
            model,
            vec![45391, 45392, 45393],
            "0.0.0.0:58981".parse().unwrap(),
            Some("203.0.113.10".parse().unwrap()),
            1,
            0,
        )
        .await;
    let state = manager.fresh_mapping_for_peer("peer1").await.unwrap();
    assert_eq!(state.punch_generation, 2);
    assert_eq!(state.predicted_ports, vec![45394, 45395, 45396]);
    assert_eq!(state.socket_local_endpoint.port(), 58980);
}

#[tokio::test]
async fn fresh_mapping_prediction_history_dedup_is_atomic_under_concurrency() {
    let manager = PeerManager::new(test_config());
    let endpoint: SocketAddr = "127.0.0.1:51863".parse().unwrap();
    manager.add_peer(&test_peer("peer1", endpoint)).await;

    let model = p2pnet_nat::mapping::build_model(
        &[45390, 45391, 45392],
        Some("203.0.113.10".parse().unwrap()),
        1_000,
    );
    manager
        .record_fresh_mapping(
            "peer1",
            model,
            vec![45393, 45394, 45395, 45396],
            "0.0.0.0:58980".parse().unwrap(),
            Some("203.0.113.10".parse().unwrap()),
            39,
            0,
        )
        .await;

    // Many concurrent notifications for the same (generation, port): exactly
    // one must be recorded as the first inserter.
    let manager = std::sync::Arc::new(manager);
    let mut tasks = Vec::new();
    for _ in 0..16 {
        let manager = manager.clone();
        tasks.push(tokio::spawn(async move {
            manager
                .record_fresh_mapping_prediction_result(
                    "peer1",
                    "203.0.113.10:45395".parse().unwrap(),
                )
                .await;
        }));
    }
    for task in tasks {
        tokio::time::timeout(Duration::from_secs(5), task)
            .await
            .expect("dedup tasks must finish without deadlock")
            .unwrap();
    }
    let history = manager
        .fresh_mapping_history
        .lock()
        .unwrap()
        .get("peer1")
        .cloned()
        .unwrap();
    assert_eq!(
        history
            .iter()
            .filter(|recorded| recorded.actual_port == 45395)
            .count(),
        1,
        "concurrent duplicates must collapse into one history entry"
    );
    let hits = manager
        .connections
        .read()
        .await
        .get("peer1")
        .unwrap()
        .direct_events
        .iter()
        .filter(|event| event.stage == "fresh_mapping_prediction_hit")
        .count();
    assert_eq!(hits, 1, "only the first inserter may record the hit event");
}

/// An apply whose commit loses the CAS must not leave its candidates in the
/// shared candidate set: the losers roll their own apply back, so a higher
/// identity's committed candidates are the only ones that survive.
#[tokio::test]
async fn lost_commit_rolls_its_apply_back_out_of_the_shared_set() {
    let manager = PeerManager::new(test_config());
    let endpoint: SocketAddr = "127.0.0.1:51864".parse().unwrap();
    manager.add_peer(&test_peer("peer1", endpoint)).await;

    let id = |generation: u64| crate::FreshPredictionId {
        boot_epoch: 1_742_987_654_321,
        generation,
    };
    let loser_candidates = vec!["203.0.113.10:45393".to_string()];
    let loser_sources = HashMap::from([(
        "203.0.113.10:45393".to_string(),
        crate::fresh_prediction_source_label(id(1)),
    )]);
    let winner_candidates = vec!["203.0.113.10:45401".to_string()];
    let winner_sources = HashMap::from([(
        "203.0.113.10:45401".to_string(),
        crate::fresh_prediction_source_label(id(2)),
    )]);

    // The loser's full transaction runs first (the prepare/apply/commit
    // sequence is serialized by the control event loop).
    assert!(matches!(
        manager
            .prepare_remote_fresh_prediction(
                "peer1",
                id(1),
                &loser_candidates,
                &loser_sources,
                None
            )
            .await,
        RemoteFreshAdmission::Accepted
    ));
    assert_eq!(
        manager
            .apply_remote_fresh_candidates(
                "peer1",
                id(1),
                &loser_candidates,
                &loser_sources,
                1,
                None
            )
            .await,
        CandidateSetApplyResult::Applied
    );

    // The winner's transaction supersedes it before the loser commits: the
    // winner's apply replaces the loser's candidates in the shared set.
    assert!(matches!(
        manager
            .prepare_remote_fresh_prediction(
                "peer1",
                id(2),
                &winner_candidates,
                &winner_sources,
                None
            )
            .await,
        RemoteFreshAdmission::Accepted
    ));
    assert_eq!(
        manager
            .apply_remote_fresh_candidates(
                "peer1",
                id(2),
                &winner_candidates,
                &winner_sources,
                2,
                None
            )
            .await,
        CandidateSetApplyResult::Applied
    );
    assert!(manager.commit_remote_fresh_prediction("peer1", id(2)).await);

    // The loser's commit loses the CAS and must roll its own apply back.
    assert!(
        !manager.commit_remote_fresh_prediction("peer1", id(1)).await,
        "the older identity must lose the commit"
    );
    manager.rollback_remote_fresh_apply("peer1", id(1)).await;

    let conn = manager.get_connection("peer1").await.unwrap();
    assert!(
        !conn.candidates.contains(&"203.0.113.10:45393".to_string()),
        "the loser's candidates must be rolled back out of the shared set"
    );
    assert!(
        conn.candidates.contains(&"203.0.113.10:45401".to_string()),
        "the winner's committed candidates must survive"
    );
    // The loser's identity is never committed: a retry of the SAME payload is
    // admitted again (the high-water is the winner's, so it is still Stale for
    // the old identity, but the snapshot bookkeeping is clean).
    assert_eq!(
        manager
            .prepare_remote_fresh_prediction(
                "peer1",
                id(1),
                &loser_candidates,
                &loser_sources,
                None
            )
            .await,
        RemoteFreshAdmission::Stale
    );
}

/// An ordinary refresh interleaved with a fresh retry must not disturb the
/// fresh session: the punch targets come from the committed snapshot, and an
/// ordinary refresh never re-applies or overwrites the fresh identity.
#[tokio::test]
async fn ordinary_refresh_never_overwrites_committed_fresh_snapshot() {
    let manager = PeerManager::new(test_config());
    let endpoint: SocketAddr = "127.0.0.1:51865".parse().unwrap();
    manager.add_peer(&test_peer("peer1", endpoint)).await;

    let id = crate::FreshPredictionId {
        boot_epoch: 1_742_987_654_321,
        generation: 1,
    };
    let fresh_candidates = vec!["203.0.113.10:45393".to_string()];
    let fresh_sources = HashMap::from([(
        "203.0.113.10:45393".to_string(),
        crate::fresh_prediction_source_label(id),
    )]);

    // Commit the fresh identity (full transaction).
    assert!(matches!(
        manager
            .prepare_remote_fresh_prediction("peer1", id, &fresh_candidates, &fresh_sources, None)
            .await,
        RemoteFreshAdmission::Accepted
    ));
    assert_eq!(
        manager
            .apply_remote_fresh_candidates("peer1", id, &fresh_candidates, &fresh_sources, 1, None)
            .await,
        CandidateSetApplyResult::Applied
    );
    assert!(manager.commit_remote_fresh_prediction("peer1", id).await);

    // An ordinary refresh interleaves and replaces the shared candidate set.
    manager
        .add_candidates_with_metadata(
            "peer1",
            &["198.51.100.9:44444".to_string()],
            &HashMap::from([(
                "198.51.100.9:44444".to_string(),
                "stun_observed".to_string(),
            )]),
            99,
            None,
        )
        .await;

    // The committed snapshot is untouched: a retry of the fresh identity with
    // the SAME payload is still idempotent, and its punch targets come from
    // the snapshot — never from the refreshed ordinary set.
    assert_eq!(
        manager
            .prepare_remote_fresh_prediction("peer1", id, &fresh_candidates, &fresh_sources, None)
            .await,
        RemoteFreshAdmission::AlreadyRecorded,
        "an ordinary refresh must never consume or overwrite the fresh identity"
    );
    let snapshot = manager.remote_fresh_snapshot_for("peer1", id).await;
    let snapshot_targets = snapshot
        .map(|snapshot| snapshot.candidates)
        .unwrap_or_default();
    assert_eq!(
        snapshot_targets, fresh_candidates,
        "the committed fresh snapshot must stay immutable across ordinary refreshes"
    );
}

/// PeerLeft removes the connection; a rejoin with a NEW public key
/// (`is_new == true`, `public_key_changed == false` on the fresh connection)
/// must NOT inherit the old incarnation's fresh-prediction high-water: the
/// old high-water would judge the new incarnation's first predictions stale
/// forever.  The identity-key map survives `remove_peer`, so the rejoin is
/// recognized as an identity change even though the connection is new.
#[tokio::test]
async fn rejoin_with_new_key_after_peer_left_resets_the_fresh_space() {
    let manager = PeerManager::new(test_config());
    let endpoint: SocketAddr = "127.0.0.1:51864".parse().unwrap();
    let boot = 1_742_987_654_321u64;
    let id = |boot_epoch: u64, generation: u64| crate::FreshPredictionId {
        boot_epoch,
        generation,
    };
    let payload = (vec!["203.0.113.10:45393".to_string()], HashMap::new(), None);

    let peer = test_peer("peer1", endpoint);
    manager.add_peer(&peer).await;
    assert_eq!(
        manager
            .prepare_remote_fresh_prediction(
                "peer1",
                id(boot, 9),
                &payload.0,
                &payload.1,
                payload.2
            )
            .await,
        RemoteFreshAdmission::Accepted
    );
    assert_eq!(
        manager
            .apply_remote_fresh_candidates(
                "peer1",
                id(boot, 9),
                &payload.0,
                &payload.1,
                boot.saturating_mul(2).saturating_add(9),
                payload.2,
            )
            .await,
        CandidateSetApplyResult::Applied
    );
    assert!(
        manager
            .commit_remote_fresh_prediction("peer1", id(boot, 9))
            .await
    );

    // The peer leaves and rejoins with a NEW public key: the connection is
    // brand new, so `public_key_changed` is false, but the identity-key map
    // records the change and must reset the fresh space.
    manager.remove_peer("peer1").await;
    let mut rejoined = test_peer("peer1", endpoint);
    rejoined.public_key = "rejoined-with-new-key".to_string();
    let update = manager.add_peer(&rejoined).await;
    assert!(update.is_new, "the rejoin creates a new connection");
    assert!(
        !update.public_key_changed,
        "a new connection cannot report a public-key change"
    );

    // The old high-water must be gone: the new identity's first prediction
    // (same boot epoch, low generation) is admitted and really applies.
    assert_eq!(
        manager
            .prepare_remote_fresh_prediction(
                "peer1",
                id(boot, 1),
                &payload.0,
                &payload.1,
                payload.2
            )
            .await,
        RemoteFreshAdmission::Accepted,
        "a rejoin with a new key must not inherit the old incarnation's high-water"
    );
    assert_eq!(
        manager
            .apply_remote_fresh_candidates(
                "peer1",
                id(boot, 1),
                &payload.0,
                &payload.1,
                boot.saturating_mul(2).saturating_add(1),
                payload.2,
            )
            .await,
        CandidateSetApplyResult::Applied
    );
    assert!(
        manager
            .commit_remote_fresh_prediction("peer1", id(boot, 1))
            .await,
        "the new identity's commit must win"
    );

    // A rejoin with the SAME key keeps the high-water (a plain PeerLeft does
    // not clear it): the late old signal stays rejected.
    manager.remove_peer("peer1").await;
    let update = manager.add_peer(&rejoined).await;
    assert!(update.is_new);
    assert!(
        !update.public_key_changed,
        "the same-key rejoin is not an identity change"
    );
    assert_eq!(
        manager
            .prepare_remote_fresh_prediction(
                "peer1",
                id(boot - 1, 1),
                &payload.0,
                &payload.1,
                payload.2,
            )
            .await,
        RemoteFreshAdmission::Stale,
        "a same-key rejoin must keep the committed high-water (late old signals stay rejected)"
    );
    assert_eq!(
        manager
            .prepare_remote_fresh_prediction(
                "peer1",
                id(boot, 1),
                &payload.0,
                &payload.1,
                payload.2
            )
            .await,
        RemoteFreshAdmission::AlreadyRecorded,
        "the same-key rejoin's committed identity stays idempotently retryable"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn new_identity_fresh_high_water_is_reset_before_membership_publish() {
    let manager = Arc::new(PeerManager::new(test_config()));
    let peer_id = "peer-fresh-publish-boundary";
    let endpoint: SocketAddr = "127.0.0.1:51880".parse().unwrap();
    let old_id = crate::FreshPredictionId {
        boot_epoch: 1_742_987_654_321,
        generation: 9,
    };
    let new_id = crate::FreshPredictionId {
        boot_epoch: old_id.boot_epoch,
        generation: 1,
    };
    let candidate = "203.0.113.10:45409".to_string();
    let candidates = vec![candidate.clone()];
    let old_sources = HashMap::from([(
        candidate.clone(),
        crate::fresh_prediction_source_label(old_id),
    )]);

    manager.add_peer(&test_peer(peer_id, endpoint)).await;
    assert_eq!(
        manager
            .prepare_remote_fresh_prediction(peer_id, old_id, &candidates, &old_sources, None,)
            .await,
        RemoteFreshAdmission::Accepted,
    );
    assert_eq!(
        manager
            .apply_and_commit_remote_fresh_prediction_for_identity(
                peer_id,
                old_id,
                &candidates,
                &old_sources,
                9,
                None,
                None,
            )
            .await,
        RemoteFreshTransactionOutcome::Committed,
    );
    manager.remove_peer(peer_id).await;

    let gate = install_peer_membership_publish_test_gate(peer_id);
    let add_task = {
        let manager = manager.clone();
        let mut replacement = test_peer(peer_id, endpoint);
        replacement.public_key = "replacement-fresh-identity-key".to_string();
        tokio::spawn(async move { manager.add_peer(&replacement).await })
    };
    tokio::time::timeout(Duration::from_secs(2), gate.reached.notified())
        .await
        .expect("replacement membership must publish");
    assert!(
        manager.peer_exists_sync(peer_id),
        "the regression point must observe replacement membership as published",
    );

    let new_sources = HashMap::from([(
        candidate.clone(),
        crate::fresh_prediction_source_label(new_id),
    )]);
    assert_eq!(
        manager
            .prepare_remote_fresh_prediction(
                peer_id,
                new_id,
                &candidates,
                &new_sources,
                None,
            )
            .await,
        RemoteFreshAdmission::Accepted,
        "membership must never expose the replacement before the old identity's fresh high-water is cleared",
    );
    gate.release.notify_one();
    let update = add_task.await.unwrap();
    assert!(update.is_new);
}

/// The snapshot map keeps only the CURRENT high-water's snapshot per peer:
/// older identities' snapshots are pruned at commit, so the map cannot grow
/// without bound across generations and incarnations.
#[tokio::test]
async fn fresh_snapshots_are_pruned_to_the_current_high_water() {
    let manager = PeerManager::new(test_config());
    let endpoint: SocketAddr = "127.0.0.1:51865".parse().unwrap();
    manager.add_peer(&test_peer("peer1", endpoint)).await;

    let boot = 1_742_987_654_321u64;
    let id = |boot_epoch: u64, generation: u64| crate::FreshPredictionId {
        boot_epoch,
        generation,
    };
    let payload = (vec!["203.0.113.10:45393".to_string()], HashMap::new(), None);
    async fn admit(
        manager: &PeerManager,
        identity: crate::FreshPredictionId,
        payload: &(Vec<String>, HashMap<String, String>, Option<u64>),
    ) {
        assert_eq!(
            manager
                .prepare_remote_fresh_prediction(
                    "peer1", identity, &payload.0, &payload.1, payload.2
                )
                .await,
            RemoteFreshAdmission::Accepted
        );
        assert_eq!(
            manager
                .apply_remote_fresh_candidates(
                    "peer1",
                    identity,
                    &payload.0,
                    &payload.1,
                    identity
                        .boot_epoch
                        .saturating_mul(2)
                        .saturating_add(identity.generation),
                    payload.2,
                )
                .await,
            CandidateSetApplyResult::Applied
        );
        assert!(
            manager
                .commit_remote_fresh_prediction("peer1", identity)
                .await
        );
    }

    admit(&manager, id(boot, 1), &payload).await;
    admit(&manager, id(boot, 2), &payload).await;
    admit(&manager, id(boot, 3), &payload).await;
    let snapshot_count = manager
        .remote_fresh_snapshots
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .iter()
        .filter(|((owner, _), _)| owner == "peer1")
        .count();
    assert_eq!(
        snapshot_count, 1,
        "only the current high-water's snapshot may survive"
    );
    assert!(
        manager
            .remote_fresh_snapshot_for("peer1", id(boot, 3))
            .await
            .is_some(),
        "the newest identity's snapshot must be retained"
    );
    assert!(
        manager
            .remote_fresh_snapshot_for("peer1", id(boot, 1))
            .await
            .is_none(),
        "the oldest identity's snapshot must be pruned"
    );
}
