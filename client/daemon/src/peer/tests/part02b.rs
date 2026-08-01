#[tokio::test]
async fn direct_failure_only_marks_sent_probe_candidates_when_some_were_sent() {
    let manager = PeerManager::new(test_config());
    let stable_endpoint: SocketAddr = "8.8.8.8:40000".parse().unwrap();
    let predicted_endpoint: SocketAddr = "8.8.8.8:40001".parse().unwrap();
    let birthday_endpoint: SocketAddr = "8.8.8.8:40002".parse().unwrap();

    manager.add_peer(&test_peer("peer1", stable_endpoint)).await;
    let candidates = vec![
        predicted_endpoint.to_string(),
        birthday_endpoint.to_string(),
    ];
    manager
        .add_candidates_with_sources(
            "peer1",
            &candidates,
            &HashMap::from([
                (predicted_endpoint.to_string(), "predicted".to_string()),
                (birthday_endpoint.to_string(), "birthday".to_string()),
            ]),
        )
        .await;

    let targets = manager.direct_probe_targets_for("peer1").await;
    assert!(targets.contains(&predicted_endpoint));
    assert!(targets.contains(&birthday_endpoint));
    assert!(
        manager
            .record_direct_probe_sent("peer1", predicted_endpoint)
            .await
    );

    assert!(
        manager
            .record_direct_failure_for_generation("peer1", 0, REASON_DIRECT_PROBE_FAILED, "no ACK",)
            .await
    );

    let conn = manager.get_connection("peer1").await.unwrap();
    let predicted_pair = conn
        .candidate_pairs
        .iter()
        .find(|pair| pair.remote_endpoint == predicted_endpoint)
        .unwrap();
    let birthday_pair = conn
        .candidate_pairs
        .iter()
        .find(|pair| pair.remote_endpoint == birthday_endpoint)
        .unwrap();

    assert_eq!(predicted_pair.state, CandidatePairState::Failed);
    assert_eq!(predicted_pair.failure_count, 1);
    assert_eq!(birthday_pair.state, CandidatePairState::Waiting);
    assert_eq!(birthday_pair.failure_count, 0);
    assert!(birthday_pair.last_error_code.is_none());

    let history = manager.traversal_history_diagnostics().await;
    assert!(history
        .sources
        .iter()
        .any(|source| source.source == "predicted" && source.failure_count == 1));
    assert!(!history
        .sources
        .iter()
        .any(|source| source.source == "birthday"));
}

#[tokio::test]
async fn candidate_pair_selection_prefers_selected_endpoint_for_send() {
    let config = test_config();
    let manager = PeerManager::new(config);
    let old_endpoint: SocketAddr = "127.0.0.1:51827".parse().unwrap();
    let new_endpoint: SocketAddr = "127.0.0.1:51828".parse().unwrap();

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
    manager
        .add_candidates("peer1", &[new_endpoint.to_string()])
        .await;

    assert_eq!(
        manager.direct_endpoint_for_send("peer1").await,
        Some(old_endpoint)
    );

    assert!(
        manager
            .record_direct_probe_success_with_latency_for_generation(
                "peer1",
                new_endpoint,
                Some(Duration::from_millis(4)),
                0,
            )
            .await
    );

    assert_eq!(
        manager.direct_endpoint_for_send("peer1").await,
        Some(new_endpoint)
    );
    assert!(manager.direct_endpoints().await.is_empty());
    manager
        .record_direct_success("peer1", Some(new_endpoint))
        .await;
    assert_eq!(
        manager.direct_endpoints().await,
        vec![("peer1".to_string(), new_endpoint)]
    );
}

#[tokio::test]
async fn confirmed_public_direct_still_probes_waiting_private_candidate() {
    let config = test_config();
    let manager = PeerManager::new(config);
    let public_endpoint: SocketAddr = "8.8.8.8:51842".parse().unwrap();
    let private_endpoint: SocketAddr = "192.168.2.11:51842".parse().unwrap();

    manager.add_peer(&test_peer("peer1", public_endpoint)).await;
    let candidates = vec![public_endpoint.to_string(), private_endpoint.to_string()];
    let sources = HashMap::from([
        (public_endpoint.to_string(), "peer_reflexive".to_string()),
        (private_endpoint.to_string(), "host".to_string()),
    ]);
    manager
        .add_candidates_with_sources("peer1", &candidates, &sources)
        .await;
    manager
        .record_direct_probe_success_with_latency(
            "peer1",
            public_endpoint,
            Some(Duration::from_millis(620)),
        )
        .await;
    manager
        .record_direct_success("peer1", Some(public_endpoint))
        .await;

    let targets = manager.direct_probe_targets_for("peer1").await;

    assert!(
        targets.contains(&private_endpoint),
        "waiting LAN candidate should still be probed while slow public Direct is active"
    );
}

#[tokio::test]
async fn low_latency_private_candidate_beats_selected_public_direct() {
    let config = test_config();
    let manager = PeerManager::new(config);
    let public_endpoint: SocketAddr = "8.8.8.8:51843".parse().unwrap();
    let private_endpoint: SocketAddr = "192.168.2.11:51843".parse().unwrap();

    manager.add_peer(&test_peer("peer1", public_endpoint)).await;
    let candidates = vec![public_endpoint.to_string(), private_endpoint.to_string()];
    let sources = HashMap::from([
        (public_endpoint.to_string(), "peer_reflexive".to_string()),
        (private_endpoint.to_string(), "host".to_string()),
    ]);
    manager
        .add_candidates_with_sources("peer1", &candidates, &sources)
        .await;
    manager
        .record_direct_probe_success_with_latency(
            "peer1",
            public_endpoint,
            Some(Duration::from_millis(620)),
        )
        .await;
    manager
        .record_direct_success("peer1", Some(public_endpoint))
        .await;

    manager
        .record_direct_probe_success_with_latency(
            "peer1",
            private_endpoint,
            Some(Duration::from_millis(7)),
        )
        .await;

    assert_eq!(
        manager.direct_endpoint_for_send("peer1").await,
        Some(private_endpoint)
    );

    let selection = manager.select_path_for_data("peer1", true, true).await;
    assert_eq!(selection.path, Some(NetworkPath::Direct));
    assert_eq!(selection.direct_endpoint, Some(private_endpoint));

    manager
        .record_direct_success("peer1", Some(private_endpoint))
        .await;
    let diagnostics = manager
        .diagnostics_with_path_selection(true, true, Duration::from_secs(5), None)
        .await;
    let peer = diagnostics
        .iter()
        .find(|peer| peer.node_id == "peer1")
        .expect("peer diagnostics should be present");
    let private_endpoint_text = private_endpoint.to_string();

    assert_eq!(peer.direct_type, DirectPathType::Lan);
    assert_eq!(
        peer.selected_pair
            .as_ref()
            .map(|pair| pair.remote_endpoint.as_str()),
        Some(private_endpoint_text.as_str())
    );
    assert_eq!(
        peer.current_direct_pair
            .as_ref()
            .map(|pair| pair.remote_endpoint.as_str()),
        Some(private_endpoint_text.as_str())
    );
}

#[tokio::test]
async fn candidate_pair_stats_aggregate_real_outcomes_by_source() {
    let config = test_config();
    let manager = PeerManager::new(config);
    let signaled_endpoint: SocketAddr = "127.0.0.1:51836".parse().unwrap();
    let peer_reflexive_endpoint: SocketAddr = "127.0.0.1:51837".parse().unwrap();

    manager
        .add_peer(&test_peer("peer1", signaled_endpoint))
        .await;

    {
        let mut conns = manager.connections.write().await;
        let conn = conns.get_mut("peer1").unwrap();
        conn.ensure_candidate_pair_with_source(signaled_endpoint, 0, CandidatePairSource::Signaled)
            .record_success(Some(Duration::from_millis(12)), false, None);
        let peer_reflexive = conn.ensure_candidate_pair_with_source(
            peer_reflexive_endpoint,
            0,
            CandidatePairSource::PeerReflexive,
        );
        peer_reflexive.record_success(Some(Duration::from_millis(9)), false, None);
        peer_reflexive.record_failure(REASON_DIRECT_PROBE_FAILED, "no ACK", None);
    }

    let diagnostics = manager.diagnostics().await;
    let stats = &diagnostics[0].candidate_pair_stats;
    let signaled = stats
        .iter()
        .find(|stats| stats.source == CandidatePairSource::Signaled)
        .unwrap();
    assert_eq!(signaled.pair_count, 1);
    assert_eq!(signaled.current_pair_count, 1);
    assert_eq!(signaled.success_count, 1);
    assert_eq!(signaled.failure_count, 0);
    assert_eq!(signaled.success_rate_per_mille, Some(1000));

    let peer_reflexive = stats
        .iter()
        .find(|stats| stats.source == CandidatePairSource::PeerReflexive)
        .unwrap();
    assert_eq!(peer_reflexive.pair_count, 1);
    assert_eq!(peer_reflexive.degraded_count, 1);
    assert_eq!(peer_reflexive.success_count, 1);
    assert_eq!(peer_reflexive.failure_count, 1);
    assert_eq!(peer_reflexive.success_rate_per_mille, Some(500));

    let json = serde_json::to_value(&diagnostics[0]).unwrap();
    assert_eq!(json["candidate_pair_stats"].as_array().unwrap().len(), 2);
}

#[tokio::test]
async fn repeated_probe_acks_record_one_traversal_success_transition() {
    let manager = PeerManager::new(test_config());
    let signaled_endpoint: SocketAddr = "127.0.0.1:51856".parse().unwrap();
    let peer_reflexive_endpoint: SocketAddr = "127.0.0.1:51857".parse().unwrap();
    manager
        .add_peer(&test_peer("peer1", signaled_endpoint))
        .await;
    manager
        .add_candidates_with_sources(
            "peer1",
            &[peer_reflexive_endpoint.to_string()],
            &HashMap::from([(
                peer_reflexive_endpoint.to_string(),
                "peer_reflexive".to_string(),
            )]),
        )
        .await;

    for latency_ms in [9, 7] {
        assert!(
            manager
                .record_direct_probe_success_with_latency_for_generation(
                    "peer1",
                    peer_reflexive_endpoint,
                    Some(Duration::from_millis(latency_ms)),
                    0,
                )
                .await
        );
    }

    let history = manager.traversal_history_diagnostics().await;
    let peer_reflexive_history = history
        .sources
        .iter()
        .find(|source| source.source == "peer_reflexive")
        .unwrap();
    assert_eq!(peer_reflexive_history.success_count, 1);

    let diagnostics = manager.diagnostics().await;
    let pair = diagnostics[0]
        .candidate_pairs
        .iter()
        .find(|pair| pair.remote_endpoint == peer_reflexive_endpoint.to_string())
        .unwrap();
    assert_eq!(pair.success_count, 2);
    assert_eq!(
        diagnostics[0]
            .direct_events
            .iter()
            .filter(|event| event.stage == "probe_ack_received")
            .count(),
        1
    );
}
