#[test]
fn birthday_probe_endpoints_cover_layered_port_window() {
    let base: SocketAddr = "203.0.113.10:40000".parse().unwrap();
    let endpoints = birthday_probe_endpoints(base);
    let ports = endpoints
        .iter()
        .map(SocketAddr::port)
        .collect::<HashSet<_>>();

    assert_eq!(endpoints.len(), birthday_probe_near_rank_count());
    for port in [
        39999, 40001, 39996, 40004, 39990, 40010, 39983, 40017, 39981, 40019, 39968, 40032, 39904,
        40096,
    ] {
        assert!(ports.contains(&port), "missing birthday port {port}");
    }
}

#[test]
fn birthday_probe_endpoints_for_bases_interleaves_public_ports() {
    let bases = vec![
        "203.0.113.10:40000".parse::<SocketAddr>().unwrap(),
        "203.0.113.10:40100".parse::<SocketAddr>().unwrap(),
        "203.0.113.10:40200".parse::<SocketAddr>().unwrap(),
    ];

    let endpoints = birthday_probe_endpoints_for_bases(&bases, 6);
    let ports = endpoints
        .iter()
        .map(SocketAddr::port)
        .collect::<HashSet<_>>();

    assert_eq!(endpoints.len(), 6);
    for port in [40001, 39999, 40101, 40099, 40201, 40199] {
        assert!(
            ports.contains(&port),
            "missing interleaved birthday port {port}"
        );
    }
}

#[test]
fn birthday_probe_endpoints_for_bases_spreads_beyond_near_window() {
    let base: SocketAddr = "203.0.113.10:40000".parse().unwrap();
    let budget = birthday_probe_near_rank_count() + 4;
    let endpoints = birthday_probe_endpoints_for_bases(&[base], budget);
    let ports = endpoints
        .iter()
        .map(SocketAddr::port)
        .collect::<HashSet<_>>();

    assert_eq!(endpoints.len(), budget);
    assert!(ports.contains(&39904));
    assert!(ports.contains(&40096));
    assert!(ports.contains(&40251));
    assert!(ports.contains(&39749));
    assert!(ports
        .iter()
        .all(|port| port.abs_diff(40000) <= BIRTHDAY_PROBE_WIDE_MAX_DELTA as u16));
    assert!(ports.iter().any(|port| port.abs_diff(40000) > 64));
}

#[test]
fn birthday_probe_endpoints_for_bases_keeps_near_window_when_wide_window_rotates() {
    let base: SocketAddr = "203.0.113.10:40000".parse().unwrap();
    let budget = birthday_probe_near_rank_count() + 8;
    let first = birthday_probe_endpoints_for_bases_from_rank(&[base], budget, 0);
    let second =
        birthday_probe_endpoints_for_bases_from_rank(&[base], budget, BIRTHDAY_PROBE_BUDGET_PER_CYCLE);
    let first_ports = first.iter().map(SocketAddr::port).collect::<HashSet<_>>();
    let second_ports = second.iter().map(SocketAddr::port).collect::<HashSet<_>>();

    assert_eq!(first.len(), budget);
    assert_eq!(second.len(), budget);
    for port in [39999, 40001, 39904, 40096] {
        assert!(first_ports.contains(&port), "first pass missing near port {port}");
        assert!(second_ports.contains(&port), "second pass missing near port {port}");
    }
    assert!(
        first_ports
            .difference(&second_ports)
            .any(|port| port.abs_diff(40000) > BIRTHDAY_PROBE_NEAR_MAX_DELTA as u16),
        "wide positive/negative tail should still rotate"
    );
}

#[tokio::test]
async fn hard_local_easy_remote_uses_only_the_fresh_stable_public_target() {
    let config = test_config();
    let manager = PeerManager::new(config);
    let stale_endpoint: SocketAddr = "203.0.113.10:39000".parse().unwrap();
    let fresh_endpoint: SocketAddr = "203.0.113.10:40037".parse().unwrap();

    manager
        .add_peer(&test_peer("peer1", stale_endpoint))
        .await;
    manager
        .add_candidates_with_sources(
            "peer1",
            &[fresh_endpoint.to_string()],
            &HashMap::from([(
                fresh_endpoint.to_string(),
                "stun_observed".to_string(),
            )]),
        )
        .await;
    manager.update_nat_profile(birthday_nat_profile()).await;

    let initial_targets = manager.direct_probe_targets_for("peer1").await;
    assert_eq!(initial_targets, vec![fresh_endpoint]);
    assert!(!initial_targets.contains(&stale_endpoint));

    let background_targets = manager.direct_probe_targets().await;
    assert_eq!(background_targets.len(), 1);
    assert_eq!(background_targets[0].1, vec![fresh_endpoint]);
    assert!(!background_targets[0].1.contains(&stale_endpoint));
}

#[tokio::test]
async fn easy_local_scans_explicit_predicted_window_without_birthday_expansion() {
    let manager = PeerManager::new(test_config());
    let stale_endpoint: SocketAddr = "203.0.113.10:40000".parse().unwrap();
    let observed = "203.0.113.10:41000".to_string();
    let mut candidates = vec![observed.clone()];
    candidates.extend((41_001..=41_024).map(|port| format!("203.0.113.10:{port}")));
    let mut sources = candidates
        .iter()
        .cloned()
        .map(|candidate| (candidate, "predicted".to_string()))
        .collect::<HashMap<_, _>>();
    sources.insert(observed, "stun_observed".to_string());

    manager
        .add_peer(&test_peer("peer1", stale_endpoint))
        .await;
    manager
        .add_candidates_with_sources("peer1", &candidates, &sources)
        .await;

    let targets = manager.direct_probe_targets_for("peer1").await;

    assert_eq!(targets.len(), candidates.len());
    assert!(targets
        .iter()
        .all(|target| candidates.contains(&target.to_string())));
    assert!(!targets.contains(&stale_endpoint));
}

#[tokio::test]
async fn easy_local_expands_after_the_explicit_prediction_window_fails() {
    let manager = PeerManager::new(test_config());
    let registry_endpoint: SocketAddr = "203.0.113.10:40000".parse().unwrap();
    let observed: SocketAddr = "203.0.113.10:41000".parse().unwrap();
    let predicted = (41_001..=41_024)
        .map(|port| SocketAddr::new(observed.ip(), port))
        .collect::<HashSet<_>>();
    let mut candidates = vec![observed.to_string()];
    candidates.extend(predicted.iter().map(ToString::to_string));
    let mut sources = predicted
        .iter()
        .map(|endpoint| (endpoint.to_string(), "predicted".to_string()))
        .collect::<HashMap<_, _>>();
    sources.insert(observed.to_string(), "stun_observed".to_string());

    manager
        .add_peer(&test_peer("peer1", registry_endpoint))
        .await;
    manager
        .add_candidates_with_sources("peer1", &candidates, &sources)
        .await;
    let mut easy_profile = birthday_nat_profile();
    easy_profile.mapping_behavior = p2pnet_nat::MappingBehavior::EndpointIndependent;
    easy_profile.filtering_behavior = p2pnet_nat::FilteringBehavior::Unknown;
    easy_profile.birthday_candidate = false;
    manager.update_nat_profile(easy_profile).await;

    let initial_targets = manager.direct_probe_targets_for("peer1").await;
    assert!(initial_targets
        .iter()
        .all(|target| *target == observed || predicted.contains(target)));

    {
        let mut conns = manager.connections.write().await;
        let conn = conns.get_mut("peer1").unwrap();
        for endpoint in &predicted {
            conn.ensure_candidate_pair_with_source(*endpoint, 0, CandidatePairSource::Predicted)
                .record_failure(REASON_DIRECT_PROBE_FAILED, "predicted window miss", None);
        }
    }

    let synchronized_retry = manager.direct_probe_targets_for("peer1").await;
    assert!(synchronized_retry.iter().any(|target| {
        target.ip() == observed.ip() && *target != observed && !predicted.contains(target)
    }));

    let background_retries = manager.direct_probe_targets().await;
    assert_eq!(background_retries.len(), 1);
    assert!(background_retries[0].1.iter().any(|target| {
        target.ip() == observed.ip() && *target != observed && !predicted.contains(target)
    }));
}

#[tokio::test]
async fn remote_port_churn_triggers_birthday_probe_targets() {
    let config = test_config();
    let manager = PeerManager::new(config);
    let registry_endpoint: SocketAddr = "203.0.113.10:40000".parse().unwrap();
    let candidates = vec![
        "203.0.113.10:41001".to_string(),
        "203.0.113.10:41037".to_string(),
        "203.0.113.10:41113".to_string(),
    ];
    let sources = candidates
        .iter()
        .map(|candidate| (candidate.clone(), "stun_observed".to_string()))
        .collect::<HashMap<_, _>>();

    manager
        .add_peer(&test_peer("peer1", registry_endpoint))
        .await;
    manager
        .add_candidates_with_sources("peer1", &candidates, &sources)
        .await;

    let background_targets = manager.direct_probe_targets().await;
    assert_eq!(background_targets.len(), 1);
    let targets = &background_targets[0].1;
    let birthday_targets = targets
        .iter()
        .filter(|target| {
            target.ip().to_string() == "203.0.113.10"
                && !candidates.contains(&target.to_string())
                && **target != registry_endpoint
        })
        .collect::<Vec<_>>();
    let bases = candidates
        .iter()
        .map(|candidate| candidate.parse::<SocketAddr>().unwrap())
        .collect::<Vec<_>>();
    let expected_birthday_targets = birthday_probe_endpoints_for_bases(
        &bases,
        birthday_probe_budget_for_base_count(&TraversalHistory::default(), bases.len()),
    )
    .into_iter()
    .filter(|target| {
        target.ip().to_string() == "203.0.113.10"
            && !candidates.contains(&target.to_string())
            && *target != registry_endpoint
    })
    .count();

    assert!(!targets.contains(&registry_endpoint));
    assert_eq!(birthday_targets.len(), expected_birthday_targets);
    assert!(birthday_targets
        .iter()
        .any(|target| target.port().abs_diff(41001) <= 2));
    assert!(birthday_targets
        .iter()
        .any(|target| target.port().abs_diff(41037) <= 2));
    assert!(birthday_targets
        .iter()
        .any(|target| target.port().abs_diff(41113) <= 2));
}

#[tokio::test]
async fn remote_port_churn_triggers_birthday_targets_in_synchronized_punch() {
    let config = test_config();
    let manager = PeerManager::new(config);
    let registry_endpoint: SocketAddr = "203.0.113.10:40000".parse().unwrap();
    let candidates = vec![
        "203.0.113.10:41001".to_string(),
        "203.0.113.10:41037".to_string(),
        "203.0.113.10:41113".to_string(),
    ];
    let sources = candidates
        .iter()
        .map(|candidate| (candidate.clone(), "stun_observed".to_string()))
        .collect::<HashMap<_, _>>();

    manager
        .add_peer(&test_peer("peer1", registry_endpoint))
        .await;
    manager
        .add_candidates_with_sources("peer1", &candidates, &sources)
        .await;

    let targets = manager.direct_probe_targets_for("peer1").await;
    let birthday_targets = targets
        .iter()
        .filter(|target| {
            target.ip().to_string() == "203.0.113.10"
                && !candidates.contains(&target.to_string())
                && **target != registry_endpoint
        })
        .collect::<Vec<_>>();
    let bases = candidates
        .iter()
        .map(|candidate| candidate.parse::<SocketAddr>().unwrap())
        .collect::<Vec<_>>();
    let expected_birthday_targets = birthday_probe_endpoints_for_bases(
        &bases,
        birthday_probe_budget_for_base_count(&TraversalHistory::default(), bases.len()),
    )
    .into_iter()
    .filter(|target| {
        target.ip().to_string() == "203.0.113.10"
            && !candidates.contains(&target.to_string())
            && *target != registry_endpoint
    })
    .count();

    assert!(!targets.contains(&registry_endpoint));
    assert_eq!(birthday_targets.len(), expected_birthday_targets);
    assert!(birthday_targets
        .iter()
        .any(|target| target.port().abs_diff(41001) <= 2));
    assert!(birthday_targets
        .iter()
        .any(|target| target.port().abs_diff(41037) <= 2));
    assert!(birthday_targets
        .iter()
        .any(|target| target.port().abs_diff(41113) <= 2));
}

#[tokio::test]
async fn hard_local_nat_uses_single_public_peer_candidate_without_scatter() {
    let manager = PeerManager::new(test_config());
    let stable_endpoint: SocketAddr = "203.0.113.10:41000".parse().unwrap();
    let candidates = vec![stable_endpoint.to_string()];
    let sources = HashMap::from([(stable_endpoint.to_string(), "stun_observed".to_string())]);

    manager.update_nat_profile(birthday_nat_profile()).await;
    manager
        .add_peer(&test_peer("peer1", stable_endpoint))
        .await;
    manager
        .add_candidates_with_sources("peer1", &candidates, &sources)
        .await;

    let targets = manager.direct_probe_targets_for("peer1").await;
    assert_eq!(targets, vec![stable_endpoint]);
}

#[tokio::test]
async fn stale_birthday_pairs_are_pruned_when_signaled_window_moves() {
    let manager = PeerManager::new(test_config());
    manager
        .add_peer(&test_peer("peer1", "127.0.0.1:51820".parse().unwrap()))
        .await;

    let first_candidates = vec!["8.8.8.8:41000".to_string(), "8.8.8.8:41037".to_string()];
    let first_sources = first_candidates
        .iter()
        .map(|candidate| (candidate.clone(), "stun_observed".to_string()))
        .collect::<HashMap<_, _>>();
    manager
        .add_candidates_with_sources("peer1", &first_candidates, &first_sources)
        .await;

    let first_targets = manager.direct_probe_targets_for("peer1").await;
    let stale_birthday: SocketAddr = "8.8.8.8:41001".parse().unwrap();
    assert!(first_targets.contains(&stale_birthday));

    let next_candidates = vec!["9.9.9.9:42000".to_string(), "9.9.9.9:42037".to_string()];
    let next_sources = next_candidates
        .iter()
        .map(|candidate| (candidate.clone(), "stun_observed".to_string()))
        .collect::<HashMap<_, _>>();
    manager
        .add_candidates_with_sources("peer1", &next_candidates, &next_sources)
        .await;

    let next_targets = manager.direct_probe_targets_for("peer1").await;
    assert!(!next_targets.contains(&stale_birthday));

    let diagnostics = manager.diagnostics().await;
    assert!(!diagnostics[0]
        .candidate_pairs
        .iter()
        .any(|pair| pair.remote_endpoint == stale_birthday.to_string()));
}
