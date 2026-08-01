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
fn birthday_probe_endpoints_for_bases_rotates_bounded_window() {
    let base: SocketAddr = "203.0.113.10:40000".parse().unwrap();
    let first = birthday_probe_endpoints_for_bases_from_rank(&[base], 64, 0);
    let second =
        birthday_probe_endpoints_for_bases_from_rank(&[base], 64, BIRTHDAY_PROBE_BUDGET_PER_CYCLE);
    let first_ports = first.iter().map(SocketAddr::port).collect::<HashSet<_>>();
    let second_ports = second.iter().map(SocketAddr::port).collect::<HashSet<_>>();

    assert_eq!(first.len(), 64);
    assert_eq!(second.len(), 64);
    assert!(first_ports.is_disjoint(&second_ports));
}

#[tokio::test]
async fn birthday_candidates_use_wider_default_probe_budget() {
    let config = test_config();
    let manager = PeerManager::new(config);
    let endpoint: SocketAddr = "203.0.113.10:40000".parse().unwrap();

    manager.add_peer(&test_peer("peer1", endpoint)).await;
    manager.update_nat_profile(birthday_nat_profile()).await;

    let initial_targets = manager.direct_probe_targets_for("peer1").await;
    let initial_birthday_count = initial_targets
        .iter()
        .filter(|target| **target != endpoint && target.ip() == endpoint.ip())
        .count();
    assert!(initial_targets.contains(&endpoint));
    assert_eq!(initial_birthday_count, BIRTHDAY_PROBE_BUDGET_PER_CYCLE);

    let background_targets = manager.direct_probe_targets().await;
    assert_eq!(background_targets.len(), 1);
    let targets = &background_targets[0].1;
    let birthday_count = targets
        .iter()
        .filter(|target| **target != endpoint && target.ip() == endpoint.ip())
        .count();

    assert!(targets.contains(&endpoint));
    assert_eq!(birthday_count, BIRTHDAY_PROBE_BUDGET_PER_CYCLE);
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
        .chain(std::iter::once(registry_endpoint))
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

    assert!(targets.contains(&registry_endpoint));
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
        .chain(std::iter::once(registry_endpoint))
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

    assert!(targets.contains(&registry_endpoint));
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
async fn stale_birthday_pairs_are_pruned_when_signaled_ports_move() {
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

    let next_candidates = vec!["8.8.8.8:42000".to_string(), "8.8.8.8:42037".to_string()];
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
