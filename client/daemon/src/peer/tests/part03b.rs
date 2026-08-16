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
    assert!(ports.contains(&40502));
    assert!(ports.iter().any(|port| port.abs_diff(40000) > 64));
}

#[test]
fn birthday_near_window_wraps_across_udp_port_boundaries() {
    let low = birthday_probe_endpoints("203.0.113.10:1".parse().unwrap());
    let high = birthday_probe_endpoints("203.0.113.10:65535".parse().unwrap());
    assert!(low.iter().any(|endpoint| endpoint.port() == 65_535));
    assert!(high.iter().any(|endpoint| endpoint.port() == 1));
}

#[test]
fn stable_public_ip_permutation_covers_every_nonzero_udp_port_per_public_ip() {
    let public_ips = [
        "220.163.6.190".parse::<IpAddr>().unwrap(),
        "203.0.113.10".parse::<IpAddr>().unwrap(),
    ];
    let plan = stable_public_ip_probe_plan_from_rank(
        &public_ips,
        BIRTHDAY_PROBE_PORT_SPACE * public_ips.len(),
        0,
        &HashSet::new(),
    );

    assert_eq!(
        plan.endpoints.len(),
        BIRTHDAY_PROBE_PORT_SPACE * public_ips.len()
    );
    for public_ip in public_ips {
        let ports = plan
            .endpoints
            .iter()
            .filter(|endpoint| endpoint.ip() == public_ip)
            .map(SocketAddr::port)
            .collect::<HashSet<_>>();
        assert_eq!(ports.len(), BIRTHDAY_PROBE_PORT_SPACE);
        assert!(ports.contains(&1));
        assert!(ports.contains(&65_535));
    }
    assert!(plan
        .endpoints
        .contains(&"220.163.6.190:43076".parse().unwrap()));
    assert_eq!(plan.next_rank, 0);
    assert!(plan.wrapped);
}

#[test]
fn consecutive_stable_public_ip_windows_are_disjoint_before_wrap() {
    let public_ip: IpAddr = "203.0.113.10".parse().unwrap();
    let excluded = HashSet::from([
        "203.0.113.10:40000".parse().unwrap(),
        "203.0.113.10:41000".parse().unwrap(),
    ]);
    let mut committed = HashSet::new();
    let mut cursor = 0;

    for _ in 0..8 {
        let plan = stable_public_ip_probe_plan_from_rank(&[public_ip], 3_072, cursor, &excluded);
        assert!(!plan.wrapped);
        assert!(plan
            .endpoints
            .iter()
            .all(|endpoint| !excluded.contains(endpoint)));
        assert!(plan
            .endpoints
            .iter()
            .all(|endpoint| committed.insert(*endpoint)));
        cursor = plan.next_rank;
    }
}

#[test]
fn stable_public_ip_cursor_never_skips_a_partial_multi_ip_rank() {
    let public_ips = vec![
        "203.0.113.10".parse().unwrap(),
        "203.0.113.11".parse().unwrap(),
        "203.0.113.12".parse().unwrap(),
    ];
    let first = stable_public_ip_probe_plan_from_rank(&public_ips, 4, 0, &HashSet::new());
    assert_eq!(first.endpoints.len(), 3);
    assert_eq!(first.next_rank, 1);
    let second =
        stable_public_ip_probe_plan_from_rank(&public_ips, 3, first.next_rank, &HashSet::new());
    assert_eq!(second.endpoints.len(), 3);
    assert_eq!(second.next_rank, 2);
}

#[test]
fn birthday_probe_endpoints_for_bases_keeps_near_window_when_wide_window_rotates() {
    let base: SocketAddr = "203.0.113.10:40000".parse().unwrap();
    let budget = birthday_probe_near_rank_count() + 8;
    let first = birthday_probe_endpoints_for_bases_from_rank(&[base], budget, 0);
    let second = birthday_probe_endpoints_for_bases_from_rank(
        &[base],
        budget,
        BIRTHDAY_PROBE_BUDGET_PER_CYCLE,
    );
    let first_ports = first.iter().map(SocketAddr::port).collect::<HashSet<_>>();
    let second_ports = second.iter().map(SocketAddr::port).collect::<HashSet<_>>();

    assert_eq!(first.len(), budget);
    assert_eq!(second.len(), budget);
    for port in [39999, 40001, 39904, 40096] {
        assert!(
            first_ports.contains(&port),
            "first pass missing near port {port}"
        );
        assert!(
            second_ports.contains(&port),
            "second pass missing near port {port}"
        );
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

    manager.add_peer(&test_peer("peer1", stale_endpoint)).await;
    manager
        .add_candidates_with_sources(
            "peer1",
            &[fresh_endpoint.to_string()],
            &HashMap::from([(fresh_endpoint.to_string(), "stun_observed".to_string())]),
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

    manager.add_peer(&test_peer("peer1", stale_endpoint)).await;
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
async fn stable_side_wide_scatter_rotates_unique_birthday_windows() {
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
    let mut stable_profile = birthday_nat_profile();
    stable_profile.mapping_behavior = MappingBehavior::EndpointIndependent;
    stable_profile.filtering_behavior = p2pnet_nat::FilteringBehavior::Unknown;
    stable_profile.public_port_stable = Some(true);
    stable_profile.likely_symmetric = Some(false);
    stable_profile.birthday_candidate = false;
    manager.update_nat_profile(stable_profile).await;

    {
        let mut conns = manager.connections.write().await;
        let conn = conns.get_mut("peer1").unwrap();
        for endpoint in &predicted {
            conn.ensure_candidate_pair_with_source(*endpoint, 0, CandidatePairSource::Predicted)
                .record_failure(REASON_DIRECT_PROBE_FAILED, "predicted window miss", None);
        }
    }

    let first = manager
        .direct_probe_target_set_for("peer1")
        .await
        .expect("stable side should produce a wide target set");
    assert!(first.remote_scatter_pool);
    assert!(first.stable_remote_scatter);
    // The wide window is generated rank-by-rank in bounded slices: the first
    // plan is exactly one slice, never the full 3,072-candidate budget, so
    // resident candidate-pair state matches what this session actually sends.
    assert!(first.candidates.len() <= STABLE_SCATTER_PLAN_SLICE);
    assert!(first.candidates.len() >= STABLE_SCATTER_PLAN_SLICE / 2);
    assert!(first.candidates.len() <= STABLE_WIDE_SCATTER_UNIQUE_TARGET_BUDGET);
    let first_plan = first.birthday_plan.unwrap();
    assert!(first_plan.stable_side_unique_scatter);
    assert_eq!(
        first_plan.selected_birthday_candidates,
        first_plan.generated_candidates
    );
    assert_eq!(first_plan.start_rank, 0);
    assert!(
        !manager
            .commit_birthday_probe_cursor("peer1", &first_plan, false)
            .await
    );
    let incomplete_retry = manager
        .direct_probe_target_set_for("peer1")
        .await
        .expect("an incompletely sent window must remain retryable");
    assert_eq!(
        incomplete_retry.birthday_plan.unwrap().start_rank,
        first_plan.start_rank
    );
    assert!(
        manager
            .commit_birthday_probe_cursor("peer1", &first_plan, true)
            .await
    );

    // Reapplying an identical source-only signal must not reset progress.
    manager
        .add_candidates_with_sources("peer1", &candidates, &sources)
        .await;
    let second = manager
        .direct_probe_target_set_for("peer1")
        .await
        .expect("next wide target set should continue from the cursor");
    let second_plan = second.birthday_plan.unwrap();
    assert_eq!(second_plan.start_rank, first_plan.end_rank);
    assert_ne!(second.candidates, first.candidates);
    // Resident candidate pairs stay bounded across the windowed rotation.
    let diagnostics = manager.diagnostics().await;
    assert!(
        diagnostics[0].candidate_pairs.len() <= MAX_CANDIDATE_PAIRS_PER_PEER,
        "windowed generation must keep candidate-pair state bounded, got {}",
        diagnostics[0].candidate_pairs.len()
    );
}

fn stable_scatter_signal(
    public_ip: IpAddr,
    observed_port: u16,
) -> (Vec<String>, HashMap<String, String>, HashSet<SocketAddr>) {
    let observed = SocketAddr::new(public_ip, observed_port);
    let predicted = (1..=24)
        .map(|offset| SocketAddr::new(public_ip, observed_port.saturating_add(offset)))
        .collect::<HashSet<_>>();
    let mut candidates = vec![observed.to_string()];
    candidates.extend(predicted.iter().map(ToString::to_string));
    let mut sources = predicted
        .iter()
        .map(|endpoint| (endpoint.to_string(), "predicted".to_string()))
        .collect::<HashMap<_, _>>();
    sources.insert(observed.to_string(), "stun_observed".to_string());
    (candidates, sources, predicted)
}

async fn stable_scatter_manager(public_ip: IpAddr, observed_port: u16) -> PeerManager {
    let manager = PeerManager::new(test_config());
    let registry_endpoint = SocketAddr::new(public_ip, observed_port.saturating_sub(1_000));
    let (candidates, sources, predicted) = stable_scatter_signal(public_ip, observed_port);
    manager
        .add_peer(&test_peer("peer1", registry_endpoint))
        .await;
    manager
        .add_candidates_with_sources("peer1", &candidates, &sources)
        .await;

    let mut stable_profile = birthday_nat_profile();
    stable_profile.mapping_behavior = MappingBehavior::EndpointIndependent;
    stable_profile.filtering_behavior = p2pnet_nat::FilteringBehavior::Unknown;
    stable_profile.public_port_stable = Some(true);
    stable_profile.likely_symmetric = Some(false);
    stable_profile.birthday_candidate = false;
    manager.update_nat_profile(stable_profile).await;

    let generation = manager.current_network_generation().await;
    let mut conns = manager.connections.write().await;
    let conn = conns.get_mut("peer1").unwrap();
    for endpoint in predicted {
        conn.ensure_candidate_pair_with_source(
            endpoint,
            generation,
            CandidatePairSource::Predicted,
        )
        .record_failure(REASON_DIRECT_PROBE_FAILED, "predicted window miss", None);
    }
    drop(conns);
    manager
}

#[tokio::test]
async fn same_public_ip_stun_port_churn_preserves_birthday_cursor() {
    let public_ip = "203.0.113.10".parse().unwrap();
    let manager = stable_scatter_manager(public_ip, 41_000).await;

    let first_plan = manager
        .direct_probe_target_set_for("peer1")
        .await
        .unwrap()
        .birthday_plan
        .unwrap();
    assert!(
        manager
            .commit_birthday_probe_cursor("peer1", &first_plan, true)
            .await
    );
    let second_plan = manager
        .direct_probe_target_set_for("peer1")
        .await
        .unwrap()
        .birthday_plan
        .unwrap();
    assert_eq!(second_plan.start_rank, first_plan.end_rank);

    let (churned_candidates, churned_sources, churned_predicted) =
        stable_scatter_signal(public_ip, 51_000);
    manager
        .add_candidates_with_sources("peer1", &churned_candidates, &churned_sources)
        .await;
    assert!(
        manager
            .commit_birthday_probe_cursor("peer1", &second_plan, true)
            .await
    );

    let generation = manager.current_network_generation().await;
    let mut conns = manager.connections.write().await;
    let conn = conns.get_mut("peer1").unwrap();
    for endpoint in churned_predicted {
        conn.ensure_candidate_pair_with_source(
            endpoint,
            generation,
            CandidatePairSource::Predicted,
        )
        .record_failure(REASON_DIRECT_PROBE_FAILED, "predicted window miss", None);
    }
    drop(conns);

    let after_churn = manager
        .direct_probe_target_set_for("peer1")
        .await
        .unwrap()
        .birthday_plan
        .unwrap();
    assert_eq!(after_churn.start_rank, second_plan.end_rank);
}

#[tokio::test]
async fn public_ip_change_rejects_stale_birthday_cursor_commit() {
    let manager = stable_scatter_manager("203.0.113.10".parse().unwrap(), 41_000).await;
    let stale_plan = manager
        .direct_probe_target_set_for("peer1")
        .await
        .unwrap()
        .birthday_plan
        .unwrap();

    let (candidates, sources, _) = stable_scatter_signal("198.51.100.20".parse().unwrap(), 42_000);
    manager
        .add_candidates_with_sources("peer1", &candidates, &sources)
        .await;

    assert!(
        !manager
            .commit_birthday_probe_cursor("peer1", &stale_plan, true)
            .await
    );
}

#[tokio::test]
async fn network_generation_change_rejects_stale_birthday_cursor_commit() {
    let manager = stable_scatter_manager("203.0.113.10".parse().unwrap(), 41_000).await;
    let stale_plan = manager
        .direct_probe_target_set_for("peer1")
        .await
        .unwrap()
        .birthday_plan
        .unwrap();

    manager.advance_network_generation("test handover").await;

    assert!(
        !manager
            .commit_birthday_probe_cursor("peer1", &stale_plan, true)
            .await
    );
}

#[tokio::test]
async fn birthday_cursor_commits_when_planned_and_selected_counts_differ() {
    // The field log showed `selected_birthday_candidates=2973` while
    // `generated_candidates=2976` (three planned endpoints were already part
    // of the advertised candidate set and were deduplicated).  The old
    // equality check stalled the cursor at start_rank 8942 for nine cycles;
    // the commit must only require that every selected candidate was covered
    // and that birthday probing actually happened.
    let public_ip = "203.0.113.10".parse().unwrap();
    let manager = stable_scatter_manager(public_ip, 41_000).await;
    let generation = manager.current_network_generation().await;
    // Advance the cursor to the field-observed start_rank first.
    let ramp = BirthdayProbePlan {
        local_generation: generation,
        stable_side_unique_scatter: true,
        bases: vec![SocketAddr::new(public_ip, 41_000)],
        public_ips: vec![public_ip],
        start_rank: 0,
        end_rank: 8942,
        generated_candidates: 2_976,
        planned_candidates: 3_072,
        selected_candidates: 3_072,
        selected_birthday_candidates: 2_976,
        unique_target_ports: 3_072,
        wrapped: false,
    };
    assert!(manager.commit_birthday_probe_cursor("peer1", &ramp, true).await);
    let plan = BirthdayProbePlan {
        local_generation: manager.current_network_generation().await,
        stable_side_unique_scatter: true,
        bases: vec![SocketAddr::new(public_ip, 41_000)],
        public_ips: vec![public_ip],
        start_rank: 8942,
        end_rank: 11_921,
        generated_candidates: 2_976,
        planned_candidates: 3_072,
        selected_candidates: 3_072,
        selected_birthday_candidates: 2_973,
        unique_target_ports: 3_072,
        wrapped: false,
    };
    assert!(
        manager
            .commit_birthday_probe_cursor("peer1", &plan, true)
            .await,
        "cursor must advance even when some planned birthday endpoints were deduplicated"
    );
    let next = manager
        .direct_probe_target_set_for("peer1")
        .await
        .unwrap()
        .birthday_plan
        .unwrap();
    assert_eq!(next.start_rank, 11_921 % birthday_probe_wide_rank_count());
    assert_ne!(next.start_rank, 8942);
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
    // The birthday window is generated in bounded per-plan slices: the
    // expected set mirrors the sliced budget exactly.
    let sliced_budget = birthday_probe_budget_for_base_count(&TraversalHistory::default(), bases.len())
        .min(BIRTHDAY_PLAN_SLICE.saturating_sub(candidates.len()));
    let expected_birthday_targets = birthday_probe_endpoints_for_bases(&bases, sliced_budget)
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
async fn remote_nat_behavior_hint_starts_bounded_scatter_with_one_candidate() {
    let manager = PeerManager::new(test_config());
    let stable_profile = NatProfile {
        mapping_behavior: MappingBehavior::EndpointIndependent,
        public_ip_stable: Some(true),
        public_port_stable: Some(true),
        likely_symmetric: Some(false),
        birthday_candidate: false,
        ..birthday_nat_profile()
    };
    manager.update_nat_profile(stable_profile).await;

    let endpoint: SocketAddr = "203.0.113.10:41001".parse().unwrap();
    let mut peer = test_peer("peer-hinted-hard", endpoint);
    peer.nat_type = "p2:m=address_or_port_dependent;a=linear;d=32;c=90".to_string();
    manager.add_peer(&peer).await;
    manager
        .add_candidates_with_sources(
            "peer-hinted-hard",
            &[endpoint.to_string()],
            &HashMap::from([(endpoint.to_string(), "stun_observed".to_string())]),
        )
        .await;

    let target_set = manager
        .direct_probe_target_set_for("peer-hinted-hard")
        .await
        .expect("the hinted peer must receive a direct target set");
    assert!(target_set.remote_scatter_pool);
    assert!(target_set.stable_remote_scatter);
    assert!(
        target_set.candidates.len() > 1,
        "a stable local side must begin a bounded scatter plan immediately"
    );
    assert!(target_set.birthday_plan.is_some());
}

#[tokio::test]
async fn port_dependent_remote_explicit_predicted_window_never_silences_stable_scatter() {
    // Field evidence (v0.1.116, R9): the `a=random` remote advertised a fresh
    // prediction window whose ports covered only ITS rendering for its other
    // targets — the mapping the local peer actually needs sat outside it.  The
    // explicit (unfailed) window used to suppress the stable side's scatter
    // until the window had fully failed, so the punch expired before the wide
    // scan ever covered the real mapping.
    let manager = PeerManager::new(test_config());
    let registry_endpoint: SocketAddr = "203.0.113.10:40000".parse().unwrap();
    let observed: SocketAddr = "203.0.113.10:41000".parse().unwrap();
    let predicted = (41_001..=41_008)
        .map(|port| SocketAddr::new(observed.ip(), port))
        .collect::<Vec<_>>();
    let mut candidates = vec![observed.to_string()];
    candidates.extend(predicted.iter().map(ToString::to_string));
    let mut sources = predicted
        .iter()
        .map(|endpoint| (endpoint.to_string(), "predicted".to_string()))
        .collect::<HashMap<_, _>>();
    sources.insert(observed.to_string(), "stun_observed".to_string());

    let mut peer = test_peer("peer-r9-apd", registry_endpoint);
    peer.nat_type = "p2:m=address_or_port_dependent;a=random;d=32;c=90".to_string();
    manager.add_peer(&peer).await;
    manager
        .add_candidates_with_sources("peer-r9-apd", &candidates, &sources)
        .await;
    let mut stable_profile = birthday_nat_profile();
    stable_profile.mapping_behavior = MappingBehavior::EndpointIndependent;
    stable_profile.filtering_behavior = p2pnet_nat::FilteringBehavior::Unknown;
    stable_profile.public_port_stable = Some(true);
    stable_profile.likely_symmetric = Some(false);
    stable_profile.birthday_candidate = false;
    manager.update_nat_profile(stable_profile).await;

    let target_set = manager
        .direct_probe_target_set_for("peer-r9-apd")
        .await
        .expect("the port-dependent remote must receive a direct target set");
    assert!(
        target_set.remote_scatter_pool,
        "a port-dependent remote's explicit prediction window is destination-specific and must not silence the stable side's scatter"
    );
    assert!(target_set.stable_remote_scatter);
    assert!(
        target_set.birthday_plan.is_some(),
        "the wide scatter plan must be generated immediately, without waiting for the predicted window to fail"
    );
    assert!(
        target_set.candidates.iter().any(|candidate| {
            candidate.ip() == observed.ip() && !predicted.contains(candidate)
        }),
        "the scatter must reach ports outside the advertised prediction window"
    );
}

#[tokio::test]
async fn port_dependent_remote_predicted_stage_offers_full_192_unique_scatter_window() {
    // Field evidence v0.1.116 (R4/R7/R8): the stable side of an
    // address/port-dependent remote reached only 64 unique CGNAT ports per
    // recovery session.  StableUniqueScatter uses ONE socket (one datagram
    // per distinct port), so the recovery stage's `ceiling / socket_count`
    // division was wrongly halving the 192-datagram budget by three — at
    // ~0.1% per-port hit odds on a destination-dependent mapping, that 64 vs
    // 192 coverage gap is why 3/10 real rounds stayed on relay.  Once the
    // epoch reaches Predicted (predicted window had no matched ACK), the
    // window must grow to ~192 distinct ports.
    let manager = PeerManager::new(test_config());
    let registry_endpoint: SocketAddr = "203.0.113.10:40000".parse().unwrap();
    let observed: SocketAddr = "203.0.113.10:41000".parse().unwrap();
    let predicted = (41_001..=41_008)
        .map(|port| SocketAddr::new(observed.ip(), port))
        .collect::<Vec<_>>();
    let mut candidates = vec![observed.to_string()];
    candidates.extend(predicted.iter().map(ToString::to_string));
    let mut sources = predicted
        .iter()
        .map(|endpoint| (endpoint.to_string(), "predicted".to_string()))
        .collect::<HashMap<_, _>>();
    sources.insert(observed.to_string(), "stun_observed".to_string());

    let mut peer = test_peer("peer-r9-apd-stage", registry_endpoint);
    peer.nat_type = "p2:m=address_or_port_dependent;a=random;d=32;c=90".to_string();
    manager.add_peer(&peer).await;
    manager
        .add_candidates_with_sources("peer-r9-apd-stage", &candidates, &sources)
        .await;
    let mut stable_profile = birthday_nat_profile();
    stable_profile.mapping_behavior = MappingBehavior::EndpointIndependent;
    stable_profile.filtering_behavior = p2pnet_nat::FilteringBehavior::Unknown;
    stable_profile.public_port_stable = Some(true);
    stable_profile.likely_symmetric = Some(false);
    stable_profile.birthday_candidate = false;
    manager.update_nat_profile(stable_profile).await;

    // Open the recovery epoch and advance Initial -> Predicted (one
    // zero-matched-ACK feedback round), the stage where the APD remote's wide
    // scatter is released.
    let admission = manager
        .recovery_epoch_admit("peer-r9-apd-stage")
        .await;
    assert!(matches!(
        admission,
        RecoveryAdmission::Accepted { .. }
    ));
    manager
        .advance_recovery_stage_after_no_ack("peer-r9-apd-stage", "predicted window no ack")
        .await;
    assert_eq!(
        manager
            .recovery_stage_for("peer-r9-apd-stage")
            .await,
        RecoveryStage::Predicted
    );

    let target_set = manager
        .direct_probe_target_set_for("peer-r9-apd-stage")
        .await
        .expect("APD remote must receive a target set");
    assert!(target_set.remote_scatter_pool);
    assert!(target_set.stable_remote_scatter);
    assert!(
        target_set.birthday_plan.is_some(),
        "wide scatter must survive the Predicted stage for a port-dependent remote"
    );
    assert!(
        target_set.candidates.len() >= 128,
        "stable-side unique scatter must cover ~192 distinct ports (one socket, one datagram each), not 64: got {}",
        target_set.candidates.len()
    );
    assert!(
        target_set.candidates.len() <= STABLE_SCATTER_PLAN_SLICE,
        "the window stays bounded by the per-plan slice"
    );
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
    // The birthday window is generated in bounded per-plan slices: the
    // expected set mirrors the sliced budget exactly.
    let sliced_budget = birthday_probe_budget_for_base_count(&TraversalHistory::default(), bases.len())
        .min(BIRTHDAY_PLAN_SLICE.saturating_sub(candidates.len()));
    let expected_birthday_targets = birthday_probe_endpoints_for_bases(&bases, sliced_budget)
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
    manager.add_peer(&test_peer("peer1", stable_endpoint)).await;
    manager
        .add_candidates_with_sources("peer1", &candidates, &sources)
        .await;

    let targets = manager.direct_probe_targets_for("peer1").await;
    assert_eq!(targets, vec![stable_endpoint]);
}

#[tokio::test]
async fn hard_local_nat_maintainer_targets_stable_public_endpoint() {
    let manager = PeerManager::new(test_config());
    let stable_endpoint: SocketAddr = "203.0.113.10:41000".parse().unwrap();
    let candidates = vec![stable_endpoint.to_string()];
    let sources = HashMap::from([(stable_endpoint.to_string(), "stun_observed".to_string())]);

    manager.update_nat_profile(birthday_nat_profile()).await;
    manager.add_peer(&test_peer("peer1", stable_endpoint)).await;
    manager
        .add_candidates_with_sources("peer1", &candidates, &sources)
        .await;

    let targets = manager.direct_nat_maintainer_targets_for("peer1").await;
    assert_eq!(targets, vec![stable_endpoint]);
}

#[tokio::test]
async fn hard_local_nat_treats_small_stun_pool_as_stable_remote() {
    let manager = PeerManager::new(test_config());
    let registry_endpoint: SocketAddr = "203.0.113.10:41000".parse().unwrap();
    let stable_pool = [
        "203.0.113.10:41000".parse::<SocketAddr>().unwrap(),
        "203.0.113.10:41002".parse::<SocketAddr>().unwrap(),
        "203.0.113.10:41003".parse::<SocketAddr>().unwrap(),
    ];
    let candidates = stable_pool
        .iter()
        .map(ToString::to_string)
        .collect::<Vec<_>>();
    let sources = candidates
        .iter()
        .cloned()
        .map(|candidate| (candidate, "stun_observed".to_string()))
        .collect::<HashMap<_, _>>();

    manager.update_nat_profile(birthday_nat_profile()).await;
    manager
        .add_peer(&test_peer("peer1", registry_endpoint))
        .await;
    manager
        .add_candidates_with_sources("peer1", &candidates, &sources)
        .await;

    let targets = manager.direct_probe_targets_for("peer1").await;
    assert_eq!(
        targets.len(),
        stable_pool.len(),
        "a small authoritative STUN pool is fully covered: only one of the peer's socket mappings may be live, so the first burst must probe every advertised mapping"
    );
    assert!(stable_pool.iter().all(|endpoint| targets.contains(endpoint)));

    let maintainer_targets = manager.direct_nat_maintainer_targets_for("peer1").await;
    assert_eq!(maintainer_targets, targets);

    let target_set = manager
        .direct_probe_target_set_for("peer1")
        .await
        .expect("stable pool should still produce direct targets");
    assert!(!target_set.remote_scatter_pool);
}

#[tokio::test]
async fn hard_local_nat_keeps_large_stun_churn_out_of_stable_remote_role() {
    let manager = PeerManager::new(test_config());
    let registry_endpoint: SocketAddr = "203.0.113.10:41000".parse().unwrap();
    let churn = [
        "203.0.113.10:41000",
        "203.0.113.10:41005",
        "203.0.113.10:41009",
        "203.0.113.10:41014",
        "203.0.113.10:41018",
    ]
    .into_iter()
    .map(str::to_string)
    .collect::<Vec<_>>();
    let sources = churn
        .iter()
        .cloned()
        .map(|candidate| (candidate, "stun_observed".to_string()))
        .collect::<HashMap<_, _>>();

    manager.update_nat_profile(birthday_nat_profile()).await;
    manager
        .add_peer(&test_peer("peer1", registry_endpoint))
        .await;
    manager
        .add_candidates_with_sources("peer1", &churn, &sources)
        .await;

    assert!(
        manager
            .direct_nat_maintainer_targets_for("peer1")
            .await
            .is_empty(),
        "large same-IP STUN churn should not be treated as a stable socket pool"
    );

    let targets = manager.direct_probe_targets_for("peer1").await;
    assert!(
        targets.len() > churn.len(),
        "large STUN churn should retain birthday expansion"
    );
}

#[tokio::test]
async fn easy_local_nat_starts_maintainer_for_peer_scatter_risk() {
    let manager = PeerManager::new(test_config());
    let stable_endpoint: SocketAddr = "203.0.113.10:41000".parse().unwrap();
    let predicted = (41_001..=41_008)
        .map(|port| SocketAddr::new(stable_endpoint.ip(), port))
        .collect::<Vec<_>>();
    let mut candidates = vec![stable_endpoint.to_string()];
    candidates.extend(predicted.iter().map(ToString::to_string));
    let mut sources = predicted
        .iter()
        .map(|endpoint| (endpoint.to_string(), "predicted".to_string()))
        .collect::<HashMap<_, _>>();
    sources.insert(stable_endpoint.to_string(), "stun_observed".to_string());

    manager.add_peer(&test_peer("peer1", stable_endpoint)).await;
    manager
        .add_candidates_with_sources("peer1", &candidates, &sources)
        .await;

    // No local NAT profile is set at all: the maintainer must still start
    // because the peer's predicted/scatter candidate set is hard-NAT risk.
    let targets = manager.direct_nat_maintainer_targets_for("peer1").await;
    assert_eq!(targets, vec![stable_endpoint]);
}

#[tokio::test]
async fn predicted_window_remains_in_synchronized_active_pool_scan() {
    let manager = PeerManager::new(test_config());
    let stable_endpoint: SocketAddr = "203.0.113.10:41000".parse().unwrap();
    let predicted = (41_001..=41_008)
        .map(|port| SocketAddr::new(stable_endpoint.ip(), port))
        .collect::<Vec<_>>();
    let mut candidates = vec![stable_endpoint.to_string()];
    candidates.extend(predicted.iter().map(ToString::to_string));
    let mut sources = predicted
        .iter()
        .map(|endpoint| (endpoint.to_string(), "predicted".to_string()))
        .collect::<HashMap<_, _>>();
    sources.insert(stable_endpoint.to_string(), "stun_observed".to_string());

    manager.add_peer(&test_peer("peer1", stable_endpoint)).await;
    manager
        .add_candidates_with_sources("peer1", &candidates, &sources)
        .await;

    let targets = manager.direct_probe_targets_for("peer1").await;
    assert!(targets.contains(&stable_endpoint));
    assert!(predicted.iter().any(|endpoint| targets.contains(endpoint)));

    let target_set = manager
        .direct_probe_target_set_for("peer1")
        .await
        .expect("predicted window should produce synchronized targets");
    assert!(target_set.remote_scatter_pool);
}

#[tokio::test]
async fn ordinary_stable_public_probe_remains_single_target() {
    let manager = PeerManager::new(test_config());
    let stable_endpoint: SocketAddr = "203.0.113.10:41000".parse().unwrap();
    let candidates = vec![stable_endpoint.to_string()];
    let sources = HashMap::from([(stable_endpoint.to_string(), "stun_observed".to_string())]);

    manager.add_peer(&test_peer("peer1", stable_endpoint)).await;
    manager
        .add_candidates_with_sources("peer1", &candidates, &sources)
        .await;

    let targets = manager.direct_probe_targets_for("peer1").await;
    assert_eq!(targets, vec![stable_endpoint]);

    let target_set = manager
        .direct_probe_target_set_for("peer1")
        .await
        .expect("stable candidate should produce targets");
    assert!(!target_set.remote_scatter_pool);
}

#[tokio::test]
async fn fresh_public_candidate_ranks_before_stale_peer_reflexive_without_success() {
    let manager = PeerManager::new(test_config());
    let stale_peer_reflexive: SocketAddr = "8.8.8.8:1414".parse().unwrap();
    let fresh_stable: SocketAddr = "8.8.8.8:2778".parse().unwrap();
    let candidates = vec![fresh_stable.to_string()];
    let sources = HashMap::from([(fresh_stable.to_string(), "stun_observed".to_string())]);

    manager
        .add_peer(&test_peer("peer1", stale_peer_reflexive))
        .await;
    assert!(
        manager
            .learn_authenticated_endpoint("peer1", stale_peer_reflexive)
            .await
    );
    {
        let mut conns = manager.connections.write().await;
        let conn = conns.get_mut("peer1").unwrap();
        for pair in &mut conn.candidate_pairs {
            if pair.remote_endpoint == stale_peer_reflexive {
                pair.source_observed_at = Some(Instant::now() - Duration::from_secs(45));
            }
        }
    }
    manager
        .add_candidates_with_sources("peer1", &candidates, &sources)
        .await;

    let targets = manager.direct_probe_targets_for("peer1").await;
    assert!(targets.len() >= 2);
    assert_eq!(targets[0], fresh_stable);
    assert_eq!(targets[1], stale_peer_reflexive);
}

#[tokio::test]
async fn hard_local_nat_prefers_fresh_public_candidate_over_stale_peer_reflexive_without_scatter() {
    let manager = PeerManager::new(test_config());
    let stale_peer_reflexive: SocketAddr = "8.8.8.8:1414".parse().unwrap();
    let fresh_stable: SocketAddr = "8.8.8.8:2778".parse().unwrap();
    let host_candidate: SocketAddr = "192.168.2.16:53765".parse().unwrap();
    let candidates = vec![host_candidate.to_string(), fresh_stable.to_string()];
    let sources = HashMap::from([
        (host_candidate.to_string(), "host".to_string()),
        (fresh_stable.to_string(), "stun_observed".to_string()),
    ]);

    manager.update_nat_profile(birthday_nat_profile()).await;
    manager
        .add_peer(&test_peer("peer1", stale_peer_reflexive))
        .await;
    assert!(
        manager
            .learn_authenticated_endpoint("peer1", stale_peer_reflexive)
            .await
    );
    manager
        .add_candidates_with_sources("peer1", &candidates, &sources)
        .await;

    let targets = manager.direct_probe_targets_for("peer1").await;
    assert_eq!(targets, vec![fresh_stable]);
    assert!(!targets.contains(&host_candidate));
    assert!(!targets.contains(&stale_peer_reflexive));

    let conn = manager.get_connection("peer1").await.unwrap();
    assert!(!conn
        .candidate_pairs
        .iter()
        .any(|pair| pair.source == CandidatePairSource::Birthday));
}

#[tokio::test]
async fn hard_local_nat_keeps_previously_successful_private_candidate_for_reclaim() {
    let manager = PeerManager::new(test_config());
    let host_candidate: SocketAddr = "192.168.2.16:53765".parse().unwrap();
    let stable_public: SocketAddr = "8.8.8.8:2778".parse().unwrap();
    let candidates = vec![host_candidate.to_string(), stable_public.to_string()];
    let sources = HashMap::from([
        (host_candidate.to_string(), "host".to_string()),
        (stable_public.to_string(), "stun_observed".to_string()),
    ]);

    manager.update_nat_profile(birthday_nat_profile()).await;
    manager.add_peer(&test_peer("peer1", stable_public)).await;
    manager
        .add_candidates_with_sources("peer1", &candidates, &sources)
        .await;
    {
        let mut conns = manager.connections.write().await;
        conns
            .get_mut("peer1")
            .unwrap()
            .ensure_candidate_pair_with_source(host_candidate, 0, CandidatePairSource::Host)
            .record_success(Some(Duration::from_millis(4)), false, None);
    }

    let targets = manager.direct_probe_targets_for("peer1").await;
    assert!(targets.contains(&host_candidate));
    assert!(targets.contains(&stable_public));
    assert!(!targets
        .iter()
        .any(|target| { target.ip() == stable_public.ip() && *target != stable_public }));
}

#[tokio::test]
async fn hard_local_nat_uses_single_peer_reflexive_public_candidate_without_scatter() {
    let manager = PeerManager::new(test_config());
    let peer_reflexive: SocketAddr = "8.8.8.8:41000".parse().unwrap();
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

    manager.update_nat_profile(birthday_nat_profile()).await;
    manager.add_peer(&peer).await;
    assert!(
        manager
            .learn_authenticated_endpoint("peer1", peer_reflexive)
            .await
    );

    let targets = manager.direct_probe_targets_for("peer1").await;
    assert_eq!(targets, vec![peer_reflexive]);
}

#[tokio::test]
async fn peer_reflexive_public_candidates_do_not_become_birthday_bases_for_easy_local_nat() {
    let manager = PeerManager::new(test_config());
    let first_peer_reflexive: SocketAddr = "8.8.8.8:41000".parse().unwrap();
    let fresh_peer_reflexive: SocketAddr = "8.8.8.8:41037".parse().unwrap();

    manager
        .add_peer(&test_peer("peer1", first_peer_reflexive))
        .await;
    assert!(
        manager
            .learn_authenticated_endpoint("peer1", first_peer_reflexive)
            .await
    );
    assert!(
        manager
            .learn_authenticated_endpoint("peer1", fresh_peer_reflexive)
            .await
    );

    let targets = manager.direct_probe_targets_for("peer1").await;
    assert_eq!(targets, vec![fresh_peer_reflexive, first_peer_reflexive]);

    let conn = manager.get_connection("peer1").await.unwrap();
    assert!(!conn
        .candidate_pairs
        .iter()
        .any(|pair| pair.source == CandidatePairSource::Birthday));
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
