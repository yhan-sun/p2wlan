// ============================================================
// v0.1.114: mini <-> Air direct-connect fixes
//
// A. hard-NAT side covers EVERY stable public mapping (never only the
//    top-ranked `public.first()` endpoint) and the easy side activates its
//    dormant socket pool while a multi-socket peer may probe the advertised
//    mappings;
// B. the NAT binding maintainer is isolated from the recovery-epoch
//    traversal credit, and new authenticated evidence re-opens a frozen
//    epoch for a bounded retry;
// C. candidate-pair state is sliced per plan, pruned across generations and
//    hard-capped;
// plus the strict Direct gate: a matched ACK alone never promotes Direct.
// ============================================================

use std::net::Ipv4Addr;

#[tokio::test]
async fn hard_nat_side_probes_every_stable_public_mapping_in_initial_burst() {
    let manager = PeerManager::new(test_config());
    let stale_endpoint: SocketAddr = "220.165.178.32:9092".parse().unwrap();
    let advertised_pool = [
        "220.165.178.32:9089".parse::<SocketAddr>().unwrap(),
        "220.165.178.32:9091".parse::<SocketAddr>().unwrap(),
        "220.165.178.32:9092".parse::<SocketAddr>().unwrap(),
    ];
    let candidates = advertised_pool
        .iter()
        .map(ToString::to_string)
        .collect::<Vec<_>>();
    let sources = candidates
        .iter()
        .cloned()
        .map(|candidate| (candidate, "stun_observed".to_string()))
        .collect::<HashMap<_, _>>();

    // Air-like: hard NAT, and the connection endpoint happens to be the
    // STALE :9092 mapping (learned first / long ago).
    manager.update_nat_profile(birthday_nat_profile()).await;
    manager
        .add_peer(&test_peer("peer1", stale_endpoint))
        .await;
    manager
        .add_candidates_with_sources("peer1", &candidates, &sources)
        .await;

    let targets = manager.direct_probe_targets_for("peer1").await;
    assert_eq!(
        targets.len(),
        advertised_pool.len(),
        "the hard side must cover every advertised stable public mapping in the first burst"
    );
    for endpoint in &advertised_pool {
        assert!(
            targets.contains(endpoint),
            "target set must include {endpoint}"
        );
    }
    assert!(
        targets.iter().any(|target| *target != stale_endpoint),
        "the punch must not lock onto the stale :9092 endpoint exclusively"
    );

    // The maintainer keeps every advertised mapping warm, never only one.
    let maintainer_targets = manager.direct_nat_maintainer_targets_for("peer1").await;
    assert_eq!(maintainer_targets, targets);

    // The asymmetric stable role must not birthday-expand the peer's
    // multi-port set: it is a stable socket pool, not port churn.
    let target_set = manager
        .direct_probe_target_set_for("peer1")
        .await
        .expect("stable pool should produce direct targets");
    assert!(
        target_set.birthday_plan.is_none(),
        "the asymmetric stable role never builds a birthday plan"
    );
    let conn = manager.get_connection("peer1").await.unwrap();
    assert!(!conn
        .candidate_pairs
        .iter()
        .any(|pair| pair.source == CandidatePairSource::Birthday));
}

#[tokio::test]
async fn easy_nat_activates_socket_pool_for_multi_socket_hard_peer() {
    let manager = PeerManager::new(test_config());
    let mut stable_profile = birthday_nat_profile();
    stable_profile.mapping_behavior = MappingBehavior::EndpointIndependent;
    stable_profile.filtering_behavior = p2pnet_nat::FilteringBehavior::Unknown;
    stable_profile.public_port_stable = Some(true);
    stable_profile.likely_symmetric = Some(false);
    stable_profile.birthday_candidate = false;
    manager.update_nat_profile(stable_profile.clone()).await;

    let air_pool = [
        "8.8.8.8:10001".parse::<SocketAddr>().unwrap(),
        "8.8.8.8:10002".parse::<SocketAddr>().unwrap(),
        "8.8.8.8:10003".parse::<SocketAddr>().unwrap(),
    ];
    let candidates = air_pool
        .iter()
        .map(ToString::to_string)
        .collect::<Vec<_>>();
    let sources = candidates
        .iter()
        .cloned()
        .map(|candidate| (candidate, "stun_observed".to_string()))
        .collect::<HashMap<_, _>>();
    manager
        .add_peer(&test_peer("peer1", air_pool[0]))
        .await;
    manager
        .add_candidates_with_sources("peer1", &candidates, &sources)
        .await;

    assert!(
        manager.peer_needs_local_socket_pool("peer1").await,
        "a multi-socket peer probing our advertised mappings must activate the local pool"
    );

    // A single-mapping peer does not need the pool.
    let single_manager = PeerManager::new(test_config());
    single_manager.update_nat_profile(stable_profile.clone()).await;
    let single: SocketAddr = "8.8.8.8:5000".parse().unwrap();
    single_manager
        .add_peer(&test_peer("peer-single", single))
        .await;
    single_manager
        .add_candidates_with_sources(
            "peer-single",
            &[single.to_string()],
            &HashMap::from([(single.to_string(), "stun_observed".to_string())]),
        )
        .await;
    assert!(
        !single_manager.peer_needs_local_socket_pool("peer-single").await,
        "a single-mapping peer never needs the local socket pool"
    );

    // A hard local NAT already runs the pool; the easy-side trigger is moot.
    let hard_manager = PeerManager::new(test_config());
    hard_manager.update_nat_profile(birthday_nat_profile()).await;
    hard_manager
        .add_peer(&test_peer("peer-hard", air_pool[0]))
        .await;
    hard_manager
        .add_candidates_with_sources("peer-hard", &candidates, &sources)
        .await;
    assert!(
        !hard_manager.peer_needs_local_socket_pool("peer-hard").await,
        "the hard side already activates its pool through the NAT profile"
    );
}

#[tokio::test]
async fn maintainer_targets_cover_the_whole_advertised_pool_on_the_hard_side() {
    let manager = PeerManager::new(test_config());
    let pool = [
        "220.165.178.32:9089".parse::<SocketAddr>().unwrap(),
        "220.165.178.32:9091".parse::<SocketAddr>().unwrap(),
        "220.165.178.32:9092".parse::<SocketAddr>().unwrap(),
    ];
    let candidates = pool.iter().map(ToString::to_string).collect::<Vec<_>>();
    let sources = candidates
        .iter()
        .cloned()
        .map(|candidate| (candidate, "stun_observed".to_string()))
        .collect::<HashMap<_, _>>();

    manager.update_nat_profile(birthday_nat_profile()).await;
    manager
        .add_peer(&test_peer("peer1", pool[0]))
        .await;
    manager
        .add_candidates_with_sources("peer1", &candidates, &sources)
        .await;

    let targets = manager.direct_nat_maintainer_targets_for("peer1").await;
    assert_eq!(
        targets.iter().copied().collect::<HashSet<_>>(),
        pool.iter().copied().collect::<HashSet<_>>(),
        "the maintainer must cover every advertised mapping"
    );
}

#[tokio::test]
async fn authenticated_evidence_reopens_frozen_epoch_with_bounded_retry_credit() {
    let manager = PeerManager::new(test_config());
    manager
        .add_peer(&flood_peer_112("peer-fail", "10.20.0.3", "5.6.7.8:5001".parse().unwrap()))
        .await;
    manager.recovery_epoch_admit("peer-fail").await;

    // Exhaust every budget exactly like a maintainer-starved episode: probe
    // credit, plan builds and sessions all at zero, epoch frozen.
    while manager.try_consume_recovery_probe_credit("peer-fail").await {}
    for _ in 0..RECOVERY_EPOCH_PLAN_BUILDS {
        assert!(manager.try_consume_recovery_plan_build("peer-fail").await);
    }
    assert!(!manager.try_consume_recovery_plan_build("peer-fail").await);
    for _ in 0..RECOVERY_EPOCH_SESSIONS {
        assert!(manager.try_consume_recovery_session("peer-fail").await);
    }
    manager
        .mark_recovery_budget_exhausted("peer-fail", 1, 0, 0, 0, "test freeze")
        .await;
    assert!(manager.recovery_budget_frozen("peer-fail").await);
    assert!(!manager.try_consume_recovery_probe_credit("peer-fail").await);

    // New authenticated evidence re-opens the epoch for ONE bounded retry.
    manager
        .recovery_reopen_on_evidence("peer-fail", "authenticated_punch")
        .await;
    assert!(!manager.recovery_budget_frozen("peer-fail").await);
    let report = manager
        .recovery_epoch_work_budget_report("peer-fail")
        .await
        .expect("epoch must exist");
    assert_eq!(
        report.probe_credit_remaining,
        RECOVERY_EVIDENCE_RETRY_CREDIT,
        "the re-open grants exactly the small retry credit, never a full refill"
    );
    assert_eq!(
        report.plan_builds_remaining,
        RECOVERY_EVIDENCE_REGRANT_PLAN_BUILDS
    );
    assert_eq!(
        report.sessions_remaining,
        RECOVERY_EVIDENCE_REGRANT_SESSIONS
    );
    assert_eq!(
        report.stage,
        RecoveryStage::Initial,
        "evidence re-open resets the stage so the retry is compact"
    );

    // The re-open is bounded: after the per-epoch cap, further evidence
    // cannot un-freeze the epoch.
    for _ in 0..RECOVERY_EPOCH_MAX_EVIDENCE_REOPENS {
        manager
            .mark_recovery_budget_exhausted("peer-fail", 1, 0, 0, 0, "test freeze")
            .await;
        manager
            .recovery_reopen_on_evidence("peer-fail", "authenticated_punch")
            .await;
    }
    manager
        .mark_recovery_budget_exhausted("peer-fail", 1, 0, 0, 0, "test freeze")
        .await;
    manager
        .recovery_reopen_on_evidence("peer-fail", "authenticated_punch")
        .await;
    assert!(
        manager.recovery_budget_frozen("peer-fail").await,
        "evidence re-opens are capped per epoch; the epoch must stay frozen"
    );

    // A healthy epoch is untouched by the re-open.
    let healthy_manager = PeerManager::new(test_config());
    healthy_manager
        .add_peer(&flood_peer_112("peer-ok", "10.20.0.4", "5.6.7.8:5002".parse().unwrap()))
        .await;
    healthy_manager.recovery_epoch_admit("peer-ok").await;
    let before = healthy_manager
        .recovery_epoch_work_budget_report("peer-ok")
        .await
        .unwrap();
    healthy_manager
        .recovery_reopen_on_evidence("peer-ok", "authenticated_punch")
        .await;
    let after = healthy_manager
        .recovery_epoch_work_budget_report("peer-ok")
        .await
        .unwrap();
    assert_eq!(
        before.probe_credit_remaining,
        after.probe_credit_remaining,
        "a healthy epoch must not be refilled by evidence"
    );
}

#[tokio::test]
async fn quota_exhaustion_events_are_reported_once_per_epoch() {
    let manager = PeerManager::new(test_config());
    manager
        .add_peer(&flood_peer_112("peer-fail", "10.20.0.3", "5.6.7.8:5001".parse().unwrap()))
        .await;
    manager.recovery_epoch_admit("peer-fail").await;
    for _ in 0..RECOVERY_EPOCH_PLAN_BUILDS {
        assert!(manager.try_consume_recovery_plan_build("peer-fail").await);
    }

    assert!(
        manager
            .recovery_quota_event_report_due("peer-fail", "plan_build")
            .await,
        "the first quota-exhausted tick reports the event"
    );
    for _ in 0..10 {
        assert!(
            !manager
                .recovery_quota_event_report_due("peer-fail", "plan_build")
                .await,
            "repeated ticks must not re-report the same quota event"
        );
    }
    assert!(
        manager
            .recovery_quota_event_report_due("peer-fail", "session")
            .await,
        "a different quota stage reports independently"
    );
}

#[tokio::test]
async fn candidate_pair_state_stays_bounded_across_windows_and_generations() {
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

    // Sweep several stable-side windows in a row: every plan generates one
    // bounded slice and the cursor advances; the resident pair table must
    // stay far below the old 3,072-candidate balloon.
    for _ in 0..6 {
        let set = manager
            .direct_probe_target_set_for("peer1")
            .await
            .expect("stable side should produce a wide target set");
        let plan = set.birthday_plan.expect("wide scatter plan expected");
        assert!(
            plan.generated_candidates <= STABLE_SCATTER_PLAN_SLICE,
            "each plan generates at most one slice, got {}",
            plan.generated_candidates
        );
        assert!(
            manager
                .commit_birthday_probe_cursor("peer1", &plan, true)
                .await,
            "a fully sent slice must advance the cursor"
        );
    }
    // A generation change must not resurrect the retired windows either.
    manager
        .advance_candidate_refresh_generation("test generation advance")
        .await;
    manager
        .direct_probe_target_set_for("peer1")
        .await
        .expect("targets still computable after the generation advance");

    let diagnostics = manager.diagnostics().await;
    let pairs = &diagnostics[0].candidate_pairs;
    assert!(
        pairs.len() <= MAX_CANDIDATE_PAIRS_PER_PEER,
        "candidate-pair state must stay within the hard cap, got {}",
        pairs.len()
    );
    assert!(
        pairs.len() <= STABLE_SCATTER_PLAN_SLICE.saturating_add(128),
        "resident pairs must match the current window, got {}",
        pairs.len()
    );
}

#[test]
fn old_generation_pairs_without_success_are_pruned_when_targets_move() {
    let mut conn = PeerConnection::new("peer-b", "10.20.0.2");
    let old_generation = 0u64;
    let current_generation = 1u64;
    for port in 1000..1100 {
        conn.candidate_pairs.push(CandidatePair::new_with_source(
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)), port),
            old_generation,
            CandidatePairSource::Birthday,
        ));
    }
    // A successful old-generation pair is retained: the Direct-reclaim
    // window reads success history across generations.
    let mut successful = CandidatePair::new_with_source(
        SocketAddr::new(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)), 2000),
        old_generation,
        CandidatePairSource::Signaled,
    );
    successful.record_success(Some(Duration::from_millis(5)), false, None);
    conn.candidate_pairs.push(successful);

    let current: SocketAddr = "8.8.8.8:3000".parse().unwrap();
    conn.candidate_sources
        .insert(current.to_string(), CandidatePairSource::StunObserved);
    conn.candidates.push(current.to_string());

    let pruned = conn.prune_candidate_pairs_outside_targets(current_generation, &[current]);
    assert_eq!(pruned, 100);
    assert!(
        conn.candidate_pairs
            .iter()
            .any(|pair| pair.remote_endpoint.port() == 2000),
        "successful old-generation pairs must be retained"
    );
    assert!(
        !conn
            .candidate_pairs
            .iter()
            .any(|pair| (1000..1100).contains(&pair.remote_endpoint.port())),
        "zero-success old-generation pairs must be pruned"
    );
}

#[test]
fn candidate_pair_state_is_hard_capped() {
    let mut conn = PeerConnection::new("peer-b", "10.20.0.2");
    let generation = 0u64;
    let mut targets = Vec::new();
    for port in 1..=(MAX_CANDIDATE_PAIRS_PER_PEER + 200) as u16 {
        let endpoint = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)), port);
        conn.candidate_pairs.push(CandidatePair::new_with_source(
            endpoint,
            generation,
            CandidatePairSource::Birthday,
        ));
        targets.push(endpoint);
    }
    // All pairs are current targets, so the ordinary target prune keeps
    // them; only the hard per-peer cap may retire the surplus.
    let pruned = conn.prune_candidate_pairs_outside_targets(generation, &targets);
    assert_eq!(pruned, 200);
    assert!(
        conn.candidate_pairs.len() <= MAX_CANDIDATE_PAIRS_PER_PEER,
        "the per-peer pair table must never exceed the cap, got {}",
        conn.candidate_pairs.len()
    );
    assert!(
        conn.candidate_pairs.len() >= MAX_CANDIDATE_PAIRS_PER_PEER - 64,
        "the cap must retire the oldest non-selected pairs, got {}",
        conn.candidate_pairs.len()
    );
}

#[test]
fn candidate_pair_cap_keeps_current_probed_and_recent_pairs() {
    let mut conn = PeerConnection::new("peer-b", "10.20.0.2");
    let current_generation = 7u64;
    let old_generation = current_generation - 1;
    let ip = Ipv4Addr::new(198, 51, 100, 7);

    // The base population is valuable current-generation evidence: it has
    // been probed repeatedly and observed recently.
    let mut valuable = Vec::new();
    for port in 20_000..(20_000 + MAX_CANDIDATE_PAIRS_PER_PEER as u16) {
        let endpoint = SocketAddr::new(ip.into(), port);
        let pair = conn.ensure_candidate_pair_with_source(
            endpoint,
            current_generation,
            CandidatePairSource::StunObserved,
        );
        for _ in 0..3 {
            pair.record_probing(None);
        }
        valuable.push(endpoint);
    }

    // Older generations must lose before even highly-probed current pairs.
    let old_recent_high = SocketAddr::new(ip.into(), 30_000);
    let old_recent_high_2 = SocketAddr::new(ip.into(), 30_001);
    for endpoint in [old_recent_high, old_recent_high_2] {
        let pair = conn.ensure_candidate_pair_with_source(
            endpoint,
            old_generation,
            CandidatePairSource::Birthday,
        );
        for _ in 0..100 {
            pair.record_probing(None);
        }
    }

    // Four current-generation weak pairs exercise probe count, old/new
    // observation, and None ordering. The cap is exceeded by six, so these
    // four plus the two old-generation pairs are exactly the retirees.
    let weak_none = SocketAddr::new(ip.into(), 30_010);
    let weak_old = SocketAddr::new(ip.into(), 30_011);
    let weak_recent = SocketAddr::new(ip.into(), 30_012);
    let weak_low_probe = SocketAddr::new(ip.into(), 30_013);
    conn.candidate_pairs.push(CandidatePair::new_with_source(
        weak_none,
        current_generation,
        CandidatePairSource::Birthday,
    ));
    let mut old_observation = CandidatePair::new_with_source(
        weak_old,
        current_generation,
        CandidatePairSource::Birthday,
    );
    old_observation.source_observed_at = Some(Instant::now() - Duration::from_secs(60));
    conn.candidate_pairs.push(old_observation);
    let mut recent_observation = CandidatePair::new_with_source(
        weak_recent,
        current_generation,
        CandidatePairSource::Birthday,
    );
    recent_observation.source_observed_at = Some(Instant::now() - Duration::from_secs(1));
    conn.candidate_pairs.push(recent_observation);
    let mut low_probe = CandidatePair::new_with_source(
        weak_low_probe,
        current_generation,
        CandidatePairSource::Birthday,
    );
    low_probe.record_probing(None);
    low_probe.source_observed_at = Some(Instant::now());
    conn.candidate_pairs.push(low_probe);

    let targets = conn
        .candidate_pairs
        .iter()
        .map(|pair| pair.remote_endpoint)
        .collect::<Vec<_>>();
    assert_eq!(conn.candidate_pairs.len(), MAX_CANDIDATE_PAIRS_PER_PEER + 6);
    let retired = conn.prune_candidate_pairs_outside_targets(current_generation, &targets);
    assert_eq!(retired, 6);
    assert_eq!(conn.candidate_pairs.len(), MAX_CANDIDATE_PAIRS_PER_PEER);

    for endpoint in [old_recent_high, old_recent_high_2, weak_none, weak_old, weak_recent, weak_low_probe]
    {
        assert!(
            !conn
                .candidate_pairs
                .iter()
                .any(|pair| pair.remote_endpoint == endpoint),
            "weak pair {endpoint} should be retired"
        );
    }
    for endpoint in valuable {
        let pair = conn
            .candidate_pairs
            .iter()
            .find(|pair| pair.remote_endpoint == endpoint)
            .expect("valuable current pair must survive");
        assert_eq!(pair.local_generation, current_generation);
        assert!(pair.probe_count >= 3);
    }
}

#[tokio::test]
async fn matched_ack_alone_never_promotes_direct_without_encrypted_confirmation() {
    let manager = PeerManager::new(test_config());
    let endpoint: SocketAddr = "8.8.8.8:45000".parse().unwrap();
    manager
        .add_peer(&test_peer("peer1", endpoint))
        .await;
    manager
        .add_candidates_with_sources(
            "peer1",
            &[endpoint.to_string()],
            &HashMap::from([(endpoint.to_string(), "stun_observed".to_string())]),
        )
        .await;

    // A matched authenticated ACK proves bidirectional UDP reachability but
    // must NEVER promote Direct: the encrypted data path is unconfirmed.
    manager
        .record_direct_probe_success_with_latency("peer1", endpoint, Some(Duration::from_millis(12)))
        .await;
    let conn = manager.get_connection("peer1").await.unwrap();
    assert_ne!(
        conn.state,
        ConnectionState::Direct,
        "a matched ACK alone must not promote Direct"
    );
    assert!(
        conn.candidate_pairs.iter().any(|pair| {
            pair.remote_endpoint == endpoint
                && matches!(
                    pair.state,
                    CandidatePairState::Succeeded | CandidatePairState::Probing
                )
        }),
        "the matched ACK must mark the pair reachable"
    );
    assert!(
        manager.direct_commit_seq_sync("peer1").is_none(),
        "no direct-commit sequence may exist before encrypted confirmation"
    );

    // Only the encrypted-data-path confirmation promotes Direct.
    manager
        .record_direct_success("peer1", Some(endpoint))
        .await;
    let conn = manager.get_connection("peer1").await.unwrap();
    assert_eq!(
        conn.state,
        ConnectionState::Direct,
        "encrypted data path confirmation is the only Direct gate"
    );
    assert!(
        conn.candidate_pairs.iter().any(|pair| {
            pair.remote_endpoint == endpoint && pair.state == CandidatePairState::Selected
        }),
        "the confirmed pair must be Selected"
    );
    assert!(
        manager.direct_commit_seq_sync("peer1").is_some(),
        "the encrypted confirmation must bump the direct-commit sequence"
    );
}
