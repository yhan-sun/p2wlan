use super::*;
use p2pnet_nat::{TraversalReason, TraversalStrategy};

const CONTEXT_PEER: &str = "peer-traversal-context";
const CONTEXT_REMOTE_PROFILE_GENERATION: u64 = 7;

fn context_nat_profile(predictable: bool) -> NatProfile {
    let mut profile = birthday_nat_profile();
    let ports: &[u16] = if predictable {
        &[40_000, 40_004, 40_008, 40_012]
    } else {
        // The existing allocation-model tests use this high-entropy sequence.
        &[40_000, 1_000, 50_000, 2_000, 45_000]
    };
    profile.observations = ports
        .iter()
        .enumerate()
        .map(|(index, port)| p2pnet_nat::StunObservation {
            server: format!("198.51.100.{}:3478", index + 1),
            mapped_address: Some(format!("203.0.113.10:{port}")),
            rtt_ms: Some(1),
            error: None,
        })
        .collect();
    profile.prediction_candidate = predictable;
    profile.port_delta = predictable.then_some(4);
    profile.predicted_endpoints = if predictable {
        vec!["203.0.113.10:40016".to_string()]
    } else {
        Vec::new()
    };
    profile.confidence = 90;
    profile
}

async fn context_fixture(
    birthday_enabled: bool,
    predictable: bool,
    profile_endpoint: SocketAddr,
    stable_profile_endpoint: bool,
    remote_candidate: SocketAddr,
) -> PeerManager {
    let mut config = test_config();
    config.network.birthday_probing_enabled = birthday_enabled;
    let manager = PeerManager::new(config);
    let mut local_profile = context_nat_profile(predictable);
    local_profile.public_endpoint = Some(profile_endpoint.to_string());
    local_profile.public_port_stable = Some(stable_profile_endpoint);
    manager.update_nat_profile(local_profile).await;

    let mut peer = test_peer(CONTEXT_PEER, "203.0.113.20:41000".parse().unwrap());
    peer.public_key = hex::encode(NodeIdentity::generate().public_key());
    let allocation = if predictable { "linear" } else { "random" };
    let delta = if predictable { "4" } else { "?" };
    peer.nat_type = format!(
        "p2v2:m=address_or_port_dependent;a={allocation};d={delta};c=90;f=address_dependent;h=unknown;g={CONTEXT_REMOTE_PROFILE_GENERATION}"
    );
    manager.add_peer(&peer).await;
    manager
        .add_candidates(CONTEXT_PEER, &[remote_candidate.to_string()])
        .await;
    assert!(
        manager
            .bind_remote_nat_profile_to_candidate_epoch(
                CONTEXT_PEER,
                CONTEXT_REMOTE_PROFILE_GENERATION,
            )
            .await,
        "the fixture must bind the actual accepted profile to the current candidate epoch"
    );
    assert!(manager
        .get_connection(CONTEXT_PEER)
        .await
        .unwrap()
        .candidates
        .contains(&remote_candidate.to_string()));
    assert_context_baseline(&manager, predictable).await;
    manager
}

async fn assert_context_baseline(manager: &PeerManager, predictable: bool) {
    let local_profile = manager.local_nat_profile.read().await.clone().unwrap();
    let local = NatCapabilities::from_profile(&local_profile);
    let conn = manager.get_connection(CONTEXT_PEER).await.unwrap();
    let remote_profile = conn.remote_nat_profile.as_ref().unwrap();
    let remote = &remote_profile.capabilities;
    assert!(conn.online);
    assert_ne!(conn.state, ConnectionState::Direct);
    assert!(conn.remote_nat_profile_is_fresh());
    assert!(conn.remote_nat_profile_matches_candidate_epoch());
    assert_eq!(
        remote_profile.generation,
        Some(CONTEXT_REMOTE_PROFILE_GENERATION)
    );
    assert!(local.is_hard_nat() && remote.is_hard_nat());
    assert!(local.birthday_candidate && remote.birthday_candidate);
    assert_eq!(local.hard_allocation_is_predictable(), predictable);
    assert_eq!(remote.hard_allocation_is_predictable(), predictable);
    if !predictable {
        assert!(local.hard_allocation_is_unpredictable());
        assert!(remote.hard_allocation_is_unpredictable());
    }
    assert!(!conn.candidates.is_empty());
    for candidate in &conn.candidates {
        let endpoint: SocketAddr = candidate.parse().unwrap();
        assert!(is_public_probe_endpoint(endpoint));
        assert!(!conn.is_on_link_host_candidate(endpoint));
    }
    assert!(!conn.candidate_pairs.iter().any(|pair| {
        matches!(
            pair.source,
            CandidatePairSource::PeerReflexive | CandidatePairSource::Learned
        ) && matches!(
            pair.state,
            CandidatePairState::Succeeded | CandidatePairState::Selected
        )
    }));
    assert_no_context_owner(manager).await;
}

async fn assert_no_context_owner(manager: &PeerManager) {
    assert!(manager.hard_hard_sessions.lock().await.is_empty());
    assert!(manager.hard_hard_winners.lock().await.is_empty());
}

async fn context_diagnostics(
    manager: &PeerManager,
    display_endpoint: Option<SocketAddr>,
) -> [PeerDiagnostics; 3] {
    let mut plain = manager.diagnostics().await;
    assert_eq!(plain.len(), 1, "a missing diagnostics peer cannot pass");
    let mut selected = manager
        .diagnostics_with_path_selection(true, false, Duration::from_secs(5), display_endpoint)
        .await;
    assert_eq!(selected.len(), 1);
    let (generation, scoped) = manager
        .diagnostic_with_path_selection(
            CONTEXT_PEER,
            true,
            false,
            Duration::from_secs(5),
            display_endpoint,
        )
        .await
        .unwrap();
    assert_eq!(generation, manager.current_network_generation_sync());
    let diagnostics = [plain.pop().unwrap(), selected.pop().unwrap(), scoped];
    for diagnostic in &diagnostics {
        assert_eq!(diagnostic.node_id, CONTEXT_PEER);
        assert_eq!(
            diagnostic.remote_nat_profile_generation,
            Some(CONTEXT_REMOTE_PROFILE_GENERATION)
        );
    }
    assert_no_context_owner(manager).await;
    diagnostics
}

fn assert_context_plan(
    diagnostics: &[PeerDiagnostics; 3],
    strategy: TraversalStrategy,
    reason: TraversalReason,
    profile_usable: bool,
) {
    for (entry, diagnostic) in diagnostics.iter().enumerate() {
        let plan = diagnostic.traversal_plan.as_ref().unwrap();
        assert_eq!(plan.strategy, strategy, "diagnostics entry {entry}");
        assert_eq!(plan.reason_code, reason, "diagnostics entry {entry}");
        assert_eq!(plan.remote_profile_fresh, profile_usable);
    }
}

async fn assert_current_context_runtime_plan(manager: &PeerManager) {
    let snapshot = manager
        .hard_hard_plan_for_peer(CONTEXT_PEER)
        .await
        .expect("the complete current fixture must allow the runtime HH plan");
    let conn = manager.get_connection(CONTEXT_PEER).await.unwrap();
    assert_eq!(
        snapshot.local_network_generation,
        manager.current_network_generation_sync()
    );
    assert_eq!(
        snapshot.local_profile_generation,
        manager.current_local_profile_generation_sync()
    );
    assert_eq!(
        snapshot.remote_candidate_epoch,
        conn.remote_candidate_epoch()
    );
    assert_eq!(
        snapshot.remote_profile_generation,
        CONTEXT_REMOTE_PROFILE_GENERATION
    );
    assert_no_context_owner(manager).await;
}

#[tokio::test]
async fn traversal_diagnostics_birthday_disabled_matches_runtime_context() {
    let manager = context_fixture(
        false,
        false,
        "203.0.113.10:40007".parse().unwrap(),
        false,
        "203.0.113.20:41000".parse().unwrap(),
    )
    .await;
    assert!(manager
        .hard_hard_plan_for_peer(CONTEXT_PEER)
        .await
        .is_none());
    let diagnostics = context_diagnostics(&manager, None).await;
    for diagnostic in &diagnostics {
        assert!(diagnostic.remote_nat_profile_fresh);
    }
    assert_context_plan(
        &diagnostics,
        TraversalStrategy::RelayWithBackgroundReclaim,
        TraversalReason::BothUnpredictableHardNat,
        true,
    );
}

#[tokio::test]
async fn traversal_diagnostics_epoch_mismatch_marks_profile_unusable() {
    let manager = context_fixture(
        true,
        false,
        "203.0.113.10:40007".parse().unwrap(),
        false,
        "203.0.113.20:41000".parse().unwrap(),
    )
    .await;
    assert_current_context_runtime_plan(&manager).await;
    let before = manager.get_connection(CONTEXT_PEER).await.unwrap();
    let profile_before = before.remote_nat_profile.clone().unwrap();
    let peer_session = manager.peer_session_generation_sync(CONTEXT_PEER).unwrap();
    {
        let mut connections = manager.connections.write().await;
        let conn = connections.get_mut(CONTEXT_PEER).unwrap();
        let next_epoch = conn.mark_remote_transport_handover(
            manager.current_network_generation_sync(),
            peer_session,
            "test candidate context replacement",
        );
        assert_ne!(next_epoch, before.remote_candidate_epoch());
    }
    let after = manager.get_connection(CONTEXT_PEER).await.unwrap();
    assert!(after.online);
    assert_ne!(after.state, ConnectionState::Direct);
    assert_eq!(after.remote_nat_profile.as_ref().unwrap(), &profile_before);
    assert!(after.remote_nat_profile_is_fresh());
    assert!(!after.remote_nat_profile_matches_candidate_epoch());
    assert!(manager
        .hard_hard_plan_for_peer(CONTEXT_PEER)
        .await
        .is_none());
    let diagnostics = context_diagnostics(&manager, None).await;
    for diagnostic in &diagnostics {
        // Observation age is independent of eligibility in the current epoch.
        assert!(diagnostic.remote_nat_profile_fresh);
        assert_eq!(
            diagnostic.remote_candidate_epoch,
            after.remote_candidate_epoch()
        );
    }
    assert_context_plan(
        &diagnostics,
        TraversalStrategy::StandardUdpPunch,
        TraversalReason::UnknownRemoteProfile,
        false,
    );
}

#[tokio::test]
async fn traversal_diagnostics_ipv6_uses_local_profile_endpoint() {
    // Documentation-prefix addresses exercise the existing address-scope
    // predicate; this fixture does not claim measured IPv6 reachability.
    let ipv6: SocketAddr = "[2001:db8::10]:40007".parse().unwrap();
    let remote: SocketAddr = "[2001:db8::20]:41000".parse().unwrap();
    let manager = context_fixture(true, false, ipv6, true, remote).await;
    let profile = manager.local_nat_profile.read().await.clone().unwrap();
    assert_eq!(
        NatCapabilities::from_profile(&profile).stable_public_endpoint,
        Some(ipv6.to_string()),
        "the fixture must exercise the runtime's actual capability endpoint"
    );
    assert!(manager
        .hard_hard_plan_for_peer(CONTEXT_PEER)
        .await
        .is_none());

    // Before the expected red assertion, prove that the converse profile
    // source permits HH even with a public IPv6 remote candidate.
    let inverse = context_fixture(
        true,
        false,
        "203.0.113.10:40007".parse().unwrap(),
        true,
        remote,
    )
    .await;
    assert_current_context_runtime_plan(&inverse).await;

    let diagnostics = context_diagnostics(&manager, Some("127.0.0.1:60207".parse().unwrap())).await;
    assert_context_plan(
        &diagnostics,
        TraversalStrategy::Ipv6Direct,
        TraversalReason::GlobalIpv6Evidence,
        true,
    );
    // A displayed IPv6 socket cannot manufacture IPv6 planning evidence when
    // the measured capability endpoint is IPv4. Executed after the first
    // red assertion only once the production input mismatch is repaired.
    let inverse_diagnostics = context_diagnostics(&inverse, Some(ipv6)).await;
    assert_context_plan(
        &inverse_diagnostics,
        TraversalStrategy::HardHardSynchronizedCandidate,
        TraversalReason::HardHardBoundedBirthday,
        true,
    );
}

#[tokio::test]
async fn traversal_context_normal_birthday_keeps_runtime_candidate() {
    let manager = context_fixture(
        true,
        false,
        "203.0.113.10:40007".parse().unwrap(),
        false,
        "203.0.113.20:41000".parse().unwrap(),
    )
    .await;
    assert_current_context_runtime_plan(&manager).await;
    let diagnostics = context_diagnostics(&manager, None).await;
    assert_context_plan(
        &diagnostics,
        TraversalStrategy::HardHardSynchronizedCandidate,
        TraversalReason::HardHardBoundedBirthday,
        true,
    );
    assert_context_baseline(&manager, false).await;
}

#[tokio::test]
async fn traversal_context_predictable_ignores_birthday_disable() {
    for birthday_enabled in [false, true] {
        let manager = context_fixture(
            birthday_enabled,
            true,
            "203.0.113.10:40007".parse().unwrap(),
            false,
            "203.0.113.20:41000".parse().unwrap(),
        )
        .await;
        assert_current_context_runtime_plan(&manager).await;
        let diagnostics = context_diagnostics(&manager, None).await;
        assert_context_plan(
            &diagnostics,
            TraversalStrategy::HardHardSynchronizedCandidate,
            TraversalReason::BothPredictableHardNat,
            true,
        );
        assert_context_baseline(&manager, true).await;
    }
}
