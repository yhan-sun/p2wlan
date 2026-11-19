async fn gather_fence_transport() -> (Arc<PeerManager>, UdpTransport) {
    let mut config = Config::generate_default("https://control.example.com", "gather-fence")
        .expect("test configuration");
    config.network.gather_host_candidates = false;
    let peers = Arc::new(PeerManager::new(config));
    let udp = UdpTransport::bind("127.0.0.1:0".parse().unwrap(), peers.clone())
        .await
        .unwrap();
    udp.set_inbound_publication_owner(1);
    (peers, udp)
}

#[tokio::test]
async fn completed_old_discovery_cannot_replace_a_newer_same_generation_snapshot() {
    let (peers, udp) = gather_fence_transport().await;
    let snapshots = Arc::new(RwLock::new(None));
    let refresh_lock = Mutex::new(());
    let guard = refresh_lock.lock().await;
    publish_candidate_snapshot_to_store(&snapshots, Vec::new(), HashMap::new(), Vec::new()).await;
    let fence = CandidateGatherFence::capture(&guard, &udp, &peers, &snapshots).await;
    let old_report = p2pnet_nat::candidate_report_from_observations(
        udp.local_addr().unwrap(),
        false,
        Vec::new(),
    );
    drop(guard);

    // The older STUN result is complete, but its concurrent gateway discovery
    // has not returned. A fast maintenance gather commits restored reachability
    // during this unlocked interval without changing the network generation.
    let current_report = p2pnet_nat::candidate_report_from_observations(
        udp.local_addr().unwrap(),
        false,
        vec![p2pnet_nat::StunObservation {
            failure_kind: None,
            server: "192.0.2.1:3478".into(),
            mapped_address: Some("198.51.100.1:40000".into()),
            rtt_ms: Some(10),
            error: None,
        }],
    );
    let guard = refresh_lock.lock().await;
    peers.update_nat_profile(current_report.nat_profile).await;
    let endpoint = "198.51.100.1:40000".to_string();
    publish_candidate_snapshot_to_store(
        &snapshots,
        vec![endpoint.clone()],
        HashMap::from([(endpoint.clone(), "stun_observed".into())]),
        vec!["public-ip:198.51.100.1".into()],
    )
    .await;
    let accepted_version = snapshots.read().await.as_ref().unwrap().version;
    let accepted_profile = peers.current_local_profile_generation_sync();
    drop(guard);

    let guard = refresh_lock.lock().await;
    let rejection = fence.stale_reason(&guard, &udp, &peers, &snapshots).await;
    // This is the production commit gate: rejecting a result must precede its
    // profile update as well as the candidate/scheduling-policy publication.
    if rejection.is_none() {
        peers.update_nat_profile(old_report.nat_profile).await;
        publish_candidate_snapshot_to_store(&snapshots, Vec::new(), HashMap::new(), Vec::new())
            .await;
    }
    assert_eq!(rejection, Some("candidate_snapshot_replaced"));
    assert_eq!(
        peers.current_network_generation_sync(),
        fence.network_generation
    );
    assert_eq!(
        peers.current_local_profile_generation_sync(),
        accepted_profile
    );
    let accepted = snapshots.read().await;
    let accepted = accepted.as_ref().unwrap();
    assert_eq!(accepted.version, accepted_version);
    assert_eq!(accepted.candidates, vec![endpoint]);
}

#[tokio::test]
async fn discovery_rejects_generation_and_publication_changes_without_a_snapshot_change() {
    let (peers, udp) = gather_fence_transport().await;
    let snapshots = Arc::new(RwLock::new(None));
    let refresh_lock = Mutex::new(());
    let guard = refresh_lock.lock().await;
    let fence = CandidateGatherFence::capture(&guard, &udp, &peers, &snapshots).await;
    assert_eq!(
        fence.stale_reason(&guard, &udp, &peers, &snapshots).await,
        None
    );
    drop(guard);
    peers
        .advance_network_generation("test discovery handover")
        .await;
    let guard = refresh_lock.lock().await;
    assert_eq!(
        fence.stale_reason(&guard, &udp, &peers, &snapshots).await,
        Some("network_generation_changed")
    );
    let fence = CandidateGatherFence::capture(&guard, &udp, &peers, &snapshots).await;
    drop(guard);
    assert!(udp.clear_inbound_publication_owner_if_matches(1));
    let guard = refresh_lock.lock().await;
    assert_eq!(
        fence.stale_reason(&guard, &udp, &peers, &snapshots).await,
        Some("udp_transport_replaced")
    );
}

#[tokio::test]
async fn uncommitted_full_discovery_does_not_disable_an_active_socket_pool() {
    let (_, udp) = gather_fence_transport().await;
    let udp = udp.with_socket_pool(2).await.unwrap();
    udp.set_socket_pool_active(true);
    // No observers and host gathering disabled: this creates an Unknown
    // profile without any network request. Unknown cannot activate the pool,
    // but missing observations are not evidence that UDP is blocked.
    let report = udp
        .gather_candidate_report_live_parallel_full(Vec::new(), Duration::ZERO)
        .await
        .unwrap();
    assert!(report.nat_profile.observations.is_empty());
    assert_eq!(
        report.nat_profile.mapping_behavior,
        p2pnet_nat::MappingBehavior::Unknown
    );
    assert!(!report.nat_profile.udp_blocked);
    assert!(
        udp.socket_pool_active(),
        "uncommitted reports have no pool policy effect"
    );
    udp.apply_candidate_report_socket_pool_policy(&report);
    assert!(
        !udp.socket_pool_active(),
        "accepted reports still apply the policy"
    );
}
