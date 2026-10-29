use super::*;

fn mapping(generation: u64, punch_generation: u64) -> crate::peer::LocalFreshMapping {
    crate::peer::LocalFreshMapping {
        punch_generation,
        network_generation: generation,
        socket_local_endpoint: "127.0.0.1:40000".parse().unwrap(),
        socket_index: 1,
        model: p2pnet_nat::mapping::build_model(&[40000, 40001, 40002], None, 0),
        predicted_ports: vec![40003],
        public_ip: None,
        created_at: Instant::now(),
    }
}

#[tokio::test]
async fn fresh_metadata_rechecks_original_owner_after_writer_wait() {
    let daemon =
        crate::Daemon::new(crate::Config::generate_default("https://ctrl.test", "net1").unwrap());
    let udp = UdpTransport::bind("127.0.0.1:0".parse().unwrap(), daemon.peers.clone())
        .await
        .unwrap();
    let lease = daemon.udp_transport_publication.publish(udp.clone()).await;
    let generation = daemon.peers.current_network_generation_sync();
    let udp = udp.with_probe_publication_identity(lease.owner().0, generation);
    assert!(
        udp.commit_fresh_mapping_for_publication("peer", mapping(generation, 1), None)
            .await
    );
    let writer = daemon.peers.lock_fresh_mapping_for_commit().await;
    let mut commit =
        Box::pin(udp.commit_fresh_mapping_for_publication("peer", mapping(generation, 2), None));
    assert!(futures_util::poll!(commit.as_mut()).is_pending());
    daemon.udp_transport_publication.clear_current().await;
    let replacement = UdpTransport::bind("127.0.0.1:0".parse().unwrap(), daemon.peers.clone())
        .await
        .unwrap();
    let replacement_lease = daemon
        .udp_transport_publication
        .publish(replacement.clone())
        .await;
    assert_eq!(daemon.peers.current_network_generation_sync(), generation);
    drop(writer);
    assert!(
        !commit.await,
        "owner-only replacement cannot publish late metadata"
    );
    assert_eq!(
        daemon
            .peers
            .fresh_mapping_for_peer("peer")
            .await
            .unwrap()
            .punch_generation,
        1
    );
    let replacement =
        replacement.with_probe_publication_identity(replacement_lease.owner().0, generation);
    assert!(
        replacement
            .commit_fresh_mapping_for_publication("peer", mapping(generation, 3), None)
            .await
    );
    assert_eq!(
        daemon
            .peers
            .fresh_mapping_for_peer("peer")
            .await
            .unwrap()
            .punch_generation,
        3
    );
    daemon.udp_transport_publication.clear_current().await;
}

#[tokio::test]
async fn fresh_metadata_writer_wait_cannot_cross_network_epoch_advance() {
    let daemon =
        crate::Daemon::new(crate::Config::generate_default("https://ctrl.test", "net1").unwrap());
    let udp = UdpTransport::bind("127.0.0.1:0".parse().unwrap(), daemon.peers.clone())
        .await
        .unwrap();
    let lease = daemon.udp_transport_publication.publish(udp.clone()).await;
    let generation = daemon.peers.current_network_generation_sync();
    let udp = udp.with_probe_publication_identity(lease.owner().0, generation);
    let writer = daemon.peers.lock_fresh_mapping_for_commit().await;
    let mut commit =
        Box::pin(udp.commit_fresh_mapping_for_publication("peer", mapping(generation, 1), None));
    assert!(futures_util::poll!(commit.as_mut()).is_pending());
    // Advancing the epoch waits for the same metadata writer to invalidate
    // old mappings. The commit must fail closed instead of deadlocking on it.
    let mut advance = Box::pin(daemon.peers.advance_network_generation("metadata handover"));
    assert!(futures_util::poll!(advance.as_mut()).is_pending());
    assert_ne!(daemon.peers.current_network_generation_sync(), generation);
    drop(writer);
    let (committed, _) = tokio::join!(commit, advance);
    assert!(!committed);
    assert!(daemon.peers.fresh_mapping_for_peer("peer").await.is_none());
    daemon.udp_transport_publication.clear_current().await;
}

#[tokio::test(start_paused = true)]
async fn fresh_metadata_writer_wait_is_bounded_and_session_cancelled_commit_is_rejected() {
    let daemon =
        crate::Daemon::new(crate::Config::generate_default("https://ctrl.test", "net1").unwrap());
    let udp = UdpTransport::bind("127.0.0.1:0".parse().unwrap(), daemon.peers.clone())
        .await
        .unwrap();
    let lease = daemon.udp_transport_publication.publish(udp.clone()).await;
    let udp = udp.with_probe_publication_identity(lease.owner().0, 0);
    let writer = daemon.peers.lock_fresh_mapping_for_commit().await;
    let mut commit =
        Box::pin(udp.commit_fresh_mapping_for_publication("peer", mapping(0, 1), None));
    assert!(futures_util::poll!(commit.as_mut()).is_pending());
    tokio::time::advance(Duration::from_millis(100)).await;
    assert!(!commit.await);
    drop(writer);
    let cancellation = Arc::new(crate::PunchSessionCancellation::default());
    cancellation.cancel();
    assert!(
        !udp.commit_fresh_mapping_for_publication("peer", mapping(0, 2), Some(&cancellation))
            .await
    );
    assert!(daemon.peers.fresh_mapping_for_peer("peer").await.is_none());
    daemon.udp_transport_publication.clear_current().await;
}
