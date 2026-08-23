
fn flood_peer(node_id: &str, virtual_ip: &str, endpoint: SocketAddr) -> PeerInfo {
    PeerInfo {
        node_id: node_id.to_string(),
        device_name: String::new(),
        app_version: String::new(),
        public_key: "pk-flood".to_string(),
        endpoint: endpoint.to_string(),
        nat_type: "AddressOrPortDependent".to_string(),
        virtual_ip: virtual_ip.to_string(),
        online: true,
        last_seen: 0,
        relay_rtt_ms: None,
    }
}

async fn direct_events_for(manager: &PeerManager, node_id: &str) -> usize {
    manager
        .diagnostics()
        .await
        .iter()
        .find(|diagnostics| diagnostics.node_id == node_id)
        .map(|diagnostics| diagnostics.direct_events.len())
        .unwrap_or(0)
}

#[tokio::test]
async fn direct_failure_notifies_automatic_recovery_hook() {
    let manager = PeerManager::new(test_config());
    manager
        .add_peer(&flood_peer(
            "peer-recover-hook",
            "10.20.0.8",
            "203.0.113.8:5008".parse().unwrap(),
        ))
        .await;

    let calls = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let calls_for_hook = calls.clone();
    manager.set_direct_recovery_kick_hook(std::sync::Arc::new(move |peer_id| {
        assert_eq!(peer_id, "peer-recover-hook");
        calls_for_hook.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    }));

    let generation = manager.current_network_generation().await;
    assert!(manager
        .record_direct_failure_for_generation(
            "peer-recover-hook",
            generation,
            REASON_DIRECT_PROBE_FAILED,
            "no matched direct probe ACK",
        )
        .await);
    assert_eq!(
        calls.load(std::sync::atomic::Ordering::SeqCst),
        1,
        "a live peer's first direct failure must trigger the nonblocking recovery hook"
    );
    assert_eq!(
        manager
            .get_connection("peer-recover-hook")
            .await
            .unwrap()
            .state,
        ConnectionState::FallbackToRelay
    );
}

#[tokio::test]
async fn unrelated_failed_peer_cannot_flood_or_disturb_healthy_direct_peer() {
    let manager = PeerManager::new(test_config());
    manager
        .add_peer(&flood_peer("peer-direct", "10.20.0.2", "1.2.3.4:5000".parse().unwrap()))
        .await;
    manager
        .add_peer(&flood_peer("peer-fail", "10.20.0.3", "5.6.7.8:5001".parse().unwrap()))
        .await;
    manager
        .update_state("peer-direct", ConnectionState::Direct)
        .await;
    let generation = manager.current_network_generation().await;
    let direct_events_before = direct_events_for(&manager, "peer-direct").await;

    // The failing peer repeatedly reports probe-batch failures and refreshes
    // its candidates (add_peer with a new endpoint), like a peer whose NAT
    // port keeps moving.
    for _ in 0..4 {
        manager
            .record_direct_probe_batch_failure_for_generation(
                "peer-fail",
                generation,
                "no ACK after background UDP retry probes",
            )
            .await;
        manager
            .add_peer(&flood_peer(
                "peer-fail",
                "10.20.0.3",
                "5.6.7.8:5001".parse().unwrap(),
            ))
            .await;
    }

    // The healthy Direct peer is untouched by the failing peer's churn:
    assert!(manager.is_direct("peer-direct").await, "Direct state survives");
    assert_eq!(
        manager.current_network_generation().await,
        generation,
        "a failing peer's refresh churn must never advance the network generation"
    );
    assert_eq!(
        direct_events_for(&manager, "peer-direct").await,
        direct_events_before,
        "a failing peer's churn must not add a single traversal event to the healthy Direct peer"
    );
    // The Direct peer is never re-scanned because an unrelated peer fails:
    let targets = manager.direct_probe_targets_due(Duration::from_secs(1)).await;
    assert!(
        targets.iter().all(|target| target.peer_id == "peer-fail"),
        "only the failing peer may have retry targets, got {:?}",
        targets
            .iter()
            .map(|target| target.peer_id.as_str())
            .collect::<Vec<_>>()
    );
    assert!(
        manager.is_direct_sync("peer-direct"),
        "the synchronous Direct mirror must still contain the healthy peer"
    );
    assert!(
        !manager.is_direct_sync("peer-fail"),
        "the failing peer must never appear as Direct"
    );
    let peer_direct_diag = {
        let diagnostics = manager.diagnostics().await;
        diagnostics
            .iter()
            .find(|diagnostics| diagnostics.node_id == "peer-direct")
            .cloned()
            .expect("healthy peer present")
    };
    assert_eq!(
        peer_direct_diag.direct.consecutive_failures, 0,
        "the failing peer's failures must never leak into the healthy peer's health"
    );

    // The failing peer itself is bounded: its failures grew the retry backoff
    // (not due right after the failures), and the newly arrived candidate did
    // NOT reset that backoff.
    assert!(
        !manager.direct_retry_due("peer-fail", Duration::from_secs(2)).await,
        "a failing peer must back off after consecutive failures even when new candidates arrive"
    );
}

#[tokio::test]
async fn non_direct_peer_has_bounded_recovery() {
    let manager = PeerManager::new(test_config());
    manager
        .add_peer(&flood_peer("peer-recover", "10.20.0.4", "9.9.9.9:7000".parse().unwrap()))
        .await;
    let generation = manager.current_network_generation().await;

    // The non-Direct peer still gets retry targets while its backoff allows.
    let targets = manager.direct_probe_targets_due(Duration::from_millis(100)).await;
    assert_eq!(targets.len(), 1, "the non-Direct peer must still recover");
    assert_eq!(targets[0].peer_id, "peer-recover");

    // Consecutive failures grow the backoff: with four failures and a 1s
    // base, the peer is not due until ~8s have passed.
    for _ in 0..4 {
        manager
            .record_direct_probe_batch_failure_for_generation(
                "peer-recover",
                generation,
                "no matched direct probe ACK",
            )
            .await;
    }
    assert!(
        !manager.direct_retry_due("peer-recover", Duration::from_secs(1)).await,
        "repeated failures must extend the retry backoff"
    );
    // Recovery is not suppressed forever: the backoff is bounded (max
    // exponent), so the peer stays eligible once the window elapses, and it
    // is never closed by failures.
    assert!(
        manager.is_direct_validation_eligible("peer-recover").await,
        "a failing non-Direct peer must stay eligible for recovery"
    );
    let diagnostics = manager.diagnostics().await;
    let recover = diagnostics
        .iter()
        .find(|diagnostics| diagnostics.node_id == "peer-recover")
        .expect("peer still present");
    assert!(
        recover.state != ConnectionState::Closed,
        "probe failures must not close the connection"
    );
}

#[test]
fn direct_retry_backoff_grows_exponentially_and_is_bounded() {
    let mut health = PathHealth::default();
    let base = Duration::from_secs(1);
    assert_eq!(health.retry_after(base), base);
    health.record_failure("probe_failed", "no ACK");
    assert_eq!(health.retry_after(base), base, "first failure keeps the base");
    health.record_failure("probe_failed", "no ACK");
    assert_eq!(health.retry_after(base), Duration::from_secs(2));
    health.record_failure("probe_failed", "no ACK");
    assert_eq!(health.retry_after(base), Duration::from_secs(4));
    // The exponent is capped: a very long failure streak must not produce an
    // unbounded wait (DIRECT_RETRY_BACKOFF_MAX_EXPONENT).
    for _ in 0..64 {
        health.record_failure("probe_failed", "no ACK");
    }
    let bounded = health.retry_after(base);
    assert!(
        bounded <= Duration::from_secs(1u64 << DIRECT_RETRY_BACKOFF_MAX_EXPONENT.min(30)),
        "the retry backoff must be bounded, got {bounded:?}"
    );
    assert!(bounded > Duration::from_secs(4));
    // Success resets the streak so recovery is not permanently suppressed.
    health.record_success();
    assert_eq!(health.retry_after(base), base);
}
