// ============================================================
// v0.1.119: outbound-UDP liveness decision — TTL/generation cache
// ============================================================
//
// These drive the `outbound_liveness_cache` directly (no real sockets) via
// the `test_seed_liveness` helper, covering: fresh verdict → no re-probe +
// readable verdict; expired verdict → re-probe due + not readable; and
// generation change → fresh (peer, generation) key.

use p2pnet_nat::outbound_liveness::LivenessVerdict;

#[tokio::test]
async fn liveness_ttl_cache_hit_does_not_reprobe() {
    let manager = PeerManager::new(test_config());
    let gen = manager.current_network_generation().await;
    // Fresh verdict (age 0) → probe is NOT due; evaluate returns the verdict.
    manager
        .test_seed_liveness("peer-l", gen, LivenessVerdict::Blocked, 0)
        .await;
    assert!(
        !manager.liveness_probe_due("peer-l", gen).await,
        "fresh verdict within TTL must not re-probe"
    );
    assert_eq!(
        manager.evaluate_outbound_liveness("peer-l", gen).await,
        Some(LivenessVerdict::Blocked)
    );
}

#[tokio::test]
async fn liveness_ttl_expiry_reprobes() {
    let manager = PeerManager::new(test_config());
    let gen = manager.current_network_generation().await;
    let ttl_ms = manager.config.network.udp_liveness_ttl_ms; // 30000 by default
    // Verdict aged past the TTL → probe IS due; evaluate returns None (expired).
    manager
        .test_seed_liveness("peer-l", gen, LivenessVerdict::Blocked, ttl_ms as u64 + 1000)
        .await;
    assert!(
        manager.liveness_probe_due("peer-l", gen).await,
        "expired verdict must trigger a re-probe"
    );
    assert_eq!(
        manager.evaluate_outbound_liveness("peer-l", gen).await,
        None,
        "expired verdict is not a usable cached verdict"
    );
}

#[tokio::test]
async fn liveness_generation_change_invalidates_cache() {
    let manager = PeerManager::new(test_config());
    let gen = manager.current_network_generation().await;
    // A fresh verdict for generation N exists, but generation N+1 has none —
    // the key is (peer, generation), so a new generation is a brand-new lookup.
    manager
        .test_seed_liveness("peer-l", gen, LivenessVerdict::Blocked, 0)
        .await;
    let next_gen = gen + 1;
    assert!(
        manager.liveness_probe_due("peer-l", next_gen).await,
        "a different generation is a fresh key and must re-probe"
    );
    assert_eq!(
        manager.evaluate_outbound_liveness("peer-l", next_gen).await,
        None
    );
}

#[tokio::test]
async fn liveness_blocked_applied_exactly_once_at_admit() {
    let manager = PeerManager::new(test_config());
    let endpoint: SocketAddr = "1.2.3.4:51850".parse().unwrap();
    manager.add_peer(&flood_peer_112("peer-fw", "10.20.0.3", endpoint)).await;
    let gen = manager.current_network_generation().await;

    // Seed a fresh Blocked verdict BEFORE any admit (no epoch yet).
    manager
        .test_seed_liveness("peer-fw", gen, LivenessVerdict::Blocked, 0)
        .await;

    // First admit: epoch does not exist yet → the guard returns early and does
    // NOT consume.  The epoch is created at Initial afterwards.
    let _ = manager.recovery_epoch_admit("peer-fw").await;
    assert_eq!(
        manager.recovery_stage_for("peer-fw").await,
        RecoveryStage::Initial,
        "first admit must not apply a Blocked verdict before the epoch exists"
    );
    assert_eq!(manager.direct_liveness_event_count("peer-fw").await, 0);

    // Second admit: epoch now exists → consume → stage to RelayBackoff +
    // firewall_blocked reason + one applied event.
    let _ = manager.recovery_epoch_admit("peer-fw").await;
    assert_eq!(
        manager.recovery_stage_for("peer-fw").await,
        RecoveryStage::RelayBackoff,
        "Blocked consumption must move recovery into the bounded relay-backoff regime"
    );
    assert_eq!(
        manager.direct_health_error_code("peer-fw").await.as_deref(),
        Some("firewall_blocked"),
        "the accurate firewall attribution must be stamped"
    );
    assert_eq!(
        manager.direct_liveness_event_count("peer-fw").await,
        1,
        "applied exactly once"
    );

    // Third admit: consumed → no-op; still exactly one event.
    let _ = manager.recovery_epoch_admit("peer-fw").await;
    assert_eq!(manager.direct_liveness_event_count("peer-fw").await, 1);
}

#[tokio::test]
async fn liveness_ok_verdict_is_recorded_but_never_applied() {
    let manager = PeerManager::new(test_config());
    let endpoint: SocketAddr = "1.2.3.4:51850".parse().unwrap();
    manager.add_peer(&flood_peer_112("peer-ok", "10.20.0.3", endpoint)).await;
    let gen = manager.current_network_generation().await;

    // Establish the epoch, then seed an Ok verdict (not Blocked).
    let _ = manager.recovery_epoch_admit("peer-ok").await;
    manager
        .test_seed_liveness("peer-ok", gen, LivenessVerdict::Ok, 0)
        .await;

    let _ = manager.recovery_epoch_admit("peer-ok").await;
    assert_eq!(
        manager.direct_liveness_event_count("peer-ok").await,
        0,
        "an Ok verdict must never be applied as a firewall block"
    );
    assert_ne!(
        manager.direct_health_error_code("peer-ok").await.as_deref(),
        Some("firewall_blocked"),
        "Ok must not stamp firewall_blocked"
    );
    assert_ne!(
        manager.recovery_stage_for("peer-ok").await,
        RecoveryStage::RelayBackoff,
        "Ok must not force the stage into relay-backoff"
    );
}
