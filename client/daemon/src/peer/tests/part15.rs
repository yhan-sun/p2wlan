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

#[tokio::test]
async fn liveness_pre_flight_off_never_blocks() {
    let manager = PeerManager::new(test_config()); // pre_flight defaults false
    let endpoint: SocketAddr = "1.2.3.4:51850".parse().unwrap();
    manager.add_peer(&flood_peer_112("peer-pf", "10.20.0.3", endpoint)).await;
    let gen = manager.current_network_generation().await;
    // Even with a fresh Blocked verdict, default-OFF pre-flight never skips.
    manager
        .test_seed_liveness("peer-pf", gen, LivenessVerdict::Blocked, 0)
        .await;
    assert!(
        !manager.pre_flight_liveness_blocked("peer-pf", gen).await,
        "default-OFF pre-flight must never skip a punch"
    );
}

#[tokio::test]
async fn liveness_pre_flight_on_blocks_only_on_fresh_blocked() {
    let mut config = test_config();
    config.network.udp_liveness_pre_flight = true;
    let ttl_ms = config.network.udp_liveness_ttl_ms as u64;
    let manager = PeerManager::new(config);
    let endpoint: SocketAddr = "1.2.3.4:51850".parse().unwrap();
    manager.add_peer(&flood_peer_112("peer-pf2", "10.20.0.3", endpoint)).await;
    let gen = manager.current_network_generation().await;

    // No cache → false (read-only: proceed with punch, do NOT spawn).
    assert!(!manager.pre_flight_liveness_blocked("peer-pf2", gen).await);

    // Fresh Ok → false (reachable, don't skip).
    manager.test_seed_liveness("peer-pf2", gen, LivenessVerdict::Ok, 0).await;
    assert!(!manager.pre_flight_liveness_blocked("peer-pf2", gen).await);

    // Fresh Blocked → true (skip).
    manager
        .test_seed_liveness("peer-pf2", gen, LivenessVerdict::Blocked, 0)
        .await;
    assert!(manager.pre_flight_liveness_blocked("peer-pf2", gen).await);

    // Expired Blocked → false: the TTL self-heals a transient block instead of
    // skipping forever.
    manager
        .test_seed_liveness("peer-pf2", gen, LivenessVerdict::Blocked, ttl_ms + 1000)
        .await;
    assert!(
        !manager.pre_flight_liveness_blocked("peer-pf2", gen).await,
        "an expired Blocked must not keep skipping — the TTL self-heals"
    );
}

// ============================================================
// v0.1.119: full decision-path integration — 0-ACK transition + liveness verdict
// ============================================================

#[tokio::test]
async fn scatter_extended_0ack_blocked_overwrites_reason_and_stops_scatter() {
    let manager = PeerManager::new(test_config());
    let endpoint: SocketAddr = "1.2.3.4:51850".parse().unwrap();
    manager
        .add_peer(&flood_peer_112("peer-fw", "10.20.0.3", endpoint))
        .await;
    let gen = manager.current_network_generation().await;

    // (1) Establish the epoch and drive recovery to the wide-scan stage.
    let _ = manager.recovery_epoch_admit("peer-fw").await; // creates epoch (Initial)
    manager.advance_recovery_stage_after_no_ack("peer-fw", "no-ack-1").await;
    manager.advance_recovery_stage_after_no_ack("peer-fw", "no-ack-2").await;
    manager.advance_recovery_stage_after_no_ack("peer-fw", "no-ack-3").await;
    assert_eq!(
        manager.recovery_stage_for("peer-fw").await,
        RecoveryStage::ScatterExtended,
        "test precondition: the peer is at the wide-scan boundary"
    );

    // (2) The EXISTING 0-ACK path: relay backstop + generic (UNKNOWN) attribution.
    manager
        .record_direct_probe_batch_failure_for_generation("peer-fw", gen, "wide scan 0 ACK")
        .await;
    assert_eq!(
        manager.get_connection("peer-fw").await.unwrap().state,
        ConnectionState::FallbackToRelay,
        "relay always backstops on a 0-ACK wide scan (unchanged behavior)"
    );
    assert_eq!(
        manager.direct_health_error_code("peer-fw").await.as_deref(),
        Some("direct_probe_failed"),
        "before liveness applies, the root cause is still the generic UNKNOWN"
    );

    // (3) The liveness probe finished and cached a fresh Blocked verdict.
    manager
        .test_seed_liveness("peer-fw", gen, LivenessVerdict::Blocked, 0)
        .await;

    // (4) The NEXT admission tick consumes it (Task 7 apply).
    let _ = manager.recovery_epoch_admit("peer-fw").await;

    // (5) The feature's effect:
    assert_eq!(
        manager.direct_health_error_code("peer-fw").await.as_deref(),
        Some("firewall_blocked"),
        "Blocked must overwrite the generic reason with the accurate firewall attribution"
    );
    assert_eq!(
        manager.recovery_stage_for("peer-fw").await,
        RecoveryStage::RelayBackoff,
        "Blocked must stop the wide scatter: stage moves ScatterExtended -> RelayBackoff"
    );
    assert_eq!(
        manager.get_connection("peer-fw").await.unwrap().state,
        ConnectionState::FallbackToRelay,
        "relay backstop is preserved (never resurrected to Direct by liveness)"
    );
}

#[tokio::test]
async fn scatter_extended_0ack_ok_does_not_overwrite_or_stop_scatter() {
    let manager = PeerManager::new(test_config());
    let endpoint: SocketAddr = "1.2.3.4:51850".parse().unwrap();
    manager
        .add_peer(&flood_peer_112("peer-ok", "10.20.0.3", endpoint))
        .await;
    let gen = manager.current_network_generation().await;

    let _ = manager.recovery_epoch_admit("peer-ok").await;
    manager.advance_recovery_stage_after_no_ack("peer-ok", "n1").await;
    manager.advance_recovery_stage_after_no_ack("peer-ok", "n2").await;
    manager.advance_recovery_stage_after_no_ack("peer-ok", "n3").await;
    manager
        .record_direct_probe_batch_failure_for_generation("peer-ok", gen, "wide scan 0 ACK")
        .await;
    // Outbound UDP is reachable -> the 0-ACK is a NAT miss / C=0, NOT a firewall.
    manager.test_seed_liveness("peer-ok", gen, LivenessVerdict::Ok, 0).await;
    let _ = manager.recovery_epoch_admit("peer-ok").await;

    assert_eq!(
        manager.direct_health_error_code("peer-ok").await.as_deref(),
        Some("direct_probe_failed"),
        "Ok must NOT overwrite the generic reason (the cause is a NAT miss, not a firewall)"
    );
    assert_eq!(
        manager.recovery_stage_for("peer-ok").await,
        RecoveryStage::ScatterExtended,
        "Ok must NOT stop the scan — the peer stays at ScatterExtended to keep retrying"
    );
}

#[tokio::test]
async fn scatter_extended_0ack_unknown_does_not_overwrite_or_stop_scatter() {
    let manager = PeerManager::new(test_config());
    let endpoint: SocketAddr = "1.2.3.4:51850".parse().unwrap();
    manager
        .add_peer(&flood_peer_112("peer-unk", "10.20.0.3", endpoint))
        .await;
    let gen = manager.current_network_generation().await;

    let _ = manager.recovery_epoch_admit("peer-unk").await;
    manager.advance_recovery_stage_after_no_ack("peer-unk", "n1").await;
    manager.advance_recovery_stage_after_no_ack("peer-unk", "n2").await;
    manager.advance_recovery_stage_after_no_ack("peer-unk", "n3").await;
    manager
        .record_direct_probe_batch_failure_for_generation("peer-unk", gen, "wide scan 0 ACK")
        .await;
    // Socket/system error -> Unknown: recorded but must NOT drive a decision.
    manager
        .test_seed_liveness("peer-unk", gen, LivenessVerdict::Unknown, 0)
        .await;
    let _ = manager.recovery_epoch_admit("peer-unk").await;

    assert_eq!(
        manager.direct_health_error_code("peer-unk").await.as_deref(),
        Some("direct_probe_failed"),
        "Unknown must NOT be treated as a firewall (a socket fault says nothing about egress)"
    );
    assert_eq!(
        manager.recovery_stage_for("peer-unk").await,
        RecoveryStage::ScatterExtended,
        "Unknown must NOT stop the scan"
    );
}
