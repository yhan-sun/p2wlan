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
