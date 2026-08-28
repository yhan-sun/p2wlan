// ============================================================
// v0.1.116: relay-404 quarantine authority + bounded wide windows
//
// Field evidence (v0.1.115 real Mini log): two control-online peers
// (v0.1.108 MacBook Air, v0.1.110 Linux) had permanently absent relay
// registrations.  Their endpoint heartbeats (every control poll) and
// `last_seen` growth un-quarantined them repeatedly ("authoritative
// endpoint/online update"), restarting punch + relay-404 + re-quarantine
// storms: 101+ relay 404s, 14 un-quarantine events and endless 512-probe
// scans, while the healthy Mini<->Air pair stayed stuck in a 77-second
// cold start.
//
// These tests pin the authority boundary:
//   - last_seen growth / endpoint churn / online transitions NEVER clear the
//     relay-404 grace or un-quarantine a stale incarnation;
//   - new registrations (new node ID), identity (public-key) changes,
//     authenticated inbound evidence and PeerLeft+rejoin DO;
//   - repeated 404s inside one quarantine episode are absorbed without new
//     failure samples or log churn;
//   - quarantined stale peers are excluded from the shared recovery
//     scheduler, so they cannot starve healthy peers;
//   - wide-window plan caps are divided by the socket count so one session
//     covers a COMPLETE window instead of truncating it mid-sweep.
// ============================================================

fn stale_peer(node_id: &str, endpoint: SocketAddr, last_seen: u64) -> PeerInfo {
    let mut peer = test_peer(node_id, endpoint);
    peer.last_seen = last_seen;
    peer
}

async fn quarantine_via_relay_404(manager: &PeerManager, node_id: &str) {
    manager
        .record_relay_failure(
            node_id,
            "peer_not_found",
            format!("peer not found: {node_id}"),
        )
        .await;
    manager
        .test_force_relay_not_found_grace_elapsed(node_id)
        .await;
    manager
        .record_relay_failure(
            node_id,
            "peer_not_found",
            format!("peer not found: {node_id}"),
        )
        .await;
    assert!(
        manager.peer_quarantined(node_id).await,
        "a confirmed relay 404 must quarantine the peer"
    );
}

#[tokio::test]
async fn quarantine_metadata_contention_cannot_publish_relay_ready() {
    let manager = PeerManager::new(test_config());
    let endpoint: SocketAddr = "220.165.178.32:9090".parse().unwrap();
    manager.add_peer(&test_peer("peer-stale", endpoint)).await;
    let generation = manager.current_network_generation().await;

    // Prove READY would normally be publishable, then quarantine must revoke
    // even this unconfirmed transport incarnation.
    manager
        .mark_relay_transport_ready_with_transport(
            "peer-stale",
            "relay.test:443",
            generation,
            Some(41),
        )
        .await;
    assert_eq!(
        manager
            .get_connection("peer-stale")
            .await
            .unwrap()
            .relay_ready_connection_id,
        Some(41)
    );
    manager
        .quarantine_peer("peer-stale", "confirmed relay peer_not_found")
        .await;

    // Simulate unrelated diagnostics/backoff work owning the async metadata
    // map.  The old try_lock-based dataplane predicate failed open here and
    // let a replacement relay transport restore READY.
    let _metadata_guard = manager.quarantined_peers.lock().await;
    assert!(manager.peer_quarantined_sync("peer-stale"));
    tokio::time::timeout(
        Duration::from_secs(1),
        manager.mark_relay_transport_ready_with_transport(
            "peer-stale",
            "relay.test:443",
            generation,
            Some(42),
        ),
    )
    .await
    .expect("relay-ready admission must not wait for quarantine metadata");

    let connection = manager.get_connection("peer-stale").await.unwrap();
    assert_eq!(connection.relay_ready_at, None);
    assert_eq!(connection.relay_ready_generation, None);
    assert_eq!(connection.relay_ready_endpoint, None);
    assert_eq!(connection.relay_ready_connection_id, None);
}

#[tokio::test]
async fn quarantine_metadata_contention_cannot_build_probe_plan() {
    let manager = PeerManager::new(test_config());
    let endpoint: SocketAddr = "220.165.178.32:9090".parse().unwrap();
    manager.add_peer(&test_peer("peer-stale", endpoint)).await;
    assert!(
        manager
            .direct_probe_target_set_for("peer-stale")
            .await
            .is_some(),
        "the control peer must be probe-eligible before quarantine"
    );
    manager
        .quarantine_peer("peer-stale", "confirmed relay peer_not_found")
        .await;

    // Holding the async metadata map used to make peer_quarantined_sync's
    // try_lock return false.  Probe planning must instead consult the
    // independent authoritative mirror and reject without blocking.
    let _metadata_guard = manager.quarantined_peers.lock().await;
    let target = tokio::time::timeout(
        Duration::from_secs(1),
        manager.direct_probe_target_set_for("peer-stale"),
    )
    .await
    .expect("probe admission must not wait for quarantine metadata");
    assert!(
        target.is_none(),
        "metadata contention must never turn an active quarantine into a probe plan"
    );
}

#[tokio::test]
async fn relay_404_quarantine_survives_last_seen_growth() {
    let manager = PeerManager::new(test_config());
    let endpoint: SocketAddr = "220.165.178.32:9090".parse().unwrap();
    manager
        .add_peer(&stale_peer("peer-stale", endpoint, 1000))
        .await;
    quarantine_via_relay_404(&manager, "peer-stale").await;

    // The stale incarnation's control-plane heartbeat advances last_seen.
    // This is NOT a new instance: the relay registration is still absent, so
    // the quarantine and its episode must survive.
    manager
        .add_peer(&stale_peer("peer-stale", endpoint, 2000))
        .await;
    assert!(
        manager.peer_quarantined("peer-stale").await,
        "last_seen growth on the same incarnation must NOT un-quarantine a relay-404 peer"
    );
    assert_eq!(
        manager.quarantine_consecutive("peer-stale").await,
        1,
        "the episode counter must not advance on heartbeat-only updates"
    );

    // A third heartbeat with an even newer last_seen: still quarantined.
    manager
        .add_peer(&stale_peer("peer-stale", endpoint, 3000))
        .await;
    assert!(
        manager.peer_quarantined("peer-stale").await,
        "repeated last_seen growth must never un-quarantine"
    );
}

#[tokio::test]
async fn relay_404_quarantine_survives_endpoint_churn() {
    let manager = PeerManager::new(test_config());
    let first: SocketAddr = "220.165.178.32:9090".parse().unwrap();
    manager
        .add_peer(&stale_peer("peer-stale", first, 1000))
        .await;
    quarantine_via_relay_404(&manager, "peer-stale").await;

    // Ordinary NAT endpoint churn (the same stale incarnation behind a
    // rotating NAT) is NOT authoritative recovery evidence: the field logs
    // showed the endpoint changing on every poll while the relay
    // registration stayed absent, and each change restarted the punch /
    // 404 / re-quarantine storm.
    let churned: SocketAddr = "220.165.178.32:9199".parse().unwrap();
    manager
        .add_peer(&stale_peer("peer-stale", churned, 1500))
        .await;
    assert!(
        manager.peer_quarantined("peer-stale").await,
        "endpoint churn must NOT un-quarantine a relay-404 peer"
    );
    assert_eq!(
        manager.quarantine_consecutive("peer-stale").await,
        1,
        "endpoint churn must not start a new quarantine episode"
    );

    // A new endpoint must not produce a punchable target set either: the
    // stale set stays frozen until authoritative evidence arrives.
    assert!(
        manager.direct_probe_targets_for("peer-stale").await.is_empty(),
        "a quarantined peer must not derive synchronized punch targets from its stale candidate set"
    );
}

#[tokio::test]
async fn relay_404_grace_survives_online_transition_and_last_seen_growth() {
    let manager = PeerManager::new(test_config());
    let endpoint: SocketAddr = "220.165.178.32:9090".parse().unwrap();
    let mut peer = stale_peer("peer-stale", endpoint, 1000);
    peer.online = false;
    manager.add_peer(&peer).await;
    // The peer comes back online (same incarnation); the first relay 404
    // opens the bounded registration-grace window.
    let mut back_online = stale_peer("peer-stale", endpoint, 1500);
    back_online.online = true;
    manager.add_peer(&back_online).await;
    manager
        .record_relay_failure("peer-stale", "peer_not_found", "peer not found: peer-stale")
        .await;
    assert!(
        manager
            .relay_not_found_grace
            .lock()
            .await
            .contains_key("peer-stale"),
        "a relay 404 on an online peer must open the registration grace window"
    );
    // A plain heartbeat (last_seen growth, no new instance) must not clear
    // the window: the old code treated any last_seen growth as fresh
    // handoff evidence and restarted the whole 404/grace/quarantine loop on
    // every control poll.
    manager
        .add_peer(&stale_peer("peer-stale", endpoint, 2000))
        .await;
    assert!(
        manager
            .relay_not_found_grace
            .lock()
            .await
            .contains_key("peer-stale"),
        "online transition + last_seen growth must not clear the relay-404 grace window"
    );
    // When the grace window expires with the registration still absent, the
    // peer is quarantined exactly once (episode 1).
    manager
        .test_force_relay_not_found_grace_elapsed("peer-stale")
        .await;
    manager
        .record_relay_failure("peer-stale", "peer_not_found", "peer not found: peer-stale")
        .await;
    assert!(manager.peer_quarantined("peer-stale").await);
    assert_eq!(manager.quarantine_consecutive("peer-stale").await, 1);
}

#[tokio::test]
async fn identity_change_and_authenticated_evidence_reopen_quarantine() {
    let manager = PeerManager::new(test_config());
    let endpoint: SocketAddr = "220.165.178.32:9090".parse().unwrap();
    manager
        .add_peer(&stale_peer("peer-stale", endpoint, 1000))
        .await;
    quarantine_via_relay_404(&manager, "peer-stale").await;

    // Identity change (public-key rotation / reinstall): authoritative.
    let mut rotated = stale_peer("peer-stale", endpoint, 2000);
    rotated.public_key = "new-rotated-key".to_string();
    manager.add_peer(&rotated).await;
    assert!(
        !manager.peer_quarantined("peer-stale").await,
        "a public-key identity change must re-open recovery for the quarantined peer"
    );

    // Re-quarantine, then prove authenticated inbound evidence re-opens it.
    quarantine_via_relay_404(&manager, "peer-stale").await;
    assert!(manager.peer_quarantined("peer-stale").await);
    let live: SocketAddr = "220.165.178.32:7955".parse().unwrap();
    assert!(
        manager
            .learn_authenticated_endpoint("peer-stale", live)
            .await,
        "an authenticated inbound punch must be learnable"
    );
    assert!(
        !manager.peer_quarantined("peer-stale").await,
        "an authenticated inbound punch is authoritative live-path evidence and must un-quarantine"
    );
    // The learned endpoint is immediately punchable.
    let targets = manager.direct_probe_targets_for("peer-stale").await;
    assert!(
        targets.contains(&live),
        "the peer-reflexive endpoint learned from the authenticated punch must be in the target set"
    );
}

#[tokio::test]
async fn peer_left_clears_quarantine_for_clean_rejoin() {
    let manager = PeerManager::new(test_config());
    let endpoint: SocketAddr = "220.165.178.32:9090".parse().unwrap();
    manager
        .add_peer(&stale_peer("peer-stale", endpoint, 1000))
        .await;
    quarantine_via_relay_404(&manager, "peer-stale").await;

    // PeerLeft: the incarnation is gone; the new incarnation (new node ID)
    // must not inherit the dead incarnation's isolation.
    manager.remove_peer("peer-stale").await;
    assert!(
        !manager.peer_quarantined("peer-stale").await,
        "PeerLeft must clear the relay-404 quarantine"
    );
    let rejoined = stale_peer("peer-rejoined", endpoint, 4000);
    manager.add_peer(&rejoined).await;
    assert!(
        !manager.peer_quarantined("peer-rejoined").await
            && manager.quarantine_consecutive("peer-rejoined").await == 0,
        "a fresh registration after PeerLeft must start with a clean quarantine slate"
    );
}

#[tokio::test]
async fn quarantine_absorbs_repeated_404_without_new_failure_samples() {
    let manager = PeerManager::new(test_config());
    let endpoint: SocketAddr = "220.165.178.32:9090".parse().unwrap();
    manager
        .add_peer(&stale_peer("peer-stale", endpoint, 1000))
        .await;
    quarantine_via_relay_404(&manager, "peer-stale").await;

    let failures_after_quarantine = {
        let conn = manager.get_connection("peer-stale").await.unwrap();
        conn.relay_health.failure_count
    };
    // The relay keeps sending 404 frames while the stale peer's registration
    // stays absent (field evidence: 404s every ~5 s for minutes).  Every one
    // inside the same quarantine episode must be absorbed: no new failure
    // sample, no state churn, no episode growth.
    for _ in 0..12 {
        manager
            .record_relay_failure("peer-stale", "peer_not_found", "peer not found: peer-stale")
            .await;
    }
    let conn = manager.get_connection("peer-stale").await.unwrap();
    assert_eq!(
        conn.relay_health.failure_count, failures_after_quarantine,
        "repeated 404s inside one quarantine episode must not add peer-health failure samples"
    );
    assert_eq!(
        manager.quarantine_consecutive("peer-stale").await,
        1,
        "repeated 404s inside one quarantine episode must not restart the episode"
    );
}

#[tokio::test]
async fn stale_peers_do_not_starve_healthy_peers_in_shared_scheduler() {
    let manager = PeerManager::new(test_config());
    let stale_a: SocketAddr = "220.165.178.32:9090".parse().unwrap();
    let stale_b: SocketAddr = "220.165.178.32:9091".parse().unwrap();
    let healthy_a: SocketAddr = "220.163.6.190:6609".parse().unwrap();
    let healthy_b: SocketAddr = "220.163.6.190:6610".parse().unwrap();

    manager
        .add_peer(&stale_peer("stale-a", stale_a, 1000))
        .await;
    manager
        .add_peer(&stale_peer("stale-b", stale_b, 1000))
        .await;
    quarantine_via_relay_404(&manager, "stale-a").await;
    quarantine_via_relay_404(&manager, "stale-b").await;

    let healthy_candidates = ["220.163.6.190:6609", "220.163.6.190:6610"]
        .iter()
        .map(|endpoint| (*endpoint).to_string())
        .collect::<Vec<_>>();
    let sources = healthy_candidates
        .iter()
        .cloned()
        .map(|candidate| (candidate, "stun_observed".to_string()))
        .collect::<HashMap<_, _>>();
    for (peer, endpoint) in [("healthy-a", healthy_a), ("healthy-b", healthy_b)] {
        manager.add_peer(&test_peer(peer, endpoint)).await;
        manager
            .add_candidates_with_sources(peer, &healthy_candidates, &sources)
            .await;
    }

    // The shared per-tick scheduler must hand its work slots to the healthy
    // targets only: quarantined stale peers never appear in the due set, so
    // they can neither consume slots nor rebuild plans.
    let sets = manager
        .direct_probe_targets_due(Duration::from_secs(1))
        .await;
    assert_eq!(
        sets.len(),
        2,
        "both healthy peers must receive recovery work"
    );
    assert!(
        sets.iter().all(|set| set.peer_id.starts_with("healthy-")),
        "quarantined stale peers must never occupy scheduler work slots: {:?}",
        sets.iter()
            .map(|set| set.peer_id.clone())
            .collect::<Vec<_>>()
    );
    for set in &sets {
        assert!(
            !set.candidates.is_empty(),
            "healthy peer {} must keep a punchable target set",
            set.peer_id
        );
    }
}

#[tokio::test]
async fn recovery_target_cap_scales_with_socket_count_for_complete_windows() {
    // The stage ceilings count physical datagrams; a pool punch sends every
    // planned candidate from every socket, so the plan must be sized so one
    // session covers a COMPLETE window (ceiling / sockets).  Field evidence:
    // a 512-datagram cap with a 3-socket pool truncated a 384-candidate
    // ScatterSmall plan at 171 unique endpoints — the rest of the window was
    // never scanned and the birthday cursor could not advance.  v0.1.116
    // bounds every ActivePool stage by the 192-datagram session cap so a
    // window always fits one controlled coverage.
    let active_pool = |socket_count| RecoveryProbeShape {
        socket_count,
        remote_port_dependent: false,
        stable_side_unique_scatter: false,
        remote_allocation_random: false,
    };
    let stable_scatter = |socket_count| RecoveryProbeShape {
        socket_count,
        remote_port_dependent: true,
        stable_side_unique_scatter: true,
        remote_allocation_random: false,
    };
    let three_sockets = recovery_target_cap(
        Some(RecoveryStage::ScatterSmall),
        false,
        active_pool(3),
    );
    assert_eq!(
        three_sockets,
        Some(192 / 3),
        "ScatterSmall with 3 sockets must plan candidates that a 192-datagram session can fully cover"
    );
    let one_socket = recovery_target_cap(
        Some(RecoveryStage::ScatterSmall),
        false,
        active_pool(1),
    );
    assert_eq!(
        one_socket,
        Some(192),
        "a single socket keeps the full 192-candidate window"
    );
    let predicted = recovery_target_cap(Some(RecoveryStage::Predicted), false, active_pool(3));
    assert_eq!(
        predicted,
        Some(192 / 3),
        "Predicted with 3 sockets must fit the 192-datagram ceiling"
    );
    let relay_backed = recovery_target_cap(
        Some(RecoveryStage::ScatterExtended),
        true,
        active_pool(3),
    );
    assert_eq!(
        relay_backed,
        Some(96 / 3),
        "a relay-backed wide stage is downgraded to the bounded heartbeat ceiling, socket-scaled"
    );
    let port_dependent_predicted =
        recovery_target_cap(Some(RecoveryStage::Predicted), false, stable_scatter(3));
    assert_eq!(
        port_dependent_predicted,
        Some(192),
        "a port-dependent remote opens the wide ceiling as soon as its predicted window had no ACK; the stable side sweeps via StableUniqueScatter (one socket), so the full 192-datagram ceiling is 192 distinct ports, NOT ceiling/sockets (field evidence v0.1.116: the 192/3=64 division spent only 64 unique CGNAT ports)"
    );
    let port_dependent_relay_backed =
        recovery_target_cap(Some(RecoveryStage::Predicted), true, stable_scatter(3));
    assert_eq!(
        port_dependent_relay_backed,
        Some(96),
        "relay downgrades the ceiling to the bounded heartbeat 96, but the port-dependent remote still sweeps it via StableUniqueScatter (one socket): 96 distinct ports, NOT 96/3 (field evidence v0.1.116: the relay safety net is confirmed within ~100 ms in availability runs, so a relay gate must not shrink the stable side to 32 unique ports)"
    );
    // No socket (unit context) must not degenerate to zero candidates.
    assert!(
        recovery_target_cap(Some(RecoveryStage::Initial), false, active_pool(0))
            .is_some_and(|cap| cap > 0)
    );

    assert_eq!(
        recovery_target_cap(Some(RecoveryStage::Initial), false, stable_scatter(3)),
        Some(RECOVERY_STAGE_INITIAL_MAX_PROBES as usize),
        "the stable side's one-socket Initial sweep must cover all 96 target ports instead of repeating 32 ports from three sockets"
    );
}

#[tokio::test]
async fn validation_evidence_survives_post_promotion_event_burst() {
    let manager = PeerManager::new(test_config());
    let endpoint: SocketAddr = "220.163.6.190:6609".parse().unwrap();
    manager.add_peer(&test_peer("peer-chain", endpoint)).await;

    // Emit the owned validation chain first, then a large burst of ordinary
    // post-promotion traversal events (scan completions, inbound probes,
    // maintainer stops) that previously evicted the chain from the bounded
    // 32-entry ring (field evidence: v0.1.116 acceptance rounds converged in
    // ~1 s and lost `direct_validation_request_sent` before the harness
    // snapshot, so the strict parser could not reconstruct the owned chain).
    let stages = [
        "direct_validation_request_sent",
        "direct_validation_ack_received",
        "direct_validation_emit_lock_timeout",
        "direct_validation_promoted",
        "direct_path_promoted",
    ];
    for stage in stages {
        manager
            .record_direct_validation_event(
                "peer-chain",
                0,
                1,
                stage,
                Some(endpoint),
                Some(1),
                Some(1),
                format!("validation evidence {stage}"),
            )
            .await;
    }
    for index in 0..200 {
        manager
            .record_direct_event(
                "peer-chain",
                "inbound_probe_received",
                Some(endpoint),
                None,
                None,
                format!("ordinary post-promotion noise {index}"),
            )
            .await;
    }

    let conn = manager.get_connection("peer-chain").await.unwrap();
    let stages_in_ring = conn
        .direct_events
        .iter()
        .map(|event| event.stage.as_str())
        .collect::<Vec<_>>();
    for stage in stages {
        assert!(
            stages_in_ring.contains(&stage),
            "the validation evidence stage {stage} must survive the post-promotion event burst"
        );
    }
    assert!(
        conn.direct_events.len() <= 64,
        "the ring must stay bounded even with protected validation events; got {}",
        conn.direct_events.len()
    );
}

#[tokio::test]
async fn predicted_window_survives_stage_cap_when_window_fits() {
    // A fresh 64-port prediction window with a 3-socket pool must be planned
    // COMPLETELY (64 candidates == 192/3 = 64 Predicted cap), never truncated
    // mid-window, so the whole advertised window gets one full coverage in a
    // single session.  The successful field profile (a 32-candidate scan
    // converging in ~0.5 s with 64 datagrams) is 2x inside this window, so
    // shrinking the wide window from 96 to 64 ports keeps the CGNAT resolution
    // capability while cutting the per-session physical ceiling to 192.
    let manager = PeerManager::new(test_config());
    let endpoint: SocketAddr = "220.163.6.190:6609".parse().unwrap();
    let mut peer = test_peer("peer-window", endpoint);
    peer.public_key = "window-peer-key".to_string();
    manager.add_peer(&peer).await;

    let predicted = (0..64)
        .map(|offset| format!("220.163.6.190:{}", 6600 + offset))
        .collect::<Vec<_>>();
    let sources = predicted
        .iter()
        .cloned()
        .map(|candidate| (candidate, "predicted".to_string()))
        .collect::<HashMap<_, _>>();
    manager
        .add_candidates_with_sources("peer-window", &predicted, &sources)
        .await;

    // Advance to the Predicted stage (Initial -> Predicted after zero-ACK
    // feedback) so the stage cap is the 192/3 = 64 candidate ceiling.
    manager
        .advance_recovery_stage_after_no_ack("peer-window", "test")
        .await;
    let targets = manager.direct_probe_targets_for("peer-window").await;
    assert!(
        targets.len() >= 64,
        "the 64-port predicted window must survive the Predicted-stage cap; got {}",
        targets.len()
    );
    for port in 6600..6664 {
        assert!(
            targets.contains(&format!("220.163.6.190:{port}").parse().unwrap()),
            "the complete window must include port {port}"
        );
    }
}
