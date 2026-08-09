// ============================================================
// v0.1.113: recovery work budget, zero-send backoff, stale-peer
// quarantine, cross-peer fairness, bounded restart recovery
// ============================================================

use std::time::Duration;

fn flood_peer_113(node_id: &str, virtual_ip: &str, endpoint: SocketAddr) -> PeerInfo {
    PeerInfo {
        node_id: node_id.to_string(),
        device_name: String::new(),
        app_version: String::new(),
        public_key: "pk-recovery-113".to_string(),
        endpoint: endpoint.to_string(),
        nat_type: "AddressOrPortDependent".to_string(),
        virtual_ip: virtual_ip.to_string(),
        online: true,
        last_seen: 0,
        relay_rtt_ms: None,
    }
}

#[tokio::test]
async fn budget_exhausted_recovery_does_not_spin_or_rebuild_wide_plan() {
    let manager = PeerManager::new(test_config());
    manager
        .add_peer(&flood_peer_113(
            "peer-fail",
            "10.20.0.3",
            "5.6.7.8:5001".parse().unwrap(),
        ))
        .await;

    // The first due tick builds the plan.
    let sets = manager
        .direct_probe_targets_due(Duration::from_secs(1))
        .await;
    assert_eq!(sets.len(), 1, "the first tick must build the peer's plan");
    assert_eq!(sets[0].peer_id, "peer-fail");

    // Every probe of the session was rejected by the budget (zero-send):
    // the verdict must freeze the epoch with a controlled backoff instead of
    // being swallowed.
    manager
        .record_zero_send_recovery_session("peer-fail", 1, 1, 1, "all_probes_rejected_by_budget")
        .await;
    assert!(
        manager.recovery_budget_frozen("peer-fail").await,
        "a zero-send session must freeze the recovery epoch"
    );
    let admission = manager.recovery_epoch_admit("peer-fail").await;
    assert!(
        matches!(admission, RecoveryAdmission::BudgetExhausted { .. }),
        "a frozen epoch must reject new triggers with BudgetExhausted, got {admission:?}"
    );

    // The 1-second tick keeps firing: the frozen epoch must NOT rebuild the
    // wide plan (previously this loop rebuilt a 778/3072-candidate plan and
    // iterated thousands of budget-rejected candidates every second).
    for _ in 0..10 {
        let sets = manager
            .direct_probe_targets_due(Duration::from_secs(1))
            .await;
        assert!(
            sets.is_empty(),
            "a budget-frozen epoch must never rebuild a plan on the next tick, got {} set(s)",
            sets.len()
        );
    }

    // The plan/session/candidate-iteration budgets hold hard upper bounds.
    let snapshot = manager
        .recovery_epoch_work_budget_report("peer-fail")
        .await
        .expect("epoch must exist");
    assert_eq!(snapshot.plan_builds_remaining, RECOVERY_EPOCH_PLAN_BUILDS - 1);
    assert_eq!(
        snapshot.sessions_remaining,
        RECOVERY_EPOCH_SESSIONS - 1,
        "one due tick consumes one session slot"
    );
    assert_eq!(
        snapshot.candidate_iterations_remaining,
        RECOVERY_EPOCH_CANDIDATE_ITERATIONS,
        "the plan build itself does not enumerate candidates"
    );

    // Only an authoritative epoch rotation (new network generation) re-opens
    // recovery.
    manager
        .advance_candidate_refresh_generation("test generation advance")
        .await;
    let admission = manager.recovery_epoch_admit("peer-fail").await;
    assert!(
        matches!(admission, RecoveryAdmission::Accepted { .. }),
        "a generation advance must re-open recovery, got {admission:?}"
    );
}

#[tokio::test]
async fn zero_send_probe_session_records_backoff_and_preserves_progress() {
    let manager = PeerManager::new(test_config());
    manager
        .add_peer(&flood_peer_113(
            "peer-fail",
            "10.20.0.3",
            "5.6.7.8:5001".parse().unwrap(),
        ))
        .await;
    manager.recovery_epoch_admit("peer-fail").await;

    // Two consecutive zero-send sessions: the backoff must double and the
    // structured event must carry the counts and the next retry deadline.
    manager
        .record_zero_send_recovery_session("peer-fail", 3_072, 3_072, 3_072, "epoch_credit")
        .await;
    let first = manager.recovery_epoch_work_budget_report("peer-fail").await.unwrap();
    assert!(first.budget_exhausted);
    assert_eq!(first.zero_send_streak, 1);
    assert!(first.next_retry_at_ms_since_epoch.is_some());

    let event1 = manager.recovery_last_budget_event("peer-fail").await.unwrap();
    assert_eq!(event1.candidate_count, 3_072);
    assert_eq!(event1.visited, 3_072);
    assert_eq!(event1.sent, 0);
    assert_eq!(event1.skipped, 3_072);
    assert_eq!(event1.zero_send_streak, 1);
    assert_eq!(event1.reason, "epoch_credit");

    // A second zero-send episode in the SAME epoch doubles the streak and
    // the backoff (the controlled backoff is simulated as elapsed so the
    // next session may start without waiting for wall-clock time).
    manager.test_force_budget_backoff_elapsed("peer-fail").await;
    let admission = manager.recovery_epoch_admit("peer-fail").await;
    assert!(
        matches!(admission, RecoveryAdmission::Accepted { .. }),
        "the controlled backoff must re-open the epoch, got {admission:?}"
    );
    manager
        .record_zero_send_recovery_session("peer-fail", 778, 778, 778, "epoch_credit")
        .await;
    let second = manager
        .recovery_epoch_work_budget_report("peer-fail")
        .await
        .unwrap();
    assert_eq!(second.zero_send_streak, 2);
    let event2 = manager.recovery_last_budget_event("peer-fail").await.unwrap();
    assert_eq!(event2.candidate_count, 778);
    assert_eq!(event2.zero_send_streak, 2);
    assert!(
        event2.next_retry_at_ms_since_epoch > event1.next_retry_at_ms_since_epoch,
        "the backoff deadline must move forward, never backwards"
    );

    // A matched ACK unfreezes a budget-exhausted epoch (live path evidence).
    manager.test_force_budget_backoff_elapsed("peer-fail").await;
    manager.recovery_epoch_admit("peer-fail").await;
    manager
        .record_zero_send_recovery_session("peer-fail", 1, 1, 1, "epoch_credit")
        .await;
    assert!(manager.recovery_budget_frozen("peer-fail").await);
    manager
        .record_recovery_ack_feedback("peer-fail", "5.6.7.8:5001".parse().unwrap())
        .await;
    assert!(
        !manager.recovery_budget_frozen("peer-fail").await,
        "a matched ACK must unfreeze the epoch"
    );
}

#[tokio::test]
async fn stale_peer_not_found_is_quarantined_and_cannot_starve_direct_recovery() {
    let manager = PeerManager::new(test_config());
    // The main peer with prior Direct success.
    manager
        .add_peer(&flood_peer_113(
            "peer-main",
            "10.20.0.2",
            "5.6.7.9:5001".parse().unwrap(),
        ))
        .await;
    manager
        .record_direct_success("peer-main", Some("5.6.7.9:5001".parse().unwrap()))
        .await;
    manager
        .advance_network_generation("simulated restart of peer-main")
        .await;
    // A stale third peer whose relay lookups return 404.
    manager
        .add_peer(&flood_peer_113(
            "peer-stale",
            "10.20.0.4",
            "6.7.8.9:5001".parse().unwrap(),
        ))
        .await;

    manager
        .record_relay_failure("peer-stale", "peer_not_found", "peer not found: peer-stale")
        .await;
    assert!(
        manager.peer_quarantined("peer-stale").await,
        "a relay 404 must quarantine the peer"
    );
    assert!(
        !manager.recovery_epoch_active("peer-stale").await,
        "quarantine must cancel the stale peer's recovery epoch"
    );

    // The stale peer must produce NO recovery work on repeated ticks.
    for _ in 0..10 {
        let sets = manager
            .direct_probe_targets_due(Duration::from_secs(1))
            .await;
        assert!(
            !sets.iter().any(|set| set.peer_id == "peer-stale"),
            "a quarantined peer must never build a candidate plan"
        );
        assert!(
            sets.iter().any(|set| set.peer_id == "peer-main"),
            "the main peer must keep its recovery work slot"
        );
    }

    // A stale/404 peer must not trigger fresh mapping or HTTP fan-out.
    let fresh = manager.fresh_mapping_for_peer("peer-stale").await;
    assert!(fresh.is_none(), "quarantine must invalidate fresh mappings");

    // Authoritative control-plane evidence (new endpoint + online) re-opens
    // recovery; plain refresh without evidence does not.
    let mut refresh = flood_peer_113("peer-stale", "10.20.0.4", "6.7.8.9:5001".parse().unwrap());
    refresh.endpoint = "6.7.8.9:5002".to_string();
    manager.add_peer(&refresh).await;
    assert!(
        !manager.peer_quarantined("peer-stale").await,
        "a new authoritative endpoint must unquarantine the peer"
    );
}

#[tokio::test]
async fn recovery_scheduler_is_fair_across_shared_nat_peers() {
    let manager = PeerManager::new(test_config());
    // One recently-Direct reclaim peer (highest priority).
    manager
        .add_peer(&flood_peer_113(
            "peer-reclaim",
            "10.20.0.2",
            "5.6.7.9:5001".parse().unwrap(),
        ))
        .await;
    manager
        .record_direct_success("peer-reclaim", Some("5.6.7.9:5001".parse().unwrap()))
        .await;
    manager
        .advance_network_generation("simulated interface change")
        .await;
    // Two failing peers.
    manager
        .add_peer(&flood_peer_113(
            "peer-fail-a",
            "10.20.0.3",
            "5.6.7.10:5001".parse().unwrap(),
        ))
        .await;
    manager
        .add_peer(&flood_peer_113(
            "peer-fail-b",
            "10.20.0.5",
            "5.6.7.11:5001".parse().unwrap(),
        ))
        .await;

    let mut reclaim_seen = false;
    let mut fail_a_seen = false;
    let mut fail_b_seen = false;
    for _ in 0..6 {
        let sets = manager
            .direct_probe_targets_due(Duration::from_secs(1))
            .await;
        // Hard upper bound on per-tick work regardless of how many peers are
        // failing.
        assert!(
            sets.len() <= RECOVERY_WORK_SLOTS_PER_TICK,
            "per-tick recovery work must be capped at {} slots, got {}",
            RECOVERY_WORK_SLOTS_PER_TICK,
            sets.len()
        );
        for set in &sets {
            if set.peer_id == "peer-reclaim" {
                reclaim_seen = true;
            }
            if set.peer_id == "peer-fail-a" {
                fail_a_seen = true;
            }
            if set.peer_id == "peer-fail-b" {
                fail_b_seen = true;
            }
        }
    }
    assert!(
        reclaim_seen,
        "the recently-Direct reclaim peer must always be scheduled first"
    );
    // Fairness across ticks: the failing peers must not be starved forever
    // (the reclaim peer only holds a slot while its reclaim window is open,
    // and slots rotate between the failing peers).
    assert!(
        fail_a_seen || fail_b_seen,
        "a failing peer must eventually receive a work slot"
    );
}

#[tokio::test]
async fn direct_restart_recovery_is_bounded_and_prioritized() {
    let manager = PeerManager::new(test_config());
    // The main peer: previously Direct, now degraded by a restart.
    manager
        .add_peer(&flood_peer_113(
            "peer-restart",
            "10.20.0.2",
            "5.6.7.9:5001".parse().unwrap(),
        ))
        .await;
    manager
        .record_direct_success("peer-restart", Some("5.6.7.9:5001".parse().unwrap()))
        .await;
    manager
        .advance_network_generation("peer restart detected")
        .await;
    assert!(
        manager.direct_reclaim_active("peer-restart").await,
        "a restart after Direct success must open the reclaim window"
    );

    // An unrelated failing peer with a wide scatter need.
    manager
        .add_peer(&flood_peer_113(
            "peer-unrelated",
            "10.20.0.3",
            "6.7.8.9:5001".parse().unwrap(),
        ))
        .await;

    // The restarting peer is prioritized: on every tick it holds the first
    // work slot while the unrelated peer can never fan out a wide plan
    // beyond the per-tick cap.
    for _ in 0..5 {
        let sets = manager
            .direct_probe_targets_due(Duration::from_secs(1))
            .await;
        assert!(sets.len() <= RECOVERY_WORK_SLOTS_PER_TICK);
        if let Some(first) = sets.first() {
            assert_eq!(
                first.peer_id, "peer-restart",
                "the restarting (reclaim) peer must be scheduled before unrelated peers"
            );
        }
        let restart_set = sets.iter().find(|set| set.peer_id == "peer-restart");
        if let Some(set) = restart_set {
            assert!(
                !set.stable_remote_scatter || set.candidates.len() <= RECOVERY_STAGE_INITIAL_MAX_PROBES as usize,
                "a relay-backed reclaim must stay bounded instead of wide-scattering"
            );
        }
    }
}
