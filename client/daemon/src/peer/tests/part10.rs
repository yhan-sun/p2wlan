// ============================================================
// v0.1.112: recovery-epoch scheduler, direct-commit gate, budgets
// ============================================================

fn flood_peer_112(node_id: &str, virtual_ip: &str, endpoint: SocketAddr) -> PeerInfo {
    PeerInfo {
        node_id: node_id.to_string(),
        device_name: String::new(),
        app_version: String::new(),
        public_key: "pk-recovery".to_string(),
        endpoint: endpoint.to_string(),
        nat_type: "AddressOrPortDependent".to_string(),
        virtual_ip: virtual_ip.to_string(),
        online: true,
        last_seen: 0,
        relay_rtt_ms: None,
    }
}

#[tokio::test]
async fn failed_peer_has_one_active_recovery_epoch_despite_rapid_offers() {
    let manager = PeerManager::new(test_config());
    manager
        .add_peer(&flood_peer_112("peer-fail", "10.20.0.3", "5.6.7.8:5001".parse().unwrap()))
        .await;

    // Rapid triggers (offers / retries / peer-reflexive observations) all
    // enter the SAME recovery epoch: the epoch number must not move and the
    // budgets must not reset while the peer keeps failing.
    let first = manager.recovery_epoch_admit("peer-fail").await;
    let RecoveryAdmission::Accepted { epoch: e1 } = first else {
        panic!("first trigger must be admitted");
    };
    for _ in 0..50 {
        let admission = manager.recovery_epoch_admit("peer-fail").await;
        let RecoveryAdmission::Accepted { epoch } = admission else {
            panic!("rapid triggers must stay admitted");
        };
        assert_eq!(epoch, e1, "rapid offers must not rotate the recovery epoch");
    }
    let report = manager
        .recovery_epoch_budget_report("peer-fail")
        .await
        .expect("epoch must exist");
    assert_eq!(report.0, e1);
    // The fresh-generation and HTTP quotas are still full: offers alone did
    // not consume them.
    assert_eq!(report.2, RECOVERY_EPOCH_FRESH_GENERATIONS);
    assert_eq!(report.3, RECOVERY_EPOCH_HTTP_PUBLISHES);

    // A generation advance rotates the epoch (new plan per generation).
    manager.advance_candidate_refresh_generation("test generation advance").await;
    let admission = manager.recovery_epoch_admit("peer-fail").await;
    let RecoveryAdmission::Accepted { epoch: e2 } = admission else {
        panic!("admission after generation advance must succeed");
    };
    assert!(e2 > e1, "a generation advance must start a new recovery epoch");
}

#[tokio::test]
async fn failed_scatter_requires_feedback_before_expansion() {
    let manager = PeerManager::new(test_config());
    manager
        .add_peer(&flood_peer_112("peer-fail", "10.20.0.3", "5.6.7.8:5001".parse().unwrap()))
        .await;
    manager.recovery_epoch_admit("peer-fail").await;

    assert_eq!(
        manager.recovery_stage_for("peer-fail").await,
        RecoveryStage::Initial,
        "a fresh epoch starts at the Initial stage"
    );
    // No-ACK feedback widens the stage one step at a time.
    manager
        .advance_recovery_stage_after_no_ack("peer-fail", "batch 1 no ack")
        .await;
    assert_eq!(
        manager.recovery_stage_for("peer-fail").await,
        RecoveryStage::Predicted
    );
    manager
        .advance_recovery_stage_after_no_ack("peer-fail", "batch 2 no ack")
        .await;
    assert_eq!(
        manager.recovery_stage_for("peer-fail").await,
        RecoveryStage::ScatterSmall
    );
    manager
        .advance_recovery_stage_after_no_ack("peer-fail", "batch 3 no ack")
        .await;
    assert_eq!(
        manager.recovery_stage_for("peer-fail").await,
        RecoveryStage::ScatterExtended,
        "wide scatter is only reachable after three explicit no-ACK feedback steps"
    );

    // Matched-ACK feedback resets the stage: a live path is never expanded.
    manager
        .record_recovery_ack_feedback("peer-fail", "5.6.7.8:5002".parse().unwrap())
        .await;
    assert_eq!(
        manager.recovery_stage_for("peer-fail").await,
        RecoveryStage::Initial,
        "matched ACK feedback must reset the stage so a live path is never expanded"
    );
}

#[tokio::test]
async fn recovery_epoch_probe_credit_cannot_be_bypassed_by_new_candidates() {
    let manager = PeerManager::new(test_config());
    manager
        .add_peer(&flood_peer_112("peer-fail", "10.20.0.3", "5.6.7.8:5001".parse().unwrap()))
        .await;
    manager.recovery_epoch_admit("peer-fail").await;

    // Exhaust the epoch's probe credit through the admission funnel.
    let mut accepted = 0u32;
    let mut exhausted = 0u32;
    for _ in 0..RECOVERY_EPOCH_PROBE_CREDIT + 64 {
        if manager.try_consume_recovery_probe_credit("peer-fail").await {
            accepted += 1;
        } else {
            exhausted += 1;
        }
    }
    assert_eq!(accepted, RECOVERY_EPOCH_PROBE_CREDIT);
    assert_eq!(exhausted, 64, "probes beyond the epoch credit must be rejected");

    // New candidates (offers / fresh predictions) cannot refill the credit:
    // the epoch stays exhausted regardless of how many triggers arrive.
    for _ in 0..8 {
        manager.recovery_epoch_admit("peer-fail").await;
        manager.stash_recovery_target(PendingRecoveryTarget {
            peer_id: "peer-fail".to_string(),
            candidates: vec!["5.6.7.8:6001".parse().unwrap()],
            frozen_targets: None,
            fresh_prediction: None,
            punch_at_ms: None,
            seen_at: Instant::now(),
        })
        .await;
        assert!(
            !manager.try_consume_recovery_probe_credit("peer-fail").await,
            "new candidates must never bypass the recovery-epoch probe credit"
        );
    }

    // A fresh mapping generation is also capped: the quota is separate and
    // can only be spent once per epoch.
    assert!(
        manager.try_begin_fresh_generation("peer-fail").await,
        "first fresh generation in the epoch must be allowed"
    );
    assert!(
        !manager.try_begin_fresh_generation("peer-fail").await,
        "a second fresh generation must be rejected by the per-epoch quota"
    );
}

#[tokio::test]
async fn direct_commit_seq_prevents_post_promotion_udp_sends() {
    let manager = PeerManager::new(test_config());
    manager
        .add_peer(&flood_peer_112("peer-fail", "10.20.0.3", "5.6.7.8:5001".parse().unwrap()))
        .await;
    manager.recovery_epoch_admit("peer-fail").await;
    assert_eq!(
        manager.direct_commit_seq_sync("peer-fail"),
        None,
        "no direct commit exists before promotion"
    );

    // A Direct promotion bumps the sequence inside the epoch gate, and the
    // promotion ends the recovery epoch.
    let endpoint: SocketAddr = "5.6.7.8:5001".parse().unwrap();
    manager
        .record_direct_success_with_local_endpoint("peer-fail", Some(endpoint), None)
        .await;
    let seq = manager
        .direct_commit_seq_sync("peer-fail")
        .expect("promotion must bump the direct-commit sequence");
    assert!(seq >= 1);

    // The send gate reads the sequence: once it advances past the snapshot a
    // sweep started with, no further UDP send may occur.
    assert!(
        !manager.recovery_epoch_active("peer-fail").await,
        "Direct confirmation ends the recovery epoch"
    );
    // A second confirmation with a NEW endpoint (endpoint change) bumps the
    // sequence again.
    let endpoint2: SocketAddr = "5.6.7.8:5011".parse().unwrap();
    manager
        .record_direct_success_with_local_endpoint("peer-fail", Some(endpoint2), None)
        .await;
    let seq2 = manager
        .direct_commit_seq_sync("peer-fail")
        .expect("a direct-endpoint change must bump the sequence");
    assert!(seq2 > seq, "every direct confirmation change must bump the sequence");

    // The bounded feedback wait returns immediately when a commit is already
    // newer than the snapshot.
    let promoted = manager
        .wait_for_direct_commit_or_timeout("peer-fail", Some(seq), Duration::from_secs(1))
        .await;
    assert!(promoted, "the wait must observe the newer direct commit");
}

#[tokio::test]
async fn offer_storm_cannot_reset_backoff_or_spawn_fresh_sockets() {
    let manager = PeerManager::new(test_config());
    manager
        .add_peer(&flood_peer_112("peer-fail", "10.20.0.3", "5.6.7.8:5001".parse().unwrap()))
        .await;
    manager.recovery_epoch_admit("peer-fail").await;

    // Simulate a failure history: the retry backoff grows from the health
    // counters, not from offers.
    for _ in 0..6 {
        manager
            .record_direct_failure_for_generation(
                "peer-fail",
                manager.current_network_generation().await,
                "direct_probe_failed",
                "batch no ack",
            )
            .await;
    }
    let retry_after = manager
        .diagnostics_with_path_selection(true, true, DIRECT_RETRY_BASE_INTERVAL, None)
        .await
        .iter()
        .find(|diagnostics| diagnostics.node_id == "peer-fail")
        .and_then(|diagnostics| diagnostics.direct_retry_after_ms)
        .expect("the backoff must be visible in diagnostics");
    assert_eq!(
        retry_after, 8_000,
        "six failures must reach, but not exceed, the bounded fast-recovery cap"
    );

    // An offer storm must not reset the backoff: offers only stash
    // newest-wins targets and never touch the failure counters.
    for _ in 0..20 {
        let admission = manager.recovery_epoch_admit("peer-fail").await;
        assert!(
            matches!(admission, RecoveryAdmission::Accepted { .. }),
            "the storm's triggers must stay admitted"
        );
        manager.stash_recovery_target(PendingRecoveryTarget {
            peer_id: "peer-fail".to_string(),
            candidates: vec!["5.6.7.8:7001".parse().unwrap()],
            frozen_targets: None,
            fresh_prediction: None,
            punch_at_ms: None,
            seen_at: Instant::now(),
        })
        .await;
    }
    let retry_after_after_offers = manager
        .diagnostics_with_path_selection(true, true, DIRECT_RETRY_BASE_INTERVAL, None)
        .await
        .iter()
        .find(|diagnostics| diagnostics.node_id == "peer-fail")
        .and_then(|diagnostics| diagnostics.direct_retry_after_ms)
        .expect("the backoff must still be visible");
    assert_eq!(
        retry_after_after_offers, retry_after,
        "an offer storm must never reset the failure backoff"
    );
    // The pending target is newest-wins: exactly the newest one survives.
    let pending = manager.take_recovery_target("peer-fail").await;
    assert_eq!(
        pending.as_ref().map(|target| target.candidates[0]),
        Some("5.6.7.8:7001".parse().unwrap()),
        "the newest-wins pending target must be the last stashed one"
    );
    assert!(
        manager.take_recovery_target("peer-fail").await.is_none(),
        "there must be exactly one pending target"
    );
}

#[tokio::test]
async fn old_generation_validation_ack_cannot_promote_or_adopt_affinity() {
    let manager = PeerManager::new(test_config());
    manager
        .add_peer(&flood_peer_112("peer", "10.20.0.2", "1.2.3.4:5000".parse().unwrap()))
        .await;
    let endpoint: SocketAddr = "1.2.3.4:5000".parse().unwrap();

    // An ACK from an OLD generation must be ignored: it can neither promote
    // Direct nor adopt socket affinity.
    let old_generation = manager.current_network_generation().await;
    manager.advance_candidate_refresh_generation("test generation advance").await;
    let new_generation = manager.current_network_generation().await;
    assert!(new_generation > old_generation);

    let promoted = manager
        .record_direct_success_for_generation(
            "peer",
            Some(endpoint),
            old_generation,
        )
        .await;
    assert!(!promoted, "an old-generation validation ACK must not promote");
    assert!(!manager.is_direct("peer").await);
    assert_eq!(
        manager.direct_commit_seq_sync("peer"),
        None,
        "an old-generation ACK must not bump the direct-commit sequence"
    );

    // The current-generation ACK still promotes normally.
    let promoted = manager
        .record_direct_success_for_generation("peer", Some(endpoint), new_generation)
        .await;
    assert!(promoted);
    assert!(manager.is_direct("peer").await);
    assert!(
        manager.direct_commit_seq_sync("peer").is_some(),
        "the current-generation ACK must bump the direct-commit sequence"
    );
}

#[tokio::test]
async fn unmatched_authenticated_acks_do_not_weaken_validation_or_expand_unboundedly() {
    let manager = PeerManager::new(test_config());
    manager
        .add_peer(&flood_peer_112("peer-fail", "10.20.0.3", "5.6.7.8:5001".parse().unwrap()))
        .await;
    manager.recovery_epoch_admit("peer-fail").await;

    // A matched-ACK feedback window resets the stage; unmatched probes never
    // advance it.
    manager
        .advance_recovery_stage_after_no_ack("peer-fail", "no ack")
        .await;
    manager
        .advance_recovery_stage_after_no_ack("peer-fail", "no ack")
        .await;
    assert_eq!(
        manager.recovery_stage_for("peer-fail").await,
        RecoveryStage::ScatterSmall
    );
    // Matched ACK feedback collapses the stage back to Initial.
    manager
        .record_recovery_ack_feedback("peer-fail", "5.6.7.8:5002".parse().unwrap())
        .await;
    assert_eq!(
        manager.recovery_stage_for("peer-fail").await,
        RecoveryStage::Initial
    );
    // The epoch credit is a hard total: repeated no-ACK batches cannot expand
    // beyond it because admission rejects sends.
    for _ in 0..RECOVERY_EPOCH_PROBE_CREDIT {
        assert!(manager.try_consume_recovery_probe_credit("peer-fail").await);
    }
    assert!(!manager.try_consume_recovery_probe_credit("peer-fail").await);
    let report = manager
        .recovery_epoch_budget_report("peer-fail")
        .await
        .expect("epoch must exist");
    assert_eq!(
        report.1, 0,
        "the epoch probe credit must be exactly exhausted, not negative"
    );
}
