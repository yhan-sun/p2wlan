// ============================================================
// v0.1.119: C=0 bounded fresh-fresh endpoint-pair ledger
// ============================================================
//
// These drive `c0_pair_ledgers` directly (no rendezvous windows, no real
// sockets) to lock down the bounded invariant:
//   - budget is bounded and exhausts after MAX_C0_PAIRS_PER_GENERATION misses,
//   - a hit marks the ledger finished and stops all further attempts,
//   - a generation change resets the ledger (new egress IP invalidates old
//     pairs),
//   - the exhaust attribution `c0_pairs_exhausted` fires exactly once, and
//   - a stray attempt after a hit is rejected without recording a third pair.
//
// The rendezvous-alignment (fresh target into the synchronized window at the
// same canonical punch_at_ms) is exercised at the integration layer where the
// real `claim_for_epoch_with_rendezvous` machinery lives; this file proves the
// bounded-budget and attribution invariants it sits on.

#[tokio::test]
async fn c0_budget_bounded_and_exhausts_after_cap_misses() {
    let manager = PeerManager::new(test_config());
    let endpoint: SocketAddr = "1.2.3.4:51001".parse().unwrap();
    manager
        .add_peer(&flood_peer_112("peer-c0", "10.20.0.3", endpoint))
        .await;
    let gen = manager.current_network_generation().await;

    for i in 0..MAX_C0_PAIRS_PER_GENERATION {
        assert!(
            manager.c0_pair_admission("peer-c0", gen).await,
            "attempt {} must still be admitted below the cap",
            i + 1
        );
        let exhausted = manager
            .c0_pair_attempt(
                "peer-c0",
                gen,
                i as u64,
                &format!("10.0.0.1:41{i:03}"),
                &format!("10.0.0.2:41{i:03}"),
                Some(1_780_000_000 + i as u64),
                C0PairOutcome::Miss,
            )
            .await;
        // The final attempt (index == cap-1) exhausts the budget.
        assert_eq!(exhausted, i == MAX_C0_PAIRS_PER_GENERATION - 1, "attempt {}", i + 1);
    }

    // Budget exhausted: no further admission.
    assert!(
        !manager.c0_pair_admission("peer-c0", gen).await,
        "budget must be exhausted after {} misses",
        MAX_C0_PAIRS_PER_GENERATION
    );

    let ledger = manager.c0_ledger_snapshot("peer-c0", gen).await.expect("ledger present");
    assert_eq!(
        ledger.attempted_count(),
        MAX_C0_PAIRS_PER_GENERATION,
        "exactly {} distinct pairs attempted",
        MAX_C0_PAIRS_PER_GENERATION
    );
    assert!(ledger.is_exhausted(), "ledger must be marked exhausted");

    assert_eq!(
        manager.c0_event_count("peer-c0", "c0_pairs_exhausted").await,
        1,
        "c0_pairs_exhausted attributed exactly once"
    );
}

#[tokio::test]
async fn c0_hit_stops_further_attempts_immediately() {
    let manager = PeerManager::new(test_config());
    let endpoint: SocketAddr = "1.2.3.4:51002".parse().unwrap();
    manager
        .add_peer(&flood_peer_112("peer-hit", "10.20.0.3", endpoint))
        .await;
    let gen = manager.current_network_generation().await;

    // A hit on the very first fresh-fresh pair must finish the ledger at once.
    let stopped = manager
        .c0_pair_attempt(
            "peer-hit",
            gen,
            0,
            "10.0.0.1:42001",
            "10.0.0.2:42201",
            Some(1_780_000_500),
            C0PairOutcome::Hit,
        )
        .await;
    assert!(stopped, "hit returns stop=true");

    assert!(
        !manager.c0_pair_admission("peer-hit", gen).await,
        "a hit must stop all further C=0 attempts for the generation"
    );
    let ledger = manager.c0_ledger_snapshot("peer-hit", gen).await.expect("ledger present");
    assert_eq!(ledger.attempted_count(), 1, "only the hit pair recorded");
    assert!(ledger.is_exhausted(), "hit ledger is finished");
    assert_eq!(manager.c0_event_count("peer-hit", "c0_attempt").await, 1);
}

#[tokio::test]
async fn c0_generation_change_resets_ledger() {
    let manager = PeerManager::new(test_config());
    let endpoint: SocketAddr = "1.2.3.4:51003".parse().unwrap();
    manager
        .add_peer(&flood_peer_112("peer-gen", "10.20.0.3", endpoint))
        .await;
    let gen = manager.current_network_generation().await;

    // Exhaust the budget for generation `gen`.
    for i in 0..MAX_C0_PAIRS_PER_GENERATION {
        manager
            .c0_pair_attempt(
                "peer-gen",
                gen,
                i as u64,
                &format!("10.0.0.1:43{i:03}"),
                &format!("10.0.0.2:43{i:03}"),
                None,
                C0PairOutcome::Miss,
            )
            .await;
    }

    // A new network generation is a brand-new key: admission is open again.
    let next_gen = gen + 1;
    assert!(
        manager.c0_pair_admission("peer-gen", next_gen).await,
        "generation change must reset the C=0 budget"
    );
    assert!(
        manager.c0_ledger_snapshot("peer-gen", next_gen).await.is_none(),
        "no ledger yet for the new generation"
    );
    // The exhausted old-generation ledger is untouched.
    let old = manager.c0_ledger_snapshot("peer-gen", gen).await.expect("old ledger present");
    assert!(old.is_exhausted(), "old generation ledger stays exhausted");
}

#[tokio::test]
async fn c0_attempt_distinguishes_distinct_pair_by_epoch_and_endpoints() {
    let manager = PeerManager::new(test_config());
    let endpoint: SocketAddr = "1.2.3.4:51004".parse().unwrap();
    manager
        .add_peer(&flood_peer_112("peer-pairs", "10.20.0.3", endpoint))
        .await;
    let gen = manager.current_network_generation().await;

    // Two attempts with distinct (epoch, local_fresh, remote_fresh) both
    // count as separate pairs.
    manager
        .c0_pair_attempt(
            "peer-pairs",
            gen,
            1,
            "10.0.0.1:44001",
            "10.0.0.2:44401",
            Some(1_780_001_000),
            C0PairOutcome::Miss,
        )
        .await;
    manager
        .c0_pair_attempt(
            "peer-pairs",
            gen,
            2,
            "10.0.0.1:44002",
            "10.0.0.2:44402",
            Some(1_780_002_000),
            C0PairOutcome::Miss,
        )
        .await;

    let ledger = manager.c0_ledger_snapshot("peer-pairs", gen).await.expect("ledger present");
    assert_eq!(ledger.attempted_count(), 2);
    assert_eq!(
        ledger.attempted_pairs[0].pair_index, 0,
        "first pair indexed 0"
    );
    assert_eq!(
        ledger.attempted_pairs[1].pair_index, 1,
        "second pair indexed 1"
    );
    assert_eq!(ledger.attempted_pairs[0].epoch, 1);
    assert_eq!(ledger.attempted_pairs[1].epoch, 2);
    assert_eq!(manager.c0_event_count("peer-pairs", "c0_attempt").await, 2);
    assert!(!ledger.is_exhausted(), "two misses of four do not exhaust");
}

#[tokio::test]
async fn c0_retry_after_hit_is_rejected_without_double_record() {
    let manager = PeerManager::new(test_config());
    let endpoint: SocketAddr = "1.2.3.4:51005".parse().unwrap();
    manager
        .add_peer(&flood_peer_112("peer-retry", "10.20.0.3", endpoint))
        .await;
    let gen = manager.current_network_generation().await;

    manager
        .c0_pair_attempt(
            "peer-retry",
            gen,
            0,
            "10.0.0.1:45001",
            "10.0.0.2:45501",
            Some(1_780_003_000),
            C0PairOutcome::Miss,
        )
        .await;
    // Admission still open.
    assert!(manager.c0_pair_admission("peer-retry", gen).await);
    // Hit ends it.
    let stopped = manager
        .c0_pair_attempt(
            "peer-retry",
            gen,
            1,
            "10.0.0.1:45002",
            "10.0.0.2:45502",
            Some(1_780_004_000),
            C0PairOutcome::Hit,
        )
        .await;
    assert!(stopped);

    // A stray later attempt (caller race) must be rejected, not recorded.
    let exhausted = manager
        .c0_pair_attempt(
            "peer-retry",
            gen,
            2,
            "10.0.0.1:45003",
            "10.0.0.2:45503",
            None,
            C0PairOutcome::Miss,
        )
        .await;
    assert!(exhausted, "post-hit retry reports exhaust/stop");
    let ledger = manager.c0_ledger_snapshot("peer-retry", gen).await.expect("ledger present");
    assert_eq!(ledger.attempted_count(), 2, "no third pair recorded");
    assert_eq!(manager.c0_event_count("peer-retry", "c0_attempt").await, 2);
}