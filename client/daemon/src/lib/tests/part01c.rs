// ============================================================
// v0.1.119: C=0 fresh-fresh synchronized pair plan (pure, no sockets)
// ============================================================
//
// The `C0FreshPairPlan` carries the "remote fresh targets + canonical
// punch_at_ms" contract that the bounded C=0 path must preserve when its
// rendezvous window runs:
//   - the punch targets are the REMOTE FRESH predicted endpoints, NOT the
//     historical stable_targets (APD filtering invalidates old sources),
//   - both sides share ONE canonical wall-clock deadline (the local fresh
//     endpoint is a SOURCE identity, never a target),
//   - the target slice is bounded to the micro-window cap,
//   - missing propagated deadline falls back to a local deadline so the pair
//     stays aligned rather than firing immediately.
//
// The actual UDP send is exercised by the existing rendezvous / UDP layers;
// this file locks the plan-level contract that feeds them.

#[tokio::test]
async fn c0_fresh_pair_plan_targets_remote_fresh_not_historical() {
    let local_fresh: SocketAddr = "10.0.0.1:51000".parse().unwrap();
    // The peer's OWN fresh predicted endpoints (what its offer carried).
    let remote_fresh = vec![
        "203.0.113.7:42010".parse().unwrap(),
        "203.0.113.7:42011".parse().unwrap(),
    ];

    let plan = C0FreshPairPlan::new(local_fresh, &remote_fresh, Some(1_780_100_000))
        .expect("non-empty remote fresh targets build a plan");

    assert_eq!(plan.local_fresh_endpoint, local_fresh);
    assert_eq!(
        plan.bounded_targets,
        remote_fresh,
        "the punch targets must be the remote FRESH predicted ports"
    );
    assert!(
        !plan
            .bounded_targets
            .contains(&local_fresh),
        "the local fresh endpoint is a source identity, never a target"
    );
    assert_eq!(plan.canonical_punch_at_ms, 1_780_100_000, "propagated canonical deadline honored");
}

#[tokio::test]
async fn c0_fresh_pair_plan_shared_canonical_deadline() {
    let local_fresh: SocketAddr = "10.0.0.1:51001".parse().unwrap();
    let remote_fresh: Vec<SocketAddr> = vec!["203.0.113.9:43000".parse().unwrap()];

    // Two identical plans built from the SAME propagated deadline must share
    // one canonical instant — the "single wall-clock momentum" invariant that
    // makes mutual-APD filtering tables admit simultaneously.
    let plan_a = C0FreshPairPlan::new(local_fresh, &remote_fresh, Some(1_780_200_000)).unwrap();
    let plan_b = C0FreshPairPlan::new(local_fresh, &remote_fresh, Some(1_780_200_000)).unwrap();
    assert_eq!(plan_a.canonical_punch_at_ms, plan_b.canonical_punch_at_ms);
}

#[tokio::test]
async fn c0_fresh_pair_plan_falls_back_to_local_deadline_when_no_propagation() {
    // Old signals without a deadline must not invent a one-sided window, but
    // the C=0 path still needs a shared-style instant to punch at; the local
    // relay-assisted deadline is the fallback so the pair is not an immediate
    // unscoped send.
    let local_fresh: SocketAddr = "10.0.0.1:51002".parse().unwrap();
    let remote_fresh: Vec<SocketAddr> = vec!["203.0.113.10:43010".parse().unwrap()];
    let plan = C0FreshPairPlan::new(local_fresh, &remote_fresh, None).expect("plan with fallback");
    assert!(
        plan.canonical_punch_at_ms > 0,
        "fallback deadline must be a valid relay-assisted instant"
    );
}

#[tokio::test]
async fn c0_fresh_pair_plan_bounds_target_slice() {
    let local_fresh: SocketAddr = "10.0.0.1:51003".parse().unwrap();
    // Many remote fresh candidates (a wide prediction window).
    let remote_fresh: Vec<SocketAddr> = (42_010..42_100u16)
        .map(|port| SocketAddr::from(([203, 0, 113, 11], port)))
        .collect();
    let plan = C0FreshPairPlan::new(local_fresh, &remote_fresh, Some(1_780_300_000)).unwrap();
    assert!(
        plan.bounded_targets.len() <= PEER_REFLEXIVE_MICRO_WINDOW_MAX_TARGETS,
        "target slice must be bounded to the micro-window cap"
    );
}

#[tokio::test]
async fn c0_fresh_pair_plan_rejects_empty_remote_fresh() {
    let local_fresh: SocketAddr = "10.0.0.1:51004".parse().unwrap();
    assert!(
        C0FreshPairPlan::new(local_fresh, &[], Some(1_780_400_000)).is_none(),
        "no remote fresh targets -> no plan"
    );
}