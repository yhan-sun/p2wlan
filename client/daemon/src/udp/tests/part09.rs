// Adaptive-prediction (R2) integration for the fresh-mapping generator:
// cross-batch step learning, reverse-allocation detection, and the
// network-generation reset of the shared per-egress learner cache.
//
// The scenarios reuse the loopback `SimulatedNat` (see `part04.rs`), which
// allocates a fresh public port per (socket, destination) walking a
// configurable signed `step`.  Two consecutive generations on the same
// transport feed the shared learner twice: the first batch learns the stride
// / direction, the second is the one that actually *uses* it.

/// The loopback egress public IP the `SimulatedNat` reports (see `part04`).
const LEARNER_NAT_IP: IpAddr = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1));

/// A step-parameterized fresh-mapping environment: a hard-NAT peer manager, a
/// bound transport, and a simulated NAT that allocates with the given `step`.
async fn learning_env(step: i16) -> (Arc<PeerManager>, Arc<UdpTransport>, SimulatedNat) {
    let local_identity = NodeIdentity::generate();
    let peer_identity = NodeIdentity::generate();
    let nat = SimulatedNat::start(step, false).await;

    let peers = Arc::new(PeerManager::new(config_for_identity(
        &local_identity,
        "peer-a",
    )));
    peers
        .add_peer(&peer_with_public_key(
            "peer-b",
            "10.20.0.2",
            hex::encode(peer_identity.public_key()),
            Some(nat.peer_public),
        ))
        .await;
    let report = hard_nat_profile().await;
    peers.update_nat_profile(report.nat_profile).await;

    let (tx, _rx) = mpsc::channel(64);
    let transport = UdpTransport::bind("127.0.0.1:0".parse().unwrap(), peers.clone())
        .await
        .unwrap()
        .with_local_node_id("peer-a")
        .with_inbound_channel(tx);
    (peers, Arc::new(transport), nat)
}

/// Drive one accepted fresh-mapping generation against the simulated NAT.
async fn run_one(
    transport: &Arc<UdpTransport>,
    nat: &SimulatedNat,
) -> FreshMappingResult {
    let outcome = transport
        .run_fresh_mapping_generation(
            "peer-b",
            &nat.observers,
            Duration::from_millis(500),
            &[nat.peer_public],
            Duration::from_millis(10),
            2,
            None,
        )
        .await;
    accepted_result(outcome).await
}

/// Read the `detail` string of the most recent `fresh_mapping_model` direct
/// event for a peer, or `None` when that peer recorded none.
async fn last_model_detail(peers: &Arc<PeerManager>, peer_id: &str) -> Option<String> {
    let diagnostics = peers.diagnostics().await;
    diagnostics
        .iter()
        .find(|peer| peer.node_id == peer_id)
        .and_then(|peer| {
            peer.direct_events
                .iter()
                .rev()
                .find(|event| event.stage == "fresh_mapping_model")
                .map(|event| event.detail.clone())
        })
}

/// Whether the peer recorded any `fresh_mapping_model` direct event.
async fn has_model_event(peers: &Arc<PeerManager>, peer_id: &str) -> bool {
    let diagnostics = peers.diagnostics().await;
    diagnostics
        .iter()
        .find(|peer| peer.node_id == peer_id)
        .is_some_and(|peer| {
            peer.direct_events
                .iter()
                .any(|event| event.stage == "fresh_mapping_model")
        })
}

#[tokio::test]
async fn consecutive_step3_generations_use_learned_stride() {
    let (peers, transport, nat) = learning_env(3).await;
    let _ = run_one(&transport, &nat).await;
    let _ = run_one(&transport, &nat).await;

    assert!(has_model_event(&peers, "peer-b").await, "an accepted generation must record a fresh_mapping_model event");
    let detail = last_model_detail(&peers, "peer-b")
        .await
        .expect("a fresh_mapping_model event must be recorded for an accepted generation");
    // The cross-batch EWMA learner (fed the step-3 deltas of the first batch)
    // reports stride 3 and is used by the second batch.
    assert!(
        detail.contains("step_estimate=Some(3)"),
        "the second generation must carry the learned step_estimate=3, got: {detail}"
    );
    assert!(
        detail.contains("learner_used=true"),
        "a valid learned stride within the max-abs-step bound must be used, got: {detail}"
    );
    assert!(
        detail.contains("direction_pattern=forward"),
        "an increasing allocation must be classified forward, got: {detail}"
    );
}

#[tokio::test]
async fn reverse_allocation_widens_prediction_window() {
    // Plain baseline: two step-1 generations. The second uses the learned
    // stride but does NOT widen (direction is forward), so its candidate count
    // is the 95-confidence base window (6).
    let (plain_peers, plain_transport, plain_nat) = learning_env(1).await;
    let _ = run_one(&plain_transport, &plain_nat).await;
    let _ = run_one(&plain_transport, &plain_nat).await;
    let plain_detail = last_model_detail(&plain_peers, "peer-b")
        .await
        .expect("baseline fresh_mapping_model event");
    let plain_count = predicted_port_count(&plain_detail);
    assert_eq!(
        plain_count, 6,
        "a 95-confidence forward fixed step has a 6-wide base window, got: {plain_detail}"
    );

    // Reverse allocation (step -1 -> FixedStep{-1}, conf 95, base 6). The
    // detector reads direction=reverse and the predictor widens one tier (6 ->
    // 12), still under the cap.
    let (reverse_peers, reverse_transport, reverse_nat) = learning_env(-1).await;
    let _ = run_one(&reverse_transport, &reverse_nat).await;
    let _ = run_one(&reverse_transport, &reverse_nat).await;
    let reverse_detail = last_model_detail(&reverse_peers, "peer-b")
        .await
        .expect("reverse fresh_mapping_model event");
    assert!(
        reverse_detail.contains("direction_pattern=reverse"),
        "a decreasing allocation must be classified reverse, got: {reverse_detail}"
    );
    let reverse_count = predicted_port_count(&reverse_detail);
    assert!(
        reverse_count > plain_count,
        "reverse allocation must widen the candidate window above the no-learning baseline ({reverse_count} vs {plain_count}), got: {reverse_detail}"
    );
    assert!(
        reverse_count <= p2pnet_nat::MAX_PREDICTED_PORTS,
        "the widened window must respect the wire cap, got: {reverse_count}"
    );
}

/// Parse the `predicted=[...]` tail of a `fresh_mapping_model` detail string
/// into its element count (the number of candidate ports advertised).
fn predicted_port_count(detail: &str) -> usize {
    let predicted = detail
        .split("predicted=")
        .last()
        .expect("detail must carry a predicted= field");
    let inner = predicted.trim_start_matches('[').trim_end_matches(']');
    if inner.is_empty() {
        0
    } else {
        inner.split(',').count()
    }
}

#[tokio::test]
async fn network_generation_change_resets_learning_cache() {
    let (peers, transport, nat) = learning_env(3).await;
    let initial_generation = peers.current_network_generation().await;
    // The generation observes the step-3 allocation, populating the cache.
    let _ = run_one(&transport, &nat).await;
    assert!(
        transport
            .has_learning_for(LEARNER_NAT_IP, initial_generation)
            .await,
        "the learner must hold state for the observed public IP before the change"
    );

    // A network-generation advance resets the cache: reading it at the new
    // generation finds no learned state (the estimate is back to None).
    let new_generation = peers
        .advance_network_generation("r2 reset test")
        .await;
    assert_eq!(new_generation, initial_generation + 1);
    assert!(
        !transport
            .has_learning_for(LEARNER_NAT_IP, new_generation)
            .await,
        "a generation change must clear the learned stride/direction"
    );
}

#[tokio::test]
async fn peer_scope_direction_overrides_stun_prior_and_is_isolated() {
    // P1-B: STUN-only learning observes the +step allocator direction.  Once
    // the REAL peer's mapping is observed on the wire walking the other way, the
    // peer-scope direction must become authoritative for that peer — and it must
    // not contaminate the shared STUN scope (other peers still use the prior).
    let (peers, transport, nat) = learning_env(3).await;
    let generation = peers.current_network_generation().await;
    // Feed the STUN scope once (learns forward / +3 from the simulated NAT).
    let _ = run_one(&transport, &nat).await;

    // Observe the peer's real mapping walking DOWN: reverse direction, unique
    // to this peer.  The peer scope must classify it Reverse while the STUN
    // scope stays Forward.
    transport
        .observe_peer_scope("peer-b", 5000, generation)
        .await;
    transport
        .observe_peer_scope("peer-b", 4990, generation)
        .await;
    transport
        .observe_peer_scope("peer-b", 4980, generation)
        .await;

    let peer_snapshot = transport
        .peer_learning_snapshot("peer-b", generation)
        .await
        .expect("peer scope must have learned evidence");
    assert_eq!(
        peer_snapshot.direction,
        DirectionPattern::Reverse,
        "the observed peer direction must override the STUN prior for that peer"
    );

    // Isolation: a different peer has no peer-scope evidence, so its snapshot
    // is None (falls back to the STUN prior, which stays Forward).
    assert!(
        transport
            .peer_learning_snapshot("peer-c", generation)
            .await
            .is_none(),
        "a peer with no observed mapping must have no peer-scope evidence"
    );
}
