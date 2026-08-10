fn predicted_sources(candidates: &[&str]) -> HashMap<String, CandidatePairSource> {
    candidates
        .iter()
        .map(|candidate| (candidate.to_string(), CandidatePairSource::Predicted))
        .collect()
}

fn install_predicted_candidates(
    conn: &mut PeerConnection,
    candidates: &[&str],
    generation: u64,
) {
    conn.candidate_sources = predicted_sources(candidates);
    conn.candidates = candidates.iter().map(|c| c.to_string()).collect();
    for (rank, candidate) in candidates.iter().enumerate() {
        let endpoint: SocketAddr = candidate.parse().unwrap();
        let pair = conn.ensure_candidate_pair_with_source(
            endpoint,
            generation,
            CandidatePairSource::Predicted,
        );
        pair.signal_rank = Some(rank as u32);
    }
}

#[test]
fn predicted_candidates_probe_in_signal_rank_order_not_port_order() {
    // The stable side must probe the sender's predicted window in signal
    // order: top-1 (45394) before the successor (45393), even though 45393
    // sorts first numerically.
    let mut conn = PeerConnection::new("peer-b", "10.20.0.2");
    let generation = 0;
    install_predicted_candidates(
        &mut conn,
        &["220.163.6.190:45394", "220.163.6.190:45393", "220.163.6.190:45395"],
        generation,
    );

    let history = TraversalHistory::default();
    let (endpoints, _plan) = conn.candidate_probe_endpoints(
        generation,
        &history,
        None,
        ProbeTargetMode::Synchronized,
        None,
    );
    assert_eq!(endpoints.len(), 3);
    assert_eq!(
        endpoints[0].port(),
        45394,
        "top-1 must be probed first; got {:?}",
        endpoints
    );
    assert_eq!(endpoints[1].port(), 45393);
    assert_eq!(endpoints[2].port(), 45395);
}

#[test]
fn explicit_predicted_window_defers_birthday_fallback() {
    // With an explicit predicted window that has not failed yet, the stable
    // side must NOT generate a birthday sweep: model + small window first.
    let mut conn = PeerConnection::new("peer-b", "10.20.0.2");
    let generation = 0;
    install_predicted_candidates(
        &mut conn,
        &["220.163.6.190:45393", "220.163.6.190:45394", "220.163.6.190:45395"],
        generation,
    );
    // The peer also advertised a STUN-observed base, which anchors the
    // birthday sweep once the predicted window fails.
    conn.candidates.push("220.163.6.190:27676".to_string());
    conn.candidate_sources
        .insert("220.163.6.190:27676".to_string(), CandidatePairSource::StunObserved);
    let base: SocketAddr = "220.163.6.190:27676".parse().unwrap();
    conn.ensure_candidate_pair_with_source(base, generation, CandidatePairSource::StunObserved);
    let mut birthday_profile = NatProfile {
        local_addr: "0.0.0.0:0".to_string(),
        observations: Vec::new(),
        udp_blocked: false,
        public_endpoint: Some("203.0.113.10:40000".to_string()),
        public_ip_stable: Some(true),
        public_port_stable: Some(true),
        port_preserved: Some(false),
        port_delta: None,
        likely_symmetric: Some(false),
        mapping_behavior: MappingBehavior::EndpointIndependent,
        filtering_behavior: p2pnet_nat::FilteringBehavior::Unknown,
        hairpin_behavior: p2pnet_nat::HairpinBehavior::Unknown,
        mapping_lifetime: p2pnet_nat::MappingLifetime::Unknown,
        prediction_candidate: false,
        predicted_endpoints: Vec::new(),
        birthday_candidate: true,
        confidence: 90,
    };
    let _ = &mut birthday_profile;

    let history = TraversalHistory::default();
    let (endpoints, plan) = conn.candidate_probe_endpoints(
        generation,
        &history,
        Some(&birthday_profile),
        ProbeTargetMode::Synchronized,
        None,
    );
    assert!(
        plan.is_none(),
        "birthday must be deferred while the predicted window is live"
    );
    // 3 predicted candidates + the STUN-observed base.
    assert_eq!(endpoints.len(), 4);

    // After every predicted candidate has failed, the birthday fallback may
    // engage (local NAT is not hard).
    conn.mark_current_candidate_pairs_failed(
        generation,
        "predicted_window_missed",
        "predicted window missed",
        None,
    );
    let (endpoints, plan) = conn.candidate_probe_endpoints(
        generation,
        &history,
        Some(&birthday_profile),
        ProbeTargetMode::Synchronized,
        None,
    );
    assert!(!endpoints.is_empty());
    assert!(
        plan.is_some(),
        "birthday fallback after predicted window failed"
    );
}
