// Fresh-mapping signal payload invariants.
//
// The Go control plane validates `candidate_sources` strictly: the map size
// must not exceed the candidate count, every key must be a real candidate,
// and every value must stay under 64 bytes.  These tests mirror that
// validation against the exact payload builder the daemon signals with, so
// a predicted-window offer can never be rejected with HTTP 400.

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};

fn sample_result() -> FreshMappingResult {
    FreshMappingResult {
        punch_generation: 7,
        network_generation: 3,
        socket_local_endpoint: "0.0.0.0:58980".parse().unwrap(),
        socket_index: 4096,
        model: p2pnet_nat::mapping::build_model(
            &[45390, 45391, 45392],
            Some(IpAddr::V4(Ipv4Addr::new(220, 163, 6, 190))),
            1000,
        ),
        predicted_ports: vec![45393, 45394, 45395, 45396, 45397, 45398],
        public_ip: Some(IpAddr::V4(Ipv4Addr::new(220, 163, 6, 190))),
        first_punch_sent_at_ms: 1100,
        last_punch_sent_at_ms: 1120,
    }
}

/// Mirrors `server/api/signal_handlers.go` validation for `candidate_sources`.
fn assert_passes_control_plane_validation(candidates: &[String], sources: &HashMap<String, String>) {
    assert!(
        sources.len() <= candidates.len(),
        "too many candidate sources: {} > {}",
        sources.len(),
        candidates.len()
    );
    let candidate_set: std::collections::HashSet<&String> = candidates.iter().collect();
    for (endpoint, source) in sources {
        assert!(
            candidate_set.contains(endpoint),
            "candidate source references unknown candidate: {endpoint}"
        );
        assert!(
            endpoint.len() <= 256,
            "candidate source endpoint too long: {}",
            endpoint.len()
        );
        assert!(
            source.len() <= 64,
            "candidate source value too long: {} bytes",
            source.len()
        );
    }
    for (index, candidate) in candidates.iter().enumerate() {
        assert!(candidate.len() <= 256, "candidate {index} too long");
    }
}

#[test]
fn fresh_mapping_signal_payload_passes_control_plane_validation() {
    let result = sample_result();
    let current_candidates = vec![
        "192.168.2.10:58980".to_string(),
        "220.163.6.190:45388".to_string(),
    ];
    let mut current_sources = HashMap::new();
    current_sources.insert(
        "192.168.2.10:58980".to_string(),
        "host".to_string(),
    );
    current_sources.insert(
        "220.163.6.190:45388".to_string(),
        "stun_observed".to_string(),
    );

    let (candidates, sources) = build_fresh_mapping_signal_payload(
        &result,
        1_742_987_654_321,
        &current_candidates,
        &current_sources,
    );

    assert_passes_control_plane_validation(&candidates, &sources);

    // Predicted ports are signaled first, in rank order (top-1 first), with
    // the distinct fresh-prediction label carrying the punch generation.
    let predicted = candidates
        .iter()
        .filter(|candidate| {
            sources
                .get(*candidate)
                .is_some_and(|source| source.starts_with(FRESH_PREDICTION_SOURCE_LABEL_PREFIX))
        })
        .collect::<Vec<_>>();
    assert_eq!(predicted.len(), 6);
    assert_eq!(predicted[0].parse::<SocketAddr>().unwrap().port(), 45393);
    assert_eq!(predicted[1].parse::<SocketAddr>().unwrap().port(), 45394);
    assert_eq!(predicted[5].parse::<SocketAddr>().unwrap().port(), 45398);
    for endpoint in &predicted {
        let label = sources.get(*endpoint).expect("predicted endpoint source");
        assert_eq!(
            label,
            &fresh_prediction_source_label(FreshPredictionId {
                boot_epoch: 1_742_987_654_321,
                generation: result.punch_generation,
            })
        );
    }

    // No reserved metadata keys exist in the payload.
    assert!(
        !sources.keys().any(|key| key.starts_with("__p2wlan")),
        "payload must not carry reserved metadata keys"
    );
}

#[test]
fn signal_candidate_contract_deduplicates_and_caps_all_birthday_levels() {
    for requested in [64usize, 128, 256] {
        let candidates = (0..requested)
            .map(|offset| format!("8.8.8.8:{}", 40_000 + offset))
            .collect::<Vec<_>>();
        let sources = candidates
            .iter()
            .map(|candidate| (candidate.clone(), "predicted".to_string()))
            .collect::<HashMap<_, _>>();

        let (effective, effective_sources, contract) =
            crate::candidate_refresh::normalize_signal_candidates(&candidates, &sources);
        let expected = requested.min(crate::MAX_SIGNAL_CANDIDATES);
        assert_eq!(effective.len(), expected);
        assert_eq!(contract.requested_candidate_count, requested);
        assert_eq!(contract.generated_candidate_count, requested);
        assert_eq!(contract.deduplicated_candidate_count, requested);
        assert_eq!(contract.signaled_candidate_count, expected);
        assert_eq!(contract.cap, crate::MAX_SIGNAL_CANDIDATES);
        assert_eq!(contract.capped, requested > crate::MAX_SIGNAL_CANDIDATES);
        assert!(effective_sources
            .keys()
            .all(|candidate| effective.contains(candidate)));
    }

    let duplicate = "8.8.4.4:41000".to_string();
    let mut candidates = vec![duplicate.clone(), duplicate.clone()];
    candidates.extend((0..62).map(|offset| format!("8.8.4.4:{}", 41_000 + offset)));
    let sources = candidates
        .iter()
        .map(|candidate| (candidate.clone(), "stun_observed".to_string()))
        .collect::<HashMap<_, _>>();
    let (effective, effective_sources, contract) =
        crate::candidate_refresh::normalize_signal_candidates(&candidates, &sources);
    assert_eq!(effective.len(), 62);
    assert_eq!(contract.deduplicated_candidate_count, 62);
    assert!(!contract.capped);
    assert_eq!(contract.reason, "deduplicated");
    assert_eq!(effective_sources.len(), effective.len());
}

#[test]
fn signal_payload_boundary_never_emits_more_than_server_cap() {
    let candidates = (0..256usize)
        .map(|offset| format!("8.8.8.8:{}", 42_000 + offset))
        .collect::<Vec<_>>();
    let sources = candidates
        .iter()
        .map(|candidate| (candidate.clone(), "birthday".to_string()))
        .collect::<HashMap<_, _>>();
    let payload = crate::control::prepare_signal_payload_for_test(
        "node-a",
        "node-b",
        "peer_offer_fresh",
        &candidates,
        &sources,
        b"handshake-bytes",
        Some(1_000),
        None,
        Some("session-1"),
        None,
        None,
    )
    .expect("signal payload must build");
    let json_candidates = payload["candidates"].as_array().unwrap();
    let json_sources = payload["candidate_sources"].as_object().unwrap();
    assert_eq!(json_candidates.len(), crate::MAX_SIGNAL_CANDIDATES);
    assert!(json_sources.len() <= json_candidates.len());
    assert!(json_sources.keys().all(|endpoint| {
        json_candidates
            .iter()
            .any(|candidate| candidate.as_str() == Some(endpoint))
    }));
}

#[test]
fn fresh_mapping_signal_payload_without_public_ip_falls_back_to_unspecified_ip() {
    let mut result = sample_result();
    result.public_ip = None;
    let (candidates, _sources) = build_fresh_mapping_signal_payload(
        &result,
        1_742_987_654_321,
        &[],
        &HashMap::new(),
    );
    let first: SocketAddr = candidates[0].parse().unwrap();
    assert_eq!(first.port(), 45393);
}
