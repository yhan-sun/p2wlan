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

    let (candidates, sources) =
        build_fresh_mapping_signal_payload(&result, &current_candidates, &current_sources);

    assert_passes_control_plane_validation(&candidates, &sources);

    // Predicted ports are signaled first, in rank order (top-1 first).
    let predicted = candidates
        .iter()
        .filter(|candidate| sources.get(*candidate).map(String::as_str) == Some("predicted"))
        .collect::<Vec<_>>();
    assert_eq!(predicted.len(), 6);
    assert_eq!(predicted[0].parse::<SocketAddr>().unwrap().port(), 45393);
    assert_eq!(predicted[1].parse::<SocketAddr>().unwrap().port(), 45394);
    assert_eq!(predicted[5].parse::<SocketAddr>().unwrap().port(), 45398);

    // No reserved metadata keys exist in the payload.
    assert!(
        !sources.keys().any(|key| key.starts_with("__p2wlan")),
        "payload must not carry reserved metadata keys"
    );
}

#[test]
fn fresh_mapping_signal_payload_without_public_ip_falls_back_to_unspecified_ip() {
    let mut result = sample_result();
    result.public_ip = None;
    let (candidates, _sources) =
        build_fresh_mapping_signal_payload(&result, &[], &HashMap::new());
    let first: SocketAddr = candidates[0].parse().unwrap();
    assert_eq!(first.port(), 45393);
}
