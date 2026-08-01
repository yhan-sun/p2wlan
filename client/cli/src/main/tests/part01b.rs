#[test]
fn doctor_suggests_udp_advertise_for_private_only_peer_candidates() {
    let snapshot = serde_json::json!({
        "peers": [{
            "node_id": "peer1",
            "device_name": "windows-cloud",
            "virtual_ip": "10.20.0.5",
            "endpoint": "192.168.2.4:49877",
            "candidates": ["192.168.2.4:49877", "127.0.0.1:60207"],
            "direct": { "last_error": "no UDP punch ACK after 30 probes" }
        }]
    });
    let suggestions = peer_direct_suggestions(&snapshot);
    assert_eq!(suggestions.len(), 1);
    assert!(suggestions[0].contains("windows-cloud(10.20.0.5)"));
    assert!(suggestions[0].contains("udp-advertise"));
}

#[test]
fn doctor_does_not_flag_peer_with_public_candidate_as_private_only() {
    let snapshot = serde_json::json!({
        "peers": [{
            "node_id": "peer1",
            "device_name": "linux-server",
            "virtual_ip": "10.20.0.7",
            "endpoint": "203.0.113.10:60207",
            "candidates": ["203.0.113.10:60207"],
            "direct": { "last_error": "no direct probe ACK after 6 retry probes" }
        }]
    });
    let suggestions = peer_direct_suggestions(&snapshot);
    assert_eq!(suggestions.len(), 1);
    assert!(suggestions[0].contains("Direct UDP 探测失败"));
    assert!(!suggestions[0].contains("只上报了私网/回环"));
}

#[test]
fn doctor_explains_public_stun_candidate_without_open_ingress() {
    let snapshot = serde_json::json!({
        "peers": [{
            "node_id": "peer1",
            "device_name": "home-router-peer",
            "virtual_ip": "10.20.0.8",
            "endpoint": "203.0.113.10:62000",
            "candidates": ["203.0.113.10:62000"],
            "candidate_pairs": [{
                "remote_endpoint": "203.0.113.10:62000",
                "remote_candidate_type": "stun_observed",
                "remote_source": "stun_observed"
            }],
            "direct": { "last_error": "no direct probe ACK after 6 retry probes" }
        }]
    });
    let suggestions = peer_direct_suggestions(&snapshot);
    assert_eq!(suggestions.len(), 1);
    assert!(suggestions[0].contains("home-router-peer(10.20.0.8)"));
    assert!(suggestions[0].contains("公网 STUN 映射稳定不代表 NAT 过滤开放"));
    assert!(suggestions[0].contains("UPnP/PCP/NAT-PMP"));
}

#[test]
fn doctor_explains_relay_reason_with_stable_reason_code() {
    let snapshot = serde_json::json!({
        "network_generation": 3,
        "relay_selection": {
            "selected_region": "cn-east",
            "selected_endpoint": "relay.example.com:443",
            "selected_connect_latency_ms": 42,
            "candidates": []
        },
        "peers": [{
            "node_id": "peer1",
            "device_name": "laptop",
            "virtual_ip": "10.20.0.5",
            "state": "fallback_to_relay",
            "active_path": "relay",
            "direct_generation": 3,
            "candidates": ["203.0.113.10:60207"],
            "direct": {
                "last_error_code": "handshake_timeout",
                "last_error": "handshake timed out"
            }
        }]
    });
    let peer = &snapshot["peers"][0];

    assert_eq!(
        direct_failure_stage(peer).as_deref(),
        Some("WireGuard 握手超时：handshake timed out")
    );
    assert_eq!(
        relay_path_reason(&snapshot, peer).as_deref(),
        Some("Direct 不可用：WireGuard 握手超时：handshake timed out")
    );
    let suggestions = peer_direct_suggestions(&snapshot);
    assert!(suggestions
        .iter()
        .any(|item| item.contains("WireGuard 握手超时")));
}

#[test]
fn doctor_prefers_explicit_path_selection_reason() {
    let snapshot = serde_json::json!({
        "network_generation": 3,
        "relay_selection": {
            "selected_region": "cn-east",
            "selected_endpoint": "relay.example.com:443"
        },
        "peers": [{
            "node_id": "peer1",
            "device_name": "laptop",
            "virtual_ip": "10.20.0.5",
            "state": "relay",
            "active_path": "relay",
            "direct_generation": 3,
            "candidates": [],
            "current_path_selection": {
                "path": "relay",
                "direct_endpoint": null,
                "reason_code": "path_direct_no_endpoint",
                "reason": "direct UDP has no candidate endpoint",
                "direct_confirmed": false,
                "direct_score": null,
                "relay_score": {
                    "path": "relay",
                    "score": 55,
                    "reachable": true,
                    "reachability_score": 55,
                    "preference_score": 0,
                    "latency_score": 0,
                    "stability_score": 0,
                    "penalty_score": 0,
                    "reason": "relay_available=true rtt=unknown jitter=unknown failures=0"
                }
            },
            "direct": {
                "last_error_code": "handshake_timeout",
                "last_error": "old direct failure"
            }
        }]
    });
    let peer = &snapshot["peers"][0];

    assert_eq!(
            path_selection_summary(peer, "current_path_selection").as_deref(),
            Some("path=relay endpoint=(none) confirmed=false direct_score=n/a relay_score=55(relay_available=true rtt=unknown jitter=unknown failures=0) code=path_direct_no_endpoint reason=direct UDP has no candidate endpoint")
        );
    assert_eq!(
            relay_path_reason(&snapshot, peer).as_deref(),
            Some("Path selector 选择 Relay：没有 Direct UDP endpoint（path_direct_no_endpoint）：direct UDP has no candidate endpoint")
        );
}
