#[test]
fn doctor_formats_direct_health_and_retry_backoff() {
    let snapshot = serde_json::json!({
        "peers": [{
            "node_id": "peer1",
            "device_name": "laptop",
            "virtual_ip": "10.20.0.5",
            "direct_retry_after_ms": 10000,
            "direct_retry_remaining_ms": 4200,
            "direct": {
                "success_count": 3,
                "failure_count": 2,
                "rtt_ewma_ms": 18,
                "jitter_ms": 5
            }
        }]
    });
    let peer = &snapshot["peers"][0];

    assert_eq!(
        direct_health_summary(peer).as_deref(),
        Some("success=3 failure=2 rtt_ewma=18ms jitter=5ms")
    );
    assert_eq!(
        direct_retry_summary(peer).as_deref(),
        Some("next_probe_in=4200ms backoff=10000ms")
    );
}

#[test]
fn doctor_formats_selected_pair_consent_and_pair_backoff() {
    let snapshot = serde_json::json!({
        "peers": [{
            "node_id": "peer1",
            "device_name": "laptop",
            "virtual_ip": "10.20.0.5",
            "direct_type": "public_udp",
            "consent_endpoint": "8.8.8.8:12293",
            "selected_pair": {
                "local_endpoint": "192.168.1.10:51820",
                "remote_endpoint": "8.8.8.8:12293",
                "local_candidate_type": "host",
                "remote_candidate_type": "peer_reflexive",
                "pair_state": "degraded",
                "nominated": true,
                "selected": false,
                "rtt_ms": 18,
                "last_success_age_ms": 1200,
                "probe_due": false,
                "probe_retry_after_ms": 10000,
                "probe_retry_remaining_ms": 4200
            }
        }]
    });
    let peer = &snapshot["peers"][0];
    let summary = selected_pair_summary(peer).unwrap();

    assert!(summary.contains("consent=8.8.8.8:12293"));
    assert!(summary.contains("probe_due=false"));
    assert!(summary.contains("probe_retry_after=10000ms"));
    assert!(summary.contains("probe_retry_remaining=4200ms"));
}

#[test]
fn doctor_formats_recent_path_events() {
    let snapshot = serde_json::json!({
        "peers": [{
            "node_id": "peer1",
            "device_name": "laptop",
            "virtual_ip": "10.20.0.5",
            "path_events": [{
                "selected_age_ms": 250,
                "network_generation": 2,
                "previous_path": "relay",
                "selected_path": "direct",
                "direct_endpoint": "203.0.113.10:60207",
                "reason_code": "path_direct_confirmed",
                "reason": "direct UDP pair is confirmed; score=102",
                "direct_confirmed": true,
                "direct_score": {
                    "path": "direct",
                    "score": 102,
                    "reachable": true,
                    "reachability_score": 80,
                    "preference_score": 10,
                    "latency_score": 10,
                    "stability_score": 2,
                    "penalty_score": 0,
                    "reason": "reachable=true confirmed=true trial=true rtt=9ms jitter=0ms failures=0"
                },
                "relay_score": null
            }]
        }]
    });
    let peer = &snapshot["peers"][0];

    assert_eq!(
            path_event_summaries(peer, 3),
            vec!["age=250ms gen=2 relay->direct endpoint=203.0.113.10:60207 direct_score=102(reachable=true confirmed=true trial=true rtt=9ms jitter=0ms failures=0) relay_score=n/a code=path_direct_confirmed".to_string()]
        );
}

#[test]
fn doctor_formats_recent_direct_events() {
    let snapshot = serde_json::json!({
        "peers": [{
            "node_id": "peer1",
            "device_name": "laptop",
            "virtual_ip": "10.20.0.5",
            "direct_events": [{
                "age_ms": 120,
                "network_generation": 3,
                "stage": "punch_probes_sent",
                "endpoint": "203.0.113.10:60207",
                "candidate_count": 4,
                "sent_probes": 8,
                "detail": "sent 8 UDP punch probes across 4 candidates"
            }]
        }]
    });
    let peer = &snapshot["peers"][0];

    assert_eq!(
            direct_event_summaries(peer, 5),
            vec!["age=120ms gen=3 stage=punch_probes_sent endpoint=203.0.113.10:60207 candidates=4 probes=8 detail=sent 8 UDP punch probes across 4 candidates".to_string()]
        );
}

#[test]
fn doctor_reports_generation_reprobe_reason() {
    let snapshot = serde_json::json!({
        "network_generation": 4,
        "relay_selection": {
            "selected_region": "cn-east",
            "selected_endpoint": "relay.example.com:443"
        },
        "peers": [{
            "node_id": "peer1",
            "device_name": "phone-hotspot",
            "virtual_ip": "10.20.0.9",
            "state": "relay",
            "active_path": "relay",
            "direct_generation": 3,
            "candidates": ["198.51.100.20:45000"],
            "direct": {
                "last_error_code": "network_generation_changed",
                "last_error": "network_generation_changed: refreshed UDP candidates"
            }
        }]
    });
    let peer = &snapshot["peers"][0];

    assert_eq!(
            relay_path_reason(&snapshot, peer).as_deref(),
            Some("Direct 不可用：网络切换后 Direct 状态失效：network_generation_changed: refreshed UDP candidates")
        );
    let suggestions = peer_direct_suggestions(&snapshot);
    assert!(suggestions.iter().any(|item| item.contains("旧网络代际")));
}

#[test]
fn normalizes_control_url() {
    assert_eq!(
        normalize_control_server(" http://127.0.0.1:18080/// ").unwrap(),
        "http://127.0.0.1:18080"
    );
    assert!(normalize_control_server("file:///tmp/control").is_err());
}

#[tokio::test]
async fn login_saves_token_from_control_server() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut request = vec![0_u8; 4096];
        let count = stream.read(&mut request).await.unwrap();
        let request = String::from_utf8_lossy(&request[..count]);
        assert!(request.starts_with("POST /api/v1/login "));
        assert!(request.contains("\"email\":\"user@example.com\""));
        let body = r#"{"success":true,"token":"test-token"}"#;
        let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                body.len(),
                body
            );
        stream.write_all(response.as_bytes()).await.unwrap();
    });
    let unique = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let directory = env::temp_dir().join(format!("p2wlan-cli-login-{unique}"));
    let path = directory.join("p2wlan-config.json");
    authenticate(
        &path,
        AuthArgs {
            username: "USER@example.com".to_string(),
            password: Some("password123".to_string()),
            server: Some(format!("http://{address}")),
        },
        false,
    )
    .await
    .unwrap();
    server.await.unwrap();

    let config = load_config(&path).unwrap();
    assert_eq!(config.control.auth_token, "test-token");
    assert_eq!(config.control.server_url, format!("http://{address}"));
    assert!(config.diagnostics.enabled);
    let _ = fs::remove_dir_all(directory);
}
