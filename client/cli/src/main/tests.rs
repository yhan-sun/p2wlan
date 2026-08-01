use super::*;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

#[test]
fn parses_login_short_options() {
    let cli = Cli::try_parse_from([
        "p2wlan",
        "login",
        "-u",
        "you@example.com",
        "-p",
        "password123",
    ])
    .unwrap();
    let Commands::Login(args) = cli.command else {
        panic!("expected login command");
    };
    assert_eq!(args.username, "you@example.com");
    assert_eq!(args.password.as_deref(), Some("password123"));
}

#[test]
fn parses_help_subcommand_without_side_effects() {
    let error = Cli::try_parse_from(["p2wlan", "help"]).unwrap_err();
    assert_eq!(error.kind(), clap::error::ErrorKind::DisplayHelp);
}

#[test]
fn parses_update_options() {
    let cli = Cli::try_parse_from([
        "p2wlan",
        "update",
        "--dry-run",
        "--version",
        "v0.1.27",
        "--install-dir",
        "/tmp/bin",
    ])
    .unwrap();
    let Commands::Update(args) = cli.command else {
        panic!("expected update command");
    };
    assert!(args.dry_run);
    assert_eq!(args.version.as_deref(), Some("v0.1.27"));
    assert_eq!(args.install_dir.as_deref(), Some(Path::new("/tmp/bin")));
}

#[test]
fn relay_health_summary_reports_runtime_measurements() {
    let relay = serde_json::json!({
        "selected_pong_count": 3,
        "selected_error_count": 1,
        "selected_last_pong_age_ms": 250,
        "selected_last_pong_rtt_ms": 42,
        "selected_rtt_ewma_ms": 39,
        "selected_jitter_ms": 5
    });

    assert_eq!(
        relay_health_summary(&relay).as_deref(),
        Some("pong=3 errors=1 last_rtt=42ms rtt_ewma=39ms jitter=5ms last_pong=250ms_ago")
    );
}

#[test]
fn relay_cooldown_summary_reports_skipped_candidates() {
    let relay = serde_json::json!({
        "candidates": [{
            "region": "cn-east",
            "endpoint": "relay-a.example.com:443",
            "cooldown_remaining_ms": 8_500,
            "error_code": "cooling_down"
        }, {
            "region": "cn-south",
            "endpoint": "relay-b.example.com:443",
            "error_code": null
        }]
    });

    assert_eq!(
        relay_cooldown_summaries(&relay),
        vec!["region=cn-east endpoint=relay-a.example.com:443 remaining=8500ms".to_string()]
    );
}

#[test]
fn mtu_profile_describes_common_ranges() {
    assert_eq!(mtu_profile(1279), "low (<1280, compatibility workaround)");
    assert_eq!(mtu_profile(1280), "relay-safe");
    assert_eq!(mtu_profile(1380), "relay-safe");
    assert_eq!(mtu_profile(1420), "default");
    assert_eq!(mtu_profile(1500), "high");
    assert_eq!(mtu_profile(9000), "jumbo/high-risk");
}

#[test]
fn mtu_suggestions_warn_for_high_and_relay_paths() {
    assert!(mtu_config_suggestions(1420).is_empty());
    assert!(mtu_config_suggestions(1200)
        .iter()
        .any(|item| item.contains("低于 1280")));
    assert!(mtu_config_suggestions(1501)
        .iter()
        .any(|item| item.contains("超过常见以太网 1500")));

    let relay_stats = serde_json::json!({
        "direct_connections": 0,
        "relay_connections": 2
    });
    assert!(mtu_runtime_suggestions(1420, &relay_stats)
        .iter()
        .any(|item| item.contains("Relay 路径") && item.contains("1380")));
    assert!(mtu_runtime_suggestions(1380, &relay_stats).is_empty());
}

#[test]
fn protocol_boundary_helpers_explain_runtime_contract() {
    let snapshot = serde_json::json!({
        "protocol": {
            "data_plane": "wireguard_like_noise",
            "handshake": "Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s",
            "aead": "ChaCha20-Poly1305",
            "wireguard_interop": false,
            "turn_compatible": false,
            "security_audit": "not_completed"
        }
    });

    assert_eq!(
            protocol_boundary_summary(&snapshot).as_deref(),
            Some("wireguard_like_noise handshake=Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s aead=ChaCha20-Poly1305 wg-interop=no turn=no audit=not_completed")
        );
    let suggestions = protocol_boundary_suggestions(&snapshot);
    assert!(suggestions
        .iter()
        .any(|item| item.contains("协议安全审计未完成")));
    assert!(suggestions
        .iter()
        .any(|item| item.contains("不是官方 WireGuard 互通实现")));
    assert!(protocol_boundary_summary(&serde_json::json!({})).is_none());
    assert!(protocol_boundary_suggestions(&serde_json::json!({})).is_empty());
}

#[test]
fn runtime_mtu_helpers_report_daemon_profile_and_config_drift() {
    let snapshot = serde_json::json!({
        "mtu": {
            "configured_mtu": 1420,
            "profile": "default",
            "relay_safe_mtu": 1380,
            "automatic_pmtu": false
        }
    });

    assert_eq!(
        runtime_mtu_summary(&snapshot).as_deref(),
        Some("configured=1420 profile=default relay-safe=1380 auto-pmtu=no")
    );
    assert!(mtu_snapshot_suggestions(1420, &snapshot).is_empty());
    assert!(mtu_snapshot_suggestions(1380, &snapshot)
        .iter()
        .any(|item| item.contains("daemon 运行中 MTU 为 1420")));
    assert!(runtime_mtu_summary(&serde_json::json!({})).is_none());
}

#[test]
fn runtime_mtu_helpers_use_structured_risks_when_present() {
    let snapshot = serde_json::json!({
        "mtu": {
            "configured_mtu": 1420,
            "profile": "default",
            "relay_safe_mtu": 1380,
            "automatic_pmtu": false,
            "relay_path_observed": true,
            "suggested_safe_mtu": 1380,
            "risks": [{
                "code": "relay_path_high_mtu",
                "severity": "warning",
                "message": "Relay path observed with MTU 1420; try lowering MTU.",
                "suggested_mtu": 1380
            }]
        }
    });

    assert_eq!(
            runtime_mtu_summary(&snapshot).as_deref(),
            Some("configured=1420 profile=default relay-safe=1380 auto-pmtu=no relay-path=yes suggested=1380 risks=relay_path_high_mtu")
        );
    assert!(mtu_diagnostic_suggestions(&snapshot)
        .iter()
        .any(|item| item.contains("p2wlan config set mtu 1380")));
    assert!(mtu_diagnostic_suggestions(&serde_json::json!({})).is_empty());
}

#[test]
fn nat_profile_summary_formats_stable_mapping() {
    let snapshot = serde_json::json!({
        "local_candidates": ["192.168.2.4:60207", "203.0.113.10:62000"],
        "nat_profile": {
            "mapping_behavior": "endpoint_independent",
            "filtering_behavior": "unknown",
            "hairpin_behavior": "unknown",
            "mapping_lifetime": { "lower_bound_ms": 250 },
            "udp_blocked": false,
            "public_endpoint": "203.0.113.10:62000",
            "likely_symmetric": false,
            "port_preserved": false,
            "prediction_candidate": false,
            "predicted_endpoints": [],
            "birthday_candidate": false,
            "confidence": 70,
            "observations": [{
                "server": "stun-a.example:3478",
                "mapped_address": "203.0.113.10:62000",
                "rtt_ms": 12,
                "error": null
            }, {
                "server": "stun-b.example:3478",
                "mapped_address": "203.0.113.10:62000",
                "rtt_ms": 18,
                "error": null
            }, {
                "server": "stun-c.example:3478",
                "mapped_address": null,
                "rtt_ms": null,
                "error": "timeout"
            }]
        }
    });

    assert_eq!(
            nat_profile_summary(&snapshot).as_deref(),
            Some("mapping=endpoint_independent filtering=unknown hairpin=unknown lifetime=lower_bound_ms=250 public=203.0.113.10:62000 stun=2/3 confidence=70 symmetric=false port_preserved=false prediction=false predicted=0 birthday=false")
        );
    assert_eq!(
        stun_observation_summaries(&snapshot, 2),
        vec![
            "server=stun-a.example:3478 mapped=203.0.113.10:62000 rtt=12ms".to_string(),
            "server=stun-b.example:3478 mapped=203.0.113.10:62000 rtt=18ms".to_string(),
        ]
    );
    let suggestions = nat_profile_suggestions(&snapshot, false);
    assert!(suggestions
        .iter()
        .any(|item| item.contains("公网 UDP 映射稳定")));
    assert!(suggestions
        .iter()
        .any(|item| item.contains("稳定 STUN 端口不等于可接收陌生入站包")));

    let with_gateway_mapping = serde_json::json!({
        "local_candidates": ["192.168.2.4:60207", "203.0.113.10:62000", "203.0.113.10:60207"],
        "gateway_mapping": {
            "candidate_endpoint": "203.0.113.10:60207",
            "candidate_source": "pcp"
        },
        "nat_profile": {
            "mapping_behavior": "endpoint_independent",
            "filtering_behavior": "unknown",
            "hairpin_behavior": "unknown",
            "mapping_lifetime": "unknown",
            "udp_blocked": false,
            "public_endpoint": "203.0.113.10:62000",
            "likely_symmetric": false,
            "port_preserved": false,
            "prediction_candidate": false,
            "predicted_endpoints": [],
            "birthday_candidate": false,
            "confidence": 70,
            "observations": []
        }
    });
    assert!(!nat_profile_suggestions(&with_gateway_mapping, false)
        .iter()
        .any(|item| item.contains("稳定 STUN 端口不等于")));
}

#[test]
fn udp_socket_pool_summary_includes_activation_and_per_socket_counters() {
    let snapshot = serde_json::json!({
        "udp_socket_count": 3,
        "udp_socket_pool_active": true,
        "udp_socket_pool": [{
            "socket_index": 0,
            "probes_sent": 12,
            "probe_acks_received": 2,
            "probe_acks_sent": 3,
            "encrypted_packets_sent": 4,
            "encrypted_packets_received": 5
        }, {
            "socket_index": 1,
            "probes_sent": 12,
            "probe_acks_received": 1,
            "probe_acks_sent": 0,
            "encrypted_packets_sent": 2,
            "encrypted_packets_received": 1
        }]
    });

    assert_eq!(
        udp_socket_pool_summary(&snapshot).as_deref(),
        Some("sockets=3 active #0 p=12 ack=2/3 stun=0 enc=4/5 #1 p=12 ack=1/0 stun=0 enc=2/1")
    );
}

#[test]
fn stun_config_summary_and_suggestions_explain_observer_quality() {
    assert_eq!(stun_config_summary(&[]), "default public STUN set");
    assert!(stun_config_suggestions(&[]).is_empty());

    let disabled = vec!["off".to_string()];
    assert_eq!(stun_config_summary(&disabled), "disabled");
    assert!(stun_config_suggestions(&disabled)
        .iter()
        .any(|item| item.contains("STUN 已禁用")));

    let single = vec!["stun.example.com:3478".to_string()];
    assert_eq!(
        stun_config_summary(&single),
        "1 configured (stun.example.com:3478)"
    );
    assert!(stun_config_suggestions(&single)
        .iter()
        .any(|item| item.contains("至少配置 2 个")));

    let multiple = vec![
        "stun-a.example.com:3478".to_string(),
        "stun-b.example.com:3478".to_string(),
    ];
    assert!(stun_config_suggestions(&multiple).is_empty());
}

#[test]
fn nat_profile_suggestions_explain_udp_blocked_and_symmetric() {
    let blocked = serde_json::json!({
        "local_candidates": ["192.168.2.4:60207"],
        "nat_profile": {
            "mapping_behavior": "udp_blocked",
            "filtering_behavior": "udp_blocked",
            "hairpin_behavior": "unknown",
            "mapping_lifetime": "unknown",
            "udp_blocked": true,
            "public_endpoint": null,
            "likely_symmetric": null,
            "port_preserved": null,
            "prediction_candidate": false,
            "birthday_candidate": false,
            "confidence": 60,
            "observations": [{
                "server": "stun-a.example:3478",
                "mapped_address": null,
                "rtt_ms": null,
                "error": "timeout"
            }]
        }
    });
    let suggestions = nat_profile_suggestions(&blocked, false);
    assert!(suggestions.iter().any(|item| item.contains("STUN 全失败")));
    assert!(suggestions
        .iter()
        .any(|item| item.contains("udp-advertise")));
    assert!(suggestions
        .iter()
        .any(|item| item.contains("只上报私网/回环")));

    let symmetric = serde_json::json!({
        "local_candidates": ["198.51.100.10:62000", "198.51.100.10:62008"],
        "nat_profile": {
            "mapping_behavior": "address_or_port_dependent",
            "filtering_behavior": "address_or_port_dependent",
            "hairpin_behavior": "unknown",
            "mapping_lifetime": "unknown",
            "udp_blocked": false,
            "public_endpoint": "198.51.100.10:62000",
            "likely_symmetric": true,
            "port_preserved": false,
            "prediction_candidate": true,
            "predicted_endpoints": ["198.51.100.10:62002"],
            "birthday_candidate": true,
            "confidence": 70,
            "observations": []
        }
    });
    let suggestions = nat_profile_suggestions(&symmetric, false);
    assert!(suggestions.iter().any(|item| item.contains("端口预测")));
    assert!(suggestions
        .iter()
        .any(|item| item.contains("受限端口预测 candidate")));
    assert!(suggestions.iter().any(|item| item.contains("稳定 delta")));
    assert!(suggestions
        .iter()
        .any(|item| item.contains("birthday probing")));
}

#[test]
fn candidate_pair_stats_summary_formats_source_rates() {
    let peer = serde_json::json!({
        "candidate_pair_stats": [{
            "source": "peer_reflexive",
            "success_count": 1,
            "failure_count": 1,
            "success_rate_per_mille": 500,
            "current_pair_count": 1
        }, {
            "source": "signaled",
            "success_count": 2,
            "failure_count": 0,
            "success_rate_per_mille": 1000,
            "current_pair_count": 2
        }, {
            "source": "predicted",
            "success_count": 1,
            "failure_count": 3,
            "success_rate_per_mille": 250,
            "current_pair_count": 4
        }]
    });

    assert_eq!(
            candidate_pair_stats_summary(&peer).as_deref(),
            Some("peer_reflexive=1/2:500‰,current=1 signaled=2/2:1000‰,current=2 predicted=1/4:250‰,current=4")
        );
}

#[test]
fn traversal_history_summary_formats_source_rates_and_cooldown() {
    let snapshot = serde_json::json!({
        "traversal_history": {
            "sources": [{
                "source": "predicted",
                "success_count": 2,
                "failure_count": 2,
                "success_rate_per_mille": 500,
                "cooldown_remaining_ms": null
            }, {
                "source": "birthday",
                "success_count": 0,
                "failure_count": 3,
                "success_rate_per_mille": 0,
                "cooldown_remaining_ms": 60000
            }]
        }
    });

    assert_eq!(
        traversal_history_summary(&snapshot).as_deref(),
        Some("predicted=2/4:500‰ birthday=0/3:0‰,cooldown=60000ms")
    );
}

#[test]
fn validates_and_sets_safe_config_values() {
    let mut config = Config::generate_default(DEFAULT_CONTROL_SERVER, DEFAULT_NETWORK).unwrap();
    set_config_value(&mut config, "mtu", "1380").unwrap();
    set_config_value(&mut config, "relay-policy", "relay").unwrap();
    set_config_value(&mut config, "device-name", "linux-server").unwrap();
    set_config_value(&mut config, "udp-bind", "0.0.0.0:60207").unwrap();
    set_config_value(&mut config, "udp-advertise", "203.0.113.10:60207").unwrap();
    set_config_value(
        &mut config,
        "stun",
        "stun.l.google.com:19302,stun.example.com:19302",
    )
    .unwrap();
    set_config_value(&mut config, "direct-timeout", "7000ms").unwrap();
    set_config_value(&mut config, "upnp", "off").unwrap();
    set_config_value(&mut config, "birthday-probing", "no").unwrap();
    set_config_value(&mut config, "socket-pool", "3").unwrap();
    assert_eq!(config.network.mtu, 1380);
    assert!(!config.relay.prefer_direct);
    assert_eq!(config.node.device_name, "linux-server");
    assert_eq!(config.network.udp_bind, "0.0.0.0:60207");
    assert_eq!(
        config.network.udp_advertise.as_deref(),
        Some("203.0.113.10:60207")
    );
    assert_eq!(config.network.stun_servers.len(), 2);
    assert_eq!(config.network.stun_servers[0], "stun.l.google.com:19302");
    assert_eq!(config.relay.fallback_timeout_ms, 7000);
    assert!(!config.network.upnp_enabled);
    assert!(!config.network.birthday_probing_enabled);
    assert!(config.network.socket_pool_enabled);
    assert_eq!(config.network.socket_pool_size, 3);
    set_config_value(&mut config, "socket-pool", "off").unwrap();
    assert!(!config.network.socket_pool_enabled);
    assert_eq!(config.network.socket_pool_size, 1);
    set_config_value(&mut config, "udp-advertise", "off").unwrap();
    assert!(config.network.udp_advertise.is_none());
    set_config_value(&mut config, "stun", "off").unwrap();
    assert_eq!(config.network.stun_servers, vec!["off".to_string()]);
    assert!(set_config_value(&mut config, "mtu", "10").is_err());
    assert!(set_config_value(&mut config, "udp-advertise", "0.0.0.0:60207").is_err());
    assert!(set_config_value(&mut config, "diagnostics", "0.0.0.0:39277").is_err());
    assert!(set_config_value(&mut config, "auth-token", "secret").is_err());
}

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
