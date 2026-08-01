//! Doctor/diagnostics output formatting: snapshot summarization helpers that
//! render NAT, relay, peer, traversal-history, MTU and UDP socket-pool state
//! into human-readable text. Split out of the CLI crate root.

use std::net::{IpAddr, SocketAddr};

use serde_json::Value;

use super::is_clear_value;

const IPV6_SAFE_MIN_MTU: u32 = 1280;
const RELAY_SAFE_MTU: u32 = 1380;
const WIREGUARD_STYLE_MTU: u32 = 1420;
const COMMON_ETHERNET_MTU: u32 = 1500;

pub(super) fn protocol_boundary_summary(snapshot: &Value) -> Option<String> {
    let protocol = snapshot.get("protocol")?.as_object()?;
    let data_plane = protocol
        .get("data_plane")
        .and_then(Value::as_str)
        .unwrap_or("unknown");
    let handshake = protocol
        .get("handshake")
        .and_then(Value::as_str)
        .unwrap_or("unknown");
    let aead = protocol
        .get("aead")
        .and_then(Value::as_str)
        .unwrap_or("unknown");
    let wireguard_interop = yes_no(
        protocol
            .get("wireguard_interop")
            .and_then(Value::as_bool)
            .unwrap_or(false),
    );
    let turn_compatible = yes_no(
        protocol
            .get("turn_compatible")
            .and_then(Value::as_bool)
            .unwrap_or(false),
    );
    let audit = protocol
        .get("security_audit")
        .and_then(Value::as_str)
        .unwrap_or("unknown");
    Some(format!(
        "{data_plane} handshake={handshake} aead={aead} wg-interop={wireguard_interop} turn={turn_compatible} audit={audit}"
    ))
}

pub(super) fn protocol_boundary_suggestions(snapshot: &Value) -> Vec<String> {
    let Some(protocol) = snapshot.get("protocol").and_then(Value::as_object) else {
        return Vec::new();
    };

    let mut suggestions = Vec::new();
    if protocol
        .get("security_audit")
        .and_then(Value::as_str)
        .is_some_and(|audit| audit != "completed")
    {
        suggestions.push(
            "协议安全审计未完成；发布 Production 前需要独立审计、威胁建模和互操作边界复核。"
                .to_string(),
        );
    }
    if protocol
        .get("wireguard_interop")
        .and_then(Value::as_bool)
        .is_some_and(|interop| !interop)
    {
        suggestions.push("当前数据面是 WireGuard-like Noise，不是官方 WireGuard 互通实现；文档和部署脚本应避免承诺 WireGuard 客户端兼容。".to_string());
    }
    suggestions
}

pub(super) fn runtime_mtu_summary(snapshot: &Value) -> Option<String> {
    let mtu = snapshot.get("mtu")?.as_object()?;
    let configured_mtu = mtu
        .get("configured_mtu")
        .and_then(Value::as_u64)
        .unwrap_or_default();
    let profile = mtu
        .get("profile")
        .and_then(Value::as_str)
        .unwrap_or("unknown");
    let relay_safe_mtu = mtu
        .get("relay_safe_mtu")
        .and_then(Value::as_u64)
        .unwrap_or(RELAY_SAFE_MTU as u64);
    let automatic_pmtu = yes_no(
        mtu.get("automatic_pmtu")
            .and_then(Value::as_bool)
            .unwrap_or(false),
    );
    let mut summary = format!(
        "configured={configured_mtu} profile={profile} relay-safe={relay_safe_mtu} auto-pmtu={automatic_pmtu}"
    );
    if let Some(relay_path_observed) = mtu.get("relay_path_observed").and_then(Value::as_bool) {
        summary.push_str(&format!(" relay-path={}", yes_no(relay_path_observed)));
    }
    if let Some(suggested) = mtu.get("suggested_safe_mtu").and_then(Value::as_u64) {
        summary.push_str(&format!(" suggested={suggested}"));
    }
    let risk_codes: Vec<&str> = mtu
        .get("risks")
        .and_then(Value::as_array)
        .map(|risks| {
            risks
                .iter()
                .filter_map(|risk| risk.get("code").and_then(Value::as_str))
                .collect()
        })
        .unwrap_or_default();
    if !risk_codes.is_empty() {
        summary.push_str(&format!(" risks={}", risk_codes.join(",")));
    }
    Some(summary)
}

pub(super) fn mtu_snapshot_suggestions(config_mtu: u32, snapshot: &Value) -> Vec<String> {
    let Some(runtime_mtu) = snapshot
        .get("mtu")
        .and_then(|mtu| mtu.get("configured_mtu"))
        .and_then(Value::as_u64)
    else {
        return Vec::new();
    };

    if runtime_mtu != config_mtu as u64 {
        vec![format!(
            "当前配置 MTU 为 {config_mtu}，daemon 运行中 MTU 为 {runtime_mtu}；执行 p2wlan down && p2wlan up 让配置生效。"
        )]
    } else {
        Vec::new()
    }
}

pub(super) fn mtu_diagnostic_suggestions(snapshot: &Value) -> Vec<String> {
    let Some(risks) = snapshot
        .get("mtu")
        .and_then(|mtu| mtu.get("risks"))
        .and_then(Value::as_array)
    else {
        return Vec::new();
    };

    let mut suggestions = Vec::new();
    for risk in risks {
        let Some(message) = risk.get("message").and_then(Value::as_str) else {
            continue;
        };
        if let Some(suggested_mtu) = risk.get("suggested_mtu").and_then(Value::as_u64) {
            suggestions.push(format!(
                "{message} 建议：p2wlan config set mtu {suggested_mtu}"
            ));
        } else {
            suggestions.push(message.to_string());
        }
    }
    dedupe_strings(suggestions)
}

fn yes_no(value: bool) -> &'static str {
    if value {
        "yes"
    } else {
        "no"
    }
}

pub(super) fn print_nat_diagnostics(snapshot: &Value) {
    let candidates = local_candidate_strings(snapshot);
    if !candidates.is_empty() {
        println!(
            "UDP candidates：{}{}",
            candidates.len(),
            endpoint_preview(&candidates, 4)
        );
    }

    if let Some(summary) = nat_profile_summary(snapshot) {
        println!("NAT：{summary}");
        for observation in stun_observation_summaries(snapshot, 3) {
            println!("STUN：{observation}");
        }
    } else {
        println!("NAT：未采集");
    }
}

pub(super) fn udp_socket_pool_summary(snapshot: &Value) -> Option<String> {
    let socket_count = snapshot.get("udp_socket_count")?.as_u64()?;
    let active = snapshot
        .get("udp_socket_pool_active")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let state = if active { "active" } else { "standby" };
    let members = snapshot
        .get("udp_socket_pool")
        .and_then(Value::as_array)
        .map(|members| {
            members
                .iter()
                .map(|member| {
                    format!(
                        "#{} p={} ack={}/{} stun={} enc={}/{}",
                        member
                            .get("socket_index")
                            .and_then(Value::as_u64)
                            .unwrap_or(0),
                        member
                            .get("probes_sent")
                            .and_then(Value::as_u64)
                            .unwrap_or(0),
                        member
                            .get("probe_acks_received")
                            .and_then(Value::as_u64)
                            .unwrap_or(0),
                        member
                            .get("probe_acks_sent")
                            .and_then(Value::as_u64)
                            .unwrap_or(0),
                        member
                            .get("stun_mappings_discovered")
                            .and_then(Value::as_u64)
                            .unwrap_or(0),
                        member
                            .get("encrypted_packets_sent")
                            .and_then(Value::as_u64)
                            .unwrap_or(0),
                        member
                            .get("encrypted_packets_received")
                            .and_then(Value::as_u64)
                            .unwrap_or(0),
                    )
                })
                .collect::<Vec<_>>()
                .join(" ")
        })
        .filter(|members| !members.is_empty());
    Some(match members {
        Some(members) => format!("sockets={socket_count} {state} {members}"),
        None => format!("sockets={socket_count} {state}"),
    })
}

pub(super) fn stun_config_summary(servers: &[String]) -> String {
    let configured = configured_stun_servers(servers);
    if servers.is_empty() {
        "default public STUN set".to_string()
    } else if configured.is_empty() {
        "disabled".to_string()
    } else {
        format!("{} configured ({})", configured.len(), configured.join(","))
    }
}

pub(super) fn stun_config_suggestions(servers: &[String]) -> Vec<String> {
    let configured = configured_stun_servers(servers);
    if !servers.is_empty() && configured.is_empty() {
        return vec![
            "STUN 已禁用；跨 NAT 直连将主要依赖手动 udp-advertise、端口映射或 Relay。".to_string(),
        ];
    }
    if configured.len() == 1 {
        return vec![
            "当前只配置了 1 个 STUN 观测点；建议至少配置 2 个不同网络的 STUN server，才能更可靠地区分端口相关/对称 NAT。"
                .to_string(),
        ];
    }
    Vec::new()
}

fn configured_stun_servers(servers: &[String]) -> Vec<String> {
    servers
        .iter()
        .map(|server| server.trim())
        .filter(|server| !is_clear_value(server))
        .map(ToString::to_string)
        .collect()
}

pub(super) fn nat_profile_summary(snapshot: &Value) -> Option<String> {
    let profile = snapshot.get("nat_profile")?.as_object()?;
    let mapping = profile
        .get("mapping_behavior")
        .and_then(Value::as_str)
        .unwrap_or("unknown");
    let filtering = profile
        .get("filtering_behavior")
        .and_then(Value::as_str)
        .unwrap_or("unknown");
    let hairpin = profile
        .get("hairpin_behavior")
        .and_then(Value::as_str)
        .unwrap_or("unknown");
    let lifetime = nat_lifetime_text(profile.get("mapping_lifetime"));
    let public_endpoint = profile
        .get("public_endpoint")
        .and_then(Value::as_str)
        .unwrap_or("(none)");
    let (stun_success, stun_total) = stun_observation_counts(snapshot);
    let confidence = profile
        .get("confidence")
        .and_then(Value::as_u64)
        .unwrap_or(0);
    let predicted = profile
        .get("predicted_endpoints")
        .and_then(Value::as_array)
        .map(Vec::len)
        .unwrap_or(0);
    Some(format!(
        "mapping={mapping} filtering={filtering} hairpin={hairpin} lifetime={lifetime} public={public_endpoint} stun={stun_success}/{stun_total} confidence={confidence} symmetric={} port_preserved={} prediction={} predicted={predicted} birthday={}",
        nat_bool_text(profile.get("likely_symmetric")),
        nat_bool_text(profile.get("port_preserved")),
        nat_bool_text(profile.get("prediction_candidate")),
        nat_bool_text(profile.get("birthday_candidate"))
    ))
}

pub(super) fn stun_observation_summaries(snapshot: &Value, limit: usize) -> Vec<String> {
    let Some(observations) = snapshot
        .get("nat_profile")
        .and_then(|profile| profile.get("observations"))
        .and_then(Value::as_array)
    else {
        return Vec::new();
    };

    observations
        .iter()
        .take(limit)
        .map(|observation| {
            let server = observation
                .get("server")
                .and_then(Value::as_str)
                .unwrap_or("unknown");
            if let Some(mapped) = observation.get("mapped_address").and_then(Value::as_str) {
                let rtt = observation
                    .get("rtt_ms")
                    .and_then(Value::as_u64)
                    .map(|ms| format!("{ms}ms"))
                    .unwrap_or_else(|| "unknown".to_string());
                format!("server={server} mapped={mapped} rtt={rtt}")
            } else {
                let error = observation
                    .get("error")
                    .and_then(Value::as_str)
                    .unwrap_or("unknown");
                format!("server={server} error={error}")
            }
        })
        .collect()
}

pub(super) fn nat_profile_suggestions(
    snapshot: &Value,
    udp_advertise_configured: bool,
) -> Vec<String> {
    let mut suggestions = Vec::new();
    let candidates = local_candidate_strings(snapshot);
    let has_public_candidate = candidates
        .iter()
        .filter_map(|candidate| candidate.parse::<SocketAddr>().ok())
        .any(|endpoint| is_public_udp_endpoint(&endpoint));

    let Some(profile) = snapshot.get("nat_profile").and_then(Value::as_object) else {
        if candidates.is_empty() {
            suggestions.push(
                "daemon 尚未采集到 UDP candidate/NAT profile；如果刚启动，请等待几秒或检查 STUN 配置。"
                    .to_string(),
            );
        }
        return suggestions;
    };

    if profile
        .get("udp_blocked")
        .and_then(Value::as_bool)
        .unwrap_or(false)
    {
        suggestions.push(
            "本机 STUN 全失败，可能 UDP 被防火墙、安全组、运营商或公司网络阻断；直连会高度依赖 Relay。"
                .to_string(),
        );
    }

    let mapping = profile
        .get("mapping_behavior")
        .and_then(Value::as_str)
        .unwrap_or("unknown");
    let likely_symmetric = profile
        .get("likely_symmetric")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    if likely_symmetric || mapping == "address_or_port_dependent" {
        suggestions.push(
            "本机疑似对称/地址端口相关 NAT；当前基础打洞成功率有限，后续应启用 peer-reflexive、端口预测和 birthday probing。"
                .to_string(),
        );
    }

    if profile
        .get("prediction_candidate")
        .and_then(Value::as_bool)
        .unwrap_or(false)
    {
        suggestions.push(
            "本机端口映射看起来有稳定 delta，可在后续启用受限端口预测来提高对称/地址相关 NAT 的打洞概率。"
                .to_string(),
        );
    }

    let predicted_count = profile
        .get("predicted_endpoints")
        .and_then(Value::as_array)
        .map(Vec::len)
        .unwrap_or(0);
    if predicted_count > 0 {
        suggestions.push(format!(
            "已生成 {predicted_count} 个受限端口预测 candidate；如果对端也有稳定 delta，可提高地址/端口相关 NAT 的命中率。"
        ));
    }

    if profile
        .get("birthday_candidate")
        .and_then(Value::as_bool)
        .unwrap_or(false)
    {
        suggestions.push(
            "本机适合作为 birthday probing 候选；应在有预算限制时启用多 socket/多端口短时探测。"
                .to_string(),
        );
    }

    let filtering = profile
        .get("filtering_behavior")
        .and_then(Value::as_str)
        .unwrap_or("unknown");
    if mapping == "endpoint_independent"
        && filtering != "endpoint_independent"
        && !udp_advertise_configured
        && gateway_mapping_candidate(snapshot).is_none()
    {
        suggestions.push(
            "本机公网 UDP 映射稳定，但过滤是否开放尚未被证明；稳定 STUN 端口不等于可接收陌生入站包。若要让困难 NAT 对端主动打入，请优先启用 UPnP/PCP/NAT-PMP，或在路由器/云安全组做 UDP 端口转发并配置 udp-advertise。"
                .to_string(),
        );
    }

    if !udp_advertise_configured
        && profile
            .get("public_endpoint")
            .and_then(Value::as_str)
            .is_none()
    {
        suggestions.push(
            "未发现本机公网 UDP endpoint；云服务器或固定公网主机建议配置 udp-advertise <公网IP>:<端口>。"
                .to_string(),
        );
    }

    if !udp_advertise_configured && !candidates.is_empty() && !has_public_candidate {
        suggestions.push(
            "本机当前只上报私网/回环 UDP candidate；跨公网直连通常需要 STUN 成功或显式 udp-advertise。"
                .to_string(),
        );
    }

    suggestions
}

fn gateway_mapping_candidate(snapshot: &Value) -> Option<(&str, &str)> {
    let mapping = snapshot.get("gateway_mapping")?;
    let endpoint = mapping.get("candidate_endpoint").and_then(Value::as_str)?;
    let source = mapping
        .get("candidate_source")
        .and_then(Value::as_str)
        .unwrap_or("gateway");
    Some((endpoint, source))
}

fn local_candidate_strings(snapshot: &Value) -> Vec<String> {
    snapshot
        .get("local_candidates")
        .and_then(Value::as_array)
        .map(|candidates| {
            candidates
                .iter()
                .filter_map(Value::as_str)
                .map(str::to_string)
                .collect()
        })
        .unwrap_or_default()
}

fn stun_observation_counts(snapshot: &Value) -> (usize, usize) {
    let Some(observations) = snapshot
        .get("nat_profile")
        .and_then(|profile| profile.get("observations"))
        .and_then(Value::as_array)
    else {
        return (0, 0);
    };
    let success = observations
        .iter()
        .filter(|observation| {
            observation
                .get("mapped_address")
                .and_then(Value::as_str)
                .is_some()
        })
        .count();
    (success, observations.len())
}

fn nat_bool_text(value: Option<&Value>) -> &'static str {
    match value.and_then(Value::as_bool) {
        Some(true) => "true",
        Some(false) => "false",
        None => "unknown",
    }
}

fn nat_lifetime_text(value: Option<&Value>) -> String {
    let Some(value) = value else {
        return "unknown".to_string();
    };
    if let Some(text) = value.as_str() {
        return text.to_string();
    }
    value
        .get("lower_bound_ms")
        .and_then(Value::as_u64)
        .map(|ms| format!("lower_bound_ms={ms}"))
        .unwrap_or_else(|| "unknown".to_string())
}

pub(super) fn print_peer_diagnostics(snapshot: &Value) {
    let Some(peers) = snapshot.get("peers").and_then(Value::as_array) else {
        return;
    };
    if peers.is_empty() {
        return;
    }

    println!("Peer details：");
    for peer in peers.iter().take(12) {
        let node_id = peer
            .get("node_id")
            .and_then(Value::as_str)
            .unwrap_or("unknown");
        let name = peer
            .get("device_name")
            .and_then(Value::as_str)
            .filter(|value| !value.trim().is_empty())
            .unwrap_or(node_id);
        let virtual_ip = peer
            .get("virtual_ip")
            .and_then(Value::as_str)
            .unwrap_or("unknown");
        let state = peer
            .get("state")
            .and_then(Value::as_str)
            .unwrap_or("unknown");
        let active_path = peer
            .get("active_path")
            .and_then(Value::as_str)
            .unwrap_or("none");
        let endpoint = peer
            .get("endpoint")
            .and_then(Value::as_str)
            .unwrap_or("(none)");
        let candidate_count = peer
            .get("candidates")
            .and_then(Value::as_array)
            .map(Vec::len)
            .unwrap_or(0);
        let candidates = peer_candidate_strings(peer);
        let candidate_preview = endpoint_preview(&candidates, 3);
        let direct_generation = peer
            .get("direct_generation")
            .and_then(Value::as_u64)
            .unwrap_or(0);
        let pair_summary = candidate_pair_summary(peer);
        println!(
            "- {} ({}) state={} path={} endpoint={} candidates={}{} direct_gen={}{}",
            short_text(name, 24),
            virtual_ip,
            state,
            active_path,
            endpoint,
            candidate_count,
            candidate_preview,
            direct_generation,
            pair_summary
        );
        if let Some(stage) = direct_failure_stage(peer) {
            println!("  direct-stage={stage}");
        }
        if let Some(summary) = direct_health_summary(peer) {
            println!("  direct-health={summary}");
        }
        if let Some(summary) = selected_pair_summary(peer) {
            println!("  selected-pair={summary}");
        }
        if let Some(consent_endpoint) = peer.get("consent_endpoint").and_then(Value::as_str) {
            println!("  consent-endpoint={consent_endpoint}");
        }
        if let Some(key_type) = peer.get("probe_key_type").and_then(Value::as_str) {
            let session = peer
                .get("probe_session_id")
                .and_then(Value::as_str)
                .unwrap_or("legacy");
            println!("  probe-key={key_type} session_id={session}");
        }
        if let Some(summary) = candidate_pair_stats_summary(peer) {
            println!("  pair-stats={summary}");
        }
        if let Some(warning) = peer.get("warning").and_then(Value::as_str) {
            println!("  warning={warning}");
        }
        if let Some(retry) = direct_retry_summary(peer) {
            println!("  direct-retry={retry}");
        }
        if let Some(selection) = path_selection_summary(peer, "current_path_selection") {
            println!("  path-selection={selection}");
        }
        if let Some(selection) = path_selection_summary(peer, "last_path_selection") {
            println!("  last-path-selection={selection}");
        }
        for event in path_event_summaries(peer, 3) {
            println!("  path-event={event}");
        }
        for event in direct_event_summaries(peer, 5) {
            println!("  direct-event={event}");
        }
        if let Some(reason) = relay_path_reason(snapshot, peer) {
            println!("  relay-reason={reason}");
        }
    }
}

pub(super) fn print_relay_diagnostics(snapshot: &Value) {
    let Some(relay) = snapshot
        .get("relay_selection")
        .filter(|value| value.is_object())
    else {
        return;
    };

    let selected_region = relay
        .get("selected_region")
        .and_then(Value::as_str)
        .unwrap_or("(none)");
    let selected_endpoint = relay
        .get("selected_endpoint")
        .and_then(Value::as_str)
        .unwrap_or("(none)");
    let latency = relay
        .get("selected_connect_latency_ms")
        .and_then(Value::as_u64)
        .map(|ms| format!("{ms}ms"))
        .unwrap_or_else(|| "unknown".to_string());
    let candidate_count = relay
        .get("candidates")
        .and_then(Value::as_array)
        .map(Vec::len)
        .unwrap_or(0);
    println!(
        "Relay selection：region={} endpoint={} latency={} candidates={}",
        selected_region, selected_endpoint, latency, candidate_count
    );
    if let Some(health) = relay_health_summary(relay) {
        println!("Relay health：{health}");
    }
    for cooldown in relay_cooldown_summaries(relay).into_iter().take(3) {
        println!("Relay cooldown：{cooldown}");
    }

    if let Some(error) = relay.get("last_error").and_then(Value::as_str) {
        let code = relay
            .get("last_error_code")
            .and_then(Value::as_str)
            .unwrap_or("unknown");
        println!("Relay error：code={code} message={error}");
    }
}

pub(super) fn relay_health_summary(relay: &Value) -> Option<String> {
    let pong_count = relay
        .get("selected_pong_count")
        .and_then(Value::as_u64)
        .unwrap_or(0);
    let error_count = relay
        .get("selected_error_count")
        .and_then(Value::as_u64)
        .unwrap_or(0);
    if pong_count == 0 && error_count == 0 {
        return None;
    }

    let last_rtt = relay_ms_text(relay, "selected_last_pong_rtt_ms");
    let rtt_ewma = relay_ms_text(relay, "selected_rtt_ewma_ms");
    let jitter = relay_ms_text(relay, "selected_jitter_ms");
    let last_pong = relay
        .get("selected_last_pong_age_ms")
        .and_then(Value::as_u64)
        .map(|ms| format!("{ms}ms_ago"))
        .unwrap_or_else(|| "never".to_string());

    Some(format!(
        "pong={} errors={} last_rtt={} rtt_ewma={} jitter={} last_pong={}",
        pong_count, error_count, last_rtt, rtt_ewma, jitter, last_pong
    ))
}

fn relay_ms_text(relay: &Value, field: &str) -> String {
    relay
        .get(field)
        .and_then(Value::as_u64)
        .map(|ms| format!("{ms}ms"))
        .unwrap_or_else(|| "unknown".to_string())
}

pub(super) fn relay_cooldown_summaries(relay: &Value) -> Vec<String> {
    let Some(candidates) = relay.get("candidates").and_then(Value::as_array) else {
        return Vec::new();
    };

    candidates
        .iter()
        .filter(|candidate| {
            candidate
                .get("error_code")
                .and_then(Value::as_str)
                .is_some_and(|code| code == "cooling_down" || code.starts_with("runtime_"))
        })
        .map(|candidate| {
            let region = candidate
                .get("region")
                .and_then(Value::as_str)
                .unwrap_or("unknown");
            let endpoint = candidate
                .get("endpoint")
                .and_then(Value::as_str)
                .unwrap_or("unknown");
            let remaining = candidate
                .get("cooldown_remaining_ms")
                .and_then(Value::as_u64)
                .map(|ms| format!("{ms}ms"))
                .unwrap_or_else(|| "unknown".to_string());
            format!("region={region} endpoint={endpoint} remaining={remaining}")
        })
        .collect()
}

pub(super) fn peer_direct_suggestions(snapshot: &Value) -> Vec<String> {
    let Some(peers) = snapshot.get("peers").and_then(Value::as_array) else {
        return Vec::new();
    };

    let mut private_only_peers = Vec::new();
    let mut generation_changed_peers = Vec::new();
    let mut handshake_timeout_peers = Vec::new();
    let mut direct_send_failed_peers = Vec::new();
    let mut public_without_open_ingress_peers = Vec::new();
    let mut generic_direct_failures = 0_u64;
    for peer in peers {
        let direct_error_code = direct_error_code(peer);
        let has_direct_error = direct_failure_stage(peer).is_some();
        if has_direct_error && matches!(direct_error_code, Some("direct_probe_failed") | None) {
            generic_direct_failures += 1;
        }
        match direct_error_code {
            Some("network_generation_changed") => {
                generation_changed_peers.push(peer_display_name(peer))
            }
            Some("handshake_timeout") => handshake_timeout_peers.push(peer_display_name(peer)),
            Some("direct_send_failed") => direct_send_failed_peers.push(peer_display_name(peer)),
            _ => {}
        }

        let endpoints = peer_diagnostic_endpoints(peer);
        if endpoints.is_empty() {
            continue;
        }
        let has_public_endpoint = endpoints.iter().any(is_public_udp_endpoint);
        let has_private_or_local_endpoint = endpoints
            .iter()
            .any(|endpoint| is_private_or_local_ip(endpoint.ip()));
        if has_direct_error && !has_public_endpoint && has_private_or_local_endpoint {
            private_only_peers.push(peer_display_name(peer));
        } else if has_direct_error
            && has_public_endpoint
            && peer_has_only_stun_like_public_candidates(peer)
        {
            public_without_open_ingress_peers.push(peer_display_name(peer));
        }
    }

    let mut suggestions = Vec::new();
    if !generation_changed_peers.is_empty() {
        suggestions.push(format!(
            "对端 {} 的 Direct 状态来自旧网络代际，已切回 Relay；等待新的 UDP candidate/ACK 后会自动重新选择直连。",
            generation_changed_peers.join("、")
        ));
    }
    if !handshake_timeout_peers.is_empty() {
        suggestions.push(format!(
            "对端 {} UDP 探测后 WireGuard 握手超时；通常是单向 UDP、防火墙状态表或对端会话未及时刷新。",
            handshake_timeout_peers.join("、")
        ));
    }
    if !direct_send_failed_peers.is_empty() {
        suggestions.push(format!(
            "对端 {} 的 Direct 发送失败，daemon 已降级 Relay；请重点查看网络切换、防火墙和 UDP endpoint 是否漂移。",
            direct_send_failed_peers.join("、")
        ));
    }
    if !private_only_peers.is_empty() {
        suggestions.push(format!(
            "对端 {} 只上报了私网/回环 UDP 候选；请在对应设备配置 udp-advertise <公网IP>:<端口>，并放行同一个 UDP 入站端口。",
            private_only_peers.join("、")
        ));
    } else if !public_without_open_ingress_peers.is_empty() {
        suggestions.push(format!(
            "对端 {} 有公网候选但 Direct 仍失败；公网 STUN 映射稳定不代表 NAT 过滤开放。请优先在较友好的一侧启用 UPnP/PCP/NAT-PMP 或手动 UDP 端口转发，让困难 NAT 设备能把第一包打进去。",
            public_without_open_ingress_peers.join("、")
        ));
    } else if generic_direct_failures > 0 {
        suggestions.push(
            "检测到 Direct UDP 探测失败；请确认两端 udp-bind/udp-advertise、云安全组和系统防火墙使用同一个 UDP 端口。"
                .to_string(),
        );
    }
    suggestions
}

fn peer_has_only_stun_like_public_candidates(peer: &Value) -> bool {
    let Some(pairs) = peer.get("candidate_pairs").and_then(Value::as_array) else {
        return false;
    };
    let mut saw_public = false;
    for pair in pairs {
        let Some(endpoint) = pair
            .get("remote_endpoint")
            .and_then(Value::as_str)
            .and_then(|endpoint| endpoint.parse::<SocketAddr>().ok())
        else {
            continue;
        };
        if !is_public_udp_endpoint(&endpoint) {
            continue;
        }
        saw_public = true;
        let source = pair
            .get("remote_candidate_type")
            .or_else(|| pair.get("remote_source"))
            .or_else(|| pair.get("source"))
            .and_then(Value::as_str)
            .unwrap_or("unknown");
        if matches!(
            source,
            "upnp" | "pcp" | "nat_pmp" | "nat-pmp" | "port_mapping" | "peer_reflexive" | "learned"
        ) {
            return false;
        }
    }
    saw_public
}

pub(super) fn relay_path_reason(snapshot: &Value, peer: &Value) -> Option<String> {
    let active_path = peer.get("active_path").and_then(Value::as_str);
    let state = peer.get("state").and_then(Value::as_str);
    let relayish = matches!(active_path, Some("relay"))
        || matches!(state, Some("relay" | "fallback_to_relay"));
    if !relayish {
        return None;
    }

    if let Some(reason) = path_selection_reason(peer) {
        return Some(reason);
    }

    if let Some(stage) = direct_failure_stage(peer) {
        return Some(format!("Direct 不可用：{stage}"));
    }

    let snapshot_generation = snapshot
        .get("network_generation")
        .and_then(Value::as_u64)
        .unwrap_or(0);
    let direct_generation = peer
        .get("direct_generation")
        .and_then(Value::as_u64)
        .unwrap_or(0);
    if direct_generation < snapshot_generation {
        return Some(format!(
            "Direct 成功属于旧网络代际 {direct_generation}，当前代际 {snapshot_generation} 正在重新探测"
        ));
    }

    let candidates = peer_candidate_strings(peer);
    if candidates.is_empty() {
        return Some("对端暂无 UDP candidate".to_string());
    }

    if let Some(relay) = snapshot
        .get("relay_selection")
        .filter(|value| value.is_object())
    {
        let region = relay
            .get("selected_region")
            .and_then(Value::as_str)
            .unwrap_or("unknown");
        let endpoint = relay
            .get("selected_endpoint")
            .and_then(Value::as_str)
            .unwrap_or("unknown");
        return Some(format!(
            "Relay 已选中 {region} / {endpoint}，Direct 尚未确认"
        ));
    }

    Some("Relay fallback 已生效，Direct 尚未确认".to_string())
}

pub(super) fn path_selection_summary(peer: &Value, field: &str) -> Option<String> {
    let selection = peer.get(field)?.as_object()?;
    let path = selection
        .get("path")
        .and_then(Value::as_str)
        .unwrap_or("none");
    let endpoint = selection
        .get("direct_endpoint")
        .and_then(Value::as_str)
        .unwrap_or("(none)");
    let reason_code = selection.get("reason_code").and_then(Value::as_str)?;
    let reason = selection
        .get("reason")
        .and_then(Value::as_str)
        .unwrap_or("");
    let confirmed = selection
        .get("direct_confirmed")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let direct_score = selection_score_text(selection.get("direct_score"));
    let relay_score = selection_score_text(selection.get("relay_score"));

    Some(format!(
        "path={path} endpoint={endpoint} confirmed={confirmed} direct_score={direct_score} relay_score={relay_score} code={reason_code} reason={reason}"
    ))
}

fn selection_score_text(score: Option<&Value>) -> String {
    let Some(score) = score.and_then(Value::as_object) else {
        return "n/a".to_string();
    };
    let value = score
        .get("score")
        .and_then(Value::as_i64)
        .map(|value| value.to_string())
        .unwrap_or_else(|| "unknown".to_string());
    let reason = score.get("reason").and_then(Value::as_str).unwrap_or("");
    if reason.is_empty() {
        value
    } else {
        format!("{value}({reason})")
    }
}

pub(super) fn path_event_summaries(peer: &Value, limit: usize) -> Vec<String> {
    let Some(events) = peer.get("path_events").and_then(Value::as_array) else {
        return Vec::new();
    };
    let start = events.len().saturating_sub(limit);
    events[start..]
        .iter()
        .filter_map(path_event_summary)
        .collect()
}

fn path_event_summary(event: &Value) -> Option<String> {
    let age = event
        .get("selected_age_ms")
        .and_then(Value::as_u64)
        .unwrap_or(0);
    let generation = event
        .get("network_generation")
        .and_then(Value::as_u64)
        .unwrap_or(0);
    let previous = event
        .get("previous_path")
        .and_then(Value::as_str)
        .unwrap_or("none");
    let selected = event
        .get("selected_path")
        .and_then(Value::as_str)
        .unwrap_or("none");
    let endpoint = event
        .get("direct_endpoint")
        .and_then(Value::as_str)
        .unwrap_or("(none)");
    let reason_code = event.get("reason_code").and_then(Value::as_str)?;
    let direct_score = selection_score_text(event.get("direct_score"));
    let relay_score = selection_score_text(event.get("relay_score"));

    Some(format!(
        "age={}ms gen={} {}->{} endpoint={} direct_score={} relay_score={} code={}",
        age, generation, previous, selected, endpoint, direct_score, relay_score, reason_code
    ))
}

pub(super) fn direct_event_summaries(peer: &Value, limit: usize) -> Vec<String> {
    let Some(events) = peer.get("direct_events").and_then(Value::as_array) else {
        return Vec::new();
    };
    let start = events.len().saturating_sub(limit);
    events[start..]
        .iter()
        .filter_map(direct_event_summary)
        .collect()
}

fn direct_event_summary(event: &Value) -> Option<String> {
    let age = event.get("age_ms").and_then(Value::as_u64).unwrap_or(0);
    let generation = event
        .get("network_generation")
        .and_then(Value::as_u64)
        .unwrap_or(0);
    let stage = event.get("stage").and_then(Value::as_str)?;
    let endpoint = event
        .get("endpoint")
        .and_then(Value::as_str)
        .unwrap_or("(none)");
    let candidates = event
        .get("candidate_count")
        .and_then(Value::as_u64)
        .map(|value| value.to_string())
        .unwrap_or_else(|| "n/a".to_string());
    let probes = event
        .get("sent_probes")
        .and_then(Value::as_u64)
        .map(|value| value.to_string())
        .unwrap_or_else(|| "n/a".to_string());
    let detail = event.get("detail").and_then(Value::as_str).unwrap_or("");

    Some(format!(
        "age={}ms gen={} stage={} endpoint={} candidates={} probes={} detail={}",
        age, generation, stage, endpoint, candidates, probes, detail
    ))
}

pub(super) fn direct_health_summary(peer: &Value) -> Option<String> {
    let direct = peer.get("direct")?.as_object()?;
    let success_count = direct
        .get("success_count")
        .and_then(Value::as_u64)
        .unwrap_or(0);
    let failure_count = direct
        .get("failure_count")
        .and_then(Value::as_u64)
        .unwrap_or(0);
    let ewma = direct.get("rtt_ewma_ms").and_then(Value::as_u64);
    let jitter = direct.get("jitter_ms").and_then(Value::as_u64);
    if success_count == 0 && failure_count == 0 && ewma.is_none() && jitter.is_none() {
        return None;
    }

    Some(format!(
        "success={} failure={} rtt_ewma={} jitter={}",
        success_count,
        failure_count,
        ewma.map(|ms| format!("{ms}ms"))
            .unwrap_or_else(|| "unknown".to_string()),
        jitter
            .map(|ms| format!("{ms}ms"))
            .unwrap_or_else(|| "unknown".to_string())
    ))
}

pub(super) fn direct_retry_summary(peer: &Value) -> Option<String> {
    let retry_after = peer.get("direct_retry_after_ms").and_then(Value::as_u64)?;
    let remaining = peer
        .get("direct_retry_remaining_ms")
        .and_then(Value::as_u64)
        .unwrap_or(0);
    if retry_after == 0 || remaining == 0 {
        return None;
    }
    Some(format!(
        "next_probe_in={}ms backoff={}ms",
        remaining, retry_after
    ))
}

fn path_selection_reason(peer: &Value) -> Option<String> {
    let selection = peer
        .get("current_path_selection")
        .or_else(|| peer.get("last_path_selection"))?
        .as_object()?;
    let path = selection
        .get("path")
        .and_then(Value::as_str)
        .unwrap_or("none");
    let reason_code = selection.get("reason_code").and_then(Value::as_str)?;
    let reason = selection
        .get("reason")
        .and_then(Value::as_str)
        .unwrap_or("");

    let path_label = match path {
        "direct" => "Direct",
        "relay" => "Relay",
        _ => "无可用路径",
    };
    Some(format!(
        "Path selector 选择 {path_label}：{}（{reason_code}）：{reason}",
        path_reason_label(reason_code)
    ))
}

pub(super) fn direct_failure_stage(peer: &Value) -> Option<String> {
    let direct = peer.get("direct")?;
    let error = direct.get("last_error").and_then(Value::as_str);
    let code = direct.get("last_error_code").and_then(Value::as_str);
    match (code, error) {
        (Some(code), Some(error)) => Some(format!("{}：{}", reason_label(code), error)),
        (Some(code), None) => Some(reason_label(code).to_string()),
        (None, Some(error)) => Some(error.to_string()),
        (None, None) => None,
    }
}

fn direct_error_code(peer: &Value) -> Option<&str> {
    peer.get("direct")
        .and_then(|direct| direct.get("last_error_code"))
        .and_then(Value::as_str)
}

fn reason_label(code: &str) -> &'static str {
    match code {
        "network_generation_changed" => "网络切换后 Direct 状态失效",
        "direct_probe_failed" => "UDP 探测未确认",
        "direct_send_failed" => "Direct UDP 发送失败",
        "handshake_timeout" => "WireGuard 握手超时",
        _ => "Direct 失败",
    }
}

fn path_reason_label(code: &str) -> &'static str {
    match code {
        "path_direct_confirmed" => "Direct UDP pair 已确认",
        "path_direct_trial" => "Direct 最近成功，处于试探窗口",
        "path_relay_unavailable" => "Relay 不可用，尝试 Direct",
        "path_direct_disabled" => "策略禁用 Direct",
        "path_direct_no_endpoint" => "没有 Direct UDP endpoint",
        "path_direct_not_confirmed" => "Direct UDP 尚未确认",
        "path_direct_degraded" => "Direct 质量低于 Relay",
        "path_unavailable" => "没有可用数据路径",
        _ => "路径选择原因",
    }
}

fn candidate_pair_summary(peer: &Value) -> String {
    let Some(pairs) = peer.get("candidate_pairs").and_then(Value::as_array) else {
        return String::new();
    };
    if pairs.is_empty() {
        return String::new();
    }

    let mut selected = 0;
    let mut succeeded = 0;
    let mut probing = 0;
    let mut failed = 0;
    let mut degraded = 0;
    for pair in pairs {
        match pair
            .get("state")
            .and_then(Value::as_str)
            .unwrap_or("unknown")
        {
            "selected" => selected += 1,
            "succeeded" => succeeded += 1,
            "probing" => probing += 1,
            "failed" => failed += 1,
            "degraded" => degraded += 1,
            _ => {}
        }
    }

    let mut parts = Vec::new();
    if selected > 0 {
        parts.push(format!("selected={selected}"));
    }
    if succeeded > 0 {
        parts.push(format!("succeeded={succeeded}"));
    }
    if probing > 0 {
        parts.push(format!("probing={probing}"));
    }
    if failed > 0 {
        parts.push(format!("failed={failed}"));
    }
    if degraded > 0 {
        parts.push(format!("degraded={degraded}"));
    }
    if parts.is_empty() {
        format!(" pairs={}", pairs.len())
    } else {
        format!(" pairs={}({})", pairs.len(), parts.join(","))
    }
}

pub(super) fn selected_pair_summary(peer: &Value) -> Option<String> {
    let direct_type = peer
        .get("direct_type")
        .and_then(Value::as_str)
        .unwrap_or("unknown");
    let pair = peer
        .get("selected_pair")
        .or_else(|| peer.get("current_direct_pair"))?
        .as_object()?;
    let local = pair
        .get("local_endpoint")
        .and_then(Value::as_str)
        .unwrap_or("(unknown)");
    let remote = pair.get("remote_endpoint").and_then(Value::as_str)?;
    let local_type = pair
        .get("local_candidate_type")
        .and_then(Value::as_str)
        .unwrap_or("unknown");
    let remote_type = pair
        .get("remote_candidate_type")
        .or_else(|| pair.get("remote_source"))
        .and_then(Value::as_str)
        .unwrap_or("unknown");
    let state = pair
        .get("pair_state")
        .or_else(|| pair.get("state"))
        .and_then(Value::as_str)
        .unwrap_or("unknown");
    let rtt = pair
        .get("rtt_ms")
        .or_else(|| pair.get("rtt_ewma_ms"))
        .and_then(Value::as_u64)
        .map(|value| format!("{value}ms"))
        .unwrap_or_else(|| "unknown".to_string());
    let success_age = pair
        .get("last_success_age_ms")
        .and_then(Value::as_u64)
        .map(|value| format!("{value}ms"))
        .unwrap_or_else(|| "unknown".to_string());
    let nominated = pair
        .get("nominated")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let selected = pair
        .get("selected")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let nomination = format!(" nominated={nominated} selected={selected}");
    let probe_retry = pair
        .get("probe_retry_after_ms")
        .and_then(Value::as_u64)
        .map(|after_ms| {
            let remaining_ms = pair
                .get("probe_retry_remaining_ms")
                .and_then(Value::as_u64)
                .unwrap_or(0);
            let due = pair
                .get("probe_due")
                .and_then(Value::as_bool)
                .unwrap_or(false);
            format!(
                " probe_due={due} probe_retry_after={after_ms}ms probe_retry_remaining={remaining_ms}ms"
            )
        })
        .unwrap_or_default();
    let consent = peer
        .get("consent_endpoint")
        .and_then(Value::as_str)
        .map(|value| format!(" consent={value}"))
        .unwrap_or_default();
    let warning = peer
        .get("warning")
        .or_else(|| pair.get("warning"))
        .and_then(Value::as_str)
        .map(|value| format!(" warning={value}"))
        .unwrap_or_default();

    Some(format!(
        "direct_type={direct_type} local={local} remote={remote} local_type={local_type} remote_type={remote_type} state={state}{nomination}{consent} rtt={rtt} last_success_age={success_age}{probe_retry}{warning}"
    ))
}

pub(super) fn candidate_pair_stats_summary(peer: &Value) -> Option<String> {
    let stats = peer.get("candidate_pair_stats").and_then(Value::as_array)?;
    if stats.is_empty() {
        return None;
    }

    let parts = stats
        .iter()
        .filter_map(|item| {
            let source = item.get("source").and_then(Value::as_str)?;
            let success = item
                .get("success_count")
                .and_then(Value::as_u64)
                .unwrap_or(0);
            let failure = item
                .get("failure_count")
                .and_then(Value::as_u64)
                .unwrap_or(0);
            let total = success.saturating_add(failure);
            let rate = item
                .get("success_rate_per_mille")
                .and_then(Value::as_u64)
                .map(|value| format!("{value}‰"))
                .unwrap_or_else(|| "unknown".to_string());
            let current = item
                .get("current_pair_count")
                .and_then(Value::as_u64)
                .unwrap_or(0);
            Some(format!(
                "{source}={success}/{total}:{rate},current={current}"
            ))
        })
        .collect::<Vec<_>>();

    (!parts.is_empty()).then(|| parts.join(" "))
}

pub(super) fn print_traversal_history(snapshot: &Value) {
    if let Some(summary) = traversal_history_summary(snapshot) {
        println!("Traversal history：{summary}");
    }
}

pub(super) fn traversal_history_summary(snapshot: &Value) -> Option<String> {
    let sources = snapshot
        .get("traversal_history")?
        .get("sources")?
        .as_array()?;
    if sources.is_empty() {
        return None;
    }

    let parts = sources
        .iter()
        .filter_map(|item| {
            let source = item.get("source").and_then(Value::as_str)?;
            let success = item
                .get("success_count")
                .and_then(Value::as_u64)
                .unwrap_or(0);
            let failure = item
                .get("failure_count")
                .and_then(Value::as_u64)
                .unwrap_or(0);
            let total = success.saturating_add(failure);
            let rate = item
                .get("success_rate_per_mille")
                .and_then(Value::as_u64)
                .map(|value| format!("{value}‰"))
                .unwrap_or_else(|| "unknown".to_string());
            let cooldown = item
                .get("cooldown_remaining_ms")
                .and_then(Value::as_u64)
                .filter(|value| *value > 0)
                .map(|value| format!(",cooldown={}ms", value))
                .unwrap_or_default();
            Some(format!("{source}={success}/{total}:{rate}{cooldown}"))
        })
        .collect::<Vec<_>>();

    (!parts.is_empty()).then(|| parts.join(" "))
}

fn peer_diagnostic_endpoints(peer: &Value) -> Vec<SocketAddr> {
    let mut endpoints = Vec::new();
    if let Some(endpoint) = peer.get("endpoint").and_then(Value::as_str) {
        push_socket_addr(&mut endpoints, endpoint);
    }
    for candidate in peer_candidate_strings(peer) {
        push_socket_addr(&mut endpoints, &candidate);
    }
    endpoints
}

fn peer_candidate_strings(peer: &Value) -> Vec<String> {
    peer.get("candidates")
        .and_then(Value::as_array)
        .map(|candidates| {
            candidates
                .iter()
                .filter_map(Value::as_str)
                .map(str::to_string)
                .collect()
        })
        .unwrap_or_default()
}

fn push_socket_addr(endpoints: &mut Vec<SocketAddr>, value: &str) {
    if let Ok(endpoint) = value.parse::<SocketAddr>() {
        if !endpoints.contains(&endpoint) {
            endpoints.push(endpoint);
        }
    }
}

fn is_public_udp_endpoint(endpoint: &SocketAddr) -> bool {
    endpoint.port() != 0 && !is_private_or_local_ip(endpoint.ip())
}

fn is_private_or_local_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ip) => {
            let octets = ip.octets();
            ip.is_private()
                || ip.is_loopback()
                || ip.is_link_local()
                || ip.is_broadcast()
                || ip.is_unspecified()
                || (octets[0] == 100 && (64..=127).contains(&octets[1]))
        }
        IpAddr::V6(ip) => {
            let segments = ip.segments();
            ip.is_loopback()
                || ip.is_unspecified()
                || (segments[0] & 0xfe00) == 0xfc00
                || (segments[0] & 0xffc0) == 0xfe80
        }
    }
}

fn peer_display_name(peer: &Value) -> String {
    let node_id = peer
        .get("node_id")
        .and_then(Value::as_str)
        .unwrap_or("unknown");
    let name = peer
        .get("device_name")
        .and_then(Value::as_str)
        .filter(|value| !value.trim().is_empty())
        .unwrap_or(node_id);
    let virtual_ip = peer
        .get("virtual_ip")
        .and_then(Value::as_str)
        .unwrap_or("unknown");
    format!("{}({})", short_text(name, 18), virtual_ip)
}

fn endpoint_preview(endpoints: &[String], max_items: usize) -> String {
    if endpoints.is_empty() {
        return String::new();
    }
    let preview = endpoints
        .iter()
        .take(max_items)
        .map(|endpoint| short_text(endpoint, 32))
        .collect::<Vec<_>>()
        .join(",");
    if endpoints.len() > max_items {
        format!(" [{}…]", preview)
    } else {
        format!(" [{preview}]")
    }
}

fn short_text(value: &str, max_len: usize) -> String {
    if value.chars().count() <= max_len {
        value.to_string()
    } else {
        format!("{}...", value.chars().take(max_len).collect::<String>())
    }
}

pub(super) fn mtu_profile(mtu: u32) -> &'static str {
    match mtu {
        0..=1279 => "low (<1280, compatibility workaround)",
        1280..=RELAY_SAFE_MTU => "relay-safe",
        1381..=WIREGUARD_STYLE_MTU => "default",
        1421..=COMMON_ETHERNET_MTU => "high",
        _ => "jumbo/high-risk",
    }
}

pub(super) fn mtu_config_suggestions(mtu: u32) -> Vec<String> {
    let mut suggestions = Vec::new();
    if mtu < IPV6_SAFE_MIN_MTU {
        suggestions.push(
            "当前 MTU 低于 1280；除非正在规避 PMTU blackhole，否则吞吐和 IPv6 兼容性可能受影响。"
                .to_string(),
        );
    }
    if mtu > COMMON_ETHERNET_MTU {
        suggestions.push(
            "当前 MTU 超过常见以太网 1500；除非端到端路径都支持 jumbo frame，否则建议降到 1420 或 1380。"
                .to_string(),
        );
    } else if mtu > WIREGUARD_STYLE_MTU {
        suggestions.push(
            "当前 MTU 高于 WireGuard-like 默认 1420；复杂 NAT、移动网络或中继路径更容易出现大包丢失。"
                .to_string(),
        );
    }
    suggestions
}

pub(super) fn mtu_runtime_suggestions(mtu: u32, stats: &Value) -> Vec<String> {
    let relay_connections = value_u64(stats, "relay_connections");
    if relay_connections > 0 && mtu > RELAY_SAFE_MTU {
        vec![format!(
            "当前存在 {relay_connections} 条 Relay 路径且 MTU 大于 {RELAY_SAFE_MTU}；如果 SSH/RDP 卡顿或大流量不稳定，优先尝试：p2wlan config set mtu {RELAY_SAFE_MTU}"
        )]
    } else {
        Vec::new()
    }
}

pub(super) fn value_u64(value: &Value, key: &str) -> u64 {
    value.get(key).and_then(Value::as_u64).unwrap_or(0)
}

pub(super) fn dedupe_strings(values: Vec<String>) -> Vec<String> {
    let mut deduped = Vec::new();
    for value in values {
        if !deduped.contains(&value) {
            deduped.push(value);
        }
    }
    deduped
}
