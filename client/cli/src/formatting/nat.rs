//! NAT / STUN / UDP socket-pool doctor formatting helpers.
//!
//! Renders NAT profile, STUN observations, candidate strings, and the UDP
//! socket-pool experiment state for the `p2wlan doctor` output. Split out of
//! `formatting.rs`.

use std::net::SocketAddr;

use serde_json::Value;

use super::is_clear_value;
use super::peer::{endpoint_preview, is_public_udp_endpoint};

pub(crate) fn print_nat_diagnostics(snapshot: &Value) {
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
pub(crate) fn udp_socket_pool_summary(snapshot: &Value) -> Option<String> {
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
pub(crate) fn stun_config_summary(servers: &[String]) -> String {
    let configured = configured_stun_servers(servers);
    if servers.is_empty() {
        "default public STUN set".to_string()
    } else if configured.is_empty() {
        "disabled".to_string()
    } else {
        format!("{} configured ({})", configured.len(), configured.join(","))
    }
}
pub(crate) fn stun_config_suggestions(servers: &[String]) -> Vec<String> {
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
pub(crate) fn nat_profile_summary(snapshot: &Value) -> Option<String> {
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
pub(crate) fn stun_observation_summaries(snapshot: &Value, limit: usize) -> Vec<String> {
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
pub(crate) fn nat_profile_suggestions(
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
