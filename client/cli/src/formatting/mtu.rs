//! MTU doctor/diagnostics formatting helpers.
//!
//! Renders the runtime MTU profile, snapshot drift, and suggested safe-MTU
//! actions for the `p2wlan doctor` output. Split out of `formatting.rs`.

use serde_json::Value;

use super::{dedupe_strings, value_u64, yes_no};

const IPV6_SAFE_MIN_MTU: u32 = 1280;
const RELAY_SAFE_MTU: u32 = 1380;
const WIREGUARD_STYLE_MTU: u32 = 1420;
const COMMON_ETHERNET_MTU: u32 = 1500;

pub(crate) fn runtime_mtu_summary(snapshot: &Value) -> Option<String> {
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
pub(crate) fn mtu_snapshot_suggestions(config_mtu: u32, snapshot: &Value) -> Vec<String> {
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
pub(crate) fn mtu_diagnostic_suggestions(snapshot: &Value) -> Vec<String> {
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
pub(crate) fn mtu_profile(mtu: u32) -> &'static str {
    match mtu {
        0..=1279 => "low (<1280, compatibility workaround)",
        1280..=RELAY_SAFE_MTU => "relay-safe",
        1381..=WIREGUARD_STYLE_MTU => "default",
        1421..=COMMON_ETHERNET_MTU => "high",
        _ => "jumbo/high-risk",
    }
}
pub(crate) fn mtu_config_suggestions(mtu: u32) -> Vec<String> {
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
pub(crate) fn mtu_runtime_suggestions(mtu: u32, stats: &Value) -> Vec<String> {
    let relay_connections = value_u64(stats, "relay_connections");
    if relay_connections > 0 && mtu > RELAY_SAFE_MTU {
        vec![format!(
            "当前存在 {relay_connections} 条 Relay 路径且 MTU 大于 {RELAY_SAFE_MTU}；如果 SSH/RDP 卡顿或大流量不稳定，优先尝试：p2wlan config set mtu {RELAY_SAFE_MTU}"
        )]
    } else {
        Vec::new()
    }
}
