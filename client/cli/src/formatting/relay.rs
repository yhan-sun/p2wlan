//! Relay doctor/diagnostics formatting helpers.
//!
//! Renders relay health, cooldown state, and the reason a peer is still on a
//! relay path for the `p2wlan doctor` output. Split out of `formatting.rs`.

use serde_json::Value;

use super::peer::{direct_failure_stage, path_selection_reason, peer_candidate_strings};

pub(crate) fn print_relay_diagnostics(snapshot: &Value) {
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
pub(crate) fn relay_health_summary(relay: &Value) -> Option<String> {
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
pub(crate) fn relay_cooldown_summaries(relay: &Value) -> Vec<String> {
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
pub(crate) fn relay_path_reason(snapshot: &Value, peer: &Value) -> Option<String> {
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
