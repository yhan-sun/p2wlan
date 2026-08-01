//! Peer doctor/diagnostics formatting helpers.
//!
//! Renders peer connection health, path/direct event timelines, candidate
//! pairs, and traversal history for the `p2wlan doctor` output. Split out of
//! `formatting.rs`.

use std::net::{IpAddr, SocketAddr};

use serde_json::Value;

use super::relay::relay_path_reason;

pub(crate) fn print_peer_diagnostics(snapshot: &Value) {
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
pub(crate) fn peer_direct_suggestions(snapshot: &Value) -> Vec<String> {
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
pub(crate) fn path_selection_summary(peer: &Value, field: &str) -> Option<String> {
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
pub(crate) fn path_event_summaries(peer: &Value, limit: usize) -> Vec<String> {
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
pub(crate) fn direct_event_summaries(peer: &Value, limit: usize) -> Vec<String> {
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
pub(crate) fn direct_health_summary(peer: &Value) -> Option<String> {
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
pub(crate) fn direct_retry_summary(peer: &Value) -> Option<String> {
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
pub(crate) fn path_selection_reason(peer: &Value) -> Option<String> {
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
pub(crate) fn direct_failure_stage(peer: &Value) -> Option<String> {
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
pub(crate) fn selected_pair_summary(peer: &Value) -> Option<String> {
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
pub(crate) fn candidate_pair_stats_summary(peer: &Value) -> Option<String> {
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
pub(crate) fn print_traversal_history(snapshot: &Value) {
    if let Some(summary) = traversal_history_summary(snapshot) {
        println!("Traversal history：{summary}");
    }
}
pub(crate) fn traversal_history_summary(snapshot: &Value) -> Option<String> {
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
pub(crate) fn peer_candidate_strings(peer: &Value) -> Vec<String> {
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
pub(crate) fn is_public_udp_endpoint(endpoint: &SocketAddr) -> bool {
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
pub(crate) fn endpoint_preview(endpoints: &[String], max_items: usize) -> String {
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
