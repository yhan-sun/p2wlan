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
