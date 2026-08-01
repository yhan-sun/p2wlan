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
