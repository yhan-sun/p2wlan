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
