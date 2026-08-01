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
