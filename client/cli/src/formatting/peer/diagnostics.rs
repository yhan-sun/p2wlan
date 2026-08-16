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
        if let Some(nat) = peer_nat_hint_summary(peer) {
            println!("  {nat}");
        }
        if let Some(stage) = direct_failure_stage(peer) {
            println!("  direct-stage={stage}");
        }
        if let Some(liveness) = direct_liveness_summary(peer) {
            println!("  direct-liveness={liveness}");
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
