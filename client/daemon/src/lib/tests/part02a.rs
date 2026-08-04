#[test]
fn signal_candidate_cap_keeps_priority_prefix_and_source_map_aligned() {
    let mut candidates = (1..=MAX_SIGNAL_CANDIDATES + 3)
        .map(|index| format!("192.0.2.{index}:51820"))
        .collect::<Vec<_>>();
    let mapped = "198.51.100.10:42000".to_string();
    candidates.insert(0, mapped.clone());
    let mut sources = candidates
        .iter()
        .cloned()
        .map(|endpoint| (endpoint, "host".to_string()))
        .collect::<HashMap<_, _>>();
    sources.insert(mapped.clone(), "upnp".to_string());

    truncate_signal_candidates(&mut candidates, &mut sources);

    assert_eq!(candidates.len(), MAX_SIGNAL_CANDIDATES);
    assert_eq!(candidates[0], mapped);
    assert_eq!(sources.len(), MAX_SIGNAL_CANDIDATES);
    assert!(sources.keys().all(|endpoint| candidates.contains(endpoint)));
    assert_eq!(sources.get(&mapped).map(String::as_str), Some("upnp"));
}

#[test]
fn signal_candidate_cap_prefers_public_traversal_candidates_over_private_hosts() {
    let mut candidates = (1..=MAX_SIGNAL_CANDIDATES + 4)
        .map(|index| format!("192.168.1.{index}:51820"))
        .collect::<Vec<_>>();
    let stun = "203.0.113.10:42000".to_string();
    let predicted = "203.0.113.10:42004".to_string();
    candidates.push(stun.clone());
    candidates.push(predicted.clone());

    let mut sources = candidates
        .iter()
        .cloned()
        .map(|endpoint| (endpoint, "host".to_string()))
        .collect::<HashMap<_, _>>();
    sources.insert(stun.clone(), "stun_observed".to_string());
    sources.insert(predicted.clone(), "predicted".to_string());

    truncate_signal_candidates(&mut candidates, &mut sources);

    assert_eq!(candidates.len(), MAX_SIGNAL_CANDIDATES);
    assert!(candidates.contains(&stun));
    assert!(candidates.contains(&predicted));
    assert_eq!(
        sources.get(&stun).map(String::as_str),
        Some("stun_observed")
    );
    assert_eq!(
        sources.get(&predicted).map(String::as_str),
        Some("predicted")
    );
    assert!(sources.keys().all(|endpoint| candidates.contains(endpoint)));
}

#[test]
fn signal_candidate_cap_balances_disjoint_prediction_windows() {
    let mut candidates =
        (40_000..40_007).map(|port| format!("203.0.113.10:{port}")).collect::<Vec<_>>();
    candidates.extend((41_000..41_080).map(|port| format!("203.0.113.10:{port}")));
    candidates.extend((42_000..42_080).map(|port| format!("203.0.113.10:{port}")));
    let mut sources = candidates
        .iter()
        .cloned()
        .map(|endpoint| (endpoint, "predicted".to_string()))
        .collect::<HashMap<_, _>>();
    for port in 40_000..40_007 {
        sources.insert(
            format!("203.0.113.10:{port}"),
            "stun_observed".to_string(),
        );
    }

    compact_volatile_public_signal_candidates(&mut candidates, &mut sources);
    truncate_signal_candidates(&mut candidates, &mut sources);

    let first_window = candidates
        .iter()
        .filter(|endpoint| endpoint.starts_with("203.0.113.10:41"))
        .count();
    let second_window = candidates
        .iter()
        .filter(|endpoint| endpoint.starts_with("203.0.113.10:42"))
        .count();
    assert_eq!(candidates.len(), MAX_SIGNAL_CANDIDATES);
    assert!(first_window >= 40, "first window retained {first_window}");
    assert!(second_window >= 40, "second window retained {second_window}");
    assert!(candidates.contains(&"203.0.113.10:42001".to_string()));
}

#[test]
fn candidate_refresh_generation_ignores_stun_port_churn_on_same_public_ip() {
    let previous = vec![
        "192.168.1.10:59288".to_string(),
        "93.184.216.34:27106".to_string(),
    ];
    let previous_sources = HashMap::from([
        ("192.168.1.10:59288".to_string(), "host".to_string()),
        (
            "93.184.216.34:27106".to_string(),
            "stun_observed".to_string(),
        ),
    ]);
    let next = vec![
        "192.168.1.10:59288".to_string(),
        "93.184.216.34:31999".to_string(),
    ];
    let next_sources = HashMap::from([
        ("192.168.1.10:59288".to_string(), "host".to_string()),
        (
            "93.184.216.34:31999".to_string(),
            "stun_observed".to_string(),
        ),
    ]);

    assert!(!candidate_refresh_requires_network_generation_advance(
        &previous,
        &previous_sources,
        &next,
        &next_sources,
    ));
}

#[test]
fn full_network_identity_ignores_signal_candidate_count_churn() {
    let mut previous = vec!["192.168.0.239:51820".to_string()];
    previous.extend((16_807..16_836).map(|port| format!("220.163.6.190:{port}")));
    let mut next = vec!["192.168.0.239:51820".to_string()];
    next.extend((16_809..16_841).map(|port| format!("220.163.6.190:{port}")));
    let previous_sources = previous
        .iter()
        .cloned()
        .map(|endpoint| {
            let source = if endpoint.starts_with("192.168.") {
                "host"
            } else {
                "predicted"
            };
            (endpoint, source.to_string())
        })
        .collect::<HashMap<_, _>>();
    let next_sources = next
        .iter()
        .cloned()
        .map(|endpoint| {
            let source = if endpoint.starts_with("192.168.") {
                "host"
            } else {
                "predicted"
            };
            (endpoint, source.to_string())
        })
        .collect::<HashMap<_, _>>();

    assert_eq!(
        stable_network_candidate_signature(&previous, &previous_sources),
        stable_network_candidate_signature(&next, &next_sources)
    );
}

#[test]
fn candidate_refresh_generation_ignores_public_source_label_churn() {
    let previous = vec![
        "192.168.1.10:59288".to_string(),
        "93.184.216.34:27106".to_string(),
    ];
    let previous_sources = HashMap::from([
        ("192.168.1.10:59288".to_string(), "host".to_string()),
        (
            "93.184.216.34:27106".to_string(),
            "peer_reflexive".to_string(),
        ),
    ]);
    let next = vec![
        "192.168.1.10:59288".to_string(),
        "93.184.216.34:31999".to_string(),
    ];
    let next_sources = HashMap::from([
        ("192.168.1.10:59288".to_string(), "host".to_string()),
        (
            "93.184.216.34:31999".to_string(),
            "stun_observed".to_string(),
        ),
    ]);
    let learned_next_sources = HashMap::from([
        ("192.168.1.10:59288".to_string(), "host".to_string()),
        ("93.184.216.34:31999".to_string(), "learned".to_string()),
    ]);

    assert!(!candidate_refresh_requires_network_generation_advance(
        &previous,
        &previous_sources,
        &next,
        &next_sources,
    ));
    assert!(!candidate_refresh_requires_network_generation_advance(
        &previous,
        &previous_sources,
        &next,
        &learned_next_sources,
    ));
}

#[test]
fn candidate_refresh_generation_ignores_private_source_label_churn() {
    let previous = vec![
        "192.168.1.10:59288".to_string(),
        "93.184.216.34:27106".to_string(),
    ];
    let previous_sources = HashMap::from([
        (
            "192.168.1.10:59288".to_string(),
            "peer_reflexive".to_string(),
        ),
        (
            "93.184.216.34:27106".to_string(),
            "stun_observed".to_string(),
        ),
    ]);
    let next = vec![
        "192.168.1.10:59288".to_string(),
        "93.184.216.34:31999".to_string(),
    ];
    let next_sources = HashMap::from([
        ("192.168.1.10:59288".to_string(), "host".to_string()),
        (
            "93.184.216.34:31999".to_string(),
            "stun_observed".to_string(),
        ),
    ]);

    assert!(!candidate_refresh_requires_network_generation_advance(
        &previous,
        &previous_sources,
        &next,
        &next_sources,
    ));
}

#[test]
fn candidate_refresh_generation_ignores_external_overlay_and_public_port_churn() {
    let previous = vec![
        "tailscale.example.com:60155".to_string(),
        "tailscale.example.com:58770".to_string(),
        "[fd7a:115c:a1e0::b936:4102]:60155".to_string(),
        "220.163.6.190:6979".to_string(),
        "220.163.6.190:6980".to_string(),
        "220.163.6.190:6984".to_string(),
    ];
    let previous_sources = HashMap::from([
        ("tailscale.example.com:60155".to_string(), "host".to_string()),
        ("tailscale.example.com:58770".to_string(), "host".to_string()),
        (
            "[fd7a:115c:a1e0::b936:4102]:60155".to_string(),
            "host".to_string(),
        ),
        (
            "220.163.6.190:6979".to_string(),
            "stun_observed".to_string(),
        ),
        (
            "220.163.6.190:6980".to_string(),
            "stun_observed".to_string(),
        ),
        ("220.163.6.190:6984".to_string(), "predicted".to_string()),
    ]);
    let next = vec![
        "tailscale.example.com:59581".to_string(),
        "tailscale.example.com:60155".to_string(),
        "[fd7a:115c:a1e0::b936:4102]:60155".to_string(),
        "220.163.6.190:6981".to_string(),
        "220.163.6.190:6983".to_string(),
        "220.163.6.190:6995".to_string(),
    ];
    let next_sources = HashMap::from([
        ("tailscale.example.com:59581".to_string(), "host".to_string()),
        ("tailscale.example.com:60155".to_string(), "host".to_string()),
        (
            "[fd7a:115c:a1e0::b936:4102]:60155".to_string(),
            "host".to_string(),
        ),
        (
            "220.163.6.190:6981".to_string(),
            "stun_observed".to_string(),
        ),
        (
            "220.163.6.190:6983".to_string(),
            "stun_observed".to_string(),
        ),
        ("220.163.6.190:6995".to_string(), "predicted".to_string()),
    ]);

    assert!(!candidate_refresh_requires_network_generation_advance(
        &previous,
        &previous_sources,
        &next,
        &next_sources,
    ));
}

#[test]
fn candidate_refresh_generation_advances_on_host_or_public_ip_change() {
    let previous = vec![
        "192.168.1.10:59288".to_string(),
        "93.184.216.34:27106".to_string(),
    ];
    let previous_sources = HashMap::from([
        ("192.168.1.10:59288".to_string(), "host".to_string()),
        (
            "93.184.216.34:27106".to_string(),
            "stun_observed".to_string(),
        ),
    ]);
    let host_changed = vec![
        "192.168.2.10:59288".to_string(),
        "93.184.216.34:27106".to_string(),
    ];
    let host_changed_sources = HashMap::from([
        ("192.168.2.10:59288".to_string(), "host".to_string()),
        (
            "93.184.216.34:27106".to_string(),
            "stun_observed".to_string(),
        ),
    ]);
    let public_ip_changed = vec![
        "192.168.1.10:59288".to_string(),
        "93.184.216.35:27106".to_string(),
    ];
    let public_ip_changed_sources = HashMap::from([
        ("192.168.1.10:59288".to_string(), "host".to_string()),
        (
            "93.184.216.35:27106".to_string(),
            "stun_observed".to_string(),
        ),
    ]);

    assert!(candidate_refresh_requires_network_generation_advance(
        &previous,
        &previous_sources,
        &host_changed,
        &host_changed_sources,
    ));
    assert!(candidate_refresh_requires_network_generation_advance(
        &previous,
        &previous_sources,
        &public_ip_changed,
        &public_ip_changed_sources,
    ));
}

#[test]
fn candidate_set_change_reason_ignores_order_only_reshuffles() {
    let previous = vec![
        "222.221.150.140:2073".to_string(),
        "192.168.2.16:53387".to_string(),
        "222.221.150.140:2076".to_string(),
    ];
    let mut shuffled = previous.clone();
    shuffled.reverse();
    let sources = previous
        .iter()
        .map(|endpoint| (endpoint.clone(), "stun_observed".to_string()))
        .collect::<HashMap<_, _>>();
    let shuffled_sources = shuffled
        .iter()
        .map(|endpoint| (endpoint.clone(), "stun_observed".to_string()))
        .collect::<HashMap<_, _>>();

    assert_eq!(
        candidate_set_change_reason(&previous, &shuffled, &sources, &shuffled_sources),
        "order_only"
    );
    assert_eq!(
        candidate_set_change_reason(&previous, &previous, &sources, &sources.clone()),
        "no_change"
    );
    assert_eq!(
        candidate_set_hash(&previous, &sources),
        candidate_set_hash(&shuffled, &shuffled_sources),
        "order-only reshuffles must hash identically"
    );
}

#[test]
fn candidate_set_change_reason_detects_added_removed_and_port_changes() {
    let previous = vec![
        "222.221.150.140:2073".to_string(),
        "222.221.150.140:2076".to_string(),
    ];
    let sources = previous
        .iter()
        .map(|endpoint| (endpoint.clone(), "stun_observed".to_string()))
        .collect::<HashMap<_, _>>();
    let added = vec![
        "222.221.150.140:2073".to_string(),
        "222.221.150.140:2076".to_string(),
        "222.221.150.140:2077".to_string(),
    ];
    let added_sources = added
        .iter()
        .map(|endpoint| (endpoint.clone(), "stun_observed".to_string()))
        .collect::<HashMap<_, _>>();
    let removed = vec!["222.221.150.140:2073".to_string()];
    let removed_sources = removed
        .iter()
        .map(|endpoint| (endpoint.clone(), "stun_observed".to_string()))
        .collect::<HashMap<_, _>>();
    let port_changed = vec![
        "222.221.150.140:2073".to_string(),
        "222.221.150.140:2079".to_string(),
    ];
    let port_changed_sources = port_changed
        .iter()
        .map(|endpoint| (endpoint.clone(), "stun_observed".to_string()))
        .collect::<HashMap<_, _>>();

    assert_eq!(
        candidate_set_change_reason(&previous, &added, &sources, &added_sources),
        "added"
    );
    assert_eq!(
        candidate_set_change_reason(&previous, &removed, &sources, &removed_sources),
        "removed"
    );
    assert_eq!(
        candidate_set_change_reason(&previous, &port_changed, &sources, &port_changed_sources),
        "port_changed"
    );
    assert_eq!(
        candidate_set_change_reason(
            &previous,
            &previous,
            &sources,
            &previous
                .iter()
                .map(|endpoint| (endpoint.clone(), "peer_reflexive".to_string()))
                .collect::<HashMap<_, _>>(),
        ),
        "source_changed"
    );
}
