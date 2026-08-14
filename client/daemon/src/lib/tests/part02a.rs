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
    assert!(
        candidates
            .iter()
            .any(|candidate| candidate.starts_with("192.168.1.")),
        "the signal cap must reserve room for physical LAN host candidates"
    );
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
fn canonical_network_identity_is_computed_before_air_sized_signal_cap() {
    let physical_host = "192.168.0.239:56255".to_string();
    let shared_lan_host = "tailscale.example.com:56255".to_string();
    let ten_twenty_lan_host = "10.20.0.13:56255".to_string();
    let mut candidates = vec![
        physical_host.clone(),
        shared_lan_host.clone(),
        ten_twenty_lan_host.clone(),
    ];
    candidates.extend((20_000..20_120).map(|port| format!("93.184.216.34:{port}")));
    let mut sources = candidates
        .iter()
        .cloned()
        .map(|endpoint| {
            let source = if endpoint == physical_host
                || endpoint == shared_lan_host
                || endpoint == ten_twenty_lan_host
            {
                "host"
            } else {
                "predicted"
            };
            (endpoint, source.to_string())
        })
        .collect::<HashMap<_, _>>();

    let identity = prepare_signal_candidates_and_network_identity(
        &[],
        &HashMap::new(),
        &mut candidates,
        &mut sources,
    );

    assert_eq!(candidates.len(), MAX_SIGNAL_CANDIDATES);
    assert!(candidates.contains(&physical_host));
    assert!(candidates.contains(&shared_lan_host));
    assert!(candidates.contains(&ten_twenty_lan_host));
    assert!(identity.contains(&"physical-host-ip:192.168.0.239".to_string()));
    assert!(identity.contains(&"physical-host-ip:tailscale.example.com".to_string()));
    assert!(identity.contains(&"physical-host-ip:10.20.0.13".to_string()));
    assert!(identity.contains(&"public-ip:93.184.216.34".to_string()));
    assert_eq!(sources.len(), candidates.len());
}

#[test]
fn host_reservation_is_stable_across_interface_enumeration_order() {
    fn retained_hosts(mut candidates: Vec<String>) -> Vec<String> {
        candidates.extend((20_000..20_120).map(|port| format!("93.184.216.34:{port}")));
        let mut sources = candidates
            .iter()
            .cloned()
            .map(|endpoint| {
                let source = if endpoint.starts_with("93.184.216.34:") {
                    "predicted"
                } else {
                    "host"
                };
                (endpoint, source.to_string())
            })
            .collect::<HashMap<_, _>>();
        truncate_signal_candidates(&mut candidates, &mut sources);
        candidates
            .into_iter()
            .filter(|candidate| sources.get(candidate).map(String::as_str) == Some("host"))
            .collect()
    }

    let hosts = (1..=12)
        .map(|index| format!("10.20.1.{index}:51820"))
        .chain(["[fd12:3456::1]:51820".to_string()])
        .collect::<Vec<_>>();
    let mut reversed = hosts.clone();
    reversed.reverse();

    assert_eq!(retained_hosts(hosts), retained_hosts(reversed));
}

#[test]
fn canonical_network_identity_ignores_capped_prediction_window_churn() {
    fn prepared_identity(first_port: u16) -> Vec<String> {
        let host = "192.168.0.239:56255".to_string();
        let mut candidates = vec![host.clone()];
        candidates.extend(
            (first_port..first_port + 120).map(|port| format!("93.184.216.34:{port}")),
        );
        let mut sources = candidates
            .iter()
            .cloned()
            .map(|endpoint| {
                let source = if endpoint == host { "host" } else { "predicted" };
                (endpoint, source.to_string())
            })
            .collect::<HashMap<_, _>>();
        let identity = prepare_signal_candidates_and_network_identity(
            &[],
            &HashMap::new(),
            &mut candidates,
            &mut sources,
        );
        assert_eq!(candidates.len(), MAX_SIGNAL_CANDIDATES);
        assert!(candidates.contains(&host));
        identity
    }

    assert_eq!(prepared_identity(20_000), prepared_identity(21_000));
}

#[test]
fn identity_only_candidate_refresh_still_requires_commit() {
    assert!(candidate_refresh_requires_commit(false, true));
    assert!(candidate_refresh_requires_commit(true, false));
    assert!(!candidate_refresh_requires_commit(false, false));
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
fn candidate_refresh_generation_ignores_additive_interfaces_and_peer_reflexive_endpoints() {
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
    let mut next = previous.clone();
    next.push("192.168.2.10:59288".to_string());
    next.push("198.51.100.44:49001".to_string());
    let next_sources = HashMap::from([
        ("192.168.1.10:59288".to_string(), "host".to_string()),
        ("192.168.2.10:59288".to_string(), "host".to_string()),
        (
            "93.184.216.34:27106".to_string(),
            "stun_observed".to_string(),
        ),
        (
            "198.51.100.44:49001".to_string(),
            "peer_reflexive".to_string(),
        ),
    ]);

    assert!(
        !candidate_refresh_requires_network_generation_advance(
            &previous,
            &previous_sources,
            &next,
            &next_sources,
        ),
        "an additive interface or remote peer-reflexive endpoint must not revoke the current generation"
    );
}

#[test]
fn candidate_refresh_carries_identity_through_transient_stun_loss() {
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
    let mut next = vec!["192.168.1.10:60000".to_string()];
    let mut next_sources = HashMap::from([("192.168.1.10:60000".to_string(), "host".to_string())]);
    let identity = prepare_signal_candidates_and_network_identity(
        &previous,
        &previous_sources,
        &mut next,
        &mut next_sources,
    );

    assert!(identity.contains(&"public-ip:93.184.216.34".to_string()));
    assert!(identity.contains(&"physical-host-ip:192.168.1.10".to_string()));
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

#[test]
fn fresh_window_survives_full_candidate_set_with_order_and_budget() {
    // Scenario from the field: 96 ordinary candidates are already gathered
    // when a fresh-mapping prediction window must be signaled.
    let mut candidates = (1..=MAX_SIGNAL_CANDIDATES)
        .map(|index| {
            format!(
                "198.51.100.{}:{}",
                index % 32 + 1,
                40000 + index
            )
        })
        .collect::<Vec<_>>();
    let mut sources = candidates
        .iter()
        .cloned()
        .map(|endpoint| (endpoint, "stun_observed".to_string()))
        .collect::<HashMap<_, _>>();
    // Mix in ordinary predicted candidates that must NOT be mistaken for the
    // fresh window.
    for (offset, label) in [
        ("198.51.100.33:43001", "predicted"),
        ("198.51.100.33:43003", "predicted"),
        ("198.51.100.33:43005", "predicted"),
    ] {
        candidates.push(offset.to_string());
        sources.insert(offset.to_string(), label.to_string());
    }

    // The fresh window: top-1 first, then the successor window, all on the
    // public IP the model observed.
    let boot: u64 = 1_742_987_654_321;
    let fresh_label = fresh_prediction_source_label(FreshPredictionId {
        boot_epoch: boot,
        generation: 39,
    });
    let window = (0..MAX_SIGNAL_FRESH_WINDOW_CANDIDATES)
        .map(|distance| format!("203.0.113.10:{}", 45393 + distance))
        .collect::<Vec<_>>();
    let mut fresh = window.clone();
    fresh.reverse();
    for endpoint in fresh {
        candidates.insert(0, endpoint.clone());
        sources.insert(endpoint, fresh_label.clone());
    }

    truncate_signal_candidates(&mut candidates, &mut sources);

    // The output stays within the wire limit, the whole fresh window survives
    // in sender order (top-1 first), and the source map stays aligned.
    assert!(candidates.len() <= MAX_SIGNAL_CANDIDATES);
    assert_eq!(candidates.len(), MAX_SIGNAL_CANDIDATES);
    assert_eq!(sources.len(), candidates.len());
    assert!(sources.keys().all(|endpoint| candidates.contains(endpoint)));
    let kept_window = window
        .iter()
        .filter(|endpoint| candidates.contains(endpoint))
        .collect::<Vec<_>>();
    assert_eq!(kept_window.len(), MAX_SIGNAL_FRESH_WINDOW_CANDIDATES);
    let kept_ports = kept_window
        .iter()
        .map(|endpoint| endpoint.parse::<SocketAddr>().unwrap().port())
        .collect::<Vec<_>>();
    assert_eq!(
        kept_ports,
        (45393u16..45393u16 + MAX_SIGNAL_FRESH_WINDOW_CANDIDATES as u16).collect::<Vec<_>>(),
        "fresh window ports must all be preserved in sender order"
    );
    // Fresh candidates lead the list so the receiver probes top-1 first.
    assert_eq!(
        candidates[0],
        "203.0.113.10:45393",
        "fresh top-1 must stay first"
    );
    // Every surviving fresh endpoint carries the fresh label.
    for endpoint in &window {
        if candidates.contains(endpoint) {
            assert_eq!(
                sources.get(endpoint).map(String::as_str),
                Some(fresh_label.as_str()),
                "fresh label must survive truncation for {endpoint}"
            );
        }
    }
    // Ordinary predicted candidates that survived are still ordinary.
    for (endpoint, label) in [
        ("198.51.100.33:43001", "predicted"),
        ("198.51.100.33:43003", "predicted"),
        ("198.51.100.33:43005", "predicted"),
    ] {
        if candidates.contains(&endpoint.to_string()) {
            assert_eq!(
                sources.get(endpoint).map(String::as_str),
                Some(label),
                "ordinary predicted candidate must not be relabeled fresh"
            );
        }
    }
}

#[test]
fn malformed_and_zero_generation_labels_do_not_claim_fresh_budget() {
    let boot: u64 = 1_742_987_654_321;
    let mut candidates = (1..=MAX_SIGNAL_CANDIDATES + 8)
        .map(|index| format!("198.51.100.1:{}", 40000 + index))
        .collect::<Vec<_>>();
    let mut sources = candidates
        .iter()
        .cloned()
        .map(|endpoint| (endpoint, "stun_observed".to_string()))
        .collect::<HashMap<_, _>>();
    // Malformed labels and generation zero are NOT fresh: they degrade to
    // ordinary predicted candidates and must not reserve the fresh budget.
    for (endpoint, label) in [
        ("203.0.113.10:46001", format!("{FRESH_PREDICTION_SOURCE_LABEL_PREFIX}garbage")),
        ("203.0.113.10:46002", format!("{FRESH_PREDICTION_SOURCE_LABEL_PREFIX}{boot}:0")),
        ("203.0.113.10:46003", format!("{FRESH_PREDICTION_SOURCE_LABEL_PREFIX}39")),
        ("203.0.113.10:46004", "predicted".to_string()),
    ] {
        candidates.push(endpoint.to_string());
        sources.insert(endpoint.to_string(), label);
    }

    truncate_signal_candidates(&mut candidates, &mut sources);

    assert!(candidates.len() <= MAX_SIGNAL_CANDIDATES);
    // None of the degraded labels survived as reserved candidates; if any of
    // the 203.0.113.10 endpoints survived at all it is only via the ordinary
    // truncation path, never ahead of the STUN candidates.
    for endpoint in [
        "203.0.113.10:46001",
        "203.0.113.10:46002",
        "203.0.113.10:46003",
        "203.0.113.10:46004",
    ] {
        if candidates.contains(&endpoint.to_string()) {
            assert!(
                candidates.iter().position(|c| c == endpoint).unwrap() >= 4,
                "degraded predicted candidate must not jump ahead of the STUN prefix"
            );
        }
    }
    assert!(
        candidates.iter().all(|endpoint| {
            !crate::parse_fresh_prediction_source_label(
                sources.get(endpoint).map(String::as_str).unwrap_or(""),
            )
            .is_some()
        }),
        "no malformed/zero label may be treated as a valid fresh prediction"
    );
}

#[test]
fn fresh_window_mixes_with_lan_hosts_and_multiple_public_ips() {
    let boot: u64 = 1_742_987_654_321;
    let fresh_label = fresh_prediction_source_label(FreshPredictionId {
        boot_epoch: boot,
        generation: 7,
    });
    // LAN host candidates are a necessary reservation and must survive.
    let mut candidates = vec![
        "192.168.1.10:51820".to_string(),
        "192.168.1.11:51820".to_string(),
        "10.0.0.5:51820".to_string(),
    ];
    let mut sources = candidates
        .iter()
        .cloned()
        .map(|endpoint| (endpoint, "host".to_string()))
        .collect::<HashMap<_, _>>();
    // Two public IPs with fresh + ordinary predicted + STUN candidates.
    for index in 1..=MAX_SIGNAL_CANDIDATES {
        let endpoint = if index % 2 == 0 {
            format!("198.51.100.10:{}", 40000 + index)
        } else {
            format!("198.51.100.20:{}", 40000 + index)
        };
        candidates.push(endpoint.clone());
        sources.insert(endpoint, "stun_observed".to_string());
    }
    for distance in (0..MAX_SIGNAL_FRESH_WINDOW_CANDIDATES).rev() {
        let endpoint = format!("203.0.113.10:{}", 45393 + distance);
        candidates.insert(0, endpoint.clone());
        sources.insert(endpoint, fresh_label.clone());
    }
    let ordinary_predicted = "198.51.100.30:43009".to_string();
    candidates.push(ordinary_predicted.clone());
    sources.insert(ordinary_predicted.clone(), "predicted".to_string());

    truncate_signal_candidates(&mut candidates, &mut sources);

    assert_eq!(candidates.len(), MAX_SIGNAL_CANDIDATES);
    assert_eq!(sources.len(), MAX_SIGNAL_CANDIDATES);
    // LAN hosts yield when the fresh window reserves the whole budget: the
    // prediction window is time-sensitive and the peer already learned LAN
    // hosts from earlier signals.
    for endpoint in ["192.168.1.10:51820", "192.168.1.11:51820", "10.0.0.5:51820"] {
        assert!(
            !candidates.contains(&endpoint.to_string()),
            "LAN host {endpoint} must yield to the full fresh window"
        );
    }
    // Whole fresh window preserved, ordered top-1 first, and leading.
    let window_ports = candidates
        .iter()
        .take(MAX_SIGNAL_FRESH_WINDOW_CANDIDATES)
        .map(|endpoint| endpoint.parse::<SocketAddr>().unwrap().port())
        .collect::<Vec<_>>();
    assert_eq!(window_ports, (45393u16..45393u16 + MAX_SIGNAL_FRESH_WINDOW_CANDIDATES as u16).collect::<Vec<_>>());
    // Ordinary predicted may or may not survive the STUN-filled budget; if it
    // does it stays an ordinary predicted candidate.
    if candidates.contains(&ordinary_predicted) {
        assert_eq!(
            sources.get(&ordinary_predicted).map(String::as_str),
            Some("predicted")
        );
    }
    // Source map aligned and fresh labels intact.
    assert!(sources.keys().all(|endpoint| candidates.contains(endpoint)));
    let fresh_kept = candidates
        .iter()
        .filter(|endpoint| {
            crate::parse_fresh_prediction_source_label(
                sources.get(*endpoint).map(String::as_str).unwrap_or(""),
            )
            .is_some()
        })
        .count();
    assert_eq!(fresh_kept, MAX_SIGNAL_FRESH_WINDOW_CANDIDATES);
    // A full fresh window reserves the whole wire budget: ordinary STUN
    // candidates and LAN hosts yield (the peer already learned them from the
    // offer), and the payload is exactly the prediction window.
    assert!(candidates
        .iter()
        .all(|c| !c.starts_with("198.51.100.10:") && !c.starts_with("198.51.100.20:")));
}
