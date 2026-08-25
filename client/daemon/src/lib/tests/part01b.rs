#[test]
fn test_advertised_udp_endpoint_uses_configured_value() {
    let local = "0.0.0.0:51820".parse().unwrap();
    assert_eq!(
        advertised_udp_endpoint(
            local,
            Some("203.0.113.10:51820"),
            &[],
            &HashMap::new(),
            false,
        ),
        Some("203.0.113.10:51820".to_string())
    );
}

#[test]
fn test_advertised_udp_endpoint_uses_public_candidate_for_unspecified_bind() {
    let local = "0.0.0.0:51820".parse().unwrap();
    assert_eq!(
        advertised_udp_endpoint(
            local,
            None,
            &[
                "192.168.1.10:51820".to_string(),
                "8.8.8.8:43000".to_string()
            ],
            &HashMap::new(),
            false,
        ),
        Some("8.8.8.8:43000".to_string())
    );
}

#[test]
fn test_advertised_udp_endpoint_uses_specific_bind_address() {
    let local = "127.0.0.1:51820".parse().unwrap();
    assert_eq!(
        advertised_udp_endpoint(local, None, &[], &HashMap::new(), true),
        Some("127.0.0.1:51820".to_string())
    );
}

#[test]
fn advertised_udp_endpoint_omits_specific_bind_when_host_candidates_are_disabled() {
    let local = "127.0.0.1:51820".parse().unwrap();
    assert_eq!(
        advertised_udp_endpoint(local, None, &[], &HashMap::new(), false),
        None
    );
}

#[test]
fn advertised_udp_endpoint_prefers_public_candidate_over_private_host() {
    // Field evidence (v0.1.116 acceptance): advertising the private host
    // endpoint first made the peer punch the unreachable private address and
    // cold-start rounds timed out at ~102 s.  A public reflexive mapping must
    // win over the private host address even when host candidates are
    // enabled.
    let local: SocketAddr = "192.168.0.239:60482".parse().unwrap();
    let candidates = vec![
        "192.168.0.239:60482".to_string(),
        "220.165.178.32:7361".to_string(),
    ];
    let sources = HashMap::from([
        (candidates[0].clone(), "host".to_string()),
        (candidates[1].clone(), "stun_observed".to_string()),
    ]);
    assert_eq!(
        advertised_udp_endpoint(local, None, &candidates, &sources, true),
        Some("220.165.178.32:7361".to_string()),
        "the public reflexive mapping must be the advertised endpoint"
    );
    // Without any public candidate, the private host address remains the
    // fallback (LAN-only deployments).
    assert_eq!(
        advertised_udp_endpoint(
            local,
            None,
            &["192.168.0.239:60482".to_string()],
            &HashMap::from([(
                "192.168.0.239:60482".to_string(),
                "host".to_string(),
            )]),
            true,
        ),
        Some("192.168.0.239:60482".to_string())
    );
}

#[test]
fn advertised_endpoint_does_not_treat_global_host_as_public_proof() {
    let local: SocketAddr = "0.0.0.0:58079".parse().unwrap();
    let candidates = vec![
        "20.0.3.148:58079".to_string(),
        "10.23.176.16:58079".to_string(),
    ];
    let sources = HashMap::from([
        (candidates[0].clone(), "host".to_string()),
        (candidates[1].clone(), "host".to_string()),
    ]);

    assert_eq!(
        advertised_udp_endpoint(local, None, &candidates, &sources, true),
        Some("10.23.176.16:58079".to_string())
    );
}

#[test]
fn control_endpoint_keeps_private_host_ahead_of_unverified_global_host() {
    let candidates = vec![
        "20.0.3.148:58079".to_string(),
        "10.23.176.16:58079".to_string(),
    ];
    let sources = HashMap::from([
        (candidates[0].clone(), "host".to_string()),
        (candidates[1].clone(), "host".to_string()),
    ]);

    assert_eq!(
        control_udp_endpoint_from_candidates(&candidates, &sources).as_deref(),
        Some("10.23.176.16:58079")
    );
    assert!(!crate::candidate_refresh::has_real_public_candidate(
        &candidates,
        &sources
    ));
}

#[test]
fn control_endpoint_prefers_explicit_mapping_over_stun_candidate() {
    let candidates = vec!["8.8.8.8:41000".to_string(), "1.1.1.1:60207".to_string()];
    let sources = HashMap::from([
        ("8.8.8.8:41000".to_string(), "stun_observed".to_string()),
        ("1.1.1.1:60207".to_string(), "pcp".to_string()),
    ]);

    assert_eq!(
        control_udp_endpoint_from_candidates(&candidates, &sources).as_deref(),
        Some("1.1.1.1:60207")
    );
}

#[test]
fn control_endpoint_does_not_publish_peer_reflexive_as_global_endpoint() {
    let candidates = vec!["1.1.1.1:42000".to_string(), "8.8.8.8:41000".to_string()];
    let sources = HashMap::from([
        ("1.1.1.1:42000".to_string(), "peer_reflexive".to_string()),
        ("8.8.8.8:41000".to_string(), "stun_observed".to_string()),
    ]);

    assert_eq!(
        control_udp_endpoint_from_candidates(&candidates, &sources).as_deref(),
        Some("8.8.8.8:41000")
    );
}

#[test]
fn control_endpoint_does_not_publish_speculative_candidate() {
    let candidates = vec!["1.1.1.1:42008".to_string(), "8.8.8.8:41000".to_string()];
    let sources = HashMap::from([
        ("1.1.1.1:42008".to_string(), "predicted".to_string()),
        ("8.8.8.8:41000".to_string(), "stun_observed".to_string()),
    ]);

    assert_eq!(
        control_udp_endpoint_from_candidates(&candidates, &sources).as_deref(),
        Some("8.8.8.8:41000")
    );
}

#[test]
fn stable_control_endpoint_refresh_promotes_private_to_public() {
    assert!(should_update_stable_control_endpoint(
        Some("192.168.0.239:52633"),
        "8.8.8.8:41000",
        MappingBehavior::EndpointIndependent,
    ));
}

#[test]
fn stable_control_endpoint_refresh_ignores_same_public_ip_port_churn() {
    assert!(!should_update_stable_control_endpoint(
        Some("8.8.8.8:41000"),
        "8.8.8.8:41037",
        MappingBehavior::EndpointIndependent,
    ));
}

#[test]
fn symmetric_control_endpoint_refresh_publishes_same_ip_port_churn() {
    assert!(should_update_stable_control_endpoint(
        Some("8.8.8.8:41000"),
        "8.8.8.8:41037",
        MappingBehavior::AddressOrPortDependent,
    ));
}

#[test]
fn signal_candidates_compact_volatile_public_ports_per_public_ip() {
    let mut candidates = vec!["192.168.1.10:51820".to_string()];
    candidates.extend((0..120).map(|index| format!("8.8.8.8:{}", 41000 + index)));
    candidates.extend(["1.1.1.1:42000".to_string(), "1.1.1.1:42009".to_string()]);
    let mut sources = candidates
        .iter()
        .cloned()
        .map(|endpoint| (endpoint, "stun_observed".to_string()))
        .collect::<HashMap<_, _>>();
    sources.insert("192.168.1.10:51820".to_string(), "host".to_string());

    compact_volatile_public_signal_candidates(&mut candidates, &mut sources);

    assert_eq!(candidates.len(), 1 + MAX_SIGNAL_VOLATILE_PUBLIC_PER_PUBLIC_IP + 2);
    assert!(candidates.contains(&"192.168.1.10:51820".to_string()));
    assert!(candidates.contains(&"1.1.1.1:42000".to_string()));
    assert!(candidates.contains(&"1.1.1.1:42009".to_string()));
    assert_eq!(
        candidates
            .iter()
            .filter(|endpoint| endpoint.starts_with("8.8.8.8:"))
            .count(),
        MAX_SIGNAL_VOLATILE_PUBLIC_PER_PUBLIC_IP
    );
    assert!(candidates.contains(&"8.8.8.8:41095".to_string()));
    assert!(!candidates.contains(&"8.8.8.8:41096".to_string()));
    assert!(!candidates.contains(&"8.8.8.8:41119".to_string()));
    assert!(sources.keys().all(|endpoint| candidates.contains(endpoint)));
}

#[test]
fn signal_candidate_cap_preserves_high_teen_linear_prediction() {
    let mut candidates = vec!["192.168.1.10:51820".to_string()];
    candidates.extend((8135..=8137).map(|port| format!("220.163.6.190:{port}")));
    candidates.extend((8138..=8161).map(|port| format!("220.163.6.190:{port}")));
    let mut sources = HashMap::from([("192.168.1.10:51820".to_string(), "host".to_string())]);
    for port in 8135..=8137 {
        sources.insert(format!("220.163.6.190:{port}"), "stun_observed".to_string());
    }
    for port in 8138..=8161 {
        sources.insert(format!("220.163.6.190:{port}"), "predicted".to_string());
    }

    compact_volatile_public_signal_candidates(&mut candidates, &mut sources);
    truncate_signal_candidates(&mut candidates, &mut sources);

    assert_eq!(candidates.len(), 28);
    assert!(candidates.contains(&"220.163.6.190:8154".to_string()));
    assert!(candidates.contains(&"220.163.6.190:8161".to_string()));
    assert_eq!(
        sources.get("220.163.6.190:8154").map(String::as_str),
        Some("predicted")
    );
    assert!(sources.keys().all(|endpoint| candidates.contains(endpoint)));
}

#[test]
fn signal_candidate_cap_keeps_bounded_private_hosts_without_hardcoded_overlay_ranges() {
    let tailscale_v4 = "100.84.190.40:51820".to_string();
    let tailscale_v6 = "[fd7a:115c:a1e0::e136:be29]:51820".to_string();
    let p2wlan_overlay = "10.20.0.13:51820".to_string();
    let mut candidates = vec![
        tailscale_v4.clone(),
        tailscale_v6.clone(),
        p2wlan_overlay.clone(),
    ];
    candidates.extend((8135..=8240).map(|port| format!("220.163.6.190:{port}")));

    let mut sources = candidates
        .iter()
        .cloned()
        .map(|endpoint| (endpoint, "predicted".to_string()))
        .collect::<HashMap<_, _>>();
    sources.insert(tailscale_v4.clone(), "host".to_string());
    sources.insert(tailscale_v6.clone(), "host".to_string());
    sources.insert(p2wlan_overlay.clone(), "host".to_string());

    truncate_signal_candidates(&mut candidates, &mut sources);

    assert_eq!(candidates.len(), MAX_SIGNAL_CANDIDATES);
    assert!(candidates.contains(&tailscale_v4));
    assert!(candidates.contains(&tailscale_v6));
    assert!(candidates.contains(&p2wlan_overlay));
    assert_eq!(
        candidates
            .iter()
            .filter(|endpoint| endpoint.starts_with("220.163.6.190:"))
            .count(),
        MAX_SIGNAL_CANDIDATES - 3
    );
    assert!(sources.keys().all(|endpoint| candidates.contains(endpoint)));
}

/// The full prepare pipeline (compact then truncate) must never delete a
/// fresh-mapping prediction port before the truncate stage can reserve it:
/// 96 ordinary volatile candidates on the same public IP plus the complete
/// 24-port fresh window must end with every fresh port preserved, in sender
/// order (top-1 first), inside the 96-candidate signaling budget.
#[test]
fn fresh_window_survives_full_prepare_pipeline_alongside_96_ordinary_volatile() {
    let fresh_id = crate::FreshPredictionId {
        boot_epoch: 1_742_987_654_321,
        generation: 7,
    };
    let fresh_label = crate::fresh_prediction_source_label(fresh_id);
    let mut candidates = Vec::new();
    let mut sources = HashMap::new();

    // 96 ordinary volatile public candidates, all on the same public IP.
    for index in 0..MAX_SIGNAL_CANDIDATES {
        let endpoint = format!("8.8.8.8:{}", 41000 + index);
        candidates.push(endpoint.clone());
        sources.insert(endpoint, "stun_observed".to_string());
    }
    // The complete 24-port fresh prediction window, sender order preserved:
    // the first entry is the model's top-1 prediction.
    let fresh_ports = (44_000..44_000 + MAX_SIGNAL_FRESH_WINDOW_CANDIDATES)
        .map(|port| port as u16);
    let mut fresh_endpoints = Vec::new();
    for port in fresh_ports {
        let endpoint = format!("8.8.8.8:{port}");
        fresh_endpoints.push(endpoint.clone());
        candidates.push(endpoint.clone());
        sources.insert(endpoint, fresh_label.clone());
    }
    assert_eq!(candidates.len(), MAX_SIGNAL_CANDIDATES + MAX_SIGNAL_FRESH_WINDOW_CANDIDATES);

    // Run the whole prepare pipeline exactly like the runtime refresh path.
    let identity = prepare_signal_candidates_and_network_identity(
        &[],
        &HashMap::new(),
        &mut candidates,
        &mut sources,
    );
    assert!(!identity.is_empty());

    // Every fresh window port survives, in the sender's original order.
    assert_eq!(
        candidates
            .iter()
            .filter(|endpoint| fresh_endpoints.contains(endpoint))
            .cloned()
            .collect::<Vec<_>>(),
        fresh_endpoints,
        "the fresh window must survive compact+truncate in sender order"
    );
    // The final set fits the wire budget.
    assert!(candidates.len() <= MAX_SIGNAL_CANDIDATES);
    // A full fresh window reserves the whole budget, so no ordinary candidate
    // is left in the payload.
    assert_eq!(candidates.len(), MAX_SIGNAL_FRESH_WINDOW_CANDIDATES);
    // Sources stay consistent with the surviving set.
    assert!(sources.keys().all(|endpoint| candidates.contains(endpoint)));
    assert!(fresh_endpoints
        .iter()
        .all(|endpoint| sources.get(endpoint).is_some_and(|source| source == &fresh_label)));
}

/// Compact must reserve the fresh window per public IP too: when ordinary
/// volatile candidates of the same IP would crowd the per-IP truncation
/// budget, fresh prediction ports are exempt and survive into the truncate
/// stage's reservation.
#[test]
fn compact_never_truncates_fresh_window_ports_before_reservation() {
    let fresh_id = crate::FreshPredictionId {
        boot_epoch: 1_742_987_654_322,
        generation: 3,
    };
    let fresh_label = crate::fresh_prediction_source_label(fresh_id);
    let mut candidates = Vec::new();
    let mut sources = HashMap::new();
    // 150 ordinary volatile candidates on one public IP (would overflow the
    // per-IP budget on their own) plus 24 fresh ports on the same IP.
    for index in 0..150 {
        let endpoint = format!("1.1.1.1:{}", 50000 + index);
        candidates.push(endpoint.clone());
        sources.insert(endpoint, "predicted".to_string());
    }
    let mut fresh_endpoints = Vec::new();
    for index in 0..MAX_SIGNAL_FRESH_WINDOW_CANDIDATES {
        let endpoint = format!("1.1.1.1:{}", 45500 + index);
        fresh_endpoints.push(endpoint.clone());
        candidates.push(endpoint.clone());
        sources.insert(endpoint, fresh_label.clone());
    }

    compact_volatile_public_signal_candidates(&mut candidates, &mut sources);
    truncate_signal_candidates(&mut candidates, &mut sources);

    assert_eq!(
        candidates
            .iter()
            .filter(|endpoint| fresh_endpoints.contains(endpoint))
            .cloned()
            .collect::<Vec<_>>(),
        fresh_endpoints
    );
    assert!(candidates.len() <= MAX_SIGNAL_CANDIDATES);
    assert!(sources.keys().all(|endpoint| candidates.contains(endpoint)));
}

#[test]
fn control_endpoint_selection_is_independent_of_proxy_policy() {
    // A proxy only affects how control-plane HTTP TRAFFIC is transported; it
    // must never change which STUN-derived UDP candidate is published.  The
    // same `control_udp_endpoint_from_candidates` result feeds both the PATCH
    // endpoint lease (`update_endpoint`) and the offer/answer candidate
    // payloads, so the server keeps saving the exact STUN-derived candidate
    // regardless of proxy mode.
    let candidates = vec!["8.8.8.8:41000".to_string(), "10.0.0.5:41000".to_string()];
    let sources = HashMap::from([
        ("8.8.8.8:41000".to_string(), "stun_observed".to_string()),
        ("10.0.0.5:41000".to_string(), "host".to_string()),
    ]);
    let selected = control_udp_endpoint_from_candidates(&candidates, &sources);
    assert_eq!(selected.as_deref(), Some("8.8.8.8:41000"));
    // The proxy policy never enters the candidate-selection function; both
    // modes resolve to the same STUN-derived endpoint.
    assert_eq!(crate::config::ControlProxyMode::Direct.as_label(), "direct");
    assert_eq!(crate::config::ControlProxyMode::Environment.as_label(), "environment");
}

#[test]
fn relay_first_defaults_and_probe_budgets_are_stable() {
    // These invariants are load-bearing for relay-first availability: the
    // socket pool stays off, the default UDP bind stays 0.0.0.0:0, and the
    // NAT probe budgets must not be changed by this work.
    let config = Config::generate_default("https://ctrl.test", "net1").unwrap();
    assert_eq!(config.network.udp_bind, "0.0.0.0:0");
    assert!(!config.network.socket_pool_enabled);
    assert_eq!(config.network.socket_pool_size, 1);
    assert_eq!(config.relay.relay_startup_timeout_ms, 3000);

    assert_eq!(crate::peer::PREDICTED_PROBE_BUDGET_PER_CYCLE, 96);
    assert_eq!(crate::peer::BIRTHDAY_PROBE_BUDGET_PER_CYCLE, 192);
    assert_eq!(crate::peer::BIRTHDAY_PROBE_SUCCESS_BUDGET_PER_CYCLE, 256);
    assert_eq!(crate::peer::BIRTHDAY_PROBE_FAILURE_BUDGET_PER_CYCLE, 192);
}

#[test]
fn relay_first_candidate_shortcut_never_waits_for_stun_when_relay_is_ready() {
    let cached = vec!["203.0.113.10:41000".to_string()];
    let sources = HashMap::from([(
        "203.0.113.10:41000".to_string(),
        "stun_observed".to_string(),
    )]);

    assert_eq!(
        relay_first_candidate_shortcut(cached.clone(), sources.clone(), true),
        Some((cached, sources)),
        "a committed snapshot must be used without a second refresh"
    );
    assert_eq!(
        relay_first_candidate_shortcut(Vec::new(), HashMap::new(), true),
        Some((Vec::new(), HashMap::new())),
        "relay availability permits an immediate empty-candidate encrypted handshake"
    );
    assert_eq!(
        relay_first_candidate_shortcut(Vec::new(), HashMap::new(), false),
        None,
        "without relay or candidates the caller must keep the bounded race alive"
    );
}

#[test]
fn signal_payload_json_keeps_stun_candidates_under_both_proxy_modes() {
    // The STUN-derived UDP candidates are signalled to the control plane as
    // JSON verbatim.  A proxy changes how the control-plane HTTP TRAFFIC is
    // transported; it must never substitute the proxy egress IP for a STUN
    // candidate — the candidate JSON is produced independently of the proxy
    // mode, and the selected control endpoint stays the STUN-observed one.
    use std::collections::HashMap;
    let candidates = vec![
        "8.8.8.8:41000".to_string(), // STUN-observed public endpoint
        "192.168.1.10:51820".to_string(), // host candidate
    ];
    let sources = HashMap::from([
        ("8.8.8.8:41000".to_string(), "stun_observed".to_string()),
        ("192.168.1.10:51820".to_string(), "host".to_string()),
    ]);
    // The prepared signal body carries the EXACT STUN candidate list in JSON.
    let payload = crate::control::prepare_signal_payload_for_test(
        "node-a",
        "node-b",
        "offer",
        &candidates,
        &sources,
        b"handshake-bytes",
        Some(1_000),
        None,
        Some("sess-1"),
        None,
        None,
    )
    .expect("signal payload must build");
    let json_candidates: Vec<String> = payload["candidates"]
        .as_array()
        .unwrap()
        .iter()
        .map(|c| c.as_str().unwrap().to_string())
        .collect();
    assert_eq!(json_candidates, candidates, "candidate JSON must be the STUN-derived list verbatim");
    assert_eq!(
        payload["candidate_sources"]["8.8.8.8:41000"],
        "stun_observed",
        "the STUN source label must survive into the JSON"
    );
    // Neither proxy mode rewrites the STUN-derived endpoint selection.
    for mode in [
        crate::config::ControlProxyMode::Direct,
        crate::config::ControlProxyMode::Environment,
    ] {
        assert_eq!(
            control_udp_endpoint_from_candidates(&candidates, &sources).as_deref(),
            Some("8.8.8.8:41000"),
            "proxy mode {mode:?} must never replace the STUN candidate with a proxy egress"
        );
    }
}
