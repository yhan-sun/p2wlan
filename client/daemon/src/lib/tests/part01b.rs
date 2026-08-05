#[test]
fn test_advertised_udp_endpoint_uses_configured_value() {
    let local = "0.0.0.0:51820".parse().unwrap();
    assert_eq!(
        advertised_udp_endpoint(local, Some("203.0.113.10:51820"), &[]),
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
                "74.125.250.129:43000".to_string()
            ]
        ),
        Some("74.125.250.129:43000".to_string())
    );
}

#[test]
fn test_advertised_udp_endpoint_uses_specific_bind_address() {
    let local = "127.0.0.1:51820".parse().unwrap();
    assert_eq!(
        advertised_udp_endpoint(local, None, &[]),
        Some("127.0.0.1:51820".to_string())
    );
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
        "8.8.8.8:41000"
    ));
}

#[test]
fn stable_control_endpoint_refresh_ignores_same_public_ip_port_churn() {
    assert!(!should_update_stable_control_endpoint(
        Some("8.8.8.8:41000"),
        "8.8.8.8:41037"
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
