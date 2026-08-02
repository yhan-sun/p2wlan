#[test]
fn test_build_nat_profile_unknown_without_observations() {
    let profile = build_nat_profile("192.168.1.2:5000".parse().unwrap(), Vec::new());
    assert_eq!(profile.mapping_behavior, MappingBehavior::Unknown);
    assert!(!profile.udp_blocked);
    assert_eq!(profile.public_endpoint, None);
    assert_eq!(profile.filtering_behavior, FilteringBehavior::Unknown);
    assert_eq!(profile.hairpin_behavior, HairpinBehavior::Unknown);
    assert_eq!(profile.mapping_lifetime, MappingLifetime::Unknown);
    assert!(!profile.prediction_candidate);
    assert!(profile.predicted_endpoints.is_empty());
    assert!(!profile.birthday_candidate);
    assert_eq!(profile.confidence, 0);
}

#[test]
fn test_build_nat_profile_udp_blocked_when_all_stun_failed() {
    let profile = build_nat_profile(
        "192.168.1.2:5000".parse().unwrap(),
        vec![StunObservation {
            server: "stun-a.example:3478".to_string(),
            mapped_address: None,
            rtt_ms: None,
            error: Some("timeout".to_string()),
        }],
    );
    assert_eq!(profile.mapping_behavior, MappingBehavior::UdpBlocked);
    assert!(profile.udp_blocked);
    assert_eq!(profile.likely_symmetric, None);
    assert_eq!(profile.filtering_behavior, FilteringBehavior::UdpBlocked);
    assert_eq!(profile.hairpin_behavior, HairpinBehavior::Unknown);
    assert_eq!(profile.mapping_lifetime, MappingLifetime::Unknown);
    assert!(!profile.prediction_candidate);
    assert!(profile.predicted_endpoints.is_empty());
    assert!(!profile.birthday_candidate);
    assert_eq!(profile.confidence, 60);
}

#[test]
fn test_build_nat_profile_unknown_when_stun_replies_without_mapping() {
    let profile = build_nat_profile(
        "192.168.1.2:5000".parse().unwrap(),
        vec![StunObservation {
            server: "stun-a.example:3478".to_string(),
            mapped_address: None,
            rtt_ms: Some(10),
            error: None,
        }],
    );
    assert_eq!(profile.mapping_behavior, MappingBehavior::Unknown);
    assert!(!profile.udp_blocked);
    assert_eq!(profile.filtering_behavior, FilteringBehavior::Unknown);
    assert_eq!(profile.hairpin_behavior, HairpinBehavior::Unknown);
    assert_eq!(profile.mapping_lifetime, MappingLifetime::Unknown);
    assert!(!profile.prediction_candidate);
    assert!(profile.predicted_endpoints.is_empty());
    assert!(!profile.birthday_candidate);
    assert_eq!(profile.confidence, 20);
}

#[test]
fn test_build_nat_profile_endpoint_independent_mapping() {
    let profile = build_nat_profile(
        "192.168.1.2:5000".parse().unwrap(),
        vec![
            StunObservation {
                server: "stun-a.example:3478".to_string(),
                mapped_address: Some("203.0.113.10:62000".to_string()),
                rtt_ms: Some(10),
                error: None,
            },
            StunObservation {
                server: "stun-b.example:3478".to_string(),
                mapped_address: Some("203.0.113.10:62000".to_string()),
                rtt_ms: Some(12),
                error: None,
            },
        ],
    );
    assert_eq!(
        profile.mapping_behavior,
        MappingBehavior::EndpointIndependent
    );
    assert_eq!(
        profile.public_endpoint.as_deref(),
        Some("203.0.113.10:62000")
    );
    assert_eq!(profile.public_ip_stable, Some(true));
    assert_eq!(profile.public_port_stable, Some(true));
    assert_eq!(profile.port_preserved, Some(false));
    assert_eq!(profile.likely_symmetric, Some(false));
    assert_eq!(profile.port_delta, Some(0));
    assert_eq!(profile.filtering_behavior, FilteringBehavior::Unknown);
    assert_eq!(profile.hairpin_behavior, HairpinBehavior::Unknown);
    assert_eq!(profile.mapping_lifetime, MappingLifetime::Unknown);
    assert!(!profile.prediction_candidate);
    assert!(profile.predicted_endpoints.is_empty());
    assert!(!profile.birthday_candidate);
    assert_eq!(profile.confidence, 70);
}

#[test]
fn test_build_nat_profile_detects_port_dependent_mapping() {
    let profile = build_nat_profile(
        "192.168.1.2:5000".parse().unwrap(),
        vec![
            StunObservation {
                server: "stun-a.example:3478".to_string(),
                mapped_address: Some("203.0.113.10:40001".to_string()),
                rtt_ms: Some(10),
                error: None,
            },
            StunObservation {
                server: "stun-b.example:3478".to_string(),
                mapped_address: Some("203.0.113.10:40003".to_string()),
                rtt_ms: Some(11),
                error: None,
            },
            StunObservation {
                server: "stun-c.example:3478".to_string(),
                mapped_address: Some("203.0.113.10:40005".to_string()),
                rtt_ms: Some(12),
                error: None,
            },
        ],
    );
    assert_eq!(
        profile.mapping_behavior,
        MappingBehavior::AddressOrPortDependent
    );
    assert_eq!(profile.public_ip_stable, Some(true));
    assert_eq!(profile.public_port_stable, Some(false));
    assert_eq!(profile.likely_symmetric, Some(true));
    assert_eq!(profile.port_delta, Some(2));
    assert_eq!(
        profile.filtering_behavior,
        FilteringBehavior::AddressOrPortDependent
    );
    assert_eq!(profile.hairpin_behavior, HairpinBehavior::Unknown);
    assert_eq!(profile.mapping_lifetime, MappingLifetime::Unknown);
    assert!(profile.prediction_candidate);
    assert_eq!(
        profile.predicted_endpoints,
        (1..=MAX_PREDICTED_REFLEXIVE_CANDIDATES)
            .map(|step| format!("203.0.113.10:{}", 40005 + 2 * step))
            .collect::<Vec<_>>()
    );
    assert!(profile.birthday_candidate);
    assert_eq!(profile.confidence, 90);
}

#[test]
fn test_build_nat_profile_detects_jittered_linear_symmetric_mapping() {
    let profile = build_nat_profile(
        "192.168.1.2:5000".parse().unwrap(),
        vec![
            StunObservation {
                server: "stun-a.example:3478".to_string(),
                mapped_address: Some("203.0.113.10:32794".to_string()),
                rtt_ms: Some(10),
                error: None,
            },
            StunObservation {
                server: "stun-b.example:3478".to_string(),
                mapped_address: Some("203.0.113.10:32796".to_string()),
                rtt_ms: Some(11),
                error: None,
            },
            StunObservation {
                server: "stun-c.example:3478".to_string(),
                mapped_address: Some("203.0.113.10:32797".to_string()),
                rtt_ms: Some(12),
                error: None,
            },
            StunObservation {
                server: "stun-d.example:3478".to_string(),
                mapped_address: Some("203.0.113.10:32798".to_string()),
                rtt_ms: Some(13),
                error: None,
            },
        ],
    );

    assert_eq!(profile.port_delta, Some(1));
    assert!(profile.prediction_candidate);
    assert_eq!(
        profile.predicted_endpoints.first().map(String::as_str),
        Some("203.0.113.10:32799")
    );
    assert_eq!(
        profile.predicted_endpoints.last().map(String::as_str),
        Some("203.0.113.10:32894")
    );
}

#[test]
fn test_predicted_reflexive_window_uses_stable_suffix_after_outlier() {
    let profile = build_nat_profile(
        "192.168.1.2:5000".parse().unwrap(),
        vec![
            StunObservation {
                server: "stun-a.example:3478".to_string(),
                mapped_address: Some("220.163.6.190:23801".to_string()),
                rtt_ms: Some(180),
                error: None,
            },
            StunObservation {
                server: "stun-b.example:3478".to_string(),
                mapped_address: Some("220.163.6.190:23855".to_string()),
                rtt_ms: Some(80),
                error: None,
            },
            StunObservation {
                server: "stun-c.example:3478".to_string(),
                mapped_address: Some("220.163.6.190:23856".to_string()),
                rtt_ms: Some(78),
                error: None,
            },
            StunObservation {
                server: "stun-d.example:3478".to_string(),
                mapped_address: Some("220.163.6.190:23857".to_string()),
                rtt_ms: Some(170),
                error: None,
            },
            StunObservation {
                server: "observer.example:18082".to_string(),
                mapped_address: Some("220.163.6.190:23858".to_string()),
                rtt_ms: Some(14),
                error: None,
            },
        ],
    );

    assert!(profile.prediction_candidate);
    assert_eq!(
        profile.predicted_endpoints.first().map(String::as_str),
        Some("220.163.6.190:23859")
    );
    assert!(profile
        .predicted_endpoints
        .contains(&"220.163.6.190:23920".to_string()));
}

#[test]
fn test_predicted_reflexive_window_covers_webrtc_style_jump() {
    let profile = build_nat_profile(
        "192.168.1.2:5000".parse().unwrap(),
        vec![
            StunObservation {
                server: "stun-a.example:3478".to_string(),
                mapped_address: Some("220.163.6.190:8135".to_string()),
                rtt_ms: Some(10),
                error: None,
            },
            StunObservation {
                server: "stun-b.example:3478".to_string(),
                mapped_address: Some("220.163.6.190:8136".to_string()),
                rtt_ms: Some(11),
                error: None,
            },
            StunObservation {
                server: "stun-c.example:3478".to_string(),
                mapped_address: Some("220.163.6.190:8137".to_string()),
                rtt_ms: Some(12),
                error: None,
            },
        ],
    );

    assert_eq!(profile.port_delta, Some(1));
    assert!(profile.prediction_candidate);
    assert!(profile
        .predicted_endpoints
        .contains(&"220.163.6.190:8154".to_string()));
}

#[test]
fn test_predicted_reflexive_window_follows_air_linear_successor_group() {
    let profile = build_nat_profile(
        "192.168.0.239:59458".parse().unwrap(),
        vec![
            StunObservation {
                server: "stun-a.example:3478".to_string(),
                mapped_address: Some("220.163.6.190:8126".to_string()),
                rtt_ms: Some(10),
                error: None,
            },
            StunObservation {
                server: "stun-b.example:3478".to_string(),
                mapped_address: Some("220.163.6.190:8127".to_string()),
                rtt_ms: Some(11),
                error: None,
            },
            StunObservation {
                server: "stun-c.example:3478".to_string(),
                mapped_address: Some("220.163.6.190:8128".to_string()),
                rtt_ms: Some(12),
                error: None,
            },
            StunObservation {
                server: "stun-d.example:3478".to_string(),
                mapped_address: Some("220.163.6.190:8130".to_string()),
                rtt_ms: Some(13),
                error: None,
            },
            StunObservation {
                server: "observer.example:18082".to_string(),
                mapped_address: Some("220.163.6.190:8133".to_string()),
                rtt_ms: Some(14),
                error: None,
            },
        ],
    );

    assert_eq!(profile.port_delta, Some(2));
    assert!(profile.prediction_candidate);
    assert_eq!(
        profile.predicted_endpoints.first().map(String::as_str),
        Some("220.163.6.190:8134")
    );
    assert!(profile
        .predicted_endpoints
        .contains(&"220.163.6.190:8154".to_string()));
}

#[test]
fn test_build_nat_profile_rejects_wide_delta_for_prediction() {
    let profile = build_nat_profile(
        "192.168.1.2:5000".parse().unwrap(),
        vec![
            StunObservation {
                server: "stun-a.example:3478".to_string(),
                mapped_address: Some("203.0.113.10:40001".to_string()),
                rtt_ms: Some(10),
                error: None,
            },
            StunObservation {
                server: "stun-b.example:3478".to_string(),
                mapped_address: Some("203.0.113.10:40033".to_string()),
                rtt_ms: Some(11),
                error: None,
            },
            StunObservation {
                server: "stun-c.example:3478".to_string(),
                mapped_address: Some("203.0.113.10:40065".to_string()),
                rtt_ms: Some(12),
                error: None,
            },
        ],
    );
    assert_eq!(
        profile.mapping_behavior,
        MappingBehavior::AddressOrPortDependent
    );
    assert_eq!(profile.port_delta, Some(32));
    assert!(!profile.prediction_candidate);
    assert!(profile.predicted_endpoints.is_empty());
    assert!(profile.birthday_candidate);
}

#[test]
fn test_predicted_reflexive_endpoints_respect_port_bounds() {
    let high = predicted_reflexive_endpoints("203.0.113.10:65534".parse().unwrap(), Some(2), true);
    assert!(high.is_empty());

    let low = predicted_reflexive_endpoints("203.0.113.10:3".parse().unwrap(), Some(-2), true);
    assert_eq!(low, vec!["203.0.113.10:1".to_string()]);
}
