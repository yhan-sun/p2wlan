#[test]
fn preserve_peer_reflexive_candidates_keeps_observed_endpoint_across_refresh() {
    let previous = vec![
        "93.184.216.34:27106".to_string(),
        "93.184.216.34:45000".to_string(),
    ];
    let previous_sources = HashMap::from([
        (
            "93.184.216.34:27106".to_string(),
            "stun_observed".to_string(),
        ),
        (
            "93.184.216.34:45000".to_string(),
            "peer_reflexive".to_string(),
        ),
    ]);
    let mut next = vec!["93.184.216.34:31999".to_string()];
    let mut next_sources = HashMap::from([(
        "93.184.216.34:31999".to_string(),
        "stun_observed".to_string(),
    )]);

    preserve_peer_reflexive_candidates(&previous, &previous_sources, &mut next, &mut next_sources);

    assert_eq!(next[0], "93.184.216.34:45000");
    assert_eq!(
        next_sources.get("93.184.216.34:45000").map(String::as_str),
        Some("peer_reflexive")
    );
}

#[test]
fn preserve_peer_reflexive_candidates_drops_private_endpoint_after_refresh() {
    let previous = vec![
        "192.168.2.14:59366".to_string(),
        "93.184.216.34:45000".to_string(),
    ];
    let previous_sources = HashMap::from([
        (
            "192.168.2.14:59366".to_string(),
            "peer_reflexive".to_string(),
        ),
        (
            "93.184.216.34:45000".to_string(),
            "peer_reflexive".to_string(),
        ),
    ]);
    let mut next = vec!["10.46.107.87:59366".to_string()];
    let mut next_sources = HashMap::from([("10.46.107.87:59366".to_string(), "host".to_string())]);

    preserve_peer_reflexive_candidates(&previous, &previous_sources, &mut next, &mut next_sources);

    assert!(!next.contains(&"192.168.2.14:59366".to_string()));
    assert_eq!(
        next_sources.get("192.168.2.14:59366").map(String::as_str),
        None
    );
}

#[test]
fn preserve_peer_reflexive_candidates_drops_old_public_ip_after_refresh() {
    let previous = vec!["93.184.216.34:45000".to_string()];
    let previous_sources = HashMap::from([(
        "93.184.216.34:45000".to_string(),
        "peer_reflexive".to_string(),
    )]);
    let mut next = vec!["198.51.100.9:31999".to_string()];
    let mut next_sources = HashMap::from([(
        "198.51.100.9:31999".to_string(),
        "stun_observed".to_string(),
    )]);

    preserve_peer_reflexive_candidates(&previous, &previous_sources, &mut next, &mut next_sources);

    assert_eq!(next, vec!["198.51.100.9:31999"]);
    assert_eq!(
        next_sources.get("93.184.216.34:45000").map(String::as_str),
        None
    );
}

#[test]
fn peer_reflexive_candidate_update_is_idempotent_after_first_advertisement() {
    let mut candidates = vec!["192.168.1.10:51820".to_string()];
    let mut sources = HashMap::from([("192.168.1.10:51820".to_string(), "host".to_string())]);

    assert!(add_peer_reflexive_candidate_to_set(
        "93.184.216.34:45000",
        &mut candidates,
        &mut sources,
    )
    .unwrap());
    assert_eq!(candidates[0], "93.184.216.34:45000");
    assert_eq!(
        sources.get("93.184.216.34:45000").map(String::as_str),
        Some("peer_reflexive")
    );

    assert!(!add_peer_reflexive_candidate_to_set(
        "93.184.216.34:45000",
        &mut candidates,
        &mut sources,
    )
    .unwrap());
    assert_eq!(
        candidates
            .iter()
            .filter(|candidate| candidate.as_str() == "93.184.216.34:45000")
            .count(),
        1
    );
}

#[test]
fn existing_stun_candidate_is_not_relabelled_peer_reflexive() {
    let mut candidates = vec!["93.184.216.34:45000".to_string()];
    let mut sources = HashMap::from([(
        "93.184.216.34:45000".to_string(),
        "stun_observed".to_string(),
    )]);

    assert!(!add_peer_reflexive_candidate_to_set(
        "93.184.216.34:45000",
        &mut candidates,
        &mut sources,
    )
    .unwrap());
    assert!(!add_peer_reflexive_candidate_to_set(
        "93.184.216.34:45000",
        &mut candidates,
        &mut sources,
    )
    .unwrap());
    assert_eq!(
        sources.get("93.184.216.34:45000").map(String::as_str),
        Some("stun_observed")
    );
}

#[test]
fn stun_rediscovery_then_peer_reflexive_observation_is_stable() {
    let endpoint = "93.184.216.34:45000".to_string();
    let previous = vec![endpoint.clone()];
    let previous_sources = HashMap::from([(endpoint.clone(), "peer_reflexive".to_string())]);
    let mut refreshed = vec![endpoint.clone()];
    let mut refreshed_sources =
        HashMap::from([(endpoint.clone(), "stun_observed".to_string())]);

    preserve_peer_reflexive_candidates(
        &previous,
        &previous_sources,
        &mut refreshed,
        &mut refreshed_sources,
    );
    assert_eq!(
        refreshed_sources.get(&endpoint).map(String::as_str),
        Some("stun_observed")
    );
    assert!(!add_peer_reflexive_candidate_to_set(
        &endpoint,
        &mut refreshed,
        &mut refreshed_sources,
    )
    .unwrap());
    assert_eq!(
        refreshed_sources.get(&endpoint).map(String::as_str),
        Some("stun_observed")
    );
}

#[test]
fn nat_pmp_response_parsers_accept_valid_udp_mapping() {
    let public = [0, 128, 0, 0, 0, 0, 0, 1, 93, 184, 216, 34];
    assert_eq!(
        parse_nat_pmp_public_address_response(&public),
        Some(Ipv4Addr::new(93, 184, 216, 34))
    );

    let mut mapping = [0u8; 16];
    mapping[0] = 0;
    mapping[1] = 129;
    mapping[8..10].copy_from_slice(&51820u16.to_be_bytes());
    mapping[10..12].copy_from_slice(&42000u16.to_be_bytes());
    mapping[12..16].copy_from_slice(&PORT_MAPPING_LEASE_SECS.to_be_bytes());
    assert_eq!(parse_nat_pmp_mapping_response(&mapping, 51820), Some(42000));
    assert_eq!(parse_nat_pmp_mapping_response(&mapping, 51821), None);
}

#[test]
fn pcp_response_parser_accepts_ipv4_mapped_udp_mapping() {
    let mut response = [0u8; 60];
    response[0] = 2;
    response[1] = 0x81;
    response[36] = 17;
    response[40..42].copy_from_slice(&51820u16.to_be_bytes());
    response[42..44].copy_from_slice(&42000u16.to_be_bytes());
    response[44..60].copy_from_slice(&ipv4_mapped_octets(Ipv4Addr::new(93, 184, 216, 34)));
    assert_eq!(
        parse_pcp_mapping_response(&response, 51820),
        Some("93.184.216.34:42000".parse().unwrap())
    );
    assert_eq!(parse_pcp_mapping_response(&response, 51821), None);
}

#[test]
fn default_gateway_parsers_extract_ipv4_addresses() {
    assert_eq!(
        parse_first_ipv4("default via 192.168.1.1 dev en0"),
        Some(Ipv4Addr::new(192, 168, 1, 1))
    );
    assert_eq!(
        parse_first_ipv4("gateway: 10.0.0.1\ninterface: en0"),
        Some(Ipv4Addr::new(10, 0, 0, 1))
    );
}

#[test]
fn test_infer_default_relay_servers_from_public_control_host() {
    assert_eq!(
        infer_default_relay_servers("http://47.109.40.237:18080"),
        vec!["default@tcp://47.109.40.237:18081".to_string()]
    );
    assert_eq!(
        infer_default_relay_servers("https://relay.example.com/api"),
        vec!["default@tcp://relay.example.com:18081".to_string()]
    );
    assert_eq!(
        infer_default_relay_servers("http://[2001:db8::1]:18080"),
        vec!["default@tcp://[2001:db8::1]:18081".to_string()]
    );
}

#[test]
fn test_effective_relay_plaintext_policy_for_legacy_http_control() {
    let legacy_servers = vec!["default@tcp://47.109.40.237:18081".to_string()];
    assert!(effective_relay_allow_insecure_plaintext(
        "http://47.109.40.237:18080",
        &[],
        &legacy_servers,
        false,
    ));
    assert!(effective_relay_allow_insecure_plaintext(
        "https://ctrl.example.com",
        &[],
        &legacy_servers,
        true,
    ));
    assert!(!effective_relay_allow_insecure_plaintext(
        "https://ctrl.example.com",
        &[],
        &legacy_servers,
        false,
    ));

    let catalog = vec![RelayCatalogEntry {
        region: "cn".to_string(),
        audience: "relay-cn-1".to_string(),
        endpoint: "tls://relay.example.com:18081".to_string(),
        udp_observer_endpoint: None,
        udp_observer_endpoints: Vec::new(),
    }];
    assert!(!effective_relay_allow_insecure_plaintext(
        "http://47.109.40.237:18080",
        &catalog,
        &legacy_servers,
        false,
    ));

    let plaintext_catalog = vec![RelayCatalogEntry {
        region: "cn".to_string(),
        audience: "relay-cn-1".to_string(),
        endpoint: "tcp://47.109.40.237:18081".to_string(),
        udp_observer_endpoint: None,
        udp_observer_endpoints: Vec::new(),
    }];
    assert!(effective_relay_allow_insecure_plaintext(
        "http://47.109.40.237:18080",
        &plaintext_catalog,
        &[],
        false,
    ));
    assert!(!effective_relay_allow_insecure_plaintext(
        "https://ctrl.example.com",
        &plaintext_catalog,
        &[],
        false,
    ));
}

#[test]
fn test_relay_spec_plaintext_detection() {
    assert!(relay_spec_is_plaintext("default@47.109.40.237:18081"));
    assert!(relay_spec_is_plaintext("default@tcp://47.109.40.237:18081"));
    assert!(!relay_spec_is_plaintext("cn@tls://relay.example.com:18081"));
}

#[test]
fn relay_catalog_takes_precedence_over_legacy_servers() {
    let catalog = vec![RelayCatalogEntry {
        region: "sg".to_string(),
        audience: "relay-sg-1".to_string(),
        endpoint: "tls://relay.example.com:18081".to_string(),
        udp_observer_endpoint: Some("udp://relay.example.com:18082".to_string()),
        udp_observer_endpoints: Vec::new(),
    }];
    let legacy = vec!["default@127.0.0.1:18081".to_string()];

    let candidates = relay_candidates_from_sources(&catalog, &legacy);

    assert_eq!(candidates.len(), 1);
    assert_eq!(candidates[0].region, "sg");
    assert_eq!(candidates[0].audience.as_deref(), Some("relay-sg-1"));
    assert_eq!(candidates[0].endpoint, "tls://relay.example.com:18081");
}

#[test]
fn relay_catalog_udp_observers_are_merged_with_local_config() {
    let catalog = vec![RelayCatalogEntry {
        region: "sg".to_string(),
        audience: "relay-sg-1".to_string(),
        endpoint: "tls://relay.example.com:18081".to_string(),
        udp_observer_endpoint: Some("udp://relay.example.com:18082".to_string()),
        udp_observer_endpoints: vec![
            "udp://stun.l.google.com:19302".to_string(),
            "relay.example.com:18082".to_string(),
        ],
    }];
    let configured = vec!["203.0.113.10:18082".to_string()];

    let observers = udp_observers_from_sources(&catalog, &configured);

    assert_eq!(
        observers,
        vec![
            "203.0.113.10:18082".to_string(),
            "relay.example.com:18082".to_string(),
            "stun.l.google.com:19302".to_string()
        ]
    );
}

#[test]
fn relay_catalog_udp_observers_respect_explicit_disable() {
    let catalog = vec![RelayCatalogEntry {
        region: "sg".to_string(),
        audience: "relay-sg-1".to_string(),
        endpoint: "tls://relay.example.com:18081".to_string(),
        udp_observer_endpoint: Some("relay.example.com:18082".to_string()),
        udp_observer_endpoints: vec!["stun.l.google.com:19302".to_string()],
    }];
    let configured = vec!["off".to_string()];

    let observers = udp_observers_from_sources(&catalog, &configured);

    assert_eq!(observers, vec!["off".to_string()]);
}

#[test]
fn legacy_relay_servers_are_used_without_catalog() {
    let legacy = vec!["west@127.0.0.1:18081".to_string()];

    let candidates = relay_candidates_from_sources(&[], &legacy);

    assert_eq!(candidates.len(), 1);
    assert!(candidates[0].audience.is_none());
    assert_eq!(candidates[0].endpoint, "west@127.0.0.1:18081");
}

async fn wait_for_relay_endpoint(
    relay_transport: Arc<RwLock<Option<RelayTransport>>>,
    expected_endpoint: &str,
) {
    tokio::time::timeout(Duration::from_secs(4), async {
        loop {
            let matches = relay_transport
                .read()
                .await
                .as_ref()
                .is_some_and(|relay| relay.endpoint() == expected_endpoint);
            if matches {
                break;
            }
            sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("expected relay endpoint was not published");
}

async fn accept_relay_registration(listener: &TcpListener, node_id: &str) -> TcpStream {
    let (mut stream, _) = listener.accept().await.unwrap();
    let mut header = [0u8; 8];
    stream.read_exact(&mut header).await.unwrap();
    let payload_len = u16::from_be_bytes([header[6], header[7]]) as usize;
    let mut payload = vec![0u8; payload_len];
    stream.read_exact(&mut payload).await.unwrap();
    assert_eq!(&header[..4], b"DERP");
    assert_eq!(header[5], p2pnet_relay::protocol::MSG_REGISTER);
    assert_eq!(payload, node_id.as_bytes());
    stream
        .write_all(&Frame::registered(node_id).encode())
        .await
        .unwrap();
    stream
}
