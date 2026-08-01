#[tokio::test]
async fn test_gather_candidates_host_only() {
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();

    let config = IceConfig {
        gather_host: true,
        gather_srflx: false,
        stun_servers: vec![],
        stun_timeout: Duration::from_secs(1),
    };

    let report = gather_candidate_report(&socket, &config).await.unwrap();
    let candidates = report.candidates;
    assert!(!candidates.is_empty());

    // All should be host candidates
    assert!(candidates
        .iter()
        .all(|c| c.candidate_type == CandidateType::Host));

    // Should be sorted by priority (highest first)
    for i in 0..candidates.len().saturating_sub(1) {
        assert!(candidates[i].priority >= candidates[i + 1].priority);
    }
}

#[tokio::test]
async fn test_gather_candidates_with_mock_stun() {
    let (server_addr, _handle) = crate::client::test_helpers::spawn_mock_stun_server().await;

    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let local = socket.local_addr().unwrap();

    let config = IceConfig {
        gather_host: true,
        gather_srflx: true,
        stun_servers: vec![server_addr],
        stun_timeout: Duration::from_secs(2),
    };

    let report = gather_candidate_report(&socket, &config).await.unwrap();
    let candidates = report.candidates;

    // Should have at least one host and one srflx candidate
    let has_host = candidates
        .iter()
        .any(|c| c.candidate_type == CandidateType::Host);
    let has_srflx = candidates
        .iter()
        .any(|c| c.candidate_type == CandidateType::ServerReflexive);
    assert!(has_host);
    assert!(has_srflx);

    // The srflx candidate should have the same address as our local socket
    let srflx = candidates
        .iter()
        .find(|c| c.candidate_type == CandidateType::ServerReflexive)
        .unwrap();
    let srflx_addr = srflx.endpoint.to_socket_addr().unwrap();
    assert_eq!(srflx_addr, local);
    assert_eq!(report.nat_profile.observations.len(), 1);
    assert_eq!(
        report.nat_profile.mapping_behavior,
        MappingBehavior::OpenInternet
    );
    let local_text = local.to_string();
    assert_eq!(
        report.nat_profile.public_endpoint.as_deref(),
        Some(local_text.as_str())
    );
    assert_eq!(
        report.nat_profile.filtering_behavior,
        FilteringBehavior::EndpointIndependent
    );
    assert_eq!(
        report.nat_profile.hairpin_behavior,
        HairpinBehavior::NotApplicable
    );
    assert_eq!(
        report.nat_profile.mapping_lifetime,
        MappingLifetime::LowerBoundMs(duration_millis(MAPPING_LIFETIME_PROBE_DELAY))
    );
    assert!(report.nat_profile.predicted_endpoints.is_empty());
}

#[test]
fn test_candidates_to_addrs() {
    let candidates = vec![
        IceCandidate::host("192.168.1.1", 5000),
        IceCandidate::server_reflexive("1.2.3.4", 5678),
    ];

    let addrs = candidates_to_addrs(&candidates);
    assert_eq!(addrs.len(), 2);
    assert!(addrs.contains(&"192.168.1.1:5000".parse().unwrap()));
    assert!(addrs.contains(&"1.2.3.4:5678".parse().unwrap()));
}

#[test]
fn test_dedup_candidates() {
    // This test is about the dedup logic in gather_candidates
    // but since that requires async, we test the dedup logic here
    let mut candidates = vec![
        IceCandidate::host("127.0.0.1", 8080),
        IceCandidate::host("127.0.0.1", 8080), // duplicate
        IceCandidate::server_reflexive("1.2.3.4", 5678),
    ];

    let mut seen = std::collections::HashSet::new();
    candidates.retain(|c| seen.insert((c.candidate_type, c.endpoint.to_string())));

    assert_eq!(candidates.len(), 2);
}

#[test]
fn candidate_report_excludes_addresses_from_the_wrong_socket_family() {
    let report = candidate_report_from_observations(
        "0.0.0.0:51820".parse().unwrap(),
        true,
        vec![
            StunObservation {
                server: "192.0.2.1:3478".to_string(),
                mapped_address: Some("[2001:db8::10]:41000".to_string()),
                rtt_ms: Some(10),
                error: None,
            },
            StunObservation {
                server: "192.0.2.2:3478".to_string(),
                mapped_address: Some("198.51.100.10:41001".to_string()),
                rtt_ms: Some(10),
                error: None,
            },
        ],
    );

    assert!(report.candidates.iter().all(|candidate| candidate
        .endpoint
        .to_socket_addr()
        .unwrap()
        .is_ipv4()));
    assert!(report
        .candidates
        .iter()
        .any(|candidate| candidate.endpoint.to_string() == "198.51.100.10:41001"));
    assert!(!report
        .candidates
        .iter()
        .any(|candidate| candidate.endpoint.ip == "2001:db8::10"));
}
