#[tokio::test]
async fn gathers_host_candidates_for_bound_udp_port() {
    let peers = peer_manager();
    let transport = UdpTransport::bind("127.0.0.1:0".parse().unwrap(), peers)
        .await
        .unwrap();
    let local_port = transport.local_addr().unwrap().port();

    let candidates = transport
        .gather_candidates(Vec::new(), Duration::from_millis(100))
        .await
        .unwrap();

    assert!(!candidates.is_empty());
    assert!(candidates
        .iter()
        .any(|candidate| candidate.ends_with(&format!(":{local_port}"))));
}

#[tokio::test]
async fn punch_candidates_sends_probe_datagrams() {
    let receiver = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let receiver_addr = receiver.local_addr().unwrap();

    let peers = peer_manager();
    let transport = UdpTransport::bind("127.0.0.1:0".parse().unwrap(), peers)
        .await
        .unwrap();

    let sent = transport
        .punch_candidates("peer-b", vec![receiver_addr], Duration::from_millis(10), 2)
        .await
        .unwrap();

    assert_eq!(sent, 2);

    let mut buf = [0u8; 64];
    let (n, _from) = timeout(Duration::from_secs(1), receiver.recv_from(&mut buf))
        .await
        .unwrap()
        .unwrap();
    let packet = decode_punch_packet(&buf[..n]).unwrap();
    assert_eq!(packet.kind, PunchPacketKind::Punch);
}

#[tokio::test]
async fn punch_candidates_respects_outbound_probe_budget_per_remote_ip() {
    let peers = peer_manager();
    peers.add_peer(&peer("peer-b", "10.20.0.2", None)).await;
    let transport = UdpTransport::bind("127.0.0.1:0".parse().unwrap(), peers.clone())
        .await
        .unwrap();
    {
        let now = Instant::now();
        let mut budget = transport.outbound_probe_budget.lock().await;
        budget.insert(
            OutboundProbeBudgetKey::PeerRemoteIp(
                "peer-b".to_string(),
                IpAddr::V4(Ipv4Addr::LOCALHOST),
            ),
            std::iter::repeat_n(now, OUTBOUND_PROBE_BUDGET_PER_PEER_REMOTE_IP - 8).collect(),
        );
    }

    let candidates = (0..16)
        .map(|offset| format!("127.0.0.1:{}", 30_000 + offset).parse().unwrap())
        .collect::<Vec<SocketAddr>>();

    let sent = transport
        .punch_candidates("peer-b", candidates, Duration::ZERO, 1)
        .await
        .unwrap();

    assert_eq!(sent as usize, 8);
    let diagnostics = peers.diagnostics().await;
    let event = diagnostics[0]
        .direct_events
        .iter()
        .find(|event| event.stage == "probe_budget_limited")
        .expect("budget-limited probe pass should be recorded");
    assert_eq!(event.sent_probes, Some(sent));
    assert!(event.detail.contains("remote_ip_rate_limited"));
}

#[tokio::test]
async fn punch_candidates_stops_at_hard_session_probe_cap() {
    let peers = peer_manager();
    peers.add_peer(&peer("peer-b", "10.20.0.9", None)).await;
    let transport = UdpTransport::bind("127.0.0.1:0".parse().unwrap(), peers)
        .await
        .unwrap();
    let candidates = (0..600)
        .map(|index| {
            format!(
                "127.{}.{}.{}:{}",
                1 + (index % 4),
                1 + ((index / 4) % 200),
                1 + ((index / 800) % 200),
                20_000 + index
            )
            .parse()
            .unwrap()
        })
        .collect::<Vec<SocketAddr>>();

    let sent = transport
        .punch_candidates("peer-b", candidates, Duration::from_secs(1), 5)
        .await
        .unwrap();

    assert_eq!(sent, MAX_PUNCH_PROBES_PER_SESSION);
}

#[tokio::test]
async fn qualified_socket_pool_probes_from_each_bound_socket() {
    let receiver = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let receiver_addr = receiver.local_addr().unwrap();
    let peers = peer_manager();
    peers.add_peer(&peer("peer-b", "10.20.0.9", None)).await;
    let transport = UdpTransport::bind("127.0.0.1:0".parse().unwrap(), peers.clone())
        .await
        .unwrap()
        .with_socket_pool(3)
        .await
        .unwrap();

    assert_eq!(transport.socket_count(), 3);
    assert!(!transport.socket_pool_active());
    transport.set_socket_pool_active(true);
    assert!(transport.socket_pool_active());

    let sent = transport
        .punch_candidates("peer-b", vec![receiver_addr], Duration::ZERO, 1)
        .await
        .unwrap();
    assert_eq!(sent, 3);

    let mut sources = std::collections::HashSet::new();
    let mut buf = [0u8; 64];
    for _ in 0..3 {
        let (n, source) = timeout(Duration::from_secs(1), receiver.recv_from(&mut buf))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            decode_punch_packet(&buf[..n]).unwrap().kind,
            PunchPacketKind::Punch
        );
        sources.insert(source);
    }
    assert_eq!(sources.len(), 3);
    let diagnostics = transport.socket_pool_diagnostics().await;
    assert_eq!(
        diagnostics
            .iter()
            .map(|member| member.probes_sent)
            .collect::<Vec<_>>(),
        vec![1, 1, 1]
    );

    let peer_diagnostics = peers.diagnostics().await;
    let event = peer_diagnostics[0]
        .direct_events
        .iter()
        .find(|event| event.stage == "active_pool_scan_completed")
        .expect("active-pool scan should emit coverage diagnostics");
    assert_eq!(event.sent_probes, Some(sent));
    assert_eq!(event.probe_tx_socket0_count, Some(1));
    assert_eq!(event.probe_tx_alt_socket_count, Some(2));
    assert_eq!(event.probe_tx_unique_target_ports, Some(1));
    assert_eq!(event.probe_tx_repeated_target_ports, Some(2));
    assert!(event.detail.contains("scan_socket_policy=active_pool"));
    assert!(event
        .detail
        .contains(&format!("punch_sockets={}", transport.socket_count())));
}

#[tokio::test]
async fn active_pool_uses_alternate_sockets_before_remote_ip_budget_is_exhausted() {
    let peers = peer_manager();
    peers.add_peer(&peer("peer-b", "10.20.0.9", None)).await;
    let transport = UdpTransport::bind("127.0.0.1:0".parse().unwrap(), peers.clone())
        .await
        .unwrap()
        .with_socket_pool(4)
        .await
        .unwrap();
    transport.set_socket_pool_active(true);

    let candidates = (0..200)
        .map(|offset| format!("127.0.0.1:{}", 20_000 + offset).parse().unwrap())
        .collect::<Vec<SocketAddr>>();

    let sent = transport
        .punch_candidates("peer-b", candidates.clone(), Duration::ZERO, 1)
        .await
        .unwrap();

    assert_eq!(sent as usize, OUTBOUND_PROBE_BUDGET_PER_PEER_REMOTE_IP);
    let pending = transport.pending_probes.lock().await;
    let mut endpoints = pending
        .values()
        .map(|probe| probe.endpoint)
        .collect::<Vec<_>>();
    endpoints.sort_unstable();
    endpoints.dedup();

    assert_eq!(
        endpoints.len(),
        OUTBOUND_PROBE_BUDGET_PER_PEER_REMOTE_IP / transport.socket_count()
    );
    assert!(endpoints
        .iter()
        .all(|endpoint| candidates[..endpoints.len()].contains(endpoint)));
    let mut per_socket = vec![0usize; transport.socket_count()];
    for probe in pending.values() {
        per_socket[probe.socket_index] += 1;
    }
    let expected_per_socket = OUTBOUND_PROBE_BUDGET_PER_PEER_REMOTE_IP / transport.socket_count();
    assert_eq!(
        per_socket,
        vec![expected_per_socket; transport.socket_count()]
    );
    drop(pending);

    let peer_diagnostics = peers.diagnostics().await;
    let event = peer_diagnostics[0]
        .direct_events
        .iter()
        .find(|event| event.stage == "active_pool_scan_completed")
        .expect("active-pool scan should emit coverage diagnostics");
    assert_eq!(event.sent_probes, Some(sent));
    assert_eq!(
        event.probe_tx_socket0_count,
        Some(u32::try_from(expected_per_socket).unwrap())
    );
    assert_eq!(
        event.probe_tx_alt_socket_count,
        Some(u32::try_from(expected_per_socket * (transport.socket_count() - 1)).unwrap())
    );
    assert_eq!(
        event.probe_tx_unique_target_ports,
        Some(u32::try_from(expected_per_socket).unwrap())
    );
    assert!(event
        .detail
        .contains(&format!("punch_sockets={}", transport.socket_count())));
}

#[tokio::test]
async fn remote_scatter_pool_uses_all_bound_sockets_even_when_local_pool_inactive() {
    let peers = peer_manager();
    peers.add_peer(&peer("peer-b", "10.20.0.9", None)).await;
    let transport = UdpTransport::bind("127.0.0.1:0".parse().unwrap(), peers.clone())
        .await
        .unwrap()
        .with_socket_pool(4)
        .await
        .unwrap();
    assert_eq!(transport.socket_count(), 4);
    assert!(!transport.socket_pool_active());

    let candidates = (0..200)
        .map(|offset| format!("127.0.0.1:{}", 22_000 + offset).parse().unwrap())
        .collect::<Vec<SocketAddr>>();

    let sent = transport
        .punch_candidates_remote_scatter_pool("peer-b", candidates, Duration::ZERO, 1)
        .await
        .unwrap();

    assert_eq!(sent as usize, OUTBOUND_PROBE_BUDGET_PER_PEER_REMOTE_IP);
    let pending = transport.pending_probes.lock().await;
    let mut per_socket = vec![0usize; transport.socket_count()];
    for probe in pending.values() {
        per_socket[probe.socket_index] += 1;
    }
    let expected_per_socket = OUTBOUND_PROBE_BUDGET_PER_PEER_REMOTE_IP / transport.socket_count();
    assert_eq!(
        per_socket,
        vec![expected_per_socket; transport.socket_count()]
    );
    drop(pending);

    let peer_diagnostics = peers.diagnostics().await;
    let event = peer_diagnostics[0]
        .direct_events
        .iter()
        .find(|event| event.stage == "active_pool_scan_completed")
        .expect("remote scatter scan should emit coverage diagnostics");
    assert_eq!(event.sent_probes, Some(sent));
    assert_eq!(
        event.probe_tx_socket0_count,
        Some(u32::try_from(expected_per_socket).unwrap())
    );
    assert_eq!(
        event.probe_tx_alt_socket_count,
        Some(u32::try_from(expected_per_socket * (transport.socket_count() - 1)).unwrap())
    );
    assert!(event
        .detail
        .contains("scan_socket_policy=remote_scatter_pool"));
    assert!(event
        .detail
        .contains(&format!("punch_sockets={}", transport.socket_count())));
}

#[tokio::test]
async fn primary_socket_punch_never_uses_alternate_pool_sockets() {
    let peers = peer_manager();
    peers.add_peer(&peer("peer-b", "10.20.0.9", None)).await;
    let transport = UdpTransport::bind("127.0.0.1:0".parse().unwrap(), peers.clone())
        .await
        .unwrap()
        .with_socket_pool(3)
        .await
        .unwrap();
    transport.set_socket_pool_active(true);

    let candidates = (0..64)
        .map(|offset| format!("127.0.0.1:{}", 21_000 + offset).parse().unwrap())
        .collect::<Vec<SocketAddr>>();

    let sent = transport
        .punch_candidates_primary_socket("peer-b", candidates.clone(), Duration::ZERO, 1)
        .await
        .unwrap();

    assert_eq!(sent as usize, candidates.len());
    let pending = transport.pending_probes.lock().await;
    assert_eq!(pending.len(), candidates.len());
    assert!(pending.values().all(|probe| probe.socket_index == 0));
    drop(pending);

    let diagnostics = transport.socket_pool_diagnostics().await;
    assert_eq!(diagnostics[0].probes_sent, candidates.len() as u64);
    assert_eq!(
        diagnostics
            .iter()
            .skip(1)
            .map(|member| member.probes_sent)
            .sum::<u64>(),
        0
    );

    let peer_diagnostics = peers.diagnostics().await;
    let event = peer_diagnostics[0]
        .direct_events
        .iter()
        .find(|event| event.stage == "primary_socket_scan_completed")
        .expect("primary-only scan should emit coverage diagnostics");
    assert_eq!(event.sent_probes, Some(sent));
    assert_eq!(event.probe_tx_socket0_count, Some(sent));
    assert_eq!(event.probe_tx_alt_socket_count, Some(0));
    assert_eq!(event.probe_tx_unique_target_ports, Some(64));
    assert_eq!(event.probe_tx_repeated_target_ports, Some(0));
    assert!(event.detail.contains("scan_socket_policy=primary_only"));
    assert!(event.detail.contains("unique_target_ports=64"));
}

#[tokio::test]
async fn nat_binding_maintainer_uses_only_primary_socket() {
    let receiver = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let receiver_addr = receiver.local_addr().unwrap();
    let peers = peer_manager();
    peers.add_peer(&peer("peer-b", "10.20.0.9", None)).await;
    let transport = UdpTransport::bind("127.0.0.1:0".parse().unwrap(), peers.clone())
        .await
        .unwrap()
        .with_socket_pool(3)
        .await
        .unwrap();
    transport.set_socket_pool_active(true);
    let primary_addr = transport.active_sockets()[0].local_addr().unwrap();

    assert!(
        transport
            .spawn_nat_binding_maintainer(
                "peer-b",
                receiver_addr,
                Duration::from_millis(5),
                Duration::from_millis(35),
            )
            .await
    );
    assert!(
        !transport
            .spawn_nat_binding_maintainer(
                "peer-b",
                receiver_addr,
                Duration::from_millis(5),
                Duration::from_millis(35),
            )
            .await,
        "overlapping maintainer for the same peer/endpoint should be suppressed"
    );

    let mut buf = [0u8; 64];
    let mut sources = std::collections::HashSet::new();
    for _ in 0..3 {
        let (n, source) = timeout(Duration::from_secs(1), receiver.recv_from(&mut buf))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            decode_punch_packet(&buf[..n]).unwrap().kind,
            PunchPacketKind::Punch
        );
        sources.insert(source);
    }

    assert_eq!(sources, std::collections::HashSet::from([primary_addr]));
    sleep(Duration::from_millis(50)).await;
    let diagnostics = transport.socket_pool_diagnostics().await;
    assert!(diagnostics[0].nat_maintainer_probes_sent >= 3);
    assert_eq!(
        diagnostics
            .iter()
            .skip(1)
            .map(|member| member.nat_maintainer_probes_sent)
            .sum::<u64>(),
        0
    );
    let peer_diagnostics = peers.diagnostics().await;
    assert!(peer_diagnostics[0]
        .direct_events
        .iter()
        .any(|event| event.stage == "nat_maintainer_started"));
    assert!(peer_diagnostics[0]
        .direct_events
        .iter()
        .any(|event| event.stage == "nat_maintainer_suppressed"));
    assert!(peer_diagnostics[0]
        .direct_events
        .iter()
        .any(|event| event.stage == "nat_maintainer_stopped"));
}

#[tokio::test]
async fn live_candidate_refresh_advertises_each_qualified_pool_mapping() {
    let peers = peer_manager();
    let transport = UdpTransport::bind("127.0.0.1:0".parse().unwrap(), peers)
        .await
        .unwrap()
        .with_socket_pool(3)
        .await
        .unwrap();
    let (inbound_tx, _inbound_rx) = mpsc::channel(4);
    let inbound_worker = tokio::spawn(transport.clone().run_inbound(inbound_tx));

    let first_stun = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let first_stun_addr = first_stun.local_addr().unwrap();
    let first_worker = tokio::spawn(async move {
        for _ in 0..3 {
            let mut buf = [0u8; 2048];
            let (n, client_addr) = first_stun.recv_from(&mut buf).await.unwrap();
            let request = StunMessage::decode(&buf[..n]).unwrap();
            let mapped = SocketAddr::new("203.0.113.7".parse().unwrap(), client_addr.port());
            let mut response =
                StunMessage::with_transaction_id(BINDING_RESPONSE, request.transaction_id);
            response.add_attribute(StunAttribute::XorMappedAddress(mapped));
            first_stun
                .send_to(&response.encode(), client_addr)
                .await
                .unwrap();
        }
    });

    let second_stun = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let second_stun_addr = second_stun.local_addr().unwrap();
    let second_worker = tokio::spawn(async move {
        for _ in 0..3 {
            let mut buf = [0u8; 2048];
            let (n, client_addr) = second_stun.recv_from(&mut buf).await.unwrap();
            let request = StunMessage::decode(&buf[..n]).unwrap();
            let mapped = SocketAddr::new(
                "203.0.113.7".parse().unwrap(),
                client_addr.port().saturating_add(1),
            );
            let mut response =
                StunMessage::with_transaction_id(BINDING_RESPONSE, request.transaction_id);
            response.add_attribute(StunAttribute::XorMappedAddress(mapped));
            second_stun
                .send_to(&response.encode(), client_addr)
                .await
                .unwrap();
        }
    });

    let report = transport
        .gather_candidate_report_live(
            vec![first_stun_addr, second_stun_addr],
            Duration::from_secs(1),
        )
        .await
        .unwrap();

    assert!(transport.socket_pool_active());
    let public_candidates = report
        .candidates
        .iter()
        .filter(|candidate| {
            candidate.endpoint.ip == "203.0.113.7"
                && candidate.source == p2pnet_nat::CandidateSource::StunObserved
        })
        .count();
    assert_eq!(public_candidates, 6);
    let predicted_candidates = report
        .candidates
        .iter()
        .filter(|candidate| {
            candidate.endpoint.ip == "203.0.113.7"
                && candidate.source == p2pnet_nat::CandidateSource::Predicted
        })
        .count();
    assert!(
        predicted_candidates >= 8,
        "each qualified pool socket should contribute predicted ports; got {predicted_candidates}"
    );
    let diagnostics = transport.socket_pool_diagnostics().await;
    assert_eq!(diagnostics[0].stun_mappings_discovered, 0);
    assert_eq!(diagnostics[1].stun_mappings_discovered, 2);
    assert_eq!(diagnostics[2].stun_mappings_discovered, 2);

    first_worker.await.unwrap();
    second_worker.await.unwrap();
    inbound_worker.abort();
}

#[test]
fn pool_stun_observation_promotes_an_overlapping_prediction() {
    let mut predicted = p2pnet_nat::IceCandidate::server_reflexive("203.0.113.7", 42_001);
    predicted.source = p2pnet_nat::CandidateSource::Predicted;
    let mut report =
        candidate_report_from_observations("0.0.0.0:50000".parse().unwrap(), false, Vec::new());
    report.candidates = vec![predicted];

    let discovered = merge_pool_candidates(
        &mut report,
        vec![p2pnet_nat::IceCandidate::server_reflexive(
            "203.0.113.7",
            42_001,
        )],
    );

    assert_eq!(discovered, 1);
    assert_eq!(report.candidates.len(), 1);
    assert_eq!(
        report.candidates[0].source,
        p2pnet_nat::CandidateSource::StunObserved
    );
}

#[tokio::test]
async fn probe_ack_pins_peer_to_the_socket_that_received_it() {
    let receiver = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let receiver_addr = receiver.local_addr().unwrap();
    let peers = peer_manager();
    peers
        .add_peer(&peer("peer-b", "10.20.0.9", Some(receiver_addr)))
        .await;
    let transport = UdpTransport::bind("127.0.0.1:0".parse().unwrap(), peers.clone())
        .await
        .unwrap()
        .with_socket_pool(2)
        .await
        .unwrap();
    transport.set_socket_pool_active(true);
    let primary_addr = transport.local_addr().unwrap();
    let (inbound_tx, _inbound_rx) = mpsc::channel(4);
    let worker = tokio::spawn(transport.clone().run_inbound(inbound_tx));

    assert_eq!(
        transport
            .punch_candidates("peer-b", vec![receiver_addr], Duration::ZERO, 1)
            .await
            .unwrap(),
        2
    );

    let mut buf = [0u8; 64];
    let mut secondary_probe = None;
    for _ in 0..2 {
        let (n, source) = timeout(Duration::from_secs(1), receiver.recv_from(&mut buf))
            .await
            .unwrap()
            .unwrap();
        let packet = decode_punch_packet(&buf[..n]).unwrap();
        if source != primary_addr {
            secondary_probe = Some((packet.nonce, source));
        }
    }
    let (nonce, secondary_source) = secondary_probe.expect("expected a pool probe");
    receiver
        .send_to(&build_punch_ack(nonce), secondary_source)
        .await
        .unwrap();

    timeout(Duration::from_secs(1), async {
        loop {
            if transport
                .peer_socket_affinity
                .lock()
                .await
                .get("peer-b")
                .copied()
                == Some(1)
            {
                break;
            }
            sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .expect("ACK should pin the peer to the secondary socket");

    let diagnostics = transport.socket_pool_diagnostics().await;
    assert_eq!(diagnostics[1].probe_acks_received, 1);

    worker.abort();
}
