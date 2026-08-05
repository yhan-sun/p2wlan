#[tokio::test]
async fn run_inbound_rejects_authenticated_probe_with_invalid_mac() {
    let local_identity = NodeIdentity::generate();
    let peer_identity = NodeIdentity::generate();
    let peers = Arc::new(PeerManager::new(config_for_identity(
        &local_identity,
        "peer-a",
    )));
    peers
        .add_peer(&peer_with_public_key(
            "peer-b",
            "10.20.0.2",
            hex::encode(peer_identity.public_key()),
            None,
        ))
        .await;

    let key = peers.probe_key_for_peer("peer-b").await.unwrap();
    let transport = UdpTransport::bind("127.0.0.1:0".parse().unwrap(), peers.clone())
        .await
        .unwrap()
        .with_local_node_id("peer-a");
    let local_addr = transport.local_addr().unwrap();
    let (tx, mut rx) = mpsc::channel(4);
    let diagnostics_transport = transport.clone();
    let worker = tokio::spawn(transport.run_inbound(tx));

    let sender = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let (mut probe, _nonce) = build_authenticated_punch_packet("peer-b", "peer-a", 7, &key);
    let last = probe.last_mut().unwrap();
    *last ^= 0x80;
    sender.send_to(&probe, local_addr).await.unwrap();

    let mut buf = [0u8; 512];
    assert!(
        timeout(Duration::from_millis(150), sender.recv_from(&mut buf))
            .await
            .is_err()
    );
    assert!(timeout(Duration::from_millis(100), rx.recv())
        .await
        .is_err());

    let conn = peers.get_connection("peer-b").await.unwrap();
    assert_eq!(conn.endpoint, None);
    assert!(conn.candidates.is_empty());
    let diagnostics = diagnostics_transport.socket_pool_diagnostics().await;
    assert_eq!(diagnostics[0].authenticated_probe_packets_received, 1);
    assert_eq!(diagnostics[0].authenticated_probe_invalid_mac, 1);

    worker.abort();
}

#[tokio::test]
async fn probe_ack_records_peer_round_trip_latency() {
    let peers = peer_manager();
    let remote = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let remote_addr = remote.local_addr().unwrap();

    peers
        .add_peer(&peer("peer-b", "10.20.0.2", Some(remote_addr)))
        .await;

    let transport = UdpTransport::bind("127.0.0.1:0".parse().unwrap(), peers.clone())
        .await
        .unwrap();
    let local_addr = transport.local_addr().unwrap();
    let (tx, _rx) = mpsc::channel(4);
    let worker = tokio::spawn(transport.clone().run_inbound(tx));

    transport
        .send_probe(Some("peer-b"), remote_addr)
        .await
        .unwrap();
    let mut buf = [0u8; 64];
    let (n, _from) = timeout(Duration::from_secs(1), remote.recv_from(&mut buf))
        .await
        .unwrap()
        .unwrap();
    let probe = decode_punch_packet(&buf[..n]).unwrap();
    remote
        .send_to(&build_punch_ack(probe.nonce), local_addr)
        .await
        .unwrap();

    timeout(Duration::from_secs(1), async {
        loop {
            let diagnostics = peers.diagnostics().await;
            if diagnostics[0].direct.latency_ms.is_some() {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();

    let diagnostics = peers.diagnostics().await;
    assert!(diagnostics[0].direct.latency_ms.is_some());
    assert_eq!(diagnostics[0].direct.consecutive_failures, 0);

    worker.abort();
}

#[tokio::test]
async fn keepalive_ack_timeout_degrades_direct_after_three_misses() {
    let peers = peer_manager();
    let silent_remote = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let remote_addr = silent_remote.local_addr().unwrap();
    peers
        .add_peer(&peer("peer-b", "10.20.0.2", Some(remote_addr)))
        .await;
    peers
        .record_direct_probe_success_with_latency(
            "peer-b",
            remote_addr,
            Some(Duration::from_millis(5)),
        )
        .await;
    peers
        .record_direct_success("peer-b", Some(remote_addr))
        .await;

    let transport = UdpTransport::bind("127.0.0.1:0".parse().unwrap(), peers.clone())
        .await
        .unwrap();

    transport
        .run_keepalive_round(Duration::from_millis(10))
        .await;
    let after_one = peers.get_connection("peer-b").await.unwrap();
    assert_eq!(after_one.state, ConnectionState::Direct);
    assert_eq!(after_one.direct_health.consecutive_failures, 1);
    assert!(after_one
        .direct_events
        .iter()
        .any(|event| event.stage == "consent_check_sent"));
    assert!(after_one
        .direct_events
        .iter()
        .any(|event| event.stage == "consent_timeout"));

    transport
        .run_keepalive_round(Duration::from_millis(10))
        .await;
    transport
        .run_keepalive_round(Duration::from_millis(10))
        .await;
    let after_three = peers.get_connection("peer-b").await.unwrap();
    assert_eq!(after_three.state, ConnectionState::FallbackToRelay);
    assert_eq!(after_three.direct_health.consecutive_failures, 3);
    assert_eq!(
        after_three.direct_health.last_error_code.as_deref(),
        Some(crate::peer::REASON_DIRECT_KEEPALIVE_TIMEOUT)
    );
}

#[tokio::test]
async fn matching_keepalive_ack_preserves_direct_health() {
    let peers = peer_manager();
    let remote = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let remote_addr = remote.local_addr().unwrap();
    peers
        .add_peer(&peer("peer-b", "10.20.0.2", Some(remote_addr)))
        .await;
    peers
        .record_direct_probe_success_with_latency(
            "peer-b",
            remote_addr,
            Some(Duration::from_millis(5)),
        )
        .await;
    peers
        .record_direct_success("peer-b", Some(remote_addr))
        .await;

    let transport = UdpTransport::bind("127.0.0.1:0".parse().unwrap(), peers.clone())
        .await
        .unwrap();
    let local_addr = transport.local_addr().unwrap();
    let (tx, _rx) = mpsc::channel(1);
    let inbound_worker = tokio::spawn(transport.clone().run_inbound(tx));
    let responder = tokio::spawn(async move {
        let mut buf = [0u8; 256];
        let (n, _) = remote.recv_from(&mut buf).await.unwrap();
        let probe = decode_punch_packet(&buf[..n]).unwrap();
        remote
            .send_to(&build_punch_ack(probe.nonce), local_addr)
            .await
            .unwrap();
    });

    transport
        .run_keepalive_round(Duration::from_millis(100))
        .await;
    responder.await.unwrap();

    let conn = peers.get_connection("peer-b").await.unwrap();
    assert_eq!(conn.state, ConnectionState::Direct);
    assert_eq!(conn.direct_health.consecutive_failures, 0);
    assert!(conn
        .direct_events
        .iter()
        .any(|event| event.stage == "consent_check_sent"));
    assert!(conn
        .direct_events
        .iter()
        .any(|event| event.stage == "consent_ack_received"));
    assert!(!conn
        .direct_events
        .iter()
        .any(|event| event.stage == "consent_timeout"));

    inbound_worker.abort();
}

#[tokio::test]
async fn authenticated_probe_ack_learns_peer_reflexive_source_without_confirming_data() {
    let local_identity = NodeIdentity::generate();
    let peer_identity = NodeIdentity::generate();
    let remote_candidate = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let remote_candidate_addr = remote_candidate.local_addr().unwrap();

    let peers = Arc::new(PeerManager::new(config_for_identity(
        &local_identity,
        "peer-a",
    )));
    peers
        .add_peer(&peer_with_public_key(
            "peer-b",
            "10.20.0.2",
            hex::encode(peer_identity.public_key()),
            Some(remote_candidate_addr),
        ))
        .await;
    let key = peers.probe_key_for_peer("peer-b").await.unwrap();

    let transport = UdpTransport::bind("127.0.0.1:0".parse().unwrap(), peers.clone())
        .await
        .unwrap()
        .with_local_node_id("peer-a");
    let local_addr = transport.local_addr().unwrap();
    let (tx, _rx) = mpsc::channel(4);
    let worker = tokio::spawn(transport.clone().run_inbound(tx));

    transport
        .send_probe(Some("peer-b"), remote_candidate_addr)
        .await
        .unwrap();
    let mut probe_buf = [0u8; 512];
    let (n, _from) = timeout(
        Duration::from_secs(1),
        remote_candidate.recv_from(&mut probe_buf),
    )
    .await
    .unwrap()
    .unwrap();
    let probe = decode_authenticated_punch_packet(&probe_buf[..n], &key).unwrap();

    let peer_reflexive = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let peer_reflexive_addr = peer_reflexive.local_addr().unwrap();
    let ack = build_authenticated_punch_ack(probe.nonce, "peer-b", "peer-a", 11, &key);
    peer_reflexive.send_to(&ack, local_addr).await.unwrap();

    timeout(Duration::from_secs(1), async {
        loop {
            let conn = peers.get_connection("peer-b").await.unwrap();
            if conn.endpoint == Some(peer_reflexive_addr)
                && conn.state == ConnectionState::HolePunching
            {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();

    let conn = peers.get_connection("peer-b").await.unwrap();
    assert_eq!(conn.endpoint, Some(peer_reflexive_addr));
    assert!(conn.candidates.contains(&peer_reflexive_addr.to_string()));
    assert_eq!(conn.state, ConnectionState::HolePunching);
    assert_eq!(conn.active_path(), None);

    worker.abort();
}

#[tokio::test]
async fn udp_inbound_decrypts_and_writes_packet_to_tun() {
    let peers = peer_manager();
    peers.add_peer(&peer("peer-a", "10.20.0.1", None)).await;

    let (tun, mut ctrl) = MockTunDevice::new_pair("test0", 1420, "10.20.0.2");
    let (mut dataplane, _outbound_rx, inbound_tx) =
        DataPlane::new_bidirectional(tun, peers.clone());
    let dataplane_worker = tokio::spawn(async move { dataplane.run().await });

    let (mut node_a_session, node_b_session) = establish_sessions();
    let (wireguard, _encrypted_rx) = WireGuardTransport::new();
    wireguard.add_session("peer-a", node_b_session).await;
    let (udp_inbound_tx, udp_inbound_rx) = mpsc::channel(4);
    let wireguard_worker = {
        let wireguard = wireguard.clone();
        let peers = peers.clone();
        tokio::spawn(async move {
            wireguard
                .run_inbound_with_peers(udp_inbound_rx, inbound_tx, Some(peers))
                .await
        })
    };

    let udp = UdpTransport::bind("127.0.0.1:0".parse().unwrap(), peers.clone())
        .await
        .unwrap();
    let udp_addr = udp.local_addr().unwrap();
    let udp_worker = tokio::spawn(udp.run_inbound(udp_inbound_tx));

    let ip_packet = Ipv4Packet::build_icmp_echo_request(
        Ipv4Addr::new(10, 20, 0, 1),
        Ipv4Addr::new(10, 20, 0, 2),
        0x1234,
        1,
        b"ping",
    );
    let wire_bytes = node_a_session.encrypt_to_bytes(&ip_packet).unwrap();
    let sender = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    sender.send_to(&wire_bytes, udp_addr).await.unwrap();

    let written = timeout(Duration::from_secs(1), ctrl.recv_written())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(written, ip_packet);

    let conn = peers.get_connection("peer-a").await.unwrap();
    assert_eq!(conn.bytes_received, written.len() as u64);
    assert_eq!(conn.state.to_string(), "direct");
    assert_eq!(conn.endpoint, Some(sender.local_addr().unwrap()));
    assert_eq!(
        conn.candidate_sources
            .get(&sender.local_addr().unwrap().to_string()),
        Some(&crate::peer::CandidatePairSource::PeerReflexive)
    );

    udp_worker.abort();
    wireguard_worker.abort();
    dataplane_worker.abort();
}

#[tokio::test]
async fn authenticated_pending_probe_promotes_matching_wireguard_and_probe_transaction() {
    let local_identity = NodeIdentity::generate();
    let remote_identity = NodeIdentity::generate();
    let peers = Arc::new(PeerManager::new(config_for_identity(
        &local_identity,
        "local-node",
    )));
    peers
        .add_peer(&peer_with_public_key(
            "peer-b",
            "10.20.0.2",
            hex::encode(remote_identity.public_key()),
            None,
        ))
        .await;
    peers
        .set_probe_session_binding("peer-b", Some("old-probe".to_string()), Some([1u8; 32]))
        .await;
    let old_probe_key = peers.probe_key_for_peer("peer-b").await.unwrap();
    assert_eq!(
        peers
            .stage_probe_session_binding(
                "peer-b",
                "txn-1".to_string(),
                Some("new-probe".to_string()),
                Some([2u8; 32]),
                true,
            )
            .await,
        ProbeBindingStage::Staged
    );
    let pending_probe_key = peers
        .probe_key_candidates_for_peer("peer-b")
        .await
        .into_iter()
        .find_map(|candidate| {
            matches!(candidate.role, ProbeKeyRole::Pending { ref token } if token == "txn-1")
                .then_some(candidate.key)
        })
        .unwrap();
    assert_ne!(pending_probe_key, old_probe_key);

    let (_old_remote, old_local) = establish_sessions();
    let (mut new_remote, new_local) = establish_sessions();
    let (wireguard, _encrypted_rx) = WireGuardTransport::new();
    wireguard.add_session("peer-b", old_local).await;
    assert_eq!(
        wireguard
            .stage_responder_session("peer-b", "txn-1".to_string(), new_local)
            .await,
        crate::transport::ResponderSessionStage::Staged { had_active: true }
    );
    assert_eq!(
        wireguard
            .commit_responder_session("peer-b", "txn-1")
            .await,
        crate::transport::ResponderSessionCommit::PendingConfirmation
    );

    let udp = UdpTransport::bind("127.0.0.1:0".parse().unwrap(), peers.clone())
        .await
        .unwrap()
        .with_wireguard_transport(wireguard.clone());
    assert!(udp.confirm_pending_probe_adoption("peer-b", "txn-1").await);
    assert_eq!(
        peers.probe_key_for_peer("peer-b").await,
        Some(pending_probe_key)
    );
    assert!(!wireguard
        .session_status("peer-b")
        .await
        .has_pending_responder);

    let packet = Ipv4Packet::build_icmp_echo_request(
        Ipv4Addr::new(10, 20, 0, 1),
        Ipv4Addr::new(10, 20, 0, 2),
        0x5555,
        1,
        b"probe-confirmed-wg",
    );
    let encrypted = wireguard
        .encrypt_outbound(crate::dataplane::OutboundPacket {
            peer_id: "peer-b".to_string(),
            dst_ip: "10.20.0.2".to_string(),
            packet: packet.clone(),
        })
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        new_remote.decrypt_from_bytes(&encrypted.wire_bytes).unwrap(),
        packet
    );
}

#[tokio::test]
async fn pending_probe_cannot_promote_without_matching_wireguard_token() {
    let local_identity = NodeIdentity::generate();
    let remote_identity = NodeIdentity::generate();
    let peers = Arc::new(PeerManager::new(config_for_identity(
        &local_identity,
        "local-node",
    )));
    peers
        .add_peer(&peer_with_public_key(
            "peer-b",
            "10.20.0.2",
            hex::encode(remote_identity.public_key()),
            None,
        ))
        .await;
    peers
        .set_probe_session_binding("peer-b", Some("old-probe".to_string()), Some([3u8; 32]))
        .await;
    let old_probe_key = peers.probe_key_for_peer("peer-b").await.unwrap();
    assert_eq!(
        peers
            .stage_probe_session_binding(
                "peer-b",
                "missing-wg".to_string(),
                Some("new-probe".to_string()),
                Some([4u8; 32]),
                true,
            )
            .await,
        ProbeBindingStage::Staged
    );

    let (wireguard, _encrypted_rx) = WireGuardTransport::new();
    let udp = UdpTransport::bind("127.0.0.1:0".parse().unwrap(), peers.clone())
        .await
        .unwrap()
        .with_wireguard_transport(wireguard);
    assert!(!udp
        .confirm_pending_probe_adoption("peer-b", "missing-wg")
        .await);
    assert_eq!(peers.probe_key_for_peer("peer-b").await, Some(old_probe_key));
    assert!(peers
        .probe_key_candidates_for_peer("peer-b")
        .await
        .iter()
        .any(|candidate| {
            matches!(candidate.role, ProbeKeyRole::Pending { ref token } if token == "missing-wg")
        }));
}

#[tokio::test]
async fn missing_probe_transaction_cannot_partially_promote_wireguard() {
    let token = "missing-probe-side";
    let (peers, wireguard, udp, old_probe_key, _pending_probe_key) =
        pending_probe_inbound_fixture(token).await;
    assert!(peers
        .discard_pending_probe_session_binding("peer-b", token)
        .await);

    assert!(!udp.confirm_pending_probe_adoption("peer-b", token).await);
    assert_eq!(peers.probe_key_for_peer("peer-b").await, Some(old_probe_key));
    assert!(wireguard
        .session_status("peer-b")
        .await
        .has_pending_responder);
}

async fn pending_probe_inbound_fixture(
    token: &str,
) -> (
    Arc<PeerManager>,
    WireGuardTransport,
    UdpTransport,
    [u8; 32],
    [u8; 32],
) {
    let local_identity = NodeIdentity::generate();
    let remote_identity = NodeIdentity::generate();
    let peers = Arc::new(PeerManager::new(config_for_identity(
        &local_identity,
        "peer-a",
    )));
    peers
        .add_peer(&peer_with_public_key(
            "peer-b",
            "10.20.0.2",
            hex::encode(remote_identity.public_key()),
            None,
        ))
        .await;
    peers
        .set_probe_session_binding("peer-b", Some("old-probe".to_string()), Some([11u8; 32]))
        .await;
    let old_probe_key = peers.probe_key_for_peer("peer-b").await.unwrap();
    assert_eq!(
        peers
            .stage_probe_session_binding(
                "peer-b",
                token.to_string(),
                Some("new-probe".to_string()),
                Some([22u8; 32]),
                true,
            )
            .await,
        ProbeBindingStage::Staged
    );
    let pending_probe_key = peers
        .probe_key_candidates_for_peer("peer-b")
        .await
        .into_iter()
        .find_map(|candidate| {
            matches!(candidate.role, ProbeKeyRole::Pending { token: ref pending } if pending == token)
                .then_some(candidate.key)
        })
        .expect("pending Probe key should be available");
    assert_ne!(pending_probe_key, old_probe_key);

    let (_old_remote, old_local) = establish_sessions();
    let (_new_remote, new_local) = establish_sessions();
    let (wireguard, _encrypted_rx) = WireGuardTransport::new();
    wireguard.add_session("peer-b", old_local).await;
    assert_eq!(
        wireguard
            .stage_responder_session("peer-b", token.to_string(), new_local)
            .await,
        crate::transport::ResponderSessionStage::Staged { had_active: true }
    );
    assert_eq!(
        wireguard.commit_responder_session("peer-b", token).await,
        crate::transport::ResponderSessionCommit::PendingConfirmation
    );

    let udp = UdpTransport::bind("127.0.0.1:0".parse().unwrap(), peers.clone())
        .await
        .unwrap()
        .with_local_node_id("peer-a")
        .with_wireguard_transport(wireguard.clone());
    (peers, wireguard, udp, old_probe_key, pending_probe_key)
}

#[tokio::test]
async fn accepted_pending_probe_punch_promotes_only_after_admission() {
    let token = "accepted-punch";
    let (peers, wireguard, udp, _old_probe_key, pending_probe_key) =
        pending_probe_inbound_fixture(token).await;
    let local_addr = udp.local_addr().unwrap();
    let (tx, _rx) = mpsc::channel(4);
    let worker = tokio::spawn(udp.clone().run_inbound(tx));

    let sender = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let sender_addr = sender.local_addr().unwrap();
    let generation = peers.current_network_generation().await;
    let (punch, nonce) =
        build_authenticated_punch_packet("peer-b", "peer-a", generation, &pending_probe_key);
    sender.send_to(&punch, local_addr).await.unwrap();

    let mut buf = [0u8; 512];
    let (n, _from) = timeout(Duration::from_secs(1), sender.recv_from(&mut buf))
        .await
        .unwrap()
        .unwrap();
    let ack = decode_authenticated_punch_packet(&buf[..n], &pending_probe_key).unwrap();
    assert_eq!(ack.kind, PunchPacketKind::Ack);
    assert_eq!(ack.nonce, nonce);

    assert_eq!(
        peers.probe_key_for_peer("peer-b").await,
        Some(pending_probe_key)
    );
    assert!(!wireguard
        .session_status("peer-b")
        .await
        .has_pending_responder);
    let conn = peers.get_connection("peer-b").await.unwrap();
    assert_eq!(conn.endpoint, Some(sender_addr));
    assert!(conn.direct_health.success_count > 0);

    worker.abort();
}

#[tokio::test]
async fn replayed_pending_probe_punch_is_not_acked_or_promoted() {
    let token = "replayed-punch";
    let (peers, wireguard, udp, old_probe_key, pending_probe_key) =
        pending_probe_inbound_fixture(token).await;
    let local_addr = udp.local_addr().unwrap();
    let sender = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let sender_addr = sender.local_addr().unwrap();
    let generation = peers.current_network_generation().await;
    let (punch, nonce) =
        build_authenticated_punch_packet("peer-b", "peer-a", generation, &pending_probe_key);
    assert_eq!(
        udp.admit_authenticated_punch(
            "peer-b",
            generation,
            PunchPacketKind::Punch,
            nonce,
            sender_addr,
        )
        .await,
        AuthenticatedPunchAdmission::Accepted
    );

    let (tx, _rx) = mpsc::channel(4);
    let worker = tokio::spawn(udp.clone().run_inbound(tx));
    sender.send_to(&punch, local_addr).await.unwrap();

    let mut buf = [0u8; 512];
    assert!(
        timeout(Duration::from_millis(150), sender.recv_from(&mut buf))
            .await
            .is_err()
    );

    assert_eq!(peers.probe_key_for_peer("peer-b").await, Some(old_probe_key));
    assert!(wireguard
        .session_status("peer-b")
        .await
        .has_pending_responder);
    let conn = peers.get_connection("peer-b").await.unwrap();
    assert_eq!(conn.endpoint, None);
    assert_eq!(conn.direct_health.success_count, 0);
    assert_eq!(
        udp.socket_pool_diagnostics().await[0].authenticated_probe_punches_received,
        0
    );
    assert_eq!(udp.socket_pool_diagnostics().await[0].probe_acks_sent, 0);

    worker.abort();
}

#[tokio::test]
async fn pending_probe_ack_requires_authenticated_ack_admission() {
    let token = "ack-admission";
    let (peers, wireguard, udp, old_probe_key, pending_probe_key) =
        pending_probe_inbound_fixture(token).await;
    let local_addr = udp.local_addr().unwrap();
    let sender = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let sender_addr = sender.local_addr().unwrap();
    let generation = peers.current_network_generation().await;
    let nonce = [77u8; 8];
    udp.pending_probes.lock().await.insert(
        nonce,
        PendingProbe {
            sent_at: Instant::now(),
            endpoint: sender_addr,
            local_endpoint: Some(local_addr),
            socket_index: 0,
            generation,
            peer_id: Some("peer-b".to_string()),
            purpose: PendingProbePurpose::ConnectivityCheck,
            accepts_authenticated_ack: false,
            accepts_legacy_ack: true,
        },
    );

    let (tx, _rx) = mpsc::channel(4);
    let worker = tokio::spawn(udp.clone().run_inbound(tx));
    let ack =
        build_authenticated_punch_ack(nonce, "peer-b", "peer-a", generation, &pending_probe_key);
    sender.send_to(&ack, local_addr).await.unwrap();

    timeout(Duration::from_secs(1), async {
        loop {
            if udp.socket_pool_diagnostics().await[0]
                .authenticated_probe_acks_unmatched
                >= 1
            {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();

    assert_eq!(peers.probe_key_for_peer("peer-b").await, Some(old_probe_key));
    assert!(wireguard
        .session_status("peer-b")
        .await
        .has_pending_responder);
    assert!(udp.pending_probes.lock().await.contains_key(&nonce));
    let conn = peers.get_connection("peer-b").await.unwrap();
    assert_eq!(conn.endpoint, None);
    assert_eq!(conn.direct_health.success_count, 0);
    assert_eq!(udp.socket_pool_diagnostics().await[0].probe_acks_received, 0);

    worker.abort();
}

#[tokio::test]
async fn unavailable_pending_probe_ack_keeps_nonce_without_learning_direct() {
    let token = "ack-unavailable-transaction";
    let (peers, wireguard, udp, old_probe_key, pending_probe_key) =
        pending_probe_inbound_fixture(token).await;
    assert!(wireguard.discard_responder_session("peer-b", token).await);

    let local_addr = udp.local_addr().unwrap();
    let sender = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let sender_addr = sender.local_addr().unwrap();
    let generation = peers.current_network_generation().await;
    let nonce = [88u8; 8];
    udp.pending_probes.lock().await.insert(
        nonce,
        PendingProbe {
            sent_at: Instant::now(),
            endpoint: sender_addr,
            local_endpoint: Some(local_addr),
            socket_index: 0,
            generation,
            peer_id: Some("peer-b".to_string()),
            purpose: PendingProbePurpose::ConnectivityCheck,
            accepts_authenticated_ack: true,
            accepts_legacy_ack: false,
        },
    );

    let (tx, _rx) = mpsc::channel(4);
    let worker = tokio::spawn(udp.clone().run_inbound(tx));
    let ack =
        build_authenticated_punch_ack(nonce, "peer-b", "peer-a", generation, &pending_probe_key);
    sender.send_to(&ack, local_addr).await.unwrap();

    timeout(Duration::from_secs(1), async {
        loop {
            if udp.socket_pool_diagnostics().await[0].authenticated_probe_acks_observed >= 1 {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();

    assert!(udp.pending_probes.lock().await.contains_key(&nonce));
    assert_eq!(peers.probe_key_for_peer("peer-b").await, Some(old_probe_key));
    let conn = peers.get_connection("peer-b").await.unwrap();
    assert_eq!(conn.endpoint, None);
    assert_eq!(conn.direct_health.success_count, 0);
    assert_eq!(udp.socket_pool_diagnostics().await[0].probe_acks_received, 0);

    worker.abort();
}

#[tokio::test]
async fn unavailable_pending_probe_transaction_is_not_acked_or_learned() {
    let token = "unavailable-punch";
    let (peers, wireguard, udp, old_probe_key, pending_probe_key) =
        pending_probe_inbound_fixture(token).await;
    assert!(wireguard.discard_responder_session("peer-b", token).await);

    let local_addr = udp.local_addr().unwrap();
    let (tx, _rx) = mpsc::channel(4);
    let worker = tokio::spawn(udp.clone().run_inbound(tx));
    let sender = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let generation = peers.current_network_generation().await;
    let (punch, nonce) =
        build_authenticated_punch_packet("peer-b", "peer-a", generation, &pending_probe_key);
    sender.send_to(&punch, local_addr).await.unwrap();

    let mut buf = [0u8; 512];
    assert!(
        timeout(Duration::from_millis(150), sender.recv_from(&mut buf))
            .await
            .is_err()
    );
    assert_eq!(peers.probe_key_for_peer("peer-b").await, Some(old_probe_key));
    assert!(peers
        .probe_key_candidates_for_peer("peer-b")
        .await
        .iter()
        .any(|candidate| {
            matches!(candidate.role, ProbeKeyRole::Pending { token: ref pending } if pending == token)
        }));
    let conn = peers.get_connection("peer-b").await.unwrap();
    assert_eq!(conn.endpoint, None);
    assert_eq!(conn.direct_health.success_count, 0);
    let diagnostics = udp.socket_pool_diagnostics().await;
    assert_eq!(diagnostics[0].authenticated_probe_punches_received, 0);
    assert_eq!(diagnostics[0].probe_acks_sent, 0);
    assert!(!udp.authenticated_punch_replay.lock().await.contains_key(&(
        "peer-b".to_string(),
        generation,
        nonce,
        punch_kind_code(PunchPacketKind::Punch),
    )));

    worker.abort();
}
