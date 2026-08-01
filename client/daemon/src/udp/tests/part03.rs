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
