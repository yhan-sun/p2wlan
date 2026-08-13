#[tokio::test]
async fn sends_encrypted_packet_to_peer_endpoint() {
    let receiver = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let receiver_addr = receiver.local_addr().unwrap();

    let peers = peer_manager();
    peers
        .add_peer(&peer("peer-b", "10.20.0.2", Some(receiver_addr)))
        .await;

    let transport = UdpTransport::bind("127.0.0.1:0".parse().unwrap(), peers.clone())
        .await
        .unwrap();
    let payload = vec![4, 1, 2, 3, 4, 5, 6, 7];

    let sent = transport
        .send_packet(&EncryptedPeerPacket {
            peer_id: "peer-b".to_string(),
            dst_ip: "10.20.0.2".to_string(),
            wire_bytes: payload.clone(),
        })
        .await
        .unwrap();
    assert_eq!(sent, Some(payload.len()));

    let mut buf = [0u8; 128];
    let (n, _from) = timeout(Duration::from_secs(1), receiver.recv_from(&mut buf))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(&buf[..n], payload.as_slice());
    assert_eq!(peers.get_connection("peer-b").await.unwrap().bytes_sent, 0);
}

#[tokio::test]
async fn drops_packet_when_endpoint_is_unknown() {
    let peers = peer_manager();
    peers.add_peer(&peer("peer-b", "10.20.0.2", None)).await;

    let transport = UdpTransport::bind("127.0.0.1:0".parse().unwrap(), peers)
        .await
        .unwrap();

    let sent = transport
        .send_packet(&EncryptedPeerPacket {
            peer_id: "peer-b".to_string(),
            dst_ip: "10.20.0.2".to_string(),
            wire_bytes: vec![4, 1, 2, 3],
        })
        .await
        .unwrap();

    assert_eq!(sent, None);
}

#[tokio::test]
async fn run_outbound_sends_wireguard_datagram_that_peer_can_decrypt() {
    let receiver = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let receiver_addr = receiver.local_addr().unwrap();

    let peers = peer_manager();
    peers
        .add_peer(&peer("peer-b", "10.20.0.2", Some(receiver_addr)))
        .await;

    let transport = UdpTransport::bind("127.0.0.1:0".parse().unwrap(), peers)
        .await
        .unwrap();
    let (tx, rx) = mpsc::channel(4);
    let worker = tokio::spawn(transport.run_outbound(rx));

    let (mut node_a_session, mut node_b_session) = establish_sessions();
    let ip_packet = Ipv4Packet::build_icmp_echo_request(
        Ipv4Addr::new(10, 20, 0, 1),
        Ipv4Addr::new(10, 20, 0, 2),
        0x1234,
        1,
        b"ping",
    );
    let wire_bytes = node_a_session.encrypt_to_bytes(&ip_packet).unwrap();

    tx.send(EncryptedPeerPacket {
        peer_id: "peer-b".to_string(),
        dst_ip: "10.20.0.2".to_string(),
        wire_bytes,
    })
    .await
    .unwrap();

    let mut buf = [0u8; 2048];
    let (n, _from) = timeout(Duration::from_secs(1), receiver.recv_from(&mut buf))
        .await
        .unwrap()
        .unwrap();
    let decrypted = node_b_session.decrypt_from_bytes(&buf[..n]).unwrap();
    assert_eq!(decrypted, ip_packet);

    worker.abort();
}

#[tokio::test]
async fn run_inbound_emits_received_encrypted_datagram() {
    let peers = peer_manager();
    let transport = UdpTransport::bind("127.0.0.1:0".parse().unwrap(), peers)
        .await
        .unwrap();
    let local_addr = transport.local_addr().unwrap();
    let (tx, mut rx) = mpsc::channel(4);
    let worker = tokio::spawn(transport.run_inbound(tx));

    let sender = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let payload = vec![4, 9, 8, 7, 6, 5];
    sender.send_to(&payload, local_addr).await.unwrap();

    let received = timeout(Duration::from_secs(1), rx.recv())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(received.source, Some(sender.local_addr().unwrap()));
    assert_eq!(received.wire_bytes, payload);

    worker.abort();
}

#[tokio::test]
async fn live_stun_refresh_does_not_steal_encrypted_datagrams() {
    let peers = peer_manager();
    let transport = UdpTransport::bind("127.0.0.1:0".parse().unwrap(), peers)
        .await
        .unwrap();
    let local_addr = transport.local_addr().unwrap();
    let (tx, mut rx) = mpsc::channel(4);
    let inbound_worker = tokio::spawn(transport.clone().run_inbound(tx));

    let stun_server = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let stun_addr = stun_server.local_addr().unwrap();
    let stun_worker = tokio::spawn(async move {
        let mut buf = [0u8; 2048];
        let (n, client_addr) = stun_server.recv_from(&mut buf).await.unwrap();
        let request = StunMessage::decode(&buf[..n]).unwrap();
        let mapped: SocketAddr = "203.0.113.7:45678".parse().unwrap();
        let mut response =
            StunMessage::with_transaction_id(BINDING_RESPONSE, request.transaction_id);
        response.add_attribute(StunAttribute::XorMappedAddress(mapped));
        stun_server
            .send_to(&response.encode(), client_addr)
            .await
            .unwrap();
    });

    let refresh = {
        let transport = transport.clone();
        tokio::spawn(async move {
            transport
                .gather_candidate_report_live(vec![stun_addr], Duration::from_secs(1))
                .await
        })
    };

    let sender = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let encrypted = vec![4, 0x91, 0x82, 0x73, 0x64];
    sender.send_to(&encrypted, local_addr).await.unwrap();

    let received = timeout(Duration::from_secs(1), rx.recv())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(received.wire_bytes, encrypted);
    assert_eq!(received.source, Some(sender.local_addr().unwrap()));

    let report = refresh.await.unwrap().unwrap();
    assert!(report.candidates.iter().any(|candidate| {
        candidate.endpoint.to_string() == "203.0.113.7:45678"
            && candidate.source == p2pnet_nat::CandidateSource::StunObserved
    }));
    assert_eq!(report.nat_profile.observations.len(), 1);
    assert!(report.nat_profile.observations[0].error.is_none());

    stun_worker.await.unwrap();
    inbound_worker.abort();
}

#[tokio::test]
async fn parallel_live_stun_gather_does_not_sum_observer_delays() {
    let peers = peer_manager();
    let transport = UdpTransport::bind("127.0.0.1:0".parse().unwrap(), peers)
        .await
        .unwrap();
    let (tx, _rx) = mpsc::channel(4);
    let inbound_worker = tokio::spawn(transport.clone().run_inbound(tx));

    let mut servers = Vec::new();
    let mut workers = Vec::new();
    for (delay, mapped) in [
        (
            Duration::from_millis(20),
            "203.0.113.7:45678".parse::<SocketAddr>().unwrap(),
        ),
        (
            Duration::from_millis(180),
            "203.0.113.8:45679".parse::<SocketAddr>().unwrap(),
        ),
    ] {
        let server = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let server_addr = server.local_addr().unwrap();
        servers.push(server_addr);
        workers.push(tokio::spawn(async move {
            let mut buf = [0u8; 2048];
            let (n, client_addr) = server.recv_from(&mut buf).await.unwrap();
            let request = StunMessage::decode(&buf[..n]).unwrap();
            tokio::time::sleep(delay).await;
            let mut response =
                StunMessage::with_transaction_id(BINDING_RESPONSE, request.transaction_id);
            response.add_attribute(StunAttribute::XorMappedAddress(mapped));
            server
                .send_to(&response.encode(), client_addr)
                .await
                .unwrap();
        }));
    }

    let started = Instant::now();
    let report = transport
        .gather_candidate_report_live_parallel(servers, Duration::from_secs(1))
        .await
        .unwrap();
    let elapsed = started.elapsed();

    assert_eq!(report.nat_profile.observations.len(), 2);
    assert!(report
        .nat_profile
        .observations
        .iter()
        .all(|observation| observation.error.is_none()));
    assert!(
        elapsed < Duration::from_millis(320),
        "parallel gather took {elapsed:?}; observer delays were likely serialized"
    );

    for worker in workers {
        worker.await.unwrap();
    }
    inbound_worker.abort();
}

#[tokio::test]
async fn run_inbound_acks_punch_and_does_not_forward_to_wireguard() {
    let peers = peer_manager();
    let sender = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let sender_addr = sender.local_addr().unwrap();

    peers.add_peer(&peer("peer-b", "10.20.0.2", None)).await;
    peers
        .add_candidates("peer-b", &[sender_addr.to_string()])
        .await;

    let transport = UdpTransport::bind("127.0.0.1:0".parse().unwrap(), peers.clone())
        .await
        .unwrap();
    let local_addr = transport.local_addr().unwrap();
    let (tx, mut rx) = mpsc::channel(4);
    let worker = tokio::spawn(transport.run_inbound(tx));

    sender
        .send_to(&p2pnet_nat::build_punch_packet(), local_addr)
        .await
        .unwrap();

    let mut buf = [0u8; 64];
    let (n, _from) = timeout(Duration::from_secs(1), sender.recv_from(&mut buf))
        .await
        .unwrap()
        .unwrap();
    let ack = decode_punch_packet(&buf[..n]).unwrap();
    assert_eq!(ack.kind, PunchPacketKind::Ack);

    assert!(timeout(Duration::from_millis(100), rx.recv())
        .await
        .is_err());

    let conn = peers.get_connection("peer-b").await.unwrap();
    assert_eq!(conn.endpoint, Some(sender_addr));
    assert_eq!(conn.state.to_string(), "hole_punching");
    assert!(conn.direct_health.last_success_at.is_some());

    worker.abort();
}

#[tokio::test]
async fn run_inbound_accepts_authenticated_peer_reflexive_probe() {
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
    let observation_ingress = PeerReflexiveIngress::new();
    let transport = UdpTransport::bind("127.0.0.1:0".parse().unwrap(), peers.clone())
        .await
        .unwrap()
        .with_local_node_id("peer-a")
        .with_peer_reflexive_observer(observation_ingress.clone());
    let local_addr = transport.local_addr().unwrap();
    let (tx, mut rx) = mpsc::channel(4);
    let worker = tokio::spawn(transport.run_inbound(tx));

    let sender = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let sender_addr = sender.local_addr().unwrap();
    let (probe, nonce) = build_authenticated_punch_packet("peer-b", "peer-a", 7, &key);
    sender.send_to(&probe, local_addr).await.unwrap();

    let mut buf = [0u8; 512];
    let (n, _from) = timeout(Duration::from_secs(1), sender.recv_from(&mut buf))
        .await
        .unwrap()
        .unwrap();
    let ack = decode_authenticated_punch_packet(&buf[..n], &key).unwrap();
    assert_eq!(ack.kind, PunchPacketKind::Ack);
    assert_eq!(ack.nonce, nonce);
    assert_eq!(ack.source_node_id.as_deref(), Some("peer-a"));
    assert_eq!(ack.target_node_id.as_deref(), Some("peer-b"));
    assert!(!ack.use_candidate);

    let mut saw_triggered_check = false;
    for _ in 0..8 {
        let (n, _from) = timeout(Duration::from_secs(1), sender.recv_from(&mut buf))
            .await
            .unwrap()
            .unwrap();
        if let Some(identity) = peek_authenticated_punch_identity(&buf[..n]) {
            if identity.kind == PunchPacketKind::Punch
                && identity.source_node_id == "peer-a"
                && identity.target_node_id == "peer-b"
            {
                let triggered = decode_authenticated_punch_packet(&buf[..n], &key).unwrap();
                assert_eq!(triggered.kind, PunchPacketKind::Punch);
                saw_triggered_check = true;
                break;
            }
        }
    }
    assert!(
        saw_triggered_check,
        "inbound authenticated probe should trigger an immediate reverse check"
    );

    assert!(timeout(Duration::from_millis(100), rx.recv())
        .await
        .is_err());

    let observation = timeout(Duration::from_secs(1), observation_ingress.next())
        .await
        .unwrap();
    assert_eq!(observation.peer_id, "peer-b");
    assert_eq!(observation.observed_endpoint, sender_addr);

    let conn = peers.get_connection("peer-b").await.unwrap();
    assert_eq!(conn.endpoint, Some(sender_addr));
    assert!(conn.candidates.contains(&sender_addr.to_string()));
    assert_eq!(conn.state.to_string(), "hole_punching");
    assert!(conn.direct_health.last_success_at.is_some());

    worker.abort();
}

#[tokio::test]
async fn replayed_authenticated_punch_gets_idempotent_ack_without_state_update() {
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
    let sender_addr = sender.local_addr().unwrap();
    let (probe, nonce) = build_authenticated_punch_packet("peer-b", "peer-a", 7, &key);
    sender.send_to(&probe, local_addr).await.unwrap();

    let mut buf = [0u8; 512];
    let (n, _from) = timeout(Duration::from_secs(1), sender.recv_from(&mut buf))
        .await
        .unwrap()
        .unwrap();
    let first_ack = decode_authenticated_punch_packet(&buf[..n], &key).unwrap();
    assert_eq!(first_ack.kind, PunchPacketKind::Ack);
    assert_eq!(first_ack.nonce, nonce);
    drain_udp_quiet(&sender, Duration::from_millis(150)).await;

    let first_success_count = peers
        .get_connection("peer-b")
        .await
        .unwrap()
        .direct_health
        .success_count;

    sender.send_to(&probe, local_addr).await.unwrap();
    let (n, _from) = timeout(Duration::from_secs(1), sender.recv_from(&mut buf))
        .await
        .unwrap()
        .unwrap();
    let replay_ack = decode_authenticated_punch_packet(&buf[..n], &key).unwrap();
    assert_eq!(replay_ack.kind, PunchPacketKind::Ack);
    assert_eq!(replay_ack.nonce, nonce);

    assert!(timeout(Duration::from_millis(100), rx.recv())
        .await
        .is_err());
    let conn = peers.get_connection("peer-b").await.unwrap();
    assert_eq!(conn.endpoint, Some(sender_addr));
    assert_eq!(conn.direct_health.success_count, first_success_count);

    worker.abort();
}

#[tokio::test]
async fn direct_peer_authenticated_punch_produces_no_scan_no_observation_no_validation() {
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
    let observation_ingress = PeerReflexiveIngress::new();
    let validation_triggers = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let trigger_count = validation_triggers.clone();
    let transport = UdpTransport::bind("127.0.0.1:0".parse().unwrap(), peers.clone())
        .await
        .unwrap()
        .with_local_node_id("peer-a")
        .with_peer_reflexive_observer(observation_ingress.clone())
        .with_validation_trigger(Arc::new(move |_| {
            trigger_count.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        }));
    let local_addr = transport.local_addr().unwrap();
    let (tx, mut rx) = mpsc::channel(4);
    let worker = tokio::spawn(transport.clone().run_inbound(tx));

    let sender = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let sender_addr = sender.local_addr().unwrap();

    // The peer is already Direct: no traversal work may be re-created.
    peers
        .record_direct_success_for_generation("peer-b", Some(sender_addr), 0)
        .await;
    assert!(peers.is_direct("peer-b").await);

    let (probe, nonce) = build_authenticated_punch_packet("peer-b", "peer-a", 0, &key);
    sender.send_to(&probe, local_addr).await.unwrap();

    // The immediate ACK burst must still be sent (the peer needs the
    // confirmation), but no reverse connectivity check may follow.
    let mut buf = [0u8; 512];
    let (n, _from) = timeout(Duration::from_secs(1), sender.recv_from(&mut buf))
        .await
        .unwrap()
        .unwrap();
    let ack = decode_authenticated_punch_packet(&buf[..n], &key).unwrap();
    assert_eq!(ack.kind, PunchPacketKind::Ack);
    assert_eq!(ack.nonce, nonce);

    // Wait out the ACK retransmit window and assert no Punch-kind datagram
    // (triggered check) ever leaves the transport toward the Direct peer.
    let mut saw_probe_punch = false;
    let deadline = Instant::now() + Duration::from_millis(300);
    while Instant::now() < deadline {
        if let Ok(Ok((n, _))) = timeout(Duration::from_millis(60), sender.recv_from(&mut buf)).await {
            if let Some(identity) = peek_authenticated_punch_identity(&buf[..n]) {
                if identity.kind == PunchPacketKind::Punch {
                    saw_probe_punch = true;
                }
            }
        }
    }
    assert!(
        !saw_probe_punch,
        "a Direct peer must not receive a reverse triggered check after an inbound punch"
    );

    assert_eq!(
        observation_ingress.pending_len(),
        0,
        "a Direct peer's observed endpoint must not be queued for the peer-reflexive signal loop"
    );
    assert_eq!(
        validation_triggers.load(std::sync::atomic::Ordering::SeqCst),
        0,
        "a Direct peer's inbound punch must not enqueue direct validation"
    );
    assert!(!transport.has_direct_validation_expectation("peer-b").await);
    assert!(transport.direct_validation_target("peer-b").await.is_none());
    assert!(timeout(Duration::from_millis(100), rx.recv())
        .await
        .is_err());

    worker.abort();
}

#[tokio::test]
async fn direct_peer_matched_ack_creates_no_validation_expectation_or_probe() {
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
    let observation_ingress = PeerReflexiveIngress::new();
    let validation_triggers = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let trigger_count = validation_triggers.clone();
    let transport = UdpTransport::bind("127.0.0.1:0".parse().unwrap(), peers.clone())
        .await
        .unwrap()
        .with_local_node_id("peer-a")
        .with_peer_reflexive_observer(observation_ingress.clone())
        .with_validation_trigger(Arc::new(move |_| {
            trigger_count.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        }));
    let local_addr = transport.local_addr().unwrap();
    let (tx, _rx) = mpsc::channel(4);
    let worker = tokio::spawn(transport.clone().run_inbound(tx));

    let sender = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let sender_addr = sender.local_addr().unwrap();
    peers
        .record_direct_success_for_generation("peer-b", Some(sender_addr), 0)
        .await;
    assert!(peers.is_direct("peer-b").await);

    // A probe that was sent before Direct confirmation gets ACKed after the
    // promotion: the ACK must not re-create peer-reflexive signal work, a
    // validation request/expectation or a reverse probe.
    let nonce = transport
        .send_probe(Some("peer-b"), sender_addr)
        .await
        .unwrap();
    let mut buf = [0u8; 512];
    let (n, _from) = timeout(Duration::from_secs(1), sender.recv_from(&mut buf))
        .await
        .unwrap()
        .unwrap();
    let probe_packet = decode_authenticated_punch_packet(&buf[..n], &key).unwrap();
    assert_eq!(probe_packet.kind, PunchPacketKind::Punch);
    assert_eq!(probe_packet.nonce, nonce);
    // Drain the legacy v1 compatibility probe the same send emits.
    while let Ok(Ok(_)) = timeout(Duration::from_millis(150), sender.recv_from(&mut buf)).await {}

    let generation = peers.current_network_generation().await;
    let ack = p2pnet_nat::build_authenticated_punch_ack(
        nonce,
        "peer-a",
        "peer-b",
        generation,
        &key,
    );
    sender.send_to(&ack, local_addr).await.unwrap();

    let mut buf = [0u8; 512];
    assert!(
        timeout(Duration::from_millis(400), sender.recv_from(&mut buf))
            .await
            .is_err(),
        "a matched ACK for a Direct peer must not produce any outbound datagram"
    );
    assert_eq!(observation_ingress.pending_len(), 0);
    assert_eq!(
        validation_triggers.load(std::sync::atomic::Ordering::SeqCst),
        0,
        "a matched ACK for a Direct peer must not enqueue direct validation"
    );
    assert!(!transport.has_direct_validation_expectation("peer-b").await);
    assert!(transport.direct_validation_target("peer-b").await.is_none());

    worker.abort();
}
