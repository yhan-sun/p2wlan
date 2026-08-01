#[tokio::test]
async fn send_probe_retransmits_punch_burst() {
    let receiver = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let receiver_addr = receiver.local_addr().unwrap();

    let peers = peer_manager();
    let transport = UdpTransport::bind("127.0.0.1:0".parse().unwrap(), peers)
        .await
        .unwrap();

    let nonce = transport.send_probe(None, receiver_addr).await.unwrap();

    let mut buf = [0u8; 64];
    for _ in 0..=PUNCH_PROBE_RETRANSMIT_DELAYS_MS.len() {
        let (n, _from) = timeout(Duration::from_secs(1), receiver.recv_from(&mut buf))
            .await
            .unwrap()
            .unwrap();
        let packet = decode_punch_packet(&buf[..n]).unwrap();
        assert_eq!(packet.kind, PunchPacketKind::Punch);
        assert_eq!(packet.nonce, nonce);
    }
}

#[tokio::test]
async fn inbound_punch_sends_ack_burst() {
    let peers = peer_manager();
    let transport = UdpTransport::bind("127.0.0.1:0".parse().unwrap(), peers)
        .await
        .unwrap();
    let local_addr = transport.local_addr().unwrap();
    let (tx, _rx) = mpsc::channel(4);
    let worker = tokio::spawn(transport.run_inbound(tx));

    let sender = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let punch = build_punch_packet();
    let nonce = decode_punch_packet(&punch).unwrap().nonce;
    sender.send_to(&punch, local_addr).await.unwrap();

    let mut buf = [0u8; 64];
    for _ in 0..=PUNCH_ACK_RETRANSMIT_DELAYS_MS.len() {
        let (n, _from) = timeout(Duration::from_secs(1), sender.recv_from(&mut buf))
            .await
            .unwrap()
            .unwrap();
        let packet = decode_punch_packet(&buf[..n]).unwrap();
        assert_eq!(packet.kind, PunchPacketKind::Ack);
        assert_eq!(packet.nonce, nonce);
    }

    worker.abort();
}

#[tokio::test]
async fn send_probe_uses_authenticated_v2_when_key_is_available() {
    let local_identity = NodeIdentity::generate();
    let peer_identity = NodeIdentity::generate();
    let receiver = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let receiver_addr = receiver.local_addr().unwrap();

    let peers = Arc::new(PeerManager::new(config_for_identity(
        &local_identity,
        "peer-a",
    )));
    peers
        .add_peer(&peer_with_public_key(
            "peer-b",
            "10.20.0.2",
            hex::encode(peer_identity.public_key()),
            Some(receiver_addr),
        ))
        .await;

    let transport = UdpTransport::bind("127.0.0.1:0".parse().unwrap(), peers.clone())
        .await
        .unwrap()
        .with_local_node_id("peer-a");
    transport
        .send_probe(Some("peer-b"), receiver_addr)
        .await
        .unwrap();

    let mut buf = [0u8; 512];
    let (n, _from) = timeout(Duration::from_secs(1), receiver.recv_from(&mut buf))
        .await
        .unwrap()
        .unwrap();

    assert!(decode_punch_packet(&buf[..n]).is_none());
    let identity = peek_authenticated_punch_identity(&buf[..n]).unwrap();
    assert_eq!(identity.kind, PunchPacketKind::Punch);
    assert_eq!(identity.source_node_id, "peer-a");
    assert_eq!(identity.target_node_id, "peer-b");
    assert!(!identity.use_candidate);

    let key = peers.probe_key_for_peer("peer-b").await.unwrap();
    let packet = decode_authenticated_punch_packet(&buf[..n], &key).unwrap();
    assert_eq!(packet.kind, PunchPacketKind::Punch);
    assert_eq!(packet.source_node_id.as_deref(), Some("peer-a"));
    assert_eq!(packet.target_node_id.as_deref(), Some("peer-b"));
    assert!(!packet.use_candidate);
    assert!(packet.authenticated);

    let mut compat_buf = [0u8; 512];
    let (compat_n, _from) = timeout(Duration::from_secs(1), receiver.recv_from(&mut compat_buf))
        .await
        .unwrap()
        .unwrap();
    let compat_packet = decode_punch_packet(&compat_buf[..compat_n]).unwrap();
    assert_eq!(compat_packet.kind, PunchPacketKind::Punch);
    assert_eq!(compat_packet.nonce, packet.nonce);
}

#[tokio::test]
async fn send_nomination_probe_sets_use_candidate_flag() {
    let local_identity = NodeIdentity::generate();
    let peer_identity = NodeIdentity::generate();
    let receiver = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let receiver_addr = receiver.local_addr().unwrap();

    let peers = Arc::new(PeerManager::new(config_for_identity(
        &local_identity,
        "peer-a",
    )));
    peers
        .add_peer(&peer_with_public_key(
            "peer-b",
            "10.20.0.2",
            hex::encode(peer_identity.public_key()),
            Some(receiver_addr),
        ))
        .await;

    let transport = UdpTransport::bind("127.0.0.1:0".parse().unwrap(), peers.clone())
        .await
        .unwrap()
        .with_local_node_id("peer-a");
    transport
        .send_nomination_probe("peer-b", receiver_addr)
        .await
        .unwrap();

    let mut buf = [0u8; 512];
    let (n, _from) = timeout(Duration::from_secs(1), receiver.recv_from(&mut buf))
        .await
        .unwrap()
        .unwrap();

    let key = peers.probe_key_for_peer("peer-b").await.unwrap();
    let packet = decode_authenticated_punch_packet(&buf[..n], &key).unwrap();
    assert_eq!(packet.kind, PunchPacketKind::Punch);
    assert!(packet.use_candidate);
    assert!(packet.authenticated);
}

#[tokio::test]
async fn legacy_probe_ack_confirms_authenticated_probe_for_old_peer() {
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

    let mut buf = [0u8; 512];
    let (n, _from) = timeout(Duration::from_secs(1), remote_candidate.recv_from(&mut buf))
        .await
        .unwrap()
        .unwrap();
    assert!(peek_authenticated_punch_identity(&buf[..n]).is_some());

    let (legacy_n, _from) = timeout(Duration::from_secs(1), remote_candidate.recv_from(&mut buf))
        .await
        .unwrap()
        .unwrap();
    let legacy_probe = decode_punch_packet(&buf[..legacy_n]).unwrap();
    assert_eq!(legacy_probe.kind, PunchPacketKind::Punch);

    remote_candidate
        .send_to(&build_punch_ack(legacy_probe.nonce), local_addr)
        .await
        .unwrap();

    timeout(Duration::from_secs(1), async {
        loop {
            let conn = peers.get_connection("peer-b").await.unwrap();
            if conn.endpoint == Some(remote_candidate_addr)
                && conn.direct_health.consecutive_failures == 0
                && conn.candidate_pairs.iter().any(|pair| {
                    pair.remote_endpoint == remote_candidate_addr && pair.success_count > 0
                })
            {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();

    let diagnostics = transport.socket_pool_diagnostics().await;
    assert_eq!(diagnostics[0].probe_acks_received, 1);
    let conn = peers.get_connection("peer-b").await.unwrap();
    assert_eq!(
        conn.candidate_sources
            .get(&remote_candidate_addr.to_string()),
        Some(&crate::peer::CandidatePairSource::Learned)
    );

    worker.abort();
}
