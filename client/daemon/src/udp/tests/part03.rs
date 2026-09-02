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

/// A Probe-v2 MAC proves the key that verified the datagram, not that the
/// same node ID still denotes that identity after an await. Park a packet
/// immediately after old-key verification, replace the peer completely, then
/// reuse the same generation+nonce under the new key.
#[tokio::test]
async fn verified_old_probe_cannot_cross_remove_and_same_id_readd() {
    let local_identity = NodeIdentity::generate();
    let old_remote_identity = NodeIdentity::generate();
    let new_remote_identity = NodeIdentity::generate();
    let peers = Arc::new(PeerManager::new(config_for_identity(
        &local_identity,
        "peer-a",
    )));
    peers
        .add_peer(&peer_with_public_key(
            "peer-b",
            "10.20.0.2",
            hex::encode(old_remote_identity.public_key()),
            None,
        ))
        .await;
    let old_key = peers.probe_key_for_peer("peer-b").await.unwrap();

    let transport = UdpTransport::bind("127.0.0.1:0".parse().unwrap(), peers.clone())
        .await
        .unwrap()
        .with_local_node_id("peer-a");
    let local_addr = transport.local_addr().unwrap();
    let (tx, _rx) = mpsc::channel(4);
    let worker = tokio::spawn(transport.clone().run_inbound(tx));

    let gate = Arc::new(crate::peer::AuthenticatedProbeVerifyGate::new());
    peers.install_authenticated_probe_verify_gate_for_test("peer-b", gate.clone());
    let old_sender = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let old_source = old_sender.local_addr().unwrap();
    let generation = peers.current_network_generation().await;
    let (old_punch, nonce) =
        build_authenticated_punch_packet("peer-b", "peer-a", generation, &old_key);
    old_sender.send_to(&old_punch, local_addr).await.unwrap();

    timeout(Duration::from_secs(1), gate.reached.notified())
        .await
        .expect("old packet must reach the post-MAC lifecycle barrier");

    transport
        .cleanup_peer_lifecycle("peer-b", "peer_left", true)
        .await;
    peers
        .add_peer(&peer_with_public_key(
            "peer-b",
            "10.20.0.2",
            hex::encode(new_remote_identity.public_key()),
            None,
        ))
        .await;
    let new_key = peers.probe_key_for_peer("peer-b").await.unwrap();
    assert_ne!(old_key, new_key);
    gate.release.wait().await;

    // A fresh replacement packet is processed by the same sequential reader.
    // Its ACK proves the paused stale handler already finished.
    let new_sender = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let new_source = new_sender.local_addr().unwrap();
    let (fresh_punch, fresh_nonce) =
        build_authenticated_punch_packet("peer-b", "peer-a", generation, &new_key);
    new_sender.send_to(&fresh_punch, local_addr).await.unwrap();
    let mut buf = [0u8; 512];
    let (n, _) = timeout(Duration::from_secs(1), new_sender.recv_from(&mut buf))
        .await
        .expect("fresh replacement-session packet must receive an ACK")
        .unwrap();
    let ack = decode_authenticated_punch_packet(&buf[..n], &new_key).unwrap();
    assert_eq!(ack.kind, PunchPacketKind::Ack);
    assert_eq!(ack.nonce, fresh_nonce);

    let mut old_ack = [0u8; 512];
    assert!(
        timeout(
            Duration::from_millis(100),
            old_sender.recv_from(&mut old_ack)
        )
        .await
        .is_err(),
        "the stale old-key packet must not be ACKed"
    );

    let conn = peers.get_connection("peer-b").await.unwrap();
    assert_eq!(conn.endpoint, Some(new_source));
    assert_eq!(conn.direct_health.success_count, 1);
    assert!(!conn
        .candidates
        .iter()
        .any(|candidate| candidate == &old_source.to_string()));
    assert!(conn
        .candidate_pairs
        .iter()
        .all(|pair| pair.remote_endpoint != old_source));
    assert!(transport.affinity_pin_for_test("peer-b").await.is_some());
    assert!(
        !transport
            .authenticated_punch_rate
            .lock()
            .await
            .contains_key(&("peer-b".to_string(), old_source)),
        "stale lifecycle evidence must not consume replacement rate state"
    );
    assert!(
        !transport
            .authenticated_punch_replay
            .lock()
            .await
            .contains_key(&(
                "peer-b".to_string(),
                generation,
                nonce,
                punch_kind_code(PunchPacketKind::Punch),
            )),
        "stale lifecycle evidence must not leave a replay admission"
    );
    let diagnostics = transport.socket_pool_diagnostics().await;
    assert_eq!(diagnostics[0].authenticated_probe_punches_received, 1);
    assert_eq!(diagnostics[0].probe_acks_sent, 1);

    worker.abort();
}

/// A remote restart used to release the adoption lock after UDP cleanup and
/// only then rotate PeerSessionGeneration. Park exactly in that old gap and
/// prove a packet verified under the retired generation cannot acquire the
/// adoption turn until the lifecycle reset has been published.
#[tokio::test]
async fn remote_incarnation_cleanup_and_finish_are_one_adoption_transaction() {
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
    let probe_key = peers.probe_key_for_peer("peer-b").await.unwrap();
    let old_peer_session = peers.peer_session_snapshot_for_test("peer-b").unwrap();
    let old_candidate_generation = 0x4000_0000_0000_0000u64 | (3000u64 << 21) | 1;
    let new_candidate_generation = 0x4000_0000_0000_0000u64 | (3001u64 << 21) | 1;
    assert_eq!(
        peers
            .add_candidates_with_metadata(
                "peer-b",
                &["198.51.100.10:40000".to_string()],
                &HashMap::new(),
                old_candidate_generation,
                None,
            )
            .await,
        crate::peer::CandidateSetApplyResult::Applied
    );

    let transport = UdpTransport::bind("127.0.0.1:0".parse().unwrap(), peers.clone())
        .await
        .unwrap()
        .with_local_node_id("peer-a");
    let local_addr = transport.local_addr().unwrap();
    let (tx, _rx) = mpsc::channel(4);
    let worker = tokio::spawn(transport.clone().run_inbound(tx));

    let verify_gate = Arc::new(crate::peer::AuthenticatedProbeVerifyGate::new());
    peers.install_authenticated_probe_verify_gate_for_test("peer-b", verify_gate.clone());
    let cleanup_gate = Arc::new(RemoteIncarnationCleanupGate::new());
    transport.install_remote_incarnation_cleanup_gate_for_test("peer-b", cleanup_gate.clone());

    let stale_sender = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let stale_source = stale_sender.local_addr().unwrap();
    let generation = peers.current_network_generation().await;
    let (stale_punch, _stale_nonce) =
        build_authenticated_punch_packet("peer-b", "peer-a", generation, &probe_key);
    stale_sender
        .send_to(&stale_punch, local_addr)
        .await
        .unwrap();
    timeout(Duration::from_secs(1), verify_gate.reached.notified())
        .await
        .expect("old packet must pause after MAC verification");

    let (old_incarnation, claimed_incarnation) = peers
        .claim_remote_candidate_incarnation_if_newer("peer-b", new_candidate_generation)
        .await
        .expect("new remote boot must claim a reset");
    let reset_transport = transport.clone();
    let reset = tokio::spawn(async move {
        reset_transport
            .cleanup_peer_lifecycle_and_finish_remote_incarnation_reset(
                "peer-b",
                "remote_incarnation_changed",
                old_incarnation,
                claimed_incarnation,
            )
            .await
    });
    timeout(Duration::from_secs(1), cleanup_gate.reached.notified())
        .await
        .expect("reset must park after cleanup while retaining adoption");

    verify_gate.release.wait().await;
    let mut stale_ack = [0u8; 512];
    assert!(
        timeout(
            Duration::from_millis(100),
            stale_sender.recv_from(&mut stale_ack)
        )
        .await
        .is_err(),
        "the verified old packet must remain blocked while reset owns adoption"
    );

    cleanup_gate.release.wait().await;
    assert!(reset.await.unwrap());
    assert_ne!(
        peers.peer_session_snapshot_for_test("peer-b").unwrap().0,
        old_peer_session.0,
        "finish must rotate the lifecycle before releasing adoption"
    );

    // A fresh packet is processed by the same sequential reader only after the
    // stale handler failed its lifecycle fence.
    let fresh_sender = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let fresh_source = fresh_sender.local_addr().unwrap();
    let (fresh_punch, fresh_nonce) =
        build_authenticated_punch_packet("peer-b", "peer-a", generation, &probe_key);
    fresh_sender
        .send_to(&fresh_punch, local_addr)
        .await
        .unwrap();
    let mut fresh_ack = [0u8; 512];
    let (n, _) = timeout(
        Duration::from_secs(1),
        fresh_sender.recv_from(&mut fresh_ack),
    )
    .await
    .expect("current-lifecycle packet must receive an ACK")
    .unwrap();
    let ack = decode_authenticated_punch_packet(&fresh_ack[..n], &probe_key).unwrap();
    assert_eq!(ack.kind, PunchPacketKind::Ack);
    assert_eq!(ack.nonce, fresh_nonce);
    assert!(
        timeout(
            Duration::from_millis(100),
            stale_sender.recv_from(&mut stale_ack)
        )
        .await
        .is_err(),
        "the retired packet must never receive a late ACK"
    );

    let conn = peers.get_connection("peer-b").await.unwrap();
    assert_eq!(conn.endpoint, Some(fresh_source));
    assert!(!conn
        .candidates
        .iter()
        .any(|candidate| candidate == &stale_source.to_string()));
    assert!(conn
        .candidate_pairs
        .iter()
        .all(|pair| pair.remote_endpoint != stale_source));
    let diagnostics = transport.socket_pool_diagnostics().await;
    assert_eq!(diagnostics[0].authenticated_probe_punches_received, 1);
    assert_eq!(diagnostics[0].probe_acks_sent, 1);

    worker.abort();
}

/// Pending-key promotion must wait for WireGuard's emit turn before taking
/// the global epoch; otherwise outbound `emit -> epoch` and inbound
/// `epoch -> emit` form a process-wide ABBA deadlock.
#[tokio::test]
async fn pending_probe_waits_for_emit_before_acquiring_network_epoch() {
    let token = "pending-emit-order";
    let (peers, wireguard, udp, _old_probe_key, pending_probe_key) =
        pending_probe_inbound_fixture(token).await;
    let local_addr = udp.local_addr().unwrap();
    let (tx, _rx) = mpsc::channel(4);
    let worker = tokio::spawn(udp.clone().run_inbound(tx));

    let gate = Arc::new(crate::peer::AuthenticatedProbeVerifyGate::new());
    peers.install_authenticated_probe_verify_gate_for_test("peer-b", gate.clone());
    let sender = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let generation = peers.current_network_generation().await;
    let (punch, nonce) =
        build_authenticated_punch_packet("peer-b", "peer-a", generation, &pending_probe_key);
    sender.send_to(&punch, local_addr).await.unwrap();

    timeout(Duration::from_secs(1), gate.reached.notified())
        .await
        .expect("pending-key packet must pause after MAC verification");
    let emit_guard = wireguard.acquire_outbound_emit_guard("peer-b").await;
    gate.release.wait().await;
    timeout(
        Duration::from_secs(1),
        gate.pending_emit_wait_started.notified(),
    )
    .await
    .expect("inbound handler must reach the contended emit acquisition");

    let epoch_guard = timeout(Duration::from_millis(250), udp.network_epoch_gate.lock())
        .await
        .expect("network epoch must remain available while promotion waits for emit");
    drop(epoch_guard);

    let mut buf = [0u8; 512];
    assert!(
        timeout(Duration::from_millis(100), sender.recv_from(&mut buf))
            .await
            .is_err(),
        "pending packet cannot complete until its emit turn is released"
    );
    drop(emit_guard);

    let (n, _) = timeout(Duration::from_secs(1), sender.recv_from(&mut buf))
        .await
        .expect("pending packet must finish after emit is released")
        .unwrap();
    let ack = decode_authenticated_punch_packet(&buf[..n], &pending_probe_key).unwrap();
    assert_eq!(ack.kind, PunchPacketKind::Ack);
    assert_eq!(ack.nonce, nonce);
    assert_eq!(
        peers.probe_key_for_peer("peer-b").await,
        Some(pending_probe_key)
    );

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

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
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

    // The production consent deadline is two seconds.  Keep this fixture
    // comfortably below that limit while leaving enough scheduling margin for
    // the inbound worker and responder to run on a loaded workspace test host.
    transport
        .run_keepalive_round(Duration::from_millis(500))
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

    let (tun, ctrl) = MockTunDevice::new_pair("test0", 1420, "10.20.0.2");
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
                .run_inbound_with_peers(udp_inbound_rx, inbound_tx, Some(peers), None)
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
    assert_ne!(
        conn.state.to_string(),
        "direct",
        "a decrypted ordinary payload is evidence for validation, not Direct proof"
    );
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
        wireguard.commit_responder_session("peer-b", "txn-1").await,
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
    assert!(
        !wireguard
            .session_status("peer-b")
            .await
            .has_pending_responder
    );

    let packet = Ipv4Packet::build_icmp_echo_request(
        Ipv4Addr::new(10, 20, 0, 1),
        Ipv4Addr::new(10, 20, 0, 2),
        0x5555,
        1,
        b"probe-confirmed-wg",
    );
    let encrypted = wireguard
        .encrypt_outbound(crate::dataplane::OutboundPacket {
                trace: None,
            peer_id: "peer-b".to_string(),
            dst_ip: "10.20.0.2".to_string(),
            packet: packet.clone(),
        })
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        new_remote
            .decrypt_from_bytes(&encrypted.wire_bytes)
            .unwrap(),
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
    assert!(
        !udp.confirm_pending_probe_adoption("peer-b", "missing-wg")
            .await
    );
    assert_eq!(
        peers.probe_key_for_peer("peer-b").await,
        Some(old_probe_key)
    );
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
    assert!(
        peers
            .discard_pending_probe_session_binding("peer-b", token)
            .await
    );

    assert!(!udp.confirm_pending_probe_adoption("peer-b", token).await);
    assert_eq!(
        peers.probe_key_for_peer("peer-b").await,
        Some(old_probe_key)
    );
    assert!(
        wireguard
            .session_status("peer-b")
            .await
            .has_pending_responder
    );
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

    // The receive path intentionally emits the NAT-window ACK before endpoint
    // learning and probe bookkeeping. Wait for the admitted transaction to
    // finish instead of treating ACK delivery as completion of those later
    // local mutations.
    timeout(Duration::from_secs(1), async {
        loop {
            let conn = peers.get_connection("peer-b").await.unwrap();
            if conn.endpoint == Some(sender_addr) && conn.direct_health.success_count > 0 {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("accepted pending Probe punch must finish endpoint and health adoption");

    assert_eq!(
        peers.probe_key_for_peer("peer-b").await,
        Some(pending_probe_key)
    );
    assert!(
        !wireguard
            .session_status("peer-b")
            .await
            .has_pending_responder
    );
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

    assert_eq!(
        peers.probe_key_for_peer("peer-b").await,
        Some(old_probe_key)
    );
    assert!(
        wireguard
            .session_status("peer-b")
            .await
            .has_pending_responder
    );
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
            expires_at: Instant::now() + DIRECT_KEEPALIVE_ACK_TIMEOUT,
            endpoint: sender_addr,
            local_endpoint: Some(local_addr),
            socket_index: 0,
            generation,
            remote_candidate_epoch: 0,
            probe_session_id: None,
            peer_id: Some("peer-b".to_string()),
            purpose: PendingProbePurpose::ConnectivityCheck,
            accepts_authenticated_ack: false,
            accepts_legacy_ack: true,
            socket_epoch: 0,
            cleanup_epoch: 0,
            direct_commit_seq: 0,
        },
    );

    let (tx, _rx) = mpsc::channel(4);
    let worker = tokio::spawn(udp.clone().run_inbound(tx));
    let ack =
        build_authenticated_punch_ack(nonce, "peer-b", "peer-a", generation, &pending_probe_key);
    sender.send_to(&ack, local_addr).await.unwrap();

    timeout(Duration::from_secs(1), async {
        loop {
            if udp.socket_pool_diagnostics().await[0].authenticated_probe_acks_unmatched >= 1 {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();

    assert_eq!(
        peers.probe_key_for_peer("peer-b").await,
        Some(old_probe_key)
    );
    assert!(
        wireguard
            .session_status("peer-b")
            .await
            .has_pending_responder
    );
    assert!(udp.pending_probes.lock().await.contains_key(&nonce));
    let conn = peers.get_connection("peer-b").await.unwrap();
    assert_eq!(conn.endpoint, None);
    assert_eq!(conn.direct_health.success_count, 0);
    assert_eq!(
        udp.socket_pool_diagnostics().await[0].probe_acks_received,
        0
    );

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
            expires_at: Instant::now() + DIRECT_KEEPALIVE_ACK_TIMEOUT,
            endpoint: sender_addr,
            local_endpoint: Some(local_addr),
            socket_index: 0,
            generation,
            remote_candidate_epoch: 0,
            probe_session_id: None,
            peer_id: Some("peer-b".to_string()),
            purpose: PendingProbePurpose::ConnectivityCheck,
            accepts_authenticated_ack: true,
            accepts_legacy_ack: false,
            socket_epoch: 0,
            cleanup_epoch: 0,
            direct_commit_seq: 0,
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
    assert_eq!(
        peers.probe_key_for_peer("peer-b").await,
        Some(old_probe_key)
    );
    let conn = peers.get_connection("peer-b").await.unwrap();
    assert_eq!(conn.endpoint, None);
    assert_eq!(conn.direct_health.success_count, 0);
    assert_eq!(
        udp.socket_pool_diagnostics().await[0].probe_acks_received,
        0
    );

    worker.abort();
}

#[tokio::test]
async fn expired_authenticated_probe_ack_is_terminal_and_cannot_learn_direct() {
    let token = "expired-probe-ack";
    let (peers, _wireguard, udp, _old_probe_key, pending_probe_key) =
        pending_probe_inbound_fixture(token).await;
    let local_addr = udp.local_addr().unwrap();
    let sender = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let sender_addr = sender.local_addr().unwrap();
    let generation = peers.current_network_generation().await;
    let nonce = [199u8; 8];
    udp.pending_probes.lock().await.insert(
        nonce,
        PendingProbe {
            sent_at: Instant::now() - Duration::from_secs(3),
            expires_at: Instant::now() - Duration::from_millis(1),
            endpoint: sender_addr,
            local_endpoint: Some(local_addr),
            socket_index: 0,
            generation,
            remote_candidate_epoch: 0,
            probe_session_id: Some("expired-session".to_string()),
            peer_id: Some("peer-b".to_string()),
            purpose: PendingProbePurpose::ConnectivityCheck,
            accepts_authenticated_ack: true,
            accepts_legacy_ack: false,
            socket_epoch: 0,
            cleanup_epoch: 0,
            direct_commit_seq: 0,
        },
    );

    let (tx, _rx) = mpsc::channel(4);
    let worker = tokio::spawn(udp.clone().run_inbound(tx));
    let ack =
        build_authenticated_punch_ack(nonce, "peer-b", "peer-a", generation, &pending_probe_key);
    sender.send_to(&ack, local_addr).await.unwrap();

    timeout(Duration::from_secs(1), async {
        loop {
            if udp.socket_pool_diagnostics().await[0].authenticated_probe_acks_unmatched >= 1 {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();

    assert!(!udp.pending_probes.lock().await.contains_key(&nonce));
    let conn = peers.get_connection("peer-b").await.unwrap();
    assert_eq!(conn.endpoint, None);
    assert_eq!(conn.direct_health.success_count, 0);
    assert!(conn
        .direct_events
        .iter()
        .any(|event| event.stage == "direct_probe_ack_expired"));

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
    assert_eq!(
        peers.probe_key_for_peer("peer-b").await,
        Some(old_probe_key)
    );
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
