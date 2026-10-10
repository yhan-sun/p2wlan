async fn assert_validation_request_during_emit_contention(replace_session: bool) {
    let (mut remote_session, local_session) = establish_sessions();
    let (transport, _outbound_rx) = WireGuardTransport::new();
    transport.add_session("peer-a", local_session).await;
    let peers = Arc::new(PeerManager::new(
        Config::generate_default("http://127.0.0.1:1", "validation-contention").unwrap(),
    ));
    peers
        .add_peer(&PeerInfo {
            capabilities: crate::control::PeerCapabilities::default(),
            registration_seq: 0,
            node_id: "peer-a".to_string(),
            virtual_ip: "10.20.0.2".to_string(),
            online: true,
            ..PeerInfo::default()
        })
        .await;
    let udp = UdpTransport::bind("127.0.0.1:0".parse().unwrap(), peers.clone())
        .await
        .unwrap();
    let remote_socket = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let request_id = 0x7101;
    let packet = Ipv4Packet::build_icmp_echo_request(
        Ipv4Addr::new(10, 20, 0, 2),
        Ipv4Addr::new(10, 20, 0, 1),
        request_id,
        0,
        &build_direct_validation_payload(DirectValidationKind::Request, 0, request_id, 0, 19),
    );
    let (encrypted_tx, encrypted_rx) = mpsc::channel(1);
    let (inbound_tx, mut inbound_rx) = mpsc::channel(1);
    encrypted_tx
        .send(ReceivedEncryptedPacket {
            physical_ingress: None,
            source: Some(remote_socket.local_addr().unwrap()),
            local_endpoint: udp.local_addr().ok(),
            relay_endpoint: None,
            relay_connection_id: None,
            relay_peer_id: None,
            socket_index: Some(0),
            direct_socket: None,
            udp_transport_owner: None,
            network_generation: Some(0),
            profile_sampled: false,
            udp_received: None,
            transport_queue_send_started: None,
            wire_bytes: remote_session.encrypt_to_bytes(&packet).unwrap(),
        })
        .await
        .unwrap();
    drop(encrypted_tx);

    let emit_lock = transport.outbound_emit_lock("peer-a").await;
    let emit_guard = emit_lock.lock().await;
    let mut inbound = Box::pin(transport.run_inbound_with_peers(
        encrypted_rx,
        inbound_tx,
        Some(peers.clone()),
        Some(udp),
    ));
    assert!(
        futures_util::poll!(&mut inbound).is_pending(),
        "a decrypted request must wait for transient emit contention instead of being discarded"
    );
    assert!(!peers
        .get_connection("peer-a")
        .await
        .unwrap()
        .direct_events
        .iter()
        .any(|event| event.stage == "direct_validation_request_received"));

    if replace_session {
        let (_, new_local) = establish_sessions();
        let mut replacement = Box::pin(transport.add_session("peer-a", new_local));
        assert!(futures_util::poll!(&mut replacement).is_pending());
        drop(emit_guard);
        assert!(replacement.await);
    } else {
        drop(emit_guard);
    }
    tokio::time::advance(Duration::from_millis(1)).await;
    timeout(Duration::from_millis(20), inbound)
        .await
        .expect("bounded evidence wait must resolve after emit releases")
        .unwrap();
    assert!(inbound_rx.recv().await.is_none());

    let connection = peers.get_connection("peer-a").await.unwrap();
    let request_seen = connection
        .direct_events
        .iter()
        .any(|event| event.stage == "direct_validation_request_received");
    let ack_sent = connection
        .direct_events
        .iter()
        .any(|event| event.stage == "direct_validation_ack_sent");
    assert_eq!(request_seen, !replace_session);
    assert_eq!(ack_sent, !replace_session);
    assert_ne!(connection.state, ConnectionState::Direct);
    // The contention and session-fence checks above use virtual time, but
    // loopback UDP readiness is delivered by the real OS. A paused Tokio
    // clock may advance a receive timeout before that readiness is observed.
    // Resume only for the network assertion; the bounded emit-wait test
    // below still verifies the production deadline with virtual time.
    tokio::time::resume();
    let mut buffer = [0u8; 2048];
    if replace_session {
        assert!(
            matches!(remote_socket.try_recv_from(&mut buffer), Err(error) if error.kind() == std::io::ErrorKind::WouldBlock)
        );
    } else {
        let (size, _) = timeout(Duration::from_secs(1), remote_socket.recv_from(&mut buffer))
            .await
            .unwrap()
            .unwrap();
        let message = MessageTransport::from_bytes(&buffer[..size]).unwrap();
        let ack = remote_session.decrypt(&message).unwrap();
        let token = parse_direct_validation_token(&ack).unwrap();
        assert_eq!(token.kind, DirectValidationKind::Ack);
        assert_eq!(token.request_id, request_id);
        assert_eq!(token.owner_token, 19);
    }
}

#[tokio::test(start_paused = true)]
async fn direct_validation_emit_contention_preserves_first_request_ack() {
    assert_validation_request_during_emit_contention(false).await;
}

#[tokio::test(start_paused = true)]
async fn direct_validation_emit_contention_still_rejects_replaced_session() {
    assert_validation_request_during_emit_contention(true).await;
}

#[tokio::test(start_paused = true)]
async fn direct_validation_emit_contention_has_one_bounded_fence_wait() {
    let (_, local_session) = establish_sessions();
    let (transport, _outbound_rx) = WireGuardTransport::new();
    transport.add_session("peer-a", local_session).await;
    let emit_lock = transport.outbound_emit_lock("peer-a").await;
    let _emit_guard = emit_lock.lock().await;
    let mut wait = Box::pin(transport.acquire_direct_validation_session_guard("peer-a", Some(1)));
    assert!(futures_util::poll!(&mut wait).is_pending());
    tokio::time::advance(DIRECT_VALIDATION_EMIT_LOCK_TIMEOUT).await;
    assert!(matches!(
        wait.await,
        CurrentSessionEvidenceGuardOutcome::Contended
    ));
}

async fn assert_ack_transaction_fences_rekey(expire_transaction: bool) {
    let (mut remote_session, local_session) = establish_sessions();
    let (transport, _outbound_rx) = WireGuardTransport::new();
    transport.add_session("peer-a", local_session).await;
    let peers = Arc::new(PeerManager::new(
        Config::generate_default("http://127.0.0.1:1", "ack-instance-fence").unwrap(),
    ));
    let source: SocketAddr = "198.51.100.42:51820".parse().unwrap();
    peers
        .add_peer(&PeerInfo {
            node_id: "peer-a".into(),
            virtual_ip: "10.20.0.2".into(),
            endpoint: source.to_string(),
            online: true,
            ..PeerInfo::default()
        })
        .await;
    let udp = UdpTransport::bind("127.0.0.1:0".parse().unwrap(), peers.clone())
        .await
        .unwrap();
    let generation = peers.current_network_generation_sync();
    let owner = match udp
        .begin_or_merge_direct_validation("peer-a", source, generation)
        .await
    {
        crate::udp::DirectValidationSessionStart::Spawn(lease) => lease.owner_token,
        _ => panic!("fresh validation owner required"),
    };
    let request_id = 0x7192;
    let peer_session = peers.peer_session_generation_sync("peer-a").unwrap();
    let remote_epoch = peers
        .current_remote_candidate_epoch("peer-a")
        .await
        .unwrap();
    assert!(
        peers
            .mark_direct_validation_started(
                "peer-a",
                crate::peer::DirectValidationIdentity::owned(
                    crate::peer::PathEpoch::new(generation, peer_session, remote_epoch),
                    owner,
                    Some(request_id),
                    Some(source),
                ),
            )
            .await
    );
    assert!(
        udp.expect_direct_validation_ack_owned_on_socket(
            "peer-a",
            request_id,
            generation,
            owner,
            source,
            Some(0),
        )
        .await
    );
    let packet = Ipv4Packet::build_icmp_echo_request(
        Ipv4Addr::new(10, 20, 0, 2),
        Ipv4Addr::new(10, 20, 0, 1),
        request_id,
        0,
        &build_direct_validation_payload(
            DirectValidationKind::Ack,
            generation,
            request_id,
            0,
            owner,
        ),
    );
    let (encrypted_tx, encrypted_rx) = mpsc::channel(1);
    let (inbound_tx, mut inbound_rx) = mpsc::channel(1);
    encrypted_tx
        .send(ReceivedEncryptedPacket {
            physical_ingress: None,
            source: Some(source),
            local_endpoint: udp.local_addr().ok(),
            relay_endpoint: None,
            relay_connection_id: None,
            relay_peer_id: None,
            socket_index: Some(0),
            direct_socket: None,
            udp_transport_owner: None,
            network_generation: Some(generation),
            profile_sampled: false,
            udp_received: None,
            transport_queue_send_started: None,
            wire_bytes: remote_session.encrypt_to_bytes(&packet).unwrap(),
        })
        .await
        .unwrap();
    drop(encrypted_tx);

    // Park after successful decryption/current-instance acquisition and
    // before ACK consumption. No sleeps are needed to establish this race.
    let adoption = udp.lock_peer_adoption_for_direct_validation("peer-a").await;
    let mut inbound = Box::pin(transport.run_inbound_with_peers(
        encrypted_rx,
        inbound_tx,
        Some(peers.clone()),
        Some(udp.clone()),
    ));
    assert!(futures_util::poll!(&mut inbound).is_pending());
    let emit = transport.outbound_emit_lock("peer-a").await;
    assert!(
        emit.try_lock().is_err(),
        "ACK must retain its original instance fence"
    );
    let (_, new_session) = establish_sessions();
    let mut rekey = Box::pin(transport.add_session("peer-a", new_session));
    assert!(futures_util::poll!(&mut rekey).is_pending());

    if expire_transaction {
        tokio::time::advance(DIRECT_VALIDATION_EMIT_LOCK_TIMEOUT).await;
        inbound.await.unwrap();
        assert!(!peers.is_direct_sync("peer-a"));
        assert!(
            udp.has_direct_validation_expectation("peer-a").await,
            "timeout before consumption must preserve the live request"
        );
        assert!(rekey.await, "timeout must release emit for replacement");
        drop(adoption);
    } else {
        drop(adoption);
        inbound.await.unwrap();
        assert!(peers.is_direct_sync("peer-a"));
        assert!(!udp.has_direct_validation_expectation("peer-a").await);
        assert!(
            rekey.await,
            "committed path must release emit before housekeeping ends"
        );
    }
    assert!(inbound_rx.recv().await.is_none());
}

#[tokio::test(start_paused = true)]
async fn direct_validation_ack_holds_instance_until_authoritative_commit() {
    assert_ack_transaction_fences_rekey(false).await;
}

#[tokio::test(start_paused = true)]
async fn direct_validation_ack_commit_wait_is_bounded_and_releases_instance() {
    assert_ack_transaction_fences_rekey(true).await;
}
