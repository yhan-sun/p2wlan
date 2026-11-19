use super::*;

#[tokio::test]
async fn opaque_pending_first_probe_can_complete_original_wireguard_adoption() {
    let local = NodeIdentity::generate();
    let remote = NodeIdentity::generate();
    let peers = Arc::new(PeerManager::new(config_for_identity(&local, "peer-a")));
    let control = crate::control::ControlClient::disabled_for_test();
    control.set_local_registration_for_test(Some(1), crate::control::PeerCapabilities::current());
    assert!(peers.bind_opaque_probe_registration(control));
    let mut remote_peer = peer_with_public_key(
        "peer-b",
        "10.20.0.2",
        hex::encode(remote.public_key()),
        None,
    );
    remote_peer.capabilities = crate::control::PeerCapabilities::current();
    remote_peer.registration_seq = 1;
    peers.add_peer(&remote_peer).await;
    assert_eq!(peers.opaque_probe_send_mode_for_peer("peer-b").await, None);
    assert_eq!(
        peers
            .stage_probe_session_binding(
                "peer-b",
                "initial".into(),
                Some("first-session".into()),
                Some([8; 32]),
                true
            )
            .await,
        ProbeBindingStage::Staged
    );
    let key = peers
        .probe_key_candidates_for_peer("peer-b")
        .await
        .into_iter()
        .find(|candidate| matches!(candidate.role, ProbeKeyRole::Pending { .. }))
        .unwrap()
        .key;
    let (_, local_session) = establish_sessions();
    let (wireguard, _rx) = WireGuardTransport::new();
    assert_eq!(
        wireguard
            .stage_responder_session("peer-b", "initial".into(), local_session)
            .await,
        crate::transport::ResponderSessionStage::Staged { had_active: false }
    );
    assert_eq!(
        wireguard
            .commit_responder_session("peer-b", "initial")
            .await,
        crate::transport::ResponderSessionCommit::ActivatedInitial
    );
    let udp = UdpTransport::bind("127.0.0.1:0".parse().unwrap(), peers.clone())
        .await
        .unwrap()
        .with_local_node_id("peer-a")
        .with_wireguard_transport(wireguard.clone());
    let (tx, _rx) = mpsc::channel(4);
    let worker = tokio::spawn(udp.clone().run_inbound(tx));
    let sender = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let (punch, nonce) =
        build_opaque_punch_packet_with_nomination("peer-b", "peer-a", 0, false, &key, &key);
    let scenario = async {
        sender
            .send_to(&punch, udp.local_addr().unwrap())
            .await
            .unwrap();
        let mut buffer = [0u8; 512];
        let (length, _) = sender.recv_from(&mut buffer).await.unwrap();
        let ack = decode_authenticated_punch_packet(&buffer[..length], &key).unwrap();
        assert_eq!(ack.version, OPAQUE_PUNCH_VERSION);
        assert_eq!(ack.nonce, nonce);
        while peers.probe_key_for_peer("peer-b").await != Some(key) {
            tokio::task::yield_now().await;
        }
        assert_eq!(
            peers.opaque_probe_send_mode_for_peer("peer-b").await,
            Some(true)
        );
        assert!(
            !wireguard
                .session_status("peer-b")
                .await
                .has_pending_responder
        );
    };
    let outcome = timeout(Duration::from_secs(3), scenario).await;
    worker.abort();
    let _ = worker.await;
    outcome.unwrap();
}

#[tokio::test]
async fn opaque_probe_udp_round_trip_preserves_nonce_and_rejects_stable_identity_downgrade() {
    let identity = NodeIdentity::generate();
    let remote_identity = NodeIdentity::generate();
    let peers = Arc::new(PeerManager::new(config_for_identity(&identity, "stable-a")));
    let control = crate::control::ControlClient::disabled_for_test();
    control.set_local_registration_for_test(Some(1), crate::control::PeerCapabilities::current());
    assert!(peers.bind_opaque_probe_registration(control));
    let remote = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let mut remote_peer = peer_with_public_key(
        "stable-b",
        "10.20.0.2",
        hex::encode(remote_identity.public_key()),
        Some(remote.local_addr().unwrap()),
    );
    remote_peer.capabilities = crate::control::PeerCapabilities::current();
    remote_peer.registration_seq = 1;
    peers.add_peer(&remote_peer).await;
    assert!(
        peers
            .set_probe_session_binding("stable-b", Some("opaque-session".into()), Some([3; 32]))
            .await
    );
    let key = peers.probe_key_for_peer("stable-b").await.unwrap();
    let transport = UdpTransport::bind("127.0.0.1:0".parse().unwrap(), peers.clone())
        .await
        .unwrap()
        .with_local_node_id("stable-a");
    let (tx, _rx) = mpsc::channel(4);
    let worker = tokio::spawn(transport.clone().run_inbound(tx));
    let scenario = async {
        let nonce = transport
            .send_probe_on_socket(
                0,
                transport.socket.clone(),
                Some("stable-b"),
                remote.local_addr().unwrap(),
                false,
                PendingProbePurpose::ConnectivityCheck,
            )
            .await
            .unwrap();
        let mut buffer = [0u8; 1024];
        let (length, source) = remote.recv_from(&mut buffer).await.unwrap();
        let wire = &buffer[..length];
        assert_eq!(wire[4], OPAQUE_PUNCH_VERSION);
        assert!(!wire
            .windows(8)
            .any(|bytes| bytes == b"stable-a" || bytes == b"stable-b"));
        let packet = decode_authenticated_punch_packet(wire, &key).unwrap();
        assert_eq!(packet.nonce, nonce);
        assert!(
            matches!(remote.try_recv_from(&mut [0u8; 1024]), Err(error)
            if error.kind() == std::io::ErrorKind::WouldBlock),
            "opaque mode must not send a legacy compatibility copy"
        );
        // The same authenticated key must not permit stable identity fallback.
        let downgrade = build_authenticated_punch_ack(nonce, "stable-b", "stable-a", 0, &key);
        remote.send_to(&downgrade, source).await.unwrap();
        let ack =
            build_authenticated_punch_ack_for_received(&packet, "stable-b", "stable-a", 0, &key)
                .unwrap();
        remote.send_to(&ack, source).await.unwrap();
        loop {
            let diagnostics = transport.socket_pool_diagnostics().await;
            if diagnostics[0].probe_acks_received == 1 {
                assert_eq!(diagnostics[0].authenticated_probe_acks_unmatched, 0);
                break;
            }
            tokio::task::yield_now().await;
        }
        assert!(!transport.pending_probes.lock().await.contains_key(&nonce));
    };
    let outcome = timeout(Duration::from_secs(3), scenario).await;
    worker.abort();
    let _ = worker.await;
    outcome.unwrap();
}

#[tokio::test]
async fn opaque_probe_requires_local_acceptance_and_preserves_known_legacy_peers() {
    let local = NodeIdentity::generate();
    let remote = NodeIdentity::generate();
    let peers = Arc::new(PeerManager::new(config_for_identity(&local, "stable-a")));
    let remote_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let mut remote_peer = peer_with_public_key(
        "stable-b",
        "10.20.0.2",
        hex::encode(remote.public_key()),
        Some(remote_socket.local_addr().unwrap()),
    );
    remote_peer.capabilities = crate::control::PeerCapabilities::current();
    remote_peer.registration_seq = 1;
    peers.add_peer(&remote_peer).await;
    peers
        .set_probe_session_binding("stable-b", Some("session".into()), Some([3; 32]))
        .await;
    let transport = UdpTransport::bind("127.0.0.1:0".parse().unwrap(), peers)
        .await
        .unwrap()
        .with_local_node_id("stable-a");
    assert!(transport
        .send_probe_on_socket(
            0,
            transport.socket.clone(),
            Some("stable-b"),
            remote_socket.local_addr().unwrap(),
            false,
            PendingProbePurpose::ConnectivityCheck
        )
        .await
        .is_err());
    let mut buffer = [0u8; 1024];
    assert!(
        matches!(remote_socket.try_recv_from(&mut buffer), Err(error)
        if error.kind() == std::io::ErrorKind::WouldBlock)
    );
    // A new authenticated registration that explicitly declares no opaque
    // support remains compatible with older v2 clients and control servers.
    remote_peer.capabilities = crate::control::PeerCapabilities::default();
    remote_peer.registration_seq = 2;
    transport.peers.add_peer(&remote_peer).await;
    transport
        .send_probe_on_socket(
            0,
            transport.socket.clone(),
            Some("stable-b"),
            remote_socket.local_addr().unwrap(),
            false,
            PendingProbePurpose::ConnectivityCheck,
        )
        .await
        .unwrap();
    let (length, _) = timeout(Duration::from_secs(1), remote_socket.recv_from(&mut buffer))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        peek_authenticated_punch_identity(&buffer[..length])
            .unwrap()
            .version,
        2
    );
}
