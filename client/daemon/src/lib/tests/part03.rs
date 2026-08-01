#[tokio::test]
async fn relay_supervisor_reconnects_after_stream_closes() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let endpoint = listener.local_addr().unwrap().to_string();
    let (reconnected_tx, mut reconnected_rx) = mpsc::channel(1);
    let server = tokio::spawn(async move {
        let first = accept_relay_registration(&listener, "node-a").await;
        drop(first);

        let _second = accept_relay_registration(&listener, "node-a").await;
        reconnected_tx.send(()).await.unwrap();
        std::future::pending::<()>().await;
    });

    let config = Config::generate_default("https://ctrl.test", "net1").unwrap();
    let peers = Arc::new(PeerManager::new(config));
    let relay_transport = Arc::new(RwLock::new(None));
    let relay_selection = Arc::new(RwLock::new(RelaySelectionDiagnostics::default()));
    let (inbound_tx, _inbound_rx) = mpsc::channel(4);
    let supervisor = tokio::spawn(
        RelaySupervisor {
            relay_candidates: vec![RelayCandidateConfig::legacy(endpoint)],
            preferred_regions: Vec::new(),
            selection_timeout: Duration::from_millis(500),
            node_id: "node-a".to_string(),
            peers,
            relay_transport: relay_transport.clone(),
            relay_selection: relay_selection.clone(),
            inbound_tx,
            ticket_cache: None,
            relay_ticket: None,
            allow_insecure_plaintext: true, // test
            ca_cert_path: None,
        }
        .run(),
    );

    tokio::time::timeout(Duration::from_secs(4), reconnected_rx.recv())
        .await
        .expect("relay supervisor did not reconnect")
        .expect("relay test server stopped");
    tokio::time::timeout(Duration::from_secs(1), async {
        while relay_transport.read().await.is_none() {
            sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("reconnected relay was not published");
    assert!(relay_selection.read().await.last_error.is_none());

    supervisor.abort();
    server.abort();
}

#[tokio::test]
async fn relay_supervisor_fails_over_to_standby_after_runtime_disconnect() {
    let primary = RelayServer::start_random().await.unwrap();
    let standby = RelayServer::start_random().await.unwrap();
    let primary_endpoint = primary.addr.to_string();
    let standby_endpoint = standby.addr.to_string();

    let config = Config::generate_default("https://ctrl.test", "net1").unwrap();
    let peers = Arc::new(PeerManager::new(config));
    let relay_transport = Arc::new(RwLock::new(None));
    let relay_selection = Arc::new(RwLock::new(RelaySelectionDiagnostics::default()));
    let (inbound_tx, _inbound_rx) = mpsc::channel(4);
    let supervisor = tokio::spawn(
        RelaySupervisor {
            relay_candidates: vec![
                RelayCandidateConfig::legacy(format!("primary@{primary_endpoint}")),
                RelayCandidateConfig::legacy(format!("standby@{standby_endpoint}")),
            ],
            preferred_regions: vec!["primary".to_string()],
            selection_timeout: Duration::from_millis(500),
            node_id: "node-a".to_string(),
            peers,
            relay_transport: relay_transport.clone(),
            relay_selection: relay_selection.clone(),
            inbound_tx,
            ticket_cache: None,
            relay_ticket: None,
            allow_insecure_plaintext: true,
            ca_cert_path: None,
        }
        .run(),
    );

    wait_for_relay_endpoint(relay_transport.clone(), &primary_endpoint).await;
    primary.shutdown().await;
    wait_for_relay_endpoint(relay_transport, &standby_endpoint).await;

    let diagnostics = relay_selection.read().await.clone();
    assert_eq!(
        diagnostics.selected_endpoint.as_deref(),
        Some(standby_endpoint.as_str())
    );
    let primary_candidate = diagnostics
        .candidates
        .iter()
        .find(|candidate| candidate.endpoint == primary_endpoint)
        .expect("primary relay candidate should remain in diagnostics");
    assert_eq!(
        primary_candidate.error_code.as_deref(),
        Some("cooling_down")
    );
    assert!(primary_candidate.cooldown_remaining_ms.is_some());

    supervisor.abort();
    standby.shutdown().await;
}

#[test]
fn test_infer_default_relay_servers_skips_local_and_test_hosts() {
    assert!(infer_default_relay_servers("http://127.0.0.1:18080").is_empty());
    assert!(infer_default_relay_servers("http://localhost:18080").is_empty());
    assert!(infer_default_relay_servers("https://ctrl.test").is_empty());
}

#[tokio::test]
async fn test_parse_stun_servers() {
    let servers = parse_stun_servers(
        &["127.0.0.1:3478".to_string(), " 10.0.0.1:3478 ".to_string()],
        Duration::from_millis(100),
    )
    .await
    .unwrap();
    assert_eq!(servers.len(), 2);
    assert_eq!(servers[0], "127.0.0.1:3478".parse().unwrap());
    assert_eq!(servers[1], "10.0.0.1:3478".parse().unwrap());
}

#[tokio::test]
async fn test_parse_stun_servers_resolves_hostname() {
    let servers = parse_stun_servers(&["localhost:3478".to_string()], Duration::from_secs(1))
        .await
        .unwrap();
    assert!(servers
        .iter()
        .any(|server| server.ip().is_loopback() && server.port() == 3478));
}

#[tokio::test]
async fn test_parse_stun_servers_can_be_disabled() {
    assert!(
        parse_stun_servers(&["off".to_string()], Duration::from_millis(100))
            .await
            .unwrap()
            .is_empty()
    );
}

#[tokio::test]
async fn test_parse_stun_servers_rejects_invalid_endpoint() {
    let err = parse_stun_servers(&["not-a-socket".to_string()], Duration::from_millis(100))
        .await
        .unwrap_err();
    assert!(err
        .to_string()
        .contains("invalid or unresolved STUN server"));
}

#[test]
fn maintenance_offer_cancellation_keeps_rekey_initiation_alive() {
    assert!(should_cancel_maintenance_offer(false, true, false, false));
    assert!(!should_cancel_maintenance_offer(false, false, false, false));
    assert!(!should_cancel_maintenance_offer(true, true, true, false));
    assert!(!should_cancel_maintenance_offer(true, true, false, true));
    assert!(!should_cancel_maintenance_offer(true, false, false, false));
    assert!(should_cancel_maintenance_offer(true, true, false, false));
}

#[tokio::test]
async fn stale_wireguard_answer_does_not_clear_pending_handshake() {
    let config = Config::generate_default("https://ctrl.test", "net1").unwrap();
    let mut daemon = Daemon::new(config);
    let peer_id = "peer-stale-answer";

    let peer_identity = NodeIdentity::generate();
    let mut initiator = HandshakeInitiator::new(
        daemon.local_identity().unwrap(),
        peer_identity.public_key(),
        None,
    );
    let initiation = initiator.create_initiation().unwrap();

    {
        let mut state = daemon.pending_handshakes.lock().await;
        state.insert(peer_id.to_string(), initiator, None, None);
        state.attempts.insert(peer_id.to_string(), 1);
    }

    let mut responder = HandshakeResponder::new(peer_identity, None);
    let (mut stale_response, _) = responder
        .consume_initiation_and_respond(&initiation)
        .unwrap();
    stale_response.receiver_index ^= 0x1111_0001;

    daemon
        .handle_peer_answer(peer_id, &stale_response.to_bytes(), None, None)
        .await
        .unwrap();

    let state = daemon.pending_handshakes.lock().await;
    assert!(state.pending.contains_key(peer_id));
    assert_eq!(state.attempts.get(peer_id), Some(&1));
}

#[test]
fn handshake_start_reservation_prevents_concurrent_initiators() {
    let mut state = PendingHandshakeState::default();
    let peer_id = "peer-race";

    assert!(state.reserve_start(peer_id));
    assert!(state.starting.contains(peer_id));
    assert!(
        !state.reserve_start(peer_id),
        "a second trigger must not start an initiator while the first gathers candidates"
    );

    state.cancel_reservation(peer_id);
    assert!(state.reserve_start(peer_id));
}

#[tokio::test]
async fn test_network_outbound_uses_relay_when_udp_unavailable() {
    let server = p2pnet_relay::RelayServer::start_random().await.unwrap();
    let relay_endpoint = server.addr.to_string();

    let peers = Arc::new(PeerManager::new(
        Config::generate_default("https://ctrl.test", "net1").unwrap(),
    ));
    peers
        .add_peer(&control::PeerInfo {
            node_id: "node-b".to_string(),
            device_name: String::new(),
            app_version: String::new(),
            public_key: "pk".to_string(),
            endpoint: String::new(),
            nat_type: "Unknown".to_string(),
            virtual_ip: "10.20.0.2".to_string(),
            online: true,
            last_seen: 0,
            relay_rtt_ms: None,
        })
        .await;

    let (relay_a, _rx_a) = RelayTransport::connect(&relay_endpoint, "node-a", peers.clone())
        .await
        .unwrap();
    let (_relay_b, mut rx_b) = p2pnet_relay::RelayClient::connect(&relay_endpoint, "node-b")
        .await
        .unwrap();

    let udp_transport = Arc::new(RwLock::new(None));
    let relay_transport = Arc::new(RwLock::new(Some(relay_a)));
    let (encrypted_tx, encrypted_rx) = mpsc::channel(4);
    let worker = tokio::spawn(run_network_outbound(
        encrypted_rx,
        peers,
        true,
        udp_transport,
        relay_transport,
    ));

    let payload = vec![4, 9, 8, 7, 6];
    encrypted_tx
        .send(EncryptedPeerPacket {
            peer_id: "node-b".to_string(),
            dst_ip: "10.20.0.2".to_string(),
            wire_bytes: payload.clone(),
        })
        .await
        .unwrap();

    let received = tokio::time::timeout(Duration::from_secs(2), rx_b.recv())
        .await
        .unwrap()
        .unwrap();
    if let RelayMessage::Data { from_node, data } = received {
        assert_eq!(from_node, "node-a");
        assert_eq!(data, payload);
    } else {
        panic!("Expected Data message, got {:?}", received);
    }

    worker.abort();
    server.shutdown().await;
}

#[tokio::test]
async fn test_network_outbound_uses_relay_until_direct_is_verified() {
    let server = p2pnet_relay::RelayServer::start_random().await.unwrap();
    let relay_endpoint = server.addr.to_string();
    let direct_sink = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let direct_endpoint = direct_sink.local_addr().unwrap();

    let peers = Arc::new(PeerManager::new(
        Config::generate_default("https://ctrl.test", "net1").unwrap(),
    ));
    peers
        .add_peer(&control::PeerInfo {
            node_id: "node-b".to_string(),
            device_name: String::new(),
            app_version: String::new(),
            public_key: "pk".to_string(),
            endpoint: direct_endpoint.to_string(),
            nat_type: "Unknown".to_string(),
            virtual_ip: "10.20.0.2".to_string(),
            online: true,
            last_seen: 0,
            relay_rtt_ms: None,
        })
        .await;

    let udp = UdpTransport::bind("127.0.0.1:0".parse().unwrap(), peers.clone())
        .await
        .unwrap();
    let (relay_a, _rx_a) = RelayTransport::connect(&relay_endpoint, "node-a", peers.clone())
        .await
        .unwrap();
    let (_relay_b, mut rx_b) = p2pnet_relay::RelayClient::connect(&relay_endpoint, "node-b")
        .await
        .unwrap();

    let udp_transport = Arc::new(RwLock::new(Some(udp)));
    let relay_transport = Arc::new(RwLock::new(Some(relay_a)));
    let (encrypted_tx, encrypted_rx) = mpsc::channel(4);
    let worker = tokio::spawn(run_network_outbound(
        encrypted_rx,
        peers.clone(),
        true,
        udp_transport,
        relay_transport,
    ));

    let payload = vec![9, 8, 7, 6, 5];
    encrypted_tx
        .send(EncryptedPeerPacket {
            peer_id: "node-b".to_string(),
            dst_ip: "10.20.0.2".to_string(),
            wire_bytes: payload.clone(),
        })
        .await
        .unwrap();

    let received = tokio::time::timeout(Duration::from_secs(2), rx_b.recv())
        .await
        .unwrap()
        .unwrap();
    if let RelayMessage::Data { from_node, data } = received {
        assert_eq!(from_node, "node-a");
        assert_eq!(data, payload);
    } else {
        panic!("Expected Data message, got {:?}", received);
    }

    let mut buf = [0u8; 64];
    assert!(
        tokio::time::timeout(Duration::from_millis(100), direct_sink.recv_from(&mut buf))
            .await
            .is_err()
    );

    let conn = peers.get_connection("node-b").await.unwrap();
    assert_eq!(conn.state, ConnectionState::Idle);
    assert_eq!(conn.active_path(), None);
    assert_eq!(conn.relay_server, Some(relay_endpoint));
    let selection = peers.select_path_for_data("node-b", true, true).await;
    assert_eq!(selection.path, Some(peer::NetworkPath::Relay));

    worker.abort();
    server.shutdown().await;
}

#[tokio::test]
async fn test_daemon_acl_check() {
    let config = Config::generate_default("https://ctrl.test", "net1").unwrap();
    let daemon = Daemon::new(config);

    // Default ACL allows everything
    assert!(daemon.check_acl("node1", "node2", "tcp", 80).await);
}

#[tokio::test]
async fn test_daemon_dns() {
    let mut config = Config::generate_default("https://ctrl.test", "net1").unwrap();
    config.dns.enabled = true;
    let daemon = Daemon::new(config);

    daemon
        .dns()
        .register("test", "10.20.0.5", Some("node1"))
        .await;
    let ip = daemon.dns().resolve("test").await;
    assert_eq!(ip, Some("10.20.0.5".to_string()));
}

#[tokio::test]
async fn test_daemon_port_mapping() {
    let config = Config::generate_default("https://ctrl.test", "net1").unwrap();
    let daemon = Daemon::new(config);

    let mapping =
        port_mapping::PortMapping::new(port_mapping::Protocol::Tcp, "127.0.0.1", 8080, 30000);
    daemon.port_mappings().create(mapping).await.unwrap();
    let list = daemon.port_mappings().list().await;
    assert_eq!(list.len(), 1);
}
