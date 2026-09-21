use super::*;

fn direct_first_timer_peer(node_id: &str, public_key: &str) -> control::PeerInfo {
    control::PeerInfo {
        node_id: node_id.to_string(),
        device_name: String::new(),
        app_version: String::new(),
        public_key: public_key.to_string(),
        endpoint: "198.51.100.10:41000".to_string(),
        nat_type: "Unknown".to_string(),
        virtual_ip: "10.20.0.2".to_string(),
        online: true,
        last_seen: 0,
        relay_rtt_ms: None,
    }
}

#[tokio::test(start_paused = true)]
async fn direct_first_deadline_progresses_without_business_ingress() {
    let mut config = Config::generate_default("https://ctrl.test", "net1").unwrap();
    config.relay.path_policy = crate::config::PathPolicy::DirectFirst;
    let peers = Arc::new(PeerManager::new(config));
    peers
        .add_peer(&direct_first_timer_peer("node-b", "pk-b"))
        .await;
    let generation = peers.current_network_generation_sync();
    assert!(
        peers
            .confirm_relay_peer("node-b", "relay.test:443", generation)
            .await
    );
    assert_eq!(
        peers
            .committed_business_path_snapshot_sync("node-b")
            .and_then(|snapshot| snapshot.active_path()),
        None,
        "confirmed Relay must remain standby during the DirectFirst window"
    );

    let mut path_changes = peers.subscribe_committed_business_path_changes();
    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let deadline_owner = tokio::spawn(run_direct_first_deadline_loop(peers.clone(), shutdown_rx));
    tokio::task::yield_now().await;
    tokio::time::advance(crate::peer::DIRECT_FIRST_WINDOW - Duration::from_millis(1)).await;
    tokio::task::yield_now().await;
    assert_eq!(
        peers
            .committed_business_path_snapshot_sync("node-b")
            .and_then(|snapshot| snapshot.active_path()),
        None,
        "Relay was admitted before the complete DirectFirst budget elapsed"
    );

    tokio::time::advance(Duration::from_millis(1)).await;
    path_changes
        .changed()
        .await
        .expect("deadline commit must publish the active Relay path");
    assert_eq!(
        peers
            .committed_business_path_snapshot_sync("node-b")
            .and_then(|snapshot| snapshot.active_path()),
        Some(peer::NetworkPath::Relay)
    );

    shutdown_tx.send_replace(true);
    deadline_owner
        .await
        .expect("deadline owner must stop through its bounded shutdown channel");
}

#[tokio::test]
async fn retired_direct_first_deadline_cannot_release_replacement_peer() {
    let mut config = Config::generate_default("https://ctrl.test", "net1").unwrap();
    config.relay.path_policy = crate::config::PathPolicy::DirectFirst;
    let peers = PeerManager::new(config);
    peers
        .add_peer(&direct_first_timer_peer("node-b", "pk-old"))
        .await;
    let retired_deadline = peers
        .try_next_direct_first_deadline()
        .expect("connection map must be observable")
        .expect("old peer must own a DirectFirst deadline");

    peers.remove_peer("node-b").await;
    peers
        .add_peer(&direct_first_timer_peer("node-b", "pk-new"))
        .await;
    let replacement_deadline = peers
        .try_next_direct_first_deadline()
        .expect("connection map must be observable")
        .expect("replacement peer must own its own DirectFirst deadline");
    assert!(replacement_deadline > retired_deadline);
    let generation = peers.current_network_generation_sync();
    assert!(
        peers
            .confirm_relay_peer("node-b", "relay.test:443", generation)
            .await
    );

    assert_eq!(
        peers
            .try_advance_direct_first_deadlines_at(retired_deadline)
            .expect("deadline commit must not contend"),
        0,
        "a retired peer timer must be fenced from the replacement lifecycle"
    );
    assert_eq!(
        peers
            .committed_business_path_snapshot_sync("node-b")
            .and_then(|snapshot| snapshot.active_path()),
        None
    );
    assert_eq!(
        peers
            .try_advance_direct_first_deadlines_at(replacement_deadline)
            .expect("replacement deadline commit must not contend"),
        1
    );
    assert_eq!(
        peers
            .committed_business_path_snapshot_sync("node-b")
            .and_then(|snapshot| snapshot.active_path()),
        Some(peer::NetworkPath::Relay)
    );
}

/// Check real emitted ciphertext, not only the selector's diagnostic label.
/// A warm, authenticated Relay must not steal the first application payload.
#[tokio::test]
async fn direct_first_queued_business_uses_direct_without_relay_prelude() {
    run_direct_first_queued_business_case(true).await;
}

#[tokio::test]
async fn direct_first_queued_business_falls_back_only_after_its_bounded_window() {
    run_direct_first_queued_business_case(false).await;
}

async fn run_direct_first_queued_business_case(establish_direct: bool) {
    let server = p2pnet_relay::RelayServer::start_random().await.unwrap();
    let relay_endpoint = server.addr.to_string();
    let sink = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let endpoint = sink.local_addr().unwrap();
    let config = Config::generate_default("https://ctrl.test", "net1").unwrap();
    let startup = RelayStartupWait {
        relay_expected: true,
        timeout: config.relay.startup_wait_timeout(true),
    };
    let peers = Arc::new(PeerManager::new(config));
    let started = std::time::Instant::now();
    peers
        .add_peer(&control::PeerInfo {
            node_id: "node-b".to_string(),
            device_name: String::new(),
            app_version: String::new(),
            public_key: "pk".to_string(),
            endpoint: endpoint.to_string(),
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
    let (relay, _rx_a) = RelayTransport::connect(&relay_endpoint, "node-a", peers.clone())
        .await
        .unwrap();
    let (_remote_relay, mut relay_rx) =
        p2pnet_relay::RelayClient::connect(&relay_endpoint, "node-b")
            .await
            .unwrap();
    let generation = peers.current_network_generation().await;
    assert!(
        peers
            .confirm_relay_peer("node-b", &relay_endpoint, generation)
            .await
    );
    let (transport, outbound_rx, mut remote_session) = part03_outbound_transport("node-b").await;
    let (dataplane_tx, dataplane_rx) = mpsc::channel(4);
    let forwarder = tokio::spawn({
        let transport = transport.clone();
        async move { transport.run_outbound(dataplane_rx).await }
    });
    let (_relay_available_tx, relay_available_rx) = watch::channel(true);
    let (probe_tx, _probe_rx) = watch::channel(0u64);
    let worker = tokio::spawn(run_network_outbound(
        outbound_rx,
        transport,
        peers.clone(),
        true,
        Arc::new(RwLock::new(Some(udp))),
        Arc::new(RwLock::new(Some(relay))),
        relay_available_rx,
        startup,
        probe_tx,
        ConnectionTimeline::new("node-a", 0),
    ));
    let packet = Ipv4Packet::build_icmp_echo_request(
        "10.20.0.1".parse().unwrap(),
        "10.20.0.2".parse().unwrap(),
        1,
        1,
        &[1, 2, 3, 4],
    );
    dataplane_tx
        .send(OutboundPacket {
            room_authorization: None,
            trace: None,
            peer_id: "node-b".to_string(),
            dst_ip: "10.20.0.2".to_string(),
            packet: packet.clone(),
        })
        .await
        .unwrap();
    assert!(
        tokio::time::timeout(Duration::from_millis(150), relay_rx.recv())
            .await
            .is_err()
    );
    peers.record_direct_probe_success("node-b", endpoint).await;
    assert!(
        tokio::time::timeout(Duration::from_millis(150), relay_rx.recv())
            .await
            .is_err()
    );
    let mut buf = [0u8; 2048];
    assert!(
        tokio::time::timeout(Duration::from_millis(50), sink.recv_from(&mut buf))
            .await
            .is_err()
    );
    if !establish_direct {
        // Use the production timer and FIFO, not a test-only state override.
        // The configured queue lease outlives the first Direct attempt.
        let relayed = tokio::time::timeout(Duration::from_secs(7), relay_rx.recv())
            .await
            .expect("bounded Direct attempt must fall back before the queue expires")
            .expect("Relay stays connected");
        assert!(started.elapsed() >= crate::peer::DIRECT_FIRST_WINDOW);
        let RelayMessage::Data { from_node, data } = relayed else {
            panic!("expected encrypted business data, got {relayed:?}");
        };
        assert_eq!(from_node, "node-a");
        assert_eq!(remote_session.decrypt_from_bytes(&data).unwrap(), packet);
        assert_eq!(
            peers.select_path_for_data("node-b", true, true).await.path,
            Some(peer::NetworkPath::Relay)
        );
        worker.abort();
        forwarder.abort();
        let _ = worker.await;
        let _ = forwarder.await;
        server.shutdown().await;
        return;
    }
    // Inject the existing authoritative validation commit; no application
    // packet has ever arrived in the reverse direction or through Relay.
    peers.record_direct_success("node-b", Some(endpoint)).await;
    let (len, _) = tokio::time::timeout(Duration::from_secs(2), sink.recv_from(&mut buf))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        remote_session.decrypt_from_bytes(&buf[..len]).unwrap(),
        packet
    );
    assert!(
        tokio::time::timeout(Duration::from_millis(100), relay_rx.recv())
            .await
            .is_err()
    );
    assert_eq!(
        peers.select_path_for_data("node-b", true, true).await.path,
        Some(peer::NetworkPath::Direct)
    );

    // Unlike a synthetic validation/BASE ACK fixture, a real business
    // ciphertext has now left the outbound owner and been decrypted here.
    // Recovery must not replay the first-connection preference window.
    assert!(started.elapsed() < crate::peer::DIRECT_FIRST_WINDOW);
    assert!(
        peers
            .is_relay_business_admitted_for_generation("node-b", generation)
            .await
    );
    peers
        .record_direct_failure("node-b", "established Direct recovery regression")
        .await;
    assert_eq!(
        peers.select_path_for_data("node-b", true, true).await.path,
        Some(peer::NetworkPath::Relay)
    );
    let recovery_packet = Ipv4Packet::build_icmp_echo_request(
        "10.20.0.1".parse().unwrap(),
        "10.20.0.2".parse().unwrap(),
        1,
        2,
        &[5, 6, 7, 8],
    );
    dataplane_tx
        .send(OutboundPacket {
            room_authorization: None,
            trace: None,
            peer_id: "node-b".to_string(),
            dst_ip: "10.20.0.2".to_string(),
            packet: recovery_packet.clone(),
        })
        .await
        .unwrap();
    let relayed = tokio::time::timeout(Duration::from_secs(1), relay_rx.recv())
        .await
        .expect("established Direct failure must not incur a new cold-start wait")
        .expect("confirmed standby must remain connected");
    let RelayMessage::Data { from_node, data } = relayed else {
        panic!("expected encrypted recovery business data, got {relayed:?}");
    };
    assert_eq!(from_node, "node-a");
    assert_eq!(
        remote_session.decrypt_from_bytes(&data).unwrap(),
        recovery_packet
    );
    assert!(started.elapsed() < crate::peer::DIRECT_FIRST_WINDOW);
    assert!(relay_rx.try_recv().is_err());
    assert!(matches!(
        sink.try_recv_from(&mut buf),
        Err(error) if error.kind() == std::io::ErrorKind::WouldBlock
    ));
    worker.abort();
    forwarder.abort();
    let _ = worker.await;
    let _ = forwarder.await;
    server.shutdown().await;
}
