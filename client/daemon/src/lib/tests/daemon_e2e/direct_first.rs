use super::*;

/// Check real emitted ciphertext, not only the selector's diagnostic label.
/// A warm, authenticated Relay must not steal the first application payload.
#[tokio::test]
async fn direct_first_queued_business_uses_direct_without_relay_prelude() {
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
    worker.abort();
    forwarder.abort();
    server.shutdown().await;
}
