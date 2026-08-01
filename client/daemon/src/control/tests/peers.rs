#[tokio::test]
async fn poll_peers_preserves_offline_devices_from_control_plane() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut request = [0u8; 2048];
        let _ = stream.read(&mut request).await.unwrap();
        let body = r#"{"nodes":[{"id":"peer-offline","device_name":"Travel Laptop","public_key":"peer-public-key","app_version":"0.1.68","endpoint":"","nat_type":"Unknown","virtual_ip":"10.20.0.9","online":false,"last_seen":1785320000}]}"#;
        let response = format!(
                "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{}",
                body.len(),
                body
            );
        stream.write_all(response.as_bytes()).await.unwrap();
    });

    let config = test_config();
    let state = Arc::new(RwLock::new(ClientState {
        registered: true,
        peers: HashMap::new(),
        virtual_ip: Some("10.20.0.2".to_string()),
        _relay_servers: Vec::new(),
    }));
    let (event_tx, mut event_rx) = mpsc::unbounded_channel();

    poll_peers(
        &reqwest::Client::new(),
        &format!("http://{address}"),
        "test-token",
        &config,
        "self-node",
        &state,
        &event_tx,
    )
    .await
    .unwrap();

    let peers = state.read().await.peers.clone();
    let peer = peers.get("peer-offline").unwrap();
    assert!(!peer.online);
    assert_eq!(peer.last_seen, 1_785_320_000);
    assert_eq!(peer.device_name, "Travel Laptop");
    assert_eq!(peer.app_version, "0.1.68");

    match event_rx.try_recv().unwrap() {
        ControlEvent::PeerJoined(peer) => {
            assert_eq!(peer.node_id, "peer-offline");
            assert_eq!(peer.app_version, "0.1.68");
            assert!(!peer.online);
        }
        event => panic!("expected offline peer join event, got {event:?}"),
    }

    server.await.unwrap();
}

#[test]
fn peer_endpoint_change_is_reported_as_metadata_update() {
    let known = PeerInfo {
        node_id: "peer-a".to_string(),
        device_name: "peer".to_string(),
        app_version: String::new(),
        public_key: "key".to_string(),
        endpoint: "192.168.1.10:5000".to_string(),
        nat_type: "unknown".to_string(),
        virtual_ip: "10.20.0.2".to_string(),
        online: true,
        last_seen: 1,
        relay_rtt_ms: None,
    };
    let mut updated = known.clone();
    updated.endpoint = "203.0.113.10:62000".to_string();
    updated.last_seen = 2;

    assert!(peer_metadata_changed(&known, &updated));

    updated.endpoint = known.endpoint.clone();
    assert!(!peer_metadata_changed(&known, &updated));

    updated.app_version = "0.1.68".to_string();
    assert!(peer_metadata_changed(&known, &updated));
}
