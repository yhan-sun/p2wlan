use super::*;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

fn test_config() -> Config {
    Config::generate_default("https://ctrl.test", "net1").unwrap()
}

#[test]
fn managed_register_payload_omits_stale_virtual_ip() {
    let mut config = test_config();
    config.network.manual = false;
    config.network.virtual_ip = "10.20.0.1".to_string();

    let payload = register_device_payload(&config);

    assert!(payload.get("virtual_ip").is_none());
    assert_eq!(payload["network_id"], "net1");
    assert_eq!(payload["app_version"], env!("CARGO_PKG_VERSION"));
}

#[test]
fn manual_register_payload_keeps_requested_virtual_ip() {
    let mut config = test_config();
    config.network.manual = true;
    config.network.virtual_ip = "10.20.0.44".to_string();

    let payload = register_device_payload(&config);

    assert_eq!(payload["virtual_ip"], "10.20.0.44");
}

#[test]
fn signal_websocket_url_uses_secure_scheme_and_fixed_path() {
    assert_eq!(
        signal_websocket_url("https://control.example.com/base?old=1").unwrap(),
        "wss://control.example.com/api/v1/signals/ws"
    );
    assert_eq!(
        signal_websocket_url("http://127.0.0.1:18080").unwrap(),
        "ws://127.0.0.1:18080/api/v1/signals/ws"
    );
    assert!(signal_websocket_url("ftp://control.example.com").is_err());
}

#[tokio::test]
#[allow(clippy::result_large_err)]
async fn signal_websocket_authenticates_negotiates_and_wakes() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let (shutdown_tx, shutdown_rx) = oneshot::channel::<()>();
    let server = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        let mut socket = tokio_tungstenite::accept_hdr_async(
                stream,
                |request: &tokio_tungstenite::tungstenite::handshake::server::Request,
                 mut response: tokio_tungstenite::tungstenite::handshake::server::Response| {
                    assert_eq!(
                        request
                            .headers()
                            .get(AUTHORIZATION)
                            .and_then(|value| value.to_str().ok()),
                        Some("Bearer dc-test-token")
                    );
                    assert_eq!(
                        request
                            .headers()
                            .get(SEC_WEBSOCKET_PROTOCOL)
                            .and_then(|value| value.to_str().ok()),
                        Some(SIGNAL_WS_PROTOCOL)
                    );
                    response.headers_mut().insert(
                        SEC_WEBSOCKET_PROTOCOL,
                        HeaderValue::from_static(SIGNAL_WS_PROTOCOL),
                    );
                    Ok(response)
                },
            )
            .await
            .unwrap();
        socket
            .send(WebSocketMessage::Text(
                serde_json::json!({
                    "type": "ready",
                    "protocol_version": 1,
                    "node_id": "node-a",
                    "network_id": "network-a",
                    "server_time_ms": 1000
                })
                .to_string()
                .into(),
            ))
            .await
            .unwrap();
        socket
            .send(WebSocketMessage::Text(
                serde_json::json!({
                    "type": "signals_available",
                    "protocol_version": 1,
                    "sequence": 1,
                    "server_time_ms": 1001
                })
                .to_string()
                .into(),
            ))
            .await
            .unwrap();
        let _ = shutdown_rx.await;
        let _ = socket.close(None).await;
    });

    let (wake_tx, mut wake_rx) = mpsc::channel(4);
    let connected = Arc::new(AtomicBool::new(false));
    let client_connected = connected.clone();
    let base_url = format!("http://{address}");
    let client = tokio::spawn(async move {
        run_signal_websocket(
            &base_url,
            "dc-test-token",
            "node-a",
            "network-a",
            wake_tx,
            client_connected,
        )
        .await;
    });

    time::timeout(Duration::from_secs(2), wake_rx.recv())
        .await
        .unwrap()
        .unwrap();
    time::timeout(Duration::from_secs(2), wake_rx.recv())
        .await
        .unwrap()
        .unwrap();
    assert!(connected.load(Ordering::Acquire));

    let _ = shutdown_tx.send(());
    client.abort();
    server.await.unwrap();
}

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

#[test]
fn test_control_message_serialization() {
    let msg = ControlMessage::Register {
        node_id: "node123".to_string(),
        public_key: "pubkey".to_string(),
        device_name: "my-laptop".to_string(),
        platform: "windows".to_string(),
        network_id: "net1".to_string(),
    };

    let json = serde_json::to_string(&msg).unwrap();
    let decoded: ControlMessage = serde_json::from_str(&json).unwrap();

    if let ControlMessage::Register { node_id, .. } = decoded {
        assert_eq!(node_id, "node123");
    } else {
        panic!("Expected Register message");
    }
}

#[test]
fn test_peer_offer_serialization() {
    let msg = ControlMessage::PeerOffer {
        from_node_id: "alice".to_string(),
        to_node_id: "bob".to_string(),
        candidates: vec!["10.0.0.1:5000".to_string()],
        session_id: Some("sess-test".to_string()),
        probe_ephemeral_public_key: Some(
            "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f".to_string(),
        ),
        probe_ephemeral_signature: None,
        candidate_sources: HashMap::new(),
        candidate_generation: 7,
        candidates_expires_at_ms: Some(42_000),
        handshake_init: vec![0x01, 0x02],
        punch_at_ms: Some(1234),
    };

    let json = serde_json::to_string(&msg).unwrap();
    let decoded: ControlMessage = serde_json::from_str(&json).unwrap();
    assert!(matches!(decoded, ControlMessage::PeerOffer { .. }));
}

#[test]
fn test_peer_reflexive_serialization() {
    let msg = ControlMessage::PeerReflexive {
        from_node_id: "alice".to_string(),
        to_node_id: "bob".to_string(),
        observed_endpoint: "203.0.113.10:51820".to_string(),
        punch_at_ms: Some(42_000),
    };

    let json = serde_json::to_string(&msg).unwrap();
    assert!(json.contains("\"type\":\"peer_reflexive\""));
    assert!(json.contains("\"observed_endpoint\":\"203.0.113.10:51820\""));

    let decoded: ControlMessage = serde_json::from_str(&json).unwrap();
    match decoded {
        ControlMessage::PeerReflexive {
            from_node_id,
            to_node_id,
            observed_endpoint,
            punch_at_ms,
        } => {
            assert_eq!(from_node_id, "alice");
            assert_eq!(to_node_id, "bob");
            assert_eq!(observed_endpoint, "203.0.113.10:51820");
            assert_eq!(punch_at_ms, Some(42_000));
        }
        other => panic!("expected PeerReflexive, got {other:?}"),
    }
}

#[test]
fn rest_signal_response_defaults_to_v1_for_legacy_servers() {
    let signal: SignalResponse = serde_json::from_str(
        r#"{
                "from_node_id": "alice",
                "type": "peer_offer",
                "candidates": ["203.0.113.10:51820"]
            }"#,
    )
    .unwrap();

    assert_eq!(signal.protocol_version, SIGNAL_REST_PROTOCOL_VERSION);
}

#[test]
fn test_peer_reflexive_endpoint_prefers_tagged_candidate() {
    let signal = SignalResponse {
        from_node_id: "alice".to_string(),
        signal_type: "peer_reflexive".to_string(),
        protocol_version: SIGNAL_REST_PROTOCOL_VERSION,
        candidates: vec![
            "198.51.100.1:40000".to_string(),
            "203.0.113.10:51820".to_string(),
        ],
        session_id: None,
        probe_ephemeral_public_key: None,
        candidate_sources: HashMap::from([
            (
                "198.51.100.1:40000".to_string(),
                "stun_observed".to_string(),
            ),
            (
                "203.0.113.10:51820".to_string(),
                "peer_reflexive".to_string(),
            ),
        ]),
        candidate_generation: 0,
        candidates_expires_at_ms: None,
        handshake: String::new(),
        punch_at_ms: Some(77),
    };

    assert_eq!(
        peer_reflexive_endpoint_from_signal(&signal),
        Some("203.0.113.10:51820".to_string())
    );
}

#[test]
fn test_peer_reflexive_endpoint_falls_back_to_first_candidate() {
    let signal = SignalResponse {
        from_node_id: "alice".to_string(),
        signal_type: "peer_reflexive".to_string(),
        protocol_version: SIGNAL_REST_PROTOCOL_VERSION,
        candidates: vec!["198.51.100.1:40000".to_string()],
        session_id: None,
        probe_ephemeral_public_key: None,
        candidate_sources: HashMap::new(),
        candidate_generation: 0,
        candidates_expires_at_ms: None,
        handshake: String::new(),
        punch_at_ms: None,
    };

    assert_eq!(
        peer_reflexive_endpoint_from_signal(&signal),
        Some("198.51.100.1:40000".to_string())
    );
}

#[test]
fn signal_punch_time_uses_server_clock_offset() {
    assert_eq!(
        normalize_signal_punch_at(Some(11_500), Some(10_000), 50_000),
        Some(51_500)
    );
    assert_eq!(
        normalize_signal_punch_at(Some(9_000), Some(10_000), 50_000),
        Some(50_000)
    );
    assert_eq!(
        normalize_signal_punch_at(Some(11_500), None, 50_000),
        Some(11_500)
    );
    assert_eq!(normalize_signal_punch_at(None, Some(10_000), 50_000), None);
}

#[test]
fn candidate_expiry_uses_the_server_clock_offset() {
    assert_eq!(
        normalize_signal_candidate_expiry(Some(55_000), Some(10_000), 80_000),
        Some(125_000)
    );
    assert_eq!(
        normalize_signal_candidate_expiry(Some(9_000), Some(10_000), 80_000),
        Some(80_000)
    );
    assert_eq!(
        normalize_signal_candidate_expiry(Some(55_000), None, 80_000),
        Some(55_000)
    );
}

#[test]
fn candidate_generations_are_strictly_monotonic() {
    let first = next_candidate_generation();
    let second = next_candidate_generation();
    assert!(second > first);
}

#[test]
fn test_control_client_creation() {
    let config = test_config();
    let (client, _rx) = ControlClient::new(&config, true, None, None);
    // Client created successfully, no events yet
    drop(client);
}

#[test]
fn test_control_client_creation_disabled() {
    let mut config = test_config();
    config.control.auth_token = "test-token".to_string();
    // When disabled, no background control loop is spawned
    let (client, _rx) = ControlClient::new(&config, false, None, None);
    drop(client);
}

#[test]
fn control_credential_accepts_device_credential_only() {
    let mut config = test_config();
    config.control.auth_token.clear();
    config.control.device_credential = "device-token".to_string();
    assert!(has_control_credential(&config));

    config.control.device_credential.clear();
    assert!(!has_control_credential(&config));
}

/// Regression: with token + unreachable control, disabled mode must not
/// emit ServerError/Disconnected (which would otherwise shut down the daemon).
#[tokio::test]
async fn test_control_client_disabled_emits_no_events() {
    let mut config = test_config();
    config.control.auth_token = "test-token".to_string();
    config.control.server_url = "http://127.0.0.1:1".to_string(); // unreachable

    let (client, mut rx) = ControlClient::new(&config, false, None, None);

    // Give any accidental background task a moment to fire events.
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    assert!(
        rx.try_recv().is_err(),
        "disabled ControlClient must not emit control events"
    );
    drop(client);
}

#[tokio::test]
async fn test_control_client_handle_registered() {
    let config = test_config();
    let (client, mut rx) = ControlClient::new(&config, true, None, None);

    client
        .handle_message(ControlMessage::Registered {
            virtual_ip: "10.20.0.5".to_string(),
            relay_servers: vec!["relay1:8080".to_string()],
        })
        .await;

    assert_eq!(client.virtual_ip().await, Some("10.20.0.5".to_string()));

    let event = rx.recv().await.unwrap();
    if let ControlEvent::Registered {
        node_id,
        virtual_ip,
        cidr: _,
        relay_servers,
        relay_catalog: _,
    } = event
    {
        assert_eq!(node_id, None);
        assert_eq!(virtual_ip, "10.20.0.5");
        assert_eq!(relay_servers.len(), 1);
    } else {
        panic!("Expected Registered event");
    }
}

#[tokio::test]
async fn test_control_client_handle_peer_join_leave() {
    let config = test_config();
    let (client, _rx) = ControlClient::new(&config, true, None, None);

    client
        .handle_message(ControlMessage::PeerJoin {
            node_id: "peer1".to_string(),
            public_key: "pk1".to_string(),
            endpoint: "1.2.3.4:5000".to_string(),
            nat_type: "FullCone".to_string(),
            virtual_ip: "10.20.0.2".to_string(),
        })
        .await;

    let peers = client.peers().await;
    assert!(peers.contains_key("peer1"));

    client
        .handle_message(ControlMessage::PeerLeave {
            node_id: "peer1".to_string(),
        })
        .await;

    let peers = client.peers().await;
    assert!(!peers.contains_key("peer1"));
}

#[test]
fn test_heartbeat_message() {
    let msg = ControlMessage::Heartbeat {
        node_id: "node1".to_string(),
        timestamp: 12345,
    };
    let json = serde_json::to_string(&msg).unwrap();
    assert!(json.contains("heartbeat"));
}

#[test]
fn test_peer_info_default() {
    let info = PeerInfo::default();
    assert!(info.node_id.is_empty());
    assert!(!info.online);
}
