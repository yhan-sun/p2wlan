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
