#[tokio::test]
async fn test_invalid_limits() {
    let config = RelayServerConfig {
        allow_insecure_plaintext: true,
        require_authentication: false,
        max_connections: 0,
        ..Default::default()
    };
    assert!(config.validate().is_err());
    assert!(RelayServer::start_with_config("127.0.0.1:0", config)
        .await
        .is_err());

    let client_cfg = RelayClientConfig {
        cmd_queue_capacity: 0,
        ..Default::default()
    };
    assert!(client_cfg.validate().is_err());
}

#[tokio::test]
async fn test_client_command_and_inbound_queue_bounded() {
    let server = RelayServer::start_random().await.unwrap();
    let addr = server.addr;

    let config = RelayClientConfig {
        cmd_queue_capacity: 1,
        inbound_queue_capacity: 1,
        ..Default::default()
    };

    let (_client, _rx) =
        RelayClient::connect_verified_with_config(&addr.to_string(), "client-bounded", config)
            .await
            .unwrap();
    server.shutdown().await;
}

#[tokio::test]
async fn test_server_outbound_queue_full_policy() {
    let config = RelayServerConfig {
        allow_insecure_plaintext: true,
        require_authentication: false,
        outbound_queue_capacity: 1,
        ..dev_config()
    };

    let peer_table: PeerTable = Arc::new(Mutex::new(HashMap::new()));
    let (bob_tx, _bob_rx) = mpsc::channel::<Vec<u8>>(1);
    bob_tx
        .try_send(Frame::received("existing", b"queued").unwrap().encode())
        .unwrap();
    let (bob_shutdown_tx, mut bob_shutdown_rx) = tokio::sync::oneshot::channel();
    peer_table.lock().await.insert(
        NetworkNodeKey::new(String::new(), "bob".to_string()),
        PeerConnection {
            tx: bob_tx,
            shutdown_tx: Arc::new(Mutex::new(Some(bob_shutdown_tx))),
            conn_id: 1,
        },
    );

    let (mut client_side, server_side) = tokio::io::duplex(4096);
    let (alice_tx, mut alice_rx) = mpsc::channel::<Vec<u8>>(4);
    let (shutdown_tx, _) = tokio::sync::broadcast::channel(1);
    let (_dup_shutdown_tx, dup_shutdown_rx) = tokio::sync::oneshot::channel();
    let registered_key = Some(NetworkNodeKey::new(String::new(), "alice".to_string()));
    let shutdown_rx = shutdown_tx.subscribe();

    let task = tokio::spawn(async move {
        run_read_loop(
            server_side,
            alice_tx,
            2,
            &config,
            shutdown_rx,
            dup_shutdown_rx,
            peer_table.clone(),
            "alice",
            String::new(),
            registered_key,
            None,
        )
        .await
    });

    client_side
        .write_all(&Frame::forward("bob", b"payload").unwrap().encode())
        .await
        .unwrap();

    let error_bytes = tokio::time::timeout(Duration::from_secs(1), alice_rx.recv())
        .await
        .expect("timed out waiting for backpressure error")
        .expect("alice outbound queue closed before error");
    let (error_frame, consumed) = Frame::decode(&error_bytes).unwrap();
    assert_eq!(consumed, error_bytes.len());
    assert_eq!(error_frame.msg_type, MSG_ERROR);
    let (code, message) = error_frame.parse_error().unwrap();
    assert_eq!(code, ERR_PEER_BACKPRESSURE);
    assert_eq!(message, "peer backpressure: bob");

    tokio::time::timeout(Duration::from_secs(1), &mut bob_shutdown_rx)
        .await
        .expect("timed out waiting for slow peer shutdown")
        .expect("slow peer shutdown sender dropped");

    let _ = shutdown_tx.send(());
    drop(client_side);
    let _ = tokio::time::timeout(Duration::from_secs(1), task)
        .await
        .expect("relay read loop did not shut down");
}
