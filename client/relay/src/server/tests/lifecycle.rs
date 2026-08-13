#[tokio::test]
async fn test_real_shutdown_lifecycle() {
    let server_config = dev_config();
    let server = RelayServer::start_with_config("127.0.0.1:0", server_config)
        .await
        .unwrap();
    let addr = server.addr;

    let (client, mut rx) = RelayClient::connect_verified(&addr.to_string(), "lifecycle-node")
        .await
        .unwrap();

    client.ping().await.unwrap();
    let pong = tokio::time::timeout(Duration::from_millis(500), rx.recv())
        .await
        .unwrap()
        .unwrap();
    assert!(matches!(pong, RelayMessage::Pong { .. }));

    server.shutdown().await;

    let closed_msg = tokio::time::timeout(Duration::from_millis(500), rx.recv())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(closed_msg, RelayMessage::Closed { reason: RelayCloseReason::ServerEof });
}

/// Deterministic registration cleanup test: shares the server's peer_table directly
/// and verifies the mapping is absent after the handler task exits.
#[tokio::test]
async fn test_error_after_registration_cleanup_deterministic() {
    // Build server internals so we can inspect peer_table directly.
    let peer_table: PeerTable = Arc::new(Mutex::new(HashMap::new()));
    let (shutdown_tx, _) = tokio::sync::broadcast::channel::<()>(1);

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    // Accept loop: spawn a single client handler, then stop.
    let table_clone = peer_table.clone();
    let s_tx = shutdown_tx.clone();
    let handler_task = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        let shutdown_rx = s_tx.subscribe();
        let config = dev_config();
        handle_client(Box::new(stream), table_clone, 1, config, None, shutdown_rx).await
    });

    // --- Client side ---
    let mut stream = TcpStream::connect(addr).await.unwrap();
    stream
        .write_all(&Frame::register("errnode").encode())
        .await
        .unwrap();

    let mut buf = [0u8; 256];
    let n = stream.read(&mut buf).await.unwrap();
    let (f, _) = Frame::decode(&buf[..n]).unwrap();
    assert_eq!(f.msg_type, MSG_REGISTERED);

    // Verify the mapping is present right after registration.
    {
        let table = peer_table.lock().await;
        let key = NetworkNodeKey::new(String::new(), "errnode".to_string());
        assert!(
            table.contains_key(&key),
            "peer table must contain errnode after registration"
        );
    }

    // Send a bad-version frame to force a protocol error that tears down the handler.
    let mut bad_frame = Vec::new();
    bad_frame.extend_from_slice(&MAGIC);
    bad_frame.push(99); // bad version
    bad_frame.push(MSG_PING);
    bad_frame.extend_from_slice(&0u16.to_be_bytes());
    stream.write_all(&bad_frame).await.unwrap();

    // Read until the connection is closed (error frame + EOF).
    let total_read = tokio::time::timeout(Duration::from_secs(2), async {
        let mut total_read = 0usize;
        loop {
            match stream.read(&mut buf).await {
                Ok(0) | Err(_) => break,
                Ok(n) => total_read += n,
            }
        }
        total_read
    })
    .await
    .expect("connection did not close within 2s");
    assert!(total_read > 0, "expected at least an error frame");

    // Wait for the handler task to finish (guarantees cleanup ran).
    tokio::time::timeout(Duration::from_secs(2), handler_task)
        .await
        .expect("handler did not finish within 2s")
        .expect("handler task panicked")
        .ok();

    // The mapping must now be gone.
    {
        let table = peer_table.lock().await;
        let key = NetworkNodeKey::new(String::new(), "errnode".to_string());
        assert!(
            !table.contains_key(&key),
            "peer table must NOT contain errnode after handler exit"
        );
    }
}
