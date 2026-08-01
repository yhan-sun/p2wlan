#[tokio::test]
async fn test_client_config_invalid() {
    let config = RelayClientConfig {
        idle_timeout: Duration::from_secs(5),
        keepalive_interval: Duration::from_secs(10),
        ..Default::default()
    };
    assert!(config.validate().is_err());

    let config2 = RelayClientConfig {
        keepalive_interval: Duration::ZERO,
        ..Default::default()
    };
    assert!(config2.validate().is_err());
}

/// Verify that a silent server (never responds to pings) triggers idle timeout and
/// the client delivers Error{4009} + Closed.
#[tokio::test]
async fn test_client_idle_timeout() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut buf = [0u8; 1024];
        let n = stream.read(&mut buf).await.unwrap();
        let (f, _) = Frame::decode(&buf[..n]).unwrap();
        assert_eq!(f.msg_type, MSG_REGISTER);
        // Reply with Registered, then go silent — never respond to Ping.
        stream
            .write_all(&Frame::registered("client-idle").encode())
            .await
            .unwrap();
        tokio::time::sleep(Duration::from_millis(500)).await;
    });

    let config = RelayClientConfig {
        idle_timeout: Duration::from_millis(100),
        keepalive_interval: Duration::from_millis(40),
        ..Default::default()
    };
    let (_client, mut rx) =
        RelayClient::connect_verified_with_config(&addr.to_string(), "client-idle", config)
            .await
            .unwrap();

    let msg1 = tokio::time::timeout(Duration::from_millis(400), rx.recv())
        .await
        .expect("timed out waiting for idle-timeout error")
        .expect("channel closed unexpectedly");
    assert_eq!(
        msg1,
        RelayMessage::Error {
            code: 4009,
            message: "idle timeout".to_string()
        }
    );

    let msg2 = tokio::time::timeout(Duration::from_millis(400), rx.recv())
        .await
        .expect("timed out waiting for Closed")
        .expect("channel closed unexpectedly");
    assert_eq!(msg2, RelayMessage::Closed);
}

/// Verify that a working relay server (responds with Pong) does NOT trigger idle
/// timeout even when the client's idle_timeout is short.
#[tokio::test]
async fn test_keepalive_prevents_idle_timeout() {
    let server = RelayServer::start_random().await.unwrap();
    let addr = server.addr;

    // idle_timeout=200ms, keepalive_interval=60ms — pings arrive well within timeout.
    let config = RelayClientConfig {
        idle_timeout: Duration::from_millis(200),
        keepalive_interval: Duration::from_millis(60),
        ..Default::default()
    };
    let (_client, mut rx) =
        RelayClient::connect_verified_with_config(&addr.to_string(), "keepalive-node", config)
            .await
            .unwrap();

    // Over ~400ms (several keepalive cycles) we should receive only Pong messages,
    // no Error{4009} or Closed.
    let deadline = tokio::time::Instant::now() + Duration::from_millis(400);
    let mut pong_count = 0usize;
    loop {
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        if remaining.is_zero() {
            break;
        }
        match tokio::time::timeout(remaining, rx.recv()).await {
            Ok(Some(RelayMessage::Pong { .. })) => {
                pong_count += 1;
            }
            Ok(Some(RelayMessage::Error { code, message })) => {
                panic!("unexpected error during keepalive: code={code}, msg={message}");
            }
            Ok(Some(RelayMessage::Closed)) => {
                panic!("connection closed unexpectedly during keepalive test");
            }
            Ok(Some(other)) => {
                panic!("unexpected message: {other:?}");
            }
            Ok(None) | Err(_) => break,
        }
    }

    assert!(
        pong_count >= 2,
        "expected at least 2 Pong responses during keepalive window, got {pong_count}"
    );
    server.shutdown().await;
}
