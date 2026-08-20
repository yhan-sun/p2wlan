#[tokio::test]
async fn test_register_timeout() {
    let server_config = RelayServerConfig {
        allow_insecure_plaintext: true,
        require_authentication: false,
        register_timeout: Duration::from_millis(100),
        ..Default::default()
    };
    let server = RelayServer::start_with_config("127.0.0.1:0", server_config)
        .await
        .unwrap();
    let addr = server.addr;

    let mut stream = TcpStream::connect(addr).await.unwrap();
    tokio::time::sleep(Duration::from_millis(200)).await;
    let mut buf = [0u8; 1024];
    let n = stream.read(&mut buf).await.unwrap();
    assert!(n > 0);
    let frame = Frame::decode(&buf[..n]);
    if let Ok((f, _)) = frame {
        assert_eq!(f.msg_type, MSG_ERROR);
        let (code, _) = f.parse_error().unwrap();
        assert_eq!(code, ERR_REGISTRATION_TIMEOUT);
    }
    server.shutdown().await;
}

#[tokio::test]
async fn test_idle_timeout() {
    let server_config = RelayServerConfig {
        allow_insecure_plaintext: true,
        require_authentication: false,
        // Keep enough wall-clock margin for the test process when the relay
        // crate runs alongside the daemon integration tests. The production
        // timeout is still short; this avoids asserting on a 150ms scheduler
        // window rather than on the idle-timeout behavior itself.
        idle_timeout: Duration::from_millis(300),
        ..Default::default()
    };
    let server = RelayServer::start_with_config("127.0.0.1:0", server_config)
        .await
        .unwrap();
    let addr = server.addr;

    let (_client, mut rx) = RelayClient::connect_verified(&addr.to_string(), "client-idle")
        .await
        .unwrap();
    tokio::time::sleep(Duration::from_millis(500)).await;
    let msg = tokio::time::timeout(Duration::from_millis(500), rx.recv())
        .await
        .unwrap()
        .unwrap();
    assert!(matches!(msg, RelayMessage::Error { code: 4009, .. }));
    server.shutdown().await;
}

#[tokio::test]
async fn test_max_connections() {
    let server_config = RelayServerConfig {
        allow_insecure_plaintext: true,
        require_authentication: false,
        max_connections: 1,
        ..Default::default()
    };
    let server = RelayServer::start_with_config("127.0.0.1:0", server_config)
        .await
        .unwrap();
    let addr = server.addr;

    let (_client1, _rx1) = RelayClient::connect_verified(&addr.to_string(), "c1")
        .await
        .unwrap();
    let res = RelayClient::connect_verified(&addr.to_string(), "c2").await;
    assert!(res.is_err());
    let err = res.unwrap_err();
    if let RelayError::ServerError(code, _) = err {
        assert_eq!(code, ERR_CONNECTION_LIMIT);
    } else {
        panic!("Expected server error, got: {:?}", err);
    }
    server.shutdown().await;
}

#[tokio::test]
async fn test_oversized_frame_rejected_before_payload() {
    let server_config = RelayServerConfig {
        allow_insecure_plaintext: true,
        require_authentication: false,
        max_frame_payload: 10,
        ..Default::default()
    };
    let server = RelayServer::start_with_config("127.0.0.1:0", server_config)
        .await
        .unwrap();
    let addr = server.addr;

    let mut stream = TcpStream::connect(addr).await.unwrap();
    let reg = Frame::register("c1").encode();
    stream.write_all(&reg).await.unwrap();
    let mut buf = [0u8; 100];
    let n = stream.read(&mut buf).await.unwrap();
    let (f, _) = Frame::decode(&buf[..n]).unwrap();
    assert_eq!(f.msg_type, MSG_REGISTERED);

    let mut header = Vec::new();
    header.extend_from_slice(&MAGIC);
    header.push(VERSION);
    header.push(MSG_FORWARD);
    header.extend_from_slice(&1000u16.to_be_bytes());
    stream.write_all(&header).await.unwrap();

    let n = stream.read(&mut buf).await.unwrap();
    assert!(n > 0);
    let (f, _) = Frame::decode(&buf[..n]).unwrap();
    assert_eq!(f.msg_type, MSG_ERROR);
    let (code, _) = f.parse_error().unwrap();
    assert_eq!(code, ERR_FRAME_TOO_LARGE);
    server.shutdown().await;
}

#[tokio::test]
async fn test_duplicate_registration_race_and_ownership() {
    let server = RelayServer::start_random().await.unwrap();
    let addr = server.addr;

    let client1 = RelayClient::connect_verified(&addr.to_string(), "dup")
        .await
        .unwrap()
        .0;
    let (_client2, mut rx2) = RelayClient::connect_verified(&addr.to_string(), "dup")
        .await
        .unwrap();

    // client1 exiting should be clean
    drop(client1);
    tokio::time::sleep(Duration::from_millis(50)).await;

    let (client3, _rx3) = RelayClient::connect_verified(&addr.to_string(), "sender3")
        .await
        .unwrap();
    client3.send_data("dup", b"still here").await.unwrap();

    let msg = tokio::time::timeout(Duration::from_secs(2), rx2.recv())
        .await
        .unwrap()
        .unwrap();
    if let RelayMessage::Data { from_node, data } = msg {
        assert_eq!(from_node, "sender3");
        assert_eq!(data, b"still here");
    } else {
        panic!("Expected Data, got {:?}", msg);
    }
    server.shutdown().await;
}

#[tokio::test]
async fn test_duplicate_registration_same_connection() {
    let server = RelayServer::start_random().await.unwrap();
    let addr = server.addr;

    let mut stream = TcpStream::connect(addr).await.unwrap();
    let reg1 = Frame::register("node-a").encode();
    stream.write_all(&reg1).await.unwrap();
    let mut buf = [0u8; 100];
    let n = stream.read(&mut buf).await.unwrap();
    let (f, _) = Frame::decode(&buf[..n]).unwrap();
    assert_eq!(f.msg_type, MSG_REGISTERED);

    stream.write_all(&reg1).await.unwrap();
    let n = stream.read(&mut buf).await.unwrap();
    let (f, _) = Frame::decode(&buf[..n]).unwrap();
    assert_eq!(f.msg_type, MSG_REGISTERED);

    let reg2 = Frame::register("node-b").encode();
    stream.write_all(&reg2).await.unwrap();
    let n = stream.read(&mut buf).await.unwrap();
    assert!(n > 0);
    let (f, _) = Frame::decode(&buf[..n]).unwrap();
    assert_eq!(f.msg_type, MSG_ERROR);
    let (code, _) = f.parse_error().unwrap();
    assert_eq!(code, ERR_DUPLICATE_REGISTRATION);
    server.shutdown().await;
}

#[test]
fn test_unknown_wire_error_code() {
    let frame = Frame::error(9999, "unknown issue");
    let (code, msg) = frame.parse_error().unwrap();
    assert_eq!(code, 9999);
    assert_eq!(msg, "unknown issue");

    let ec = RelayErrorCode::from_u16(9999);
    assert!(ec.is_none());
}
