#[tokio::test]
async fn test_server_start_and_shutdown() {
    let server = RelayServer::start_random().await.unwrap();
    assert!(server.addr.port() > 0);
    server.shutdown().await;
}

#[tokio::test]
async fn test_client_register_and_forward() {
    let server = RelayServer::start_random().await.unwrap();
    let addr = server.addr;

    // Client A registers
    let (mut client_a, mut rx_a) = RelayClient::connect(&addr.to_string(), "nodeA")
        .await
        .unwrap();

    // Client B registers
    let (mut client_b, mut rx_b) = RelayClient::connect(&addr.to_string(), "nodeB")
        .await
        .unwrap();

    tokio::time::sleep(Duration::from_millis(50)).await;

    // A sends data to B
    client_a.send_data("nodeB", b"hello from A").await.unwrap();

    // B should receive it
    let received = tokio::time::timeout(Duration::from_secs(2), rx_b.recv())
        .await
        .expect("timeout")
        .expect("channel closed");

    if let RelayMessage::Data { from_node, data } = received {
        assert_eq!(from_node, "nodeA");
        assert_eq!(data, b"hello from A");
    } else {
        panic!("Expected Data, got {:?}", received);
    }

    // B sends data back to A
    client_b.send_data("nodeA", b"hi from B").await.unwrap();

    let received = tokio::time::timeout(Duration::from_secs(2), rx_a.recv())
        .await
        .expect("timeout")
        .expect("channel closed");

    if let RelayMessage::Data { from_node, data } = received {
        assert_eq!(from_node, "nodeB");
        assert_eq!(data, b"hi from B");
    } else {
        panic!("Expected Data, got {:?}", received);
    }

    server.shutdown().await;
}

#[tokio::test]
async fn test_forward_to_nonexistent_peer() {
    let server = RelayServer::start_random().await.unwrap();
    let addr = server.addr;

    let (mut client, mut rx) = RelayClient::connect(&addr.to_string(), "lonely")
        .await
        .unwrap();

    // Send to a peer that doesn't exist
    client.send_data("ghost", b"data").await.unwrap();

    // Should receive an error
    let received = tokio::time::timeout(Duration::from_secs(2), rx.recv())
        .await
        .expect("timeout")
        .expect("channel closed");

    assert!(matches!(received, RelayMessage::Error { code: 404, .. }));

    server.shutdown().await;
}

#[tokio::test]
async fn test_ping_pong() {
    let server = RelayServer::start_random().await.unwrap();
    let addr = server.addr;

    let (mut client, mut rx) = RelayClient::connect(&addr.to_string(), "pinger")
        .await
        .unwrap();

    client.ping().await.unwrap();

    // Should receive a pong
    let received = tokio::time::timeout(Duration::from_secs(2), rx.recv())
        .await
        .expect("timeout")
        .expect("channel closed");

    assert!(matches!(received, RelayMessage::Pong { .. }));

    server.shutdown().await;
}

#[tokio::test]
async fn test_multiple_peers() {
    let server = RelayServer::start_random().await.unwrap();
    let addr = server.addr;

    // Register 3 clients
    let (_c1, mut rx1) = RelayClient::connect(&addr.to_string(), "p1").await.unwrap();
    let (_c2, mut rx2) = RelayClient::connect(&addr.to_string(), "p2").await.unwrap();
    let (mut c3, _rx3) = RelayClient::connect(&addr.to_string(), "p3").await.unwrap();

    tokio::time::sleep(Duration::from_millis(50)).await;

    // p3 sends to p1 and p2
    c3.send_data("p1", b"to p1").await.unwrap();
    c3.send_data("p2", b"to p2").await.unwrap();

    let r1 = tokio::time::timeout(Duration::from_secs(2), rx1.recv())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        r1,
        RelayMessage::Data {
            from_node: "p3".to_string(),
            data: b"to p1".to_vec()
        }
    );

    let r2 = tokio::time::timeout(Duration::from_secs(2), rx2.recv())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        r2,
        RelayMessage::Data {
            from_node: "p3".to_string(),
            data: b"to p2".to_vec()
        }
    );

    server.shutdown().await;
}

#[tokio::test]
async fn test_large_data_transfer() {
    let server = RelayServer::start_random().await.unwrap();
    let addr = server.addr;

    let (mut client_a, _rxa) = RelayClient::connect(&addr.to_string(), "bigA")
        .await
        .unwrap();
    let (_client_b, mut rxb) = RelayClient::connect(&addr.to_string(), "bigB")
        .await
        .unwrap();

    // Send 60KB of data
    let big_data = vec![0x42u8; 60000];
    client_a.send_data("bigB", &big_data).await.unwrap();

    let received = tokio::time::timeout(Duration::from_secs(3), rxb.recv())
        .await
        .unwrap()
        .unwrap();

    if let RelayMessage::Data { from_node, data } = received {
        assert_eq!(from_node, "bigA");
        assert_eq!(data.len(), 60000);
        assert!(data.iter().all(|&b| b == 0x42));
    } else {
        panic!("Expected Data, got {:?}", received);
    }

    server.shutdown().await;
}
