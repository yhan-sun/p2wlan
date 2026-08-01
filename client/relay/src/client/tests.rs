use super::*;
use crate::server::RelayServer;
use std::time::Duration;

#[tokio::test]
async fn test_connect_and_registration_confirmed() {
    let server = RelayServer::start_random().await.unwrap();
    let addr = server.addr;

    // connect() should wait for registration confirmation internally
    let (_client, _rx) = RelayClient::connect(&addr.to_string(), "testnode")
        .await
        .unwrap();

    // If connect() returned successfully, registration was confirmed
    server.shutdown().await;
}

#[tokio::test]
async fn idle_connection_sends_keepalive_ping() {
    let server = RelayServer::start_random().await.unwrap();
    let addr = server.addr;
    let (_client, mut rx) =
        RelayClient::connect_to_addr_with_keepalive(addr, "idle-node", Duration::from_millis(50))
            .await
            .unwrap();

    let pong = tokio::time::timeout(Duration::from_millis(500), async {
        loop {
            let message = rx.recv().await.expect("relay stream closed");
            if let RelayMessage::Pong { .. } = message {
                return message;
            }
        }
    })
    .await
    .expect("relay keepalive pong timed out");

    assert!(matches!(pong, RelayMessage::Pong { .. }));
    server.shutdown().await;
}

#[tokio::test]
async fn test_send_data_between_clients() {
    let server = RelayServer::start_random().await.unwrap();
    let addr = server.addr;

    let (mut alice, mut rx_a) = RelayClient::connect(&addr.to_string(), "alice")
        .await
        .unwrap();
    let (mut bob, mut rx_b) = RelayClient::connect(&addr.to_string(), "bob")
        .await
        .unwrap();

    // Alice → Bob
    alice.send_data("bob", b"hello bob").await.unwrap();

    let msg = tokio::time::timeout(Duration::from_secs(2), rx_b.recv())
        .await
        .unwrap()
        .unwrap();

    assert_eq!(
        msg,
        RelayMessage::Data {
            from_node: "alice".to_string(),
            data: b"hello bob".to_vec()
        }
    );

    // Bob → Alice
    bob.send_data("alice", b"hi alice").await.unwrap();

    let msg = tokio::time::timeout(Duration::from_secs(2), rx_a.recv())
        .await
        .unwrap()
        .unwrap();

    assert_eq!(
        msg,
        RelayMessage::Data {
            from_node: "bob".to_string(),
            data: b"hi alice".to_vec()
        }
    );

    server.shutdown().await;
}

#[tokio::test]
async fn test_send_to_nonexistent_peer() {
    let server = RelayServer::start_random().await.unwrap();
    let addr = server.addr;

    let (mut client, mut rx) = RelayClient::connect(&addr.to_string(), "sender")
        .await
        .unwrap();

    // Send to nonexistent peer
    client.send_data("nonexistent", b"data").await.unwrap();

    // Should get an error response (code 404)
    let msg = tokio::time::timeout(Duration::from_secs(2), rx.recv())
        .await
        .unwrap()
        .unwrap();

    assert!(
        matches!(msg, RelayMessage::Error { code: 404, .. }),
        "got: {:?}",
        msg
    );
}

#[tokio::test]
async fn test_ping_pong() {
    let server = RelayServer::start_random().await.unwrap();
    let addr = server.addr;

    let (mut client, mut rx) = RelayClient::connect(&addr.to_string(), "pinger")
        .await
        .unwrap();

    client.ping().await.unwrap();

    let msg = tokio::time::timeout(Duration::from_secs(2), rx.recv())
        .await
        .unwrap()
        .unwrap();

    assert!(matches!(msg, RelayMessage::Pong { .. }));

    server.shutdown().await;
}

#[tokio::test]
async fn test_large_data() {
    let server = RelayServer::start_random().await.unwrap();
    let addr = server.addr;

    let (mut sender, _rx_s) = RelayClient::connect(&addr.to_string(), "sender")
        .await
        .unwrap();
    let (_receiver, mut rx_r) = RelayClient::connect(&addr.to_string(), "receiver")
        .await
        .unwrap();

    tokio::time::sleep(Duration::from_millis(50)).await;

    // Send 60KB
    let data = vec![0xAB; 60_000];
    sender.send_data("receiver", &data).await.unwrap();

    let msg = tokio::time::timeout(Duration::from_secs(3), rx_r.recv())
        .await
        .unwrap()
        .unwrap();

    if let RelayMessage::Data { from_node, data } = msg {
        assert_eq!(from_node, "sender");
        assert_eq!(data.len(), 60_000);
        assert!(data.iter().all(|&b| b == 0xAB));
    } else {
        panic!("expected Data, got {:?}", msg);
    }

    server.shutdown().await;
}

#[tokio::test]
async fn test_connect_to_invalid_address() {
    let result = RelayClient::connect("127.0.0.1:1", "test").await;
    assert!(result.is_err());
}

#[tokio::test]
async fn test_close_connection() {
    let server = RelayServer::start_random().await.unwrap();
    let addr = server.addr;

    let (mut client, _rx) = RelayClient::connect(&addr.to_string(), "closer")
        .await
        .unwrap();

    client.close().await.unwrap();

    tokio::time::sleep(Duration::from_millis(200)).await;

    server.shutdown().await;
}

#[tokio::test]
async fn test_bidirectional_stream() {
    let server = RelayServer::start_random().await.unwrap();
    let addr = server.addr;

    let (mut a, mut rxa) = RelayClient::connect(&addr.to_string(), "streamA")
        .await
        .unwrap();
    let (mut b, mut rxb) = RelayClient::connect(&addr.to_string(), "streamB")
        .await
        .unwrap();

    tokio::time::sleep(Duration::from_millis(150)).await;

    for i in 0..5 {
        let msg = format!("message-{}", i);
        a.send_data("streamB", msg.as_bytes()).await.unwrap();
        b.send_data("streamA", msg.as_bytes()).await.unwrap();
    }

    let mut a_to_b = Vec::new();
    for _ in 0..5 {
        let msg = tokio::time::timeout(Duration::from_secs(2), rxb.recv())
            .await
            .unwrap()
            .unwrap();
        if let RelayMessage::Data { ref from_node, .. } = msg {
            if !from_node.is_empty() {
                a_to_b.push(msg);
            }
        }
    }

    let mut b_to_a = Vec::new();
    for _ in 0..5 {
        let msg = tokio::time::timeout(Duration::from_secs(2), rxa.recv())
            .await
            .unwrap()
            .unwrap();
        if let RelayMessage::Data { ref from_node, .. } = msg {
            if !from_node.is_empty() {
                b_to_a.push(msg);
            }
        }
    }

    assert_eq!(a_to_b.len(), 5);
    assert_eq!(b_to_a.len(), 5);
    assert!(a_to_b
        .iter()
        .all(|m| matches!(m, RelayMessage::Data { from_node, .. } if from_node == "streamA")));
    assert!(b_to_a
        .iter()
        .all(|m| matches!(m, RelayMessage::Data { from_node, .. } if from_node == "streamB")));

    server.shutdown().await;
}
