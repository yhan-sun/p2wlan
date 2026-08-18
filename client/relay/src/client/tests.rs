use super::*;
use crate::{RelayClientConfig, RelayServer, RelayServerConfig};
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

    let (alice, mut rx_a) = RelayClient::connect(&addr.to_string(), "alice")
        .await
        .unwrap();
    let (bob, mut rx_b) = RelayClient::connect(&addr.to_string(), "bob")
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

    let (client, mut rx) = RelayClient::connect(&addr.to_string(), "sender")
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

    let (client, mut rx) = RelayClient::connect(&addr.to_string(), "pinger")
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

    let (sender, _rx_s) = RelayClient::connect(&addr.to_string(), "sender")
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

    let (client, _rx) = RelayClient::connect(&addr.to_string(), "closer")
        .await
        .unwrap();

    client.close().await.unwrap();

    tokio::time::sleep(Duration::from_millis(200)).await;

    server.shutdown().await;
}

/// Once a data command has been accepted by the local queue, aborting the
/// connection must wake a blocked `write_all` and classify the packet as
/// delivery-uncertain. The old writer must not resume later and emit the
/// stale ciphertext after a replacement connection has started.
#[tokio::test]
async fn abort_interrupts_blocked_write_without_late_completion() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let (client_stream, mut server_stream) = tokio::io::duplex(1024);
    let server = tokio::spawn(async move {
        let mut header = [0u8; FRAME_HEADER_SIZE];
        server_stream.read_exact(&mut header).await.unwrap();
        let payload_len = u16::from_be_bytes([header[6], header[7]]) as usize;
        let mut payload = vec![0u8; payload_len];
        server_stream.read_exact(&mut payload).await.unwrap();
        server_stream
            .write_all(&Frame::registered("blocked-writer").encode())
            .await
            .unwrap();
        // Do not drain the following large forward frame. Its write must
        // remain pending until the client-side abort signal wins the select.
        tokio::time::sleep(Duration::from_secs(2)).await;
    });

    let config = RelayClientConfig {
        register_timeout: Duration::from_secs(1),
        ..Default::default()
    };
    let (client, _rx) =
        RelayClient::finish_connect_with_stream(client_stream, "blocked-writer", config)
            .await
            .unwrap();
    let abort_handle = client.clone();
    let send_task =
        tokio::spawn(async move { client.send_data("peer", &vec![0xA5; 60_000]).await });

    tokio::time::sleep(Duration::from_millis(50)).await;
    abort_handle.abort();
    let result = tokio::time::timeout(Duration::from_secs(1), send_task)
        .await
        .expect("aborting a blocked write must wake send_data")
        .expect("send task must not panic")
        .expect_err("a blocked write interrupted by abort cannot be successful");
    assert!(
        matches!(result, RelayError::WriteUncertain(_)),
        "{result:?}"
    );
    server.await.unwrap();
}

#[tokio::test]
async fn test_bidirectional_stream() {
    let server = RelayServer::start_random().await.unwrap();
    let addr = server.addr;

    let (a, mut rxa) = RelayClient::connect(&addr.to_string(), "streamA")
        .await
        .unwrap();
    let (b, mut rxb) = RelayClient::connect(&addr.to_string(), "streamB")
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

/// Keepalive pings keep the connection alive across many idle windows: with
/// keepalive 50ms and a server idle timeout of 200ms, the connection must
/// survive 600ms (3 idle windows) and keep receiving pongs.
#[tokio::test]
async fn relay_ping_pong_survives_idle_window() {
    let server_config = RelayServerConfig {
        idle_timeout: Duration::from_millis(200),
        allow_insecure_plaintext: true,
        require_authentication: false,
        allow_legacy_unauthenticated: true,
        ..Default::default()
    };
    let server = RelayServer::start_with_config("127.0.0.1:0", server_config)
        .await
        .unwrap();
    let addr = server.addr;

    let (_client, mut rx) = RelayClient::connect_to_addr_with_keepalive(
        addr,
        "survive-idle",
        Duration::from_millis(50),
    )
    .await
    .unwrap();

    let deadline = tokio::time::Instant::now() + Duration::from_millis(600);
    let mut pong_count = 0u32;
    loop {
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        if remaining.is_zero() {
            break;
        }
        match tokio::time::timeout(remaining, rx.recv()).await {
            Ok(Some(RelayMessage::Pong { .. })) => pong_count += 1,
            Ok(Some(other)) => {
                panic!("unexpected message while keepalive should survive: {other:?}")
            }
            Ok(None) => panic!("relay connection closed while keepalive is healthy"),
            Err(_) => {
                // The keepalive interval may not align with the deadline; a
                // timeout right at the end is fine as long as the connection
                // survived the whole window.
                if tokio::time::Instant::now() >= deadline {
                    break;
                }
                panic!("no pong within the keepalive interval");
            }
        }
    }
    assert!(
        pong_count >= 3,
        "the keepalive must produce regular pongs across multiple idle windows, got {pong_count}"
    );
    server.shutdown().await;
}

/// Force an RST on the connection: SO_LINGER(0) is the only portable way to
/// make the kernel send RST instead of a clean FIN on close.
#[allow(deprecated)]
fn force_rst(stream: &tokio::net::TcpStream) {
    stream
        .set_linger(Some(std::time::Duration::from_millis(0)))
        .unwrap();
}

/// Minimal raw TCP server harness that behaves like a relay for
/// close-classification tests.
async fn raw_relay_peer<F, Fut>(handler: F) -> std::net::SocketAddr
where
    F: FnOnce(tokio::net::TcpStream) -> Fut + Send + 'static,
    Fut: std::future::Future<Output = ()> + Send + 'static,
{
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        if let Ok((stream, _)) = listener.accept().await {
            handler(stream).await;
        }
    });
    addr
}

/// The client classifies every disconnect: server EOF, TCP reset, explicit
/// server Close frame, idle timeout and a local shutdown are distinguishable.
#[tokio::test]
async fn relay_disconnect_reason_is_classified() {
    use tokio::io::AsyncWriteExt;

    // 1. Server drops the connection after consuming the register frame
    //    (clean FIN) -> ServerEof.
    let addr = raw_relay_peer(|mut stream| async move {
        use tokio::io::AsyncReadExt;
        let mut buf = [0u8; 512];
        let _ = stream.read(&mut buf).await;
        stream
            .write_all(&Frame::registered("eof-node").encode())
            .await
            .unwrap();
        drop(stream);
    })
    .await;
    let (_client, mut rx) = RelayClient::connect(&addr.to_string(), "eof-node")
        .await
        .unwrap();
    match tokio::time::timeout(Duration::from_secs(2), rx.recv())
        .await
        .unwrap()
        .unwrap()
    {
        RelayMessage::Closed { reason } => assert_eq!(reason, RelayCloseReason::ServerEof),
        other => panic!("expected ServerEof classification, got {other:?}"),
    }

    // 2. Server resets the TCP connection -> TcpReset.
    let addr = raw_relay_peer(|mut stream| async move {
        use tokio::io::AsyncReadExt;
        let mut buf = [0u8; 512];
        let _ = stream.read(&mut buf).await;
        stream
            .write_all(&Frame::registered("rst-node").encode())
            .await
            .unwrap();
        stream.flush().await.unwrap();
        // Windows can otherwise deliver the reset before the client has
        // consumed the registration frame, making the setup itself fail
        // instead of exercising disconnect classification.
        tokio::time::sleep(Duration::from_millis(100)).await;
        force_rst(&stream);
        drop(stream);
    })
    .await;
    let (_client, mut rx) = RelayClient::connect(&addr.to_string(), "rst-node")
        .await
        .unwrap();
    match tokio::time::timeout(Duration::from_secs(2), rx.recv())
        .await
        .unwrap()
        .unwrap()
    {
        RelayMessage::Closed { reason } => assert_eq!(reason, RelayCloseReason::TcpReset),
        other => panic!("expected TcpReset classification, got {other:?}"),
    }

    // 3. Server sends an explicit Close frame -> ServerCloseFrame.
    let addr = raw_relay_peer(|mut stream| async move {
        use tokio::io::AsyncReadExt;
        let mut buf = [0u8; 512];
        let _ = stream.read(&mut buf).await;
        stream
            .write_all(&Frame::registered("close-node").encode())
            .await
            .unwrap();
        stream
            .write_all(&Frame::close(CLOSE_NORMAL).encode())
            .await
            .unwrap();
        stream.flush().await.unwrap();
    })
    .await;
    let (_client, mut rx) = RelayClient::connect(&addr.to_string(), "close-node")
        .await
        .unwrap();
    match tokio::time::timeout(Duration::from_secs(2), rx.recv())
        .await
        .unwrap()
        .unwrap()
    {
        RelayMessage::Closed { reason } => assert_eq!(reason, RelayCloseReason::ServerCloseFrame),
        other => panic!("expected ServerCloseFrame classification, got {other:?}"),
    }

    // 4. Idle timeout -> the Error{4009} frame is followed by Closed with the
    //    IdleTimeout classification.
    let addr = raw_relay_peer(|mut stream| async move {
        use tokio::io::AsyncReadExt;
        let mut buf = [0u8; 512];
        let _ = stream.read(&mut buf).await;
        stream
            .write_all(&Frame::registered("idle-node").encode())
            .await
            .unwrap();
        stream.flush().await.unwrap();
        eprintln!("[idle-server] sleeping 500ms");
        tokio::time::sleep(std::time::Duration::from_millis(500)).await;
        eprintln!("[idle-server] dropping");
    })
    .await;
    let config = RelayClientConfig {
        idle_timeout: Duration::from_millis(100),
        keepalive_interval: Duration::from_millis(50),
        ..Default::default()
    };
    let (_client, mut rx) =
        RelayClient::connect_with_config(&addr.to_string(), "idle-node", config)
            .await
            .unwrap();
    let first = tokio::time::timeout(Duration::from_secs(2), rx.recv())
        .await
        .unwrap()
        .unwrap();
    eprintln!("idle-case first message: {first:?}");
    assert_eq!(
        first,
        RelayMessage::Error {
            code: ERR_IDLE_TIMEOUT,
            message: "idle timeout".to_string()
        }
    );
    let second = tokio::time::timeout(Duration::from_secs(2), rx.recv())
        .await
        .unwrap()
        .unwrap();
    match second {
        RelayMessage::Closed { reason } => assert_eq!(reason, RelayCloseReason::IdleTimeout),
        other => panic!("expected IdleTimeout classification, got {other:?}"),
    }

    // 5. Local shutdown via the client Close command -> LocalShutdown.
    let server_config = RelayServerConfig {
        allow_insecure_plaintext: true,
        require_authentication: false,
        allow_legacy_unauthenticated: true,
        ..Default::default()
    };
    let server = RelayServer::start_with_config("127.0.0.1:0", server_config)
        .await
        .unwrap();
    let addr = server.addr;
    let (client, mut rx) = RelayClient::connect(&addr.to_string(), "local-node")
        .await
        .unwrap();
    client.close().await.unwrap();
    match tokio::time::timeout(Duration::from_secs(2), rx.recv())
        .await
        .unwrap()
        .unwrap()
    {
        RelayMessage::Closed { reason } => assert_eq!(reason, RelayCloseReason::LocalShutdown),
        other => panic!("expected LocalShutdown classification, got {other:?}"),
    }
    server.shutdown().await;
}

/// The first close-reason attribution wins: a write failure that races the
/// read task's close observation is never mislabeled as a server close.
#[test]
fn close_reason_first_writer_wins_for_write_failure() {
    let reason = Arc::new(std::sync::Mutex::new(RelayCloseReason::Unknown));
    note_close_reason(&reason, RelayCloseReason::LocalWriteFailed);
    note_close_reason(&reason, RelayCloseReason::ServerEof);
    assert_eq!(*reason.lock().unwrap(), RelayCloseReason::LocalWriteFailed);
    assert_eq!(
        resolve_close_reason(&reason),
        RelayCloseReason::LocalWriteFailed
    );

    let unclassified = Arc::new(std::sync::Mutex::new(RelayCloseReason::Unknown));
    assert_eq!(
        resolve_close_reason(&unclassified),
        RelayCloseReason::LocalShutdown
    );
}
