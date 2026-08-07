use tokio::net::TcpListener;
use tokio::time::{sleep, timeout};
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

#[tokio::test]
async fn queued_fresh_offer_is_skipped_when_ownership_revoked() {
    // Mock control plane: registers the device, answers signal polls with an
    // empty list, and counts every POST to /api/v1/signals.
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let signal_posts = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let posts = signal_posts.clone();
    let server = tokio::spawn(async move {
        loop {
            let Ok((mut stream, _)) = listener.accept().await else {
                break;
            };
            let posts = posts.clone();
            tokio::spawn(async move {
                let mut buf = Vec::new();
                let mut chunk = [0u8; 4096];
                loop {
                    match stream.read(&mut chunk).await {
                        Ok(0) => return,
                        Ok(n) => {
                            buf.extend_from_slice(&chunk[..n]);
                            if buf.windows(4).any(|window| window == b"\r\n\r\n") {
                                break;
                            }
                        }
                        Err(_) => return,
                    }
                }
                let head = String::from_utf8_lossy(&buf);
                let is_signal_post =
                    head.starts_with("POST") && head.contains("/api/v1/signals");
                let is_device_post =
                    head.starts_with("POST") && head.contains("/api/v1/devices");
                if is_signal_post {
                    posts.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                }
                let body = if is_device_post {
                    r#"{"success":true,"node_id":"node-a","virtual_ip":"10.20.0.1","cidr":"10.20.0.0/16","relay_servers":[]}"#
                } else {
                    r#"{"success":true,"signals":[],"server_time_ms":0}"#
                };
                let response = format!(
                    "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{}",
                    body.len(),
                    body
                );
                let _ = stream.write_all(response.as_bytes()).await;
            });
        }
    });

    let mut config = test_config();
    config.control.server_url = format!("http://{address}");
    config.control.auth_token = "test-token".to_string();
    config.node.node_id = "node-a".to_string();
    let (client, mut rx) = ControlClient::new(&config, true, None, None);

    timeout(Duration::from_secs(5), async {
        loop {
            match rx.recv().await {
                Some(ControlEvent::Registered { .. }) => break,
                Some(_) => continue,
                None => panic!("control channel closed before registration"),
            }
        }
    })
    .await
    .expect("device registration must complete against the mock server");

    // A fresh-mapping offer whose punch session was revoked must be skipped
    // by the HTTP worker even though it is already queued, and must be
    // reported as Cancelled — never as a successful send.
    let revoked = Arc::new(crate::PunchSessionCancellation::default());
    revoked.cancel();
    let result = client
        .send_peer_offer_with_sources_and_punch_at(
            "peer-b",
            &["203.0.113.10:40001".to_string()],
            &HashMap::new(),
            &[],
            None,
            Some(revoked),
        )
        .await;
    assert!(
        matches!(
            result,
            Err(crate::control::PeerOfferSendFailure::Cancelled)
        ),
        "a revoked fresh offer must be reported as Cancelled, got {result:?}"
    );
    // Give the worker time to process the queue: it must never post.
    sleep(Duration::from_millis(200)).await;
    assert_eq!(
        signal_posts.load(std::sync::atomic::Ordering::Relaxed),
        0,
        "a revoked fresh-mapping offer must never reach the wire"
    );

    // A live ownership reaches the wire exactly once.
    let live = Arc::new(crate::PunchSessionCancellation::default());
    let result = client
        .send_peer_offer_with_sources_and_punch_at(
            "peer-b",
            &["203.0.113.10:40002".to_string()],
            &HashMap::new(),
            &[],
            None,
            Some(live),
        )
        .await;
    assert!(result.is_ok(), "a live fresh offer must be sent");
    timeout(Duration::from_secs(5), async {
        loop {
            if signal_posts.load(std::sync::atomic::Ordering::Relaxed) >= 1 {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("the live fresh offer must reach the wire");
    assert_eq!(
        signal_posts.load(std::sync::atomic::Ordering::Relaxed),
        1,
        "only the live offer may be posted"
    );

    drop(client);
    server.abort();
}

/// A malformed signal in a poll batch must never abort the whole batch: the
/// server already deleted every delivered row, so aborting here would drop the
/// healthy signals of the same poll together with the bad one.  The healthy
/// signals must still reach the event loop and the poll must return Ok.
#[tokio::test]
async fn poll_signals_skips_bad_handshake_without_dropping_healthy_signals() {
    use tokio::net::TcpListener;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut chunk = [0u8; 4096];
        let mut buf = Vec::new();
        loop {
            match stream.read(&mut chunk).await {
                Ok(0) => break,
                Ok(n) => {
                    buf.extend_from_slice(&chunk[..n]);
                    if buf.windows(4).any(|window| window == b"\r\n\r\n") {
                        break;
                    }
                }
                Err(_) => break,
            }
        }
        // Two healthy signals sandwich one with a malformed handshake.
        let body = serde_json::json!({
            "signals": [
                {
                    "from_node_id": "peer-b",
                    "type": "peer_offer",
                    "candidates": ["203.0.113.10:40001"],
                    "candidate_sources": {"203.0.113.10:40001": "stun_observed"},
                    "handshake": "01020304",
                    "punch_at_ms": 0
                },
                {
                    "from_node_id": "peer-c",
                    "type": "peer_offer",
                    "candidates": ["203.0.113.10:40002"],
                    "handshake": "zz-not-hex"
                },
                {
                    "from_node_id": "peer-d",
                    "type": "peer_offer",
                    "candidates": ["203.0.113.10:40003"],
                    "handshake": "01020305",
                    "punch_at_ms": 0
                }
            ],
            "server_time_ms": 0
        });
        let body = body.to_string();
        let response = format!(
            "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{}",
            body.len(),
            body
        );
        let _ = stream.write_all(response.as_bytes()).await;
    });

    let (event_tx, mut event_rx) = mpsc::unbounded_channel();
    let result = poll_signals(
        &reqwest::Client::new(),
        &format!("http://{address}"),
        "test-token",
        "node-a",
        &event_tx,
        0,
        &Arc::new(tokio::sync::Mutex::new(VecDeque::new())),
    )
    .await;
    assert!(
        result.is_ok(),
        "a malformed signal must be skipped, not abort the poll: {result:?}"
    );

    // The two healthy signals arrive; the malformed one is dropped.
    let mut offered = Vec::new();
    for _ in 0..2 {
        match timeout(Duration::from_secs(5), event_rx.recv()).await {
            Ok(Some(ControlEvent::PeerOffer { from_node_id, .. })) => {
                offered.push(from_node_id);
            }
            other => panic!("expected a healthy peer offer, got {other:?}"),
        }
    }
    offered.sort();
    assert_eq!(offered, vec!["peer-b".to_string(), "peer-d".to_string()]);
    assert!(
        event_rx.try_recv().is_err(),
        "the malformed signal must not produce an event"
    );

    server.abort();
}

/// ACK-mode delivery: the server hands out delivery leases with per-row
/// tokens, the client decodes and enqueues every healthy signal, and only
/// THEN acknowledges the batch.  A redelivered batch (simulated by a second
/// poll with the same signals) is deduped by signal id but still ACKed.
#[tokio::test]
async fn poll_signals_ack_mode_enqueues_then_acks_and_dedupes_redelivery() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let ack_posts = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let server = {
        let ack_posts = ack_posts.clone();
        tokio::spawn(async move {
            loop {
                let (mut stream, _) = listener.accept().await.unwrap();
                let mut chunk = [0u8; 8192];
                let mut buf = Vec::new();
                loop {
                    match stream.read(&mut chunk).await {
                        Ok(0) => break,
                        Ok(n) => {
                            buf.extend_from_slice(&chunk[..n]);
                            if buf.windows(4).any(|window| window == b"\r\n\r\n") {
                                break;
                            }
                        }
                        Err(_) => break,
                    }
                }
                let request = String::from_utf8_lossy(&buf);
                if request.starts_with("POST") {
                    // The ACK request: count it and reply success.
                    ack_posts.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    let body = r#"{"success":true,"deleted":1}"#;
                    let response = format!(
                        "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{}",
                        body.len(),
                        body
                    );
                    let _ = stream.write_all(response.as_bytes()).await;
                    continue;
                }
                // GET: deliver the same leased batch (as after a lost ACK).
                let body = serde_json::json!({
                    "signals": [
                        {
                            "id": "signal-redelivery-1",
                            "from_node_id": "peer-b",
                            "type": "peer_offer",
                            "candidates": ["203.0.113.10:45001"],
                            "handshake": "01020304",
                            "delivery_token": "dlv-token-1"
                        }
                    ],
                    "delivery": {
                        "batch_token": "batch-token-1",
                        "lease_expires_at_ms": 1760000000000i64
                    },
                    "server_time_ms": 0
                });
                let body = body.to_string();
                let response = format!(
                    "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{}",
                    body.len(),
                    body
                );
                let _ = stream.write_all(response.as_bytes()).await;
            }
        })
    };

    let (event_tx, mut event_rx) = mpsc::unbounded_channel();
    let dedup: Arc<tokio::sync::Mutex<VecDeque<String>>> =
        Arc::new(tokio::sync::Mutex::new(VecDeque::new()));

    // First poll: the signal is decoded, enqueued, and ACKed.
    let result = poll_signals(
        &reqwest::Client::new(),
        &format!("http://{address}"),
        "test-token",
        "node-a",
        &event_tx,
        0,
        &dedup,
    )
    .await;
    assert!(result.is_ok(), "first poll must succeed: {result:?}");
    match timeout(Duration::from_secs(5), event_rx.recv()).await {
        Ok(Some(ControlEvent::PeerOffer { from_node_id, .. })) => {
            assert_eq!(from_node_id, "peer-b");
        }
        other => panic!("expected the delivered peer offer, got {other:?}"),
    }
    // The ACK is sent after the enqueue (the mock server must have seen it).
    timeout(Duration::from_secs(5), async {
        while ack_posts.load(std::sync::atomic::Ordering::Relaxed) == 0 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("the delivered batch must be ACKed after enqueueing");

    // Second poll: the SAME batch is redelivered (the ACK was "lost" and the
    // lease expired).  The signal id dedup skips the duplicate event but the
    // ACK is still sent, so the server stops redelivering.
    let result = poll_signals(
        &reqwest::Client::new(),
        &format!("http://{address}"),
        "test-token",
        "node-a",
        &event_tx,
        0,
        &dedup,
    )
    .await;
    assert!(result.is_ok(), "second poll must succeed: {result:?}");
    assert!(
        event_rx.try_recv().is_err(),
        "a redelivered signal must not be enqueued twice"
    );
    timeout(Duration::from_secs(5), async {
        while ack_posts.load(std::sync::atomic::Ordering::Relaxed) < 2 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("the redelivered batch must still be ACKed");
    server.abort();
}
