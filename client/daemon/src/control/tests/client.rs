use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use tokio::net::{TcpListener, TcpStream};
use tokio::task::JoinHandle;
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

// ---------------------------------------------------------------
// Handshake critical-lane tests.  The mock server decides each request's
// fate with a closure so a test can stall candidate-only traffic, saturate
// the offer lane, fail the first answer POST, or hold one answer open while
// a newer owner is served.
// ---------------------------------------------------------------

#[derive(Clone, Copy)]
enum MockAction {
    /// Respond with HTTP 200 success immediately.
    Ok,
    /// Hold the connection open without a response until the test aborts.
    Stall,
    /// Respond with HTTP 500 immediately.
    Fail500,
}

struct HttpRequest {
    line: String,
    body: String,
}

struct MockControlServer {
    address: String,
    registered: Arc<AtomicBool>,
    signal_posts: Arc<Mutex<Vec<String>>>,
    endpoint_posts: Arc<Mutex<Vec<String>>>,
    task: JoinHandle<()>,
}

fn find_subsequence(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

async fn read_http_request(stream: &mut TcpStream) -> Option<HttpRequest> {
    let mut buf = Vec::new();
    let mut chunk = [0u8; 4096];
    loop {
        match stream.read(&mut chunk).await {
            Ok(0) => return None,
            Ok(n) => {
                buf.extend_from_slice(&chunk[..n]);
                if let Some(head_end) = find_subsequence(&buf, b"\r\n\r\n") {
                    let head = String::from_utf8_lossy(&buf[..head_end]).into_owned();
                    let content_length = head
                        .lines()
                        .find_map(|line| {
                            line.to_ascii_lowercase()
                                .strip_prefix("content-length:")
                                .map(|value| value.trim().parse::<usize>().unwrap_or(0))
                        })
                        .unwrap_or(0);
                    let body_start = head_end + 4;
                    while buf.len() < body_start + content_length {
                        match stream.read(&mut chunk).await {
                            Ok(0) => return None,
                            Ok(n) => buf.extend_from_slice(&chunk[..n]),
                            Err(_) => return None,
                        }
                    }
                    let line = head.lines().next().unwrap_or_default().to_string();
                    let body = String::from_utf8_lossy(
                        &buf[body_start..body_start + content_length],
                    )
                    .into_owned();
                    return Some(HttpRequest { line, body });
                }
            }
            Err(_) => return None,
        }
    }
}

async fn mock_respond(mut stream: TcpStream, status: u16, body: &str) {
    let reason = if status == 200 { "OK" } else { "Internal Server Error" };
    let response = format!(
        "HTTP/1.1 {status} {reason}\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{}",
        body.len(),
        body
    );
    let _ = stream.write_all(response.as_bytes()).await;
}

impl MockControlServer {
    /// Serve registration, empty signal polls, and `POST /api/v1/signals` /
    /// `PATCH .../endpoint` whose fate is decided per request by `decide`.
    async fn spawn(
        decide: impl Fn(&str, &str) -> MockAction + Send + Sync + 'static,
    ) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap().to_string();
        let registered = Arc::new(AtomicBool::new(false));
        let signal_posts = Arc::new(Mutex::new(Vec::new()));
        let endpoint_posts = Arc::new(Mutex::new(Vec::new()));
        let decide = Arc::new(decide);
        let task = {
            let registered = registered.clone();
            let signal_posts = signal_posts.clone();
            let endpoint_posts = endpoint_posts.clone();
            tokio::spawn(async move {
                loop {
                    let Ok((mut stream, _)) = listener.accept().await else {
                        break;
                    };
                    let registered = registered.clone();
                    let signal_posts = signal_posts.clone();
                    let endpoint_posts = endpoint_posts.clone();
                    let decide = decide.clone();
                    tokio::spawn(async move {
                        let Some(request) = read_http_request(&mut stream).await else {
                            return;
                        };
                        let line = request.line.clone();
                        let kind = if line.starts_with("POST") && line.contains("/api/v1/devices")
                        {
                            "register"
                        } else if line.starts_with("GET") && line.contains("/api/v1/signals") {
                            "poll"
                        } else if line.starts_with("POST") && line.contains("/api/v1/signals") {
                            signal_posts.lock().unwrap().push(request.body.clone());
                            "signal"
                        } else if line.starts_with("PATCH") && line.contains("/endpoint") {
                            endpoint_posts.lock().unwrap().push(request.body.clone());
                            "endpoint"
                        } else {
                            "other"
                        };
                        match kind {
                            "register" => {
                                registered.store(true, Ordering::SeqCst);
                                mock_respond(
                                    stream,
                                    200,
                                    r#"{"success":true,"node_id":"node-a","virtual_ip":"10.20.0.1","cidr":"10.20.0.0/16","relay_servers":[]}"#,
                                )
                                .await;
                            }
                            "poll" => {
                                mock_respond(
                                    stream,
                                    200,
                                    r#"{"signals":[],"server_time_ms":0}"#,
                                )
                                .await;
                            }
                            "signal" | "endpoint" => match decide(kind, &request.body) {
                                MockAction::Ok => {
                                    mock_respond(
                                        stream,
                                        200,
                                        r#"{"success":true,"protocol_version":1}"#,
                                    )
                                    .await;
                                }
                                MockAction::Fail500 => mock_respond(stream, 500, "{}").await,
                                MockAction::Stall => {
                                    tokio::time::sleep(Duration::from_secs(120)).await;
                                }
                            },
                            _ => {}
                        }
                    });
                }
            })
        };
        Self {
            address,
            registered,
            signal_posts,
            endpoint_posts,
            task,
        }
    }

    async fn wait_registered(&self) {
        timeout(Duration::from_secs(5), async {
            while !self.registered.load(Ordering::SeqCst) {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("device registration must complete against the mock server");
    }

    fn answer_bodies(&self) -> Vec<String> {
        self.signal_posts
            .lock()
            .unwrap()
            .iter()
            .filter(|body| body.contains("\"type\":\"peer_answer\""))
            .cloned()
            .collect()
    }
}

/// A candidate-only peer offer stalled on the ordinary lane must not delay a
/// responder answer for another peer: the answer travels the independent
/// answer-priority lane and reaches the server within a strict short timeout.
#[tokio::test]
async fn critical_answer_bypasses_stalled_ordinary_candidate_post() {
    let server = MockControlServer::spawn(|kind, body| {
        if kind == "signal"
            && body.contains("\"type\":\"peer_offer\"")
            && body.contains("\"handshake\":\"\"")
        {
            MockAction::Stall
        } else {
            MockAction::Ok
        }
    })
    .await;
    let mut config = test_config();
    config.control.server_url = format!("http://{}", server.address);
    config.control.auth_token = "test-token".to_string();
    config.node.node_id = "node-a".to_string();
    let (client, _rx) = ControlClient::new(&config, true, None, None);
    server.wait_registered().await;

    let stalled = tokio::spawn({
        let client = client.clone();
        async move {
            client
                .send_peer_offer_with_sources_and_punch_at(
                    "peer-c",
                    &["203.0.113.60:50000".to_string()],
                    &HashMap::new(),
                    &[],
                    None,
                    None,
                )
                .await
        }
    });
    // Give the ordinary lane time to enter the blocked POST.
    sleep(Duration::from_millis(150)).await;

    timeout(Duration::from_secs(2), client.send_peer_answer(
        "peer-d",
        &["203.0.113.61:50001".to_string()],
        b"wg-answer-bytes",
    ))
    .await
    .expect("the critical answer must not wait behind the stalled ordinary POST")
    .expect("the critical answer must be delivered");

    let posts = server.signal_posts.lock().unwrap().clone();
    assert!(
        posts.iter().any(|body| {
            body.contains("\"type\":\"peer_answer\"") && body.contains("peer-d")
        }),
        "the answer must reach the server: {posts:?}"
    );
    assert!(
        posts
            .iter()
            .any(|body| body.contains("peer-c") && body.contains("\"handshake\":\"\"")),
        "the stalled candidate-only offer must have reached the server: {posts:?}"
    );

    drop(client);
    stalled.abort();
    server.task.abort();
}

/// Critical offers fill their own lane budget (4 in flight + queued) and are
/// stalled forever; a later answer for a different peer must still be
/// delivered promptly because answers never wait behind offers.
#[tokio::test]
async fn critical_answer_not_blocked_by_slow_critical_offers() {
    let server = MockControlServer::spawn(|kind, body| {
        if kind == "signal" && body.contains("\"type\":\"peer_offer\"") {
            MockAction::Stall
        } else {
            MockAction::Ok
        }
    })
    .await;
    let mut config = test_config();
    config.control.server_url = format!("http://{}", server.address);
    config.control.auth_token = "test-token".to_string();
    config.node.node_id = "node-a".to_string();
    let (client, _rx) = ControlClient::new(&config, true, None, None);
    server.wait_registered().await;

    let mut offers = Vec::new();
    for index in 0..5 {
        let client = client.clone();
        offers.push(tokio::spawn(async move {
            client
                .send_peer_offer_with_sources_punch_and_session(
                    &format!("peer-offer-{index}"),
                    &[format!("203.0.113.70:{}", 51000 + index)],
                    &HashMap::new(),
                    b"wg-offer-bytes",
                    None,
                    Some(format!("sess-offer-{index}")),
                    None,
                )
                .await
        }));
    }
    // Let the offers occupy the offer lane (in flight + queued).
    sleep(Duration::from_millis(250)).await;

    timeout(Duration::from_secs(2), client.send_peer_answer(
        "peer-answer-1",
        &["203.0.113.71:52001".to_string()],
        b"wg-answer-bytes",
    ))
    .await
    .expect("a later answer must never wait behind slow critical offers")
    .expect("the answer must be delivered");

    assert_eq!(
        server.answer_bodies().len(),
        1,
        "exactly one answer may reach the wire"
    );

    drop(client);
    for offer in offers {
        offer.abort();
    }
    server.task.abort();
}

/// A transient answer POST failure is retried with the EXACT same payload
/// (one candidate generation, expiry, signature, session id, handshake bytes)
/// and succeeds; no background retry leaks after success.
#[tokio::test]
async fn critical_answer_retries_exact_payload_then_succeeds() {
    let answer_attempts = Arc::new(AtomicUsize::new(0));
    let attempts = answer_attempts.clone();
    let server = MockControlServer::spawn(move |kind, body| {
        if kind == "signal"
            && body.contains("\"type\":\"peer_answer\"")
            && attempts.fetch_add(1, Ordering::SeqCst) == 0
        {
            MockAction::Fail500
        } else {
            MockAction::Ok
        }
    })
    .await;
    let mut config = test_config();
    config.control.server_url = format!("http://{}", server.address);
    config.control.auth_token = "test-token".to_string();
    config.node.node_id = "node-a".to_string();
    let (client, _rx) = ControlClient::new(&config, true, None, None);
    server.wait_registered().await;

    timeout(Duration::from_secs(3), client.send_peer_answer_with_sources_schedule_and_session(
        "peer-e",
        &["203.0.113.80:53000".to_string()],
        &HashMap::from([("203.0.113.80:53000".to_string(), "host".to_string())]),
        b"wg-answer-retry",
        None,
        None,
        Some("session-retry-1".to_string()),
        None,
    ))
    .await
    .expect("the transient failure must be retried within the lane deadline")
    .expect("the retry must succeed");

    let posts = server.answer_bodies();
    assert_eq!(
        posts.len(),
        2,
        "one failed attempt plus one successful retry, no leak: {posts:?}"
    );
    assert_eq!(
        posts[0], posts[1],
        "the retry must re-send the exact same prepared payload"
    );

    // No background retry continues after success.
    sleep(Duration::from_millis(300)).await;
    assert_eq!(
        server.answer_bodies().len(),
        2,
        "no retry may be launched after a successful delivery"
    );

    drop(client);
    server.task.abort();
}

/// Cancelling an in-flight answer (owner dropped) aborts it: no retry and no
/// further request from the stale owner.  A newer owner for the same peer is
/// unaffected and is served normally.
#[tokio::test]
async fn cancelled_critical_answer_aborts_and_new_owner_is_unaffected() {
    let server = MockControlServer::spawn(|kind, body| {
        if kind == "signal"
            && body.contains("\"type\":\"peer_answer\"")
            && body.contains("60001")
        {
            MockAction::Stall
        } else {
            MockAction::Ok
        }
    })
    .await;
    let mut config = test_config();
    config.control.server_url = format!("http://{}", server.address);
    config.control.auth_token = "test-token".to_string();
    config.node.node_id = "node-a".to_string();
    let (client, _rx) = ControlClient::new(&config, true, None, None);
    server.wait_registered().await;

    // Owner A's answer is in flight against a stalled server connection.
    let first = tokio::spawn({
        let client = client.clone();
        async move {
            client
                .send_peer_answer(
                    "peer-x",
                    &["203.0.113.90:60001".to_string()],
                    b"first-owner-answer",
                )
                .await
        }
    });
    sleep(Duration::from_millis(250)).await;
    first.abort();
    sleep(Duration::from_millis(300)).await;

    let stalled_posts = server
        .signal_posts
        .lock()
        .unwrap()
        .iter()
        .filter(|body| body.contains("60001"))
        .count();
    assert_eq!(
        stalled_posts, 1,
        "the cancelled owner may have sent at most the in-flight request; it must never retry"
    );

    // A new owner for the same peer is served normally.
    timeout(Duration::from_secs(2), client.send_peer_answer(
        "peer-x",
        &["203.0.113.90:60002".to_string()],
        b"new-owner-answer",
    ))
    .await
    .expect("the new owner's answer must be delivered")
    .expect("the new owner's answer must succeed");
    assert_eq!(
        server
            .signal_posts
            .lock()
            .unwrap()
            .iter()
            .filter(|body| body.contains("60002"))
            .count(),
        1,
        "the new owner's answer must reach the wire exactly once"
    );

    drop(client);
    server.task.abort();
}

/// The endpoint publish used after a responder answer travels its own lane:
/// a stalled candidate-only POST on the ordinary lane must not delay it.
#[tokio::test]
async fn critical_endpoint_publish_bypasses_stalled_ordinary_lane() {
    let server = MockControlServer::spawn(|kind, body| {
        if kind == "signal"
            && body.contains("\"type\":\"peer_offer\"")
            && body.contains("\"handshake\":\"\"")
        {
            MockAction::Stall
        } else {
            MockAction::Ok
        }
    })
    .await;
    let mut config = test_config();
    config.control.server_url = format!("http://{}", server.address);
    config.control.auth_token = "test-token".to_string();
    config.node.node_id = "node-a".to_string();
    let (client, _rx) = ControlClient::new(&config, true, None, None);
    server.wait_registered().await;

    let stalled = tokio::spawn({
        let client = client.clone();
        async move {
            client
                .send_peer_offer_with_sources_and_punch_at(
                    "peer-c",
                    &["203.0.113.60:50010".to_string()],
                    &HashMap::new(),
                    &[],
                    None,
                    None,
                )
                .await
        }
    });
    sleep(Duration::from_millis(150)).await;

    timeout(Duration::from_secs(2), client.update_endpoint_for_handshake(
        "203.0.113.99:54000",
        "FullCone",
    ))
    .await
    .expect("the handshake endpoint publish must not wait behind the ordinary lane")
    .expect("the handshake endpoint publish must succeed");

    let endpoints = server.endpoint_posts.lock().unwrap().clone();
    assert!(
        endpoints.iter().any(|body| body.contains("203.0.113.99:54000")),
        "the endpoint publish must reach the server: {endpoints:?}"
    );

    drop(client);
    stalled.abort();
    server.task.abort();
}
