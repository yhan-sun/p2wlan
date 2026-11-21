use super::*;
use crate::config::ControlProxyMode;
use crate::control::route_aware_control_http_clients_with_wake;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::time::timeout;

fn auth(base_url: String) -> CriticalControlAuth {
    CriticalControlAuth {
        wake_device_credential: true,
        wake_proxy_v1: true,
        accepted_peer_capabilities: crate::control::PeerCapabilities::current(),
        base_url,
        token: "device-test-token".into(),
        self_node_id: "node-a".into(),
        registration_seq: Some(7),
        signal_signing_identity: None,
    }
}

fn mac(id: u8) -> MacAddress {
    format!("02:00:00:00:00:{id:02x}").parse().unwrap()
}

#[test]
fn opt_in_capability_requires_scoped_credentials_and_safe_control_transport() {
    assert!(permitted_control_transport("https://control.example.com"));
    assert!(permitted_control_transport("http://127.0.0.1:1234"));
    assert!(permitted_control_transport("http://[::1]:1234"));
    assert!(!permitted_control_transport("http://control.example.com"));
    assert!(!permitted_control_transport(
        "https://u:p@control.example.com"
    ));
    assert!(!permitted_control_transport("file:///tmp/proxy"));
    let mut config = Config::generate_default("https://control.example.com", "net").unwrap();
    config.wake.proxy = true;
    config.control.auth_token = "jwt-only".into();
    let base_url = config.control.server_url.clone();
    assert!(!request_proxy_capability(&config, &base_url));

    config.control.device_credential = "device-test-token".into();
    assert_eq!(request_proxy_capability(&config, &base_url), PROXY_PLATFORM);
    let declaration = crate::control::http::register_device_payload_with_incarnation(&config, 2);
    assert_eq!(
        declaration["capabilities"]["wake_proxy_v1"].as_bool(),
        PROXY_PLATFORM.then_some(true)
    );
    let unfenced = crate::control::http::register_device_payload_with_incarnation(&config, 0);
    assert!(unfenced["capabilities"].get("wake_proxy_v1").is_none());
    config.network.manual = true;
    assert!(!request_proxy_capability(&config, &base_url));
}

#[test]
fn legacy_config_defaults_to_no_wake_roles() {
    let config = Config::generate_default("https://control.example.com", "net").unwrap();
    let mut value = serde_json::to_value(config).unwrap();
    value.as_object_mut().unwrap().remove("wake");
    let legacy: Config = serde_json::from_value(value).unwrap();
    assert_eq!(legacy.wake, WakeConfig::default());
}

#[test]
fn limiter_enforces_sliding_mac_and_total_windows() {
    let mut agent = Agent::default();
    let start = Instant::now();
    assert!(agent.allow(start, mac(1)));
    assert!(!agent.allow(start + Duration::from_secs(4), mac(1)));
    assert!(agent.allow(start + Duration::from_secs(5), mac(1)));
    for id in 2..=7 {
        assert!(agent.allow(start + Duration::from_secs(8), mac(id)));
    }
    assert!(!agent.allow(start + Duration::from_secs(30), mac(8)));
    assert!(agent.allow(start + LOCAL_SEND_WINDOW, mac(8)));
    assert_eq!(agent.sent.len(), LOCAL_SEND_LIMIT);
}

#[test]
fn completion_cache_is_bounded_and_reuses_ambiguous_delivery_disposition() {
    let mut agent = Agent::default();
    let now = Instant::now();
    for id in 0..=COMPLETION_LIMIT {
        agent.record(now, &id.to_string(), WakeResult::Sent);
    }
    assert_eq!(agent.finished.len(), COMPLETION_LIMIT);
    assert_eq!(agent.finished("0", now), None);
    assert_eq!(
        agent.finished(&COMPLETION_LIMIT.to_string(), now),
        Some(WakeResult::Sent),
    );
    assert_eq!(agent.finished("1", now + COMPLETION_TTL), None);
}

#[test]
fn diagnostics_contains_only_config_flags_and_typed_statuses() {
    let mut config = Config::generate_default("https://control.example.com", "net").unwrap();
    config.wake.proxy_interface = Some("secret-device-interface".into());
    let status = WakeStatus::new(&config, true);
    let value = serde_json::to_value(status.snapshot()).unwrap();
    assert_eq!(
        value,
        serde_json::json!({
            "proxy": false,
            "proxy_state": "disabled",
            "allow_remote": false,
            "target_state": "disabled",
        }),
    );
}

async fn read_request(stream: &mut TcpStream) -> String {
    let mut bytes = Vec::new();
    let mut chunk = [0u8; 2048];
    loop {
        let count = stream.read(&mut chunk).await.unwrap();
        if count == 0 {
            break;
        }
        bytes.extend_from_slice(&chunk[..count]);
        if let Some(end) = bytes.windows(4).position(|slice| slice == b"\r\n\r\n") {
            let header = std::str::from_utf8(&bytes[..end])
                .unwrap()
                .to_ascii_lowercase();
            let content = header
                .lines()
                .find_map(|line| line.strip_prefix("content-length:"))
                .map(|count| count.trim().parse::<usize>().unwrap())
                .unwrap_or(0);
            if bytes.len() >= end + 4 + content {
                break;
            }
        }
    }
    String::from_utf8(bytes).unwrap()
}

async fn reply(stream: &mut TcpStream, code: u16, body: &str) {
    let response = format!(
        "HTTP/1.1 {code} Test\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len(),
    );
    stream.write_all(response.as_bytes()).await.unwrap();
}

fn wake_pool(base_url: &str) -> RouteAwareControlHttpClient {
    route_aware_control_http_clients_with_wake(ControlProxyMode::Direct, base_url, None, true).0
}

#[tokio::test]
async fn send_is_fenced_after_claim_and_cancelled_work_does_not_report_result() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base_url = format!("http://{}", listener.local_addr().unwrap());
    let owner = auth(base_url.clone());
    let pool = wake_pool(&base_url);
    let (http, _) = pool.remote_wake_pool().unwrap();
    let client = WakeHttp::new(&http, &owner, 7);
    let (active, mut monitor) = watch::channel(true);
    let server = async {
        let (mut stream, _) = listener.accept().await.unwrap();
        let text = read_request(&mut stream).await;
        assert!(text.starts_with("GET /api/v1/wake/jobs?state=queued&limit=4 "));
        let header = text.to_ascii_lowercase();
        assert!(header.contains("x-p2wlan-registration-seq: 7"));
        assert!(header.contains("authorization: bearer device-test-token"));
        reply(
            &mut stream,
            200,
            r#"{"jobs":[{"id":"wake-job-1","state":"claimed"}]}"#,
        )
        .await;
        let (mut stream, _) = listener.accept().await.unwrap();
        assert!(read_request(&mut stream)
            .await
            .starts_with("POST /api/v1/wake/jobs/wake-job-1/claim "));
        active.send_replace(false);
        reply(
            &mut stream,
            200,
            r#"{"mac":"02:00:00:00:00:01","lease_ms":9000,"claim_token":"claim-proof"}"#,
        )
        .await;
    };
    let mut worker = Agent::default();
    let work = worker.poll(&client, None, "p2wlan-test", || *monitor.borrow());
    timeout(Duration::from_secs(3), async {
        tokio::join!(server, work).1.unwrap();
    })
    .await
    .unwrap();
    assert!(worker.sent.is_empty());
    assert!(worker.finished.is_empty());
    assert!(!*monitor.borrow_and_update());
}

#[tokio::test]
async fn failed_result_response_retries_identical_claim_token_and_reason() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base_url = format!("http://{}", listener.local_addr().unwrap());
    let owner = auth(base_url.clone());
    let pool = wake_pool(&base_url);
    let (http, _) = pool.remote_wake_pool().unwrap();
    let client = WakeHttp::new(&http, &owner, 7);
    let server = async {
        let (mut stream, _) = listener.accept().await.unwrap();
        assert!(read_request(&mut stream).await.contains("/claim "));
        reply(
            &mut stream,
            200,
            r#"{"mac":"02:00:00:00:00:01","lease_ms":9000,"claim_token":"claim-proof"}"#,
        )
        .await;
        let mut last = None;
        for code in [500, 204] {
            let (mut stream, _) = listener.accept().await.unwrap();
            let text = read_request(&mut stream).await;
            assert!(text.contains("/result "));
            let body: serde_json::Value =
                serde_json::from_str(text.split_once("\r\n\r\n").unwrap().1).unwrap();
            assert_eq!(
                body,
                serde_json::json!({
                    "state": "failed", "reason": "no_lan_interface", "claim_token": "claim-proof",
                }),
            );
            if let Some(previous) = last.replace(body.clone()) {
                assert_eq!(previous, body);
            }
            reply(&mut stream, code, "").await;
        }
    };
    let work = async {
        let claim = client.claim("wake-job-1").await.unwrap().unwrap();
        client
            .result("wake-job-1", &claim, WakeResult::Failed("no_lan_interface"))
            .await
            .unwrap();
    };
    timeout(Duration::from_secs(3), async {
        tokio::join!(server, work);
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn legacy_wake_routes_degrade_and_redirects_never_forward_private_payloads() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base_url = format!("http://{}", listener.local_addr().unwrap());
    let owner = auth(base_url.clone());
    let pool = wake_pool(&base_url);
    let (http, _) = pool.remote_wake_pool().unwrap();
    let client = WakeHttp::new(&http, &owner, 7);
    let server = async {
        let (mut stream, _) = listener.accept().await.unwrap();
        assert!(read_request(&mut stream)
            .await
            .starts_with("GET /api/v1/wake/jobs"));
        reply(&mut stream, 404, "").await;
        let (mut stream, _) = listener.accept().await.unwrap();
        assert!(read_request(&mut stream)
            .await
            .starts_with("PUT /api/v1/devices/node-a/wake "));
        stream
            .write_all(b"HTTP/1.1 307 Test\r\nLocation: /redirect\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
            .await
            .unwrap();
        assert!(timeout(Duration::from_millis(150), listener.accept())
            .await
            .is_err());
    };
    let work = async {
        assert!(matches!(
            client.jobs().await,
            Err(WakeHttpError::Unsupported)
        ));
        assert_eq!(
            client.put_target(mac(1), "wired").await,
            Err(WakeHttpError::Unavailable),
        );
    };
    timeout(Duration::from_secs(3), async {
        tokio::join!(server, work);
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn first_boot_proxy_activation_requires_the_same_registration() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base_url = format!("http://{}", listener.local_addr().unwrap());
    let owner = auth(base_url.clone());
    let pool = wake_pool(&base_url);
    let (http, _) = pool.remote_wake_pool().unwrap();
    let client = WakeHttp::new(&http, &owner, 7);
    let server = async {
        for seq in [7, 8] {
            let (mut stream, _) = listener.accept().await.unwrap();
            let text = read_request(&mut stream).await;
            assert!(text.starts_with("POST /api/v1/devices "));
            let header = text.to_ascii_lowercase();
            assert!(header.contains("authorization: bearer device-test-token"));
            assert!(header.contains("x-p2wlan-registration-seq: 7"));
            let body: serde_json::Value =
                serde_json::from_str(text.split_once("\r\n\r\n").unwrap().1).unwrap();
            assert_eq!(body["capabilities"]["wake_proxy_v1"], true);
            assert_eq!(body["registration_incarnation"], 11);
            let body = serde_json::json!({
                "success": true,
                "node_id": "node-a",
                "registration_seq": seq,
                "registration_incarnation": 11,
                "accepted_peer_capabilities": {"wake_proxy_v1": true},
            });
            reply(&mut stream, 200, &body.to_string()).await;
        }
    };
    let work = async {
        let mut config = Config::generate_default(&base_url, "net").unwrap();
        config.wake.proxy = true;
        let payload = crate::control::http::registration_payload(&config, 11, true);
        assert_eq!(client.activate_proxy(&payload).await, Ok(true));
        assert_eq!(
            client.activate_proxy(&payload).await,
            Err(WakeHttpError::InvalidResponse),
        );
    };
    timeout(Duration::from_secs(3), async {
        tokio::join!(server, work);
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn shutdown_cancels_an_inflight_wake_request() {
    if !PROXY_PLATFORM {
        return;
    }
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base_url = format!("http://{}", listener.local_addr().unwrap());
    let mut config = Config::generate_default(&base_url, "net").unwrap();
    config.wake.proxy = true;
    let status = Arc::new(WakeStatus::new(&config, true));
    let (auth_tx, auth_rx) = watch::channel(Some(auth(base_url.clone())));
    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let worker = tokio::spawn(run(
        Profile::new(&config),
        status.clone(),
        wake_pool(&base_url),
        auth_rx,
        shutdown_rx,
    ));
    let (mut stream, _) = timeout(Duration::from_secs(3), listener.accept())
        .await
        .unwrap()
        .unwrap();
    assert!(read_request(&mut stream).await.contains("/api/v1/"));
    shutdown_tx.send_replace(true);
    timeout(Duration::from_millis(500), worker)
        .await
        .expect("no wake HTTP timeout or peer lock may delay shutdown")
        .unwrap();
    assert_eq!(status.snapshot().proxy_state, State::Disabled);
    drop(auth_tx);
}
