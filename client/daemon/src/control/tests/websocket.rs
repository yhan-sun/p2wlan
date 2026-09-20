#[test]
fn signal_websocket_url_uses_secure_scheme_and_fixed_path() {
    assert_eq!(
        signal_websocket_url("https://control.example.com/base?old=1").unwrap(),
        "wss://control.example.com/api/v1/signals/ws"
    );
    assert_eq!(
        signal_websocket_url("http://127.0.0.1:18080").unwrap(),
        "ws://127.0.0.1:18080/api/v1/signals/ws"
    );
    assert!(signal_websocket_url("ftp://control.example.com").is_err());
}

#[tokio::test]
#[allow(clippy::result_large_err)]
async fn signal_websocket_authenticates_negotiates_and_wakes() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let (shutdown_tx, shutdown_rx) = oneshot::channel::<()>();
    let server = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        let mut socket = tokio_tungstenite::accept_hdr_async(
                stream,
                |request: &tokio_tungstenite::tungstenite::handshake::server::Request,
                 mut response: tokio_tungstenite::tungstenite::handshake::server::Response| {
                    assert_eq!(
                        request
                            .headers()
                            .get(AUTHORIZATION)
                            .and_then(|value| value.to_str().ok()),
                        Some("Bearer dc-test-token")
                    );
                    assert_eq!(
                        request
                            .headers()
                            .get(SEC_WEBSOCKET_PROTOCOL)
                            .and_then(|value| value.to_str().ok()),
                        Some(SIGNAL_WS_PROTOCOL)
                    );
                    assert_eq!(
                        request
                            .headers()
                            .get("x-p2wlan-registration-seq")
                            .and_then(|value| value.to_str().ok()),
                        Some("37")
                    );
                    response.headers_mut().insert(
                        SEC_WEBSOCKET_PROTOCOL,
                        HeaderValue::from_static(SIGNAL_WS_PROTOCOL),
                    );
                    Ok(response)
                },
            )
            .await
            .unwrap();
        socket
            .send(WebSocketMessage::Text(
                serde_json::json!({
                    "type": "ready",
                    "protocol_version": 1,
                    "node_id": "node-a",
                    "network_id": "network-a",
                    "server_time_ms": 1000
                })
                .to_string()
                .into(),
            ))
            .await
            .unwrap();
        socket
            .send(WebSocketMessage::Text(
                serde_json::json!({
                    "type": "signals_available",
                    "protocol_version": 1,
                    "sequence": 1,
                    "server_time_ms": 1001
                })
                .to_string()
                .into(),
            ))
            .await
            .unwrap();
        let _ = shutdown_rx.await;
        let _ = socket.close(None).await;
    });

    let (wake_tx, mut wake_rx) = mpsc::channel(4);
    let connected = Arc::new(AtomicBool::new(false));
    let client_connected = connected.clone();
    let base_url = format!("http://{address}");
    let client = tokio::spawn(async move {
        run_signal_websocket(
            &base_url,
            "dc-test-token",
            "node-a",
            "network-a",
            Some(37),
            wake_tx,
            client_connected,
            None,
        )
        .await;
    });

    time::timeout(Duration::from_secs(2), wake_rx.recv())
        .await
        .unwrap()
        .unwrap();
    time::timeout(Duration::from_secs(2), wake_rx.recv())
        .await
        .unwrap()
        .unwrap();
    assert!(connected.load(Ordering::Acquire));

    let _ = shutdown_tx.send(());
    client.abort();
    server.await.unwrap();
}

#[test]
fn websocket_proxy_policy_is_direct_only_and_stable() {
    // WebSocket signaling uses the pinned tokio-tungstenite client which has
    // no proxy support: the policy is ALWAYS direct-only, independent of the
    // REST lane's ControlProxyMode.  This label is surfaced in the startup
    // diagnostics so an operator can see the limitation explicitly.
    assert_eq!(
        crate::control::websocket_proxy_policy_label(),
        "direct_only"
    );
    // The REST HTTP lane can opt into environment proxies; the WS lane never
    // can — the two policies are deliberately distinct and must not silently
    // diverge into an inconsistent state.
    assert!(crate::control::proxy_consults_environment(
        crate::config::ControlProxyMode::Environment
    ));
    assert!(!crate::control::proxy_consults_environment(
        crate::config::ControlProxyMode::Direct
    ));
}

#[tokio::test]
#[allow(clippy::result_large_err)]
async fn signal_websocket_exchanges_active_path_telemetry_when_advertised() {
    use crate::peer::path_telemetry::PathTelemetryHub;
    use crate::peer::NetworkPath;
    use crate::peer::PathObservabilitySnapshot;
    use futures_util::{SinkExt, StreamExt};

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel();

    let server = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        let mut socket = tokio_tungstenite::accept_hdr_async(
            stream,
            |_request: &tokio_tungstenite::tungstenite::handshake::server::Request,
             mut response: tokio_tungstenite::tungstenite::handshake::server::Response| {
                response.headers_mut().insert(
                    tokio_tungstenite::tungstenite::http::header::SEC_WEBSOCKET_PROTOCOL,
                    tokio_tungstenite::tungstenite::http::HeaderValue::from_static(crate::control::websocket::SIGNAL_WS_PROTOCOL),
                );
                Ok(response)
            },
        )
        .await
        .unwrap();

        // 1. Send ready message with path_telemetry_v1 capability
        socket
            .send(WebSocketMessage::Text(
                serde_json::json!({
                    "type": "ready",
                    "protocol_version": 1,
                    "node_id": "node-tele",
                    "network_id": "network-tele",
                    "capabilities": ["path_telemetry_v1"],
                    "server_time_ms": 2000
                })
                .to_string()
                .into(),
            ))
            .await
            .unwrap();

        // 2. Expect telemetry frame from client
        let msg = socket.next().await.unwrap().unwrap();
        if let WebSocketMessage::Text(text) = msg {
            let parsed: serde_json::Value = serde_json::from_str(&text).unwrap();
            assert_eq!(parsed["type"], "path_telemetry");
            assert_eq!(parsed["payload"]["device_id"], "node-tele");
            assert_eq!(parsed["payload"]["network_id"], "network-tele");
            assert_eq!(
                parsed["payload"]["observations"][0]["remote_device_id"],
                "remote-peer"
            );
            assert_eq!(
                parsed["payload"]["observations"][0]["current_path"],
                "direct"
            );

            // 3. Reply with path_telemetry_ack
            socket
                .send(WebSocketMessage::Text(
                    serde_json::json!({
                        "type": "path_telemetry_ack",
                        "protocol_version": 1,
                        "sent_at": 2000
                    })
                    .to_string()
                    .into(),
                ))
                .await
                .unwrap();
        } else {
            panic!("expected text frame");
        }

        let _ = shutdown_rx.await;
        let _ = socket.close(None).await;
    });

    let (wake_tx, mut _wake_rx) = mpsc::channel(4);
    let connected = Arc::new(AtomicBool::new(false));
    let client_connected = connected.clone();
    let base_url = format!("http://{address}");

    let hub = Arc::new(PathTelemetryHub::new(
        "node-tele".into(),
        "network-tele".into(),
    ));
    let snap = PathObservabilitySnapshot {
        current_path: Some(NetworkPath::Direct),
        path_state_revision: 1,
        ..Default::default()
    };
    hub.enqueue("remote-peer", &snap);

    let client_hub = hub.clone();
    let client = tokio::spawn(async move {
        run_signal_websocket(
            &base_url,
            "dc-test-token",
            "node-tele",
            "network-tele",
            Some(10),
            wake_tx,
            client_connected,
            Some(client_hub),
        )
        .await;
    });

    // Wait for ack to be received
    let deadline = tokio::time::Instant::now() + Duration::from_secs(3);
    while tokio::time::Instant::now() < deadline {
        if hub.metrics().ack_received >= 1 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }

    assert_eq!(hub.metrics().ack_received, 1);
    assert_eq!(hub.metrics().sent_batches, 1);
    assert_eq!(hub.metrics().sent_observations, 1);

    let _ = shutdown_tx.send(());
    client.abort();
    server.await.unwrap();
}
