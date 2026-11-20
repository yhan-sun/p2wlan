#[tokio::test]
#[allow(clippy::result_large_err)]
async fn room_roster_notification_wakes_authenticated_current_websocket() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let (shutdown_tx, shutdown_rx) = oneshot::channel::<()>();
    let server = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        let mut socket = tokio_tungstenite::accept_hdr_async(
            stream,
            |request: &tokio_tungstenite::tungstenite::handshake::server::Request,
             mut response: tokio_tungstenite::tungstenite::handshake::server::Response| {
                assert_eq!(request.headers().get(AUTHORIZATION).unwrap(), "Bearer dc-test-token");
                assert_eq!(request.headers().get("x-p2wlan-registration-seq").unwrap(), "37");
                response.headers_mut().insert(
                    SEC_WEBSOCKET_PROTOCOL,
                    HeaderValue::from_static(SIGNAL_WS_PROTOCOL),
                );
                Ok(response)
            },
        ).await.unwrap();
        for message in [
            serde_json::json!({"type":"ready", "protocol_version":1,
                "node_id":"node-a", "network_id":"network-a", "server_time_ms":1000}),
            serde_json::json!({"type":"roster_changed", "protocol_version":1,
                "node_id":"node-a", "network_id":"network-a", "sequence":1, "server_time_ms":1001}),
        ] {
            socket
                .send(WebSocketMessage::Text(message.to_string().into()))
                .await
                .unwrap();
        }
        let _ = shutdown_rx.await;
        let _ = socket.close(None).await;
    });
    let (wake_tx, mut wake_rx) = wake::channel(4);
    let connected = Arc::new(AtomicBool::new(false));
    let observed = connected.clone();
    let client = tokio::spawn(async move {
        run_signal_websocket(
            &format!("http://{address}"),
            "dc-test-token",
            "node-a",
            "network-a",
            Some(37),
            wake_tx,
            connected,
            None,
        )
        .await;
    });
    let ready = time::timeout(Duration::from_secs(2), wake_rx.recv()).await;
    let roster = time::timeout(Duration::from_secs(2), wake_rx.recv()).await;
    let is_connected = observed.load(Ordering::Acquire);
    let _ = shutdown_tx.send(());
    client.abort();
    server.await.unwrap();
    assert!(ready.unwrap().is_some());
    assert!(
        roster.unwrap().is_some(),
        "committed roster notification must reach the existing wake consumer"
    );
    assert!(is_connected);
}

impl CommandHarness {
    async fn invoke_roster_wake(&mut self, include_signals: bool) -> ControlCommandDisposition {
        let (tx, mut rx) = wake::channel(1);
        if include_signals {
            assert!(tx.notify(wake::Wake::SIGNALS));
        }
        assert!(tx.notify(wake::Wake::ROSTER));
        let wake = rx.recv().await.unwrap();
        let mut signal_failures = 0;
        let recent = Arc::new(tokio::sync::Mutex::new(SignalDeliveryTracker::default()));
        let clock = self.state.read().await.server_clock.clone();
        let (critical_auth, _) = watch::channel(Some(CriticalControlAuth {
            wake_device_credential: false,
            wake_proxy_v1: false,
            accepted_peer_capabilities: PeerCapabilities::default(),
            base_url: self.base_url.clone(),
            token: self.token.clone(),
            self_node_id: self.self_node_id.clone(),
            registration_seq: self.registration_seq,
            signal_signing_identity: None,
        }));
        handle_control_wake(
            wake,
            &self.http,
            &self.base_url,
            &self.token,
            &self.config,
            &self.self_node_id,
            self.registration_seq,
            &self.state,
            &self.event_tx,
            Some(&self.health),
            None,
            &self.advertised_snapshot,
            &mut self.peer_roster_tick,
            None,
            &mut self.poll_failures,
            &mut signal_failures,
            &recent,
            &clock,
            &critical_auth,
        )
        .await
    }
}

#[tokio::test]
async fn room_roster_wake_refreshes_authoritative_membership_before_signal_io() {
    let count = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let observed = count.clone();
    let config = test_config();
    let public_key = config.node.public_key.clone();
    let stub = ControlStub::start(move |line| {
        if line.starts_with("GET /api/v1/nodes?") {
            let first = observed.fetch_add(1, Ordering::SeqCst) == 0;
            let node = |id: &str, key: &str, vip: &str| {
                serde_json::json!({"id":id,
                "device_name":"device", "public_key":key, "endpoint":"", "nat_type":"Unknown",
                "virtual_ip":vip, "online":true, "last_seen":1785320000})
            };
            let mut nodes = vec![node("node-a", &public_key, "10.21.1.2")];
            if first {
                nodes.push(node("peer-b", "peer-key", "10.21.1.3"));
            }
            (
                200,
                serde_json::json!({"nodes":nodes,"authorization_lease_seconds":30}).to_string(),
            )
        } else {
            (200, r#"{"signals":[]}"#.to_string())
        }
    })
    .await;
    let mut h = CommandHarness::new(&stub.base_url);
    h.config = config;
    h.config.network.network_id = "room-wake".into();
    let room = Arc::new(crate::rooms::RoomAuthorization::new("room-wake"));
    h.state.write().await.room_authorization = room.clone();
    assert_eq!(
        h.invoke(ControlCommand::PollPeersNow, None).await,
        ControlCommandDisposition::Continue
    );
    assert!(room.allows("peer-b", "10.21.1.3", "10.21.1.2"));
    h.events();
    assert_eq!(
        h.invoke_roster_wake(true).await,
        ControlCommandDisposition::Continue
    );
    assert!(!room.allows("peer-b", "10.21.1.3", "10.21.1.2"));
    assert!(!h.state.read().await.peers.contains_key("peer-b"));
    assert!(h
        .events()
        .iter()
        .any(|e| matches!(e, ControlEvent::PeerLeft(id) if id=="peer-b")));
    let requests = stub.requests();
    assert_eq!(requests.len(), 3);
    assert!(requests[1].starts_with("GET /api/v1/nodes?"));
    assert!(requests[2].starts_with("GET /api/v1/signals?"));
    assert_eq!(count.load(Ordering::SeqCst), 2);
}

#[tokio::test]
async fn room_roster_wake_keeps_registration_conflict_exit_before_signals() {
    let stub = ControlStub::start(|_| (409, lifecycle_conflict_body())).await;
    let mut h = CommandHarness::new(&stub.base_url);
    assert_eq!(
        h.invoke_roster_wake(true).await,
        ControlCommandDisposition::Exit
    );
    assert_eq!(stub.requests().len(), 1);
    assert!(stub.saw("GET /api/v1/nodes?"));
    assert!(!stub.saw("GET /api/v1/signals?"));
    assert!(h.events().iter().any(is_reauth_required));
}

#[tokio::test]
async fn room_roster_wake_http_denial_invalidates_room_without_hint_authority() {
    let stub = ControlStub::start(|_| (403, r#"{"error":"room access revoked"}"#.into())).await;
    let mut h = CommandHarness::new(&stub.base_url);
    h.config.network.network_id = "room-wake".into();
    let room = Arc::new(crate::rooms::RoomAuthorization::new("room-wake"));
    assert!(room.replace(
        "10.21.1.2",
        [("peer-b".into(), "10.21.1.3".into())],
        std::time::Instant::now(),
        30
    ));
    h.state.write().await.room_authorization = room.clone();
    assert!(room.allows("peer-b", "10.21.1.3", "10.21.1.2"));
    assert_eq!(
        h.invoke_roster_wake(false).await,
        ControlCommandDisposition::Continue
    );
    assert!(!room.allows("peer-b", "10.21.1.3", "10.21.1.2"));
    assert_eq!(stub.requests().len(), 1);
    assert_eq!(h.poll_failures, 1);
}
