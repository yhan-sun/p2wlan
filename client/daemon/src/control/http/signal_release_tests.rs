#[tokio::test]
async fn revoked_lane_releases_with_current_identity_without_waiting_for_application() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base = format!("http://{}", listener.local_addr().unwrap());
    let auth = registration(&base);
    let fence = SignalAckRegistration::capture(
        &base,
        "ack-test-token",
        "ack-test-node",
        Some(41),
        auth.subscribe(),
    )
    .unwrap();
    let mut replacement = auth.borrow().clone().unwrap();
    replacement.registration_seq = Some(42);
    replacement.token = "replacement-test-token".into();
    let (ack_tx, ack_rx) = mpsc::channel(SIGNAL_ACK_PIPELINE_CAPACITY);
    let (entered_tx, entered_rx) = tokio::sync::oneshot::channel();
    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let (head, body) = read_ack(&mut stream).await;
        let head = head.to_ascii_lowercase();
        assert!(head.starts_with("post /api/v1/signals/release?node_id=ack-test-node "));
        assert!(head.contains("x-p2wlan-registration-seq: 42"));
        assert!(head.contains("authorization: bearer replacement-test-token"));
        assert_eq!(body["signals"][0]["id"], "in-flight");
        assert_eq!(body["signals"][0]["delivery_token"], "old-lease");
        stream
            .write_all(b"HTTP/1.1 200 OK\r\ncontent-length: 2\r\nconnection: close\r\n\r\n{}")
            .await
            .unwrap();
        entered_tx.send(()).unwrap();
    });
    let leased = vec![delivery("in-flight", 1, "old-lease").ack];
    let http = reqwest::Client::builder().no_proxy().build().unwrap();
    let task = tokio::spawn(async move {
        acknowledge_signal_batch(
            &http,
            &release_transport(&base),
            &base,
            "ack-test-token",
            "ack-test-node",
            fence,
            ack_rx,
            &leased,
        )
        .await;
    });
    // No application result enters the ACK channel. A registration edge must
    // independently retire the consumer and relinquish the old exact lease.
    auth.send_replace(Some(replacement));
    tokio::time::timeout(Duration::from_secs(2), entered_rx)
        .await
        .unwrap()
        .unwrap();
    task.await.unwrap();
    assert!(ack_tx.is_closed());
    server.await.unwrap();
}

#[tokio::test]
async fn revoked_lease_cleanup_never_crosses_device_identity() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base = format!("http://{}", listener.local_addr().unwrap());
    let auth = registration(&base);
    let fence = SignalAckRegistration::capture(
        &base,
        "ack-test-token",
        "ack-test-node",
        Some(41),
        auth.subscribe(),
    )
    .unwrap();
    let mut replacement = auth.borrow().clone().unwrap();
    replacement.self_node_id = "another-device".into();
    auth.send_replace(Some(replacement));
    release_revoked_signal_leases(
        &release_transport(&base),
        fence,
        &[delivery("signal", 1, "lease").ack],
    )
    .await;
    assert!(
        tokio::time::timeout(Duration::from_millis(20), listener.accept())
            .await
            .is_err()
    );
}

#[tokio::test]
async fn lease_release_resolves_the_replacement_pool_after_auth_recovers() {
    fn pool(label: &'static str, pool_id: u64) -> ControlHttpPoolState {
        let mut headers = reqwest::header::HeaderMap::new();
        headers.insert(
            "x-test-pool",
            reqwest::header::HeaderValue::from_static(label),
        );
        let client = Arc::new(
            reqwest::Client::builder()
                .no_proxy()
                .default_headers(headers)
                .build()
                .unwrap(),
        );
        ControlHttpPoolState {
            pool_id,
            primary: Some(client.clone()),
            candidate: Some(client),
            wake: None,
            unavailable_reason: None,
        }
    }
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base = format!("http://{}", listener.local_addr().unwrap());
    let auth = registration(&base);
    let fence = SignalAckRegistration::capture(
        &base,
        "ack-test-token",
        "ack-test-node",
        Some(41),
        auth.subscribe(),
    )
    .unwrap();
    let mut replacement = auth.borrow().clone().unwrap();
    replacement.registration_seq = Some(42);
    auth.send_replace(None);
    let (pool_tx, pool_rx) = tokio::sync::watch::channel(pool("retired", 1));
    let transport = RouteAwareControlHttpClient {
        timing: None,
        route_aware: false,
        state_rx: pool_rx,
        lane: ControlHttpLane::Primary,
        force_network_change_tx: None,
    };
    let leases = [delivery("signal", 1, "old-token").ack];
    let mut release = Box::pin(release_revoked_signal_leases(&transport, fence, &leases));
    assert!(
        futures_util::poll!(release.as_mut()).is_pending(),
        "release waits for current authentication"
    );
    pool_tx.send_replace(pool("replacement", 2));
    auth.send_replace(Some(replacement));
    let server = async {
        let (mut stream, _) = listener.accept().await.unwrap();
        let (head, body) = read_ack(&mut stream).await;
        let head = head.to_ascii_lowercase();
        assert!(head.contains("x-test-pool: replacement"));
        assert!(!head.contains("x-test-pool: retired"));
        assert!(head.contains("x-p2wlan-registration-seq: 42"));
        assert_eq!(body["signals"][0]["delivery_token"], "old-token");
        stream
            .write_all(b"HTTP/1.1 200 OK\r\ncontent-length: 2\r\nconnection: close\r\n\r\n{}")
            .await
            .unwrap();
    };
    tokio::time::timeout(Duration::from_secs(2), async {
        tokio::join!(release, server);
    })
    .await
    .unwrap();
}
