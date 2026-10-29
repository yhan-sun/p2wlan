struct RecoveryWaitHarness {
    http: RouteAwareControlHttpClient,
    clock: Arc<ServerClockEstimate>,
    pool_id: u64,
    auth_tx: watch::Sender<Option<CriticalControlAuth>>,
    _auth_rx: watch::Receiver<Option<CriticalControlAuth>>,
    event_tx: mpsc::UnboundedSender<ControlEvent>,
    events: mpsc::UnboundedReceiver<ControlEvent>,
}

impl RecoveryWaitHarness {
    fn new() -> Self {
        let clock = Arc::new(ServerClockEstimate::default());
        // Client construction only: none of these tests performs HTTP or
        // starts the route watcher, registration, or WebSocket workers.
        let http = route_aware_control_http_clients(
            ControlProxyMode::Direct,
            "http://127.0.0.1:9",
            Some(clock.clone()),
            None,
        )
        .0;
        let (_, pool_id) = http.current_with_pool_id().unwrap();
        let (auth_tx, auth_rx) = watch::channel(Some(CriticalControlAuth {
            accepted_peer_capabilities: PeerCapabilities::default(),
            base_url: "http://127.0.0.1:9".into(),
            token: "dc-recovery-test".into(),
            self_node_id: "recovery-peer".into(),
            registration_seq: Some(7),
            signal_signing_identity: None,
        }));
        let (event_tx, events) = mpsc::unbounded_channel();
        Self {
            http,
            clock,
            pool_id,
            auth_tx,
            _auth_rx: auth_rx,
            event_tx,
            events,
        }
    }
}

#[tokio::test(start_paused = true)]
async fn registration_backoff_keeps_network_hint_and_revokes_previous_auth() {
    let harness = RecoveryWaitHarness::new();
    let (commands, mut command_rx) = mpsc::unbounded_channel();
    let (response_tx, mut response_rx) = oneshot::channel();
    commands
        .send(ControlCommand::UpdateEndpoint {
            endpoint: "192.0.2.1:41000".into(),
            nat_type: "unknown".into(),
            publication_fence: None,
            response_tx,
        })
        .unwrap();
    commands.send(network_change_test_command()).unwrap();
    let started = time::Instant::now();

    assert!(
        wait_control_recovery(
            ControlRecoveryDelay::Transient(Duration::from_secs(300)),
            &harness.http,
            &mut command_rx,
            &harness.event_tx,
            &harness.auth_tx,
            &harness.clock,
            None,
        )
        .await
    );

    assert_eq!(time::Instant::now(), started);
    assert!(harness.auth_tx.borrow().is_none());
    assert!(harness
        .clock
        .request_identity(Some(7), harness.pool_id)
        .is_none());
    assert!(matches!(
        response_rx.try_recv(),
        Err(oneshot::error::TryRecvError::Closed)
    ));
    assert!(command_rx.is_empty());
}

#[tokio::test(start_paused = true)]
async fn confirmed_route_wakes_sleeping_registration_backoff() {
    let harness = RecoveryWaitHarness::new();
    let (commands, mut command_rx) = mpsc::unbounded_channel();
    let notifier = network_change::ControlRouteChangeNotifier::new(
        Arc::new(ControlNetworkChanges::default()),
        commands,
    );
    let wait = wait_control_recovery(
        ControlRecoveryDelay::Transient(Duration::from_secs(300)),
        &harness.http,
        &mut command_rx,
        &harness.event_tx,
        &harness.auth_tx,
        &harness.clock,
        None,
    );
    tokio::pin!(wait);
    assert!(futures_util::poll!(&mut wait).is_pending());
    time::advance(Duration::from_secs(1)).await;
    let changed_at = time::Instant::now();
    notifier.notify();
    assert!(wait.await);
    assert_eq!(time::Instant::now(), changed_at);
    assert!(harness.auth_tx.borrow().is_none());
}

#[tokio::test(start_paused = true)]
async fn confirmed_route_preserves_permanent_auth_cooldown() {
    let harness = RecoveryWaitHarness::new();
    let (commands, mut command_rx) = mpsc::unbounded_channel();
    let notifier = network_change::ControlRouteChangeNotifier::new(
        Arc::new(ControlNetworkChanges::default()),
        commands,
    );
    let started = time::Instant::now();
    let wait = wait_control_recovery(
        ControlRecoveryDelay::PermanentAuth,
        &harness.http,
        &mut command_rx,
        &harness.event_tx,
        &harness.auth_tx,
        &harness.clock,
        None,
    );
    tokio::pin!(wait);
    assert!(futures_util::poll!(&mut wait).is_pending());
    time::advance(Duration::from_secs(59)).await;
    notifier.notify();
    assert!(futures_util::poll!(&mut wait).is_pending());
    time::advance(Duration::from_secs(1)).await;
    assert!(wait.await);
    assert_eq!(time::Instant::now() - started, Duration::from_secs(60));
}

#[tokio::test(start_paused = true)]
async fn permanent_auth_hints_preserve_original_cooldown_and_fence_late_timing() {
    let harness = RecoveryWaitHarness::new();
    let old_identity = harness
        .clock
        .request_identity(Some(7), harness.pool_id)
        .unwrap();
    let (commands, mut command_rx) = mpsc::unbounded_channel();
    let wait = wait_control_recovery(
        ControlRecoveryDelay::PermanentAuth,
        &harness.http,
        &mut command_rx,
        &harness.event_tx,
        &harness.auth_tx,
        &harness.clock,
        None,
    );
    tokio::pin!(wait);
    assert!(futures_util::poll!(&mut wait).is_pending());
    assert!(harness.auth_tx.borrow().is_none());
    // Registration invalidation alone keeps the pool; a consumed network
    // hint must invoke the stronger network invalidation as well.
    assert!(harness
        .clock
        .request_identity(Some(7), harness.pool_id)
        .is_some());

    time::advance(Duration::from_secs(59)).await;
    commands.send(network_change_test_command()).unwrap();
    assert!(futures_util::poll!(&mut wait).is_pending());
    assert!(harness
        .clock
        .request_identity(Some(7), harness.pool_id)
        .is_none());
    harness.clock.observe_short_request(
        old_identity,
        20_010,
        10_000,
        10_010,
        Duration::from_millis(10),
        Instant::now(),
    );
    assert!(harness.clock.timing_hint(Instant::now(), 7).is_none());

    time::advance(Duration::from_millis(500)).await;
    commands.send(network_change_test_command()).unwrap();
    commands.send(ControlCommand::PollPeersNow).unwrap();
    assert!(futures_util::poll!(&mut wait).is_pending());
    time::advance(Duration::from_millis(500)).await;
    assert!(wait.await);
    assert!(harness.auth_tx.borrow().is_none());
}

#[tokio::test(start_paused = true)]
async fn recovery_wait_shutdown_and_closed_owner_exit_without_retry() {
    for shutdown in [true, false] {
        let mut harness = RecoveryWaitHarness::new();
        let (commands, mut command_rx) = mpsc::unbounded_channel();
        let (response_tx, response_rx) = oneshot::channel();
        if shutdown {
            commands
                .send(ControlCommand::Shutdown { response_tx })
                .unwrap();
        }
        drop(commands);
        let started = time::Instant::now();
        assert!(
            !wait_control_recovery(
                ControlRecoveryDelay::PermanentAuth,
                &harness.http,
                &mut command_rx,
                &harness.event_tx,
                &harness.auth_tx,
                &harness.clock,
                None,
            )
            .await
        );
        assert_eq!(time::Instant::now(), started);
        assert!(harness.auth_tx.borrow().is_none());
        assert!(matches!(
            harness.events.try_recv(),
            Ok(ControlEvent::Disconnected)
        ));
        if shutdown {
            assert!(response_rx.await.is_ok());
        }
    }
}
