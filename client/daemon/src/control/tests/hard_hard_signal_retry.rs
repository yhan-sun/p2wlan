type StartAckRetryFenceHook = Arc<Mutex<Option<Box<dyn FnOnce() + Send>>>>;

struct StartAckRetryHarness {
    client: ControlClient,
    auth_tx: watch::Sender<Option<CriticalControlAuth>>,
    events: mpsc::UnboundedReceiver<ControlEvent>,
    worker: JoinHandle<()>,
}

impl Drop for StartAckRetryHarness {
    fn drop(&mut self) {
        self.worker.abort();
    }
}

impl StartAckRetryHarness {
    fn new(base_url: &str) -> Self {
        let mut client = ControlClient::disabled_for_test();
        client.set_local_registration_for_test(Some(1), PeerCapabilities::current());
        let (commands, receiver) = mpsc::channel(4);
        client.candidate_offer_tx = commands;
        let (auth_tx, auth_rx) = watch::channel(Some(CriticalControlAuth {
            accepted_peer_capabilities: PeerCapabilities::current(),
            base_url: base_url.to_string(),
            token: "test-token".to_string(),
            self_node_id: "node-a".to_string(),
            registration_seq: Some(1),
            signal_signing_identity: None,
        }));
        let (event_tx, events) = mpsc::unbounded_channel();
        let http = route_aware_control_http_clients(
            crate::config::ControlProxyMode::Direct,
            base_url,
            None,
            None,
        )
        .0;
        let worker = tokio::spawn(run_candidate_offer_worker(
            receiver, http, auth_rx, event_tx,
        ));
        Self {
            client,
            auth_tx,
            events,
            worker,
        }
    }

    async fn queue(
        &self,
        attempts: u8,
        deadline: Instant,
        owner: Arc<crate::PunchSessionCancellation>,
    ) -> Arc<HardHardStartAckDelivery> {
        self.client
            .queue_hard_hard_start_ack(
                "peer-ack",
                &["192.0.2.1:41000".to_string()],
                &HashMap::new(),
                1,
                1,
                "start-ack-retry-test".to_string(),
                owner,
                deadline,
                attempts,
                1,
            )
            .await
            .unwrap()
    }

    async fn completion(&mut self) -> ControlEvent {
        timeout(Duration::from_secs(2), self.events.recv())
            .await
            .expect("candidate worker must complete within its original deadline")
            .expect("worker event channel must remain open")
    }

    async fn flush(&self) {
        timeout(
            Duration::from_secs(2),
            self.client.send_peer_offer_with_sources_and_punch_at(
                "peer-ack",
                &["192.0.2.1:41001".to_string()],
                &HashMap::new(),
                &[],
                None,
                None,
            ),
        )
        .await
        .expect("the existing FIFO must remain available")
        .unwrap();
    }
}

#[tokio::test]
async fn final_ack_retries_only_the_prepaid_immutable_payload() {
    let attempts = Arc::new(AtomicUsize::new(0));
    let seen = attempts.clone();
    let server = MockControlServer::spawn(move |_, _| {
        if seen.fetch_add(1, Ordering::SeqCst) < 2 {
            MockAction::Fail500
        } else {
            MockAction::Ok
        }
    })
    .await;
    let mut harness = StartAckRetryHarness::new(&format!("http://{}", server.address));
    let delivery = harness
        .queue(
            3,
            Instant::now() + Duration::from_secs(1),
            Arc::new(crate::PunchSessionCancellation::default()),
        )
        .await;
    assert!(matches!(
        harness.completion().await,
        ControlEvent::ControlHealthy
    ));
    assert!(delivery.server_accepted());
    let posts = server.signal_posts.lock().unwrap().clone();
    assert_eq!(posts.len(), 3);
    assert!(
        posts.windows(2).all(|pair| pair[0] == pair[1]),
        "generation, expiry, signature and start must be immutable across retries"
    );
    drop(harness);
    server.task.abort();
}

#[tokio::test]
async fn final_ack_never_exceeds_prepaid_attempts_and_ordinary_candidates_do_not_retry() {
    for attempts in 1..=HARD_HARD_START_ACK_MAX_ATTEMPTS {
        let server = MockControlServer::spawn(|_, _| MockAction::Fail500).await;
        let mut harness = StartAckRetryHarness::new(&format!("http://{}", server.address));
        let delivery = harness
            .queue(
                attempts,
                Instant::now() + Duration::from_secs(1),
                Arc::new(crate::PunchSessionCancellation::default()),
            )
            .await;
        assert!(matches!(
            harness.completion().await,
            ControlEvent::ServerError { .. }
        ));
        assert!(!delivery.server_accepted());
        assert_eq!(
            server.signal_posts.lock().unwrap().len(),
            usize::from(attempts)
        );
        assert!(harness
            .client
            .send_peer_offer_with_sources_and_punch_at(
                "peer-ack",
                &["192.0.2.1:41001".to_string()],
                &HashMap::new(),
                &[],
                None,
                None
            )
            .await
            .is_err());
        assert_eq!(
            server.signal_posts.lock().unwrap().len(),
            usize::from(attempts) + 1
        );
        drop(harness);
        server.task.abort();
    }
}

#[tokio::test]
async fn final_ack_permanent_auth_and_registration_conflict_are_not_retried() {
    for status in [401, 403, 409] {
        let server = ControlStub::start(move |_| (status,
            r#"{"error":"registration conflict","error_code":"registration_conflict","registration_seq":2}"#.to_string())).await;
        let mut harness = StartAckRetryHarness::new(&server.base_url);
        let delivery = harness
            .queue(
                3,
                Instant::now() + Duration::from_secs(1),
                Arc::new(crate::PunchSessionCancellation::default()),
            )
            .await;
        assert!(matches!(
            harness.completion().await,
            ControlEvent::ServerError { .. }
        ));
        assert!(!delivery.server_accepted());
        assert_eq!(server.requests().len(), 1);
    }
}

#[tokio::test]
async fn final_ack_retry_stops_on_owner_drop_cancellation_or_registration_replacement() {
    for fence in 0..3 {
        let hook: StartAckRetryFenceHook = Arc::new(Mutex::new(None));
        let first_request_hook = hook.clone();
        let server = MockControlServer::spawn(move |_, body| {
            if body.contains("start-ack-retry-test") {
                if let Some(hook) = first_request_hook.lock().unwrap().take() {
                    hook();
                }
                MockAction::Fail500
            } else {
                MockAction::Ok
            }
        })
        .await;
        let harness = StartAckRetryHarness::new(&format!("http://{}", server.address));
        let owner = Arc::new(crate::PunchSessionCancellation::default());
        let delivery = harness
            .queue(3, Instant::now() + Duration::from_secs(1), owner.clone())
            .await;
        let mut retained_delivery = Some(delivery);
        *hook.lock().unwrap() = Some(match fence {
            0 => Box::new(move || {
                owner.cancel_for_hard_hard_cleanup();
            }),
            1 => {
                let auth = harness.auth_tx.clone();
                Box::new(move || {
                    auth.send_modify(|current| {
                        current.as_mut().unwrap().registration_seq = Some(2);
                    })
                })
            }
            _ => {
                let delivery = retained_delivery.take().unwrap();
                Box::new(move || drop(delivery))
            }
        });
        // The sentinel is queued behind the ACK, proving completion without
        // sleeps or relying on whether an aborted command emits diagnostics.
        harness.flush().await;
        assert_eq!(
            server
                .signal_posts
                .lock()
                .unwrap()
                .iter()
                .filter(|body| body.contains("start-ack-retry-test"))
                .count(),
            1
        );
        if let Some(delivery) = retained_delivery {
            assert!(!delivery.server_accepted());
        }
        drop(harness);
        server.task.abort();
    }
}

#[tokio::test]
async fn final_ack_original_deadline_cuts_off_remaining_prepaid_attempts() {
    let server = MockControlServer::spawn(|_, _| MockAction::Delay200).await;
    let mut harness = StartAckRetryHarness::new(&format!("http://{}", server.address));
    let delivery = harness
        .queue(
            3,
            Instant::now() + Duration::from_millis(40),
            Arc::new(crate::PunchSessionCancellation::default()),
        )
        .await;
    assert!(matches!(
        harness.completion().await,
        ControlEvent::ServerError { .. }
    ));
    assert!(!delivery.server_accepted());
    // A heavily delayed worker may expire before its first HTTP poll; either
    // way it must never consume the additional prepaid attempts past start.
    assert!(server.signal_posts.lock().unwrap().len() <= 1);
    drop(harness);
    server.task.abort();
}

#[tokio::test]
async fn initial_hh2_publication_retries_one_identical_payload_within_original_deadline() {
    let attempts = Arc::new(AtomicUsize::new(0));
    let seen = attempts.clone();
    let server = MockControlServer::spawn(move |_, _| {
        if seen.fetch_add(1, Ordering::SeqCst) == 0 {
            MockAction::Fail500
        } else {
            MockAction::Ok
        }
    })
    .await;
    let harness = StartAckRetryHarness::new(&format!("http://{}", server.address));
    harness
        .client
        .set_local_registration_for_test(Some(1), PeerCapabilities::current());
    assert!(harness
        .client
        .send_hard_hard_initial_offer(
            "peer-ack",
            &["192.0.2.1:41000".into()],
            &HashMap::new(),
            1,
            2,
            "initial-offer-retry-test".into(),
            Arc::new(crate::PunchSessionCancellation::default()),
            Instant::now() + Duration::from_secs(1),
            2,
            1
        )
        .await
        .is_ok());
    let posts = server.signal_posts.lock().unwrap().clone();
    assert_eq!(posts.len(), 2);
    assert_eq!(
        posts[0], posts[1],
        "the signed envelope, source generation, candidate expiry and schedule cannot change"
    );
    drop(harness);
    server.task.abort();
}

#[tokio::test]
async fn initial_hh2_publication_rejects_replaced_registration_or_cancelled_queue_owner() {
    let server = MockControlServer::spawn(|_, _| MockAction::Ok).await;
    let harness = StartAckRetryHarness::new(&format!("http://{}", server.address));
    harness
        .client
        .set_local_registration_for_test(Some(2), PeerCapabilities::current());
    // Both the pre-queue check and the worker's captured registration must
    // match. Here the caller matches local seq 2 but the live worker is seq 1.
    assert!(harness
        .client
        .send_hard_hard_initial_offer(
            "peer-ack",
            &["192.0.2.1:41000".into()],
            &HashMap::new(),
            1,
            2,
            "initial-offer-stale-auth".into(),
            Arc::new(crate::PunchSessionCancellation::default()),
            Instant::now() + Duration::from_secs(1),
            2,
            2
        )
        .await
        .is_err());
    assert!(server.signal_posts.lock().unwrap().is_empty());
    harness
        .client
        .set_local_registration_for_test(Some(1), PeerCapabilities::current());
    let owner = Arc::new(crate::PunchSessionCancellation::default());
    owner.cancel_for_hard_hard_cleanup();
    assert!(harness
        .client
        .send_hard_hard_initial_offer(
            "peer-ack",
            &["192.0.2.1:41000".into()],
            &HashMap::new(),
            1,
            2,
            "initial-offer-cancelled".into(),
            owner,
            Instant::now() + Duration::from_secs(1),
            2,
            1
        )
        .await
        .is_err());
    assert!(server.signal_posts.lock().unwrap().is_empty());
    drop(harness);
    server.task.abort();
}

#[tokio::test]
async fn initial_hh2_publication_never_renews_a_short_original_deadline() {
    let server = MockControlServer::spawn(|_, _| MockAction::Delay200).await;
    let harness = StartAckRetryHarness::new(&format!("http://{}", server.address));
    harness
        .client
        .set_local_registration_for_test(Some(1), PeerCapabilities::current());
    assert!(harness
        .client
        .send_hard_hard_initial_offer(
            "peer-ack",
            &["192.0.2.1:41000".into()],
            &HashMap::new(),
            1,
            2,
            "initial-offer-expired".into(),
            Arc::new(crate::PunchSessionCancellation::default()),
            Instant::now() + Duration::from_millis(20),
            2,
            1
        )
        .await
        .is_err());
    assert!(server.signal_posts.lock().unwrap().len() <= 1);
    drop(harness);
    server.task.abort();
}

#[tokio::test]
async fn hard_hard_barrier_http_slice_has_one_attempt_without_renewing_its_phase() {
    let server = MockControlServer::spawn(|_, body| {
        if body.contains("immutable-sync") {
            MockAction::Stall
        } else {
            MockAction::Ok
        }
    })
    .await;
    let harness = StartAckRetryHarness::new(&format!("http://{}", server.address));
    let result = timeout(
        Duration::from_secs(1),
        send_barrier_for_test(
            &harness.client,
            "sync",
            Instant::now() + Duration::from_secs(2),
            Arc::new(crate::PunchSessionCancellation::default()),
        ),
    )
    .await
    .expect("the HTTP slice must finish before the remaining phase, without an outer 400ms timer");
    assert!(result.is_err(), "a stalled POST is not delivery evidence");
    harness.flush().await;
    assert_eq!(
        server
            .signal_posts
            .lock()
            .unwrap()
            .iter()
            .filter(|body| body.contains("immutable-sync"))
            .count(),
        1,
        "only the original phase owner can pay for a subsequent barrier attempt"
    );
    drop(harness);
    server.task.abort();
}
