struct CandidateLaneTestHarness {
    lanes: HashMap<String, CandidateOfferLane>,
    tasks: JoinSet<()>,
    http: RouteAwareControlHttpClient,
    auth_tx: watch::Sender<Option<CriticalControlAuth>>,
    auth_rx: watch::Receiver<Option<CriticalControlAuth>>,
    event_tx: mpsc::UnboundedSender<ControlEvent>,
}

impl CandidateLaneTestHarness {
    fn new() -> Self {
        let (auth_tx, auth_rx) = dispatch_auth_for_test();
        let (event_tx, _) = mpsc::unbounded_channel();
        Self {
            lanes: HashMap::new(),
            tasks: JoinSet::new(),
            http: route_aware_control_http_clients(
                crate::config::ControlProxyMode::Direct,
                "http://127.0.0.1:9",
                None,
                None,
            )
            .0,
            auth_tx,
            auth_rx,
            event_tx,
        }
    }

    fn route(&mut self, command: CandidateDispatchCommand) -> Option<PendingCandidateDispatch> {
        route_candidate_offer(
            command,
            &mut self.lanes,
            &mut self.tasks,
            &self.http,
            &self.auth_rx,
            &self.event_tx,
        )
    }

    fn blocked_lane(&mut self, peer: String) -> oneshot::Sender<()> {
        let (sender, receiver) = mpsc::channel(CANDIDATE_OFFER_QUEUE_CAPACITY);
        let (finish, done) = oneshot::channel();
        let task = self.tasks.spawn(async move {
            let _receiver = receiver;
            let _ = done.await;
        });
        self.lanes.insert(
            peer,
            CandidateOfferLane {
                sender,
                task_id: task.id(),
            },
        );
        finish
    }

    async fn reap_one(&mut self) {
        let completed = self.tasks.join_next_with_id().await.unwrap();
        reap_candidate_offer_lane(&mut self.lanes, completed);
    }
}

#[tokio::test]
async fn queued_candidate_refresh_rejects_replaced_network_before_http() {
    let server = MockControlServer::spawn(|_, _| MockAction::Ok).await;
    let base_url = format!("http://{}", server.address);
    let http = route_aware_control_http_clients(
        crate::config::ControlProxyMode::Direct,
        &base_url,
        None,
        None,
    )
    .0;
    let (auth_tx, auth_rx) = dispatch_auth_for_test();
    let mut auth = auth_tx.borrow().clone().unwrap();
    auth.base_url = base_url;
    auth_tx.send_replace(None);
    let (candidate_tx, candidate_rx) = mpsc::channel(CANDIDATE_OFFER_QUEUE_CAPACITY);
    let (event_tx, _events) = mpsc::unbounded_channel();
    let worker = tokio::spawn(run_candidate_offer_worker(
        candidate_rx,
        http,
        auth_rx,
        event_tx,
    ));

    let peers = Arc::new(crate::peer::PeerManager::new(test_config()));
    peers
        .add_peer(&PeerInfo {
            node_id: "peer".into(),
            public_key: "peer-key".into(),
            endpoint: "192.0.2.1:41000".into(),
            virtual_ip: "10.20.0.9".into(),
            online: true,
            ..PeerInfo::default()
        })
        .await;
    let old_generation = peers.current_network_generation_sync();
    let peer_session = peers.peer_session_generation_sync("peer").unwrap();
    let old_fence = CandidatePublicationFence::new(
        peers.clone(),
        None,
        "peer".into(),
        old_generation,
        peer_session,
        0,
    );
    assert!(old_fence.is_current().await);

    let deadline = Instant::now() + Duration::from_secs(3);
    let (_delivery, mut stale_command) = prepaid_ack_command_for_test(
        deadline,
        Arc::new(crate::PunchSessionCancellation::default()),
    )
    .await;
    stale_command.not_after = None;
    stale_command.expected_registration_seq = None;
    stale_command.prepaid_attempts = 1;
    stale_command.publication_fence = Some(old_fence);
    let (stale_tx, stale_rx) = oneshot::channel();
    stale_command.response_tx = stale_tx;
    candidate_tx.send(stale_command).await.unwrap();

    peers
        .advance_network_generation("test network handover")
        .await;
    assert_ne!(peers.current_network_generation_sync(), old_generation);
    auth_tx.send_replace(Some(auth));
    assert_eq!(
        timeout(Duration::from_secs(2), stale_rx)
            .await
            .unwrap()
            .unwrap(),
        PeerOfferSendOutcome::Cancelled
    );
    assert!(server.signal_posts.lock().unwrap().is_empty());

    let current_fence = CandidatePublicationFence::new(
        peers.clone(),
        None,
        "peer".into(),
        peers.current_network_generation_sync(),
        peers.peer_session_generation_sync("peer").unwrap(),
        0,
    );
    assert!(current_fence.is_current().await);
    let (_delivery, mut current_command) = prepaid_ack_command_for_test(
        deadline,
        Arc::new(crate::PunchSessionCancellation::default()),
    )
    .await;
    current_command.not_after = None;
    current_command.expected_registration_seq = None;
    current_command.prepaid_attempts = 1;
    current_command.publication_fence = Some(current_fence);
    let (current_tx, current_rx) = oneshot::channel();
    current_command.response_tx = current_tx;
    candidate_tx.send(current_command).await.unwrap();
    assert_eq!(
        timeout(Duration::from_secs(2), current_rx)
            .await
            .unwrap()
            .unwrap(),
        PeerOfferSendOutcome::Sent
    );
    assert_eq!(server.signal_posts.lock().unwrap().len(), 1);
    drop(candidate_tx);
    worker.abort();
    server.task.abort();
}

#[tokio::test(start_paused = true)]
async fn candidate_idle_worker_completion_reclaims_its_lane() {
    let mut harness = CandidateLaneTestHarness::new();
    let lane = spawn_candidate_offer_worker(
        &mut harness.tasks,
        harness.http.clone(),
        harness.auth_rx.clone(),
        harness.event_tx.clone(),
    );
    let sender = lane.sender.clone();
    harness.lanes.insert("historical-peer".into(), lane);
    tokio::task::yield_now().await;
    tokio::time::advance(CANDIDATE_OFFER_IDLE_TIMEOUT).await;
    harness.reap_one().await;
    assert!(sender.is_closed());
    assert!(harness.lanes.is_empty());
    assert!(harness.tasks.is_empty());
}

#[tokio::test(start_paused = true)]
async fn candidate_global_capacity_retains_one_hh_command_without_new_quota_or_task() {
    let mut harness = CandidateLaneTestHarness::new();
    let mut finishes = Vec::new();
    for index in 0..CANDIDATE_OFFER_MAX_LANES {
        finishes.push(harness.blocked_lane(format!("peer-{index}")));
    }
    let deadline = tokio::time::Instant::now().into_std() + Duration::from_secs(2);
    let (delivery, mut command) = prepaid_ack_command_for_test(
        deadline,
        Arc::new(crate::PunchSessionCancellation::default()),
    )
    .await;
    command.to_node_id = "new-peer".into();
    let mut pending = harness
        .route(CandidateDispatchCommand::new(command))
        .unwrap();
    assert!(pending
        .take_ready_lane_command(&harness.lanes, &harness.auth_rx)
        .is_none());
    assert_eq!(harness.lanes.len(), CANDIDATE_OFFER_MAX_LANES);
    assert_eq!(harness.tasks.len(), CANDIDATE_OFFER_MAX_LANES);

    let (ordinary_delivery, mut ordinary) = prepaid_ack_command_for_test(
        deadline,
        Arc::new(crate::PunchSessionCancellation::default()),
    )
    .await;
    ordinary.to_node_id = "ordinary-over-cap".into();
    ordinary.not_after = None;
    ordinary.expected_registration_seq = None;
    assert!(harness
        .route(CandidateDispatchCommand::new(ordinary))
        .is_none());
    assert!(!ordinary_delivery.server_accepted());
    assert_eq!(harness.tasks.len(), CANDIDATE_OFFER_MAX_LANES);

    finishes.pop().unwrap().send(()).unwrap();
    harness.reap_one().await;
    let ready = pending
        .take_ready_lane_command(&harness.lanes, &harness.auth_rx)
        .unwrap();
    assert_eq!(
        ready.closed_retries_remaining, 1,
        "capacity waiting is not a worker restart"
    );
    assert_eq!(ready.command.prepaid_attempts, 3);
    assert_eq!(ready.command.not_after, Some(deadline));
    assert_eq!(ready.command.expected_registration_seq, Some(1));
    assert_eq!(
        ready.command.session_id.as_deref(),
        Some("immutable-prepaid-ack")
    );
    assert!(!delivery.server_accepted());
}

#[tokio::test(start_paused = true)]
async fn candidate_idle_close_drains_prior_permit_before_same_peer_recreation() {
    let mut harness = CandidateLaneTestHarness::new();
    let (sender, mut receiver) = mpsc::channel(CANDIDATE_OFFER_QUEUE_CAPACITY);
    // A reservation issued before close can deliver after close. The old lane
    // must finish that accepted command before the next lane can exist.
    let reserved = sender.clone().reserve_owned().await.unwrap();
    let (observed_tx, observed_rx) = oneshot::channel();
    let (finish_tx, finish_rx) = oneshot::channel();
    let task = harness.tasks.spawn(async move {
        let mut retiring = false;
        let command = receive_candidate_offer(&mut receiver, &mut retiring)
            .await
            .unwrap();
        assert!(retiring);
        assert_eq!(command.session_id.as_deref(), Some("old-accepted-command"));
        command
            .response_tx
            .send(PeerOfferSendOutcome::Sent)
            .unwrap();
        observed_tx.send(()).unwrap();
        finish_rx.await.unwrap();
        assert!(receive_candidate_offer(&mut receiver, &mut retiring)
            .await
            .is_none());
    });
    harness.lanes.insert(
        "peer".into(),
        CandidateOfferLane {
            sender: sender.clone(),
            task_id: task.id(),
        },
    );
    tokio::task::yield_now().await;
    tokio::time::advance(CANDIDATE_OFFER_IDLE_TIMEOUT).await;
    tokio::task::yield_now().await;
    assert!(sender.is_closed());
    let deadline = tokio::time::Instant::now().into_std() + Duration::from_secs(2);
    let (older_delivery, mut older) = prepaid_ack_command_for_test(
        deadline,
        Arc::new(crate::PunchSessionCancellation::default()),
    )
    .await;
    older.session_id = Some("old-accepted-command".into());
    reserved.send(older);
    observed_rx.await.unwrap();
    assert!(older_delivery.server_accepted());
    let (_delivery, command) = prepaid_ack_command_for_test(
        deadline,
        Arc::new(crate::PunchSessionCancellation::default()),
    )
    .await;
    let mut pending = harness
        .route(CandidateDispatchCommand::new(command))
        .unwrap();
    assert!(pending
        .take_ready_lane_command(&harness.lanes, &harness.auth_rx)
        .is_none());
    assert_eq!(
        harness.tasks.len(),
        1,
        "closed does not mean the old FIFO has drained"
    );
    finish_tx.send(()).unwrap();
    harness.reap_one().await;
    let ready = pending
        .take_ready_lane_command(&harness.lanes, &harness.auth_rx)
        .unwrap();
    assert_eq!(ready.closed_retries_remaining, 0);
    assert_eq!(ready.command.prepaid_attempts, 3);
    assert!(
        PendingCandidateDispatch::wait_for_closed_lane(ready, &harness.auth_rx).is_none(),
        "the same command can recreate a closed worker only once"
    );
    assert!(harness.tasks.is_empty());
}

#[tokio::test(start_paused = true)]
async fn candidate_capacity_wait_rechecks_exact_auth_owner_deadline_and_receiver_before_take() {
    for fence in 0..5 {
        let harness = CandidateLaneTestHarness::new();
        let owner = Arc::new(crate::PunchSessionCancellation::default());
        let deadline = tokio::time::Instant::now().into_std() + Duration::from_secs(1);
        let (delivery, command) = prepaid_ack_command_for_test(deadline, owner.clone()).await;
        let mut delivery = Some(delivery);
        let mut pending = PendingCandidateDispatch::wait_for_lane(
            CandidateDispatchCommand::new(command),
            &harness.auth_rx,
        );
        match fence {
            0 => owner.cancel_for_hard_hard_cleanup(),
            1 => drop(delivery.take()),
            2 => tokio::time::advance(Duration::from_secs(2)).await,
            3 => harness
                .auth_tx
                .send_modify(|auth| auth.as_mut().unwrap().registration_seq = Some(2)),
            _ => harness.auth_tx.send_modify(|auth| {
                auth.as_mut().unwrap().token = "replacement-token-same-seq".into()
            }),
        }
        assert!(pending
            .take_ready_lane_command(&harness.lanes, &harness.auth_rx)
            .is_none());
        assert!(pending.poll(harness.auth_rx.clone()).await.is_none());
        drop(pending);
        assert!(delivery
            .as_ref()
            .is_none_or(|receipt| !receipt.server_accepted()));
    }
}

#[tokio::test]
async fn candidate_lane_panic_is_reaped_by_exact_task_id() {
    let mut harness = CandidateLaneTestHarness::new();
    let (sender, receiver) = mpsc::channel(CANDIDATE_OFFER_QUEUE_CAPACITY);
    let task = harness.tasks.spawn(async move {
        drop(receiver);
        panic!("test worker failure");
    });
    harness.lanes.insert(
        "failed-peer".into(),
        CandidateOfferLane {
            sender,
            task_id: task.id(),
        },
    );
    let survivor = harness.blocked_lane("surviving-peer".into());
    harness.reap_one().await;
    assert!(!harness.lanes.contains_key("failed-peer"));
    assert!(harness.lanes.contains_key("surviving-peer"));
    survivor.send(()).unwrap();
    harness.reap_one().await;
    assert!(harness.lanes.is_empty());
}

#[tokio::test]
async fn critical_answer_dispatches_while_hh_waits_for_full_candidate_lane_capacity() {
    let server = MockControlServer::spawn(|_, body| {
        if body.contains("candidate-cap-") {
            MockAction::Stall
        } else {
            MockAction::Ok
        }
    })
    .await;
    let base_url = format!("http://{}", server.address);
    let http = route_aware_control_http_clients(
        crate::config::ControlProxyMode::Direct,
        &base_url,
        None,
        None,
    )
    .0;
    let (auth_tx, auth_rx) = dispatch_auth_for_test();
    auth_tx.send_modify(|auth| auth.as_mut().unwrap().base_url = base_url);
    let (answer_tx, answer_rx) = mpsc::channel(CRITICAL_ANSWER_QUEUE_CAPACITY);
    let (_offer_tx, offer_rx) = mpsc::channel(CRITICAL_OFFER_QUEUE_CAPACITY);
    let (_ctrl_tx, ctrl_rx) = mpsc::channel(CRITICAL_CTRL_QUEUE_CAPACITY);
    let (candidate_tx, candidate_rx) = mpsc::channel(CANDIDATE_OFFER_QUEUE_CAPACITY);
    let (event_tx, _events) = mpsc::unbounded_channel();
    let (lifecycle_tx, _lifecycle_rx) = mpsc::unbounded_channel();
    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let router = tokio::spawn(run_critical_control_loop(
        http.clone(),
        http,
        answer_rx,
        offer_rx,
        ctrl_rx,
        candidate_rx,
        auth_rx,
        event_tx,
        None,
        None,
        shutdown_rx,
        Arc::new(Mutex::new(AdvertisedEndpointSnapshot::default())),
        lifecycle_tx,
    ));
    let mut client = ControlClient::disabled_for_test();
    client.critical_answer_tx = answer_tx;
    client.candidate_offer_tx = candidate_tx;
    let mut receipts = Vec::new();
    let deadline = Instant::now() + Duration::from_secs(6);
    for index in 0..CANDIDATE_OFFER_MAX_LANES {
        let (receipt, mut command) = prepaid_ack_command_for_test(
            deadline,
            Arc::new(crate::PunchSessionCancellation::default()),
        )
        .await;
        command.to_node_id = format!("candidate-cap-{index}");
        command.not_after = None;
        command.expected_registration_seq = None;
        command.prepaid_attempts = 1;
        receipts.push(receipt);
        client.candidate_offer_tx.send(command).await.ok().unwrap();
    }
    timeout(Duration::from_secs(2), async {
        while server.signal_posts.lock().unwrap().len() < CANDIDATE_OFFER_MAX_LANES {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("all bounded candidate lanes must enter their held request");
    let (pending_receipt, command) = prepaid_ack_command_for_test(
        deadline,
        Arc::new(crate::PunchSessionCancellation::default()),
    )
    .await;
    client.candidate_offer_tx.send(command).await.ok().unwrap();
    timeout(Duration::from_secs(1), async {
        while client.candidate_offer_tx.capacity() != CANDIDATE_OFFER_QUEUE_CAPACITY {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    timeout(
        Duration::from_secs(2),
        client.send_peer_answer(
            "answer-with-full-candidates",
            &["192.0.2.1:41000".into()],
            b"answer",
        ),
    )
    .await
    .expect("the pending candidate must not block answer dispatch")
    .unwrap();
    assert_eq!(
        server
            .signal_posts
            .lock()
            .unwrap()
            .iter()
            .filter(|body| body.contains("candidate-cap-"))
            .count(),
        CANDIDATE_OFFER_MAX_LANES
    );
    assert!(!pending_receipt.server_accepted());
    shutdown_tx.send(true).unwrap();
    timeout(Duration::from_secs(1), router)
        .await
        .unwrap()
        .unwrap();
    assert!(!pending_receipt.server_accepted());
    drop(receipts);
    server.task.abort();
}
