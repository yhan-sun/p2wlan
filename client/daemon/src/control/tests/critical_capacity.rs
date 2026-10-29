#[tokio::test]
async fn critical_router_bounds_waiting_tasks_without_blocking_other_lanes_or_shutdown() {
    // No auth is ever published: the admitted tasks wait without performing
    // HTTP, so channel capacity exposes whether the router spawned excess
    // permit waiters. This exercises the real router, not a mirrored counter.
    let http = route_aware_control_http_clients(
        crate::config::ControlProxyMode::Direct,
        "http://127.0.0.1:9",
        None,
        None,
    )
    .0;
    let (auth_tx, auth_rx) = watch::channel(None);
    let (answer_tx, answer_rx) = mpsc::channel(CRITICAL_ANSWER_QUEUE_CAPACITY);
    let (offer_tx, offer_rx) = mpsc::channel(CRITICAL_OFFER_QUEUE_CAPACITY);
    let (ctrl_tx, ctrl_rx) = mpsc::channel(CRITICAL_CTRL_QUEUE_CAPACITY);
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
    let mut answers = Vec::new();
    let mut offers = Vec::new();
    let mut controls = Vec::new();
    let mut answer = || {
        let (response_tx, response_rx) = oneshot::channel();
        answers.push(response_rx);
        CriticalAnswerCommand {
            to_node_id: "answer-peer".into(),
            candidates: Vec::new(),
            session_id: None,
            probe_ephemeral_public_key: None,
            candidate_sources: HashMap::new(),
            handshake_response: Vec::new(),
            punch_at_ms: None,
            punch_at_server_ms: None,
            response_tx,
        }
    };
    for _ in 0..CRITICAL_ANSWER_MAX_INFLIGHT {
        assert!(answer_tx.try_send(answer()).is_ok());
    }
    wait_for_critical_channel_capacity(&answer_tx, CRITICAL_ANSWER_QUEUE_CAPACITY).await;
    for _ in 0..CRITICAL_ANSWER_QUEUE_CAPACITY {
        assert!(answer_tx.try_send(answer()).is_ok());
    }
    assert!(timeout(Duration::from_millis(30), answer_tx.reserve())
        .await
        .is_err());

    // A full higher-priority lane cannot stop offers from reaching their own
    // independent capacity, nor controls after both handshake lanes are full.
    let mut offer = || {
        let (response_tx, response_rx) = oneshot::channel();
        offers.push(response_rx);
        CriticalOfferCommand {
            to_node_id: "offer-peer".into(),
            candidates: Vec::new(),
            session_id: None,
            probe_ephemeral_public_key: None,
            candidate_sources: HashMap::new(),
            handshake_init: Vec::new(),
            punch_at_ms: None,
            response_tx,
        }
    };
    for _ in 0..CRITICAL_OFFER_MAX_INFLIGHT {
        assert!(offer_tx.try_send(offer()).is_ok());
    }
    wait_for_critical_channel_capacity(&offer_tx, CRITICAL_OFFER_QUEUE_CAPACITY).await;
    for _ in 0..CRITICAL_OFFER_QUEUE_CAPACITY {
        assert!(offer_tx.try_send(offer()).is_ok());
    }
    assert!(timeout(Duration::from_millis(30), offer_tx.reserve())
        .await
        .is_err());

    let mut control = || {
        let (response_tx, response_rx) = oneshot::channel();
        controls.push(response_rx);
        CriticalControlCommand::UpdateEndpoint {
            endpoint: "192.0.2.1:41000".into(),
            nat_type: "Hard".into(),
            publication_fence: None,
            response_tx,
        }
    };
    for _ in 0..CRITICAL_CTRL_MAX_INFLIGHT {
        assert!(ctrl_tx.try_send(control()).is_ok());
    }
    wait_for_critical_channel_capacity(&ctrl_tx, CRITICAL_CTRL_QUEUE_CAPACITY).await;
    for _ in 0..CRITICAL_CTRL_QUEUE_CAPACITY {
        assert!(ctrl_tx.try_send(control()).is_ok());
    }
    assert!(timeout(Duration::from_millis(30), ctrl_tx.reserve())
        .await
        .is_err());

    // Cancellation releases an admitted answer slot and admits exactly one
    // queued successor. The other saturated lanes remain bounded.
    drop(answers.remove(0));
    wait_for_critical_channel_capacity(&answer_tx, 1).await;
    assert!(timeout(Duration::from_millis(30), offer_tx.reserve())
        .await
        .is_err());
    assert_eq!(ctrl_tx.capacity(), 0);

    shutdown_tx.send(true).unwrap();
    timeout(Duration::from_secs(1), router)
        .await
        .expect("shutdown must bypass every full control channel")
        .unwrap();
    assert!(answer_tx.is_closed());
    assert!(offer_tx.is_closed());
    assert!(ctrl_tx.is_closed());
    assert!(candidate_tx.is_closed());
    assert!(answers.iter_mut().all(|response| matches!(
        response.try_recv(),
        Err(oneshot::error::TryRecvError::Closed)
    )));
    assert!(offers.iter_mut().all(|response| matches!(
        response.try_recv(),
        Err(oneshot::error::TryRecvError::Closed)
    )));
    assert!(controls.iter_mut().all(|response| matches!(
        response.try_recv(),
        Err(oneshot::error::TryRecvError::Closed)
    )));
    drop(auth_tx);
}

async fn wait_for_critical_channel_capacity<T>(sender: &mpsc::Sender<T>, capacity: usize) {
    timeout(Duration::from_secs(1), async {
        while sender.capacity() != capacity {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("the independent lane must dispatch only its admitted tasks");
}

#[tokio::test]
async fn cancelled_critical_permit_wait_releases_without_waiting_for_active_request() {
    let permits = Arc::new(Semaphore::new(1));
    let held = permits.clone().acquire_owned().await.unwrap();
    let (mut response_tx, response_rx) = oneshot::channel::<()>();
    let waiting_permits = permits.clone();
    let waiting = tokio::spawn(async move {
        acquire_critical_permit_or_skip(&waiting_permits, &mut response_tx).await
    });
    tokio::task::yield_now().await;
    drop(response_rx);
    assert!(timeout(Duration::from_secs(1), waiting)
        .await
        .expect("cancellation must not wait for the active request's permit")
        .unwrap()
        .is_none());
    assert_eq!(permits.available_permits(), 0);
    drop(held);
    assert_eq!(permits.available_permits(), 1);
}
