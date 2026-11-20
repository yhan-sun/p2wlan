/// Exercise the production queue/receipt wiring while retaining the exact
/// response sender observed by the existing candidate worker.
async fn pending_hard_hard_start_ack() -> (
    Arc<HardHardStartAckDelivery>,
    oneshot::Sender<PeerOfferSendOutcome>,
) {
    let mut client = ControlClient::disabled_for_test();
    client.set_local_registration_for_test(Some(1), PeerCapabilities::current());
    let (candidate_tx, mut candidate_rx) = mpsc::channel(1);
    client.candidate_offer_tx = candidate_tx;
    let delivery = client
        .queue_hard_hard_start_ack(
            "peer",
            &["192.0.2.1:41000".to_string()],
            &HashMap::new(),
            1,
            1,
            "start-ack-receipt-test".to_string(),
            Arc::new(crate::PunchSessionCancellation::default()),
            Instant::now() + Duration::from_secs(1),
            1,
            1,
        )
        .await
        .expect("the bounded test queue must accept the ACK");
    let command = candidate_rx
        .try_recv()
        .expect("ACK must use candidate lane");
    (delivery, command.response_tx)
}

#[tokio::test]
async fn hard_hard_start_ack_last_owner_drop_closes_worker_response() {
    let (delivery, mut response_tx) = pending_hard_hard_start_ack().await;
    let snapshot = delivery.clone();
    assert!(!response_tx.is_closed());
    drop(delivery);
    assert!(
        !response_tx.is_closed(),
        "a live plan snapshot retains delivery"
    );
    drop(snapshot);
    assert!(
        response_tx.is_closed(),
        "the final owner must revoke delivery"
    );
    // This is the same cancellation future selected by the candidate worker.
    response_tx.closed().await;
}

#[tokio::test]
async fn hard_hard_start_ack_pending_and_failed_are_not_server_acceptance() {
    for outcome in [
        PeerOfferSendOutcome::Failed,
        PeerOfferSendOutcome::Cancelled,
    ] {
        let (delivery, response_tx) = pending_hard_hard_start_ack().await;
        assert!(!delivery.server_accepted());
        assert!(
            !response_tx.is_closed(),
            "polling pending must retain its receiver"
        );
        assert!(!delivery.server_accepted());
        response_tx.send(outcome).unwrap();
        assert!(!delivery.server_accepted());
        assert!(
            !delivery.server_accepted(),
            "failure cannot become accepted later"
        );
    }
}

#[tokio::test]
async fn hard_hard_start_ack_closed_lane_is_not_server_acceptance() {
    let (delivery, response_tx) = pending_hard_hard_start_ack().await;
    drop(response_tx);
    assert!(!delivery.server_accepted());
    assert!(!delivery.server_accepted());
}

#[tokio::test]
async fn hard_hard_start_ack_success_is_cached_across_plan_snapshots() {
    let (delivery, response_tx) = pending_hard_hard_start_ack().await;
    let snapshot = delivery.clone();
    assert!(!delivery.server_accepted());
    response_tx.send(PeerOfferSendOutcome::Sent).unwrap();
    assert!(delivery.server_accepted());
    // The oneshot has been consumed, so the second snapshot must see the
    // cached server result rather than downgrade it to a closed channel.
    drop(delivery);
    assert!(snapshot.server_accepted());
    assert!(snapshot.server_accepted());
}

async fn queue_prepaid_ack_for_test(
    client: &ControlClient,
    deadline: Instant,
    owner: Arc<crate::PunchSessionCancellation>,
) -> std::result::Result<Arc<HardHardStartAckDelivery>, PeerOfferSendFailure> {
    client
        .queue_hard_hard_start_ack(
            "peer",
            &["192.0.2.1:41000".to_string()],
            &HashMap::new(),
            100,
            200,
            "immutable-prepaid-ack".into(),
            owner,
            deadline,
            3,
            1,
        )
        .await
}

async fn prepaid_ack_command_for_test(
    deadline: Instant,
    owner: Arc<crate::PunchSessionCancellation>,
) -> (Arc<HardHardStartAckDelivery>, CandidateOfferCommand) {
    let mut client = ControlClient::disabled_for_test();
    client.set_local_registration_for_test(Some(1), PeerCapabilities::current());
    let (tx, mut rx) = mpsc::channel(1);
    client.candidate_offer_tx = tx;
    let delivery = queue_prepaid_ack_for_test(&client, deadline, owner)
        .await
        .unwrap();
    (delivery, rx.try_recv().unwrap())
}

fn dispatch_auth_for_test() -> (
    watch::Sender<Option<CriticalControlAuth>>,
    watch::Receiver<Option<CriticalControlAuth>>,
) {
    watch::channel(Some(CriticalControlAuth {
        wake_device_credential: false,
        wake_proxy_v1: false,
        accepted_peer_capabilities: PeerCapabilities::current(),
        base_url: "https://ctrl.test".into(),
        token: "test-token".into(),
        self_node_id: "node-a".into(),
        registration_seq: Some(1),
        signal_signing_identity: None,
    }))
}

async fn send_barrier_for_test(
    client: &ControlClient,
    stage: &str,
    deadline: Instant,
    owner: Arc<crate::PunchSessionCancellation>,
) -> std::result::Result<(), PeerOfferSendFailure> {
    client
        .send_hard_hard_barrier(
            "peer",
            &["192.0.2.1:41000".to_string()],
            &HashMap::new(),
            100,
            200,
            format!("immutable-{stage}"),
            owner,
            deadline,
            1,
        )
        .await
}

#[tokio::test(start_paused = true)]
async fn hard_hard_barriers_queue_longer_than_http_slice_without_spending_another_attempt() {
    for stage in ["ready", "ready-ack", "sync"] {
        let mut client = ControlClient::disabled_for_test();
        client.set_local_registration_for_test(Some(1), PeerCapabilities::current());
        let (tx, mut rx) = mpsc::channel(1);
        let occupied = tx.clone().reserve_owned().await.unwrap();
        client.candidate_offer_tx = tx;
        let deadline = tokio::time::Instant::now().into_std() + Duration::from_secs(4);
        let owner = Arc::new(crate::PunchSessionCancellation::default());
        let mut send = Box::pin(send_barrier_for_test(&client, stage, deadline, owner));
        tokio::select! {
            biased;
            _ = &mut send => panic!("full global queue must retain the barrier"),
            _ = tokio::task::yield_now() => {}
        }
        tokio::time::advance(Duration::from_millis(600)).await;
        tokio::select! {
            biased;
            _ = &mut send => panic!("HTTP's 400ms slice must not time out global queue admission"),
            _ = tokio::task::yield_now() => {}
        }
        drop(occupied);
        let command = tokio::select! {
            biased;
            _ = &mut send => panic!("queue admission is not server acceptance"),
            command = rx.recv() => command.unwrap(),
        };
        let (lane_tx, mut lane_rx) = mpsc::channel(1);
        let occupied = lane_tx.clone().reserve_owned().await.unwrap();
        let (_auth, auth_rx) = dispatch_auth_for_test();
        let mut dispatch = defer_prepaid_candidate_dispatch(lane_tx, command, auth_rx);
        tokio::select! {
            biased;
            _ = &mut dispatch => panic!("full peer lane must retain the same barrier"),
            _ = tokio::task::yield_now() => {}
        }
        tokio::time::advance(Duration::from_millis(600)).await;
        tokio::select! {
            biased;
            _ = &mut send => panic!("HTTP's slice must not time out peer queue admission"),
            _ = &mut dispatch => panic!("peer queue is still full"),
            _ = tokio::task::yield_now() => {}
        }
        drop(occupied);
        assert!(dispatch.await.is_none());
        let command = lane_rx.try_recv().unwrap();
        assert_eq!(command.prepaid_attempts, 1);
        assert_eq!(command.attempt_timeout, Some(Duration::from_millis(400)));
        assert_eq!(command.not_after, Some(deadline));
        assert_eq!(command.expected_registration_seq, Some(1));
        assert_eq!(command.session_id, Some(format!("immutable-{stage}")));
        assert_eq!(command.punch_at_server_ms, Some(200));
        assert!(rx.try_recv().is_err());
        assert!(lane_rx.try_recv().is_err());
        command
            .response_tx
            .send(PeerOfferSendOutcome::Sent)
            .unwrap();
        assert!(send.await.is_ok());
    }
}

#[tokio::test(start_paused = true)]
async fn hard_hard_barrier_peer_queue_preserves_owner_registration_deadline_and_drop_fences() {
    for fence in 0..4 {
        let mut client = ControlClient::disabled_for_test();
        client.set_local_registration_for_test(Some(1), PeerCapabilities::current());
        let (tx, mut rx) = mpsc::channel(1);
        client.candidate_offer_tx = tx;
        let owner = Arc::new(crate::PunchSessionCancellation::default());
        let deadline = tokio::time::Instant::now().into_std() + Duration::from_secs(1);
        let mut send = Box::pin(send_barrier_for_test(
            &client,
            "sync",
            deadline,
            owner.clone(),
        ));
        let command = tokio::select! {
            biased;
            _ = &mut send => panic!("barrier must await server acceptance"),
            command = rx.recv() => command.unwrap(),
        };
        let (lane_tx, mut lane_rx) = mpsc::channel(1);
        let occupied = lane_tx.clone().reserve_owned().await.unwrap();
        let (auth, auth_rx) = dispatch_auth_for_test();
        let mut dispatch = defer_prepaid_candidate_dispatch(lane_tx, command, auth_rx);
        tokio::select! {
            biased;
            _ = &mut dispatch => panic!("peer lane must remain pending"),
            _ = tokio::task::yield_now() => {}
        }
        match fence {
            0 => owner.cancel_for_hard_hard_cleanup(),
            1 => auth.send_modify(|value| value.as_mut().unwrap().registration_seq = Some(2)),
            2 => tokio::time::advance(Duration::from_secs(2)).await,
            _ => {
                drop(send);
                drop(occupied);
                assert!(dispatch.await.is_none());
                assert!(lane_rx.try_recv().is_err());
                continue;
            }
        }
        drop(occupied);
        assert!(dispatch.await.is_none());
        assert!(lane_rx.try_recv().is_err());
        assert!(send.await.is_err());
    }
}

#[tokio::test]
async fn final_ack_retains_three_prepaid_attempts_through_full_global_and_peer_queues() {
    let mut client = ControlClient::disabled_for_test();
    client.set_local_registration_for_test(Some(1), PeerCapabilities::current());
    let (tx, mut rx) = mpsc::channel(1);
    let occupied = tx.clone().reserve_owned().await.unwrap();
    client.candidate_offer_tx = tx;
    let deadline = Instant::now() + Duration::from_secs(2);
    let owner = Arc::new(crate::PunchSessionCancellation::default());
    let mut queue = Box::pin(queue_prepaid_ack_for_test(&client, deadline, owner.clone()));
    tokio::select! {
        biased;
        _ = &mut queue => panic!("full global queue must retain this one prepaid owner"),
        _ = tokio::task::yield_now() => {}
    }
    drop(occupied);
    let delivery = queue.await.unwrap();
    let command = rx.try_recv().unwrap();
    let (lane_tx, mut lane_rx) = mpsc::channel(1);
    let (older_delivery, mut older) = prepaid_ack_command_for_test(deadline, owner).await;
    older.session_id = Some("older-fifo-command".into());
    assert!(lane_tx.try_send(older).is_ok());
    let (_auth, auth_rx) = dispatch_auth_for_test();
    let mut dispatch = defer_prepaid_candidate_dispatch(lane_tx, command, auth_rx);
    tokio::select! {
        biased;
        _ = &mut dispatch => panic!("full peer lane must retain the same command"),
        _ = tokio::task::yield_now() => {}
    }
    assert_eq!(
        lane_rx.try_recv().unwrap().session_id.as_deref(),
        Some("older-fifo-command")
    );
    assert!(dispatch.await.is_none());
    let command = lane_rx.try_recv().unwrap();
    assert_eq!(command.prepaid_attempts, 3);
    assert_eq!(command.not_after, Some(deadline));
    assert_eq!(command.expected_registration_seq, Some(1));
    assert_eq!(command.session_id.as_deref(), Some("immutable-prepaid-ack"));
    assert_eq!(command.punch_at_server_ms, Some(200));
    assert!(
        lane_rx.try_recv().is_err(),
        "no duplicate command was reconstructed"
    );
    assert!(
        !delivery.server_accepted(),
        "queue admission is not HTTP acceptance"
    );
    drop(delivery);
    assert!(command.response_tx.is_closed());
    drop(older_delivery);
}

#[tokio::test(start_paused = true)]
async fn final_ack_global_queue_wait_respects_cancel_registration_deadline_and_drop() {
    for fence in 0..4 {
        let mut client = ControlClient::disabled_for_test();
        client.set_local_registration_for_test(Some(1), PeerCapabilities::current());
        let (tx, mut rx) = mpsc::channel(1);
        let occupied = tx.clone().reserve_owned().await.unwrap();
        client.candidate_offer_tx = tx;
        let owner = Arc::new(crate::PunchSessionCancellation::default());
        let mut queue = Box::pin(queue_prepaid_ack_for_test(
            &client,
            tokio::time::Instant::now().into_std() + Duration::from_secs(1),
            owner.clone(),
        ));
        tokio::select! {
            biased;
            _ = &mut queue => panic!("occupied queue must remain pending"),
            _ = tokio::task::yield_now() => {}
        }
        match fence {
            0 => owner.cancel_for_hard_hard_cleanup(),
            1 => client.set_local_registration_for_test(Some(2), PeerCapabilities::current()),
            2 => tokio::time::advance(Duration::from_secs(2)).await,
            _ => {
                drop(queue);
                drop(occupied);
                assert!(rx.try_recv().is_err());
                continue;
            }
        }
        drop(occupied);
        assert!(queue.await.is_err());
        assert!(
            rx.try_recv().is_err(),
            "a revoked wait must never enqueue later"
        );
    }
}

#[tokio::test(start_paused = true)]
async fn final_ack_peer_lane_wait_respects_cancel_registration_deadline_and_receiver_drop() {
    for fence in 0..4 {
        let deadline = tokio::time::Instant::now().into_std() + Duration::from_secs(1);
        let owner = Arc::new(crate::PunchSessionCancellation::default());
        let (delivery, command) = prepaid_ack_command_for_test(deadline, owner.clone()).await;
        let (tx, mut rx) = mpsc::channel(1);
        let occupied = tx.clone().reserve_owned().await.unwrap();
        let (auth, auth_rx) = dispatch_auth_for_test();
        let mut dispatch = defer_prepaid_candidate_dispatch(tx, command, auth_rx);
        tokio::select! {
            biased;
            _ = &mut dispatch => panic!("occupied peer lane must remain pending"),
            _ = tokio::task::yield_now() => {}
        }
        let mut delivery = Some(delivery);
        match fence {
            0 => owner.cancel_for_hard_hard_cleanup(),
            1 => auth.send_modify(|value| value.as_mut().unwrap().registration_seq = Some(2)),
            2 => tokio::time::advance(Duration::from_secs(2)).await,
            _ => drop(delivery.take()),
        }
        drop(occupied);
        assert!(
            dispatch.await.is_none(),
            "revocation is terminal, not lane recreation"
        );
        assert!(rx.try_recv().is_err());
        assert!(delivery
            .as_ref()
            .is_none_or(|delivery| !delivery.server_accepted()));
    }
}

#[tokio::test]
async fn final_ack_closed_peer_lane_returns_the_exact_command_for_one_router_recreation() {
    let deadline = Instant::now() + Duration::from_secs(1);
    let owner = Arc::new(crate::PunchSessionCancellation::default());
    let (delivery, command) = prepaid_ack_command_for_test(deadline, owner).await;
    let (tx, rx) = mpsc::channel(1);
    drop(rx);
    let (_auth, auth_rx) = dispatch_auth_for_test();
    let command = defer_prepaid_candidate_dispatch(tx, command, auth_rx.clone())
        .await
        .unwrap();
    assert_eq!(command.prepaid_attempts, 3);
    assert_eq!(command.not_after, Some(deadline));
    let (replacement, mut receiver) = mpsc::channel(1);
    assert!(
        defer_prepaid_candidate_dispatch(replacement, command, auth_rx)
            .await
            .is_none()
    );
    let command = receiver.try_recv().unwrap();
    assert_eq!(command.session_id.as_deref(), Some("immutable-prepaid-ack"));
    assert!(!delivery.server_accepted());
    drop(delivery);
    assert!(command.response_tx.is_closed());
}
