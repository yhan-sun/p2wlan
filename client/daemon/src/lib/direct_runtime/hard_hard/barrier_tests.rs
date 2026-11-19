async fn barrier_fixture() -> (
    Daemon,
    HardHardSessionRecord,
    HardHardCoordination,
    Vec<String>,
) {
    let mut daemon =
        Daemon::new(Config::generate_default("http://127.0.0.1:1", "barrier-fence").unwrap());
    daemon.control = ControlClient::disabled_for_test();
    daemon
        .control
        .set_local_registration_for_test(Some(101), control::PeerCapabilities::current());
    let (mut offer, mut barrier, offered, answered) = transcript();
    let peer = control::PeerInfo {
        node_id: "peer-negotiation".into(),
        online: true,
        public_key: hex::encode(NodeIdentity::generate().public_key()),
        registration_seq: 202,
        capabilities: control::PeerCapabilities {
            probe_opaque_ids_v1: false,
            ..control::PeerCapabilities::current()
        },
        nat_type: format!(
            "p2v2:m=address_or_port_dependent;a=linear;d=1;c=60;f=unknown;h=unknown;g={};o=1",
            offer.remote_profile_generation
        ),
        ..Default::default()
    };
    daemon.peers.add_peer(&peer).await;
    assert!(
        daemon
            .peers
            .bind_remote_nat_profile_to_candidate_epoch(
                &peer.node_id,
                offer.remote_profile_generation
            )
            .await
    );
    offer.local_network_generation = daemon.peers.current_network_generation_sync();
    offer.local_profile_generation = daemon.peers.current_local_profile_generation_sync();
    offer.remote_candidate_epoch = daemon
        .peers
        .get_connection(&peer.node_id)
        .await
        .unwrap()
        .remote_candidate_epoch();
    let mut record = initial_record(&offer, &offered);
    record.remote_network_generation = 25;
    record.remote_prediction = answered.clone();
    let plan = record.coordinated_plan.as_mut().unwrap();
    plan.remote_offer = Some(barrier.v2.as_ref().unwrap().local);
    plan.agreement = Some(HardHardAgreedPlan {
        strategy: HardHardProbeStrategy::FixedAnchor,
        digest: [0xa5; 16],
    });
    plan.ready_sent_at = Some(Instant::now());
    let meta = barrier.v2.as_mut().unwrap();
    meta.stage = HardHardV2Stage::ReadyAck;
    meta.phase = plan.phase;
    meta.remote = plan.local_offer;
    meta.agreement = plan.agreement;
    barrier.local_network_generation = record.remote_network_generation;
    barrier.remote_network_generation = record.local_network_generation;
    barrier.local_profile_generation = record.remote_profile_generation;
    barrier.remote_profile_generation = record.local_profile_generation;
    assert!(
        daemon
            .peers
            .hard_hard_register_session(record.clone())
            .await
    );
    assert!(
        daemon
            .peers
            .hard_hard_session_identity_is_current(&record.fresh_socket)
            .await
    );
    (
        daemon,
        record,
        barrier,
        answered.iter().map(ToString::to_string).collect(),
    )
}

#[tokio::test(start_paused = true)]
async fn ready_barrier_drives_unrelated_candidate_writer_beyond_old_fifty_ms_limit() {
    use futures_util::{stream::FuturesUnordered, StreamExt};
    let (daemon, record, barrier, candidates) = barrier_fixture().await;
    let unrelated = "peer-unrelated-to-hh2";
    daemon
        .peers
        .add_peer(&control::PeerInfo {
            node_id: unrelated.into(),
            online: true,
            public_key: hex::encode(NodeIdentity::generate().public_key()),
            ..Default::default()
        })
        .await;
    let map = daemon.peers.connection_map_for_test();
    let reader = map.read().await;
    let mut slow = FuturesUnordered::new();
    let mut retry = FuturesUnordered::new();
    let mut responder = FuturesUnordered::new();
    let mut candidate: FuturesUnordered<ControlEventWork<'_>> = FuturesUnordered::new();
    candidate.push(Box::pin(
        daemon
            .peers
            .update_state(unrelated, ConnectionState::HolePunching),
    ));
    // Establish the granted-but-unpolled fair-lock queue with an observable
    // pending poll. No sleep is used to guess whether the writer queued.
    assert!(futures_util::poll!(candidate.next()).is_pending());
    assert!(map.try_read().is_err());
    let mut deferred = InitiatorQueue::new();
    let mut application = Box::pin(await_peer_lifecycle_commit_while_driving_work(
        &daemon,
        daemon.apply_hard_hard_barrier_signal(
            &record.peer_id,
            &barrier,
            &candidates,
            Some(record.punch_at_ms),
            Some(10_000),
        ),
        &mut slow,
        &mut retry,
        &mut responder,
        &mut candidate,
        &mut deferred,
    ));
    assert!(futures_util::poll!(&mut application).is_pending());
    tokio::time::advance(Duration::from_millis(60)).await;
    assert!(
        futures_util::poll!(&mut application).is_pending(),
        "local lock contention must not force server lease Retry at 50ms"
    );
    drop(reader);
    assert_eq!(application.await, control::SignalApplyOutcome::Applied);
    assert!(
        daemon
            .peers
            .hard_hard_session_by_token(&record.peer_id, &record.session_token)
            .await
            .unwrap()
            .coordinated_plan
            .unwrap()
            .ready_ack_received
    );
    assert_eq!(
        daemon.peers.get_connection(unrelated).await.unwrap().state,
        ConnectionState::HolePunching
    );
}

#[tokio::test(start_paused = true)]
async fn barrier_deadline_and_cancellation_are_terminal_and_cannot_extend_current_plan() {
    let (daemon, record, barrier, candidates) = barrier_fixture().await;
    let map = daemon.peers.connection_map_for_test();
    let writer = map.write().await;
    let mut application = Box::pin(daemon.apply_hard_hard_barrier_signal(
        &record.peer_id,
        &barrier,
        &candidates,
        Some(u64::MAX),
        Some(10_000),
    ));
    assert!(futures_util::poll!(&mut application).is_pending());
    tokio::time::advance(Duration::from_millis(2_100)).await;
    assert_eq!(
        application.await,
        control::SignalApplyOutcome::TerminalRejected,
        "untrusted wire time must tighten to the current plan start"
    );
    drop(writer);
    assert!(
        !daemon
            .peers
            .hard_hard_session_by_token(&record.peer_id, &record.session_token)
            .await
            .unwrap()
            .coordinated_plan
            .unwrap()
            .ready_ack_received
    );
}

#[tokio::test(start_paused = true)]
async fn barrier_cancellation_interrupts_the_current_record_wait() {
    let (daemon, record, barrier, candidates) = barrier_fixture().await;
    let map = daemon.peers.connection_map_for_test();
    let _writer = map.write().await;
    let mut application = Box::pin(daemon.apply_hard_hard_barrier_signal(
        &record.peer_id,
        &barrier,
        &candidates,
        Some(record.punch_at_ms),
        Some(10_000),
    ));
    assert!(futures_util::poll!(&mut application).is_pending());
    record.cancellation.cancel();
    assert_eq!(
        application.await,
        control::SignalApplyOutcome::TerminalRejected
    );
}
