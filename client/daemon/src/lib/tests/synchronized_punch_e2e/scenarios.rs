// Split out of the former flat include!-ed test file so the module is a
// real Rust scope. Everything below is unchanged test code.
use super::*;

#[tokio::test(flavor = "current_thread")]
async fn hard_hard_role_fence_uses_the_managed_registration_node_id() {
    let (_daemon, peers, _udp, _control) = build_hard_hard_ordinary_fallback_fixture().await;
    assert_eq!(peers.local_node_id_for_traversal(), HARD_HARD_A);

    let resolved = "node-peer-a-registration";
    peers.set_local_node_id_for_traversal(resolved);

    assert_eq!(peers.local_node_id_for_traversal(), resolved);
    assert!(
        peers.local_node_id_for_traversal().as_str() < "node-peer-b-registration",
        "same-format resolved identities must select exactly one deterministic initiator"
    );
}

fn hard_hard_fallback_signal(
    control: ControlClient,
    boot_epoch_ms: u64,
    stun_servers: Vec<SocketAddr>,
) -> HolePunchSignalContext {
    // This unit fixture supplies a control context directly rather than
    // polling HTTP or installing the two-peer forwarder. Model the fresh
    // server timestamp either production signaling path would have supplied.
    control.refresh_server_clock_for_test();
    HolePunchSignalContext {
        control,
        candidate_snapshot: Arc::new(RwLock::new(None)),
        stun_servers,
        stun_timeout: Duration::from_millis(25),
        boot_epoch_ms,
    }
}

#[tokio::test(flavor = "current_thread")]
async fn hard_hard_experiment_lane_never_falls_into_ordinary_punching() {
    let (_daemon, peers, udp, _control) =
        build_hard_hard_ordinary_fallback_fixture_with_experiment(true).await;

    spawn_hole_punch_task(
        udp,
        peers.clone(),
        PunchAttemptDeduplicator::default(),
        HARD_HARD_B.to_string(),
        Duration::from_millis(1),
        1,
        None,
        None,
        None,
        None,
    )
    .await;

    wait_for_stage(&peers, HARD_HARD_B, "hard_hard_experiment_waiting").await;
    let conn = peers.get_connection(HARD_HARD_B).await.unwrap();
    assert!(
        !conn
            .direct_events
            .iter()
            .any(|event| event.stage == "punch_started"),
        "the independent Hard↔Hard experiment must not consume its quota through an ordinary punch"
    );
}

#[tokio::test(flavor = "current_thread")]
async fn hard_hard_initiator_is_cancelled_with_its_udp_invocation_only() {
    let (_daemon, peers, udp, control) = build_hard_hard_ordinary_fallback_fixture().await;
    let blackholes = [
        UdpSocket::bind("127.0.0.1:0").await.unwrap(),
        UdpSocket::bind("127.0.0.1:0").await.unwrap(),
        UdpSocket::bind("127.0.0.1:0").await.unwrap(),
    ];
    let signal = hard_hard_fallback_signal(
        control,
        1,
        blackholes
            .iter()
            .map(|socket| socket.local_addr().unwrap())
            .collect(),
    );
    let deduplicator = PunchAttemptDeduplicator::default();
    let (shutdown_tx, shutdown_rx) = watch::channel(false);

    spawn_hole_punch_task_with_lifecycle(
        udp,
        peers.clone(),
        deduplicator.clone(),
        HARD_HARD_B.to_string(),
        Duration::from_millis(1),
        1,
        None,
        Some(signal),
        None,
        None,
        Some(shutdown_rx),
    )
    .await;
    assert_eq!(
        deduplicator.active_session_count(),
        1,
        "the initiator measurement must own its punch permit before detaching"
    );

    shutdown_tx.send(true).unwrap();
    let replacement_generation = peers
        .advance_network_generation("supersede Hard-Hard UDP invocation")
        .await;
    timeout(Duration::from_secs(1), async {
        while deduplicator.active_session_count() != 0 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("the old invocation must cancel and release its exact Hard-Hard permit");
    sleep(Duration::from_millis(150)).await;

    let conn = peers.get_connection(HARD_HARD_B).await.unwrap();
    assert!(
        !conn.direct_events.iter().any(|event| {
            event.network_generation == replacement_generation
                && matches!(
                    event.stage.as_str(),
                    "hard_hard_measurement_failed"
                        | "hard_hard_measurement_fenced"
                        | "hard_hard_prediction_signaled"
                        | "hard_hard_advertisement_failed"
                        | "punch_started"
                )
        }),
        "a cancelled old Hard-Hard invocation must not publish or write recovery progress into the replacement generation"
    );
}

#[tokio::test(flavor = "current_thread")]
async fn hard_hard_failed_preledger_measurement_releases_udp_lifecycle_watcher() {
    let (_daemon, peers, udp, control) = build_hard_hard_ordinary_fallback_fixture().await;
    let blackholes = [
        UdpSocket::bind("127.0.0.1:0").await.unwrap(),
        UdpSocket::bind("127.0.0.1:0").await.unwrap(),
        UdpSocket::bind("127.0.0.1:0").await.unwrap(),
    ];
    let signal = hard_hard_fallback_signal(
        control,
        1,
        blackholes
            .iter()
            .map(|socket| socket.local_addr().unwrap())
            .collect(),
    );
    let deduplicator = PunchAttemptDeduplicator::default();
    let (shutdown_tx, shutdown_rx) = watch::channel(false);

    spawn_hole_punch_task_with_lifecycle(
        udp,
        peers.clone(),
        deduplicator.clone(),
        HARD_HARD_B.to_string(),
        Duration::from_millis(1),
        1,
        None,
        Some(signal),
        None,
        None,
        Some(shutdown_rx),
    )
    .await;
    wait_for_stage(&peers, HARD_HARD_B, "hard_hard_measurement_failed").await;

    timeout(Duration::from_secs(1), async {
        while shutdown_tx.receiver_count() != 0 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("a pre-ledger failure must cancel its handle and let the lease watcher exit");
    assert_eq!(
        deduplicator.active_session_count(),
        0,
        "the failed measurement must also release its short-lived punch owner"
    );
    assert!(
        !*shutdown_tx.borrow(),
        "the watcher must exit because its exact session was cancelled, not because the UDP lease ended"
    );
}

#[tokio::test(flavor = "current_thread")]
async fn hard_hard_lifecycle_watcher_exits_when_session_finishes_first() {
    let (_shutdown_tx, shutdown_rx) = watch::channel(false);
    let cancellation = Arc::new(crate::PunchSessionCancellation::default());
    bind_hard_hard_session_to_punch_invocation(Some(shutdown_rx), cancellation.clone());
    assert!(
        Arc::strong_count(&cancellation) >= 2,
        "the lifecycle watcher must own the exact session cancellation handle"
    );

    cancellation.cancel_for_hard_hard_cleanup();
    timeout(Duration::from_secs(1), async {
        while Arc::strong_count(&cancellation) != 1 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("a completed/removed session must not retain a watcher until the UDP lease ends");
}

#[tokio::test(flavor = "current_thread")]
async fn hard_hard_preflight_failure_falls_through_to_ordinary_punch() {
    let (_daemon, peers, udp, control) = build_hard_hard_ordinary_fallback_fixture().await;
    let signal = hard_hard_fallback_signal(control, 0, Vec::new());

    spawn_hole_punch_task(
        udp,
        peers.clone(),
        PunchAttemptDeduplicator::default(),
        HARD_HARD_B.to_string(),
        Duration::from_millis(1),
        1,
        None,
        Some(signal),
        None,
        None,
    )
    .await;

    let fallback = wait_for_stage(&peers, HARD_HARD_B, "hard_hard_fallback_to_ordinary").await;
    assert!(fallback.detail.contains("reason=boot_epoch_unavailable"));
    wait_for_stage(&peers, HARD_HARD_B, "punch_started").await;
}

#[tokio::test(flavor = "current_thread")]
async fn hard_hard_insufficient_stun_falls_through_to_ordinary_punch() {
    let (_daemon, peers, udp, control) = build_hard_hard_ordinary_fallback_fixture().await;
    let blackholes = [
        UdpSocket::bind("127.0.0.1:0").await.unwrap(),
        UdpSocket::bind("127.0.0.1:0").await.unwrap(),
    ];
    let signal = hard_hard_fallback_signal(
        control,
        1,
        blackholes
            .iter()
            .map(|socket| socket.local_addr().unwrap())
            .collect(),
    );

    spawn_hole_punch_task(
        udp,
        peers.clone(),
        PunchAttemptDeduplicator::default(),
        HARD_HARD_B.to_string(),
        Duration::from_millis(1),
        1,
        None,
        Some(signal),
        None,
        None,
    )
    .await;

    let fallback = wait_for_stage(&peers, HARD_HARD_B, "hard_hard_fallback_to_ordinary").await;
    assert!(fallback
        .detail
        .contains("reason=insufficient_stun_observers"));
    wait_for_stage(&peers, HARD_HARD_B, "punch_started").await;
}

#[tokio::test(flavor = "current_thread")]
async fn hard_hard_responder_without_stun_worker_falls_back_to_admitted_fresh_punch() {
    // The Hard-Hard clock override is process-global so spawned E2E workers can
    // observe it. Serialize this real-clock assertion with those fixtures, and
    // clear any previous override only after owning their shared guard.
    let _serial = HARD_HARD_E2E_SERIAL.acquire().await.unwrap();
    set_hard_hard_test_now_ms(None);
    let _clock = HardHardClockReset;
    let (daemon, peers, udp, _control) = build_hard_hard_ordinary_fallback_fixture().await;
    let local_endpoint = udp.local_addr().unwrap();
    daemon
        .publish_candidate_snapshot(
            vec![local_endpoint.to_string()],
            HashMap::from([(local_endpoint.to_string(), "host".to_string())]),
            vec!["hard-hard-responder-fallback".to_string()],
        )
        .await;
    *daemon.udp_transport.write().await = Some(udp);
    daemon.runtime_stun_servers.write().await.clear();

    let plan = peers
        .hard_hard_plan_for_peer(HARD_HARD_B)
        .await
        .expect("fixture must retain its Hard↔Hard plan");
    let remote_prediction: SocketAddr = "198.51.100.20:42000".parse().unwrap();
    let coordination = HardHardCoordination {
        role: HardHardRole::Initiator,
        token: "feed-face".to_string(),
        local_network_generation: 0,
        remote_candidate_epoch: plan.remote_candidate_epoch,
        local_profile_generation: plan.remote_profile_generation,
        remote_profile_generation: plan.local_profile_generation,
        local_prediction_confidence: 90,
        remote_prediction_confidence: 0,
        local_prediction_model: "fixed_step".to_string(),
        remote_prediction_model: "unknown".to_string(),
        remote_network_generation: 0,
    };
    let punch_at_ms = hard_hard_now_for_test().saturating_add(3_500);
    let offer = PendingPeerOffer {
        from_node_id: HARD_HARD_B.to_string(),
        candidates: vec![remote_prediction.to_string()],
        candidate_sources: HashMap::new(),
        candidate_generation: 1,
        network_generation: peers.current_network_generation_sync(),
        peer_session_generation: peers.peer_session_generation_sync(HARD_HARD_B),
        candidates_expires_at_ms: Some(punch_at_ms.saturating_add(30_000)),
        sender_public_key: None,
        handshake_init: Vec::new(),
        punch_at_ms: Some(punch_at_ms),
        punch_at_server_ms: None,
        session_id: Some(coordination.encode()),
        probe_ephemeral_public_key: None,
        delivery_receipt: None,
    };

    daemon
        .apply_deferred_peer_offer_punch(
            &offer,
            CandidateSetApplyResult::Applied,
            FreshPunchDecision::Fresh(
                crate::FreshPredictionId {
                    boot_epoch: 1,
                    generation: 1,
                },
                vec![remote_prediction],
            ),
        )
        .await;

    wait_for_stage(&peers, HARD_HARD_B, "hard_hard_skipped").await;
    wait_for_stage(&peers, HARD_HARD_B, "punch_scheduled").await;
    assert!(
        !peers.hard_hard_session_is_active(HARD_HARD_B).await,
        "a responder which never claimed a Hard↔Hard worker must not leave a handled session"
    );
}

#[tokio::test(flavor = "current_thread")]
async fn hard_hard_async_failure_uses_next_trigger_for_ordinary_punch() {
    let (_daemon, peers, udp, control) = build_hard_hard_ordinary_fallback_fixture().await;
    // Bound three sockets that intentionally never answer STUN.  This admits
    // Hard↔Hard, then deterministically fails its asynchronous measurement.
    let blackholes = [
        UdpSocket::bind("127.0.0.1:0").await.unwrap(),
        UdpSocket::bind("127.0.0.1:0").await.unwrap(),
        UdpSocket::bind("127.0.0.1:0").await.unwrap(),
    ];
    let stun_servers = blackholes
        .iter()
        .map(|socket| socket.local_addr().unwrap())
        .collect::<Vec<_>>();
    let signal = hard_hard_fallback_signal(control, 1, stun_servers);
    let deduplicator = PunchAttemptDeduplicator::default();

    spawn_hole_punch_task(
        udp.clone(),
        peers.clone(),
        deduplicator.clone(),
        HARD_HARD_B.to_string(),
        Duration::from_millis(1),
        1,
        None,
        Some(signal.clone()),
        None,
        None,
    )
    .await;
    wait_for_stage(&peers, HARD_HARD_B, "hard_hard_measurement_failed").await;
    assert!(
        !peers
            .get_connection(HARD_HARD_B)
            .await
            .unwrap()
            .direct_events
            .iter()
            .any(|event| event.stage == "punch_started"),
        "the trigger owned by the asynchronous Hard↔Hard attempt must not also start ordinary punching"
    );

    // A recovery epoch permits exactly one fresh generation.  Once the failed
    // worker releases its punch permit, the next trigger observes that spent
    // quota, returns NotStarted, and must continue through ordinary punching.
    spawn_hole_punch_task(
        udp,
        peers.clone(),
        deduplicator,
        HARD_HARD_B.to_string(),
        Duration::from_millis(1),
        1,
        None,
        Some(signal),
        None,
        None,
    )
    .await;
    let fallback = wait_for_stage(&peers, HARD_HARD_B, "hard_hard_fallback_to_ordinary").await;
    assert!(fallback
        .detail
        .contains("reason=fresh_generation_quota_exhausted"));
    wait_for_stage(&peers, HARD_HARD_B, "punch_started").await;
}

#[tokio::test(flavor = "current_thread")]
async fn hard_hard_initiator_deferred_claim_refunds_exact_fresh_quota() {
    let (_daemon, peers, udp, control) = build_hard_hard_ordinary_fallback_fixture().await;
    let blackholes = [
        UdpSocket::bind("127.0.0.1:0").await.unwrap(),
        UdpSocket::bind("127.0.0.1:0").await.unwrap(),
        UdpSocket::bind("127.0.0.1:0").await.unwrap(),
    ];
    let signal = hard_hard_fallback_signal(
        control,
        1,
        blackholes
            .iter()
            .map(|socket| socket.local_addr().unwrap())
            .collect(),
    );
    let deduplicator = PunchAttemptDeduplicator::default();
    let epoch = match peers.recovery_epoch_admit(HARD_HARD_B).await {
        RecoveryAdmission::Accepted { epoch } => epoch,
        admission => panic!("fixture recovery must be admitted: {admission:?}"),
    };
    let existing = match deduplicator
        .claim_for_epoch_with_rendezvous(
            HARD_HARD_B,
            peers.current_network_generation_sync(),
            epoch,
            PUNCH_PRIORITY_FRESH_PREDICTION,
            None,
            None,
        )
        .await
    {
        RendezvousPunchClaim::Claimed(session) => session,
        RendezvousPunchClaim::Deferred(_) => panic!("fixture fresh owner must claim"),
        RendezvousPunchClaim::RejectedStalePeerSession => {
            panic!("fixture lifecycle must not be retired")
        }
    };

    assert_eq!(
        spawn_hard_hard_initiator(
            udp,
            peers.clone(),
            deduplicator,
            HARD_HARD_B.to_string(),
            signal,
            None,
        )
        .await,
        HardHardInitiatorStart::ExistingPunchOwner,
    );
    assert_eq!(
        peers
            .recovery_epoch_work_budget_report(HARD_HARD_B)
            .await
            .expect("the recovery epoch must remain active")
            .fresh_generations_remaining,
        1,
        "an initiator which never acquired the punch owner must refund its exact reservation"
    );
    assert_eq!(
        peers
            .recovery_epoch_work_budget_report(HARD_HARD_B)
            .await
            .expect("the recovery epoch must remain active")
            .hard_hard_generations_remaining,
        1,
        "the dedicated Hard↔Hard fresh-generation lane must not be consumed by a deferred claim"
    );
    assert!(!existing.is_cancelled());
}

#[tokio::test(flavor = "current_thread")]
async fn hard_hard_response_network_generation_fence_precedes_punch_preemption() {
    let (_daemon, peers, udp, _control) = build_hard_hard_ordinary_fallback_fixture().await;
    let plan = peers
        .hard_hard_plan_for_peer(HARD_HARD_B)
        .await
        .expect("fixture must retain its Hard↔Hard plan");
    let punch_at_ms = hard_hard_now_for_test().saturating_add(3_500);
    let token = "network-fence-before-claim".to_string();
    let socket_local_endpoint = udp.local_addr().unwrap();
    let remote_prediction: SocketAddr = "198.51.100.20:42000".parse().unwrap();
    assert!(
        peers
            .hard_hard_register_session(peer::HardHardSessionRecord {
                session_id: format!("hh1:i:{token}"),
                probe_session_id: None,
                session_token: token.clone(),
                peer_id: HARD_HARD_B.to_string(),
                initiator: true,
                remote_network_generation: 0,
                local_network_generation: plan.local_network_generation,
                remote_candidate_epoch: plan.remote_candidate_epoch,
                local_profile_generation: plan.local_profile_generation,
                remote_profile_generation: plan.remote_profile_generation,
                local_prediction_confidence: 95,
                remote_prediction_confidence: 0,
                requested_birthday_level: 0,
                generated_candidate_count: 1,
                signaled_candidate_count: 1,
                birthday: false,
                requested_socket_indices: vec![4096],
                requested_socket_count: 1,
                prediction_window: vec![remote_prediction],
                remote_prediction: Vec::new(),
                fresh_socket: peer::HardHardFreshSocketIdentity {
                    peer_id: HARD_HARD_B.to_string(),
                    session_token: token.clone(),
                    network_generation: plan.local_network_generation,
                    remote_candidate_epoch: plan.remote_candidate_epoch,
                    local_profile_generation: plan.local_profile_generation,
                    remote_profile_generation: plan.remote_profile_generation,
                    punch_generation: 1,
                    socket_index: 4096,
                    socket_local_endpoint,
                },
                punch_at_ms,
                expires_at_ms: punch_at_ms.saturating_add(30_000),
                state: peer::HardHardSessionState::AwaitingPeer,
                attempt_count: 0,
                measurement: peer::HardHardMeasurementObservation::default(),
                created_at: Instant::now(),
                cancellation: Arc::new(crate::PunchSessionCancellation::default()),
            })
            .await
    );
    let epoch = match peers.recovery_epoch_admit(HARD_HARD_B).await {
        RecoveryAdmission::Accepted { epoch } => epoch,
        admission => panic!("fixture recovery must be admitted: {admission:?}"),
    };
    let deduplicator = PunchAttemptDeduplicator::default();
    let ordinary = match deduplicator
        .claim_for_epoch_with_rendezvous(
            HARD_HARD_B,
            plan.local_network_generation,
            epoch,
            PUNCH_PRIORITY_SYNCHRONIZED,
            None,
            Some(punch_at_ms),
        )
        .await
    {
        RendezvousPunchClaim::Claimed(session) => session,
        RendezvousPunchClaim::Deferred(_) => panic!("ordinary fixture must claim first"),
        RendezvousPunchClaim::RejectedStalePeerSession => {
            panic!("fixture lifecycle must not be retired")
        }
    };

    let disposition = spawn_hard_hard_initiator_response(
        udp,
        peers,
        deduplicator,
        HARD_HARD_B.to_string(),
        HardHardCoordination {
            role: HardHardRole::Responder,
            token,
            local_network_generation: 9,
            remote_candidate_epoch: plan.remote_candidate_epoch,
            local_profile_generation: plan.remote_profile_generation,
            remote_profile_generation: plan.local_profile_generation,
            local_prediction_confidence: 90,
            remote_prediction_confidence: 95,
            local_prediction_model: "fixed_step".to_string(),
            remote_prediction_model: "fixed_step".to_string(),
            // Deliberately invalid: this must fence before a priority-2 claim
            // can cancel the ordinary priority-1 owner.
            remote_network_generation: plan.local_network_generation.saturating_add(1),
        },
        vec![remote_prediction],
        punch_at_ms,
    )
    .await;
    assert_eq!(disposition, HardHardRemoteStart::Rejected);
    assert!(
        !ordinary.is_cancelled(),
        "a generation-mismatched response must not preempt the existing ordinary owner"
    );
}

#[tokio::test(flavor = "current_thread")]
async fn stale_fresh_reservation_cannot_refund_recreated_numeric_epoch() {
    let (_daemon, peers, _udp, _control) = build_hard_hard_ordinary_fallback_fixture().await;
    let old_epoch = match peers.recovery_epoch_admit(HARD_HARD_B).await {
        RecoveryAdmission::Accepted { epoch } => epoch,
        admission => panic!("old recovery epoch must be admitted: {admission:?}"),
    };
    let old_reservation = peers
        .try_begin_fresh_generation_for_epoch(HARD_HARD_B, old_epoch)
        .await
        .expect("old epoch must reserve its fresh quota");

    peers
        .recovery_epoch_end(HARD_HARD_B, "test_recreate_numeric_epoch")
        .await;
    let new_epoch = match peers.recovery_epoch_admit(HARD_HARD_B).await {
        RecoveryAdmission::Accepted { epoch } => epoch,
        admission => panic!("replacement recovery epoch must be admitted: {admission:?}"),
    };
    assert_eq!(
        new_epoch, old_epoch,
        "the regression fixture must reproduce numeric recovery-epoch ABA"
    );
    let new_reservation = peers
        .try_begin_fresh_generation_for_epoch(HARD_HARD_B, new_epoch)
        .await
        .expect("replacement epoch must independently reserve its quota");

    old_reservation.refund().await;
    assert_eq!(
        peers
            .recovery_epoch_work_budget_report(HARD_HARD_B)
            .await
            .expect("replacement epoch must remain active")
            .fresh_generations_remaining,
        0,
        "an old allocation token must not replenish the replacement epoch"
    );
    new_reservation.refund().await;
}

#[tokio::test(flavor = "current_thread")]
async fn dropped_fresh_reservation_refunds_after_epoch_lock_contention() {
    let (_daemon, peers, _udp, _control) = build_hard_hard_ordinary_fallback_fixture().await;
    let epoch = match peers.recovery_epoch_admit(HARD_HARD_B).await {
        RecoveryAdmission::Accepted { epoch } => epoch,
        admission => panic!("recovery epoch must be admitted: {admission:?}"),
    };
    let reservation = peers
        .try_begin_fresh_generation_for_epoch(HARD_HARD_B, epoch)
        .await
        .expect("fixture must reserve the sole fresh quota");
    let reached = Arc::new(Notify::new());
    let release = Arc::new(Notify::new());
    let holder = tokio::spawn({
        let peers = peers.clone();
        let reached = reached.clone();
        let release = release.clone();
        async move {
            peers
                .hold_recovery_epoch_write_for_test(reached, release)
                .await;
        }
    });
    reached.notified().await;

    // Models an outer UDP-lease select dropping the Hard↔Hard future while
    // its explicit refund is blocked behind the epoch writer.
    drop(reservation);
    release.notify_one();
    holder.await.unwrap();
    timeout(Duration::from_secs(1), async {
        loop {
            if peers
                .recovery_epoch_work_budget_report(HARD_HARD_B)
                .await
                .is_some_and(|budget| budget.fresh_generations_remaining == 1)
            {
                return;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("cancelling the reservation owner must asynchronously refund the exact epoch");
}

async fn hard_hard_two_peer_success_with_stun(stun: HarnessStunProfile) {
    hard_hard_two_peer_success_with_stun_and_mtu(stun, [65_535, 65_535]).await;
}

async fn hard_hard_two_peer_success_with_stun_and_mtu(stun: HarnessStunProfile, mtu: [u64; 2]) {
    let _serial = HARD_HARD_E2E_SERIAL.acquire().await.unwrap();
    let now = hard_hard_now_for_test();
    set_hard_hard_test_now_ms(Some(now));
    let _clock = HardHardClockReset;
    let harness = build_two_peer_harness_with_stun(true, false, false, stun).await;
    for (direction, limit) in harness.link.mtu.iter().zip(mtu) {
        direction.ip_mtu.store(limit, Ordering::Release);
    }
    // Keep this scenario scoped to the production Hard-Hard path. The
    // peer-reflexive worker also owns an ordinary primary-socket fast punch;
    // under a loaded libtest runtime that independent path can legitimately
    // become Direct first and turn this exact-socket test into the competing
    // primary scenario covered separately below. The encrypted-validation
    // workers remain live, so Hard-Hard still has to prove the real dynamic
    // socket through the complete Request/ACK path.
    for task in &harness.peer_reflexive_tasks {
        task.abort();
    }
    trigger_initial_offer(&harness).await;
    wait_for_both_direct(&harness).await;
    // Reciprocal exact-socket traffic can promote both peers before the
    // non-owner reaches its scheduled sweep.  Require the authoritative path
    // outcome on both sides and proof that at least one real sweep owner
    // completed; do not require a redundant post-Direct sweep from both.
    let sweep_detail = timeout(Duration::from_secs(3), async {
        loop {
            for (peers, peer_id) in [
                (&harness.peers_a, HARD_HARD_B),
                (&harness.peers_b, HARD_HARD_A),
            ] {
                if let Some(detail) = peers.get_connection(peer_id).await.and_then(|connection| {
                    connection
                        .direct_events
                        .iter()
                        .find(|event| event.stage == "hard_hard_sweep_completed")
                        .map(|event| event.detail.clone())
                }) {
                    return detail;
                }
            }
            sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("at least one exact-socket Hard↔Hard owner must complete its sweep");
    assert!(sweep_detail.contains("exact_socket=true"));
    assert!(sweep_detail.contains("direct_confirmed=true"));

    let fresh_direct_a =
        wait_for_current_fresh_direct(&harness.peers_a, &harness.udp_a, HARD_HARD_B).await;
    let fresh_direct_b =
        wait_for_current_fresh_direct(&harness.peers_b, &harness.udp_b, HARD_HARD_A).await;
    let peer_a = fresh_direct_a.diagnostics;
    let peer_b = fresh_direct_b.diagnostics;
    for diagnostics in [&peer_a, &peer_b] {
        assert_eq!(diagnostics.state, ConnectionState::Direct);
        assert_eq!(diagnostics.active_path, Some(NetworkPath::Direct));
    }

    let measured_a = fresh_direct_a.socket_index;
    let measured_b = fresh_direct_b.socket_index;
    assert!(!fresh_direct_a.predicted_ports.is_empty());
    assert!(!fresh_direct_b.predicted_ports.is_empty());
    assert_eq!(
        Some(fresh_direct_a.socket_local_endpoint),
        harness
            .udp_a
            .socket_for_peer(Some(HARD_HARD_B))
            .await
            .and_then(|(_, socket)| socket.local_addr().ok())
    );
    assert_eq!(
        Some(fresh_direct_b.socket_local_endpoint),
        harness
            .udp_b
            .socket_for_peer(Some(HARD_HARD_A))
            .await
            .and_then(|(_, socket)| socket.local_addr().ok())
    );
    assert_eq!(
        harness
            .udp_a
            .affinity_pin_for_test(HARD_HARD_B)
            .await
            .map(|pin| pin.socket_index),
        Some(measured_a),
    );
    assert_eq!(
        harness
            .udp_b
            .affinity_pin_for_test(HARD_HARD_A)
            .await
            .map(|pin| pin.socket_index),
        Some(measured_b),
    );
    let current_pair_a = peer_a
        .current_direct_pair
        .as_ref()
        .expect("A must expose its selected Direct candidate pair");
    let current_pair_b = peer_b
        .current_direct_pair
        .as_ref()
        .expect("B must expose its selected Direct candidate pair");
    let expected_remote_a = harness.link.b_public.local_addr().unwrap();
    let expected_remote_b = harness.link.a_public.local_addr().unwrap();
    assert_eq!(
        current_pair_a.source,
        peer::CandidatePairSource::PeerReflexive
    );
    assert_eq!(
        current_pair_b.source,
        peer::CandidatePairSource::PeerReflexive
    );
    assert_eq!(
        current_pair_a.remote_endpoint,
        expected_remote_a.to_string()
    );
    assert_eq!(
        current_pair_b.remote_endpoint,
        expected_remote_b.to_string()
    );
    assert_eq!(
        current_pair_a.local_endpoint.as_deref(),
        Some(fresh_direct_a.socket_local_endpoint.to_string()).as_deref()
    );
    assert_eq!(
        current_pair_b.local_endpoint.as_deref(),
        Some(fresh_direct_b.socket_local_endpoint.to_string()).as_deref()
    );
    assert!(
        harness
            .udp_a
            .authenticated_evidence_for_socket(measured_a)
            .await
            > 0
    );
    assert!(
        harness
            .udp_b
            .authenticated_evidence_for_socket(measured_b)
            .await
            > 0
    );
    assert!(harness.udp_a.dynamic_socket_count().await >= 1);
    assert!(harness.udp_b.dynamic_socket_count().await >= 1);
    for (index, direction) in harness.link.mtu.iter().enumerate() {
        let largest = direction.max_udp_payload.load(Ordering::Relaxed);
        assert!(
            largest > 0,
            "both peers must transmit real control datagrams"
        );
        assert!(
            largest + 28 <= mtu[index],
            "control traffic exceeded IPv4 path MTU"
        );
        assert_eq!(direction.oversize_drops.load(Ordering::Relaxed), 0);
        println!(
            "HARD_HARD_MTU direction={} ip_mtu={} udp_budget={} max_udp_payload={} oversize_drops=0 direct=true",
            if index == 0 { "A->B" } else { "B->A" },
            mtu[index],
            mtu[index] - 28,
            largest,
        );
    }
    for signals in [&harness.signals_a, &harness.signals_b] {
        assert!(signals.lock().unwrap().iter().any(|signal| {
            signal.session_id.is_some()
                && signal
                    .candidate_sources
                    .values()
                    .any(|source| source.starts_with("predicted_fresh:"))
        }));
    }

    harness.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn hard_hard_two_peer_success_is_full_e2e_and_exact_socket() {
    hard_hard_two_peer_success_with_stun(HarnessStunProfile::FULL_CAPACITY).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn hard_hard_two_peer_success_with_minimum_stun_capacity() {
    hard_hard_two_peer_success_with_stun(HarnessStunProfile::MINIMUM_CAPACITY).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn hard_hard_asymmetric_mtu_500_900() {
    hard_hard_two_peer_success_with_stun_and_mtu(HarnessStunProfile::FULL_CAPACITY, [500, 900])
        .await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn hard_hard_random_random_birthday_collision_is_full_production_e2e() {
    let _serial = HARD_HARD_E2E_SERIAL.acquire().await.unwrap();
    let now = hard_hard_now_for_test();
    set_hard_hard_test_now_ms(Some(now));
    let _clock = HardHardClockReset;
    let harness = build_two_peer_harness_with_stun_mode(
        true,
        false,
        false,
        HarnessStunProfile::FULL_CAPACITY,
        HarnessNatMode::HighEntropy,
    )
    .await;

    for diagnostics in [
        harness.peers_a.diagnostics().await,
        harness.peers_b.diagnostics().await,
    ] {
        assert_eq!(
            diagnostics[0]
                .traversal_plan
                .as_ref()
                .map(|plan| plan.reason.as_str()),
            Some("hard_hard_bounded_birthday")
        );
    }

    trigger_initial_offer(&harness).await;
    wait_for_both_direct_compact(&harness).await;

    for (peers, remote_id, expected_remote) in [
        (
            &harness.peers_a,
            HARD_HARD_B,
            harness.link.b_public.local_addr().unwrap(),
        ),
        (
            &harness.peers_b,
            HARD_HARD_A,
            harness.link.a_public.local_addr().unwrap(),
        ),
    ] {
        let peer = wait_for_current_direct_diagnostics(peers, remote_id).await;
        assert_eq!(peer.state, ConnectionState::Direct);
        assert_eq!(peer.active_path, Some(NetworkPath::Direct));
        let observed = peer
            .direct_events
            .iter()
            .find(|event| event.stage == "hard_hard_fresh_mapping_observed")
            .or_else(|| {
                peer.direct_events
                    .iter()
                    .find(|event| event.stage == "hard_hard_local_nat_model")
            });
        if let Some(observed) = observed {
            assert!(observed.detail.contains("model=high_entropy"));
            assert!(observed.detail.contains("strategy=bounded_birthday"));
            assert!(observed.detail.contains("socket_count=2"));
        }
        let winner = peer
            .direct_events
            .iter()
            .find(|event| event.stage == "hard_hard_winner_selected")
            .expect("authenticated Probe v2 evidence must select a birthday winner");
        let winner_socket = winner.socket_index.expect("winner must name its socket");
        let winner_phase = if remote_id == HARD_HARD_B {
            harness
                .udp_a
                .dynamic_socket_phase_for_test(winner_socket)
                .await
        } else {
            harness
                .udp_b
                .dynamic_socket_phase_for_test(winner_socket)
                .await
        };
        assert_eq!(
            winner_phase,
            Some(crate::udp::DynamicSocketPhase::Finalized),
            "authenticated birthday winner must reach the Finalized phase: peer={} winner={} dynamic_count={} stages={:?}",
            peer.node_id,
            winner_socket,
            if remote_id == HARD_HARD_B {
                harness.udp_a.dynamic_socket_count().await
            } else {
                harness.udp_b.dynamic_socket_count().await
            },
            peer.direct_events
                .iter()
                .filter(|event| event.stage.starts_with("hard_hard_"))
                .map(|event| (event.stage.as_str(), event.detail.as_str()))
                .collect::<Vec<_>>(),
        );
        let affinity_socket = if remote_id == HARD_HARD_B {
            harness
                .udp_a
                .affinity_pin_for_test(remote_id)
                .await
                .map(|pin| pin.socket_index)
        } else {
            harness
                .udp_b
                .affinity_pin_for_test(remote_id)
                .await
                .map(|pin| pin.socket_index)
        };
        assert_eq!(affinity_socket, Some(winner_socket));
        let pair = peer
            .current_direct_pair
            .as_ref()
            .expect("Direct must expose the selected birthday pair");
        assert_eq!(pair.source, peer::CandidatePairSource::PeerReflexive);
        assert_eq!(pair.remote_endpoint, expected_remote.to_string());
    }
    let birthday_signals = [
        harness
            .signals_a
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clone(),
        harness
            .signals_b
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clone(),
    ];
    let birthday_signal_seen = birthday_signals
        .iter()
        .flat_map(|signals| signals.iter())
        .any(|signal| {
            signal
                .session_id
                .as_deref()
                .is_some_and(|session| session.contains("high_entropy"))
        });
    assert!(
        birthday_signal_seen,
        "the session envelope must identify the HighEntropy birthday lane"
    );

    let parse_count = |detail: &str, key: &str| {
        detail
            .split_whitespace()
            .find_map(|field| field.strip_prefix(key)?.parse::<usize>().ok())
    };
    // Read the durable connection ring, not the non-blocking diagnostics
    // cache. A reciprocal Direct promotion can still own the connections
    // writer when this assertion runs; the cache is allowed to return its
    // previous snapshot in that narrow interval.
    let birthday_events = timeout(HARD_HARD_E2E_TIMEOUT, async {
        loop {
            for (peers, peer_id) in [
                (&harness.peers_a, HARD_HARD_B),
                (&harness.peers_b, HARD_HARD_A),
            ] {
                if let Some(connection) = peers.get_connection(peer_id).await {
                    let events = connection
                        .direct_events
                        .into_iter()
                        .filter(|event| {
                            event.stage == "hard_hard_birthday_sweep_summary"
                                && event.detail.contains("requested_level=64")
                        })
                        .collect::<Vec<_>>();
                    if !events.is_empty() {
                        return events;
                    }
                }
            }
            sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("production birthday sweep must report its bounded send count");
    let mut birthday_summaries = 0;
    for event in &birthday_events {
        let sent = parse_count(&event.detail, "packets_sent=")
            .expect("birthday summary must report sent packets");
        let unique = parse_count(&event.detail, "unique_target_endpoints=")
            .expect("birthday summary must report unique target endpoints");
        let effective_target_count = parse_count(&event.detail, "effective_target_count=")
            .expect("birthday summary must report effective target count");
        let generated_candidate_count = parse_count(&event.detail, "generated_candidate_count=")
            .expect("birthday summary must report generated candidates");
        let signaled_candidate_count = parse_count(&event.detail, "signaled_candidate_count=")
            .expect("birthday summary must report signaled candidates");
        let requested_socket_count = parse_count(&event.detail, "requested_socket_count=")
            .expect("birthday summary must report requested sockets");
        let attached_socket_count = parse_count(&event.detail, "attached_socket_count=")
            .expect("birthday summary must report attached sockets");
        let usable_socket_count = parse_count(&event.detail, "usable_socket_count=")
            .expect("birthday summary must report usable sockets");
        let unavailable_socket_count = parse_count(&event.detail, "unavailable_socket_count=")
            .expect("birthday summary must report unavailable sockets");
        let packets_planned = parse_count(&event.detail, "packets_planned=")
            .expect("birthday summary must report planned packets");
        let waves_planned = parse_count(&event.detail, "waves_planned=")
            .expect("birthday summary must report planned waves");
        let waves_started = parse_count(&event.detail, "waves_started=")
            .expect("birthday summary must report started waves");
        let waves_fully_completed = parse_count(&event.detail, "waves_fully_completed=")
            .expect("birthday summary must report fully completed waves");
        let targets_assigned = parse_count(&event.detail, "targets_assigned=")
            .expect("birthday summary must report assigned targets");
        let targets_examined = parse_count(&event.detail, "targets_examined=")
            .expect("birthday summary must report examined targets");
        let targets_attempted = parse_count(&event.detail, "targets_attempted=")
            .expect("birthday summary must report attempted targets");
        let logical_probes_attempted = parse_count(&event.detail, "logical_probes_attempted=")
            .expect("birthday summary must report logical attempts");
        let logical_probes_sent = parse_count(&event.detail, "logical_probes_sent=")
            .expect("birthday summary must report logical probes");
        let physical_datagrams_sent = parse_count(&event.detail, "physical_datagrams_sent=")
            .expect("birthday summary must report physical datagrams");
        let physical_send_errors = parse_count(&event.detail, "physical_send_errors=")
            .expect("birthday summary must report physical send errors");
        let targets_cancelled = parse_count(&event.detail, "targets_cancelled=")
            .expect("birthday summary must report cancelled targets");
        assert_eq!(waves_planned, 2);
        assert_eq!(packets_planned, effective_target_count * 2);
        assert!(sent <= packets_planned);
        assert!(unique <= effective_target_count);
        assert!(generated_candidate_count >= signaled_candidate_count);
        assert_eq!(signaled_candidate_count, effective_target_count);
        assert_eq!(requested_socket_count, 2);
        assert!(attached_socket_count <= requested_socket_count);
        assert!(usable_socket_count <= attached_socket_count);
        assert_eq!(
            unavailable_socket_count,
            requested_socket_count - usable_socket_count
        );
        assert!(waves_fully_completed <= waves_started);
        assert!(waves_started <= waves_planned);
        assert!(targets_examined <= targets_assigned);
        assert!(targets_attempted <= targets_assigned);
        assert!(targets_attempted <= targets_examined);
        assert!(logical_probes_sent <= logical_probes_attempted);
        assert!(logical_probes_sent <= effective_target_count * 2);
        assert!(physical_datagrams_sent >= logical_probes_sent);
        assert!(physical_send_errors <= effective_target_count * 2);
        assert_eq!(targets_cancelled, targets_assigned - targets_attempted);
        assert!(event.detail.contains("first_send_at_ms="));
        assert!(event.detail.contains("last_send_at_ms="));
        assert!(event.detail.contains("stop_reason="));
        birthday_summaries += 1;
    }
    assert!(
        birthday_summaries > 0,
        "production birthday sweep must report its bounded send count"
    );

    timeout(Duration::from_secs(1), async {
        loop {
            if harness.udp_a.dynamic_socket_count().await == 1
                && harness.udp_b.dynamic_socket_count().await == 1
            {
                return;
            }
            sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("birthday losers must detach after the authenticated winner is selected");
    harness.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn hard_hard_physical_send_error_reaches_one_consistent_terminal_reason() {
    let _serial = HARD_HARD_E2E_SERIAL.acquire().await.unwrap();
    let now = hard_hard_now_for_test();
    set_hard_hard_test_now_ms(Some(now));
    let _clock = HardHardClockReset;
    let harness = build_two_peer_harness_with_stun_mode(
        true,
        false,
        false,
        HarnessStunProfile::FULL_CAPACITY,
        HarnessNatMode::HighEntropy,
    )
    .await;

    // This is the production Hard birthday entry point. Fail its first
    // physical UDP send at the shared send abstraction; the socket itself is
    // left open so this cannot be mistaken for socket_unavailable.
    let _send_failures = harness.udp_a.set_probe_send_failures_for_test(1..=512);
    let _peer_send_failures = harness.udp_b.set_probe_send_failures_for_test(1..=512);
    harness.link.set_drop_a_to_b(true);
    harness.link.set_drop_b_to_a(true);
    trigger_initial_offer(&harness).await;

    let summary = wait_for_stage(
        &harness.peers_a,
        HARD_HARD_B,
        "hard_hard_birthday_sweep_summary",
    )
    .await;
    assert!(summary.detail.contains("physical_send_errors="));
    assert!(
        summary.detail.contains("stop_reason=send_error"),
        "unexpected birthday summary: {}",
        summary.detail
    );
    assert!(!summary.detail.contains("stop_reason=socket_unavailable"));

    let sweep_failed =
        wait_for_stage(&harness.peers_a, HARD_HARD_B, "hard_hard_sweep_failed").await;
    let hard_failed = wait_for_stage(&harness.peers_a, HARD_HARD_B, "hard_hard_failed").await;
    assert!(sweep_failed.detail.contains("stop_reason=send_error"));
    assert!(hard_failed.detail.contains("stop_reason=send_error"));

    let summary_count = harness
        .peers_a
        .get_connection(HARD_HARD_B)
        .await
        .unwrap()
        .direct_events
        .iter()
        .filter(|event| event.stage == "hard_hard_birthday_sweep_summary")
        .count();
    assert_eq!(
        summary_count, 1,
        "one session must emit one final birthday summary"
    );
    harness.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn hard_hard_random_random_birthday_no_collision_cleans_up_without_direct() {
    let _serial = HARD_HARD_E2E_SERIAL.acquire().await.unwrap();
    let now = hard_hard_now_for_test();
    set_hard_hard_test_now_ms(Some(now));
    let _clock = HardHardClockReset;
    let harness = build_two_peer_harness_with_stun_mode(
        true,
        false,
        false,
        HarnessStunProfile::FULL_CAPACITY,
        HarnessNatMode::HighEntropy,
    )
    .await;
    harness.link.set_drop_a_to_b(true);
    harness.link.set_drop_b_to_a(true);
    // High-entropy candidates intentionally include the public endpoints that
    // the synthetic NAT owns.  Hold authenticated Punch packets as well as
    // dropping forwarded traffic so this no-collision fixture cannot race a
    // direct winner through the link's dynamic-socket fallback before either
    // birthday sweep reaches its terminal failure state.
    harness.link.set_hold_authenticated_punch(true);
    trigger_initial_offer(&harness).await;

    // Do not let the initial "not active and no sockets" state satisfy the
    // cleanup predicate before the control event has started either side's
    // session.  The two durable terminal events prove both birthday sweeps
    // actually ran; only then is it meaningful to assert complete cleanup.
    wait_for_both_sweep_failures(&harness).await;

    timeout(Duration::from_secs(5), async {
        loop {
            if !harness.peers_a.is_direct(HARD_HARD_B).await
                && !harness.peers_b.is_direct(HARD_HARD_A).await
                && !harness
                    .peers_a
                    .hard_hard_session_is_active(HARD_HARD_B)
                    .await
                && !harness
                    .peers_b
                    .hard_hard_session_is_active(HARD_HARD_A)
                    .await
                && harness.udp_a.dynamic_socket_count().await == 0
                && harness.udp_b.dynamic_socket_count().await == 0
                && harness
                    .udp_a
                    .hard_hard_pending_probe_count_for_test(HARD_HARD_B)
                    .await
                    == 0
                && harness
                    .udp_b
                    .hard_hard_pending_probe_count_for_test(HARD_HARD_A)
                    .await
                    == 0
            {
                return;
            }
            sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("bounded birthday no-collision session must terminate and clean up");

    for (peers, peer_id) in [
        (&harness.peers_a, HARD_HARD_B),
        (&harness.peers_b, HARD_HARD_A),
    ] {
        let peer = peers
            .get_connection(peer_id)
            .await
            .expect("the completed Hard↔Hard sweep must retain its peer lifecycle");
        assert!(peer.state != ConnectionState::Direct);
        assert!(!peer
            .direct_events
            .iter()
            .any(|event| event.stage == "hard_hard_winner_selected"));
    }
    assert_relay_remains_available(&harness).await;
    assert_eq!(
        harness
            .udp_a
            .hard_hard_pending_probe_count_for_test(HARD_HARD_B)
            .await,
        0
    );
    assert_eq!(
        harness
            .udp_b
            .hard_hard_pending_probe_count_for_test(HARD_HARD_A)
            .await,
        0
    );
    harness.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn hard_hard_birthday_production_cleanup_waits_for_udp_completion() {
    let _serial = HARD_HARD_E2E_SERIAL.acquire().await.unwrap();
    let now = hard_hard_now_for_test();
    set_hard_hard_test_now_ms(Some(now));
    let _clock = HardHardClockReset;
    let harness = build_two_peer_harness_with_stun_mode(
        true,
        false,
        false,
        HarnessStunProfile::FULL_CAPACITY,
        HarnessNatMode::HighEntropy,
    )
    .await;
    harness.link.set_drop_a_to_b(true);
    harness.link.set_drop_b_to_a(true);
    trigger_initial_offer(&harness).await;

    let record = timeout(HARD_HARD_E2E_TIMEOUT, async {
        loop {
            if let Some(record) = harness
                .peers_b
                .hard_hard_session_for_test(HARD_HARD_A)
                .await
            {
                if record.state != peer::HardHardSessionState::Retiring
                    && harness.udp_b.dynamic_socket_count().await > 0
                    && harness
                        .udp_b
                        .hard_hard_pending_probe_count_for_test(HARD_HARD_A)
                        .await
                        > 0
                {
                    return record;
                }
            }
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
    })
    .await
    .expect("production Birthday entry must expose a live socket and pending Probe");
    let (gate, _gate_guard) = harness.peers_b.install_hard_hard_cleanup_gate_for_test(
        &record.peer_id,
        &record.session_id,
        &record.session_token,
    );
    harness
        .peers_b
        .clear_hard_hard_sessions(Some(HARD_HARD_A))
        .await;
    timeout(Duration::from_secs(3), gate.wait_for_reached())
        .await
        .expect("production cleanup must reach the pre-UDP test gate");

    let retiring = harness
        .peers_b
        .hard_hard_session_snapshot_for_cleanup(
            &record.peer_id,
            &record.session_id,
            &record.session_token,
        )
        .await
        .expect("Retiring ledger entry must remain until UDP cleanup completes");
    assert_eq!(retiring.state, peer::HardHardSessionState::Retiring);
    assert!(
        !harness
            .peers_b
            .hard_hard_session_is_active(HARD_HARD_A)
            .await
    );
    assert!(harness.udp_b.dynamic_socket_count().await > 0);
    assert!(
        harness
            .udp_b
            .hard_hard_pending_probe_count_for_test(HARD_HARD_A)
            .await
            > 0
    );

    gate.release();
    timeout(Duration::from_secs(5), gate.wait_for_completed())
        .await
        .expect("production cleanup must publish completion after UDP cleanup");
    assert!(harness
        .peers_b
        .hard_hard_session_snapshot_for_cleanup(
            &record.peer_id,
            &record.session_id,
            &record.session_token,
        )
        .await
        .is_none());
    assert_eq!(harness.udp_b.dynamic_socket_count().await, 0);
    assert_eq!(
        harness
            .udp_b
            .hard_hard_pending_probe_count_for_test(HARD_HARD_A)
            .await,
        0
    );
    harness.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn hard_hard_random_random_unauthenticated_packet_cannot_win() {
    let _serial = HARD_HARD_E2E_SERIAL.acquire().await.unwrap();
    let now = hard_hard_now_for_test();
    set_hard_hard_test_now_ms(Some(now));
    let _clock = HardHardClockReset;
    let harness = build_two_peer_harness_with_stun_mode(
        true,
        false,
        false,
        HarnessStunProfile::FULL_CAPACITY,
        HarnessNatMode::HighEntropy,
    )
    .await;
    harness.link.set_drop_a_to_b(true);
    harness.link.set_drop_b_to_a(true);
    trigger_initial_offer(&harness).await;
    let _ = wait_for_hard_hard_response_signal(&harness).await;
    // The exact dynamic socket is durable production state; the diagnostic
    // ring is intentionally bounded and may evict `hard_hard_sweep_started`
    // after a 128-probe burst before this test's polling task runs.
    let (_, speculative_socket) = timeout(HARD_HARD_E2E_TIMEOUT, async {
        loop {
            if let Some(socket) = harness.udp_a.socket_for_peer(Some(HARD_HARD_B)).await {
                return socket;
            }
            sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("birthday sweep must expose a speculative socket");
    let injector = UdpSocket::bind("127.0.0.1:0".parse::<SocketAddr>().unwrap())
        .await
        .unwrap();
    injector
        .send_to(
            b"not-a-probe-v2-packet",
            speculative_socket.local_addr().unwrap(),
        )
        .await
        .unwrap();
    sleep(Duration::from_millis(50)).await;
    for (peers, peer_id) in [
        (&harness.peers_a, HARD_HARD_B),
        (&harness.peers_b, HARD_HARD_A),
    ] {
        // `diagnostics()` is a non-blocking snapshot and can legitimately
        // return its still-empty cache while the connection-map writer is
        // busy. The peer lifecycle itself is the authoritative state here.
        let peer = peers
            .get_connection(peer_id)
            .await
            .expect("the seeded Hard↔Hard peer must remain in the lifecycle map");
        assert!(!peer
            .direct_events
            .iter()
            .any(|event| event.stage == "hard_hard_winner_selected"));
        assert_ne!(peer.state, ConnectionState::Direct);
    }
    drop(injector);
    harness.shutdown().await;

    // A fresh production session must still select an authenticated birthday
    // winner; the raw packet above is the only input in the first session.
    set_hard_hard_test_now_ms(Some(hard_hard_now_for_test()));
    let valid_harness = build_two_peer_harness_with_stun_mode(
        true,
        false,
        false,
        HarnessStunProfile::FULL_CAPACITY,
        HarnessNatMode::HighEntropy,
    )
    .await;
    // Keep validation ingress live in this fresh production session. The
    // first harness above already proves that a malformed datagram cannot
    // select a winner; this session must exercise the normal authenticated
    // birthday path without pausing or dropping its legal validation evidence.
    trigger_initial_offer(&valid_harness).await;
    wait_for_both_direct_compact(&valid_harness).await;
    let valid_a_connection = timeout(HARD_HARD_E2E_TIMEOUT, async {
        loop {
            if let Some(connection) = valid_harness.peers_a.get_connection(HARD_HARD_B).await {
                if connection.state == ConnectionState::Direct
                    && connection.active_path() == Some(NetworkPath::Direct)
                    && connection.candidate_pairs.iter().any(|pair| {
                        pair.state == peer::CandidatePairState::Selected
                            && pair.source == peer::CandidatePairSource::PeerReflexive
                    })
                {
                    return connection;
                }
            }
            sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .expect(
        "a fresh production session must promote an authenticated peer-reflexive birthday pair",
    );
    assert_eq!(valid_a_connection.state, ConnectionState::Direct);
    let valid_b_connection = timeout(HARD_HARD_E2E_TIMEOUT, async {
        loop {
            if let Some(connection) = valid_harness.peers_b.get_connection(HARD_HARD_A).await {
                if connection.state == ConnectionState::Direct
                    && connection.active_path() == Some(NetworkPath::Direct)
                    && connection.candidate_pairs.iter().any(|pair| {
                        pair.state == peer::CandidatePairState::Selected
                            && pair.source == peer::CandidatePairSource::PeerReflexive
                    })
                {
                    return connection;
                }
            }
            sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("the reciprocal production session must promote an authenticated peer-reflexive birthday pair");
    assert_eq!(valid_b_connection.state, ConnectionState::Direct);
    valid_harness.shutdown().await;
}

async fn install_direct_scheduler_birthday_session(
    peers: &Arc<PeerManager>,
    peer_id: &str,
    token: &str,
    plan: peer::HardHardPlanSnapshot,
    result: &crate::udp::HardHardBirthdayResult,
) {
    let socket = result
        .sockets
        .first()
        .expect("a Birthday scheduler session needs one exact socket");
    let identity = peer::HardHardFreshSocketIdentity {
        peer_id: peer_id.to_string(),
        session_token: token.to_string(),
        network_generation: plan.local_network_generation,
        remote_candidate_epoch: plan.remote_candidate_epoch,
        local_profile_generation: plan.local_profile_generation,
        remote_profile_generation: plan.remote_profile_generation,
        punch_generation: socket.punch_generation,
        socket_index: socket.socket_index,
        socket_local_endpoint: socket.socket_local_endpoint,
    };
    let now = hard_hard_now_for_test();
    assert!(
        peers
            .hard_hard_register_session(peer::HardHardSessionRecord {
                session_id: format!("birthday-scheduler-{token}"),
                probe_session_id: None,
                session_token: token.to_string(),
                peer_id: peer_id.to_string(),
                initiator: true,
                remote_network_generation: 0,
                local_network_generation: plan.local_network_generation,
                remote_candidate_epoch: plan.remote_candidate_epoch,
                local_profile_generation: plan.local_profile_generation,
                remote_profile_generation: plan.remote_profile_generation,
                local_prediction_confidence: 90,
                remote_prediction_confidence: 0,
                requested_birthday_level: result.requested_level,
                generated_candidate_count: result.requested_level,
                signaled_candidate_count: result
                    .candidate_endpoints
                    .len()
                    .min(crate::MAX_SIGNAL_CANDIDATES),
                birthday: true,
                requested_socket_indices: result
                    .sockets
                    .iter()
                    .map(|socket| socket.socket_index)
                    .collect(),
                requested_socket_count: result.requested_socket_count,
                prediction_window: result.candidate_endpoints.clone(),
                remote_prediction: Vec::new(),
                fresh_socket: identity,
                punch_at_ms: now,
                expires_at_ms: now.saturating_add(30_000),
                state: peer::HardHardSessionState::AwaitingPeer,
                attempt_count: 0,
                measurement: peer::HardHardMeasurementObservation::default(),
                created_at: Instant::now(),
                cancellation: Arc::new(crate::PunchSessionCancellation::default()),
            })
            .await
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn hard_hard_birthday_levels_report_requested_and_actual_socket_counts() {
    let _serial = HARD_HARD_E2E_SERIAL.acquire().await.unwrap();
    for (requested_level, expected_socket_count) in [(64, 2), (128, 4)] {
        let now = hard_hard_now_for_test();
        set_hard_hard_test_now_ms(Some(now));
        let _clock = HardHardClockReset;
        let harness = build_two_peer_harness_with_stun_mode(
            true,
            false,
            false,
            HarnessStunProfile::FULL_CAPACITY,
            HarnessNatMode::HighEntropy,
        )
        .await;
        let observers = harness
            .stun_observers
            .iter()
            .take(4)
            .map(|observer| observer.endpoint)
            .collect::<Vec<_>>();
        let result = harness
            .udp_a
            .run_hard_hard_birthday_generation(
                HARD_HARD_B,
                &observers,
                Duration::from_millis(300),
                requested_level,
                &format!("level-{requested_level}"),
                None,
            )
            .await
            .expect("birthday generation must succeed below the socket cap");
        assert_eq!(result.requested_level, requested_level);
        assert_eq!(result.level, requested_level);
        assert_eq!(result.requested_socket_count, expected_socket_count);
        assert_eq!(result.sockets.len(), expected_socket_count);
        let plan = harness
            .peers_a
            .hard_hard_plan_for_peer(HARD_HARD_B)
            .await
            .expect("production scheduler test requires the live Hard plan");
        let peer_session_generation = harness
            .peers_a
            .peer_session_generation_sync(HARD_HARD_B)
            .expect("production scheduler test requires the live peer session");
        install_direct_scheduler_birthday_session(
            &harness.peers_a,
            HARD_HARD_B,
            &format!("level-{requested_level}"),
            plan,
            &result,
        )
        .await;
        // This case validates production scheduler accounting, not peer
        // convergence. Keep its targets on owned sink sockets so the
        // synthetic NAT link cannot turn the metadata assertion into a
        // competing Direct lifecycle transition.
        let mut scheduler_targets = Vec::with_capacity(requested_level);
        let mut scheduler_sinks = Vec::with_capacity(requested_level);
        for _ in 0..requested_level {
            let sink = UdpSocket::bind(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0))
                .await
                .expect("bind isolated Birthday scheduler sink");
            scheduler_targets.push(
                sink.local_addr()
                    .expect("isolated Birthday scheduler sink has an endpoint"),
            );
            scheduler_sinks.push(sink);
        }
        let scheduler_report = harness
            .udp_a
            .punch_hard_hard_birthday_candidates_with_metadata(
                HARD_HARD_B,
                result
                    .sockets
                    .iter()
                    .map(|socket| socket.socket_index)
                    .collect(),
                scheduler_targets,
                requested_level,
                requested_level,
                requested_level.min(crate::MAX_SIGNAL_CANDIDATES),
                peer_session_generation,
                (
                    plan.local_profile_generation,
                    plan.remote_profile_generation,
                ),
                &format!("level-{requested_level}"),
                None,
            )
            .await
            .expect("production Birthday scheduler must return a bounded report");
        let scheduler_birthday = scheduler_report
            .birthday
            .as_ref()
            .expect("Birthday scheduler must expose its report");
        assert_eq!(scheduler_birthday.requested_level, requested_level);
        assert_eq!(
            scheduler_birthday.generated_candidate_count,
            requested_level
        );
        assert_eq!(
            scheduler_birthday.signaled_candidate_count,
            requested_level.min(crate::MAX_SIGNAL_CANDIDATES)
        );
        assert_eq!(
            scheduler_birthday.effective_target_count,
            requested_level.min(crate::MAX_SIGNAL_CANDIDATES)
        );
        assert_eq!(
            scheduler_birthday.requested_socket_count,
            expected_socket_count
        );
        for socket in &result.sockets {
            assert!(socket.guard.finalize().await);
        }
        harness
            .udp_a
            .detach_hard_hard_sockets_for_token(
                HARD_HARD_B,
                &format!("level-{requested_level}"),
                None,
                "hard_hard_birthday_level_test_cleanup",
            )
            .await;
        harness.shutdown().await;
    }

    let now = hard_hard_now_for_test();
    set_hard_hard_test_now_ms(Some(now));
    let _clock = HardHardClockReset;
    let harness = build_two_peer_harness_with_stun_mode(
        true,
        false,
        false,
        HarnessStunProfile::FULL_CAPACITY,
        HarnessNatMode::HighEntropy,
    )
    .await;
    let observers = harness
        .stun_observers
        .iter()
        .take(4)
        .map(|observer| observer.endpoint)
        .collect::<Vec<_>>();
    let predecessor =
        install_committed_birthday_predecessor(&harness.peers_a, &harness.udp_a, HARD_HARD_B).await;
    let mut filler_guards = Vec::new();
    for index in 0..7 {
        let peer_id = format!("birthday-cap-filler-{index}");
        let (socket_index, socket) = harness.udp_a.bind_fresh_punch_socket().await.unwrap();
        filler_guards.push(
            harness
                .udp_a
                .attach_dynamic_punch_socket(
                    &peer_id,
                    socket_index,
                    socket,
                    harness.peers_a.current_network_generation_sync(),
                    10_000 + index as u64,
                    None,
                )
                .await
                .unwrap(),
        );
    }
    assert_eq!(harness.udp_a.dynamic_socket_count().await, 8);
    let token = "level-256-cap";
    let result = harness
        .udp_a
        .run_hard_hard_birthday_generation(
            HARD_HARD_B,
            &observers,
            Duration::from_millis(300),
            256,
            token,
            None,
        )
        .await
        .expect("capacity downgrade must keep a safe bounded birthday lane");
    assert_eq!(result.requested_level, 256);
    assert_eq!(result.requested_socket_count, 8);
    assert_eq!(result.level, 128);
    assert_eq!(result.sockets.len(), 4);
    let plan = harness
        .peers_a
        .hard_hard_plan_for_peer(HARD_HARD_B)
        .await
        .expect("production scheduler cap test requires the live Hard plan");
    let peer_session_generation = harness
        .peers_a
        .peer_session_generation_sync(HARD_HARD_B)
        .expect("production scheduler cap test requires the live peer session");
    install_direct_scheduler_birthday_session(&harness.peers_a, HARD_HARD_B, token, plan, &result)
        .await;
    let scheduler_targets = (0..256usize)
        .map(|index| {
            SocketAddr::new(
                IpAddr::V4(Ipv4Addr::LOCALHOST),
                41_000 + u16::try_from(index).expect("test target port fits in u16"),
            )
        })
        .collect::<Vec<_>>();
    let scheduler_report = harness
        .udp_a
        .punch_hard_hard_birthday_candidates_with_metadata(
            HARD_HARD_B,
            result
                .sockets
                .iter()
                .map(|socket| socket.socket_index)
                .collect(),
            scheduler_targets,
            256,
            256,
            crate::MAX_SIGNAL_CANDIDATES,
            peer_session_generation,
            (
                plan.local_profile_generation,
                plan.remote_profile_generation,
            ),
            token,
            None,
        )
        .await
        .expect("production Birthday scheduler must retain the raw 256 request");
    let scheduler_birthday = scheduler_report
        .birthday
        .as_ref()
        .expect("Birthday scheduler cap test must expose its report");
    assert_eq!(scheduler_birthday.requested_level, 256);
    assert_eq!(scheduler_birthday.generated_candidate_count, 256);
    assert_eq!(
        scheduler_birthday.signaled_candidate_count,
        crate::MAX_SIGNAL_CANDIDATES
    );
    assert_eq!(
        scheduler_birthday.effective_target_count,
        crate::MAX_SIGNAL_CANDIDATES
    );
    assert_eq!(scheduler_birthday.requested_socket_count, 8);
    assert_eq!(scheduler_birthday.attached_socket_count, 4);
    assert_eq!(scheduler_birthday.usable_socket_count, 4);
    assert_eq!(scheduler_birthday.unavailable_socket_count, 4);
    assert_eq!(scheduler_birthday.waves_planned, 2);
    let diagnostics = harness.peers_a.diagnostics().await;
    assert!(diagnostics[0].direct_events.iter().any(|event| {
        event.stage == "hard_hard_birthday_degraded"
            && event.detail.contains("requested_level=256")
            && event.detail.contains("actual_level=128")
            && event.detail.contains("requested_socket_count=8")
            && event.detail.contains("actual_socket_count=4")
            && event.detail.contains("reason=socket_cap")
    }));
    assert!(harness.udp_a.dynamic_socket_count().await <= 8);
    for socket in &result.sockets {
        assert!(socket.guard.finalize().await);
    }
    harness
        .udp_a
        .detach_hard_hard_sockets_for_token(
            HARD_HARD_B,
            token,
            None,
            "hard_hard_birthday_cap_test_cleanup",
        )
        .await;
    drop(filler_guards);
    drop(predecessor);
    timeout(Duration::from_secs(1), async {
        while harness.udp_a.dynamic_socket_count().await != 0 {
            sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("capacity validation must clean predecessor and filler readers");
    harness.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn hard_hard_responder_measurement_candidate_epoch_change_fences_response() {
    let _serial = HARD_HARD_E2E_SERIAL.acquire().await.unwrap();
    let now = hard_hard_now_for_test();
    set_hard_hard_test_now_ms(Some(now));
    let _clock = HardHardClockReset;
    let harness = build_two_peer_harness(false, false, false).await;
    let gate = install_hard_hard_responder_measurement_gate_for_test();

    trigger_initial_offer(&harness).await;
    timeout(Duration::from_secs(3), gate.reached.notified())
        .await
        .expect("B responder measurement must pause before its post-measurement plan fence");

    let old_plan = harness
        .peers_b
        .hard_hard_plan_for_peer(HARD_HARD_A)
        .await
        .expect("B must retain the admitted Hard↔Hard plan while measurement is paused");
    let initiator_offer = harness
        .signals_b
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .iter()
        .find(|signal| {
            signal
                .session_id
                .as_deref()
                .is_some_and(|session| session.starts_with("hh1:i:"))
        })
        .cloned()
        .expect("A must have published the initiator prediction before B measures it");
    let replacement = hard_hard_replacement_candidate(
        initiator_offer
            .candidates
            .first()
            .expect("the initiator prediction must contain a candidate"),
    );
    let replacement_sources = HashMap::from([(replacement.clone(), "predicted".to_string())]);
    assert!(matches!(
        harness
            .peers_b
            .add_candidates_with_metadata(
                HARD_HARD_A,
                &[replacement],
                &replacement_sources,
                initiator_offer.candidate_generation.saturating_add(1),
                initiator_offer.candidates_expires_at_ms,
            )
            .await,
        CandidateSetApplyResult::Applied
    ));
    assert!(
        harness
            .peers_b
            .bind_remote_nat_profile_to_candidate_epoch(
                HARD_HARD_A,
                old_plan.remote_profile_generation,
            )
            .await,
        "the changed candidate epoch must still have a current remote profile so the planner remains selected"
    );
    let changed_plan = harness
        .peers_b
        .hard_hard_plan_for_peer(HARD_HARD_A)
        .await
        .expect("the regression must change only the candidate epoch, not remove the planner");
    assert_eq!(
        changed_plan.remote_candidate_epoch,
        old_plan.remote_candidate_epoch.saturating_add(1)
    );
    assert_eq!(
        changed_plan.local_network_generation,
        old_plan.local_network_generation
    );
    assert_eq!(
        changed_plan.local_profile_generation,
        old_plan.local_profile_generation
    );
    assert_eq!(
        changed_plan.remote_profile_generation,
        old_plan.remote_profile_generation
    );

    gate.release.notify_one();
    timeout(Duration::from_secs(3), gate.completed.notified())
        .await
        .expect("the responder worker must finish after rechecking the advanced candidate epoch");
    assert!(
        !harness
            .signals_a
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .iter()
            .any(|signal| {
                signal
                    .session_id
                    .as_deref()
                    .is_some_and(|session| session.starts_with("hh1:r:"))
            }),
        "a responder measured against the old remote candidate epoch must not publish a reciprocal response"
    );
    harness.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn hard_hard_two_peer_first_send_protection_refunds_then_retries_response() {
    let _serial = HARD_HARD_E2E_SERIAL.acquire().await.unwrap();
    let now = hard_hard_now_for_test();
    set_hard_hard_test_now_ms(Some(now));
    let _clock = HardHardClockReset;
    let harness = build_two_peer_harness(true, false, false).await;

    let epoch = match harness.peers_b.recovery_epoch_admit(HARD_HARD_A).await {
        RecoveryAdmission::Accepted { epoch } => epoch,
        admission => panic!("B must admit the protected ordinary fixture: {admission:?}"),
    };
    let ordinary_punch_at =
        unix_time_millis().saturating_add(RELAY_ASSISTED_PUNCH_LEAD.as_millis() as u64);
    let ordinary = match harness
        .punch_attempts_b
        .claim_for_epoch_with_rendezvous(
            HARD_HARD_A,
            harness.peers_b.current_network_generation_sync(),
            epoch,
            PUNCH_PRIORITY_SYNCHRONIZED,
            None,
            Some(ordinary_punch_at),
        )
        .await
    {
        RendezvousPunchClaim::Claimed(session) => session,
        RendezvousPunchClaim::Deferred(_) => panic!("ordinary fixture must own B's punch window"),
        RendezvousPunchClaim::RejectedStalePeerSession => {
            panic!("fixture lifecycle must not be retired")
        }
    };
    let ordinary_cancellation = ordinary.cancellation_handle();
    let ordinary_owner = Arc::new(StdMutex::new(Some(ordinary)));
    *harness.signal_hook_a_to_b.lock().unwrap() = Some(Arc::new({
        let ordinary_owner = ordinary_owner.clone();
        move |signal: &TestControlSignal| {
            if signal
                .session_id
                .as_deref()
                .is_some_and(|session| session.starts_with("hh1:i:"))
            {
                ordinary_owner
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner())
                    .as_ref()
                    .expect("ordinary owner must remain live through the protected claim")
                    .mark_first_send_started();
            }
        }
    }));

    trigger_initial_offer(&harness).await;
    let deferred = wait_for_stage(
        &harness.peers_b,
        HARD_HARD_A,
        "hard_hard_responder_claim_deferred",
    )
    .await;
    assert!(
        deferred
            .detail
            .contains("reason=active_first_send_protected"),
        "the responder must encounter the real first-send protection branch: {}",
        deferred.detail
    );
    assert_eq!(
        harness
            .peers_b
            .recovery_epoch_work_budget_report(HARD_HARD_A)
            .await
            .expect("the same recovery epoch must remain active while retrying")
            .fresh_generations_remaining,
        1,
        "a Deferred claim must refund B's sole fresh-generation reservation before waiting"
    );

    wait_for_hard_hard_response_signal(&harness).await;
    assert!(
        ordinary_cancellation.is_cancelled(),
        "after the bounded protection expires, the fresh response must preempt the ordinary owner"
    );
    wait_for_both_direct(&harness).await;
    harness.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn hard_hard_two_peer_initiator_response_retries_first_send_protection_once() {
    let _serial = HARD_HARD_E2E_SERIAL.acquire().await.unwrap();
    // Use the real clock here: both workers must continue targeting the same
    // absolute punch_at while the initiator waits out the 250ms protection.
    set_hard_hard_test_now_ms(None);
    let _clock = HardHardClockReset;
    let harness = build_two_peer_harness(false, false, false).await;
    let responder_gate = install_hard_hard_responder_measurement_gate_for_test();

    trigger_initial_offer(&harness).await;
    // The gate follows two sequential production-bounded measurements (the
    // initiator, then the responder). Their 1.2s budgets plus debug-runtime
    // scheduling leave too little headroom in a 3s fixture-only wait.
    timeout(Duration::from_secs(5), responder_gate.reached.notified())
        .await
        .expect("B must pause after measurement before publishing its response");
    wait_for_stage(
        &harness.peers_a,
        HARD_HARD_B,
        "hard_hard_prediction_signaled",
    )
    .await;

    let epoch = match harness.peers_a.recovery_epoch_admit(HARD_HARD_B).await {
        RecoveryAdmission::Accepted { epoch } => epoch,
        admission => panic!("A must retain its initiator recovery epoch: {admission:?}"),
    };
    let ordinary_punch_at =
        unix_time_millis().saturating_add(RELAY_ASSISTED_PUNCH_LEAD.as_millis() as u64);
    let ordinary = match harness
        .punch_attempts_a
        .claim_for_epoch_with_rendezvous(
            HARD_HARD_B,
            harness.peers_a.current_network_generation_sync(),
            epoch,
            PUNCH_PRIORITY_SYNCHRONIZED,
            None,
            Some(ordinary_punch_at),
        )
        .await
    {
        RendezvousPunchClaim::Claimed(session) => session,
        RendezvousPunchClaim::Deferred(_) => {
            panic!("ordinary fixture must own A's punch window while awaiting the response")
        }
        RendezvousPunchClaim::RejectedStalePeerSession => {
            panic!("fixture lifecycle must not be retired")
        }
    };
    let ordinary_cancellation = ordinary.cancellation_handle();
    let ordinary_owner = Arc::new(StdMutex::new(Some(ordinary)));
    *harness.signal_hook_b_to_a.lock().unwrap() = Some(Arc::new({
        let ordinary_owner = ordinary_owner.clone();
        move |signal: &TestControlSignal| {
            if signal
                .session_id
                .as_deref()
                .is_some_and(|session| session.starts_with("hh1:r:"))
            {
                ordinary_owner
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner())
                    .as_ref()
                    .expect("ordinary owner must remain live until A receives the response")
                    .mark_first_send_started();
            }
        }
    }));

    responder_gate.release.notify_one();
    let deferred = wait_for_stage(
        &harness.peers_a,
        HARD_HARD_B,
        "hard_hard_initiator_response_claim_deferred",
    )
    .await;
    assert!(
        deferred
            .detail
            .contains("reason=active_first_send_protected"),
        "the initiator response must hit the real first-send protection branch: {}",
        deferred.detail
    );
    assert!(
        deferred.detail.contains("waiting once"),
        "the protected collision must enter the one bounded retry branch: {}",
        deferred.detail
    );
    assert!(
        !ordinary_cancellation.is_cancelled(),
        "the initial fresh claim must preserve the already-dispatched ordinary send"
    );
    timeout(Duration::from_secs(2), async {
        while !ordinary_cancellation.is_cancelled() {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("the one bounded retry must preempt the ordinary owner after protection expires");

    wait_for_both_direct(&harness).await;
    harness.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn hard_hard_two_peer_prediction_miss_keeps_relay_and_cleans_up() {
    let _serial = HARD_HARD_E2E_SERIAL.acquire().await.unwrap();
    let now = hard_hard_now_for_test();
    set_hard_hard_test_now_ms(Some(now));
    let _clock = HardHardClockReset;
    let harness = build_two_peer_harness(true, false, true).await;
    harness.link.set_drop_a_to_b(true);
    harness.link.set_drop_b_to_a(true);
    trigger_initial_offer(&harness).await;
    wait_for_hard_hard_response_signal(&harness).await;

    let actual_a = harness.link._a_source.local_addr().unwrap().port();
    let actual_b = harness.link._b_source.local_addr().unwrap().port();
    let fresh_a = harness
        .peers_a
        .fresh_mapping_for_peer(HARD_HARD_B)
        .await
        .expect("A must have completed its measured mapping before the miss");
    let fresh_b = harness
        .peers_b
        .fresh_mapping_for_peer(HARD_HARD_A)
        .await
        .expect("B must have completed its measured mapping before the miss");
    assert!(!fresh_a.predicted_ports.contains(&actual_a));
    assert!(!fresh_b.predicted_ports.contains(&actual_b));
    assert!(!harness.peers_a.is_direct(HARD_HARD_B).await);
    assert!(!harness.peers_b.is_direct(HARD_HARD_A).await);
    assert_relay_remains_available(&harness).await;
    // The per-peer direct-event ring is intentionally best-effort under
    // connection-map contention.  Session/socket/probe teardown is the
    // authoritative completion fence for a missed rendezvous.
    wait_for_failed_attempt_cleanup(&harness).await;

    for peers in [&harness.peers_a, &harness.peers_b] {
        let diagnostics = peers.diagnostics().await;
        let peer = &diagnostics[0];
        assert!(!peer
            .direct_events
            .iter()
            .any(|event| event.stage == "hard_hard_sweep_completed"));
        assert!(!peer
            .direct_events
            .iter()
            .any(|event| event.stage == "direct_validation_promoted"));
    }
    harness.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn hard_hard_two_peer_partial_reachability_never_stays_asymmetric_direct() {
    let _serial = HARD_HARD_E2E_SERIAL.acquire().await.unwrap();
    let now = hard_hard_now_for_test();
    set_hard_hard_test_now_ms(Some(now));
    let _clock = HardHardClockReset;
    let harness = build_two_peer_harness(true, false, false).await;
    harness.link.set_drop_b_to_a(true);
    trigger_initial_offer(&harness).await;
    wait_for_both_sweep_failures(&harness).await;
    harness.link.set_drop_a_to_b(true);

    assert!(!harness.peers_a.is_direct(HARD_HARD_B).await);
    assert!(!harness.peers_b.is_direct(HARD_HARD_A).await);
    assert_relay_remains_available(&harness).await;
    wait_for_failed_attempt_cleanup(&harness).await;
    harness.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn hard_hard_two_peer_local_handover_cancels_waiting_session() {
    let _serial = HARD_HARD_E2E_SERIAL.acquire().await.unwrap();
    let now = hard_hard_now_for_test();
    set_hard_hard_test_now_ms(Some(now));
    let _clock = HardHardClockReset;
    let harness = build_two_peer_harness(false, false, false).await;
    trigger_initial_offer(&harness).await;
    let response = wait_for_hard_hard_response_signal(&harness).await;
    assert!(harness
        .peers_a
        .fresh_mapping_for_peer(HARD_HARD_B)
        .await
        .is_some());

    let new_generation = harness
        .peers_a
        .advance_network_generation("phase_2_2_test_local_handover")
        .await;
    assert_eq!(new_generation, 1);
    assert!(
        !harness
            .peers_a
            .hard_hard_session_is_active(HARD_HARD_B)
            .await
    );
    assert!(harness
        .peers_a
        .fresh_mapping_for_peer(HARD_HARD_B)
        .await
        .is_none());
    set_hard_hard_test_now_ms(Some(
        response
            .punch_at_ms
            .expect("response must carry punch_at_ms"),
    ));
    wait_for_failed_attempt_cleanup(&harness).await;
    assert!(!harness.peers_a.is_direct(HARD_HARD_B).await);
    assert_relay_remains_available(&harness).await;
    assert_eq!(harness.udp_a.dynamic_socket_count().await, 0);
    harness.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn hard_hard_two_peer_stale_ack_cannot_resurrect_retired_session() {
    let _serial = HARD_HARD_E2E_SERIAL.acquire().await.unwrap();
    let now = hard_hard_now_for_test();
    set_hard_hard_test_now_ms(Some(now));
    let _clock = HardHardClockReset;
    // Advance the shared fixture clock inside the response forwarder, before
    // either endpoint can observe the response.  Advancing it after merely
    // observing the outgoing signal lets the responder capture the old
    // 3.5-second delay while the initiator captures zero, separating the two
    // authenticated-probe windows.
    let harness = build_two_peer_harness(true, false, false).await;
    // Force the CI race: S1 has claimed its response owner, but its sweep
    // admission resumes only after both network generations are retired.
    // The old response must not start ordinary punching in S2's generation.
    let response_gate = install_hard_hard_initiator_response_gate_for_test();
    harness.link.set_hold_ack(true);
    harness.validation_enabled_a.store(false, Ordering::Release);
    harness.validation_enabled_b.store(false, Ordering::Release);

    trigger_initial_offer(&harness).await;
    let response_s1 = wait_for_hard_hard_response_signal(&harness).await;
    timeout(HARD_HARD_E2E_TIMEOUT, response_gate.reached.notified())
        .await
        .expect("S1 response must pause after claiming its owner and before entering its sweep");
    assert!(
        response_s1.punch_at_ms.is_some(),
        "S1 response must carry a canonical punch deadline"
    );
    // On a slow CI runner the fake clock can advance through the bounded S1
    // sweep before this polling task observes the transient socket/pending
    // state.  An authenticated ACK held by the link is the durable evidence
    // that S1 emitted a probe; the later S2 assertions verify that replaying
    // those ACKs cannot consume S2's live transactions.
    let s1_probe_wait = timeout(HARD_HARD_E2E_TIMEOUT, async {
        loop {
            if harness.link.held_ack_count() > 0 {
                return;
            }
            sleep(Duration::from_millis(10)).await;
        }
    })
    .await;
    if s1_probe_wait.is_err() {
        let stages_a = summarize_hard_hard_diagnostics(&harness.peers_a, HARD_HARD_B).await;
        let stages_b = summarize_hard_hard_diagnostics(&harness.peers_b, HARD_HARD_A).await;
        panic!(
            "S1 must emit authenticated probes whose ACKs can be held: held={} A sockets={} B sockets={} A pending={} B pending={} A events={stages_a:#?} B events={stages_b:#?}",
            harness.link.held_ack_count(),
            harness.udp_a.dynamic_socket_count().await,
            harness.udp_b.dynamic_socket_count().await,
            harness
                .udp_a
                .hard_hard_pending_probe_count_for_test(HARD_HARD_B)
                .await,
            harness
                .udp_b
                .hard_hard_pending_probe_count_for_test(HARD_HARD_A)
                .await,
        );
    }
    let stale_s1_acks = harness.link.take_held_acks();
    assert!(!stale_s1_acks.a_to_b.is_empty() || !stale_s1_acks.b_to_a.is_empty());

    harness
        .peers_a
        .advance_network_generation("phase_2_2_test_stale_ack_s1_cancel_a")
        .await;
    harness
        .peers_b
        .advance_network_generation("phase_2_2_test_stale_ack_s1_cancel_b")
        .await;
    response_gate.release.notify_one();
    wait_for_failed_attempt_cleanup(&harness).await;
    assert!(!harness.peers_a.is_direct(HARD_HARD_B).await);
    assert!(!harness.peers_b.is_direct(HARD_HARD_A).await);

    // Keep ACK holding enabled while S2 is pending. This leaves S2's own
    // pending Probe-v2 transactions alive so replaying only S1's packets is a
    // meaningful stale-ACK assertion rather than a post-success no-op.  Hold
    // only authenticated Punch packets at the harness boundary so one side
    // cannot select a winner before the other side has admitted its own S2
    // pending probes; ACK packets remain held and are still replayed below.
    harness.link.set_hold_authenticated_punch(true);
    sleep(Duration::from_millis(2_100)).await;
    trigger_retry_offer_with_current_candidates(&harness, &response_s1).await;
    let response_s2 = wait_for_hard_hard_response_signal_number(&harness, 2).await;
    timeout(Duration::from_secs(5), async {
        loop {
            if harness.udp_a.dynamic_socket_count().await == 1
                && harness.udp_b.dynamic_socket_count().await == 1
            {
                return;
            }
            sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("S2 must install fresh sockets after S1 cancellation");
    assert!(
        response_s2.punch_at_ms.is_some(),
        "S2 response must carry a canonical punch deadline"
    );
    let s2_probe_wait = timeout(Duration::from_secs(5), async {
        loop {
            if harness.link.held_authenticated_punch_count() > 0
                && harness
                    .udp_a
                    .hard_hard_pending_probe_count_for_test(HARD_HARD_B)
                    .await
                    > 0
                && harness
                    .udp_b
                    .hard_hard_pending_probe_count_for_test(HARD_HARD_A)
                    .await
                    > 0
            {
                return;
            }
            sleep(Duration::from_millis(10)).await;
        }
    })
    .await;
    if s2_probe_wait.is_err() {
        let stages_a = summarize_hard_hard_diagnostics(&harness.peers_a, HARD_HARD_B).await;
        let stages_b = summarize_hard_hard_diagnostics(&harness.peers_b, HARD_HARD_A).await;
        let session_a = harness
            .peers_a
            .hard_hard_session_for_test(HARD_HARD_B)
            .await;
        let session_b = harness
            .peers_b
            .hard_hard_session_for_test(HARD_HARD_A)
            .await;
        panic!(
            "S2 must have live pending probes before stale ACK replay: now={} held={} A sockets={} B sockets={} A pending={} B pending={} A session={session_a:#?} B session={session_b:#?} A events={stages_a:#?} B events={stages_b:#?}",
            hard_hard_now_for_test(),
            harness.link.held_ack_count(),
            harness.udp_a.dynamic_socket_count().await,
            harness.udp_b.dynamic_socket_count().await,
            harness
                .udp_a
                .hard_hard_pending_probe_count_for_test(HARD_HARD_B)
                .await,
            harness
                .udp_b
                .hard_hard_pending_probe_count_for_test(HARD_HARD_A)
                .await,
        );
    }
    let s2_token_a = harness
        .peers_a
        .hard_hard_session_for_test(HARD_HARD_B)
        .await
        .expect("S2 must be authoritative on A")
        .session_token;
    let s2_token_b = harness
        .peers_b
        .hard_hard_session_for_test(HARD_HARD_A)
        .await
        .expect("S2 must be authoritative on B")
        .session_token;

    harness
        .link
        .replay_acks(stale_s1_acks, &harness.udp_a, &harness.udp_b)
        .await;
    sleep(Duration::from_millis(100)).await;
    assert!(!harness.peers_a.is_direct(HARD_HARD_B).await);
    assert!(!harness.peers_b.is_direct(HARD_HARD_A).await);
    assert!(
        harness
            .udp_a
            .hard_hard_pending_probe_count_for_test(HARD_HARD_B)
            .await
            > 0,
        "S1 ACKs must not consume S2's A-side pending probes"
    );
    assert!(
        harness
            .udp_b
            .hard_hard_pending_probe_count_for_test(HARD_HARD_A)
            .await
            > 0,
        "S1 ACKs must not consume S2's B-side pending probes"
    );
    assert_eq!(
        harness
            .peers_a
            .hard_hard_session_for_test(HARD_HARD_B)
            .await
            .expect("S2 must remain live after stale ACK replay")
            .session_token,
        s2_token_a
    );
    assert_eq!(
        harness
            .peers_b
            .hard_hard_session_for_test(HARD_HARD_A)
            .await
            .expect("S2 must remain live after stale ACK replay")
            .session_token,
        s2_token_b
    );

    harness.validation_enabled_a.store(true, Ordering::Release);
    harness.validation_enabled_b.store(true, Ordering::Release);
    harness
        .link
        .release_held_authenticated_punches(&harness.udp_a, &harness.udp_b)
        .await;
    timeout(Duration::from_secs(5), async {
        loop {
            if harness.link.held_ack_count() > 0 {
                return;
            }
            sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("S2 Punch release must produce held ACKs");
    harness.link.set_hold_authenticated_punch(false);
    harness.link.set_hold_ack(false);
    let s2_acks = harness.link.take_held_acks();
    harness
        .link
        .replay_acks(s2_acks, &harness.udp_a, &harness.udp_b)
        .await;
    wait_for_both_direct(&harness).await;
    harness.shutdown().await;
}

#[tokio::test(flavor = "current_thread")]
async fn hard_hard_manager_peer_isolation_keeps_unrelated_session_authoritative() {
    let root_identity = NodeIdentity::generate();
    let manager = Arc::new(PeerManager::new(harness_config(
        &root_identity,
        "peer-root",
        "10.20.0.10",
        std::env::temp_dir().join(format!("p2wlan-phase-2-2-isolation-{}", std::process::id())),
        HarnessStunProfile::FULL_CAPACITY,
    )));
    let identity_b = NodeIdentity::generate();
    let identity_c = NodeIdentity::generate();
    manager
        .add_peer(&peer_info(
            "peer-b",
            "10.20.0.11",
            hex::encode(identity_b.public_key()),
            "127.0.0.1:31001".parse().unwrap(),
            "phase-2-2-test".to_string(),
        ))
        .await;
    manager
        .add_peer(&peer_info(
            "peer-c",
            "10.20.0.12",
            hex::encode(identity_c.public_key()),
            "127.0.0.1:31002".parse().unwrap(),
            "phase-2-2-test".to_string(),
        ))
        .await;

    let make_record = |peer_id: &str, token: &str, socket_index: usize| {
        let socket_local_endpoint = SocketAddr::new(
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            31_100 + socket_index as u16,
        );
        let identity = peer::HardHardFreshSocketIdentity {
            peer_id: peer_id.to_string(),
            session_token: token.to_string(),
            network_generation: 0,
            remote_candidate_epoch: 1,
            local_profile_generation: 1,
            remote_profile_generation: 1,
            punch_generation: 1,
            socket_index,
            socket_local_endpoint,
        };
        peer::HardHardSessionRecord {
            session_id: format!("hh1:i:{token}"),
            probe_session_id: None,
            session_token: token.to_string(),
            peer_id: peer_id.to_string(),
            initiator: true,
            remote_network_generation: 0,
            local_network_generation: 0,
            remote_candidate_epoch: 1,
            local_profile_generation: 1,
            remote_profile_generation: 1,
            local_prediction_confidence: 90,
            remote_prediction_confidence: 0,
            requested_birthday_level: 0,
            generated_candidate_count: 1,
            signaled_candidate_count: 1,
            birthday: false,
            requested_socket_indices: vec![socket_index],
            requested_socket_count: 1,
            prediction_window: vec![socket_local_endpoint],
            remote_prediction: Vec::new(),
            fresh_socket: identity,
            punch_at_ms: hard_hard_now_for_test().saturating_add(5_000),
            expires_at_ms: hard_hard_now_for_test().saturating_add(30_000),
            state: peer::HardHardSessionState::AwaitingPeer,
            attempt_count: 0,
            measurement: peer::HardHardMeasurementObservation::default(),
            created_at: Instant::now(),
            cancellation: Arc::new(crate::PunchSessionCancellation::default()),
        }
    };
    assert!(
        manager
            .hard_hard_register_session(make_record("peer-b", "token-b", 1000))
            .await
    );
    assert!(
        manager
            .hard_hard_register_session(make_record("peer-c", "token-c", 1001))
            .await
    );
    let c_before = manager
        .hard_hard_session_for_test("peer-c")
        .await
        .expect("peer C session must be present before peer B cleanup");

    manager.clear_hard_hard_sessions(Some("peer-b")).await;
    assert!(!manager.hard_hard_session_is_active("peer-b").await);
    let c_after = manager
        .hard_hard_session_for_test("peer-c")
        .await
        .expect("cleaning peer B must not remove peer C's session");
    assert_eq!(c_after.session_token, c_before.session_token);
    assert_eq!(
        c_after.fresh_socket.socket_index,
        c_before.fresh_socket.socket_index
    );
    assert!(manager.hard_hard_session_is_active("peer-c").await);
    manager.clear_hard_hard_sessions(None).await;
}

#[tokio::test(flavor = "current_thread")]
async fn hard_hard_manager_sticky_winner_rejects_delayed_authenticated_socket() {
    let identity = NodeIdentity::generate();
    let manager = PeerManager::new(harness_config(
        &identity,
        "peer-sticky-root",
        "10.20.0.30",
        std::env::temp_dir().join(format!("p2wlan-phase-2-2-sticky-{}", std::process::id())),
        HarnessStunProfile::FULL_CAPACITY,
    ));
    let peer_identity = NodeIdentity::generate();
    manager
        .add_peer(&peer_info(
            "peer-sticky",
            "10.20.0.31",
            hex::encode(peer_identity.public_key()),
            "127.0.0.1:31031".parse().unwrap(),
            "phase-2-2-test".to_string(),
        ))
        .await;
    let endpoint_a: SocketAddr = "127.0.0.1:31100".parse().unwrap();
    let endpoint_b: SocketAddr = "127.0.0.1:31101".parse().unwrap();
    let record = peer::HardHardSessionRecord {
        session_id: "hh1:i:sticky-token".to_string(),
        probe_session_id: None,
        session_token: "sticky-token".to_string(),
        peer_id: "peer-sticky".to_string(),
        initiator: true,
        remote_network_generation: 0,
        local_network_generation: 0,
        remote_candidate_epoch: 1,
        local_profile_generation: 1,
        remote_profile_generation: 1,
        local_prediction_confidence: 90,
        remote_prediction_confidence: 0,
        requested_birthday_level: 0,
        generated_candidate_count: 1,
        signaled_candidate_count: 1,
        birthday: false,
        requested_socket_indices: vec![4100],
        requested_socket_count: 1,
        prediction_window: vec![endpoint_a],
        remote_prediction: Vec::new(),
        fresh_socket: peer::HardHardFreshSocketIdentity {
            peer_id: "peer-sticky".to_string(),
            session_token: "sticky-token".to_string(),
            network_generation: 0,
            remote_candidate_epoch: 1,
            local_profile_generation: 1,
            remote_profile_generation: 1,
            punch_generation: 1,
            socket_index: 4100,
            socket_local_endpoint: endpoint_a,
        },
        punch_at_ms: hard_hard_now_for_test().saturating_add(5_000),
        expires_at_ms: hard_hard_now_for_test().saturating_add(30_000),
        state: peer::HardHardSessionState::AwaitingPeer,
        attempt_count: 0,
        measurement: peer::HardHardMeasurementObservation::default(),
        created_at: Instant::now(),
        cancellation: Arc::new(crate::PunchSessionCancellation::default()),
    };
    assert!(manager.hard_hard_register_session(record).await);
    assert!(manager
        .hard_hard_begin_sweep("peer-sticky", "sticky-token", vec![endpoint_a], 90, 0,)
        .await
        .is_some());

    let first = manager
        .hard_hard_select_winner("peer-sticky", "sticky-token", 4100, 0, 1, endpoint_a)
        .await
        .expect("the first authenticated socket must become the winner");
    assert_eq!(first.socket_index, 4100);
    assert!(manager
        .hard_hard_select_winner("peer-sticky", "sticky-token", 4101, 0, 2, endpoint_b)
        .await
        .is_none());
    assert_eq!(
        manager
            .hard_hard_winner_for_token("peer-sticky", "sticky-token")
            .await,
        Some(4100)
    );
    assert_eq!(
        manager
            .hard_hard_session_by_token("peer-sticky", "sticky-token")
            .await
            .expect("sticky session must remain authoritative")
            .fresh_socket
            .socket_index,
        4100
    );
    manager.clear_hard_hard_sessions(None).await;
}

async fn hard_hard_remote_candidate_epoch_fence_with_stun(stun: HarnessStunProfile) {
    let _serial = HARD_HARD_E2E_SERIAL.acquire().await.unwrap();
    let now = hard_hard_now_for_test();
    set_hard_hard_test_now_ms(Some(now));
    let _clock = HardHardClockReset;
    let harness = build_two_peer_harness_with_stun(false, false, false, stun).await;
    trigger_initial_offer(&harness).await;
    let response = wait_for_hard_hard_response_signal(&harness).await;
    let old_epoch = harness
        .peers_a
        .current_remote_candidate_epoch(HARD_HARD_B)
        .await
        .expect("A must have a remote candidate epoch");
    harness.link.set_drop_a_to_b(true);
    harness.link.set_drop_b_to_a(true);
    let candidate = response
        .candidates
        .first()
        .cloned()
        .expect("response must carry a candidate");
    // A newer freshness revision alone no longer advances the remote
    // transport epoch. Use a genuinely different endpoint so this remains a
    // transport-handover fencing test rather than a version-counter test.
    let replacement_candidate = hard_hard_replacement_candidate(&candidate);
    assert!(!response.candidates.contains(&replacement_candidate));
    let candidate_sources =
        HashMap::from([(replacement_candidate.clone(), "predicted".to_string())]);
    let old_epoch_b = harness
        .peers_b
        .current_remote_candidate_epoch(HARD_HARD_A)
        .await
        .expect("B must have a remote candidate epoch");
    let local_candidate_for_b = harness
        .link
        .a_public
        .local_addr()
        .expect("A public test socket must have an endpoint")
        .to_string();
    let replacement_candidate_for_b = hard_hard_replacement_candidate(&local_candidate_for_b);
    let candidate_sources_for_b =
        HashMap::from([(replacement_candidate_for_b.clone(), "predicted".to_string())]);
    let candidates_a = [replacement_candidate];
    let candidates_b = [replacement_candidate_for_b];
    let (apply_result_a, apply_result_b) = tokio::join!(
        harness.peers_a.add_candidates_with_metadata(
            HARD_HARD_B,
            &candidates_a,
            &candidate_sources,
            response.candidate_generation.saturating_add(1),
            response.candidates_expires_at_ms,
        ),
        harness.peers_b.add_candidates_with_metadata(
            HARD_HARD_A,
            &candidates_b,
            &candidate_sources_for_b,
            response.candidate_generation.saturating_add(1),
            None,
        ),
    );
    assert!(matches!(apply_result_a, CandidateSetApplyResult::Applied));
    assert!(matches!(apply_result_b, CandidateSetApplyResult::Applied));
    timeout(Duration::from_secs(3), async {
        loop {
            let epoch_a = harness
                .peers_a
                .current_remote_candidate_epoch(HARD_HARD_B)
                .await;
            let epoch_b = harness
                .peers_b
                .current_remote_candidate_epoch(HARD_HARD_A)
                .await;
            if epoch_a == Some(old_epoch.saturating_add(1))
                && epoch_b == Some(old_epoch_b.saturating_add(1))
            {
                return;
            }
            sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("the accepted newer candidate signal must advance exactly one epoch");
    set_hard_hard_test_now_ms(Some(
        response
            .punch_at_ms
            .expect("response must carry punch_at_ms")
            .saturating_add(30_000),
    ));
    wait_for_failed_attempt_cleanup(&harness).await;
    assert!(!harness.peers_a.is_direct(HARD_HARD_B).await);
    assert_relay_remains_available(&harness).await;
    let diagnostics_a = harness.peers_a.diagnostics().await;
    assert!(diagnostics_a[0]
        .direct_events
        .iter()
        .any(|event| event.stage == "remote_candidates_invalidated"));
    harness.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn hard_hard_two_peer_remote_candidate_epoch_fences_old_session() {
    hard_hard_remote_candidate_epoch_fence_with_stun(HarnessStunProfile::FULL_CAPACITY).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn hard_hard_remote_candidate_epoch_fence_with_minimum_stun_capacity() {
    hard_hard_remote_candidate_epoch_fence_with_stun(HarnessStunProfile::MINIMUM_CAPACITY).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn hard_hard_two_peer_profile_generation_fences_old_session() {
    let _serial = HARD_HARD_E2E_SERIAL.acquire().await.unwrap();
    let now = hard_hard_now_for_test();
    set_hard_hard_test_now_ms(Some(now));
    let _clock = HardHardClockReset;
    let harness = build_two_peer_harness(false, false, false).await;
    trigger_initial_offer(&harness).await;
    let response = wait_for_hard_hard_response_signal(&harness).await;
    harness
        .peers_a
        .update_nat_profile(hard_hard_profile("127.0.0.1:49991".parse().unwrap(), 5))
        .await;
    assert_eq!(harness.peers_a.current_local_profile_generation_sync(), 2);
    set_hard_hard_test_now_ms(Some(
        response
            .punch_at_ms
            .expect("response must carry punch_at_ms"),
    ));
    wait_for_failed_attempt_cleanup(&harness).await;
    assert!(!harness.peers_a.is_direct(HARD_HARD_B).await);
    assert_relay_remains_available(&harness).await;
    assert_eq!(harness.udp_a.dynamic_socket_count().await, 0);
    harness.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn hard_hard_two_peer_duplicate_and_stale_signals_do_not_reopen_session() {
    let _serial = HARD_HARD_E2E_SERIAL.acquire().await.unwrap();
    let now = hard_hard_now_for_test();
    set_hard_hard_test_now_ms(Some(now));
    let _clock = HardHardClockReset;
    let harness = build_two_peer_harness(false, false, false).await;
    // The predictable harness reserves every signaled candidate port, so a
    // Windows ephemeral dynamic socket cannot bypass these NAT drop flags by
    // binding one of the synthetic public targets directly.
    harness.link.set_drop_a_to_b(true);
    harness.link.set_drop_b_to_a(true);
    trigger_initial_offer(&harness).await;
    let response = wait_for_hard_hard_response_signal(&harness).await;
    // The response signal is logged when it is admitted to the control lane,
    // while candidate-only work is applied by a separate newest-wins worker.
    // Wait for the original candidate set to be visible before injecting an
    // exact duplicate; otherwise the duplicate can become the first applied
    // payload and legitimately create the initial epoch, making this test
    // assert on queue admission order instead of duplicate idempotence.
    wait_for_remote_candidates(&harness.peers_a, HARD_HARD_B, &response.candidates).await;
    let original_a = harness.udp_a.dynamic_socket_count().await;
    let original_b = harness.udp_b.dynamic_socket_count().await;

    assert_eq!(harness.udp_a.dynamic_socket_count().await, original_a);
    assert_eq!(harness.udp_b.dynamic_socket_count().await, original_b);

    // A duplicate full offer can wait behind the active responder transaction.
    // Move the shared test clock to its punch boundary, then wait for both
    // durable deliveries to reach a terminal state before installing the next
    // candidate generation. This prevents an old queued offer from racing the
    // direct test mutation below while preserving the real responder ordering.
    set_hard_hard_test_now_ms(Some(
        response
            .punch_at_ms
            .expect("response must carry punch_at_ms"),
    ));
    let duplicate_one = inject_candidate_offer(
        &harness,
        &response,
        response.candidate_generation,
        response.session_id.clone(),
    )
    .await;
    assert_eq!(
        wait_for_injected_offer_disposition(duplicate_one).await,
        crate::control::SignalApplyOutcome::Applied,
        "the first duplicate must drain through the existing responder lane"
    );
    let epoch_after_first_duplicate = harness
        .peers_a
        .current_remote_candidate_epoch(HARD_HARD_B)
        .await
        .unwrap();
    let duplicate_two = inject_candidate_offer(
        &harness,
        &response,
        response.candidate_generation,
        response.session_id.clone(),
    )
    .await;
    assert_eq!(
        wait_for_injected_offer_disposition(duplicate_two).await,
        crate::control::SignalApplyOutcome::Applied,
        "the second duplicate must drain through the existing responder lane"
    );
    assert_eq!(
        harness
            .peers_a
            .current_remote_candidate_epoch(HARD_HARD_B)
            .await,
        Some(epoch_after_first_duplicate),
        "an exact duplicate must not advance the remote candidate epoch"
    );
    wait_for_failed_attempt_cleanup(&harness).await;

    let epoch_before_new = harness
        .peers_a
        .current_remote_candidate_epoch(HARD_HARD_B)
        .await
        .unwrap();

    let candidate = response
        .candidates
        .first()
        .cloned()
        .expect("response must carry a candidate");
    // Model a real replacement transport before replaying the stale response;
    // an identical set with a higher revision is only a freshness refresh.
    let replacement_candidate = hard_hard_replacement_candidate(&candidate);
    assert!(!response.candidates.contains(&replacement_candidate));
    let sources = HashMap::from([(replacement_candidate.clone(), "predicted".to_string())]);
    assert!(matches!(
        harness
            .peers_a
            .add_candidates_with_metadata(
                HARD_HARD_B,
                &[replacement_candidate],
                &sources,
                response.candidate_generation.saturating_add(1),
                response.candidates_expires_at_ms,
            )
            .await,
        CandidateSetApplyResult::Applied
    ));
    let epoch_after_new = harness
        .peers_a
        .current_remote_candidate_epoch(HARD_HARD_B)
        .await
        .unwrap();
    assert_eq!(epoch_after_new, epoch_before_new.saturating_add(1));
    // Deliver the old response after the newer candidate epoch. The real
    // control ingress must reject it as stale instead of reviving S1.
    let stale_offer = inject_candidate_offer(
        &harness,
        &response,
        response.candidate_generation,
        response.session_id.clone(),
    )
    .await;
    let stale_outcome = wait_for_injected_offer_disposition(stale_offer).await;
    assert!(
        matches!(
            stale_outcome,
            crate::control::SignalApplyOutcome::Applied
                | crate::control::SignalApplyOutcome::TerminalRejected
        ),
        "the stale offer must finish terminally, got {stale_outcome:?}"
    );
    wait_for_failed_attempt_cleanup(&harness).await;
    assert!(!harness.peers_a.is_direct(HARD_HARD_B).await);
    assert_relay_remains_available(&harness).await;
    assert_eq!(
        harness
            .peers_a
            .current_remote_candidate_epoch(HARD_HARD_B)
            .await,
        Some(epoch_after_new),
        "the old response must not advance or replace the newer candidate epoch"
    );
    harness.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn hard_hard_two_peer_competing_primary_direct_supersedes_hard_hard() {
    let _serial = HARD_HARD_E2E_SERIAL.acquire().await.unwrap();
    let now = hard_hard_now_for_test();
    set_hard_hard_test_now_ms(Some(now));
    let _clock = HardHardClockReset;
    let harness = build_two_peer_harness(false, true, false).await;
    trigger_initial_offer(&harness).await;
    let response = wait_for_hard_hard_response_signal(&harness).await;
    let punch_at_ms = response
        .punch_at_ms
        .expect("Hard↔Hard response carries a canonical punch deadline");
    let hard_socket_index = harness
        .peers_a
        .fresh_mapping_for_peer(HARD_HARD_B)
        .await
        .expect("A must have its Hard↔Hard measurement before the race")
        .socket_index;

    let primary_local = harness.udp_a.local_addr().unwrap();
    let b_public = harness.link.b_public.local_addr().unwrap();
    harness
        .udp_a
        .punch_candidates_primary_socket(HARD_HARD_B, vec![b_public], Duration::ZERO, 1)
        .await
        .expect("ordinary primary punch must send through the real UDP path");
    timeout(Duration::from_secs(5), async {
        loop {
            if harness.peers_a.is_direct(HARD_HARD_B).await
                && harness
                    .udp_a
                    .affinity_pin_for_test(HARD_HARD_B)
                    .await
                    .is_some_and(|pin| pin.socket_index == 0)
            {
                return;
            }
            sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("ordinary primary direct path must win before the Hard↔Hard deadline");

    set_hard_hard_test_now_ms(Some(punch_at_ms));
    // Direct promotion revokes the Hard↔Hard owner immediately. Under a
    // loaded test runtime the cancelled worker can therefore finish without
    // publishing its best-effort diagnostic event (or the ring can evict that
    // event before a long generic wait observes it). The socket/session state
    // below is the authoritative supersession proof; inspect the event when
    // it is available, but do not make cleanup correctness depend on it.
    let superseded_a = timeout(Duration::from_secs(5), async {
        loop {
            if let Some(event) = harness
                .peers_a
                .diagnostics()
                .await
                .into_iter()
                .find(|peer| peer.node_id == HARD_HARD_B)
                .and_then(|peer| {
                    peer.direct_events
                        .into_iter()
                        .find(|event| event.stage == "hard_hard_superseded_by_other_direct")
                })
            {
                return event;
            }
            sleep(Duration::from_millis(20)).await;
        }
    })
    .await;
    if let Ok(superseded_a) = superseded_a {
        assert!(
            superseded_a
                .detail
                .contains(&format!("socket index={hard_socket_index}")),
            "superseded event must identify the detached Hard↔Hard socket: {}",
            superseded_a.detail
        );
    }
    assert_eq!(
        harness.udp_a.dynamic_socket_count().await,
        0,
        "the superseded Hard↔Hard socket must detach while primary remains"
    );
    assert!(
        !harness
            .peers_a
            .hard_hard_session_is_active(HARD_HARD_B)
            .await,
        "the superseded Hard↔Hard session must be retired"
    );
    assert_eq!(
        harness
            .peers_a
            .select_path_for_data(HARD_HARD_B, true, true)
            .await
            .path,
        Some(NetworkPath::Direct)
    );
    assert_eq!(
        harness
            .udp_a
            .affinity_pin_for_test(HARD_HARD_B)
            .await
            .map(|pin| pin.socket_index),
        Some(0)
    );
    assert_eq!(
        harness
            .udp_a
            .socket_for_peer(Some(HARD_HARD_B))
            .await
            .map(|(index, _)| index),
        Some(0)
    );
    let primary_local_text = primary_local.to_string();
    assert_eq!(
        harness.peers_a.diagnostics().await[0]
            .current_direct_pair
            .as_ref()
            .and_then(|pair| pair.local_endpoint.as_deref()),
        Some(primary_local_text.as_str())
    );
    let diagnostics_a = harness.peers_a.diagnostics().await;
    assert!(!diagnostics_a[0]
        .direct_events
        .iter()
        .any(|event| event.stage == "hard_hard_sweep_completed"));
    harness.shutdown().await;
}
