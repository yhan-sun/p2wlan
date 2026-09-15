// Split out of the former flat include!-ed test file so the module is a
// real Rust scope. Everything below is unchanged test code.
use super::*;

#[tokio::test]
async fn exact_handshake_retry_cancellation_is_merged_and_stale_wake_is_harmless() {
    let config = Config::generate_default("http://127.0.0.1:1", "net1").unwrap();
    let daemon = Daemon::new(config);
    let peer_identity = NodeIdentity::generate();
    let peer_info = control::PeerInfo {
        node_id: "peer-cancelled-exact-retry".to_string(),
        device_name: String::new(),
        app_version: String::new(),
        public_key: hex::encode(peer_identity.public_key()),
        endpoint: String::new(),
        nat_type: "Unknown".to_string(),
        virtual_ip: "10.20.0.2".to_string(),
        online: true,
        last_seen: 0,
        relay_rtt_ms: None,
    };
    daemon.peers.add_peer(&peer_info).await;

    let mut retry_rx = daemon.handshake_retry_kick_tx.subscribe();
    let mut reservation = daemon
        .reserve_event_initiator_handshake(&peer_info.node_id)
        .expect("event initiator reservation must be admitted");
    let mut cancellation = reservation.cancellation.clone();
    assert!(daemon.schedule_initiator_retry(
        &peer_info.node_id,
        &mut reservation,
        InitiatorRetryPhase::Preparation,
        "test_contention",
    ));
    assert!(daemon.schedule_initiator_retry(
        &peer_info.node_id,
        &mut reservation,
        InitiatorRetryPhase::Preparation,
        "duplicate_test_contention",
    ));
    tokio::time::timeout(Duration::from_secs(1), retry_rx.changed())
        .await
        .expect("commit-before-wake retry edge was lost")
        .expect("retry coordinator must stay live");

    let retry_revision = {
        let state = daemon.pending_handshakes.lock();
        assert_eq!(state.initiator_retries.len(), 1);
        let retry = state
            .initiator_retries
            .get(&peer_info.node_id)
            .expect("newest exact retry must remain");
        assert_eq!(retry.identity.reservation_owner, reservation.owner);
        assert_eq!(retry.identity.attempt, 2);
        state.retry_revision()
    };

    daemon.clear_peer_handshake_lifecycle(&peer_info.node_id, "test_peer_left");
    assert!(*cancellation.borrow_and_update());
    {
        let state = daemon.pending_handshakes.lock();
        assert!(!state.starting.contains(&peer_info.node_id));
        assert!(!state.starting_prepared.contains_key(&peer_info.node_id));
        assert!(!state.initiator_retries.contains_key(&peer_info.node_id));
    }

    // A coalesced/late watch value is only a hint.  The authoritative ledger
    // is empty after cancellation, so it cannot resurrect the retired owner.
    daemon.handshake_retry_kick_tx.send_replace(retry_revision);
    assert!(daemon
        .pending_handshakes
        .lock()
        .claim_ready_initiator_retry(Instant::now())
        .is_none());
}
#[tokio::test]
async fn committed_initiator_offer_wait_is_cancelled_when_pending_is_removed() {
    let peer_id = "peer-cancelled-initiator-offer";
    let mut state = PendingHandshakeState::default();
    let reservation = state
        .reserve_start_with_owner(peer_id)
        .expect("initiator reservation must be admitted");
    let local_identity = NodeIdentity::generate();
    let peer_identity = NodeIdentity::generate();
    let initiator = HandshakeInitiator::new(local_identity, peer_identity.public_key(), None);
    let pending_id = state
        .insert_reserved_if_current(
            peer_id.to_string(),
            reservation.owner,
            initiator,
            None,
            None,
        )
        .expect("reservation must commit into a pending initiator");
    assert!(state.is_current(peer_id, pending_id));
    assert!(
        state.pending_cancellations.contains_key(peer_id),
        "committing the initiator must retain the reservation cancellation sender"
    );

    let mut cancellation = reservation.cancellation.clone();
    let (offer_started_tx, offer_started_rx) = tokio::sync::oneshot::channel();
    let offer_wait = tokio::spawn(async move {
        await_initiator_offer_or_cancellation(
            async move {
                let _ = offer_started_tx.send(());
                std::future::pending::<Result<()>>().await
            },
            &mut cancellation,
        )
        .await
    });
    offer_started_rx
        .await
        .expect("offer waiter must reach the slow control-plane wait");

    // `handle_peer_answer` uses this exact removal path after it consumes a
    // matching answer; `clear_peer` reaches it for PeerLeft. Both must wake
    // the committed initiator rather than leave a control-event slot pending.
    assert!(state.remove(peer_id).is_some());
    let outcome = tokio::time::timeout(Duration::from_millis(100), offer_wait)
        .await
        .expect("removing a pending initiator must cancel its offer wait")
        .expect("offer waiter task must not panic");
    assert!(outcome.is_none());
}

#[tokio::test(start_paused = true)]
async fn handshake_arbiter_telemetry_pairs_holder_release_timeout_and_cancellation() {
    use std::task::Poll;

    let timeline = ConnectionTimeline::new("arbiter-telemetry", 0);
    let arbiter = HandshakeArbiter::new(timeline.clone());
    let peer_id = "peer-arbiter-telemetry";
    let owner = arbiter
        .try_acquire(HandshakeLeaseIdentity::new(
            peer_id,
            HandshakeOwnerKind::MaintenanceInitiator,
            Some(77),
            9,
            Some(PeerSessionGeneration::for_test(11)),
            "maintenance_snapshot_commit",
        ))
        .expect("maintenance mutation turn must be acquired");
    let holder = arbiter
        .current_holder(peer_id)
        .expect("current holder metadata must be visible without an async lock");
    assert_eq!(
        holder.identity.owner_kind,
        HandshakeOwnerKind::MaintenanceInitiator
    );
    assert_eq!(holder.identity.phase, "maintenance_snapshot_commit");
    assert_eq!(holder.identity.reservation_owner, Some(77));
    assert_eq!(holder.identity.network_generation, 9);
    assert_eq!(
        holder.identity.peer_session_generation,
        Some(PeerSessionGeneration::for_test(11))
    );
    assert!(holder.held_for < Duration::from_secs(1));

    let contention = match arbiter.try_acquire(HandshakeLeaseIdentity::new(
        peer_id,
        HandshakeOwnerKind::EventInitiatorPrepare,
        Some(78),
        9,
        Some(PeerSessionGeneration::for_test(11)),
        "preparation",
    )) {
        Ok(_) => panic!("the maintenance holder unexpectedly admitted a second turn"),
        Err(contention) => contention,
    };
    assert_eq!(
        contention.holder.unwrap().identity,
        holder.identity,
        "contention diagnostics must identify the actual maintenance holder"
    );

    let mut timed = Box::pin(arbiter.acquire_with_timeout(
        HandshakeLeaseIdentity::new(
            peer_id,
            HandshakeOwnerKind::Responder,
            None,
            9,
            Some(PeerSessionGeneration::for_test(11)),
            "responder_admission",
        ),
        Duration::from_millis(10),
    ));
    std::future::poll_fn(
        |context| match std::future::Future::poll(timed.as_mut(), context) {
            Poll::Pending => Poll::Ready(()),
            Poll::Ready(_) => panic!("bounded waiter completed before paused time advanced"),
        },
    )
    .await;
    tokio::time::advance(Duration::from_millis(11)).await;
    assert!(timed.await.is_none());

    let mut cancelled = Box::pin(arbiter.acquire_with_timeout(
        HandshakeLeaseIdentity::new(
            peer_id,
            HandshakeOwnerKind::Cleanup,
            None,
            9,
            Some(PeerSessionGeneration::for_test(11)),
            "peer_left",
        ),
        Duration::from_secs(1),
    ));
    std::future::poll_fn(
        |context| match std::future::Future::poll(cancelled.as_mut(), context) {
            Poll::Pending => Poll::Ready(()),
            Poll::Ready(_) => panic!("cancellation waiter unexpectedly acquired the turn"),
        },
    )
    .await;
    drop(cancelled);
    drop(owner);
    assert!(arbiter.current_holder(peer_id).is_none());

    let events = timeline.snapshot().events;
    let count = |name: &str| events.iter().filter(|event| event.event == name).count();
    assert_eq!(count("handshake_arbiter_wait_started"), 4);
    assert_eq!(count("handshake_arbiter_acquired"), 1);
    assert_eq!(count("handshake_arbiter_contended"), 1);
    assert_eq!(count("handshake_arbiter_timeout"), 1);
    assert_eq!(count("handshake_arbiter_cancelled"), 1);
    assert_eq!(count("handshake_arbiter_released"), 1);
    assert!(events.iter().any(|event| {
        event.event == "handshake_arbiter_released"
            && event.detail.as_deref().is_some_and(|detail| {
                detail.contains("owner_kind=maintenance_initiator")
                    && detail.contains("phase=maintenance_snapshot_commit")
                    && detail.contains("reservation_owner=77")
                    && detail.contains("held_us=")
            })
    }));
    let diagnostic_text = events
        .iter()
        .filter_map(|event| event.detail.as_deref())
        .collect::<Vec<_>>()
        .join("\n");
    for forbidden in [
        "do-not-log-private-key",
        "do-not-log-session-secret",
        "do-not-log-raw-handshake-token",
    ] {
        assert!(!diagnostic_text.contains(forbidden));
    }
}

#[tokio::test]
async fn peer_scoped_handshake_arbiter_contention_does_not_block_another_peer_session() {
    let arbiter = HandshakeArbiter::default();
    let peer_a = "peer-arbiter-a";
    let peer_b = "peer-arbiter-b";
    let peer_a_owner = arbiter
        .try_acquire(HandshakeLeaseIdentity::new(
            peer_a,
            HandshakeOwnerKind::MaintenanceInitiator,
            Some(1),
            0,
            Some(PeerSessionGeneration::for_test(1)),
            "maintenance_reserve",
        ))
        .unwrap();
    let peer_b_turn = arbiter
        .try_acquire(HandshakeLeaseIdentity::new(
            peer_b,
            HandshakeOwnerKind::Responder,
            None,
            0,
            Some(PeerSessionGeneration::for_test(1)),
            "responder_admission",
        ))
        .expect("peer A's turn must not serialize peer B");
    drop(peer_b_turn);

    let (transport, _outbound_rx) = WireGuardTransport::new();
    let (peer_b_session, _) = part03_establish_sessions();
    transport.add_session(peer_b, peer_b_session).await;
    assert!(transport.has_session(peer_b).await);
    assert_eq!(
        arbiter.current_holder(peer_a).unwrap().identity.owner_kind,
        HandshakeOwnerKind::MaintenanceInitiator
    );
    drop(peer_a_owner);
}

#[test]
fn exact_handshake_retry_has_strict_ttl_and_all_lifecycle_cancellations_are_terminal() {
    fn reserve_retry(
        state: &mut PendingHandshakeState,
        peer_id: &str,
        network_generation: u64,
        peer_session_generation: PeerSessionGeneration,
        now: Instant,
    ) -> (HandshakeStartReservation, watch::Receiver<bool>) {
        let reservation = state
            .reserve_start_with_owner_at_generation(
                peer_id,
                network_generation,
                peer_session_generation,
            )
            .expect("test lifecycle must reserve an initiator");
        let cancellation = reservation.cancellation.clone();
        state
            .schedule_initiator_retry(peer_id, &reservation, InitiatorRetryPhase::Preparation, now)
            .expect("test lifecycle must retain one exact retry");
        (reservation, cancellation)
    }

    let now = Instant::now();
    let peer_generation = PeerSessionGeneration::for_test(1);
    let mut ttl_state = PendingHandshakeState::default();
    let (ttl_reservation, mut ttl_cancellation) =
        reserve_retry(&mut ttl_state, "peer-retry-ttl", 4, peer_generation, now);
    let original_expiry = ttl_state
        .initiator_retries
        .get("peer-retry-ttl")
        .unwrap()
        .expires_at;
    ttl_state
        .schedule_initiator_retry(
            "peer-retry-ttl",
            &ttl_reservation,
            InitiatorRetryPhase::Preparation,
            now + Duration::from_millis(1),
        )
        .expect("duplicate retry must merge before TTL");
    assert_eq!(
        ttl_state
            .initiator_retries
            .get("peer-retry-ttl")
            .unwrap()
            .expires_at,
        original_expiry,
        "duplicate kicks must not extend the strict phase TTL"
    );
    let (claimed_identity, claimed_reservation) = ttl_state
        .claim_ready_initiator_retry(now + Duration::from_millis(12))
        .expect("the merged retry must become ready deterministically");
    assert_eq!(claimed_identity.attempt, 2);
    let (rescheduled_identity, _, _) = ttl_state
        .schedule_initiator_retry(
            "peer-retry-ttl",
            &claimed_reservation,
            InitiatorRetryPhase::Preparation,
            now + Duration::from_millis(12),
        )
        .expect("claimed contention must preserve its retry lineage");
    assert_eq!(rescheduled_identity.attempt, 3);
    assert_eq!(
        ttl_state
            .initiator_retries
            .get("peer-retry-ttl")
            .unwrap()
            .expires_at,
        original_expiry,
        "claim and reschedule must not reset the strict phase TTL"
    );
    assert!(ttl_state
        .claim_ready_initiator_retry(original_expiry)
        .is_none());
    assert!(*ttl_cancellation.borrow_and_update());
    assert!(!ttl_state.starting.contains("peer-retry-ttl"));
    assert!(!ttl_state.initiator_retries.contains_key("peer-retry-ttl"));

    let mut full_lane_expiry = PendingHandshakeState::default();
    let (_, mut full_lane_cancellation) = reserve_retry(
        &mut full_lane_expiry,
        "peer-full-lane-expiry",
        4,
        peer_generation,
        now,
    );
    full_lane_expiry.expire_initiator_retries(now + INITIATOR_RETRY_TTL);
    assert!(*full_lane_cancellation.borrow_and_update());
    assert!(full_lane_expiry.initiator_retries.is_empty());
    assert!(!full_lane_expiry.starting.contains("peer-full-lane-expiry"));

    let mut peer_left = PendingHandshakeState::default();
    let (_, mut peer_left_cancel) =
        reserve_retry(&mut peer_left, "peer-left-retry", 1, peer_generation, now);
    peer_left.clear_peer("peer-left-retry");
    assert!(*peer_left_cancel.borrow_and_update());
    assert!(peer_left.initiator_retries.is_empty());

    let mut offline = PendingHandshakeState::default();
    let (_, mut offline_cancel) =
        reserve_retry(&mut offline, "peer-offline-retry", 1, peer_generation, now);
    offline.clear_peer("peer-offline-retry");
    assert!(*offline_cancel.borrow_and_update());
    assert!(offline.initiator_retries.is_empty());

    let mut generation = PendingHandshakeState::default();
    let (_, mut generation_cancel) = reserve_retry(
        &mut generation,
        "peer-generation-retry",
        1,
        peer_generation,
        now,
    );
    let replacement = generation
        .reserve_start_with_owner_at_generation("peer-generation-retry", 2, peer_generation)
        .expect("a new network generation must replace the stale retry owner");
    assert!(*generation_cancel.borrow_and_update());
    assert_eq!(generation.initiator_retries.len(), 0);
    generation.cancel_reservation_if_current("peer-generation-retry", replacement.owner);

    let mut rejoin = PendingHandshakeState::default();
    let (_, mut rejoin_cancel) =
        reserve_retry(&mut rejoin, "peer-rejoin-retry", 1, peer_generation, now);
    rejoin.clear_peer("peer-rejoin-retry");
    let replacement_generation = PeerSessionGeneration::for_test(2);
    let replacement = rejoin
        .reserve_start_with_owner_at_generation("peer-rejoin-retry", 1, replacement_generation)
        .expect("same-node rejoin must create a new exact lifecycle owner");
    assert!(*rejoin_cancel.borrow_and_update());
    assert_eq!(replacement.peer_session_generation, replacement_generation);
    rejoin.cancel_reservation_if_current("peer-rejoin-retry", replacement.owner);

    let mut responder = PendingHandshakeState::default();
    let (reservation, mut responder_cancel) = reserve_retry(
        &mut responder,
        "peer-responder-retry",
        1,
        peer_generation,
        now,
    );
    assert!(responder.cancel_reservation_if_current("peer-responder-retry", reservation.owner));
    assert!(*responder_cancel.borrow_and_update());
    assert!(responder.initiator_retries.is_empty());

    let mut bounded = PendingHandshakeState::default();
    for index in 0..MAX_PENDING_INITIATOR_RETRIES {
        let peer_id = format!("bounded-retry-{index}");
        let reservation = bounded
            .reserve_start_with_owner_at_generation(&peer_id, 1, peer_generation)
            .unwrap();
        assert!(bounded
            .schedule_initiator_retry(
                &peer_id,
                &reservation,
                InitiatorRetryPhase::Preparation,
                now,
            )
            .is_some());
    }
    let overflow_peer = "bounded-retry-overflow";
    let overflow = bounded
        .reserve_start_with_owner_at_generation(overflow_peer, 1, peer_generation)
        .unwrap();
    assert!(bounded
        .schedule_initiator_retry(
            overflow_peer,
            &overflow,
            InitiatorRetryPhase::Preparation,
            now,
        )
        .is_none());
    assert_eq!(
        bounded.initiator_retries.len(),
        MAX_PENDING_INITIATOR_RETRIES
    );
}

#[tokio::test]
async fn network_generation_advance_synchronously_cancels_exact_handshake_retry_and_pending_offer()
{
    let daemon = Daemon::new(
        Config::generate_default("http://127.0.0.1:1", "generation-cancel-network").unwrap(),
    );
    let peer_id = "peer-generation-hook-cancel";
    let peer_identity = NodeIdentity::generate();
    daemon
        .peers
        .add_peer(&control::PeerInfo {
            node_id: peer_id.to_string(),
            public_key: hex::encode(peer_identity.public_key()),
            virtual_ip: "10.20.0.9".to_string(),
            online: true,
            ..control::PeerInfo::default()
        })
        .await;
    let mut reservation = daemon
        .pending_handshakes
        .lock()
        .reserve_start_with_owner_at_generation(
            peer_id,
            0,
            daemon.peers.peer_session_generation_sync(peer_id).unwrap(),
        )
        .unwrap();
    let mut cancellation = reservation.cancellation.clone();
    assert!(daemon.schedule_initiator_retry(
        peer_id,
        &mut reservation,
        InitiatorRetryPhase::Preparation,
        "test_generation_advance",
    ));

    let pending_peer_id = "peer-generation-hook-pending";
    let pending_peer_identity = NodeIdentity::generate();
    daemon
        .peers
        .add_peer(&control::PeerInfo {
            node_id: pending_peer_id.to_string(),
            public_key: hex::encode(pending_peer_identity.public_key()),
            virtual_ip: "10.20.0.10".to_string(),
            online: true,
            ..control::PeerInfo::default()
        })
        .await;
    let pending_peer_session = daemon
        .peers
        .peer_session_generation_sync(pending_peer_id)
        .unwrap();
    let pending_token = "generation-bound-pending-token".to_string();
    let (pending_id, mut pending_cancellation) = {
        let mut state = daemon.pending_handshakes.lock();
        let pending_reservation = state
            .reserve_start_with_owner_at_generation(pending_peer_id, 0, pending_peer_session)
            .unwrap();
        let cancellation = pending_reservation.cancellation.clone();
        let initiator = HandshakeInitiator::new(
            daemon.local_identity().unwrap(),
            pending_peer_identity.public_key(),
            None,
        );
        let pending_id = state
            .insert_reserved_if_current_with_generation(
                pending_peer_id.to_string(),
                pending_reservation.owner,
                initiator,
                Some(pending_token.clone()),
                None,
                0,
                pending_peer_session,
            )
            .unwrap();
        (pending_id, cancellation)
    };
    assert_eq!(
        daemon
            .peers
            .stage_probe_session_binding(
                pending_peer_id,
                pending_token.clone(),
                Some(pending_token.clone()),
                None,
                false,
            )
            .await,
        ProbeBindingStage::Staged
    );
    assert!(daemon
        .pending_handshakes
        .lock()
        .is_current(pending_peer_id, pending_id));

    assert_eq!(
        daemon
            .peers
            .advance_network_generation("test exact handshake retry cancellation")
            .await,
        1
    );
    assert!(*cancellation.borrow_and_update());
    assert!(*pending_cancellation.borrow_and_update());
    {
        let state = daemon.pending_handshakes.lock();
        assert!(!state.starting.contains(peer_id));
        assert!(!state.initiator_retries.contains_key(peer_id));
        assert!(!state.pending.contains_key(pending_peer_id));
    }
    assert_eq!(
        daemon
            .peers
            .try_confirm_pending_probe_session_binding(pending_peer_id, &pending_token),
        PendingProbeBindingCommitOutcome::Missing,
        "the generation transaction must remove the exact staged Probe binding"
    );

    // Candidate refresh is a second network-generation transition, not a
    // weaker lifecycle. It must execute the same synchronous handshake fence.
    let current_generation = daemon.peers.current_network_generation_sync();
    let peer_session = daemon.peers.peer_session_generation_sync(peer_id).unwrap();
    let mut refresh_reservation = daemon
        .pending_handshakes
        .lock()
        .reserve_start_with_owner_at_generation(peer_id, current_generation, peer_session)
        .unwrap();
    let mut refresh_cancellation = refresh_reservation.cancellation.clone();
    assert!(daemon.schedule_initiator_retry(
        peer_id,
        &mut refresh_reservation,
        InitiatorRetryPhase::Preparation,
        "test_candidate_refresh_generation_advance",
    ));

    let pending_peer_session = daemon
        .peers
        .peer_session_generation_sync(pending_peer_id)
        .unwrap();
    let refresh_pending_token = "candidate-refresh-bound-pending-token".to_string();
    let mut refresh_pending_cancellation = {
        let mut state = daemon.pending_handshakes.lock();
        let reservation = state
            .reserve_start_with_owner_at_generation(
                pending_peer_id,
                current_generation,
                pending_peer_session,
            )
            .unwrap();
        let cancellation = reservation.cancellation.clone();
        state
            .insert_reserved_if_current_with_generation(
                pending_peer_id.to_string(),
                reservation.owner,
                HandshakeInitiator::new(
                    daemon.local_identity().unwrap(),
                    pending_peer_identity.public_key(),
                    None,
                ),
                Some(refresh_pending_token.clone()),
                None,
                current_generation,
                pending_peer_session,
            )
            .unwrap();
        cancellation
    };
    assert_eq!(
        daemon
            .peers
            .stage_probe_session_binding(
                pending_peer_id,
                refresh_pending_token.clone(),
                Some(refresh_pending_token.clone()),
                None,
                false,
            )
            .await,
        ProbeBindingStage::Staged
    );

    assert_eq!(
        daemon
            .peers
            .advance_candidate_refresh_generation("test candidate-refresh handshake cancellation",)
            .await,
        current_generation + 1
    );
    assert!(*refresh_cancellation.borrow_and_update());
    assert!(*refresh_pending_cancellation.borrow_and_update());
    {
        let state = daemon.pending_handshakes.lock();
        assert!(!state.starting.contains(peer_id));
        assert!(!state.initiator_retries.contains_key(peer_id));
        assert!(!state.pending.contains_key(pending_peer_id));
    }
    assert_eq!(
        daemon
            .peers
            .try_confirm_pending_probe_session_binding(pending_peer_id, &refresh_pending_token,),
        PendingProbeBindingCommitOutcome::Missing,
        "candidate refresh must remove the exact staged Probe binding"
    );
}

#[test]
fn handshake_lifecycle_model_checks_first_1000_deterministic_interleavings() {
    fn next_permutation(values: &mut [u8]) -> bool {
        let Some(pivot) = (0..values.len().saturating_sub(1))
            .rev()
            .find(|&index| values[index] < values[index + 1])
        else {
            return false;
        };
        let swap = (pivot + 1..values.len())
            .rev()
            .find(|&index| values[pivot] < values[index])
            .unwrap();
        values.swap(pivot, swap);
        values[pivot + 1..].reverse();
        true
    }

    const MAINTENANCE_SNAPSHOT: u8 = 0;
    const EVENT_RESERVE: u8 = 1;
    const MAINTENANCE_RESERVE: u8 = 2;
    const EVENT_PREPARE: u8 = 3;
    const RESPONDER_OFFER: u8 = 4;
    const PUBLISH: u8 = 5;
    const GENERATION_ADVANCE: u8 = 6;

    let peer_id = "peer-interleaving-model";
    let peer_generation = PeerSessionGeneration::for_test(1);
    let mut order = [0, 1, 2, 3, 4, 5, 6];
    let mut checked = 0usize;
    loop {
        let mut state = PendingHandshakeState::default();
        let mut network_generation = 1u64;
        let mut event_owner: Option<HandshakeStartReservation> = None;
        let mut prepared_owner: Option<(u64, u64, u64)> = None;
        let mut responder_session = false;
        let mut valid_offers = 0usize;
        let stale_owner_commits = 0usize;

        for action in order {
            match action {
                MAINTENANCE_SNAPSHOT => {
                    // Snapshot-only work has no mutation ownership.
                }
                EVENT_RESERVE if !responder_session => {
                    if let Some(reservation) = state
                        .reserve_start_with_owner_at_generation_and_kind(
                            peer_id,
                            network_generation,
                            peer_generation,
                            HandshakeOwnerKind::EventInitiatorReserve,
                        )
                    {
                        event_owner = Some(reservation);
                    }
                }
                MAINTENANCE_RESERVE if !responder_session => {
                    let _ = state.reserve_start_with_owner_at_generation_and_kind(
                        peer_id,
                        network_generation,
                        peer_generation,
                        HandshakeOwnerKind::MaintenanceInitiator,
                    );
                }
                EVENT_PREPARE => {
                    if let Some(reservation) = event_owner.as_ref().filter(|reservation| {
                        state.starting_reservation_is_current(peer_id, reservation)
                    }) {
                        prepared_owner = Some((
                            reservation.owner,
                            reservation.network_generation,
                            reservation.cancellation_generation,
                        ));
                    }
                }
                RESPONDER_OFFER => {
                    state.cancel_reservation(peer_id);
                    responder_session = true;
                }
                PUBLISH => {
                    if let (Some(reservation), Some(prepared)) =
                        (event_owner.as_ref(), prepared_owner)
                    {
                        let current = state.starting_reservation_is_current(peer_id, reservation)
                            && prepared
                                == (
                                    reservation.owner,
                                    network_generation,
                                    reservation.cancellation_generation,
                                )
                            && !responder_session;
                        if current {
                            valid_offers += 1;
                            state.cancel_reservation(peer_id);
                        }
                    }
                }
                GENERATION_ADVANCE => {
                    network_generation = network_generation.saturating_add(1);
                    state.clear_peer(peer_id);
                    prepared_owner = None;
                }
                _ => {}
            }
            assert!(state.starting.len() <= 1);
            assert!(state.initiator_retries.len() <= 1);
            assert!(valid_offers <= 1);
            assert_eq!(stale_owner_commits, 0);
        }
        state.clear_peer(peer_id);
        assert!(state.starting.is_empty());
        assert!(state.initiator_retries.is_empty());
        checked += 1;
        if checked == 1000 || !next_permutation(&mut order) {
            break;
        }
    }
    assert_eq!(checked, 1000);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn maintenance_snapshot_race_yields_to_event_single_offer_and_one_session() {
    let mut control_capture = start_handshake_control_capture().await;
    let mut config =
        Config::generate_default(&control_capture.base_url, "handshake-race-network").unwrap();
    config.control.auth_token = "handshake-race-token".to_string();
    config.node.node_id = "node-local".to_string();
    let daemon = Arc::new(Daemon::new(config));
    timeout(Duration::from_secs(2), control_capture.wait_registered())
        .await
        .expect("daemon registration must not stall the deterministic race");

    let local_public = daemon.local_identity().unwrap().public_key();
    let remote_identity = loop {
        let identity = NodeIdentity::generate();
        if local_public < identity.public_key() {
            break identity;
        }
    };
    let peer_info = control::PeerInfo {
        node_id: "peer-maintenance-event-race".to_string(),
        public_key: hex::encode(remote_identity.public_key()),
        virtual_ip: "10.20.0.2".to_string(),
        online: true,
        ..control::PeerInfo::default()
    };
    daemon.peers.add_peer(&peer_info).await;
    daemon.relay_available_tx.send_replace(true);
    let network_generation = daemon.peers.current_network_generation_sync();
    let peer_session_generation = daemon
        .peers
        .peer_session_generation_sync(&peer_info.node_id)
        .unwrap();

    // Pause maintenance after its actor/control snapshots and immediately
    // before its zero-wait mutation turn: this is the exact boundary where the
    // old implementation held the arbiter across session/control awaits.
    let snapshot_ready = Arc::new(tokio::sync::Barrier::new(2));
    let allow_reserve = Arc::new(tokio::sync::Barrier::new(2));
    let maintenance = tokio::spawn({
        let transport = daemon.transport.clone();
        let pending = daemon.pending_handshakes.clone();
        let arbiter = daemon.handshake_arbiter.clone();
        let peer_id = peer_info.node_id.clone();
        let snapshot_ready = snapshot_ready.clone();
        let allow_reserve = allow_reserve.clone();
        async move {
            let status = transport.session_status(&peer_id).await;
            assert!(!status.has_active);
            snapshot_ready.wait().await;
            allow_reserve.wait().await;
            try_reserve_maintenance_initiator(
                &pending,
                &arbiter,
                &peer_id,
                network_generation,
                peer_session_generation,
            )
        }
    });
    snapshot_ready.wait().await;
    assert!(
        daemon
            .handshake_arbiter
            .current_holder(&peer_info.node_id)
            .is_none(),
        "maintenance snapshots must not own a mutation turn"
    );
    let mut event_reservation = daemon
        .reserve_event_initiator_handshake(&peer_info.node_id)
        .expect("PeerJoined must reserve while maintenance is paused at its old await boundary");
    let event_owner = event_reservation.owner;
    allow_reserve.wait().await;
    let maintenance_outcome = timeout(Duration::from_secs(1), maintenance)
        .await
        .expect("maintenance zero-wait admission did not terminate")
        .expect("maintenance snapshot task panicked");
    assert!(matches!(
        maintenance_outcome,
        MaintenanceInitiatorReservationOutcome::Busy
    ));

    let punch_at = timeout(
        Duration::from_secs(2),
        daemon.run_reserved_initiator_handshake(&peer_info, &mut event_reservation),
    )
    .await
    .expect("event preparation/publish must not wait on the retired maintenance producer")
    .expect("event initiator failed")
    .expect("event initiator did not publish its one Offer");
    assert!(punch_at > 0);
    timeout(
        Duration::from_secs(1),
        control_capture.wait_for_signal_count(1),
    )
    .await
    .expect("mock control did not receive the event Offer");
    let bodies = control_capture.signal_bodies();
    let offers = bodies
        .iter()
        .filter_map(|body| serde_json::from_str::<serde_json::Value>(body).ok())
        .filter(|body| body.get("type").and_then(serde_json::Value::as_str) == Some("peer_offer"))
        .collect::<Vec<_>>();
    assert_eq!(offers.len(), 1, "the lifecycle may publish one valid Offer");
    let offer = &offers[0];
    let initiation = hex::decode(
        offer
            .get("handshake")
            .and_then(serde_json::Value::as_str)
            .expect("captured Offer omitted its WireGuard initiation"),
    )
    .unwrap();
    let session_id = offer
        .get("session_id")
        .and_then(serde_json::Value::as_str)
        .expect("captured Offer omitted its exact session id")
        .to_string();
    let initiation = MessageInitiation::from_bytes(&initiation).unwrap();
    let mut remote_responder = HandshakeResponder::new(remote_identity, None);
    let (response, _) = remote_responder
        .consume_initiation_and_respond(&initiation)
        .unwrap();
    let remote_probe_public = hex::encode(DhKeyPair::generate().public_key());
    assert!(daemon
        .handle_peer_answer(
            &peer_info.node_id,
            &response.to_bytes(),
            Some(session_id),
            Some(remote_probe_public),
        )
        .await
        .unwrap());
    assert!(daemon.transport.has_session(&peer_info.node_id).await);
    {
        let state = daemon.pending_handshakes.lock();
        assert!(!state.pending.contains_key(&peer_info.node_id));
        assert!(!state.starting.contains(&peer_info.node_id));
        assert!(!state.initiator_retries.contains_key(&peer_info.node_id));
    }
    let staged = daemon
        .timeline
        .snapshot()
        .events
        .iter()
        .filter(|event| {
            event.event == "initiator_session_staged"
                && event
                    .detail
                    .as_deref()
                    .is_some_and(|detail| detail.contains(&format!("owner={event_owner}")))
        })
        .count();
    assert_eq!(staged, 1);
    control_capture.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn responder_preempts_contended_initiator_retry_with_bounded_turn_and_no_stale_offer() {
    let mut control_capture = start_handshake_control_capture().await;
    let mut config =
        Config::generate_default(&control_capture.base_url, "responder-preemption-network")
            .unwrap();
    config.control.auth_token = "responder-preemption-token".to_string();
    config.node.node_id = "node-local".to_string();
    let daemon = Arc::new(Daemon::new(config));
    timeout(Duration::from_secs(2), control_capture.wait_registered())
        .await
        .expect("daemon registration must complete before responder preemption");

    let local_public = daemon.local_identity().unwrap().public_key();
    let remote_identity = loop {
        let identity = NodeIdentity::generate();
        if identity.public_key() < local_public {
            break identity;
        }
    };
    let peer_id = "peer-responder-preempts-initiator";
    let peer_info = control::PeerInfo {
        node_id: peer_id.to_string(),
        public_key: hex::encode(remote_identity.public_key()),
        virtual_ip: "10.20.0.3".to_string(),
        online: true,
        ..control::PeerInfo::default()
    };
    daemon.peers.add_peer(&peer_info).await;
    daemon.relay_available_tx.send_replace(true);
    let network_generation = daemon.peers.current_network_generation_sync();
    let peer_session_generation = daemon.peers.peer_session_generation_sync(peer_id).unwrap();
    let mut stale_reservation = daemon
        .pending_handshakes
        .lock()
        .reserve_start_with_owner_at_generation(
            peer_id,
            network_generation,
            peer_session_generation,
        )
        .expect("stale event initiator must own the setup transaction");
    let stale_owner = stale_reservation.owner;
    let mut stale_cancellation = stale_reservation.cancellation.clone();

    let blocking_turn = daemon
        .handshake_arbiter
        .try_acquire(HandshakeLeaseIdentity::new(
            peer_id,
            HandshakeOwnerKind::EventInitiatorPrepare,
            Some(stale_owner),
            network_generation,
            Some(peer_session_generation),
            "preparation",
        ))
        .unwrap();
    let preparation_result = timeout(
        Duration::from_millis(100),
        daemon.run_reserved_initiator_handshake(&peer_info, &mut stale_reservation),
    )
    .await
    .expect("preparation contention must return without waiting for the held turn")
    .expect("preparation contention is non-fatal");
    assert_eq!(preparation_result, None);
    assert_eq!(
        stale_reservation.disposition,
        HandshakeStartDisposition::RetryScheduled
    );
    assert_eq!(
        daemon
            .pending_handshakes
            .lock()
            .initiator_retries
            .get(peer_id)
            .unwrap()
            .identity
            .phase,
        InitiatorRetryPhase::Preparation
    );
    let mut remote_initiator = HandshakeInitiator::new(remote_identity, local_public, None);
    let initiation = remote_initiator.create_initiation().unwrap().to_bytes();
    let responder = {
        let daemon = daemon.clone();
        let peer_id = peer_id.to_string();
        tokio::spawn(async move {
            daemon
                .handle_peer_offer(&peer_id, &[], &initiation, None, None, None, None)
                .await
        })
    };
    timeout(Duration::from_secs(1), async {
        loop {
            if daemon.timeline.snapshot().events.iter().any(|event| {
                event.event == "handshake_arbiter_wait_started"
                    && event.detail.as_deref().is_some_and(|detail| {
                        detail.contains(peer_id)
                            && detail.contains("owner_kind=responder")
                            && detail.contains("holder_kind=event_initiator_prepare")
                            && detail.contains(&format!("holder_reservation_owner={stale_owner}"))
                    })
            }) {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("responder did not expose the exact contending initiator holder");
    drop(blocking_turn);
    timeout(Duration::from_secs(2), responder)
        .await
        .expect("responder exceeded its bounded mutation-turn/control budget")
        .expect("responder task panicked")
        .expect("legal responder offer failed");
    assert!(*stale_cancellation.borrow_and_update());
    assert!(daemon.transport.has_session(peer_id).await);
    {
        let state = daemon.pending_handshakes.lock();
        assert!(!state.starting.contains(peer_id));
        assert!(!state.initiator_retries.contains_key(peer_id));
        assert!(!state.pending.contains_key(peer_id));
    }
    timeout(
        Duration::from_secs(1),
        control_capture.wait_for_signal_count(1),
    )
    .await
    .expect("responder answer was not delivered");
    let bodies = control_capture.signal_bodies();
    assert_eq!(
        bodies
            .iter()
            .filter_map(|body| serde_json::from_str::<serde_json::Value>(body).ok())
            .filter(|body| {
                body.get("type").and_then(serde_json::Value::as_str) == Some("peer_answer")
            })
            .count(),
        1
    );
    assert_eq!(
        bodies
            .iter()
            .filter_map(|body| serde_json::from_str::<serde_json::Value>(body).ok())
            .filter(|body| {
                body.get("type").and_then(serde_json::Value::as_str) == Some("peer_offer")
            })
            .count(),
        0,
        "the cancelled initiator retry must not publish a stale Offer"
    );
    control_capture.stop().await;
}

#[test]
fn handshake_role_is_deterministic_from_decoded_static_public_keys() {
    let lower = [0x11; 32];
    let higher = [0x22; 32];

    assert!(local_is_designated_handshake_initiator(&lower, &higher));
    assert!(!local_is_designated_handshake_initiator(&higher, &lower));
    assert!(!local_is_designated_handshake_initiator(&lower, &lower));
    assert!(should_start_initiator_for_keys(&lower, &higher));
    assert!(!should_start_initiator_for_keys(&higher, &lower));
    // Equal static keys are invalid configuration, but must remain visible to
    // the normal handshake validator instead of being silently suppressed by
    // the scheduling gate.
    assert!(should_start_initiator_for_keys(&lower, &lower));
}

#[tokio::test]
async fn handshake_arbiter_prunes_dead_peer_locks_on_churn() {
    let arbiter = HandshakeArbiter::default();
    let first = arbiter
        .try_acquire(HandshakeLeaseIdentity::new(
            "peer-old",
            HandshakeOwnerKind::MaintenanceInitiator,
            None,
            1,
            Some(PeerSessionGeneration::for_test(1)),
            "test_owner",
        ))
        .unwrap();
    drop(first);
    let second = arbiter
        .try_acquire(HandshakeLeaseIdentity::new(
            "peer-new",
            HandshakeOwnerKind::MaintenanceInitiator,
            None,
            1,
            Some(PeerSessionGeneration::for_test(1)),
            "test_owner",
        ))
        .unwrap();
    drop(second);

    assert!(!arbiter.peer_locks.lock().unwrap().contains_key("peer-old"));
}

#[tokio::test]
async fn handshake_arbiter_wait_is_bounded_and_recovers_after_owner_release() {
    let arbiter = HandshakeArbiter::default();
    let owner_identity = HandshakeLeaseIdentity::new(
        "peer-lock-timeout",
        HandshakeOwnerKind::MaintenanceInitiator,
        Some(7),
        3,
        Some(PeerSessionGeneration::for_test(4)),
        "maintenance_reserve",
    );
    let owner = arbiter.try_acquire(owner_identity).unwrap();

    assert!(
        arbiter
            .acquire_with_timeout(
                HandshakeLeaseIdentity::new(
                    "peer-lock-timeout",
                    HandshakeOwnerKind::Responder,
                    None,
                    3,
                    Some(PeerSessionGeneration::for_test(4)),
                    "responder_admission",
                ),
                Duration::from_millis(10),
            )
            .await
            .is_none(),
        "a responder must not wait forever behind a stale handshake owner"
    );

    drop(owner);
    assert!(
        arbiter
            .acquire_with_timeout(
                HandshakeLeaseIdentity::new(
                    "peer-lock-timeout",
                    HandshakeOwnerKind::Responder,
                    None,
                    3,
                    Some(PeerSessionGeneration::for_test(4)),
                    "responder_admission",
                ),
                Duration::from_millis(100),
            )
            .await
            .is_some(),
        "the same peer must recover immediately after the owner releases"
    );
}

#[test]
fn responder_handshake_cache_replays_exact_answer_and_rejects_token_reuse() {
    let initiator_identity = NodeIdentity::generate();
    let initiator_public = initiator_identity.public_key();
    let responder_identity = NodeIdentity::generate();
    let mut initiator =
        HandshakeInitiator::new(initiator_identity, responder_identity.public_key(), None);
    let initiation = initiator.create_initiation().unwrap();
    let initiation_bytes = initiation.to_bytes();
    let mut responder = HandshakeResponder::new(responder_identity, None);
    let (response, keys) = responder
        .consume_initiation_and_respond(&initiation)
        .unwrap();
    let response_bytes = response.to_bytes();
    let request_probe_public_key = hex::encode([0xabu8; 32]);
    let differently_cased_probe_public_key =
        format!("  {}  ", request_probe_public_key.to_ascii_uppercase());

    let mut state = PendingHandshakeState::default();
    state.cache_responder_handshake(
        "peer-cache",
        "session-cache",
        CachedResponderHandshake {
            lifecycle: ResponderHandshakeLifecycle {
                network_generation: 0,
                peer_session_generation: PeerSessionGeneration::for_test(1),
            },
            handshake_init: initiation_bytes.clone(),
            initiator_static_public_key: initiator_public,
            request_probe_ephemeral_public_key: Some(differently_cased_probe_public_key),
            response_bytes: response_bytes.clone(),
            transport_keys: keys,
            response_probe_ephemeral_public_key: Some("probe-public".to_string()),
            probe_ephemeral_shared: Some([7u8; 32]),
            expires_at: Instant::now() + RESPONDER_HANDSHAKE_CACHE_TTL,
        },
    );

    let ResponderHandshakeCacheLookup::Hit(cached) = state.responder_cache_lookup(
        "peer-cache",
        "session-cache",
        ResponderHandshakeLifecycle {
            network_generation: 0,
            peer_session_generation: PeerSessionGeneration::for_test(1),
        },
        &initiation_bytes,
        Some(&request_probe_public_key),
        &initiator_public,
    ) else {
        panic!("exact duplicate offer should hit responder cache");
    };
    assert_eq!(cached.response_bytes, response_bytes);
    assert_eq!(
        cached.response_probe_ephemeral_public_key.as_deref(),
        Some("probe-public")
    );

    let mut mismatched = initiation_bytes;
    *mismatched.last_mut().unwrap() ^= 1;
    assert!(matches!(
        state.responder_cache_lookup(
            "peer-cache",
            "session-cache",
            ResponderHandshakeLifecycle {
                network_generation: 0,
                peer_session_generation: PeerSessionGeneration::for_test(1),
            },
            &mismatched,
            Some(&request_probe_public_key),
            &initiator_public,
        ),
        ResponderHandshakeCacheLookup::FingerprintMismatch
    ));

    assert!(matches!(
        state.responder_cache_lookup(
            "peer-cache",
            "session-cache",
            ResponderHandshakeLifecycle {
                network_generation: 0,
                peer_session_generation: PeerSessionGeneration::for_test(1),
            },
            &initiation.to_bytes(),
            Some(&hex::encode([0xcdu8; 32])),
            &initiator_public,
        ),
        ResponderHandshakeCacheLookup::FingerprintMismatch
    ));

    assert!(matches!(
        state.responder_cache_lookup(
            "peer-cache",
            "session-cache",
            ResponderHandshakeLifecycle {
                network_generation: 0,
                peer_session_generation: PeerSessionGeneration::for_test(1),
            },
            &initiation.to_bytes(),
            Some(&request_probe_public_key),
            &[0xee; 32],
        ),
        ResponderHandshakeCacheLookup::FingerprintMismatch
    ));

    assert!(matches!(
        state.responder_cache_lookup(
            "peer-cache",
            "session-cache",
            ResponderHandshakeLifecycle {
                network_generation: 1,
                peer_session_generation: PeerSessionGeneration::for_test(1),
            },
            &initiation.to_bytes(),
            Some(&request_probe_public_key),
            &initiator_public,
        ),
        ResponderHandshakeCacheLookup::StaleLifecycle
    ));
    assert!(!state
        .responder_cache
        .contains_key(&("peer-cache".to_string(), "session-cache".to_string())));

    state.cache_responder_handshake("peer-cache", "session-cache", (*cached).clone());
    assert!(matches!(
        state.responder_cache_lookup(
            "peer-cache",
            "session-cache",
            ResponderHandshakeLifecycle {
                network_generation: 0,
                peer_session_generation: PeerSessionGeneration::for_test(2),
            },
            &initiation.to_bytes(),
            Some(&request_probe_public_key),
            &initiator_public,
        ),
        ResponderHandshakeCacheLookup::StaleLifecycle
    ));
    assert!(!state
        .responder_cache
        .contains_key(&("peer-cache".to_string(), "session-cache".to_string())));
}
