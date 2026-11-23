// Exercise the actual bounded candidate worker, including ordinary startup
// traffic. A direct call to the HH handler skips the ingress limiter.
async fn startup_offer(
    daemon: &Daemon,
    record: &HardHardSessionRecord,
    revision: u64,
    coordinated: bool,
) -> PendingPeerOffer {
    let candidates = endpoints(40_000 + revision as u16 * 4)
        .iter()
        .map(ToString::to_string)
        .collect::<Vec<_>>();
    let mut coordination = envelope(HardHardV2Stage::Offer);
    coordination.v2.as_mut().unwrap().local = parameters(40_000 + revision as u16 * 4, 2);
    coordination.local_profile_generation = record.remote_profile_generation;
    coordination.remote_profile_generation = record.local_profile_generation;
    let label = if coordinated {
        fresh_prediction_source_label(FreshPredictionId {
            boot_epoch: 100,
            generation: revision,
        })
    } else {
        "predicted".to_string()
    };
    PendingPeerOffer {
        nat_profile: None,
        from_node_id: record.peer_id.clone(),
        candidate_sources: candidates
            .iter()
            .map(|candidate| (candidate.clone(), label.clone()))
            .collect(),
        candidates,
        candidate_generation: revision,
        network_generation: daemon.peers.current_network_generation_sync(),
        peer_session_generation: daemon.peers.peer_session_generation_sync(&record.peer_id),
        candidates_expires_at_ms: Some(hard_hard_now_ms() + 45_000),
        sender_public_key: Some(
            daemon
                .peers
                .get_connection(&record.peer_id)
                .await
                .unwrap()
                .public_key,
        ),
        handshake_init: Vec::new(),
        punch_at_ms: Some(hard_hard_now_ms() + 3_500),
        punch_at_server_ms: Some(hard_hard_now_ms() + 3_500),
        session_id: coordinated.then(|| coordination.encode()),
        probe_ephemeral_public_key: None,
        delivery_receipt: None,
    }
}

#[tokio::test]
async fn hard_hard_startup_budgets_and_rejection_reasons_remain_bounded() {
    let (daemon, record, _, _) = barrier_fixture().await;
    daemon
        .peers
        .clear_hard_hard_sessions(Some(&record.peer_id))
        .await;
    for revision in 1..=8 {
        let offer = startup_offer(&daemon, &record, revision, revision >= 6).await;
        let (reservation, offer) = startup_reserve(&daemon, offer);
        daemon.run_candidate_offer_worker(*offer, reservation).await;
        let expected = match revision {
            5 => 4,
            8 => 7,
            _ => revision,
        };
        assert_eq!(
            daemon
                .peers
                .get_connection(&record.peer_id)
                .await
                .unwrap()
                .last_candidate_generation(),
            expected
        );
    }
    let conn = daemon.peers.get_connection(&record.peer_id).await.unwrap();
    assert!(
        conn.direct_events
            .iter()
            .any(|event| event.stage == "hard_hard_session_rejected"
                && event.detail.contains("signal_rate_limited")),
        "actual ingress throttling must not masquerade as a missing fresh label"
    );
    assert!(daemon
        .peers
        .remote_fresh_snapshot_for(
            &record.peer_id,
            FreshPredictionId {
                boot_epoch: 100,
                generation: 8
            }
        )
        .await
        .is_none());
}

#[tokio::test(start_paused = true)]
async fn hard_hard_startup_deferred_refresh_yields_to_coordinated_successor() {
    let (daemon, record, _, _) = barrier_fixture().await;
    let ordinary = startup_offer(&daemon, &record, 1, false).await;
    let coordinated = startup_offer(&daemon, &record, 2, true).await;
    let (reservation, offer) = startup_reserve(&daemon, ordinary);
    let mut worker = Box::pin(daemon.run_candidate_offer_worker(*offer, reservation));
    assert!(futures_util::poll!(&mut worker).is_pending());
    assert!(matches!(
        daemon
            .pending_handshakes
            .lock()
            .enqueue_candidate_offer_work(coordinated),
        CandidateOfferWorkAdmission::Coalesced { .. }
    ));
    tokio::time::timeout(Duration::from_millis(100), worker)
        .await
        .unwrap();
    assert!(!record.cancellation.is_cancelled());
    assert!(daemon.peers.get_connection(&record.peer_id).await.unwrap().direct_events.iter()
        .any(|event| event.stage == "hard_hard_signal_repeat_rejected"),
        "even a rejected same-token replay must be checked promptly ahead of the deferred ordinary update");
}

#[tokio::test(start_paused = true)]
async fn hard_hard_startup_deferred_refresh_has_a_monotonic_deadline() {
    let (daemon, record, _, _) = barrier_fixture().await;
    let offer = startup_offer(&daemon, &record, 1, false).await;
    let (reservation, offer) = startup_reserve(&daemon, offer);
    let mut worker = Box::pin(daemon.run_candidate_offer_worker(*offer, reservation));
    assert!(futures_util::poll!(&mut worker).is_pending());
    // Frozen wall time must not keep the candidate worker alive forever.
    tokio::time::timeout(
        HARD_HARD_SESSION_TTL + HARD_HARD_PUNCH_LEAD + Duration::from_secs(1),
        worker,
    )
    .await
    .unwrap();
    assert!(!record.cancellation.is_cancelled());
    assert_eq!(
        daemon
            .peers
            .get_connection(&record.peer_id)
            .await
            .unwrap()
            .last_candidate_generation(),
        0
    );
    assert!(daemon
        .timeline
        .snapshot()
        .events
        .iter()
        .any(|event| event.event == "peer_offer_candidate_wait_expired"));
    assert!(!daemon
        .pending_handshakes
        .lock()
        .has_candidate_offer_work_for_test(&record.peer_id));
}

#[tokio::test(start_paused = true)]
async fn hard_hard_startup_deferred_refresh_cannot_cross_network_generation() {
    let (daemon, record, _, _) = barrier_fixture().await;
    let offer = startup_offer(&daemon, &record, 1, false).await;
    let (reservation, offer) = startup_reserve(&daemon, offer);
    let mut worker = Box::pin(daemon.run_candidate_offer_worker(*offer, reservation));
    assert!(futures_util::poll!(&mut worker).is_pending());
    daemon
        .peers
        .advance_network_generation("test deferred candidate handover")
        .await;
    tokio::time::timeout(Duration::from_secs(1), worker)
        .await
        .unwrap();
    assert_eq!(
        daemon
            .peers
            .get_connection(&record.peer_id)
            .await
            .unwrap()
            .last_candidate_generation(),
        0
    );
}

#[tokio::test(start_paused = true)]
async fn hard_hard_startup_deferred_refresh_cancellation_releases_worker() {
    let (daemon, record, _, _) = barrier_fixture().await;
    let offer = startup_offer(&daemon, &record, 1, false).await;
    let (reservation, offer) = startup_reserve(&daemon, offer);
    let mut worker = Box::pin(daemon.run_candidate_offer_worker(*offer, reservation));
    assert!(futures_util::poll!(&mut worker).is_pending());
    daemon.pending_handshakes.lock().clear_peer(&record.peer_id);
    tokio::time::timeout(Duration::from_millis(1), worker)
        .await
        .unwrap();
    assert_eq!(
        daemon
            .peers
            .get_connection(&record.peer_id)
            .await
            .unwrap()
            .last_candidate_generation(),
        0
    );
}

fn startup_reserve(
    daemon: &Daemon,
    offer: PendingPeerOffer,
) -> (CandidateOfferWorkReservation, Box<PendingPeerOffer>) {
    let CandidateOfferWorkAdmission::Started(reservation, offer) = daemon
        .pending_handshakes
        .lock()
        .enqueue_candidate_offer_work(offer)
    else {
        panic!("test requires an idle candidate owner")
    };
    (reservation, offer)
}

#[tokio::test]
async fn hard_hard_startup_roster_endpoint_revision_preserves_measuring_owner() {
    for measured in [false, true] {
        let (mut daemon, record, _, _) = barrier_fixture().await;
        let (control, receiver) =
            ControlClient::new(&daemon.config, false, None, None, daemon.timeline.clone());
        daemon.control = control;
        daemon.control_rx = receiver;
        if !measured {
            daemon
                .peers
                .clear_hard_hard_sessions(Some(&record.peer_id))
                .await;
        }
        let peers = daemon.peers.clone();
        let generation = peers.peer_session_generation_sync(&record.peer_id).unwrap();
        let Some(RendezvousPunchClaim::Claimed(permit)) = daemon
            .punch_attempts
            .claim_for_epoch_with_rendezvous_for_peer_session(
                &peers,
                &record.peer_id,
                generation,
                record.local_network_generation,
                1,
                PUNCH_PRIORITY_HARD_HARD,
                None,
                Some(hard_hard_now_ms() + 3_500),
            )
            .await
        else {
            panic!("fixture requires a measuring fresh owner")
        };
        let info = control::PeerInfo {
            node_id: record.peer_id.clone(),
            online: true,
            public_key: peers
                .get_connection(&record.peer_id)
                .await
                .unwrap()
                .public_key,
            endpoint: "203.0.113.20:49000".into(),
            registration_seq: 202,
            capabilities: control::PeerCapabilities::current(),
            nat_type: format!(
                "p2v2:m=address_or_port_dependent;a=linear;d=1;c=60;f=unknown;h=unknown;g={};o=1",
                record.remote_profile_generation
            ),
            ..Default::default()
        };
        let control = daemon.control.clone();
        let shutdown = daemon.shutdown_sender();
        let (network_tx, _network_rx) = tokio::sync::mpsc::channel(8);
        let task = tokio::spawn(async move {
            daemon.run_control_event_loop(&mut false, network_tx).await;
        });
        for replacement in [false, true] {
            let mut update = info.clone();
            if replacement {
                update.public_key = hex::encode(NodeIdentity::generate().public_key());
            }
            let receipt = control::SignalDeliveryReceipt::pending();
            control
                .event_sender()
                .send(ControlEvent::DeliveredSignal {
                    signal_id: format!("roster-revision-{measured}-{replacement}"),
                    signal_seq: Some(1 + u64::from(replacement)),
                    signal_type: "peer_updated".into(),
                    event: Box::new(ControlEvent::PeerUpdated(update)),
                    receipt: receipt.clone(),
                })
                .unwrap();
            assert_eq!(
                tokio::time::timeout(Duration::from_secs(2), receipt.wait())
                    .await
                    .unwrap(),
                control::SignalApplyOutcome::Applied
            );
            assert_eq!(permit.is_cancelled(), replacement,
                "endpoint metadata must preserve the fresh owner before/after measurement; new identity must retire it");
        }
        let _ = shutdown.send(true);
        tokio::time::timeout(Duration::from_secs(2), task)
            .await
            .unwrap()
            .unwrap();
    }
}

#[tokio::test]
async fn hard_hard_startup_burst_does_not_consume_coordination_admission() {
    let (daemon, record, _, _) = barrier_fixture().await;
    daemon
        .peers
        .clear_hard_hard_sessions(Some(&record.peer_id))
        .await;
    for revision in 1..=4 {
        let offer = startup_offer(&daemon, &record, revision, false).await;
        let (reservation, offer) = startup_reserve(&daemon, offer);
        daemon.run_candidate_offer_worker(*offer, reservation).await;
    }
    let offer = startup_offer(&daemon, &record, 5, true).await;
    let (reservation, offer) = startup_reserve(&daemon, offer);
    daemon.run_candidate_offer_worker(*offer, reservation).await;
    assert!(
        daemon
            .peers
            .remote_fresh_snapshot_for(
                &record.peer_id,
                FreshPredictionId {
                    boot_epoch: 100,
                    generation: 5
                }
            )
            .await
            .is_some(),
        "the fifth startup offer must admit its real fresh labels after four ordinary updates"
    );
    let conn = daemon.peers.get_connection(&record.peer_id).await.unwrap();
    assert!(!conn
        .direct_events
        .iter()
        .any(|event| event.stage == "hard_hard_session_rejected"
            && event.detail.contains("fresh_label_missing")));
}

#[tokio::test(start_paused = true)]
async fn hard_hard_startup_candidate_refresh_waits_for_existing_owner() {
    let (daemon, record, _, _) = barrier_fixture().await;
    let before = daemon.peers.get_connection(&record.peer_id).await.unwrap();
    let offer = startup_offer(&daemon, &record, 1, false).await;
    let expected_candidates = offer.candidates.clone();
    let (reservation, offer) = startup_reserve(&daemon, offer);
    let mut worker = Box::pin(daemon.run_candidate_offer_worker(*offer, reservation));
    assert!(
        futures_util::poll!(&mut worker).is_pending(),
        "ordinary candidate refresh must wait instead of cancelling a live HH session"
    );
    assert!(!record.cancellation.is_cancelled());
    assert_eq!(
        daemon
            .peers
            .get_connection(&record.peer_id)
            .await
            .unwrap()
            .remote_candidate_epoch(),
        before.remote_candidate_epoch()
    );
    daemon
        .peers
        .clear_hard_hard_sessions(Some(&record.peer_id))
        .await;
    tokio::time::timeout(Duration::from_secs(1), worker)
        .await
        .unwrap();
    let after = daemon.peers.get_connection(&record.peer_id).await.unwrap();
    assert_eq!(after.last_candidate_generation(), 1);
    assert!(
        expected_candidates
            .iter()
            .all(|candidate| after.candidates.contains(candidate)),
        "the retained ordinary update must apply once its bounded predecessor retires"
    );
}

#[tokio::test(start_paused = true)]
async fn hard_hard_startup_candidate_refresh_waits_before_session_registration() {
    let (daemon, record, _, _) = barrier_fixture().await;
    daemon
        .peers
        .clear_hard_hard_sessions(Some(&record.peer_id))
        .await;
    let generation = daemon
        .peers
        .peer_session_generation_sync(&record.peer_id)
        .unwrap();
    let Some(RendezvousPunchClaim::Claimed(permit)) = daemon
        .punch_attempts
        .claim_for_epoch_with_rendezvous_for_peer_session(
            &daemon.peers,
            &record.peer_id,
            generation,
            record.local_network_generation,
            1,
            PUNCH_PRIORITY_HARD_HARD,
            None,
            Some(hard_hard_now_ms() + 3_500),
        )
        .await
    else {
        panic!("measuring owner")
    };
    let offer = startup_offer(&daemon, &record, 1, false).await;
    let (reservation, offer) = startup_reserve(&daemon, offer);
    let mut worker = Box::pin(daemon.run_candidate_offer_worker(*offer, reservation));
    assert!(futures_util::poll!(&mut worker).is_pending());
    assert_eq!(
        daemon
            .peers
            .get_connection(&record.peer_id)
            .await
            .unwrap()
            .last_candidate_generation(),
        0
    );
    drop(permit);
    tokio::time::timeout(Duration::from_secs(1), worker)
        .await
        .unwrap();
    assert_eq!(
        daemon
            .peers
            .get_connection(&record.peer_id)
            .await
            .unwrap()
            .last_candidate_generation(),
        1
    );
}
