use super::*;

async fn profile_wait_fixture() -> (
    Daemon,
    control::PeerInfo,
    Box<PendingPeerOffer>,
    CandidateOfferWorkReservation,
) {
    let daemon =
        Daemon::new(Config::generate_default("http://127.0.0.1:1", "profile-wait").unwrap());
    let peer = control::PeerInfo {
        capabilities: crate::control::PeerCapabilities::default(),
        registration_seq: 0,
        node_id: "peer-profile-publication".to_string(),
        public_key: hex::encode(NodeIdentity::generate().public_key()),
        virtual_ip: "10.20.0.2".to_string(),
        online: true,
        nat_type: "unknown".to_string(),
        ..control::PeerInfo::default()
    };
    daemon.peers.add_peer(&peer).await;
    let coordination = HardHardCoordination {
        v2: None,
        role: HardHardRole::Initiator,
        token: "a1".to_string(),
        local_network_generation: 0,
        remote_candidate_epoch: 0,
        local_profile_generation: 1,
        remote_profile_generation: 1,
        local_prediction_confidence: 95,
        remote_prediction_confidence: 95,
        local_prediction_model: "fixed_step".to_string(),
        remote_prediction_model: "fixed_step".to_string(),
        remote_network_generation: 0,
    };
    let offer = PendingPeerOffer {
        nat_profile: None,
        from_node_id: peer.node_id.clone(),
        candidates: vec!["198.51.100.77:40000".to_string()],
        candidate_sources: HashMap::new(),
        candidate_generation: 1,
        network_generation: 0,
        peer_session_generation: daemon.peers.peer_session_generation_sync(&peer.node_id),
        candidates_expires_at_ms: None,
        sender_public_key: Some(peer.public_key.clone()),
        handshake_init: Vec::new(),
        punch_at_ms: Some(hard_hard_now_ms() + 3_500),
        punch_at_server_ms: None,
        session_id: Some(coordination.encode()),
        probe_ephemeral_public_key: None,
        delivery_receipt: None,
    };
    let CandidateOfferWorkAdmission::Started(reservation, offer) = daemon
        .pending_handshakes
        .lock()
        .enqueue_candidate_offer_work(offer)
    else {
        panic!("fixture needs one candidate owner");
    };
    (daemon, peer, offer, reservation)
}

fn published_profile(generation: u64) -> String {
    format!(
        "p2v2:m=address_or_port_dependent;a=linear;d=1;c=60;f=unknown;h=unknown;g={generation};o=1"
    )
}

#[tokio::test(start_paused = true)]
async fn hard_hard_profile_wait_requires_actual_roster_publication() {
    let (daemon, mut peer, offer, mut reservation) = profile_wait_fixture().await;
    let mut wait =
        Box::pin(daemon.wait_for_hard_hard_profile_publication(&offer, &mut reservation));
    assert!(futures_util::poll!(&mut wait).is_pending());
    assert!(matches!(
        daemon
            .peers
            .bind_remote_nat_profile_to_candidate_epoch_with_snapshot(&peer.node_id, 1)
            .await,
        RemoteNatProfileBindResult::Rejected {
            reason: RemoteNatProfileBindFailure::ProfileGenerationMissing,
            ..
        }
    ));
    peer.nat_type = published_profile(1);
    daemon.peers.add_peer(&peer).await;
    tokio::time::advance(UNKNOWN_PEER_OFFER_POLL).await;
    assert!(wait.await);
    assert!(matches!(
        daemon
            .peers
            .bind_remote_nat_profile_to_candidate_epoch_with_snapshot(&peer.node_id, 1)
            .await,
        RemoteNatProfileBindResult::Bound(_)
    ));
    assert_eq!(
        daemon
            .timeline
            .snapshot()
            .events
            .iter()
            .filter(|event| event.event == "hard_hard_profile_publication_wait")
            .count(),
        1
    );
}

#[tokio::test(start_paused = true)]
async fn hard_hard_profile_wait_expires_without_inventing_generation() {
    let (daemon, peer, mut offer, mut reservation) = profile_wait_fixture().await;
    offer.punch_at_ms =
        Some(hard_hard_now_ms() + HARD_HARD_MIN_RESPONSE_LEAD.as_millis() as u64 + 50);
    let mut wait =
        Box::pin(daemon.wait_for_hard_hard_profile_publication(&offer, &mut reservation));
    assert!(futures_util::poll!(&mut wait).is_pending());
    tokio::time::advance(Duration::from_millis(50)).await;
    assert!(wait.await);
    assert!(matches!(
        daemon
            .peers
            .bind_remote_nat_profile_to_candidate_epoch_with_snapshot(&peer.node_id, 1)
            .await,
        RemoteNatProfileBindResult::Rejected {
            reason: RemoteNatProfileBindFailure::ProfileGenerationMissing,
            ..
        }
    ));
    assert_eq!(
        daemon
            .timeline
            .snapshot()
            .events
            .iter()
            .filter(|event| event.event == "hard_hard_profile_publication_wait")
            .count(),
        1
    );
}

#[tokio::test(start_paused = true)]
async fn hard_hard_profile_wait_preserves_successor_and_cancellation() {
    let (daemon, peer, offer, mut reservation) = profile_wait_fixture().await;
    let mut wait =
        Box::pin(daemon.wait_for_hard_hard_profile_publication(&offer, &mut reservation));
    assert!(futures_util::poll!(&mut wait).is_pending());
    let mut successor = (*offer).clone();
    successor.candidate_generation = 2;
    let mut coordination =
        HardHardCoordination::parse(successor.session_id.as_deref().unwrap()).unwrap();
    coordination.token = "b2".to_string();
    successor.session_id = Some(coordination.encode());
    assert!(matches!(
        daemon
            .pending_handshakes
            .lock()
            .enqueue_candidate_offer_work(successor),
        CandidateOfferWorkAdmission::Coalesced { .. }
    ));
    tokio::time::advance(UNKNOWN_PEER_OFFER_POLL).await;
    assert!(wait.await);
    assert_eq!(
        daemon
            .pending_handshakes
            .lock()
            .take_queued_candidate_offer_work(&peer.node_id, reservation.owner)
            .unwrap()
            .candidate_generation,
        2
    );

    let mut wait =
        Box::pin(daemon.wait_for_hard_hard_profile_publication(&offer, &mut reservation));
    assert!(futures_util::poll!(&mut wait).is_pending());
    daemon.pending_handshakes.lock().clear_peer(&peer.node_id);
    assert!(!wait.await);
}

#[tokio::test(start_paused = true)]
async fn hard_hard_profile_wait_keeps_active_transcript_on_same_token_replay() {
    let (daemon, mut peer, offer, mut reservation) = profile_wait_fixture().await;
    let original_deadline = offer.punch_at_ms;
    let mut wait =
        Box::pin(daemon.wait_for_hard_hard_profile_publication(&offer, &mut reservation));
    assert!(futures_util::poll!(&mut wait).is_pending());
    let mut replay = (*offer).clone();
    replay.candidate_generation = 2;
    replay.candidates = vec!["198.51.100.88:50000".into()];
    replay.punch_at_ms = Some(hard_hard_now_ms() + 7_000);
    assert!(matches!(
        daemon
            .pending_handshakes
            .lock()
            .enqueue_candidate_offer_work(replay),
        CandidateOfferWorkAdmission::Coalesced {
            reason: HardHardCandidateDiscardReason::SameSessionPreserved,
            discarded: Some(_),
        }
    ));
    tokio::time::advance(UNKNOWN_PEER_OFFER_POLL).await;
    assert!(
        futures_util::poll!(&mut wait).is_pending(),
        "a replay is not a new work owner or a published NAT profile"
    );
    peer.nat_type = published_profile(1);
    daemon.peers.add_peer(&peer).await;
    tokio::time::advance(UNKNOWN_PEER_OFFER_POLL).await;
    assert!(wait.await);
    assert_eq!(offer.punch_at_ms, original_deadline);
    assert_eq!(offer.candidates, ["198.51.100.77:40000"]);
    assert!(
        daemon
            .pending_handshakes
            .lock()
            .finish_candidate_offer_work(&peer.node_id, reservation.owner)
            .is_none(),
        "the altered duplicate must not become another worker after the original completes"
    );
}

#[tokio::test(start_paused = true)]
async fn hard_hard_profile_wait_does_not_accept_newer_generation() {
    let (daemon, mut peer, offer, mut reservation) = profile_wait_fixture().await;
    peer.nat_type = published_profile(2);
    daemon.peers.add_peer(&peer).await;
    assert!(
        daemon
            .wait_for_hard_hard_profile_publication(&offer, &mut reservation)
            .await
    );
    assert!(matches!(
        daemon
            .peers
            .bind_remote_nat_profile_to_candidate_epoch_with_snapshot(&peer.node_id, 1)
            .await,
        RemoteNatProfileBindResult::Rejected {
            reason: RemoteNatProfileBindFailure::ProfileGenerationMismatch,
            ..
        }
    ));
    assert!(!daemon
        .timeline
        .snapshot()
        .events
        .iter()
        .any(|event| event.event == "hard_hard_profile_publication_wait"));
}

#[tokio::test(start_paused = true)]
async fn hard_hard_profile_wait_rechecks_peer_identity_after_publication() {
    let (daemon, mut peer, offer, mut reservation) = profile_wait_fixture().await;
    let mut wait =
        Box::pin(daemon.wait_for_hard_hard_profile_publication(&offer, &mut reservation));
    assert!(futures_util::poll!(&mut wait).is_pending());
    peer.public_key = hex::encode(NodeIdentity::generate().public_key());
    peer.nat_type = published_profile(1);
    daemon.peers.add_peer(&peer).await;
    tokio::time::advance(UNKNOWN_PEER_OFFER_POLL).await;
    assert!(
        !wait.await,
        "a matching profile cannot authorize the retired sender"
    );
}
