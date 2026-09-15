// Split out of the former flat include!-ed test file so the module is a
// real Rust scope. Everything below is unchanged test code.
use super::*;

#[test]
fn handshake_start_reservation_prevents_concurrent_initiators() {
    let mut state = PendingHandshakeState::default();
    let peer_id = "peer-race";

    assert!(state.reserve_start(peer_id));
    assert!(state.starting.contains(peer_id));
    assert!(
        !state.reserve_start(peer_id),
        "a second trigger must not start an initiator while the first gathers candidates"
    );

    state.cancel_reservation(peer_id);
    assert!(state.reserve_start(peer_id));
}

#[test]
fn stale_handshake_start_owner_cannot_clear_replacement_reservation() {
    let mut state = PendingHandshakeState::default();
    let peer_id = "peer-owner-replacement";

    let old = state
        .reserve_start_with_owner(peer_id)
        .expect("first reservation must be admitted");
    state.clear_peer(peer_id);
    let replacement = state
        .reserve_start_with_owner(peer_id)
        .expect("peer rejoin must admit a replacement reservation");

    assert_ne!(old.owner, replacement.owner);
    assert!(
        !state.cancel_reservation_if_current(peer_id, old.owner),
        "a late task from the old peer incarnation must not clear the replacement"
    );
    assert!(state.starting.contains(peer_id));
    assert_eq!(state.starting_ids.get(peer_id), Some(&replacement.owner));
}

#[test]
fn handshake_reservation_commit_requires_exact_peer_lifecycle() {
    let mut state = PendingHandshakeState::default();
    let peer_id = "peer-reservation-lifecycle";
    let admitted_lifecycle = PeerSessionGeneration::for_test(41);
    let replacement_lifecycle = PeerSessionGeneration::for_test(42);
    let reservation = state
        .reserve_start_with_owner_at_generation(peer_id, 7, admitted_lifecycle)
        .expect("first lifecycle must reserve the initiator slot");

    let old_identity = NodeIdentity::generate();
    let remote_identity = NodeIdentity::generate();
    assert!(
        state
            .insert_reserved_if_current_with_generation(
                peer_id.to_string(),
                reservation.owner,
                HandshakeInitiator::new(old_identity, remote_identity.public_key(), None,),
                Some("stale-lifecycle-session".to_string()),
                None,
                7,
                replacement_lifecycle,
            )
            .is_none(),
        "the right owner token must still fail when its peer lifecycle is stale"
    );
    assert_eq!(state.starting_ids.get(peer_id), Some(&reservation.owner));
    assert_eq!(
        state.starting_peer_session_generations.get(peer_id),
        Some(&admitted_lifecycle),
        "a failed stale commit must not consume or rewrite the live reservation"
    );
    assert!(!state.pending.contains_key(peer_id));
}

#[test]
fn stale_handshake_pending_owner_cannot_remove_replacement_transaction() {
    let mut state = PendingHandshakeState::default();
    let peer_id = "peer-pending-owner-replacement";
    let remote_identity = NodeIdentity::generate();
    let old_reservation = state.reserve_start_with_owner(peer_id).unwrap();
    let old_pending_id = state
        .insert_reserved_if_current(
            peer_id.to_string(),
            old_reservation.owner,
            HandshakeInitiator::new(NodeIdentity::generate(), remote_identity.public_key(), None),
            Some("old-pending-token".to_string()),
            None,
        )
        .unwrap();
    state.remove(peer_id);

    let replacement_reservation = state.reserve_start_with_owner(peer_id).unwrap();
    let replacement_pending_id = state
        .insert_reserved_if_current(
            peer_id.to_string(),
            replacement_reservation.owner,
            HandshakeInitiator::new(NodeIdentity::generate(), remote_identity.public_key(), None),
            Some("replacement-pending-token".to_string()),
            None,
        )
        .unwrap();

    assert!(!state.remove_if_current(peer_id, old_pending_id));
    assert!(state.is_current(peer_id, replacement_pending_id));
    assert_eq!(state.session_id(peer_id), Some("replacement-pending-token"));
}

#[test]
fn new_generation_replaces_stale_pending_initiator_before_retry() {
    let mut state = PendingHandshakeState::default();
    let peer_id = "peer-stale-pending-generation";
    let local_identity = NodeIdentity::generate();
    let peer_identity = NodeIdentity::generate();
    let initiator = HandshakeInitiator::new(local_identity, peer_identity.public_key(), None);
    let reservation = state
        .reserve_start_with_owner(peer_id)
        .expect("initial generation must admit the initiator");
    let pending_id = state
        .insert_reserved_if_current_with_generation(
            peer_id.to_string(),
            reservation.owner,
            initiator,
            Some("stale-session".to_string()),
            None,
            0,
            reservation.peer_session_generation,
        )
        .expect("reservation must become pending");
    assert!(state.is_current(peer_id, pending_id));

    let stale_token = state
        .remove_stale_pending_for_generation(peer_id, 1, reservation.peer_session_generation)
        .expect("generation advance must retire the old pending transaction");
    assert_eq!(stale_token, "stale-session");
    assert!(!state.pending.contains_key(peer_id));

    let replacement = state
        .reserve_start_with_owner_at_generation(peer_id, 1, reservation.peer_session_generation)
        .expect("new generation must not wait for the stale answer timeout");
    assert!(state.starting.contains(peer_id));
    assert_eq!(
        state.starting_network_generations.get(peer_id),
        Some(&1),
        "the replacement reservation must carry the new generation"
    );
    assert_ne!(replacement.owner, reservation.owner);
}

#[test]
fn deferred_unknown_peer_offer_is_newest_wins_and_owner_scoped() {
    fn offer(peer_id: &str, endpoint: &str) -> PendingPeerOffer {
        PendingPeerOffer {
            from_node_id: peer_id.to_string(),
            candidates: vec![endpoint.to_string()],
            candidate_sources: HashMap::from([(endpoint.to_string(), "stun".to_string())]),
            candidate_generation: 1,
            network_generation: 0,
            peer_session_generation: None,
            candidates_expires_at_ms: None,
            sender_public_key: None,
            handshake_init: vec![1, 2, 3],
            punch_at_ms: None,
            punch_at_server_ms: None,
            session_id: None,
            probe_ephemeral_public_key: None,
            delivery_receipt: None,
        }
    }

    let mut state = PendingHandshakeState::default();
    let (reservation, first) = state
        .enqueue_responder_work(offer("peer-deferred", "127.0.0.1:41000"))
        .expect("first unknown offer starts one bounded waiter");
    assert!(state
        .enqueue_responder_work(offer("peer-deferred", "127.0.0.1:41001"))
        .is_none());

    let queued = state
        .take_queued_responder_work("peer-deferred", reservation.owner)
        .expect("newest offer replaces the deferred value before it is processed");
    assert_eq!(queued.candidates, vec!["127.0.0.1:41001"]);
    assert_eq!(first.candidates, vec!["127.0.0.1:41000"]);
    assert!(
        state
            .finish_responder_work("peer-deferred", reservation.owner)
            .is_none(),
        "taking the newest queued offer must retain then release the same owner only once"
    );

    // A peer lifecycle cleanup invalidates the owner.  A late worker cannot
    // consume a replacement slot after the peer rejoins.
    state.clear_peer("peer-deferred");
    assert!(state
        .finish_responder_work("peer-deferred", reservation.owner)
        .is_none());
    let replacement = state
        .enqueue_responder_work(offer("peer-deferred", "127.0.0.1:41002"))
        .expect("rejoined peer gets a fresh owner");
    assert_ne!(replacement.0.owner, reservation.owner);
}

#[test]
fn retired_active_sender_cannot_overwrite_queued_replacement_identity_offer() {
    fn offer(sender: &str, endpoint: &str) -> PendingPeerOffer {
        PendingPeerOffer {
            from_node_id: "peer-identity-coalescing".to_string(),
            candidates: vec![endpoint.to_string()],
            candidate_sources: HashMap::new(),
            candidate_generation: 1,
            network_generation: 0,
            peer_session_generation: None,
            candidates_expires_at_ms: None,
            sender_public_key: Some(sender.to_string()),
            handshake_init: vec![1],
            punch_at_ms: None,
            punch_at_server_ms: None,
            session_id: None,
            probe_ephemeral_public_key: None,
            delivery_receipt: None,
        }
    }

    let mut state = PendingHandshakeState::default();
    let (reservation, _) = state
        .enqueue_responder_work(offer("retired-key", "127.0.0.1:41100"))
        .expect("the retired offer models the already-active owner");
    assert!(state
        .enqueue_responder_work(offer("replacement-key", "127.0.0.1:41101"))
        .is_none());
    assert!(state
        .enqueue_responder_work(offer(" retired-key ", "127.0.0.1:41102"))
        .is_none());

    let replacement = state
        .take_queued_responder_work("peer-identity-coalescing", reservation.owner)
        .expect("the replacement identity's queued turn must survive");
    assert_eq!(
        replacement.sender_public_key.as_deref(),
        Some("replacement-key")
    );
    assert_eq!(replacement.candidates, vec!["127.0.0.1:41101"]);

    // `take` must atomically make the returned identity active. A retransmit
    // from that identity can no longer displace a distinct queued successor.
    assert!(state
        .enqueue_responder_work(offer("third-key", "127.0.0.1:41103"))
        .is_none());
    assert!(state
        .enqueue_responder_work(offer("replacement-key", "127.0.0.1:41104"))
        .is_none());
    let third = state
        .finish_responder_work("peer-identity-coalescing", reservation.owner)
        .expect("the distinct successor identity must remain queued");
    assert_eq!(third.sender_public_key.as_deref(), Some("third-key"));
    assert_eq!(third.candidates, vec!["127.0.0.1:41103"]);
}

#[test]
fn cancelled_responder_owner_cannot_consume_a_new_offer() {
    fn offer(endpoint: &str) -> PendingPeerOffer {
        PendingPeerOffer {
            from_node_id: "peer-cancelled-responder".to_string(),
            candidates: vec![endpoint.to_string()],
            candidate_sources: HashMap::new(),
            candidate_generation: 1,
            network_generation: 0,
            peer_session_generation: None,
            candidates_expires_at_ms: None,
            sender_public_key: None,
            handshake_init: vec![1, 2, 3],
            punch_at_ms: None,
            punch_at_server_ms: None,
            session_id: None,
            probe_ephemeral_public_key: None,
            delivery_receipt: None,
        }
    }

    let mut state = PendingHandshakeState::default();
    let (old, _) = state
        .enqueue_responder_work(offer("198.51.100.10:41000"))
        .expect("first responder owner must be admitted");
    // Simulate the cancellation notification becoming visible before a late
    // signal reaches the state machine. The late offer must get a new owner,
    // never enter the cancelled worker's queued slot.
    state
        .responder_workers
        .get_mut("peer-cancelled-responder")
        .expect("responder owner must exist")
        .cancellation
        .send_replace(true);
    let (replacement, replacement_offer) = state
        .enqueue_responder_work(offer("198.51.100.10:41001"))
        .expect("cancelled owner must be replaced");
    assert_ne!(replacement.owner, old.owner);
    assert_eq!(replacement_offer.candidates, vec!["198.51.100.10:41001"]);
}

#[test]
fn candidate_offer_work_is_newest_wins_owner_scoped_and_capacity_bounded() {
    fn offer(peer_id: &str, generation: u64) -> PendingPeerOffer {
        PendingPeerOffer {
            from_node_id: peer_id.to_string(),
            candidates: vec![format!("198.51.100.10:{}", 41_000 + generation)],
            candidate_sources: HashMap::new(),
            candidate_generation: generation,
            network_generation: 0,
            peer_session_generation: None,
            candidates_expires_at_ms: None,
            sender_public_key: Some("candidate-owner-key".to_string()),
            handshake_init: Vec::new(),
            punch_at_ms: None,
            punch_at_server_ms: None,
            session_id: None,
            probe_ephemeral_public_key: None,
            delivery_receipt: None,
        }
    }

    let mut state = PendingHandshakeState::default();
    let CandidateOfferWorkAdmission::Started(reservation, first) =
        state.enqueue_candidate_offer_work(offer("peer-candidate-owner", 1))
    else {
        panic!("first candidate payload must acquire an owner");
    };
    assert!(matches!(
        state.enqueue_candidate_offer_work(offer("peer-candidate-owner", 2)),
        CandidateOfferWorkAdmission::Coalesced,
    ));
    assert!(matches!(
        state.enqueue_candidate_offer_work(offer("peer-candidate-owner", 3)),
        CandidateOfferWorkAdmission::Coalesced,
    ));
    assert_eq!(first.candidate_generation, 1);
    let newest = state
        .take_queued_candidate_offer_work("peer-candidate-owner", reservation.owner)
        .expect("one newest-wins successor must be retained");
    assert_eq!(newest.candidate_generation, 3);
    assert!(state
        .finish_candidate_offer_work("peer-candidate-owner", reservation.owner)
        .is_none());

    state.clear_peer("peer-candidate-owner");
    let CandidateOfferWorkAdmission::Started(replacement, _) =
        state.enqueue_candidate_offer_work(offer("peer-candidate-owner", 4))
    else {
        panic!("a cleared lifecycle must admit a replacement owner");
    };
    assert_ne!(replacement.owner, reservation.owner);

    let mut full = PendingHandshakeState::default();
    for index in 0..MAX_CANDIDATE_OFFER_WORKERS {
        assert!(matches!(
            full.enqueue_candidate_offer_work(offer(&format!("peer-capacity-{index}"), 1)),
            CandidateOfferWorkAdmission::Started(_, _),
        ));
    }
    assert!(matches!(
        full.enqueue_candidate_offer_work(offer("peer-over-capacity", 1)),
        CandidateOfferWorkAdmission::Capacity,
    ));
    assert_eq!(
        full.candidate_offer_workers.len(),
        MAX_CANDIDATE_OFFER_WORKERS
    );
}

#[test]
fn peer_reflexive_work_is_newest_wins_and_owner_scoped() {
    fn observation(peer_id: &str, endpoint: &str) -> PendingPeerReflexive {
        PendingPeerReflexive {
            from_node_id: peer_id.to_string(),
            observed_endpoint: endpoint.to_string(),
            punch_at_ms: None,
            peer_session_generation: None,
            delivery_receipt: None,
        }
    }

    let mut state = PendingHandshakeState::default();
    let peer_id = "peer-reflexive-owner";
    let (reservation, first) = state
        .enqueue_peer_reflexive_work(observation(peer_id, "198.51.100.10:41000"))
        .expect("first observation starts one bounded worker");
    assert!(state
        .enqueue_peer_reflexive_work(observation(peer_id, "198.51.100.10:41001"))
        .is_none());

    let newest = state
        .finish_peer_reflexive_work(peer_id, reservation.owner)
        .expect("the worker must consume only the newest queued endpoint next");
    assert_eq!(first.observed_endpoint, "198.51.100.10:41000");
    assert_eq!(newest.observed_endpoint, "198.51.100.10:41001");

    // Peer lifecycle cleanup cancels the old owner. A late completion cannot
    // release or consume the replacement slot after a rejoin.
    state.clear_peer(peer_id);
    assert!(state
        .finish_peer_reflexive_work(peer_id, reservation.owner)
        .is_none());
    let replacement = state
        .enqueue_peer_reflexive_work(observation(peer_id, "198.51.100.10:41002"))
        .expect("rejoined peer gets a fresh peer-reflexive owner");
    assert_ne!(replacement.0.owner, reservation.owner);
}

#[tokio::test]
async fn deferred_unknown_peer_offer_replays_candidate_admission_after_peer_join() {
    let daemon = Daemon::new(Config::generate_default("https://ctrl.test", "net1").unwrap());
    let peer_identity = NodeIdentity::generate();
    let peer_id = "peer-deferred-replay";
    let candidate = "198.51.100.77:47000";
    let offer = PendingPeerOffer {
        from_node_id: peer_id.to_string(),
        candidates: vec![candidate.to_string()],
        candidate_sources: HashMap::from([(candidate.to_string(), "stun".to_string())]),
        candidate_generation: 1,
        network_generation: 0,
        peer_session_generation: None,
        candidates_expires_at_ms: None,
        sender_public_key: Some(hex::encode(peer_identity.public_key())),
        handshake_init: Vec::new(),
        punch_at_ms: None,
        punch_at_server_ms: None,
        session_id: None,
        probe_ephemeral_public_key: None,
        delivery_receipt: None,
    };
    let CandidateOfferWorkAdmission::Started(reservation, offer) = daemon
        .pending_handshakes
        .lock()
        .enqueue_candidate_offer_work(offer)
    else {
        panic!("unknown offer must acquire one deferred candidate owner");
    };

    let join = async {
        sleep(Duration::from_millis(25)).await;
        daemon
            .peers
            .add_peer(&control::PeerInfo {
                node_id: peer_id.to_string(),
                device_name: String::new(),
                app_version: String::new(),
                public_key: hex::encode(peer_identity.public_key()),
                endpoint: String::new(),
                nat_type: "Unknown".to_string(),
                virtual_ip: "10.20.0.2".to_string(),
                online: true,
                last_seen: 0,
                relay_rtt_ms: None,
            })
            .await;
    };
    tokio::join!(daemon.run_candidate_offer_worker(*offer, reservation), join);

    let connection = daemon.peers.get_connection(peer_id).await.unwrap();
    assert!(
        connection.candidates.iter().any(|value| value == candidate),
        "candidate admission must run after the peer exists"
    );
    assert!(!daemon
        .pending_handshakes
        .lock()
        .candidate_offer_workers
        .contains_key(peer_id));
}
