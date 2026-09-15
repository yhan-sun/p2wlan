// Split out of the former flat include!-ed test file so the module is a
// real Rust scope. Everything below is unchanged test code.
use super::*;

#[tokio::test]
async fn peer_answer_from_new_remote_incarnation_preserves_pending_initiator() {
    fn encoded_generation(incarnation: u64, counter: u64) -> u64 {
        0x4000_0000_0000_0000 | (incarnation << 21) | counter
    }

    let config = Config::generate_default("https://ctrl.test", "net1").unwrap();
    let daemon = Daemon::new(config);
    let peer_id = "peer-answer-remote-restart";
    let peer_identity = NodeIdentity::generate();
    let endpoint = "203.0.113.20:42100";
    daemon
        .peers
        .add_peer(&control::PeerInfo {
            node_id: peer_id.to_string(),
            device_name: String::new(),
            app_version: String::new(),
            public_key: hex::encode(peer_identity.public_key()),
            endpoint: endpoint.to_string(),
            nat_type: "Unknown".to_string(),
            virtual_ip: "10.20.0.21".to_string(),
            online: true,
            last_seen: 0,
            relay_rtt_ms: None,
        })
        .await;
    let old_candidate_generation = encoded_generation(100, 1);
    let new_candidate_generation = encoded_generation(101, 1);
    assert_eq!(
        daemon
            .peers
            .add_candidates_with_metadata(
                peer_id,
                &[endpoint.to_string()],
                &HashMap::new(),
                old_candidate_generation,
                Some(u64::MAX),
            )
            .await,
        CandidateSetApplyResult::Applied
    );
    daemon
        .peers
        .update_state(peer_id, ConnectionState::Direct)
        .await;
    let old_peer_session_generation = daemon.peers.peer_session_generation_sync(peer_id).unwrap();

    let (old_local_session, _) = part03_establish_sessions();
    daemon
        .transport
        .add_session(peer_id, old_local_session)
        .await;

    let mut initiator = HandshakeInitiator::new(
        daemon.local_identity().unwrap(),
        peer_identity.public_key(),
        None,
    );
    let initiation = initiator.create_initiation().unwrap();
    let mut responder = HandshakeResponder::new(peer_identity, None);
    let (response, _) = responder
        .consume_initiation_and_respond(&initiation)
        .unwrap();
    daemon.pending_handshakes.lock().insert_with_generation(
        peer_id.to_string(),
        initiator,
        None,
        None,
        None,
        daemon.peers.current_network_generation_sync(),
        old_peer_session_generation,
    );

    assert!(
        daemon
            .reset_peer_for_remote_incarnation_if_needed(
                peer_id,
                new_candidate_generation,
                RemoteIncarnationResetWork::PreserveInitiator,
            )
            .await
    );
    let new_peer_session_generation = daemon.peers.peer_session_generation_sync(peer_id).unwrap();
    assert_ne!(new_peer_session_generation, old_peer_session_generation);
    assert!(daemon
        .pending_handshakes
        .lock()
        .pending
        .contains_key(peer_id));
    assert!(!daemon.transport.has_session(peer_id).await);
    assert_eq!(
        daemon.peers.get_connection(peer_id).await.unwrap().state,
        ConnectionState::Idle
    );

    daemon
        .handle_peer_answer(peer_id, &response.to_bytes(), None, None)
        .await
        .unwrap();
    assert!(daemon.transport.has_session(peer_id).await);
    assert_eq!(
        daemon
            .peers
            .add_candidates_with_metadata(
                peer_id,
                &[endpoint.to_string()],
                &HashMap::new(),
                new_candidate_generation,
                Some(u64::MAX),
            )
            .await,
        CandidateSetApplyResult::Applied
    );

    assert!(
        !daemon
            .reset_peer_for_remote_incarnation_if_needed(
                peer_id,
                old_candidate_generation,
                RemoteIncarnationResetWork::ClearAll,
            )
            .await
    );
    assert_eq!(
        daemon.peers.peer_session_generation_sync(peer_id),
        Some(new_peer_session_generation)
    );
    assert!(daemon.transport.has_session(peer_id).await);
}

#[tokio::test]
async fn stale_sender_known_offer_cannot_reset_current_identity_or_apply_candidates() {
    fn encoded_generation(incarnation: u64, counter: u64) -> u64 {
        0x4000_0000_0000_0000 | (incarnation << 21) | counter
    }

    let daemon = Daemon::new(Config::generate_default("http://127.0.0.1:1", "net1").unwrap());
    let peer_id = "peer-stale-identity-offer";
    let current_identity = NodeIdentity::generate();
    let retired_identity = NodeIdentity::generate();
    let current_public_key = hex::encode(current_identity.public_key());
    daemon
        .peers
        .add_peer(&control::PeerInfo {
            node_id: peer_id.to_string(),
            device_name: String::new(),
            app_version: String::new(),
            public_key: current_public_key,
            endpoint: String::new(),
            nat_type: "Unknown".to_string(),
            virtual_ip: "10.20.0.31".to_string(),
            online: true,
            last_seen: 0,
            relay_rtt_ms: None,
        })
        .await;
    let baseline_candidate = "203.0.113.31:43100".to_string();
    assert_eq!(
        daemon
            .peers
            .add_candidates_with_metadata(
                peer_id,
                std::slice::from_ref(&baseline_candidate),
                &HashMap::new(),
                encoded_generation(31, 1),
                Some(u64::MAX),
            )
            .await,
        CandidateSetApplyResult::Applied
    );
    let original_session_generation = daemon.peers.peer_session_generation_sync(peer_id).unwrap();
    let (active_session, _) = part03_establish_sessions();
    daemon.transport.add_session(peer_id, active_session).await;
    daemon.pending_handshakes.lock().insert(
        peer_id.to_string(),
        HandshakeInitiator::new(
            daemon.local_identity().unwrap(),
            current_identity.public_key(),
            None,
        ),
        None,
        None,
    );

    let peers = daemon.peers.clone();
    let transport = daemon.transport.clone();
    let pending = daemon.pending_handshakes.clone();
    let health = daemon.health.clone();
    let shutdown = daemon.shutdown_sender();
    daemon
        .control
        .event_sender()
        .send(ControlEvent::PeerOffer {
            from_node_id: peer_id.to_string(),
            candidates: vec!["203.0.113.99:49999".to_string()],
            session_id: None,
            probe_ephemeral_public_key: None,
            candidate_sources: HashMap::new(),
            candidate_generation: encoded_generation(99, 1),
            candidates_expires_at_ms: None,
            // Deliberately malformed: identity rejection must happen before
            // parsing or staging a responder transaction.
            handshake_init: vec![0xff],
            punch_at_ms: None,
            punch_at_server_ms: None,
            sender_public_key: Some(hex::encode(retired_identity.public_key())),
        })
        .unwrap();
    daemon
        .control
        .event_sender()
        .send(ControlEvent::ControlHealthy)
        .unwrap();

    let (network_tx, _network_rx) = mpsc::channel(8);
    let mut relay_started = false;
    let mut daemon_task = daemon;
    let loop_task = tokio::spawn(async move {
        daemon_task
            .run_control_event_loop(&mut relay_started, network_tx)
            .await;
    });
    timeout(Duration::from_secs(1), async {
        // ControlHealthy proves the receiver consumed this marker and that
        // the control API is reachable. It intentionally does not forge the
        // independently-owned device lease required by control_connected.
        while !health.snapshot(&[]).await.control_api_reachable {
            sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .expect("the stale offer and following health marker must be consumed");

    assert!(transport.has_session(peer_id).await);
    assert_eq!(
        peers.peer_session_generation_sync(peer_id),
        Some(original_session_generation)
    );
    assert_eq!(
        peers.get_connection(peer_id).await.unwrap().candidates,
        vec![baseline_candidate]
    );
    assert!(pending.lock().pending.contains_key(peer_id));

    let _ = shutdown.send(true);
    timeout(Duration::from_secs(1), loop_task)
        .await
        .expect("control event loop did not stop")
        .expect("control event loop task panicked");
}

#[tokio::test]
async fn stale_sender_answer_cannot_reset_or_consume_current_initiator() {
    fn encoded_generation(incarnation: u64, counter: u64) -> u64 {
        0x4000_0000_0000_0000 | (incarnation << 21) | counter
    }

    let daemon = Daemon::new(Config::generate_default("http://127.0.0.1:1", "net1").unwrap());
    let peer_id = "peer-stale-identity-answer";
    let current_identity = NodeIdentity::generate();
    let retired_identity = NodeIdentity::generate();
    daemon
        .peers
        .add_peer(&control::PeerInfo {
            node_id: peer_id.to_string(),
            device_name: String::new(),
            app_version: String::new(),
            public_key: hex::encode(current_identity.public_key()),
            endpoint: String::new(),
            nat_type: "Unknown".to_string(),
            virtual_ip: "10.20.0.32".to_string(),
            online: true,
            last_seen: 0,
            relay_rtt_ms: None,
        })
        .await;
    let baseline_candidate = "203.0.113.32:43200".to_string();
    assert_eq!(
        daemon
            .peers
            .add_candidates_with_metadata(
                peer_id,
                std::slice::from_ref(&baseline_candidate),
                &HashMap::new(),
                encoded_generation(32, 1),
                Some(u64::MAX),
            )
            .await,
        CandidateSetApplyResult::Applied
    );
    let original_session_generation = daemon.peers.peer_session_generation_sync(peer_id).unwrap();
    let (active_session, _) = part03_establish_sessions();
    daemon.transport.add_session(peer_id, active_session).await;

    // The response is cryptographically valid for the current peer. Only the
    // server-bound retired sender identity should keep it from consuming the
    // one-shot initiator.
    let mut initiator = HandshakeInitiator::new(
        daemon.local_identity().unwrap(),
        current_identity.public_key(),
        None,
    );
    let initiation = initiator.create_initiation().unwrap();
    let mut responder = HandshakeResponder::new(current_identity, None);
    let (response, _) = responder
        .consume_initiation_and_respond(&initiation)
        .unwrap();
    daemon
        .pending_handshakes
        .lock()
        .insert(peer_id.to_string(), initiator, None, None);

    let peers = daemon.peers.clone();
    let transport = daemon.transport.clone();
    let pending = daemon.pending_handshakes.clone();
    let health = daemon.health.clone();
    let shutdown = daemon.shutdown_sender();
    daemon
        .control
        .event_sender()
        .send(ControlEvent::PeerAnswer {
            from_node_id: peer_id.to_string(),
            candidates: vec!["203.0.113.100:50000".to_string()],
            session_id: None,
            probe_ephemeral_public_key: None,
            candidate_sources: HashMap::new(),
            candidate_generation: encoded_generation(100, 1),
            candidates_expires_at_ms: None,
            handshake_response: response.to_bytes(),
            punch_at_ms: None,
            punch_at_server_ms: None,
            sender_public_key: Some(hex::encode(retired_identity.public_key())),
        })
        .unwrap();
    daemon
        .control
        .event_sender()
        .send(ControlEvent::ControlHealthy)
        .unwrap();

    let (network_tx, _network_rx) = mpsc::channel(8);
    let mut relay_started = false;
    let mut daemon_task = daemon;
    let loop_task = tokio::spawn(async move {
        daemon_task
            .run_control_event_loop(&mut relay_started, network_tx)
            .await;
    });
    timeout(Duration::from_secs(1), async {
        // ControlHealthy proves the receiver consumed this marker and that
        // the control API is reachable. It intentionally does not forge the
        // independently-owned device lease required by control_connected.
        while !health.snapshot(&[]).await.control_api_reachable {
            sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .expect("the stale answer and following health marker must be consumed");

    assert!(transport.has_session(peer_id).await);
    assert_eq!(
        peers.peer_session_generation_sync(peer_id),
        Some(original_session_generation)
    );
    assert_eq!(
        peers.get_connection(peer_id).await.unwrap().candidates,
        vec![baseline_candidate]
    );
    assert!(pending.lock().pending.contains_key(peer_id));

    let _ = shutdown.send(true);
    timeout(Duration::from_secs(1), loop_task)
        .await
        .expect("control event loop did not stop")
        .expect("control event loop task panicked");
}

#[tokio::test]
async fn stale_sender_deferred_offer_releases_owner_without_mutating_peer() {
    fn encoded_generation(incarnation: u64, counter: u64) -> u64 {
        0x4000_0000_0000_0000 | (incarnation << 21) | counter
    }

    let daemon = Daemon::new(Config::generate_default("http://127.0.0.1:1", "net1").unwrap());
    let peer_id = "peer-stale-identity-deferred";
    let current_identity = NodeIdentity::generate();
    let retired_identity = NodeIdentity::generate();
    daemon
        .peers
        .add_peer(&control::PeerInfo {
            node_id: peer_id.to_string(),
            device_name: String::new(),
            app_version: String::new(),
            public_key: hex::encode(current_identity.public_key()),
            endpoint: String::new(),
            nat_type: "Unknown".to_string(),
            virtual_ip: "10.20.0.33".to_string(),
            online: true,
            last_seen: 0,
            relay_rtt_ms: None,
        })
        .await;
    let baseline_candidate = "203.0.113.33:43300".to_string();
    assert_eq!(
        daemon
            .peers
            .add_candidates_with_metadata(
                peer_id,
                std::slice::from_ref(&baseline_candidate),
                &HashMap::new(),
                encoded_generation(33, 1),
                Some(u64::MAX),
            )
            .await,
        CandidateSetApplyResult::Applied
    );
    let original_session_generation = daemon.peers.peer_session_generation_sync(peer_id).unwrap();
    let (active_session, _) = part03_establish_sessions();
    daemon.transport.add_session(peer_id, active_session).await;
    daemon.pending_handshakes.lock().insert(
        peer_id.to_string(),
        HandshakeInitiator::new(
            daemon.local_identity().unwrap(),
            current_identity.public_key(),
            None,
        ),
        None,
        None,
    );
    let offer = PendingPeerOffer {
        from_node_id: peer_id.to_string(),
        candidates: vec!["203.0.113.101:50101".to_string()],
        candidate_sources: HashMap::new(),
        candidate_generation: encoded_generation(101, 1),
        network_generation: daemon.peers.current_network_generation_sync(),
        peer_session_generation: Some(original_session_generation),
        candidates_expires_at_ms: None,
        sender_public_key: Some(hex::encode(retired_identity.public_key())),
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
        panic!("the deferred offer must acquire a candidate owner");
    };

    timeout(
        Duration::from_secs(1),
        daemon.run_candidate_offer_worker(*offer, reservation),
    )
    .await
    .expect("the stale deferred owner must finish instead of wedging the lane");

    assert!(daemon.transport.has_session(peer_id).await);
    assert_eq!(
        daemon.peers.peer_session_generation_sync(peer_id),
        Some(original_session_generation)
    );
    assert_eq!(
        daemon
            .peers
            .get_connection(peer_id)
            .await
            .unwrap()
            .candidates,
        vec![baseline_candidate]
    );
    let pending = daemon.pending_handshakes.lock();
    assert!(pending.pending.contains_key(peer_id));
    assert!(!pending.candidate_offer_workers.contains_key(peer_id));
}

#[tokio::test]
async fn peer_left_without_udp_transport_removes_membership_and_fences_same_id_rejoin() {
    let config = Config::generate_default("http://127.0.0.1:1", "net1").unwrap();
    let daemon = Daemon::new(config);
    assert!(
        daemon.udp_transport.read().await.is_none(),
        "the regression requires the real pre-publication UDP state"
    );

    let local_public = daemon.local_identity().unwrap().public_key();
    let peer_identity = loop {
        let identity = NodeIdentity::generate();
        if identity.public_key() < local_public {
            break identity;
        }
    };
    let peer_id = "peer-left-before-udp";
    let peer_info = control::PeerInfo {
        node_id: peer_id.to_string(),
        device_name: String::new(),
        app_version: String::new(),
        public_key: hex::encode(peer_identity.public_key()),
        endpoint: "203.0.113.40:51820".to_string(),
        nat_type: "Unknown".to_string(),
        virtual_ip: "10.20.0.40".to_string(),
        online: true,
        last_seen: 0,
        relay_rtt_ms: None,
    };

    let peers = daemon.peers.clone();
    let control = daemon.control.clone();
    let shutdown = daemon.shutdown_sender();
    let (network_tx, _network_rx) = mpsc::channel(8);
    let mut relay_started = false;
    let mut daemon_task = daemon;
    let loop_task = tokio::spawn(async move {
        daemon_task
            .run_control_event_loop(&mut relay_started, network_tx)
            .await;
    });

    control
        .event_sender()
        .send(ControlEvent::PeerJoined(peer_info.clone()))
        .unwrap();
    let initial_generation = timeout(Duration::from_secs(1), async {
        loop {
            if let Some((generation, true)) = peers.peer_session_snapshot_for_test(peer_id) {
                break generation;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("PeerJoined must publish the initial lifecycle");

    control
        .event_sender()
        .send(ControlEvent::PeerLeft(peer_id.to_string()))
        .unwrap();
    timeout(Duration::from_secs(1), async {
        while peers.peer_exists_sync(peer_id) {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("PeerLeft must remove membership even without UDP");
    assert!(peers.get_connection(peer_id).await.is_none());
    assert!(peers.peer_session_snapshot_for_test(peer_id).is_none());

    control
        .event_sender()
        .send(ControlEvent::PeerJoined(peer_info))
        .unwrap();
    let replacement_generation = timeout(Duration::from_secs(1), async {
        loop {
            if let Some((generation, true)) = peers.peer_session_snapshot_for_test(peer_id) {
                if generation != initial_generation {
                    break generation;
                }
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("same-ID rejoin must allocate a fresh lifecycle");
    assert_ne!(replacement_generation, initial_generation);

    let _ = shutdown.send(true);
    timeout(Duration::from_secs(1), loop_task)
        .await
        .expect("control event loop did not stop")
        .expect("control event loop task panicked");
}
