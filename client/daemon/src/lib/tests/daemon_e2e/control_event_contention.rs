// Split out of the former flat include!-ed test file so the module is a
// real Rust scope. Everything below is unchanged test code.
use super::*;

#[tokio::test]
async fn control_event_loop_processes_critical_event_while_candidate_refresh_is_blocked() {
    let config = Config::generate_default("http://127.0.0.1:1", "net1").unwrap();
    let daemon = Daemon::new(config);
    let local_public = daemon.local_identity().unwrap().public_key();
    let peer_identity = loop {
        let identity = NodeIdentity::generate();
        if local_public < identity.public_key() {
            break identity;
        }
    };
    let peer_info = control::PeerInfo {
        node_id: "peer-slow-candidate-refresh".to_string(),
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

    // The event worker will block acquiring this lock inside
    // `local_candidate_set_for_signal`.  A serial inline handshake would keep
    // the next ControlHealthy event behind that wait; the bounded work set must
    // let the receiver consume it immediately.
    let candidate_refresh_lock = daemon.candidate_refresh_lock.clone();
    let candidate_guard = candidate_refresh_lock.lock().await;
    let control = daemon.control.clone();
    let health = daemon.health.clone();
    let shutdown = daemon.shutdown_sender();
    control
        .event_sender()
        .send(ControlEvent::PeerJoined(peer_info))
        .unwrap();
    control
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

    tokio::time::timeout(Duration::from_millis(250), async {
        loop {
            // ControlHealthy proves API reachability only; it must not forge a
            // successful device-lease refresh. This test is about receiver
            // progress, so observe the exact bit the event is allowed to set.
            if health.snapshot(&[]).await.control_api_reachable {
                break;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .expect("ControlHealthy must not wait for the blocked candidate refresh");

    drop(candidate_guard);
    let _ = shutdown.send(true);
    tokio::time::timeout(Duration::from_secs(1), loop_task)
        .await
        .expect("control event loop did not stop")
        .expect("control event loop task panicked");
}

#[tokio::test]
async fn last_seen_only_peer_update_refreshes_diagnostics_without_handshake_reservation() {
    let config = Config::generate_default("http://127.0.0.1:1", "last-seen-heartbeat").unwrap();
    let daemon = Daemon::new(config);
    let local_public = daemon.local_identity().unwrap().public_key();
    let peer_identity = loop {
        let identity = NodeIdentity::generate();
        if local_public < identity.public_key() {
            break identity;
        }
    };
    let peer_id = "peer-last-seen-heartbeat";
    let peer_info = control::PeerInfo {
        node_id: peer_id.to_string(),
        device_name: "Heartbeat Peer".to_string(),
        app_version: "1.2.3".to_string(),
        public_key: hex::encode(peer_identity.public_key()),
        endpoint: "203.0.113.50:51820".to_string(),
        nat_type: "Unknown".to_string(),
        virtual_ip: "10.20.0.50".to_string(),
        online: true,
        last_seen: 10,
        relay_rtt_ms: Some(25),
    };
    daemon.peers.add_peer(&peer_info).await;
    let lifecycle = daemon
        .peers
        .peer_session_generation_sync(peer_id)
        .expect("initial peer lifecycle must exist");

    let peers = daemon.peers.clone();
    let pending = daemon.pending_handshakes.clone();
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

    let mut heartbeat = peer_info;
    heartbeat.last_seen = 11;
    control
        .event_sender()
        .send(ControlEvent::PeerUpdated(heartbeat))
        .unwrap();
    timeout(Duration::from_secs(1), async {
        loop {
            if peers
                .get_connection(peer_id)
                .await
                .is_some_and(|conn| conn.last_seen == 11)
            {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("last_seen-only update must reach peer diagnostics");
    // Give the old behavior enough time to reserve and detach its initiator
    // worker. The fixed branch returns immediately after `add_peer`.
    sleep(Duration::from_millis(25)).await;

    {
        let state = pending.lock();
        assert!(!state.starting.contains(peer_id));
        assert!(!state.pending.contains_key(peer_id));
        assert!(!state.attempts.contains_key(peer_id));
    }
    assert_eq!(
        peers.peer_session_generation_sync(peer_id),
        Some(lifecycle),
        "a liveness timestamp must not rotate the authenticated peer lifecycle"
    );

    let _ = shutdown.send(true);
    timeout(Duration::from_secs(1), loop_task)
        .await
        .expect("control event loop did not stop")
        .expect("control event loop task panicked");
}

#[tokio::test]
async fn control_event_loop_processes_peer_answer_while_peer_reflexive_work_waits() {
    let config = Config::generate_default("http://127.0.0.1:1", "net1").unwrap();
    let daemon = Daemon::new(config);
    let peer_id = "peer-reflexive-blocked-answer";
    let peer_identity = NodeIdentity::generate();
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

    // Install a genuine pending initiator so the following PeerAnswer has to
    // cross the real inbound answer handler and install a session. If
    // PeerReflexive waited inline on candidate_refresh_lock, this answer would
    // remain queued and the assertion below would time out.
    let mut initiator = HandshakeInitiator::new(
        daemon.local_identity().unwrap(),
        peer_identity.public_key(),
        None,
    );
    let initiation = initiator.create_initiation().unwrap();
    let mut responder = HandshakeResponder::new(peer_identity.clone(), None);
    let (response, _) = responder
        .consume_initiation_and_respond(&initiation)
        .unwrap();
    daemon
        .pending_handshakes
        .lock()
        .insert(peer_id.to_string(), initiator, None, None);

    let candidate_refresh_lock = daemon.candidate_refresh_lock.clone();
    let candidate_guard = candidate_refresh_lock.lock().await;
    let control = daemon.control.clone();
    let transport = daemon.transport.clone();
    let shutdown = daemon.shutdown_sender();
    control
        .event_sender()
        .send(ControlEvent::PeerReflexive {
            from_node_id: peer_id.to_string(),
            observed_endpoint: "198.51.100.10:41000".to_string(),
            punch_at_ms: None,
        })
        .unwrap();
    control
        .event_sender()
        .send(ControlEvent::PeerAnswer {
            from_node_id: peer_id.to_string(),
            candidates: Vec::new(),
            session_id: None,
            probe_ephemeral_public_key: None,
            candidate_sources: HashMap::new(),
            candidate_generation: 0,
            candidates_expires_at_ms: None,
            handshake_response: response.to_bytes(),
            punch_at_ms: None,
            punch_at_server_ms: None,
            sender_public_key: Some(hex::encode(peer_identity.public_key())),
        })
        .unwrap();

    let (network_tx, _network_rx) = mpsc::channel(8);
    let mut relay_started = false;
    let mut daemon_task = daemon;
    let loop_task = tokio::spawn(async move {
        daemon_task
            .run_control_event_loop(&mut relay_started, network_tx)
            .await;
    });

    tokio::time::timeout(Duration::from_millis(350), async {
        while !transport.has_session(peer_id).await {
            sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .expect("PeerAnswer must not wait for blocked peer-reflexive candidate work");

    drop(candidate_guard);
    let _ = shutdown.send(true);
    tokio::time::timeout(Duration::from_secs(1), loop_task)
        .await
        .expect("control event loop did not stop")
        .expect("control event loop task panicked");
}

#[tokio::test]
async fn control_event_loop_processes_peer_offer_while_peer_reflexive_work_waits() {
    let config = Config::generate_default("http://127.0.0.1:1", "net1").unwrap();
    let daemon = Daemon::new(config);
    let peer_id = "peer-reflexive-blocked-offer";
    let peer_identity = NodeIdentity::generate();
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

    let candidate_refresh_lock = daemon.candidate_refresh_lock.clone();
    let candidate_guard = candidate_refresh_lock.lock().await;
    let control = daemon.control.clone();
    let peers = daemon.peers.clone();
    let shutdown = daemon.shutdown_sender();
    let offered_candidate = "198.51.100.11:42000".to_string();
    control
        .event_sender()
        .send(ControlEvent::PeerReflexive {
            from_node_id: peer_id.to_string(),
            observed_endpoint: "198.51.100.10:41000".to_string(),
            punch_at_ms: None,
        })
        .unwrap();
    control
        .event_sender()
        .send(ControlEvent::PeerOffer {
            from_node_id: peer_id.to_string(),
            candidates: vec![offered_candidate.clone()],
            session_id: None,
            probe_ephemeral_public_key: None,
            candidate_sources: HashMap::from([(offered_candidate.clone(), "stun".to_string())]),
            candidate_generation: 1,
            candidates_expires_at_ms: None,
            handshake_init: Vec::new(),
            punch_at_ms: None,
            punch_at_server_ms: None,
            sender_public_key: Some(hex::encode(peer_identity.public_key())),
        })
        .unwrap();

    let (network_tx, _network_rx) = mpsc::channel(8);
    let mut relay_started = false;
    let mut daemon_task = daemon;
    let loop_task = tokio::spawn(async move {
        daemon_task
            .run_control_event_loop(&mut relay_started, network_tx)
            .await;
    });

    tokio::time::timeout(Duration::from_millis(350), async {
        loop {
            let installed = peers
                .get_connection(peer_id)
                .await
                .is_some_and(|connection| connection.candidates.contains(&offered_candidate));
            if installed {
                break;
            }
            sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .expect("PeerOffer candidate admission must not wait for blocked peer-reflexive work");

    drop(candidate_guard);
    let _ = shutdown.send(true);
    tokio::time::timeout(Duration::from_secs(1), loop_task)
        .await
        .expect("control event loop did not stop")
        .expect("control event loop task panicked");
}

#[tokio::test]
async fn control_event_loop_queues_candidate_offer_while_connection_writer_is_blocked() {
    let config = Config::generate_default("http://127.0.0.1:1", "net1").unwrap();
    let daemon = Daemon::new(config);
    let peer_id = "peer-connection-writer-blocked-offer";
    let peer_identity = NodeIdentity::generate();
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

    // Reproduce the field failure: candidate refresh/fresh-mapping work owns
    // the global connection writer when a candidate-only offer reaches the
    // serial signal consumer.  Membership is already registered, so ingress
    // must enqueue the offer without awaiting this writer.  The worker may
    // wait for the writer, but the receiver itself must consume ControlHealthy.
    let connection_guard = daemon.peers.connection_map_for_test().write_owned().await;
    let offered_candidate = "198.51.100.23:42345".to_string();
    let control = daemon.control.clone();
    let health = daemon.health.clone();
    let peers = daemon.peers.clone();
    let timeline = daemon.timeline.clone();
    let shutdown = daemon.shutdown_sender();
    let (peer_add_started_tx, mut peer_add_started_rx) = mpsc::unbounded_channel();
    peers.install_peer_add_wait_observer_for_test(peer_add_started_tx);
    control
        .event_sender()
        .send(ControlEvent::PeerOffer {
            from_node_id: peer_id.to_string(),
            candidates: vec![offered_candidate.clone()],
            session_id: None,
            probe_ephemeral_public_key: None,
            candidate_sources: HashMap::from([(offered_candidate.clone(), "stun".to_string())]),
            candidate_generation: 1,
            candidates_expires_at_ms: None,
            handshake_init: Vec::new(),
            punch_at_ms: None,
            punch_at_server_ms: None,
            sender_public_key: Some(hex::encode(peer_identity.public_key())),
        })
        .unwrap();
    control
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

    tokio::time::timeout(Duration::from_secs(1), async {
        loop {
            if timeline.snapshot().events.iter().any(|event| {
                event.event == "peer_offer_candidate_retry"
                    && event.detail.as_deref().is_some_and(|detail| {
                        detail.contains("peer=peer-connection-writer-blocked-offer")
                    })
            }) {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("ordinary candidate worker did not exercise the non-queuing contention path");
    let heartbeat = control::PeerInfo {
        node_id: peer_id.to_string(),
        device_name: String::new(),
        app_version: String::new(),
        public_key: hex::encode(peer_identity.public_key()),
        endpoint: String::new(),
        nat_type: "Unknown".to_string(),
        virtual_ip: "10.20.0.2".to_string(),
        online: true,
        last_seen: 9,
        relay_rtt_ms: None,
    };
    control
        .event_sender()
        .send(ControlEvent::PeerUpdated(heartbeat.clone()))
        .unwrap();
    tokio::time::timeout(Duration::from_secs(1), peer_add_started_rx.recv())
        .await
        .expect("PeerUpdated did not enter the real peer update path")
        .expect("peer update observer closed");

    tokio::time::timeout(Duration::from_millis(250), async {
        loop {
            // ControlHealthy is API evidence, not a device-lease renewal.
            if health.snapshot(&[]).await.control_api_reachable {
                break;
            }
            sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .expect("ControlHealthy must pass a candidate offer blocked on the connection writer");

    drop(connection_guard);
    tokio::time::timeout(Duration::from_millis(300), async {
        loop {
            if peers
                .get_connection(peer_id)
                .await
                .is_some_and(|connection| connection.last_seen == heartbeat.last_seen)
            {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("ordinary candidate contention must not keep PeerUpdated queued behind its worker");
    tokio::time::timeout(Duration::from_millis(500), async {
        loop {
            let installed = peers
                .get_connection(peer_id)
                .await
                .is_some_and(|connection| connection.candidates.contains(&offered_candidate));
            if installed {
                break;
            }
            sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .expect("queued candidate offer must be consumed after the writer is released");

    let _ = shutdown.send(true);
    tokio::time::timeout(Duration::from_secs(1), loop_task)
        .await
        .expect("control event loop did not stop")
        .expect("control event loop task panicked");
}

#[tokio::test]
async fn fresh_candidate_lock_wait_does_not_stall_peer_update_or_queued_answer() {
    let mut control_capture = start_handshake_control_capture().await;
    let mut config =
        Config::generate_default(&control_capture.base_url, "fresh-candidate-event-loop").unwrap();
    config.control.auth_token = "fresh-candidate-event-loop-token".to_string();
    config.node.node_id = "node-local".to_string();
    config.network.punch_attempts = 1;
    let daemon = Daemon::new(config);
    timeout(Duration::from_secs(2), control_capture.wait_registered())
        .await
        .expect("control capture did not register the daemon");
    let peer_id = "peer-fresh-candidate-event-loop";
    let local_public = daemon.local_identity().unwrap().public_key();
    let peer_identity = loop {
        let identity = NodeIdentity::generate();
        if identity.public_key() < local_public {
            break identity;
        }
    };
    let peer_info = control::PeerInfo {
        node_id: peer_id.to_string(),
        public_key: hex::encode(peer_identity.public_key()),
        virtual_ip: "10.20.0.2".to_string(),
        online: true,
        ..control::PeerInfo::default()
    };
    daemon.peers.add_peer(&peer_info).await;

    let udp = crate::udp::UdpTransport::bind("127.0.0.1:0".parse().unwrap(), daemon.peers.clone())
        .await
        .unwrap();
    let local_candidate = udp.local_addr().unwrap().to_string();
    *daemon.udp_transport.write().await = Some(udp);
    daemon
        .publish_candidate_snapshot(vec![local_candidate], HashMap::new(), Vec::new())
        .await;

    let mut initiator = HandshakeInitiator::new(
        daemon.local_identity().unwrap(),
        peer_identity.public_key(),
        None,
    );
    let initiation = initiator.create_initiation().unwrap();
    let mut responder = HandshakeResponder::new(peer_identity.clone(), None);
    let (response, _) = responder
        .consume_initiation_and_respond(&initiation)
        .unwrap();
    let (active_session, _) = part03_establish_sessions();
    daemon
        .transport
        .install_active_session(
            peer_id,
            Some("preexisting-active-session".to_string()),
            active_session,
        )
        .await;

    let mut remote_initiator = HandshakeInitiator::new(
        peer_identity.clone(),
        daemon.local_identity().unwrap().public_key(),
        None,
    );
    let remote_initiation = remote_initiator.create_initiation().unwrap();
    let responder_cache_token = "candidate-postprocess-cache-replay".to_string();
    let responder_probe_public_key = hex::encode(DhKeyPair::generate().public_key());

    let control = daemon.control.clone();
    let peers = daemon.peers.clone();
    let transport = daemon.transport.clone();
    let pending_handshakes = daemon.pending_handshakes.clone();
    let timeline = daemon.timeline.clone();
    let candidate_postprocess_slot = daemon.candidate_postprocess_test_gate.clone();
    let shutdown = daemon.shutdown_sender();
    let (peer_add_started_tx, mut peer_add_started_rx) = mpsc::unbounded_channel();
    peers.install_peer_add_wait_observer_for_test(peer_add_started_tx);
    let (fresh_transaction_started_tx, mut fresh_transaction_started_rx) =
        mpsc::unbounded_channel();
    peers.install_remote_fresh_transaction_observer_for_test(fresh_transaction_started_tx);

    let (network_tx, _network_rx) = mpsc::channel(8);
    let mut relay_started = false;
    let mut daemon_task = daemon;
    let loop_task = tokio::spawn(async move {
        daemon_task
            .run_control_event_loop(&mut relay_started, network_tx)
            .await;
    });

    // First apply this WireGuard offer so the duplicate below takes the real
    // responder-cache replay path before candidate post-processing contends.
    control
        .event_sender()
        .send(ControlEvent::PeerOffer {
            from_node_id: peer_id.to_string(),
            candidates: Vec::new(),
            session_id: Some(responder_cache_token.clone()),
            probe_ephemeral_public_key: Some(responder_probe_public_key.clone()),
            candidate_sources: HashMap::new(),
            candidate_generation: 1,
            candidates_expires_at_ms: None,
            handshake_init: remote_initiation.to_bytes(),
            punch_at_ms: None,
            punch_at_server_ms: None,
            sender_public_key: Some(hex::encode(peer_identity.public_key())),
        })
        .unwrap();

    timeout(Duration::from_secs(1), async {
        loop {
            let completed = timeline.snapshot().events.iter().any(|event| {
                event.event == "peer_offer_responder_handler_completed"
                    && event
                        .detail
                        .as_deref()
                        .is_some_and(|detail| detail.contains("session_fp="))
            });
            let candidate_work_active = pending_handshakes
                .lock()
                .has_candidate_offer_work_for_test(peer_id);
            if transport.has_session(peer_id).await && completed && !candidate_work_active {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap_or_else(|_| {
        panic!(
            "initial responder transaction did not commit and release its candidate owner: {:#?}",
            timeline.snapshot().events
        )
    });

    // The duplicate keeps the same session token and initiation, so the real
    // responder worker must stage its cached answer while the candidate worker
    // pauses after its fresh-candidate commit.
    let postprocess_gate = Arc::new(CandidatePostprocessTestGate::new());
    *candidate_postprocess_slot
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner()) =
        Some((peer_id.to_string(), postprocess_gate.clone()));
    let fresh_candidate = "198.51.100.44:43444".to_string();
    let fresh_id = FreshPredictionId {
        boot_epoch: 1_742_987_654_322,
        generation: 2,
    };
    let sources = HashMap::from([(
        fresh_candidate.clone(),
        fresh_prediction_source_label(fresh_id),
    )]);
    control
        .event_sender()
        .send(ControlEvent::PeerOffer {
            from_node_id: peer_id.to_string(),
            candidates: vec![fresh_candidate],
            session_id: Some(responder_cache_token),
            probe_ephemeral_public_key: Some(responder_probe_public_key),
            candidate_sources: sources,
            candidate_generation: 2,
            candidates_expires_at_ms: None,
            handshake_init: remote_initiation.to_bytes(),
            punch_at_ms: None,
            punch_at_server_ms: None,
            sender_public_key: Some(hex::encode(peer_identity.public_key())),
        })
        .unwrap();

    timeout(Duration::from_secs(1), fresh_transaction_started_rx.recv())
        .await
        .expect("fresh candidate worker did not enter the production transaction")
        .expect("fresh transaction observer closed");

    timeout(Duration::from_secs(1), postprocess_gate.reached.notified())
        .await
        .expect("candidate transaction did not reach deferred punch preparation");
    timeout(Duration::from_secs(1), async {
        loop {
            let events = timeline.snapshot().events;
            let cached_hit = events.iter().any(|event| {
                event.event == "peer_offer_responder_cache_lookup"
                    && event
                        .detail
                        .as_deref()
                        .is_some_and(|detail| detail.contains("cache=hit"))
            });
            let cached_answer = events.iter().any(|event| {
                event.event == "peer_answer_staged"
                    && event.detail.as_deref().is_some_and(|detail| {
                        detail.contains("cached_replay=true") && detail.contains("had_active=true")
                    })
            });
            let completed_handlers = events
                .iter()
                .filter(|event| event.event == "peer_offer_responder_handler_completed")
                .count();
            if cached_hit && cached_answer && completed_handlers >= 2 {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("duplicate responder did not complete the cached answer replay before PeerUpdated");
    let connection_guard = peers.connection_map_for_test().write_owned().await;
    let (postprocess_wait_tx, mut postprocess_wait_rx) = mpsc::unbounded_channel();
    peers.install_candidate_postprocess_lock_wait_observer_for_test(postprocess_wait_tx);
    postprocess_gate.release.wait().await;
    timeout(Duration::from_secs(1), postprocess_wait_rx.recv())
        .await
        .expect("candidate post-processing did not attempt the contended connection lock")
        .expect("candidate post-process lock observer closed");

    let mut heartbeat = peer_info;
    heartbeat.last_seen = 7;
    let peer_updated_receipt = control::SignalDeliveryReceipt::pending();
    control
        .event_sender()
        .send(ControlEvent::DeliveredSignal {
            signal_id: "candidate-peer-updated-after-cache".to_string(),
            signal_seq: Some(8),
            signal_type: "peer_updated".to_string(),
            event: Box::new(ControlEvent::PeerUpdated(heartbeat)),
            receipt: peer_updated_receipt.clone(),
        })
        .unwrap();
    timeout(Duration::from_secs(1), peer_add_started_rx.recv())
        .await
        .expect("PeerUpdated did not enter the real PeerManager::add_peer path");
    timeout(Duration::from_secs(1), async {
        loop {
            if timeline.snapshot().events.iter().any(|event| {
                event.event == "peer_update_lock_wait_started"
                    && event.reason_code.as_deref() == Some("connections_write")
                    && event.detail.as_deref().is_some_and(|detail| {
                        detail.contains("signal_seq=8")
                            && detail.contains("signal_type=peer_updated")
                    })
            }) {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("PeerUpdated lock wait did not expose its exact resource and signal correlation");
    drop(connection_guard);
    let update_result = timeout(Duration::from_millis(300), async {
        loop {
            if peers
                .get_connection(peer_id)
                .await
                .is_some_and(|connection| connection.last_seen == 7)
            {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await;
    if update_result.is_err() {
        loop_task.abort();
        let _ = loop_task.await;
        panic!("PeerUpdated waited behind a fresh candidate task the loop could not poll");
    }
    assert_eq!(
        timeout(Duration::from_secs(1), peer_updated_receipt.wait())
            .await
            .expect("PeerUpdated receipt was not applied after releasing the writer"),
        control::SignalApplyOutcome::Applied
    );
    let peer_update_events = timeline.snapshot().events;
    let wait_detail = peer_update_events
        .iter()
        .find(|event| {
            event.event == "peer_update_lock_wait_started"
                && event.reason_code.as_deref() == Some("connections_write")
        })
        .and_then(|event| event.detail.as_deref())
        .expect("PeerUpdated connection-writer wait correlation disappeared");
    let attempt = wait_detail
        .split_whitespace()
        .find_map(|field| field.strip_prefix("attempt="))
        .expect("PeerUpdated lock diagnostic omitted its attempt id");
    for event_name in [
        "peer_update_lock_acquired",
        "peer_update_lock_released",
        "peer_update_commit_complete",
        "peer_update_postcommit_cleanup_completed",
    ] {
        assert!(
            peer_update_events.iter().any(|event| {
                event.event == event_name
                    && event
                        .detail
                        .as_deref()
                        .is_some_and(|detail| detail.contains(&format!("attempt={attempt} ")))
            }),
            "missing {event_name} for PeerUpdated attempt {attempt}"
        );
    }

    let answer_receipt = control::SignalDeliveryReceipt::pending();
    pending_handshakes
        .lock()
        .insert(peer_id.to_string(), initiator, None, None);
    control
        .event_sender()
        .send(ControlEvent::DeliveredSignal {
            signal_id: "fresh-candidate-following-answer".to_string(),
            signal_seq: Some(9),
            signal_type: "peer_answer".to_string(),
            event: Box::new(ControlEvent::PeerAnswer {
                from_node_id: peer_id.to_string(),
                candidates: Vec::new(),
                session_id: None,
                probe_ephemeral_public_key: None,
                candidate_sources: HashMap::new(),
                candidate_generation: 2,
                candidates_expires_at_ms: None,
                handshake_response: response.to_bytes(),
                punch_at_ms: None,
                punch_at_server_ms: None,
                sender_public_key: Some(hex::encode(peer_identity.public_key())),
            }),
            receipt: answer_receipt.clone(),
        })
        .unwrap();
    timeout(Duration::from_secs(1), async {
        while !transport.has_session(peer_id).await {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("queued handshake answer was not consumed after PeerUpdated");
    assert_eq!(
        timeout(Duration::from_secs(1), answer_receipt.wait())
            .await
            .expect("answer receipt did not reach a terminal application result"),
        control::SignalApplyOutcome::Applied
    );
    timeout(Duration::from_secs(1), async {
        loop {
            if peers
                .remote_fresh_snapshot_for(peer_id, fresh_id)
                .await
                .is_some()
            {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("fresh candidate retry did not atomically commit its candidate snapshot");

    timeout(
        Duration::from_secs(1),
        postprocess_gate.completed.notified(),
    )
    .await
    .expect("candidate post-processing did not finish after the receipt was applied");

    // A second post-commit owner is cancelled by the authoritative PeerLeft
    // while its non-queuing punch preparation observes a held connection
    // writer. The owner must leave through its lifecycle token and shutdown
    // must not inherit a queued reader/writer from that worker.
    let cancelled_postprocess_gate = Arc::new(CandidatePostprocessTestGate::new());
    *candidate_postprocess_slot
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner()) =
        Some((peer_id.to_string(), cancelled_postprocess_gate.clone()));
    let cancelled_fresh_id = FreshPredictionId {
        boot_epoch: fresh_id.boot_epoch,
        generation: 3,
    };
    let cancelled_candidate = "198.51.100.45:43445".to_string();
    control
        .event_sender()
        .send(ControlEvent::PeerOffer {
            from_node_id: peer_id.to_string(),
            candidates: vec![cancelled_candidate.clone()],
            session_id: None,
            probe_ephemeral_public_key: None,
            candidate_sources: HashMap::from([(
                cancelled_candidate.clone(),
                fresh_prediction_source_label(cancelled_fresh_id),
            )]),
            candidate_generation: 3,
            candidates_expires_at_ms: None,
            handshake_init: Vec::new(),
            punch_at_ms: None,
            punch_at_server_ms: None,
            sender_public_key: Some(hex::encode(peer_identity.public_key())),
        })
        .unwrap();
    timeout(Duration::from_secs(1), fresh_transaction_started_rx.recv())
        .await
        .expect("cancellable candidate transaction was not admitted")
        .expect("fresh transaction observer closed");
    timeout(
        Duration::from_secs(1),
        cancelled_postprocess_gate.reached.notified(),
    )
    .await
    .expect("cancellable candidate transaction did not reach post-processing");
    let cancellation_connection_guard = peers.connection_map_for_test().write_owned().await;
    let (cancel_wait_tx, mut cancel_wait_rx) = mpsc::unbounded_channel();
    peers.install_candidate_postprocess_lock_wait_observer_for_test(cancel_wait_tx);
    cancelled_postprocess_gate.release.wait().await;
    timeout(Duration::from_secs(1), cancel_wait_rx.recv())
        .await
        .expect("cancellable candidate did not observe the held connection writer")
        .expect("candidate lock observer closed");
    control
        .event_sender()
        .send(ControlEvent::PeerLeft(peer_id.to_string()))
        .unwrap();
    drop(cancellation_connection_guard);
    timeout(Duration::from_secs(1), async {
        while peers.peer_exists_sync(peer_id) {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("PeerLeft did not retire the lifecycle that owns candidate post-processing");
    timeout(
        Duration::from_secs(1),
        cancelled_postprocess_gate.completed.notified(),
    )
    .await
    .expect("cancelled candidate post-processing did not release its owner");
    assert!(
        !pending_handshakes
            .lock()
            .has_candidate_offer_work_for_test(peer_id),
        "PeerLeft left a candidate work owner behind"
    );
    let _ = shutdown.send(true);
    timeout(Duration::from_secs(1), loop_task)
        .await
        .expect("control event loop did not stop")
        .expect("control event loop task panicked");
    control_capture.stop().await;
    assert!(
        peers.connection_map_for_test().try_write().is_ok(),
        "candidate worker left a connection-map waiter after shutdown"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn blocking_candidate_apply_releases_epoch_before_waiting_for_writer_turn() {
    let config = Config::generate_default("http://127.0.0.1:1", "candidate-lock-order").unwrap();
    let daemon = Daemon::new(config);
    let peer_id = "peer-candidate-lock-order";
    let peer_identity = NodeIdentity::generate();
    daemon
        .peers
        .add_peer(&control::PeerInfo {
            node_id: peer_id.to_string(),
            public_key: hex::encode(peer_identity.public_key()),
            virtual_ip: "10.20.0.2".to_string(),
            online: true,
            ..control::PeerInfo::default()
        })
        .await;

    let peers = daemon.peers.clone();
    let reader = peers.connection_map_for_test().read_owned().await;
    let start = Arc::new(tokio::sync::Barrier::new(2));
    let worker_start = start.clone();
    let worker_peers = peers.clone();
    let sender_public_key = hex::encode(peer_identity.public_key());
    let worker = tokio::spawn(async move {
        worker_start.wait().await;
        worker_peers
            .add_candidates_with_metadata_for_identity(
                peer_id,
                &["198.51.100.81:48100".to_string()],
                &HashMap::from([("198.51.100.81:48100".to_string(), "stun".to_string())]),
                1,
                None,
                Some(&sender_public_key),
            )
            .await
    });
    start.wait().await;

    timeout(Duration::from_secs(1), async {
        loop {
            if peers.connection_map_for_test().try_read().is_err() {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("blocking candidate apply never entered the fair writer queue");
    assert!(
        peers.network_epoch_gate().try_lock().is_ok(),
        "candidate apply queued the connection writer while retaining the epoch"
    );

    drop(reader);
    assert_eq!(
        timeout(Duration::from_secs(1), worker)
            .await
            .expect("candidate apply did not finish after the reader released")
            .expect("candidate apply task panicked"),
        CandidateSetApplyResult::Applied
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn remote_incarnation_claim_and_finish_never_queue_writer_with_epoch() {
    fn encoded_generation(incarnation: u64, counter: u64) -> u64 {
        0x4000_0000_0000_0000 | (incarnation << 21) | counter
    }

    let config = Config::generate_default("http://127.0.0.1:1", "incarnation-lock-order").unwrap();
    let daemon = Daemon::new(config);
    let peer_id = "peer-incarnation-lock-order";
    let peer_identity = NodeIdentity::generate();
    let sender_public_key = hex::encode(peer_identity.public_key());
    daemon
        .peers
        .add_peer(&control::PeerInfo {
            node_id: peer_id.to_string(),
            public_key: sender_public_key.clone(),
            virtual_ip: "10.20.0.2".to_string(),
            online: true,
            ..control::PeerInfo::default()
        })
        .await;

    let peers = daemon.peers.clone();
    let reader = peers.connection_map_for_test().read_owned().await;
    let claim_start = Arc::new(tokio::sync::Barrier::new(2));
    let worker_start = claim_start.clone();
    let worker_peers = peers.clone();
    let claim = tokio::spawn(async move {
        worker_start.wait().await;
        worker_peers
            .claim_remote_candidate_incarnation_for_identity(
                peer_id,
                encoded_generation(9_000, 1),
                Some(&sender_public_key),
            )
            .await
    });
    claim_start.wait().await;

    timeout(Duration::from_secs(1), async {
        loop {
            if peers.connection_map_for_test().try_read().is_err() {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("remote-incarnation claim never entered the fair writer queue");
    assert!(
        peers.network_epoch_gate().try_lock().is_ok(),
        "remote-incarnation claim queued the writer while retaining the epoch"
    );
    drop(reader);
    assert_eq!(
        timeout(Duration::from_secs(1), claim)
            .await
            .expect("remote-incarnation claim did not finish after reader release")
            .expect("remote-incarnation claim task panicked"),
        crate::peer::RemoteCandidateIncarnationClaim::NoReset
    );

    let (old_incarnation, claimed_incarnation) = match peers
        .claim_remote_candidate_incarnation_for_identity(
            peer_id,
            encoded_generation(9_001, 1),
            None,
        )
        .await
    {
        crate::peer::RemoteCandidateIncarnationClaim::Reset {
            old_incarnation,
            new_incarnation,
        } => (old_incarnation, new_incarnation),
        outcome => panic!("new incarnation was not claimed: {outcome:?}"),
    };
    let retired_peer_session = peers.peer_session_generation_sync(peer_id).unwrap();
    let reader = peers.connection_map_for_test().read_owned().await;
    let finish_start = Arc::new(tokio::sync::Barrier::new(2));
    let worker_start = finish_start.clone();
    let worker_peers = peers.clone();
    let finish = tokio::spawn(async move {
        worker_start.wait().await;
        worker_peers
            .finish_claimed_remote_incarnation_reset(
                peer_id,
                old_incarnation,
                claimed_incarnation,
                "test_incarnation_lock_order",
            )
            .await
    });
    finish_start.wait().await;

    timeout(Duration::from_secs(1), async {
        loop {
            if peers.connection_map_for_test().try_read().is_err() {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("remote-incarnation finish never entered the fair writer queue");
    assert!(
        peers.network_epoch_gate().try_lock().is_ok(),
        "remote-incarnation finish queued the writer while retaining the epoch"
    );
    drop(reader);
    assert!(timeout(Duration::from_secs(1), finish)
        .await
        .expect("remote-incarnation finish did not complete after reader release")
        .expect("remote-incarnation finish task panicked"));
    assert_ne!(
        peers.peer_session_generation_sync(peer_id),
        Some(retired_peer_session),
        "remote-incarnation finish must rotate the peer lifecycle"
    );
}

#[tokio::test]
async fn remote_incarnation_rotation_cancels_retry_and_kicks_replacement() {
    fn encoded_generation(incarnation: u64, counter: u64) -> u64 {
        0x4000_0000_0000_0000 | (incarnation << 21) | counter
    }

    let config = Config::generate_default("http://127.0.0.1:1", "incarnation-retry-kick").unwrap();
    let daemon = Daemon::new(config);
    let peer_id = "peer-incarnation-retry-kick";
    let peer_identity = NodeIdentity::generate();
    daemon
        .peers
        .add_peer(&control::PeerInfo {
            node_id: peer_id.to_string(),
            public_key: hex::encode(peer_identity.public_key()),
            virtual_ip: "10.20.0.2".to_string(),
            online: true,
            ..control::PeerInfo::default()
        })
        .await;
    assert_eq!(
        daemon
            .peers
            .claim_remote_candidate_incarnation_for_identity(
                peer_id,
                encoded_generation(9_100, 1),
                None,
            )
            .await,
        crate::peer::RemoteCandidateIncarnationClaim::NoReset
    );

    let network_generation = daemon.peers.current_network_generation_sync();
    let retired_peer_session = daemon.peers.peer_session_generation_sync(peer_id).unwrap();
    let reservation = {
        let mut pending = daemon.pending_handshakes.lock();
        let reservation = pending
            .reserve_start_with_owner_at_generation_and_kind(
                peer_id,
                network_generation,
                retired_peer_session,
                HandshakeOwnerKind::EventInitiatorReserve,
            )
            .expect("the exact initiator reservation must be available");
        assert!(
            pending
                .schedule_initiator_retry(
                    peer_id,
                    &reservation,
                    InitiatorRetryPhase::Preparation,
                    Instant::now(),
                )
                .is_some(),
            "the exact retry must commit before the incarnation edge"
        );
        reservation
    };
    let mut restart_kick = daemon.path_setup_kick_tx.subscribe();

    assert!(
        daemon
            .reset_peer_for_remote_incarnation_if_needed(
                peer_id,
                encoded_generation(9_101, 1),
                RemoteIncarnationResetWork::PreserveResponder,
            )
            .await,
        "the newer remote incarnation must rotate the peer lifecycle"
    );
    timeout(Duration::from_secs(1), restart_kick.changed())
        .await
        .expect("the committed lifecycle rotation did not wake handshake maintenance")
        .expect("the handshake-maintenance kick sender closed");

    let pending = daemon.pending_handshakes.lock();
    assert!(
        !pending.starting.contains(peer_id) && !pending.initiator_retries.contains_key(peer_id),
        "the retired generation's reservation and retry must be cancelled together"
    );
    assert!(
        *reservation.cancellation.borrow(),
        "the retired exact owner must observe terminal cancellation"
    );
    assert_ne!(
        daemon.peers.peer_session_generation_sync(peer_id),
        Some(retired_peer_session),
        "the replacement wake is valid only after PeerSessionGeneration rotates"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn candidate_receipt_and_slow_work_do_not_head_of_line_block_responder_offer() {
    fn encoded_generation(incarnation: u64, counter: u64) -> u64 {
        0x4000_0000_0000_0000 | (incarnation << 21) | counter
    }

    let mut control_capture = start_handshake_control_capture().await;
    let mut config =
        Config::generate_default(&control_capture.base_url, "candidate-hol-responder").unwrap();
    config.control.auth_token = "candidate-hol-responder-token".to_string();
    config.node.node_id = "node-local".to_string();
    let daemon = Daemon::new(config);
    timeout(Duration::from_secs(2), control_capture.wait_registered())
        .await
        .expect("daemon registration must complete before the HOL regression");

    let local_public = daemon.local_identity().unwrap().public_key();
    let remote_identity = loop {
        let identity = NodeIdentity::generate();
        if identity.public_key() < local_public {
            break identity;
        }
    };
    let peer_id = "peer-candidate-hol-responder";
    let peer_info = control::PeerInfo {
        node_id: peer_id.to_string(),
        public_key: hex::encode(remote_identity.public_key()),
        virtual_ip: "10.20.0.2".to_string(),
        online: true,
        ..control::PeerInfo::default()
    };
    let mut remote_initiator = HandshakeInitiator::new(remote_identity.clone(), local_public, None);
    let initiation = remote_initiator.create_initiation().unwrap().to_bytes();
    let session_id = "candidate-hol-responder-session".to_string();
    let probe_public_key = hex::encode(DhKeyPair::generate().public_key());

    daemon.relay_available_tx.send_replace(true);
    let control = daemon.control.clone();
    let peers = daemon.peers.clone();
    let pending = daemon.pending_handshakes.clone();
    let transport = daemon.transport.clone();
    let shutdown = daemon.shutdown_sender();
    let start = Arc::new(tokio::sync::Barrier::new(2));
    let loop_start = start.clone();
    let (network_tx, _network_rx) = mpsc::channel(8);
    let mut relay_started = false;
    let mut daemon_task = daemon;
    let loop_task = tokio::spawn(async move {
        loop_start.wait().await;
        daemon_task
            .run_control_event_loop(&mut relay_started, network_tx)
            .await;
    });
    start.wait().await;

    control
        .event_sender()
        .send(ControlEvent::PeerJoined(peer_info))
        .unwrap();
    timeout(Duration::from_secs(1), async {
        while !peers.peer_exists_sync(peer_id) {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("peer lifecycle must be published before the contention edge");

    // Publish the remote incarnation first so the two delivered offers take
    // the synchronous same-incarnation fast path. The contention below then
    // occurs at candidate apply itself, not at incarnation preflight.
    let initial_incarnation = timeout(Duration::from_secs(1), async {
        loop {
            let outcome = peers.try_claim_remote_candidate_incarnation_for_identity(
                peer_id,
                encoded_generation(733, 1),
                Some(&hex::encode(remote_identity.public_key())),
            );
            if !matches!(
                outcome,
                crate::peer::RemoteCandidateIncarnationTryClaim::ContendedEpoch
                    | crate::peer::RemoteCandidateIncarnationTryClaim::ContendedConnections
            ) {
                break outcome;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("peer-join lifecycle transaction did not release its canonical locks");
    assert_eq!(
        initial_incarnation,
        crate::peer::RemoteCandidateIncarnationTryClaim::Committed(
            crate::peer::RemoteCandidateIncarnationClaim::NoReset,
        )
    );

    // A read guard makes candidate mutation need the connection writer. The
    // candidate owner must use try-write, retain the exact payload locally,
    // and ACK its durable row without joining Tokio's fair writer queue.
    let connection_reader = peers.hold_connections_reader_for_test().await;
    let candidate_receipt = control::SignalDeliveryReceipt::pending();
    control
        .event_sender()
        .send(ControlEvent::DeliveredSignal {
            signal_id: "candidate-before-handshake".to_string(),
            signal_seq: Some(1),
            signal_type: "peer_offer".to_string(),
            event: Box::new(ControlEvent::PeerOffer {
                from_node_id: peer_id.to_string(),
                candidates: vec!["198.51.100.80:48000".to_string()],
                session_id: None,
                probe_ephemeral_public_key: None,
                candidate_sources: HashMap::from([(
                    "198.51.100.80:48000".to_string(),
                    "stun".to_string(),
                )]),
                candidate_generation: encoded_generation(733, 2),
                candidates_expires_at_ms: None,
                handshake_init: Vec::new(),
                punch_at_ms: None,
                punch_at_server_ms: None,
                sender_public_key: Some(hex::encode(remote_identity.public_key())),
            }),
            receipt: candidate_receipt.clone(),
        })
        .unwrap();
    assert_eq!(
        timeout(Duration::from_secs(1), candidate_receipt.wait())
            .await
            .expect("candidate enqueue must commit while the reader is held"),
        control::SignalApplyOutcome::Applied
    );
    assert!(
        peers.connection_map_for_test().try_read().is_ok(),
        "candidate admission queued a connection writer behind the held reader"
    );
    timeout(Duration::from_secs(1), async {
        loop {
            if let Ok(epoch) = peers.network_epoch_gate().try_lock() {
                drop(epoch);
                break;
            }
            // The bounded owner may be inside its next legitimate try-only
            // transaction at the exact instant the receipt is observed. It
            // must nevertheless expose an epoch-free retry boundary while
            // the connection reader remains held.
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("candidate apply retained the network epoch across connection contention");

    let responder_receipt = control::SignalDeliveryReceipt::pending();
    control
        .event_sender()
        .send(ControlEvent::DeliveredSignal {
            signal_id: "handshake-after-candidate".to_string(),
            signal_seq: Some(2),
            signal_type: "peer_offer".to_string(),
            event: Box::new(ControlEvent::PeerOffer {
                from_node_id: peer_id.to_string(),
                candidates: vec!["198.51.100.80:48000".to_string()],
                session_id: Some(session_id),
                probe_ephemeral_public_key: Some(probe_public_key),
                candidate_sources: HashMap::from([(
                    "198.51.100.80:48000".to_string(),
                    "stun".to_string(),
                )]),
                candidate_generation: encoded_generation(733, 3),
                candidates_expires_at_ms: None,
                handshake_init: initiation,
                punch_at_ms: None,
                punch_at_server_ms: None,
                sender_public_key: Some(hex::encode(remote_identity.public_key())),
            }),
            receipt: responder_receipt.clone(),
        })
        .unwrap();

    timeout(Duration::from_secs(1), async {
        while !pending.lock().responder_workers.contains_key(peer_id) {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("handshake must enter its independent responder owner");
    assert_eq!(
        responder_receipt.current(),
        control::SignalApplyOutcome::Pending,
        "the handshake receipt must remain exact until responder commit"
    );

    // A following marker proves the serial actor is still consuming events
    // while both bounded workers observe connection contention.
    let marker_receipt = control::SignalDeliveryReceipt::pending();
    control
        .event_sender()
        .send(ControlEvent::DeliveredSignal {
            signal_id: "post-handshake-marker".to_string(),
            signal_seq: Some(3),
            signal_type: "test_marker".to_string(),
            event: Box::new(ControlEvent::ServerError {
                code: 4999,
                message: "candidate HOL regression marker".to_string(),
            }),
            receipt: marker_receipt.clone(),
        })
        .unwrap();
    assert_eq!(
        timeout(Duration::from_secs(1), marker_receipt.wait())
            .await
            .expect("serial actor stopped behind candidate/responder contention"),
        control::SignalApplyOutcome::Applied
    );

    drop(connection_reader);
    assert_eq!(
        timeout(Duration::from_secs(2), responder_receipt.wait())
            .await
            .expect("responder did not commit after connection contention cleared"),
        control::SignalApplyOutcome::Applied
    );
    timeout(
        Duration::from_secs(1),
        control_capture.wait_for_signal_count(1),
    )
    .await
    .expect("mock control did not receive the responder Answer");
    assert_eq!(
        control_capture
            .signal_bodies()
            .iter()
            .filter_map(|body| serde_json::from_str::<serde_json::Value>(body).ok())
            .filter(|body| {
                body.get("type").and_then(serde_json::Value::as_str) == Some("peer_answer")
            })
            .count(),
        1,
        "candidate contention may produce only one exact Answer"
    );
    assert!(transport.has_session(peer_id).await);
    timeout(Duration::from_secs(2), async {
        loop {
            let candidate_committed =
                peers
                    .get_connection(peer_id)
                    .await
                    .is_some_and(|connection| {
                        connection
                            .candidates
                            .iter()
                            .any(|candidate| candidate == "198.51.100.80:48000")
                    });
            let candidate_owner_finished =
                !pending.lock().candidate_offer_workers.contains_key(peer_id);
            if candidate_committed && candidate_owner_finished {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("candidate owner must retry, finish its handover transaction, and release the epoch");
    assert!(
        peers.network_epoch_gate().try_lock().is_ok(),
        "candidate follow-up leaked the network epoch guard"
    );

    let _ = shutdown.send(true);
    timeout(Duration::from_secs(1), loop_task)
        .await
        .expect("control event loop did not stop")
        .expect("control event loop task panicked");
    control_capture.stop().await;
}

#[tokio::test]
async fn remote_incarnation_cleanup_fence_prevents_no_reset_race() {
    fn encoded_generation(incarnation: u64, counter: u64) -> u64 {
        0x4000_0000_0000_0000 | (incarnation << 21) | counter
    }

    let config = Config::generate_default("http://127.0.0.1:1", "reset-fence").unwrap();
    let daemon = Daemon::new(config);
    let remote_identity = NodeIdentity::generate();
    let peer_id = "peer-reset-fence";
    let peer_info = control::PeerInfo {
        node_id: peer_id.to_string(),
        public_key: hex::encode(remote_identity.public_key()),
        virtual_ip: "10.20.0.2".to_string(),
        online: true,
        ..control::PeerInfo::default()
    };
    daemon.peers.add_peer(&peer_info).await;

    let first = encoded_generation(8_000, 1);
    assert_eq!(
        daemon
            .peers
            .try_claim_remote_candidate_incarnation_for_identity(
                peer_id,
                first,
                Some(&peer_info.public_key),
            ),
        crate::peer::RemoteCandidateIncarnationTryClaim::Committed(
            crate::peer::RemoteCandidateIncarnationClaim::NoReset,
        )
    );
    let restart = encoded_generation(8_001, 1);
    let (old_incarnation, claimed_incarnation) = match daemon
        .peers
        .try_claim_remote_candidate_incarnation_for_identity(
            peer_id,
            restart,
            Some(&peer_info.public_key),
        ) {
        crate::peer::RemoteCandidateIncarnationTryClaim::Committed(
            crate::peer::RemoteCandidateIncarnationClaim::Reset {
                old_incarnation,
                new_incarnation,
            },
        ) => (old_incarnation, new_incarnation),
        outcome => panic!("restart claim was not admitted: {outcome:?}"),
    };
    assert!(daemon
        .pending_handshakes
        .lock()
        .begin_remote_incarnation_reset(peer_id, claimed_incarnation));

    assert_eq!(
        daemon
            .reset_peer_for_remote_incarnation_if_needed_for_identity(
                peer_id,
                restart,
                Some(&peer_info.public_key),
                RemoteIncarnationResetWork::PreserveResponder,
            )
            .await,
        RemoteIncarnationResetOutcome::PendingCleanup,
        "a parallel worker must not mistake a claimed high-water for committed cleanup",
    );

    assert!(
        daemon
            .peers
            .finish_claimed_remote_incarnation_reset(
                peer_id,
                old_incarnation,
                claimed_incarnation,
                "test_reset_fence",
            )
            .await
    );
    daemon
        .pending_handshakes
        .lock()
        .finish_remote_incarnation_reset(peer_id, claimed_incarnation);
    assert_eq!(
        daemon
            .reset_peer_for_remote_incarnation_if_needed_for_identity(
                peer_id,
                restart,
                Some(&peer_info.public_key),
                RemoteIncarnationResetWork::PreserveResponder,
            )
            .await,
        RemoteIncarnationResetOutcome::Unchanged,
        "NoReset is admissible only after the claimed cleanup commits",
    );
}
