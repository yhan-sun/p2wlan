// Split out of the former flat include!-ed test file so the module is a
// real Rust scope. Everything below is unchanged test code.
use super::*;

#[tokio::test]
async fn initiator_arbiter_is_released_before_candidate_refresh_wait() {
    use std::future::Future;
    use std::task::Poll;

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
        node_id: "peer-arbiter-candidate-wait".to_string(),
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
    let candidate_refresh_lock = daemon.candidate_refresh_lock.clone();
    let candidate_guard = candidate_refresh_lock.lock().await;
    let mut reservation = daemon
        .reserve_event_initiator_handshake(&peer_info.node_id)
        .expect("event initiator reservation must be admitted");
    let mut worker =
        Box::pin(daemon.run_reserved_initiator_handshake(&peer_info, &mut reservation));

    // A direct poll reaches the blocked candidate lock. If the initiator still
    // held its arbiter guard at this point, the acquisition below would time
    // out; a crossing offer/answer could not make progress.
    std::future::poll_fn(|context| match worker.as_mut().poll(context) {
        Poll::Pending => Poll::Ready(()),
        Poll::Ready(result) => {
            panic!("candidate-blocked worker completed unexpectedly: {result:?}")
        }
    })
    .await;
    let guard = daemon
        .handshake_arbiter
        .try_acquire(HandshakeLeaseIdentity::new(
            &peer_info.node_id,
            HandshakeOwnerKind::Responder,
            None,
            daemon.peers.current_network_generation_sync(),
            daemon
                .peers
                .peer_session_generation_sync(&peer_info.node_id),
            "candidate_wait_probe",
        ))
        .expect("arbiter must be free while candidate gathering waits");
    drop(guard);

    daemon
        .pending_handshakes
        .lock()
        .clear_peer(&peer_info.node_id);
    drop(candidate_guard);
    tokio::time::timeout(Duration::from_secs(1), &mut worker)
        .await
        .expect("cancelled candidate worker did not return")
        .expect("cancelled candidate worker returned an error");
}

#[tokio::test]
async fn initiator_publish_releases_epoch_while_connection_writer_is_contended() {
    let config = Config::generate_default("http://127.0.0.1:1", "net1").unwrap();
    let daemon = Arc::new(Daemon::new(config));
    let local_public = daemon.local_identity().unwrap().public_key();
    let peer_identity = loop {
        let identity = NodeIdentity::generate();
        if local_public < identity.public_key() {
            break identity;
        }
    };
    let peer_info = control::PeerInfo {
        node_id: "peer-initiator-connection-contention".to_string(),
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
    daemon.relay_available_tx.send_replace(true);

    let mut reservation = daemon
        .reserve_event_initiator_handshake(&peer_info.node_id)
        .expect("event initiator reservation must be admitted");
    let peers = daemon.peers.clone();
    let pending = daemon.pending_handshakes.clone();
    let timeline = daemon.timeline.clone();
    let peer_id = peer_info.node_id.clone();
    let mut retry_rx = daemon.handshake_retry_kick_tx.subscribe();
    let reservation_owner = reservation.owner;

    // A candidate/connection reader is sufficient to make Probe-binding
    // staging need the connection writer. The old publish path inserted its
    // pending initiator and then awaited that writer while retaining both the
    // emit and network-epoch guards, completing an ABBA cycle with lifecycle
    // work that needed the epoch before it could release the connection map.
    let connection_guard = peers.connection_map_for_test().read_owned().await;
    let worker_daemon = daemon.clone();
    let worker_peer = peer_info.clone();
    let worker = tokio::spawn(async move {
        worker_daemon
            .run_reserved_initiator_handshake(&worker_peer, &mut reservation)
            .await
    });

    tokio::time::timeout(Duration::from_secs(1), async {
        loop {
            if timeline
                .snapshot()
                .events
                .iter()
                .any(|event| event.event == "initiator_publish_probe_binding_contended")
            {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("initiator must report connection-writer contention");

    assert!(
        !pending.lock().pending.contains_key(&peer_id),
        "an initiator must not become pending before its Probe binding is staged"
    );
    let epoch_gate = peers.network_epoch_gate();
    let epoch_guard = tokio::time::timeout(Duration::from_millis(250), epoch_gate.lock())
        .await
        .expect("connection contention must not retain the network-epoch guard");
    drop(epoch_guard);

    let result = tokio::time::timeout(Duration::from_secs(1), worker)
        .await
        .expect("contended initiator must leave the cooperative owner immediately")
        .expect("initiator task must not panic")
        .expect("connection contention is a non-fatal initiator outcome");
    assert_eq!(result, None);

    {
        let state = pending.lock();
        assert!(state.starting.contains(&peer_id));
        assert!(state.starting_prepared.contains_key(&peer_id));
        assert!(state.initiator_retries.contains_key(&peer_id));
    }

    drop(connection_guard);
    tokio::time::timeout(Duration::from_secs(1), retry_rx.changed())
        .await
        .expect("contention must publish an exact retry edge")
        .expect("handshake retry sender must stay live");
    assert!(timeline.snapshot().events.iter().any(|event| {
        event.event == "initiator_handshake_retry_scheduled"
            && event
                .detail
                .as_deref()
                .is_some_and(|detail| detail.contains("phase=publish"))
    }));
    let (identity, mut retry_reservation) = pending
        .lock()
        .claim_ready_initiator_retry(Instant::now())
        .expect("exact retry must be ready after contention");
    assert_eq!(identity.reservation_owner, reservation_owner);
    let _ = tokio::time::timeout(
        Duration::from_secs(2),
        daemon.run_reserved_initiator_handshake(&peer_info, &mut retry_reservation),
    )
    .await
    .expect("exact prepared initiation retry must not stall");
    let session_id = {
        let mut state = pending.lock();
        let session_id = state.pending_session_ids.get(&peer_id).cloned();
        state.clear_peer(&peer_id);
        session_id
    };
    if let Some(session_id) = session_id {
        daemon
            .peers
            .discard_pending_probe_session_binding(&peer_id, &session_id)
            .await;
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn initiator_publish_epoch_contention_releases_emit_and_retries_exact_offer() {
    let mut control_capture = start_handshake_control_capture().await;
    let mut config =
        Config::generate_default(&control_capture.base_url, "initiator-epoch-contention").unwrap();
    config.control.auth_token = "initiator-epoch-contention-token".to_string();
    config.node.node_id = "node-local".to_string();
    let daemon = Arc::new(Daemon::new(config));
    timeout(Duration::from_secs(2), control_capture.wait_registered())
        .await
        .expect("daemon registration must complete before epoch contention");

    let local_public = daemon.local_identity().unwrap().public_key();
    let remote_identity = loop {
        let identity = NodeIdentity::generate();
        if local_public < identity.public_key() {
            break identity;
        }
    };
    let peer_info = control::PeerInfo {
        node_id: "peer-initiator-epoch-contention".to_string(),
        public_key: hex::encode(remote_identity.public_key()),
        virtual_ip: "10.20.0.2".to_string(),
        online: true,
        ..control::PeerInfo::default()
    };
    daemon.peers.add_peer(&peer_info).await;
    daemon.relay_available_tx.send_replace(true);

    let epoch_gate = daemon.peers.network_epoch_gate();
    let epoch_guard = epoch_gate.lock().await;
    let mut reservation = daemon
        .reserve_event_initiator_handshake(&peer_info.node_id)
        .expect("event initiator reservation must be admitted");
    let reservation_owner = reservation.owner;
    let worker = {
        let daemon = daemon.clone();
        let peer_info = peer_info.clone();
        tokio::spawn(async move {
            daemon
                .run_reserved_initiator_handshake(&peer_info, &mut reservation)
                .await
        })
    };
    let first = timeout(Duration::from_secs(1), worker)
        .await
        .expect("epoch contention must not block the initiator worker")
        .expect("initiator worker panicked")
        .expect("epoch contention is a non-fatal publish outcome");
    assert_eq!(first, None);

    let emit_guard = daemon
        .transport
        .try_acquire_outbound_emit_guard(&peer_info.node_id)
        .expect("publish retained the emit guard while the epoch was contended");
    drop(emit_guard);
    {
        let state = daemon.pending_handshakes.lock();
        assert!(state.starting_prepared.contains_key(&peer_info.node_id));
        let retry = state
            .initiator_retries
            .get(&peer_info.node_id)
            .expect("exact prepared publish retry was not retained");
        assert_eq!(retry.identity.reservation_owner, reservation_owner);
        assert_eq!(retry.identity.phase, InitiatorRetryPhase::Publish);
    }
    assert!(daemon.timeline.snapshot().events.iter().any(|event| {
        event.event == "initiator_publish_epoch_gate_contended"
            && event
                .detail
                .as_deref()
                .is_some_and(|detail| detail.contains("queued=false"))
    }));

    drop(epoch_guard);
    let (identity, mut retry_reservation) = daemon
        .pending_handshakes
        .lock()
        .claim_ready_initiator_retry(Instant::now())
        .expect("exact epoch-contention retry must be ready");
    assert_eq!(identity.reservation_owner, reservation_owner);
    let published = timeout(
        Duration::from_secs(2),
        daemon.run_reserved_initiator_handshake(&peer_info, &mut retry_reservation),
    )
    .await
    .expect("exact publish retry stalled after epoch release")
    .expect("exact publish retry failed");
    assert!(published.is_some());
    timeout(
        Duration::from_secs(1),
        control_capture.wait_for_signal_count(1),
    )
    .await
    .expect("mock control did not receive the retried Offer");
    let offers = control_capture
        .signal_bodies()
        .iter()
        .filter_map(|body| serde_json::from_str::<serde_json::Value>(body).ok())
        .filter(|body| body.get("type").and_then(serde_json::Value::as_str) == Some("peer_offer"))
        .count();
    assert_eq!(offers, 1, "the exact reservation may publish one Offer");

    let session_id = {
        let mut state = daemon.pending_handshakes.lock();
        let session_id = state.pending_session_ids.get(&peer_info.node_id).cloned();
        state.clear_peer(&peer_info.node_id);
        session_id
    };
    if let Some(session_id) = session_id {
        daemon
            .peers
            .discard_pending_probe_session_binding(&peer_info.node_id, &session_id)
            .await;
    }
    control_capture.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn responder_probe_binding_contention_retains_exact_answer_without_queued_writer() {
    let mut control_capture = start_handshake_control_capture().await;
    let mut config =
        Config::generate_default(&control_capture.base_url, "responder-binding-contention")
            .unwrap();
    config.control.auth_token = "responder-binding-contention-token".to_string();
    config.node.node_id = "node-local".to_string();
    let daemon = Arc::new(Daemon::new(config));
    timeout(Duration::from_secs(2), control_capture.wait_registered())
        .await
        .expect("daemon registration must complete before responder contention");

    let local_public = daemon.local_identity().unwrap().public_key();
    let remote_identity = loop {
        let identity = NodeIdentity::generate();
        if identity.public_key() < local_public {
            break identity;
        }
    };
    let peer_id = "peer-responder-binding-contention";
    daemon
        .peers
        .add_peer(&control::PeerInfo {
            node_id: peer_id.to_string(),
            public_key: hex::encode(remote_identity.public_key()),
            virtual_ip: "10.20.0.3".to_string(),
            online: true,
            ..control::PeerInfo::default()
        })
        .await;
    daemon.relay_available_tx.send_replace(true);

    let mut remote_initiator = HandshakeInitiator::new(remote_identity, local_public, None);
    let initiation = remote_initiator.create_initiation().unwrap().to_bytes();
    let session_id = "responder-binding-contention-session".to_string();
    let request_probe_public_key = hex::encode(DhKeyPair::generate().public_key());
    let connection_guard = daemon.peers.connection_map_for_test().read_owned().await;

    let first_error = timeout(
        Duration::from_secs(1),
        daemon.handle_peer_offer(
            peer_id,
            &[],
            &initiation,
            None,
            None,
            Some(session_id.clone()),
            Some(request_probe_public_key.clone()),
        ),
    )
    .await
    .expect("responder queued behind the held connection reader")
    .expect_err("connection contention must be a typed retry outcome");
    assert!(matches!(
        first_error,
        DaemonError::Network(ref reason)
            if reason == REASON_RESPONDER_PROBE_BINDING_CONTENDED
    ));
    assert!(timeout(
        Duration::from_millis(100),
        daemon.peers.get_connection(peer_id)
    )
    .await
    .expect("responder contention queued a writer and blocked a later reader")
    .is_some());
    assert!(
        daemon
            .pending_handshakes
            .lock()
            .responder_cache
            .contains_key(&(peer_id.to_string(), session_id.clone())),
        "the authenticated exact Answer must be retained before try-write contention"
    );
    assert!(
        daemon
            .transport
            .session_status(peer_id)
            .await
            .has_pending_responder
    );

    drop(connection_guard);
    timeout(
        Duration::from_secs(2),
        daemon.handle_peer_offer(
            peer_id,
            &[],
            &initiation,
            None,
            None,
            Some(session_id),
            Some(request_probe_public_key),
        ),
    )
    .await
    .expect("exact cached responder retry stalled after reader release")
    .expect("exact cached responder retry failed");
    timeout(
        Duration::from_secs(1),
        control_capture.wait_for_signal_count(1),
    )
    .await
    .expect("mock control did not receive the retained exact Answer");
    let answers = control_capture
        .signal_bodies()
        .iter()
        .filter_map(|body| serde_json::from_str::<serde_json::Value>(body).ok())
        .filter(|body| body.get("type").and_then(serde_json::Value::as_str) == Some("peer_answer"))
        .count();
    assert_eq!(answers, 1, "contention retry may publish one exact Answer");
    assert!(daemon.transport.has_session(peer_id).await);
    control_capture.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn relay_probe_snapshot_contention_preserves_exact_publish_retry_without_queued_writer() {
    let config = Config::generate_default("http://127.0.0.1:1", "net1").unwrap();
    let daemon = Arc::new(Daemon::new(config));
    let local_public = daemon.local_identity().unwrap().public_key();
    let peer_identity = loop {
        let identity = NodeIdentity::generate();
        if local_public < identity.public_key() {
            break identity;
        }
    };
    let peer_info = control::PeerInfo {
        node_id: "peer-relay-snapshot-contention".to_string(),
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
    daemon.relay_available_tx.send_replace(true);

    let relay_snapshot_gate = Arc::new(crate::peer::RelayProbeSnapshotTestGate::new());
    daemon.peers.install_relay_probe_snapshot_gate_for_test(
        &peer_info.node_id,
        relay_snapshot_gate.clone(),
    );
    let relay_peers = daemon.peers.clone();
    let relay_targets = tokio::spawn(async move { relay_peers.relay_probe_targets().await });
    tokio::time::timeout(
        Duration::from_secs(1),
        relay_snapshot_gate.reached.notified(),
    )
    .await
    .expect("the real relay target snapshot must own the connection reader");

    let mut retry_rx = daemon.handshake_retry_kick_tx.subscribe();
    let mut reservation = daemon
        .reserve_event_initiator_handshake(&peer_info.node_id)
        .expect("event initiator reservation must be admitted");
    let reservation_owner = reservation.owner;
    let cancellation_generation = reservation.cancellation_generation;
    let first_result = tokio::time::timeout(
        Duration::from_secs(1),
        daemon.run_reserved_initiator_handshake(&peer_info, &mut reservation),
    )
    .await
    .expect("initiator must return immediately on connection contention")
    .expect("connection contention is a non-fatal initiator outcome");
    assert_eq!(first_result, None);
    assert_eq!(
        reservation.disposition,
        HandshakeStartDisposition::RetryScheduled
    );

    // A try-write must never enter Tokio's writer queue.  A later reader can
    // therefore complete while the original Relay snapshot is still held.
    assert!(tokio::time::timeout(
        Duration::from_millis(100),
        daemon.peers.get_connection(&peer_info.node_id),
    )
    .await
    .expect("connection contention queued a writer and blocked a later reader")
    .is_some());

    {
        let state = daemon.pending_handshakes.lock();
        assert!(!state.pending.contains_key(&peer_info.node_id));
        assert!(state.starting.contains(&peer_info.node_id));
        assert!(state.starting_prepared.contains_key(&peer_info.node_id));
        assert_eq!(state.initiator_retries.len(), 1);
        let retry = state
            .initiator_retries
            .get(&peer_info.node_id)
            .expect("exact publish retry must be retained");
        assert_eq!(retry.identity.reservation_owner, reservation_owner);
        assert_eq!(
            retry.identity.cancellation_generation,
            cancellation_generation
        );
        assert_eq!(retry.identity.phase, InitiatorRetryPhase::Publish);
    }
    tokio::time::timeout(Duration::from_secs(1), retry_rx.changed())
        .await
        .expect("exact retry wake must be published after the state commit")
        .expect("retry coordinator must stay live");

    relay_snapshot_gate.release.notify_one();
    tokio::time::timeout(Duration::from_secs(1), relay_targets)
        .await
        .expect("relay target scan must resume")
        .expect("relay target task must not panic");

    let (retry_identity, mut retry_reservation) = daemon
        .pending_handshakes
        .lock()
        .claim_ready_initiator_retry(Instant::now())
        .expect("the exact retry must be claimable");
    assert_eq!(retry_identity.reservation_owner, reservation_owner);
    assert_eq!(
        retry_identity.cancellation_generation,
        cancellation_generation
    );
    let _retry_result = tokio::time::timeout(
        Duration::from_secs(2),
        daemon.run_reserved_initiator_handshake(&peer_info, &mut retry_reservation),
    )
    .await
    .expect("exact prepared publication retry must not stall");

    let staged_count = daemon
        .timeline
        .snapshot()
        .events
        .iter()
        .filter(|event| {
            event.event == "initiator_session_staged"
                && event
                    .detail
                    .as_deref()
                    .is_some_and(|detail| detail.contains(&peer_info.node_id))
        })
        .count();
    assert_eq!(staged_count, 1, "the exact owner may stage only one Offer");

    let session_id = {
        let mut state = daemon.pending_handshakes.lock();
        let session_id = state.pending_session_ids.get(&peer_info.node_id).cloned();
        state.clear_peer(&peer_info.node_id);
        session_id
    };
    if let Some(session_id) = session_id {
        daemon
            .peers
            .discard_pending_probe_session_binding(&peer_info.node_id, &session_id)
            .await;
    }
}
