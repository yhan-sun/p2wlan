use super::*;

const TOKEN: &str = "winner-cleanup-token";

struct WinnerFixture {
    peers: Arc<PeerManager>,
    udp: Arc<UdpTransport>,
    remote: UdpSocket,
    indices: [usize; 2],
    sockets: [Arc<UdpSocket>; 2],
    validation: Arc<tokio::sync::Notify>,
}

impl WinnerFixture {
    async fn new() -> Self {
        Self::with_role(true).await
    }

    async fn with_role(initiator: bool) -> Self {
        Self::with_protocol(initiator, false).await
    }

    async fn with_protocol(initiator: bool, hh2: bool) -> Self {
        let local = NodeIdentity::generate();
        let remote_identity = NodeIdentity::generate();
        let remote = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let endpoint = remote.local_addr().unwrap();
        let peers = Arc::new(PeerManager::new(config_for_identity(&local, "peer-a")));
        let mut peer = peer_with_public_key(
            "peer-b",
            "10.20.0.2",
            hex::encode(remote_identity.public_key()),
            Some(endpoint),
        );
        if hh2 {
            peer.registration_seq = 1;
            peer.capabilities = crate::control::PeerCapabilities {
                hh2_pair_nomination: true,
                hh2_plan_v2: true,
                probe_opaque_ids_v1: false,
            };
            peer.nat_type = "p2v2:m=address_or_port_dependent;a=linear;d=4;c=90;f=address_dependent;h=unknown;g=1".into();
        }
        peers.add_peer(&peer).await;
        peers
            .update_nat_profile(hard_nat_profile().await.nat_profile)
            .await;
        let validation = Arc::new(tokio::sync::Notify::new());
        let validation_signal = validation.clone();
        let (tx, _rx) = mpsc::channel(8);
        let udp = Arc::new(
            UdpTransport::bind("127.0.0.1:0".parse().unwrap(), peers.clone())
                .await
                .unwrap()
                .with_local_node_id("peer-a")
                .with_inbound_channel(tx)
                .with_validation_trigger(Arc::new(move |_| validation_signal.notify_one())),
        );
        let mut attached = Vec::new();
        for position in 0..2 {
            let (index, socket) = udp.bind_fresh_punch_socket().await.unwrap();
            let generation = position + 1;
            let guard = udp
                .attach_dynamic_punch_socket("peer-b", index, socket.clone(), 0, generation, None)
                .await
                .unwrap();
            assert!(udp.reserve_hard_hard_socket("peer-b", index).await);
            let commit = if position == 0 {
                guard
                    .commit_and_pin(&udp, "peer-b", index, 0, generation)
                    .await
            } else {
                guard
                    .commit_speculative(&udp, "peer-b", index, 0, generation)
                    .await
            };
            assert!(commit.committed());
            assert!(guard.finalize().await);
            assert!(udp.tag_hard_hard_socket("peer-b", index, TOKEN).await);
            attached.push((index, socket));
        }
        let indices = [attached[0].0, attached[1].0];
        let sockets = [attached[0].1.clone(), attached[1].1.clone()];
        let epoch = peers
            .current_remote_candidate_epoch("peer-b")
            .await
            .unwrap();
        let profile_generation = peers.current_local_profile_generation_sync();
        let now = crate::peer::hard_hard_now_ms();
        assert!(
            peers
                .hard_hard_register_session(crate::peer::HardHardSessionRecord {
                    pair_nomination: hh2.then(crate::peer::HardHardPairNomination::default),
                    coordinated_plan: None,
                    session_id: "winner-cleanup-session".into(),
                    probe_session_id: None,
                    session_token: TOKEN.into(),
                    peer_id: "peer-b".into(),
                    initiator,
                    remote_network_generation: 0,
                    local_network_generation: 0,
                    remote_candidate_epoch: epoch,
                    local_profile_generation: profile_generation,
                    remote_profile_generation: if hh2 { 1 } else { 0 },
                    local_prediction_confidence: 90,
                    remote_prediction_confidence: 90,
                    requested_birthday_level: 64,
                    generated_candidate_count: 64,
                    signaled_candidate_count: 64,
                    birthday: true,
                    requested_socket_indices: indices.to_vec(),
                    requested_socket_count: 2,
                    prediction_window: vec![endpoint],
                    remote_prediction: vec![endpoint],
                    fresh_socket: crate::peer::HardHardFreshSocketIdentity {
                        peer_id: "peer-b".into(),
                        session_token: TOKEN.into(),
                        network_generation: 0,
                        remote_candidate_epoch: epoch,
                        local_profile_generation: profile_generation,
                        remote_profile_generation: if hh2 { 1 } else { 0 },
                        punch_generation: 1,
                        socket_index: indices[0],
                        socket_local_endpoint: sockets[0].local_addr().unwrap(),
                    },
                    punch_at_ms: now,
                    expires_at_ms: now.saturating_add(30_000),
                    state: crate::peer::HardHardSessionState::Sweeping,
                    attempt_count: 1,
                    measurement: crate::peer::HardHardMeasurementObservation::default(),
                    created_at: Instant::now(),
                    cancellation: Arc::new(crate::PunchSessionCancellation::default()),
                })
                .await
        );
        if hh2 {
            assert!(udp.enable_hard_hard_pair_sockets("peer-b", TOKEN).await);
        }
        Self {
            peers,
            udp,
            remote,
            indices,
            sockets,
            validation,
        }
    }

    async fn send(&self, position: usize) -> ProbeSendResult {
        self.udp
            .send_probe_on_socket_result_with_hard_hard_token_classified(
                self.indices[position],
                self.sockets[position].clone(),
                Some("peer-b"),
                self.remote.local_addr().unwrap(),
                false,
                PendingProbePurpose::ConnectivityCheck,
                Some(TOKEN),
                true,
                None,
            )
            .await
            .unwrap()
    }

    async fn assert_winner(&self) {
        let state = self.udp.socket_state.lock().await;
        assert_eq!(
            state.affinity.get("peer-b").unwrap().socket_index,
            self.indices[0]
        );
        assert!(state.dynamic.contains_key(&self.indices[0]));
        assert!(!state.dynamic.contains_key(&self.indices[1]));
        drop(state);
        assert_eq!(
            self.peers.hard_hard_winner_for_token("peer-b", TOKEN).await,
            Some(self.indices[0])
        );
    }

    async fn cleanup(self) {
        self.udp
            .clear_hard_hard_pending_probes_for_token("peer-b", TOKEN, None)
            .await;
        self.udp.clear_pending_probes_for_peer("peer-b").await;
        self.udp
            .detach_all_dynamic_punch_sockets("winner_regression_cleanup")
            .await;
    }
}

#[path = "hard_hard_pair.rs"]
mod pair_nomination;

#[tokio::test]
async fn hard_hard_token_cleanup_drops_only_detached_socket_pending_before_drain() {
    let _serial = crate::tests::HARD_HARD_E2E_SERIAL.acquire().await.unwrap();
    let fixture = WinnerFixture::new().await;
    let kept = fixture.send(0).await;
    let discarded = fixture.send(1).await;
    let reader = fixture.udp.socket_state.lock().await.dynamic[&fixture.indices[1]]
        .reader
        .abort_handle();
    timeout(
        Duration::from_millis(500),
        fixture.udp.detach_hard_hard_sockets_for_token(
            "peer-b",
            TOKEN,
            Some(fixture.indices[0]),
            "token_cleanup_regression",
        ),
    )
    .await
    .expect("a removed HH socket cannot use its ACK; cleanup must not spend its two-second grace");
    let pending = fixture.udp.pending_probes.lock().await;
    assert!(pending.contains_key(&kept.nonce));
    assert!(!pending.contains_key(&discarded.nonce));
    drop(pending);
    let bindings = fixture.udp.hard_hard_probe_bindings.lock().await;
    assert_eq!(bindings.get(&kept.nonce).map(String::as_str), Some(TOKEN));
    assert!(!bindings.contains_key(&discarded.nonce));
    drop(bindings);
    assert_eq!(fixture.udp.dynamic_socket_count().await, 1);
    tokio::task::yield_now().await;
    assert!(reader.is_finished());
    fixture.cleanup().await;
}

// Real loopback I/O must use the real clock: a paused Tokio clock can jump
// directly to the timeout before the OS reports socket readiness. The held
// loser lease, not a timer race, establishes the blocking condition here.
#[tokio::test]
async fn hard_hard_winner_ack_and_validation_do_not_wait_for_loser_pending_or_lease() {
    let _serial = crate::tests::HARD_HARD_E2E_SERIAL.acquire().await.unwrap();
    let fixture = WinnerFixture::new().await;
    let kept = fixture.send(0).await;
    let cancelled = fixture.send(1).await;
    let (_, _, lease) = fixture
        .udp
        .resolve_dynamic_socket_index_for_send("peer-b", fixture.indices[1])
        .await
        .unwrap();
    let loser_reader = fixture.udp.socket_state.lock().await.dynamic[&fixture.indices[1]]
        .reader
        .abort_handle();
    let key = fixture.peers.probe_key_for_peer("peer-b").await.unwrap();
    let (punch, nonce) = build_authenticated_punch_packet("peer-b", "peer-a", 0, &key);
    let started = tokio::time::Instant::now();
    fixture
        .remote
        .send_to(&punch, fixture.sockets[0].local_addr().unwrap())
        .await
        .unwrap();
    timeout(Duration::from_millis(250), async {
        let mut bytes = [0; 2048];
        loop {
            let (size, source) = fixture.remote.recv_from(&mut bytes).await.unwrap();
            if let Some(packet) = decode_authenticated_punch_packet(&bytes[..size], &key) {
                if packet.kind == PunchPacketKind::Ack && packet.nonce == nonce {
                    assert_eq!(source, fixture.sockets[0].local_addr().unwrap());
                    break;
                }
            }
        }
        fixture.validation.notified().await;
        // Validation workers need this same epoch gate; the inbound winner
        // transaction must have released it without waiting for our held lease.
        let _epoch = fixture.udp.network_epoch_gate.lock().await;
    })
    .await
    .expect("winner ACK and validation must precede the loser drain grace");
    assert!(started.elapsed() < DYNAMIC_SOCKET_LEASE_DRAIN_TIMEOUT);
    fixture.assert_winner().await;
    let pending = fixture.udp.pending_probes.lock().await;
    assert!(
        pending.contains_key(&kept.nonce),
        "winner pending probe must survive"
    );
    assert!(!pending.contains_key(&cancelled.nonce));
    drop(pending);
    assert!(!fixture
        .udp
        .hard_hard_probe_bindings
        .lock()
        .await
        .contains_key(&cancelled.nonce));
    tokio::task::yield_now().await;
    assert!(
        loser_reader.is_finished(),
        "revoked reader must stop even while a send lease exists"
    );
    drop(lease);
    fixture.cleanup().await;
}

#[tokio::test]
async fn hard_hard_winner_revocation_fences_a_concurrent_loser_send_and_late_ack() {
    let _serial = crate::tests::HARD_HARD_E2E_SERIAL.acquire().await.unwrap();
    let fixture = WinnerFixture::new().await;
    let (gate, gate_guard) = install_probe_post_send_gate_for_test();
    let sending = tokio::spawn({
        let udp = fixture.udp.clone();
        let socket = fixture.sockets[1].clone();
        let index = fixture.indices[1];
        let endpoint = fixture.remote.local_addr().unwrap();
        async move {
            udp.send_probe_on_socket_result_with_hard_hard_token_classified(
                index,
                socket,
                Some("peer-b"),
                endpoint,
                false,
                PendingProbePurpose::ConnectivityCheck,
                Some(TOKEN),
                true,
                None,
            )
            .await
        }
    });
    gate.reached.notified().await;
    assert!(
        fixture
            .udp
            .promote_hard_hard_winner_for_test("peer-b", TOKEN, fixture.indices[0], 0)
            .await
    );
    assert!(
        !sending.is_finished(),
        "send must still own its handoff lease"
    );
    fixture.assert_winner().await;
    drop(gate_guard);
    let sent = sending.await.unwrap().unwrap();
    assert!(!fixture
        .udp
        .pending_probes
        .lock()
        .await
        .contains_key(&sent.nonce));
    let rejected = fixture
        .udp
        .send_probe_on_socket_result_with_hard_hard_token_classified(
            fixture.indices[1],
            fixture.sockets[1].clone(),
            Some("peer-b"),
            fixture.remote.local_addr().unwrap(),
            false,
            PendingProbePurpose::ConnectivityCheck,
            Some(TOKEN),
            true,
            None,
        )
        .await
        .unwrap_err();
    assert_eq!(rejected.kind, ProbeSendFailureKind::SocketUnavailable);
    assert!(fixture
        .udp
        .resolve_dynamic_socket_index_for_send("peer-b", fixture.indices[1])
        .await
        .is_none());
    // Route a delayed loser ACK to the surviving socket: absence of its exact
    // pending transaction must prevent even this authenticated packet adopting
    // a different affinity or reviving a removed dynamic entry.
    let key = fixture.peers.probe_key_for_peer("peer-b").await.unwrap();
    let ack = build_authenticated_punch_ack(sent.nonce, "peer-b", "peer-a", 0, &key);
    fixture
        .remote
        .send_to(&ack, fixture.sockets[0].local_addr().unwrap())
        .await
        .unwrap();
    timeout(Duration::from_millis(250), async {
        loop {
            if fixture
                .udp
                .probe_rx_snapshot()
                .await
                .authenticated_probe_acks_unmatched
                > 0
            {
                break;
            }
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
    })
    .await
    .unwrap();
    fixture.assert_winner().await;
    fixture.cleanup().await;
}

#[tokio::test]
async fn hard_hard_winner_cancelled_after_commit_does_not_leak_loser_reader_or_pending() {
    let _serial = crate::tests::HARD_HARD_E2E_SERIAL.acquire().await.unwrap();
    let fixture = WinnerFixture::new().await;
    let sent = fixture.send(1).await;
    let loser_reader = fixture.udp.socket_state.lock().await.dynamic[&fixture.indices[1]]
        .reader
        .abort_handle();
    // Promotion now completes even with the diagnostic writer held. Cancel
    // the receiving caller at its next await while it still owns the epoch.
    // Reader shutdown and exact pending cleanup must already have happened;
    // neither needs a detached cleanup task or diagnostic write to finish.
    let writer = fixture.peers.hold_connections_writer_for_test().await;
    let committed = std::cell::Cell::new(false);
    let mut promotion = Box::pin(async {
        let epoch_guard = fixture.udp.network_epoch_gate.lock().await;
        assert!(
            fixture
                .udp
                .promote_hard_hard_winner_in_epoch(
                    &epoch_guard,
                    "peer-b",
                    TOKEN,
                    fixture.indices[0],
                    0,
                )
                .await
        );
        committed.set(true);
        std::future::pending::<()>().await;
        drop(epoch_guard);
    });
    std::future::poll_fn(|cx| {
        assert!(std::future::Future::poll(promotion.as_mut(), cx).is_pending());
        std::task::Poll::Ready(())
    })
    .await;
    assert!(
        committed.get(),
        "the only suspension must follow the production winner transaction"
    );
    assert!(fixture.udp.network_epoch_gate.try_lock().is_err());
    fixture.assert_winner().await;
    assert!(!fixture
        .udp
        .pending_probes
        .lock()
        .await
        .contains_key(&sent.nonce));
    assert!(!fixture
        .udp
        .hard_hard_probe_bindings
        .lock()
        .await
        .contains_key(&sent.nonce));
    drop(promotion);
    drop(writer);
    tokio::task::yield_now().await;
    assert!(loser_reader.is_finished());
    assert!(fixture.udp.network_epoch_gate.try_lock().is_ok());
    fixture.assert_winner().await;
    fixture.cleanup().await;
}

/// A topology model around the real manager + UDP winner transaction, not a
/// successful end-to-end traversal regression. Strict APDM/APDF can have two
/// viable pairs, A0<->B0 and A1<->B1, while the cross pairs are filtered. The
/// first case captures the current missing distributed nomination contract;
/// the second states the acceptance condition for a future nomination change.
/// No packet-authentication bypass is used by production: the test promotion
/// helper represents a packet already authenticated by the inbound caller.
#[tokio::test]
async fn hard_hard_sticky_winner_model_requires_shared_pair_nomination() {
    let _serial = crate::tests::HARD_HARD_E2E_SERIAL.acquire().await.unwrap();
    for (right_selected, expected_surviving_pairs) in [(1, 0), (0, 1)] {
        let left = WinnerFixture::with_role(true).await;
        let right = WinnerFixture::with_role(false).await;
        let strict_pairs = [
            (left.indices[0], right.indices[0]),
            (left.indices[1], right.indices[1]),
        ];
        // Before either first authenticated observation is committed, both
        // endpoint pairs still have live exact-socket owners.
        for (left_index, right_index) in strict_pairs {
            assert!(left
                .udp
                .resolve_dynamic_socket_index_for_send("peer-b", left_index)
                .await
                .is_some());
            assert!(right
                .udp
                .resolve_dynamic_socket_index_for_send("peer-b", right_index)
                .await
                .is_some());
        }
        assert!(
            left.udp
                .promote_hard_hard_winner_for_test("peer-b", TOKEN, left.indices[0], 0)
                .await
        );
        assert!(
            right
                .udp
                .promote_hard_hard_winner_for_test(
                    "peer-b",
                    TOKEN,
                    right.indices[right_selected],
                    0
                )
                .await
        );
        let mut surviving_pairs = 0;
        for (left_index, right_index) in strict_pairs {
            let left_live = left
                .udp
                .resolve_dynamic_socket_index_for_send("peer-b", left_index)
                .await
                .is_some();
            let right_live = right
                .udp
                .resolve_dynamic_socket_index_for_send("peer-b", right_index)
                .await
                .is_some();
            surviving_pairs += usize::from(left_live && right_live);
        }
        assert_eq!(surviving_pairs, expected_surviving_pairs);
        if right_selected == 1 {
            // Delayed evidence for either original viable pair cannot repair
            // opposite sticky winners: the required local socket was revoked.
            assert!(
                !left
                    .udp
                    .promote_hard_hard_winner_for_test("peer-b", TOKEN, left.indices[1], 0)
                    .await
            );
            assert!(
                !right
                    .udp
                    .promote_hard_hard_winner_for_test("peer-b", TOKEN, right.indices[0], 0)
                    .await
            );
        }
        assert!(!left.peers.is_direct_sync("peer-b"));
        assert!(!right.peers.is_direct_sync("peer-b"));
        left.cleanup().await;
        right.cleanup().await;
    }
}

// The measurement result is committed before its coordinator can publish the
// token. Ordinary workers must not consume any mapping in that handoff gap.
#[tokio::test]
async fn hard_hard_reservation_fences_the_commit_to_token_handoff() {
    let fixture = WinnerFixture::new().await;
    let (index, socket) = fixture.udp.bind_fresh_punch_socket().await.unwrap();
    let guard = fixture
        .udp
        .attach_dynamic_punch_socket("peer-b", index, socket.clone(), 0, 3, None)
        .await
        .unwrap();
    assert!(fixture.udp.reserve_hard_hard_socket("peer-b", index).await);
    assert!(guard
        .commit_and_pin(&fixture.udp, "peer-b", index, 0, 3)
        .await
        .committed());
    assert!(guard.finalize().await);
    assert_eq!(fixture.udp.hard_hard_socket_token(index).await, None);
    assert!(fixture.udp.socket_for_peer(Some("peer-b")).await.is_none());
    assert!(fixture
        .udp
        .resolve_dynamic_socket_for_send("peer-b")
        .await
        .is_none());
    assert!(fixture
        .udp
        .resolve_send_socket_with_lease("peer-b")
        .await
        .is_none());
    // Resolving ordinary traffic must not erase the reserved affinity.
    assert_eq!(
        fixture.udp.dynamic_socket_index_for_peer("peer-b").await,
        Some(index)
    );
    assert!(fixture
        .udp
        .resolve_dynamic_socket_index_for_send("peer-b", index)
        .await
        .is_some());
    let endpoint = fixture.remote.local_addr().unwrap();
    for token in [None, Some(TOKEN)] {
        let rejected = fixture
            .udp
            .send_probe_on_socket_result_with_hard_hard_token_classified(
                index,
                socket.clone(),
                Some("peer-b"),
                endpoint,
                false,
                PendingProbePurpose::ConnectivityCheck,
                token,
                true,
                None,
            )
            .await
            .unwrap_err();
        assert_eq!(rejected.kind, ProbeSendFailureKind::SocketRevoked);
    }
    let packet = EncryptedPeerPacket {
        room_authorization: None,
        peer_id: "peer-b".into(),
        dst_ip: "10.20.0.2".into(),
        wire_bytes: vec![0; 85],
        is_business: false,
    };
    assert!(fixture.udp.send_packet_to(&packet, endpoint).await.is_err());
    assert!(fixture
        .udp
        .send_encrypted_packet_on_socket(&socket, index, &packet, endpoint)
        .await
        .is_err());
    assert!(fixture.udp.pending_probes.lock().await.is_empty());
    let mut bytes = [0; 2048];
    assert_eq!(
        fixture.remote.try_recv_from(&mut bytes).unwrap_err().kind(),
        std::io::ErrorKind::WouldBlock
    );
    assert!(
        fixture
            .udp
            .tag_hard_hard_socket("peer-b", index, TOKEN)
            .await
    );
    let sent = fixture
        .udp
        .send_probe_on_socket_result_with_hard_hard_token_classified(
            index,
            socket.clone(),
            Some("peer-b"),
            endpoint,
            false,
            PendingProbePurpose::ConnectivityCheck,
            Some(TOKEN),
            true,
            None,
        )
        .await
        .unwrap();
    assert_eq!(sent.socket_index, index);
    let (_, source) = timeout(
        Duration::from_millis(250),
        fixture.remote.recv_from(&mut bytes),
    )
    .await
    .unwrap()
    .unwrap();
    assert_eq!(source, socket.local_addr().unwrap());
    fixture.cleanup().await;
}

#[tokio::test]
async fn hard_hard_reservation_allows_only_owned_checks_until_matching_authenticated_ack() {
    let fixture = WinnerFixture::new().await;
    let endpoint = fixture.remote.local_addr().unwrap();
    for (purpose, token) in [
        (PendingProbePurpose::ConnectivityCheck, None),
        (PendingProbePurpose::ConnectivityCheck, Some("other-token")),
        (PendingProbePurpose::ConsentCheck, Some(TOKEN)),
        (PendingProbePurpose::RelayBackoffHeartbeat, Some(TOKEN)),
    ] {
        let rejected = fixture
            .udp
            .send_probe_on_socket_result_with_hard_hard_token_classified(
                fixture.indices[0],
                fixture.sockets[0].clone(),
                Some("peer-b"),
                endpoint,
                false,
                purpose,
                token,
                true,
                None,
            )
            .await
            .unwrap_err();
        assert_eq!(rejected.kind, ProbeSendFailureKind::SocketRevoked);
    }
    assert!(fixture.udp.socket_for_peer(Some("peer-b")).await.is_none());
    assert!(fixture
        .udp
        .resolve_send_socket_with_lease("peer-b")
        .await
        .is_none());
    assert!(fixture.udp.pending_probes.lock().await.is_empty());
    let mut bytes = [0; 2048];
    assert_eq!(
        fixture.remote.try_recv_from(&mut bytes).unwrap_err().kind(),
        std::io::ErrorKind::WouldBlock
    );
    let sent = fixture.send(0).await;
    let (_, source) = timeout(
        Duration::from_millis(250),
        fixture.remote.recv_from(&mut bytes),
    )
    .await
    .unwrap()
    .unwrap();
    assert_eq!(source, fixture.sockets[0].local_addr().unwrap());
    for _ in 1..sent.datagrams_sent {
        timeout(
            Duration::from_millis(250),
            fixture.remote.recv_from(&mut bytes),
        )
        .await
        .unwrap()
        .unwrap();
    }
    // These arrive before the authenticated ACK on the same receive queue.
    // Neither an unsolicited legacy punch nor a correlated legacy ACK may
    // consume the reservation or count as authentication.
    fixture
        .remote
        .send_to(&build_punch_packet(), source)
        .await
        .unwrap();
    fixture
        .remote
        .send_to(&build_punch_ack(sent.nonce), source)
        .await
        .unwrap();
    let key = fixture.peers.probe_key_for_peer("peer-b").await.unwrap();
    let ack = build_authenticated_punch_ack(sent.nonce, "peer-b", "peer-a", 0, &key);
    fixture.remote.send_to(&ack, source).await.unwrap();
    timeout(Duration::from_millis(250), fixture.validation.notified())
        .await
        .unwrap();
    fixture.assert_winner().await;
    assert_eq!(
        fixture.remote.try_recv_from(&mut bytes).unwrap_err().kind(),
        std::io::ErrorKind::WouldBlock
    );
    assert_eq!(
        fixture.udp.socket_for_peer(Some("peer-b")).await.unwrap().0,
        fixture.indices[0]
    );
    assert_eq!(
        fixture
            .udp
            .resolve_send_socket_with_lease("peer-b")
            .await
            .unwrap()
            .0,
        fixture.indices[0]
    );
    let packet = EncryptedPeerPacket {
        room_authorization: None,
        peer_id: "peer-b".into(),
        dst_ip: "10.20.0.2".into(),
        wire_bytes: vec![0; 85],
        is_business: false,
    };
    assert_eq!(
        fixture.udp.send_packet_to(&packet, endpoint).await.unwrap(),
        85
    );
    timeout(Duration::from_millis(250), async {
        loop {
            let (size, source) = fixture.remote.recv_from(&mut bytes).await.unwrap();
            if size == 85 {
                assert_eq!(source, fixture.sockets[0].local_addr().unwrap());
                break;
            }
        }
    })
    .await
    .unwrap();
    fixture.cleanup().await;
}

#[tokio::test]
async fn hard_hard_reservation_preserves_authenticated_detached_receive_arc_handoff() {
    let fixture = WinnerFixture::new().await;
    assert!(
        fixture
            .udp
            .promote_hard_hard_winner_for_test("peer-b", TOKEN, fixture.indices[0], 0,)
            .await
    );
    let endpoint = fixture.remote.local_addr().unwrap();
    let packet = EncryptedPeerPacket {
        room_authorization: None,
        peer_id: "peer-b".into(),
        dst_ip: "10.20.0.2".into(),
        wire_bytes: vec![4; 85],
        is_business: false,
    };
    // While an entry exists its exact identity remains authoritative, even
    // after authentication. A different socket cannot borrow its permission.
    let wrong_socket = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
    assert!(fixture
        .udp
        .send_encrypted_packet_on_socket(&wrong_socket, fixture.indices[0], &packet, endpoint,)
        .await
        .is_err());
    let mut wrong_peer = packet.clone();
    wrong_peer.peer_id = "other-peer".into();
    assert!(fixture
        .udp
        .send_encrypted_packet_on_socket(
            &fixture.sockets[0],
            fixture.indices[0],
            &wrong_peer,
            endpoint,
        )
        .await
        .is_err());
    fixture
        .udp
        .detach_dynamic_socket_by_index(fixture.indices[0], "received_arc_handoff")
        .await;
    assert!(fixture
        .udp
        .resolve_dynamic_socket_index_for_send("peer-b", fixture.indices[0])
        .await
        .is_none());
    // A validated inbound envelope already retains this exact Arc; completing
    // its reply must neither re-resolve a different socket nor recreate state.
    assert_eq!(
        fixture
            .udp
            .send_encrypted_packet_on_socket(
                &fixture.sockets[0],
                fixture.indices[0],
                &packet,
                endpoint,
            )
            .await
            .unwrap(),
        packet.wire_bytes.len()
    );
    let mut bytes = [0; 2048];
    let (size, source) = timeout(Duration::from_secs(1), fixture.remote.recv_from(&mut bytes))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(source, fixture.sockets[0].local_addr().unwrap());
    assert_eq!(&bytes[..size], packet.wire_bytes.as_slice());
    assert!(fixture
        .udp
        .resolve_dynamic_socket_index_for_send("peer-b", fixture.indices[0])
        .await
        .is_none());
    fixture.cleanup().await;
}
