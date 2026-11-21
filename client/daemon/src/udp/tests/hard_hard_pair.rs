use super::*;
use crate::peer::{DirectCommitHooks, HardHardPairEvidence, HardHardPairKey};

fn pair(fixture: &WinnerFixture, position: usize, remote: SocketAddr) -> HardHardPairKey {
    HardHardPairKey {
        socket_index: fixture.indices[position],
        local_endpoint: fixture.sockets[position].local_addr().unwrap(),
        remote_endpoint: remote,
    }
}

async fn observe(
    fixture: &WinnerFixture,
    pair: &HardHardPairKey,
    evidence: HardHardPairEvidence,
) -> bool {
    fixture
        .peers
        .hard_hard_pair_observe("peer-b", TOKEN, pair.clone(), evidence)
        .await
}

async fn confirmed(fixture: &WinnerFixture) -> HardHardValidationScope {
    let pair = pair(fixture, 0, fixture.remote.local_addr().unwrap());
    assert!(observe(fixture, &pair, HardHardPairEvidence::ConnectivityAck).await);
    assert!(observe(fixture, &pair, HardHardPairEvidence::NominationAck).await);
    fixture
        .udp
        .hard_hard_validation_scope("peer-b", pair.socket_index, pair.remote_endpoint)
        .await
        .unwrap()
        .unwrap()
}

#[tokio::test]
async fn selected_responder_check_alone_can_spend_confirmation_tail() {
    use crate::peer::{HardHardPairSendPhase, RecoveryProbePurpose};
    let _serial = crate::tests::HARD_HARD_E2E_SERIAL.acquire().await.unwrap();
    let fixture = WinnerFixture::with_protocol(false, true).await;
    let selected = pair(&fixture, 0, fixture.remote.local_addr().unwrap());
    assert!(observe(&fixture, &selected, HardHardPairEvidence::Observed).await);
    let (_, purpose) = fixture
        .peers
        .hard_hard_pair_send_admission(
            "peer-b",
            TOKEN,
            &selected,
            HardHardPairSendPhase::CandidateCheck,
        )
        .await
        .unwrap();
    assert_eq!(purpose, RecoveryProbePurpose::HardHardTriggered);
    assert!(purpose.confirmation_credit_reserve() > 0);
    assert!(fixture
        .peers
        .hard_hard_pair_send_admission(
            "peer-b",
            TOKEN,
            &selected,
            HardHardPairSendPhase::SelectedCheck,
        )
        .await
        .is_none());
    assert!(observe(&fixture, &selected, HardHardPairEvidence::NominationRequest).await);
    let (_, purpose) = fixture
        .peers
        .hard_hard_pair_send_admission(
            "peer-b",
            TOKEN,
            &selected,
            HardHardPairSendPhase::SelectedCheck,
        )
        .await
        .unwrap();
    assert_eq!(purpose, RecoveryProbePurpose::HardHardSelectedCheck);
    assert_eq!(purpose.confirmation_credit_reserve(), 0);
    assert_eq!(purpose.confirmation_short_window_reserve(), 0);
    let other = pair(&fixture, 1, fixture.remote.local_addr().unwrap());
    for phase in [
        HardHardPairSendPhase::CandidateCheck,
        HardHardPairSendPhase::Nomination,
    ] {
        assert!(fixture
            .peers
            .hard_hard_pair_send_admission("peer-b", TOKEN, &selected, phase)
            .await
            .is_none());
    }
    assert!(fixture
        .peers
        .hard_hard_pair_send_admission(
            "peer-b",
            TOKEN,
            &other,
            HardHardPairSendPhase::SelectedCheck,
        )
        .await
        .is_none());
    fixture.cleanup().await;
}

#[tokio::test]
async fn hh2_validation_merges_and_replacement_owners_share_actual_request_budget() {
    let _serial = crate::tests::HARD_HARD_E2E_SERIAL.acquire().await.unwrap();
    let fixture = WinnerFixture::with_protocol(true, true).await;
    let scope = confirmed(&fixture).await;
    let DirectValidationSessionStart::Spawn(mut lease) = fixture
        .udp
        .begin_or_merge_direct_validation("peer-b", scope.pair.remote_endpoint, scope.generation)
        .await
    else {
        panic!("first validation owner");
    };
    let work = lease.hard_hard.clone().unwrap();
    for _ in 0..20 {
        assert!(matches!(
            fixture
                .udp
                .begin_or_merge_direct_validation(
                    "peer-b",
                    scope.pair.remote_endpoint,
                    scope.generation,
                )
                .await,
            DirectValidationSessionStart::Merged
        ));
    }
    assert!(
        !lease.target_rx.has_changed().unwrap(),
        "identical merges do not bypass request delay"
    );
    let packet = EncryptedPeerPacket {
        room_authorization: None,
        peer_id: "peer-b".into(),
        dst_ip: "10.20.0.2".into(),
        wire_bytes: vec![0; 85],
        is_business: false,
    };
    // An ACK response is not a Request and consumes none of its allowance.
    fixture
        .udp
        .send_direct_validation_packet_on_socket(
            &fixture.sockets[0],
            scope.pair.socket_index,
            &packet,
            scope.pair.remote_endpoint,
        )
        .await
        .unwrap();
    let limit = 16 * crate::DIRECT_VALIDATION_REQUEST_DELAYS.len();
    for request in 0..limit {
        fixture
            .udp
            .send_direct_validation_request_on_socket(
                &fixture.sockets[0],
                scope.pair.socket_index,
                &packet,
                scope.pair.remote_endpoint,
                Some(&scope),
            )
            .await
            .unwrap();
        if request + 1 < limit && (request + 1) % crate::DIRECT_VALIDATION_REQUEST_DELAYS.len() == 0
        {
            // Model an owner ending after its last ACK could not commit. A new
            // owner may retry the same live pair, but never receives fresh HH credits.
            fixture
                .udp
                .finish_direct_validation_session("peer-b", lease.owner_token)
                .await;
            fixture
                .peers
                .hard_hard_validation_completed(
                    "peer-b",
                    &scope,
                    DirectValidationCompletion::OwnerFinished,
                )
                .await;
            let DirectValidationSessionStart::Spawn(replacement) = fixture
                .udp
                .begin_or_merge_direct_validation(
                    "peer-b",
                    scope.pair.remote_endpoint,
                    scope.generation,
                )
                .await
            else {
                panic!("replacement validation owner within original deadline");
            };
            assert_ne!(replacement.owner_token, lease.owner_token);
            assert_eq!(replacement.hard_hard.as_ref(), Some(&work));
            lease = replacement;
        }
    }
    assert!(fixture
        .udp
        .send_direct_validation_request_on_socket(
            &fixture.sockets[0],
            scope.pair.socket_index,
            &packet,
            scope.pair.remote_endpoint,
            Some(&scope)
        )
        .await
        .is_err());
    assert!(fixture
        .peers
        .hard_hard_pair_next_action("peer-b", TOKEN, true)
        .await
        .is_none());
    fixture.cleanup().await;
}

#[tokio::test]
async fn hh2_validation_completion_cannot_renew_deadline_or_old_scope() {
    let _serial = crate::tests::HARD_HARD_E2E_SERIAL.acquire().await.unwrap();
    let fixture = WinnerFixture::with_protocol(true, true).await;
    let scope = confirmed(&fixture).await;
    let DirectValidationSessionStart::Spawn(lease) = fixture
        .udp
        .begin_or_merge_direct_validation("peer-b", scope.pair.remote_endpoint, scope.generation)
        .await
    else {
        panic!("validation owner");
    };
    let mut stale = scope.clone();
    stale.token.push_str("-retired");
    assert!(fixture
        .peers
        .hard_hard_validation_deadline("peer-b", &stale)
        .await
        .is_none());
    let deadline = lease.hard_hard.as_ref().unwrap().deadline;
    tokio::time::pause();
    tokio::time::advance(deadline - tokio::time::Instant::now() + Duration::from_millis(1)).await;
    fixture
        .udp
        .finish_direct_validation_session("peer-b", lease.owner_token)
        .await;
    fixture
        .peers
        .hard_hard_validation_completed(
            "peer-b",
            &scope,
            DirectValidationCompletion::DeadlineExpired,
        )
        .await;
    assert!(fixture
        .peers
        .hard_hard_validation_deadline("peer-b", &scope)
        .await
        .is_none());
    assert!(matches!(
        fixture
            .udp
            .begin_or_merge_direct_validation(
                "peer-b",
                scope.pair.remote_endpoint,
                scope.generation,
            )
            .await,
        DirectValidationSessionStart::IgnoredInactive
    ));
    tokio::time::resume();
    fixture.cleanup().await;
}

#[tokio::test]
async fn cancelled_validation_finish_preserves_owner_until_reducer_cleanup_can_retry() {
    let _serial = crate::tests::HARD_HARD_E2E_SERIAL.acquire().await.unwrap();
    // Exercise cancellation while waiting for epoch, connection state, and
    // final expectation removal. No sleeps or timing-dependent contention.
    for blocked_stage in 0..3 {
        let fixture = WinnerFixture::with_protocol(true, true).await;
        let scope = confirmed(&fixture).await;
        let DirectValidationSessionStart::Spawn(lease) = fixture
            .udp
            .begin_or_merge_direct_validation(
                "peer-b",
                scope.pair.remote_endpoint,
                scope.generation,
            )
            .await
        else {
            panic!("first owner");
        };
        let target = *lease.target_rx.borrow();
        let identity = |owner, request| {
            crate::peer::DirectValidationIdentity::owned(
                crate::peer::PathEpoch::new(
                    target.generation,
                    target.peer_session_generation,
                    target.remote_candidate_epoch,
                ),
                owner,
                Some(request),
                Some(target.endpoint),
            )
        };
        fixture
            .udp
            .prepare_direct_validation_send("peer-b", identity(lease.owner_token, 19))
            .await
            .unwrap();
        let epoch_gate = fixture.peers.network_epoch_gate();
        let epoch = if blocked_stage == 0 {
            Some(epoch_gate.lock().await)
        } else {
            None
        };
        let connections = if blocked_stage == 1 {
            Some(fixture.peers.hold_connections_writer_for_test().await)
        } else {
            None
        };
        let expectations = if blocked_stage == 2 {
            Some(fixture.udp.direct_validation.expectations.lock().await)
        } else {
            None
        };
        let mut finish = Box::pin(
            fixture
                .udp
                .finish_direct_validation_session("peer-b", lease.owner_token),
        );
        std::future::poll_fn(|cx| {
            assert!(std::future::Future::poll(finish.as_mut(), cx).is_pending());
            std::task::Poll::Ready(())
        })
        .await;
        drop(finish); // The HH deadline/cancellation drops this same future.
        drop(expectations);
        drop(connections);
        drop(epoch);
        assert_eq!(
            fixture
                .udp
                .direct_validation_target("peer-b")
                .await
                .unwrap()
                .owner_token,
            lease.owner_token,
            "stage {blocked_stage}: interrupted cleanup must retain its only owner record"
        );
        assert!(
            fixture
                .udp
                .has_direct_validation_expectation("peer-b")
                .await
        );
        assert!(!lease.target_rx.borrow().cancelled);
        assert!(
            fixture
                .udp
                .finish_direct_validation_session("peer-b", lease.owner_token)
                .await
        );
        assert!(fixture
            .udp
            .direct_validation_target("peer-b")
            .await
            .is_none());
        assert!(
            !fixture
                .udp
                .has_direct_validation_expectation("peer-b")
                .await
        );
        assert!(lease.target_rx.borrow().cancelled);

        let DirectValidationSessionStart::Spawn(replacement) = fixture
            .udp
            .begin_or_merge_direct_validation(
                "peer-b",
                scope.pair.remote_endpoint,
                scope.generation,
            )
            .await
        else {
            panic!("replacement owner");
        };
        fixture
            .udp
            .prepare_direct_validation_send("peer-b", identity(replacement.owner_token, 20))
            .await
            .expect("a retired reducer owner must not reject replacement validation");
        let before =
            fixture.peers.hold_connections_writer_for_test().await["peer-b"].path_state_snapshot();
        assert!(
            !fixture
                .udp
                .finish_direct_validation_session("peer-b", lease.owner_token)
                .await
        );
        let after =
            fixture.peers.hold_connections_writer_for_test().await["peer-b"].path_state_snapshot();
        assert_eq!(
            before.state.direct, after.state.direct,
            "late old cleanup cannot clear the replacement reducer owner"
        );
        assert_eq!(
            fixture
                .udp
                .direct_validation_target("peer-b")
                .await
                .unwrap()
                .owner_token,
            replacement.owner_token
        );
        assert!(
            fixture
                .udp
                .has_direct_validation_expectation("peer-b")
                .await
        );
        fixture
            .udp
            .finish_direct_validation_session("peer-b", replacement.owner_token)
            .await;
        fixture.cleanup().await;
    }
}

#[tokio::test]
async fn hard_hard_hh2_crossed_checks_converge_only_after_one_nomination() {
    let _serial = crate::tests::HARD_HARD_E2E_SERIAL.acquire().await.unwrap();
    let controlling = WinnerFixture::with_protocol(true, true).await;
    let controlled = WinnerFixture::with_protocol(false, true).await;
    // The first checks succeed on opposite pairs. Only the controller may
    // freeze a choice; the controlled side's earlier ACK is only validity.
    let chosen_a = pair(&controlling, 0, controlled.sockets[1].local_addr().unwrap());
    let chosen_b = pair(&controlled, 1, controlling.sockets[0].local_addr().unwrap());
    let other_b = pair(&controlled, 0, controlling.sockets[1].local_addr().unwrap());
    assert!(observe(&controlled, &other_b, HardHardPairEvidence::ConnectivityAck).await);
    assert!(
        !controlled
            .peers
            .hard_hard_pair_is_prepared("peer-b", TOKEN)
            .await
    );
    assert!(
        observe(
            &controlling,
            &chosen_a,
            HardHardPairEvidence::ConnectivityAck
        )
        .await
    );
    assert!(
        observe(
            &controlled,
            &chosen_b,
            HardHardPairEvidence::NominationRequest
        )
        .await
    );
    assert_eq!(
        controlled
            .peers
            .hard_hard_pair_validation_target("peer-b")
            .await,
        Some(None)
    );
    // Lost nomination ACK: the same request is idempotent and a conflicting
    // nomination cannot switch the controlled side to its earlier valid pair.
    assert!(
        observe(
            &controlled,
            &chosen_b,
            HardHardPairEvidence::NominationRequest
        )
        .await
    );
    assert!(
        !observe(
            &controlled,
            &other_b,
            HardHardPairEvidence::NominationRequest
        )
        .await
    );
    assert!(!observe(&controlled, &chosen_b, HardHardPairEvidence::NominationAck).await);
    assert!(
        observe(
            &controlled,
            &chosen_b,
            HardHardPairEvidence::ConnectivityAck
        )
        .await
    );
    assert!(observe(&controlling, &chosen_a, HardHardPairEvidence::NominationAck).await);
    assert_eq!(
        controlled
            .peers
            .hard_hard_pair_validation_target("peer-b")
            .await,
        Some(Some((TOKEN.into(), chosen_b.clone())))
    );
    assert_eq!(
        controlling
            .peers
            .hard_hard_pair_validation_target("peer-b")
            .await,
        Some(Some((TOKEN.into(), chosen_a.clone())))
    );
    assert_eq!(
        controlling
            .peers
            .hard_hard_winner_for_token("peer-b", TOKEN)
            .await,
        None
    );
    assert_eq!(
        controlled
            .peers
            .hard_hard_winner_for_token("peer-b", TOKEN)
            .await,
        None
    );
    assert!(
        !controlled
            .udp
            .permits_ordinary_send_on_socket(
                "peer-b",
                chosen_b.socket_index,
                &controlled.sockets[1]
            )
            .await
    );
    controlling.cleanup().await;
    controlled.cleanup().await;
}

#[tokio::test]
async fn hard_hard_hh2_ack_requires_exact_tuple_and_preserves_session_diagnostics() {
    let _serial = crate::tests::HARD_HARD_E2E_SERIAL.acquire().await.unwrap();
    let fixture = WinnerFixture::with_protocol(true, true).await;
    assert!(
        fixture
            .peers
            .set_probe_session_id("peer-b", Some("hh2-probe-session".into()))
            .await
    );
    let sent = fixture.send(0).await;
    let key = crate::peer::hard_hard_scoped_probe_key(
        &fixture.peers.probe_key_for_peer("peer-b").await.unwrap(),
        TOKEN,
    );
    let wire = build_authenticated_punch_ack(sent.nonce, "peer-b", "peer-a", 0, &key);
    assert!(decode_authenticated_punch_packet(
        &wire,
        &crate::peer::hard_hard_scoped_probe_key(
            &fixture.peers.probe_key_for_peer("peer-b").await.unwrap(),
            "other-token"
        )
    )
    .is_none());
    let ack = decode_authenticated_punch_packet(&wire, &key).unwrap();
    let wrong = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let session = fixture
        .peers
        .peer_session_generation_sync("peer-b")
        .unwrap();
    fixture
        .udp
        .handle_hard_hard_pair_packet(
            "peer-b",
            TOKEN,
            &ack,
            &key,
            session,
            Some("hh2-probe-session"),
            fixture.indices[0],
            &fixture.sockets[0],
            wrong.local_addr().unwrap(),
        )
        .await;
    assert!(fixture
        .udp
        .pending_probes
        .lock()
        .await
        .contains_key(&sent.nonce));
    assert!(
        !fixture
            .peers
            .hard_hard_pair_is_prepared("peer-b", TOKEN)
            .await
    );
    fixture
        .udp
        .handle_hard_hard_pair_packet(
            "peer-b",
            TOKEN,
            &ack,
            &key,
            session,
            Some("hh2-probe-session"),
            fixture.indices[0],
            &fixture.sockets[0],
            fixture.remote.local_addr().unwrap(),
        )
        .await;
    assert!(!fixture
        .udp
        .pending_probes
        .lock()
        .await
        .contains_key(&sent.nonce));
    let stats = fixture
        .udp
        .probe_rx_snapshot_for_peer_session("peer-b", 0, Some("hh2-probe-session"))
        .await;
    assert_eq!(stats.probe_acks_received, 1);
    assert_eq!(
        fixture
            .udp
            .probe_rx_snapshot_for_peer_session("peer-b", 0, None)
            .await
            .probe_acks_received,
        0
    );
    // A connectivity ACK prepares a pair but cannot itself confirm nomination.
    assert_eq!(
        fixture
            .peers
            .hard_hard_pair_validation_target("peer-b")
            .await,
        Some(None)
    );
    fixture.cleanup().await;
}

#[tokio::test]
async fn hard_hard_hh2_retired_detached_arc_never_accepts_legacy_or_validation() {
    let _serial = crate::tests::HARD_HARD_E2E_SERIAL.acquire().await.unwrap();
    let fixture = WinnerFixture::with_protocol(true, true).await;
    let scope = confirmed(&fixture).await;
    let retained = fixture.sockets[0].clone();
    assert!(
        fixture
            .peers
            .hard_hard_retire_session("peer-b", "winner-cleanup-session", TOKEN)
            .await
    );
    fixture
        .udp
        .detach_hard_hard_sockets_for_token("peer-b", TOKEN, None, "hh2_retired_test")
        .await;
    assert!(
        retained.local_addr().is_ok(),
        "the exact Arc remains usable by the OS"
    );
    assert!(
        !fixture
            .udp
            .permits_legacy_punch_on_socket(fixture.indices[0])
            .await
    );
    assert!(
        !fixture
            .udp
            .permits_ordinary_send_on_socket("peer-b", fixture.indices[0], &retained)
            .await
    );
    assert!(
        !fixture
            .udp
            .hard_hard_validation_scope_is_current("peer-b", &scope)
            .await
    );
    assert!(
        fixture.udp.permits_legacy_punch_on_socket(0).await,
        "legacy primary compatibility is unchanged"
    );
    fixture.cleanup().await;
}

#[tokio::test]
async fn hard_hard_hh2_validation_syscall_rechecks_cancel_after_permission_snapshot() {
    let _serial = crate::tests::HARD_HARD_E2E_SERIAL.acquire().await.unwrap();
    let fixture = WinnerFixture::with_protocol(true, true).await;
    let scope = confirmed(&fixture).await;
    let cancellation = fixture
        .peers
        .hard_hard_session_by_token("peer-b", TOKEN)
        .await
        .unwrap()
        .cancellation;
    let gate = Arc::new(
        super::super::super::hard_hard_pair_validation::HardHardValidationSendGate::default(),
    );
    *fixture.udp.hh2_validation_send_gate.lock().await = Some(gate.clone());
    let packet = EncryptedPeerPacket {
        room_authorization: None,
        peer_id: "peer-b".into(),
        dst_ip: "10.20.0.2".into(),
        wire_bytes: vec![0; 85],
        is_business: false,
    };
    let udp = fixture.udp.clone();
    let socket = fixture.sockets[0].clone();
    let send = tokio::spawn(async move {
        udp.send_direct_validation_packet_on_socket(
            &socket,
            scope.pair.socket_index,
            &packet,
            scope.pair.remote_endpoint,
        )
        .await
    });
    timeout(Duration::from_secs(1), gate.reached.notified())
        .await
        .unwrap();
    cancellation.cancel_for_hard_hard_cleanup();
    gate.release.notify_one();
    let error = send.await.unwrap().unwrap_err();
    assert!(
        error.to_string().contains("hh2 validation socket revoked"),
        "{error}"
    );
    let mut bytes = [0; 128];
    assert_eq!(
        fixture.remote.try_recv_from(&mut bytes).unwrap_err().kind(),
        std::io::ErrorKind::WouldBlock
    );
    fixture.cleanup().await;
}

#[tokio::test]
async fn hard_hard_hh2_probe_ack_syscall_rechecks_exact_socket_and_cancellation() {
    let _serial = crate::tests::HARD_HARD_E2E_SERIAL.acquire().await.unwrap();
    let fixture = WinnerFixture::with_protocol(true, true).await;
    let scope = confirmed(&fixture).await;
    let wrong_socket = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
    let epoch = fixture.udp.network_epoch_gate.lock().await;
    assert!(fixture
        .udp
        .send_hh2_probe_ack(
            &epoch,
            "peer-b",
            TOKEN,
            &scope.pair,
            &wrong_socket,
            b"ack",
            false,
        )
        .await
        .is_err());
    drop(epoch);
    let cancellation = fixture
        .peers
        .hard_hard_session_by_token("peer-b", TOKEN)
        .await
        .unwrap()
        .cancellation;
    let gate = Arc::new(
        super::super::super::hard_hard_pair_validation::HardHardValidationSendGate::default(),
    );
    *fixture.udp.hh2_probe_ack_send_gate.lock().await = Some(gate.clone());
    // Prime OS readiness before freezing time. The explicit gate, not a
    // scheduler delay, establishes cancellation after permission capture.
    fixture.sockets[0].writable().await.unwrap();
    tokio::time::pause();
    let udp = fixture.udp.clone();
    let socket = fixture.sockets[0].clone();
    let send = tokio::spawn(async move {
        let epoch = udp.network_epoch_gate.lock().await;
        udp.send_hh2_probe_ack(&epoch, "peer-b", TOKEN, &scope.pair, &socket, b"ack", false)
            .await
    });
    gate.reached.notified().await;
    cancellation.cancel_for_hard_hard_cleanup();
    gate.release.notify_one();
    assert_eq!(
        send.await.unwrap().unwrap_err().kind(),
        std::io::ErrorKind::PermissionDenied
    );
    tokio::time::resume();
    let mut bytes = [0; 128];
    assert_eq!(
        fixture.remote.try_recv_from(&mut bytes).unwrap_err().kind(),
        std::io::ErrorKind::WouldBlock
    );
    fixture.cleanup().await;
}

#[tokio::test]
async fn hard_hard_hh2_probe_ack_syscall_rechecks_original_action_deadline() {
    let _serial = crate::tests::HARD_HARD_E2E_SERIAL.acquire().await.unwrap();
    let fixture = WinnerFixture::with_protocol(true, true).await;
    let scope = confirmed(&fixture).await;
    let deadline = fixture
        .peers
        .hard_hard_pair_send_deadline("peer-b", TOKEN, &scope.pair, false)
        .await
        .unwrap();
    let gate = Arc::new(
        super::super::super::hard_hard_pair_validation::HardHardValidationSendGate::default(),
    );
    *fixture.udp.hh2_probe_ack_send_gate.lock().await = Some(gate.clone());
    fixture.sockets[0].writable().await.unwrap();
    tokio::time::pause();
    tokio::time::advance((deadline - tokio::time::Instant::now()) - Duration::from_millis(1)).await;
    let udp = fixture.udp.clone();
    let socket = fixture.sockets[0].clone();
    let send = tokio::spawn(async move {
        let epoch = udp.network_epoch_gate.lock().await;
        udp.send_hh2_probe_ack(&epoch, "peer-b", TOKEN, &scope.pair, &socket, b"ack", false)
            .await
    });
    gate.reached.notified().await;
    // Exceed the original phase deadline while remaining inside the ACK's
    // separate 25ms lock/IO bound: rejection must happen at final handoff.
    tokio::time::advance(Duration::from_millis(2)).await;
    gate.release.notify_one();
    assert_eq!(
        send.await.unwrap().unwrap_err().kind(),
        std::io::ErrorKind::PermissionDenied
    );
    tokio::time::resume();
    let mut bytes = [0; 128];
    assert_eq!(
        fixture.remote.try_recv_from(&mut bytes).unwrap_err().kind(),
        std::io::ErrorKind::WouldBlock
    );
    fixture.cleanup().await;
}

#[tokio::test]
async fn hard_hard_hh2_prepare_bounds_scope_preflight_connection_contention() {
    let _serial = crate::tests::HARD_HARD_E2E_SERIAL.acquire().await.unwrap();
    let fixture = WinnerFixture::with_protocol(true, true).await;
    let scope = confirmed(&fixture).await;
    let epoch = fixture.udp.network_epoch_gate.lock().await;
    let connections = fixture.peers.hold_connections_writer_for_test().await;
    tokio::time::pause();
    {
        let deadline = tokio::time::Instant::now() + Duration::from_millis(100);
        let boundary = tokio::time::sleep_until(deadline);
        let prepare = fixture
            .udp
            .prepare_hh2_direct_commit(&epoch, "peer-b", Some(&scope));
        tokio::pin!(boundary, prepare);
        assert!(futures_util::poll!(prepare.as_mut()).is_pending());
        tokio::time::sleep_until(deadline - Duration::from_millis(1)).await;
        assert!(futures_util::poll!(prepare.as_mut()).is_pending());
        // Tokio rounds both deadlines to its millisecond timer tick. A
        // paused clock may therefore advance slightly beyond 100ms from a
        // fractional starting instant. Require completion at the same 100ms
        // timer boundary, without granting another timer tick or lock release.
        boundary.await;
        assert!(matches!(
            futures_util::poll!(prepare.as_mut()),
            std::task::Poll::Ready(Err(()))
        ));
    }
    drop(connections);
    drop(epoch);
    tokio::time::resume();
    assert!(!fixture.peers.is_direct_sync("peer-b"));
    assert!(
        matches!(
            fixture
                .peers
                .hard_hard_pair_next_action("peer-b", TOKEN, true)
                .await,
            Some(crate::peer::HardHardPairAction::Validate(_))
        ),
        "a cancelled commit preparation must not strand the selected pair as validated"
    );
    fixture.cleanup().await;
}

#[tokio::test]
async fn hard_hard_hh2_readiness_timeout_is_not_owner_revocation() {
    let _serial = crate::tests::HARD_HARD_E2E_SERIAL.acquire().await.unwrap();
    let fixture = WinnerFixture::with_protocol(true, true).await;
    let selected = pair(&fixture, 0, fixture.remote.local_addr().unwrap());
    assert!(observe(&fixture, &selected, HardHardPairEvidence::ConnectivityAck).await);
    fixture.sockets[0].writable().await.unwrap();
    let epoch = fixture.udp.network_epoch_gate.lock().await;
    tokio::time::pause();
    let error = fixture
        .udp
        .send_hh2_probe_datagram(
            selected.socket_index,
            &fixture.sockets[0],
            b"not-sent",
            "peer-b",
            selected.remote_endpoint,
            TOKEN,
            PendingProbePurpose::HardHardNomination,
            true,
        )
        .await
        .unwrap_err();
    assert_eq!(error.kind, ProbeSendFailureKind::PreHandoffTimeout);
    assert_eq!(error.physical_send_errors, 0);
    drop(epoch);
    tokio::time::resume();
    let mut bytes = [0; 128];
    assert_eq!(
        fixture.remote.try_recv_from(&mut bytes).unwrap_err().kind(),
        std::io::ErrorKind::WouldBlock
    );
    assert!(fixture
        .peers
        .hard_hard_pair_scope("peer-b", TOKEN)
        .await
        .is_some());
    fixture.cleanup().await;
}

#[tokio::test]
async fn hard_hard_hh2_classified_readiness_timeout_is_not_physical_send_error() {
    let _serial = crate::tests::HARD_HARD_E2E_SERIAL.acquire().await.unwrap();
    let fixture = WinnerFixture::with_protocol(true, true).await;
    let selected = pair(&fixture, 0, fixture.remote.local_addr().unwrap());
    assert!(observe(&fixture, &selected, HardHardPairEvidence::ConnectivityAck).await);
    fixture.sockets[0].writable().await.unwrap();
    let live = Arc::new(StdMutex::new(LiveBirthdayProgress::default()));
    let scope = fixture
        .peers
        .hard_hard_pair_scope("peer-b", TOKEN)
        .await
        .unwrap();
    let confirmation_before = scope.measurement.evidence.confirmation_snapshot();
    let failure = {
        // Stop registration at its pending-map lock, then queue an epoch
        // waiter. The FIFO epoch gate hands that waiter ownership when the
        // registration finishes, before the physical helper can reacquire it.
        let pending = fixture.udp.pending_probes.lock().await;
        let send = fixture
            .udp
            .send_probe_on_socket_result_with_hard_hard_token_classified(
                selected.socket_index,
                fixture.sockets[0].clone(),
                Some("peer-b"),
                selected.remote_endpoint,
                true,
                PendingProbePurpose::HardHardNomination,
                Some(TOKEN),
                true,
                Some(BirthdayLiveRecorder::new(live.clone())),
            );
        tokio::pin!(send);
        assert!(futures_util::poll!(send.as_mut()).is_pending());
        let epoch_waiter = fixture.udp.network_epoch_gate.lock();
        tokio::pin!(epoch_waiter);
        assert!(futures_util::poll!(epoch_waiter.as_mut()).is_pending());
        drop(pending);
        assert!(futures_util::poll!(send.as_mut()).is_pending());
        let epoch = epoch_waiter.await;
        assert_eq!(fixture.udp.pending_probes.lock().await.len(), 1);
        tokio::time::pause();
        let failure = send.await.unwrap_err();
        drop(epoch);
        tokio::time::resume();
        failure
    };
    let mut bytes = [0; 256];
    assert_eq!(
        fixture.remote.try_recv_from(&mut bytes).unwrap_err().kind(),
        std::io::ErrorKind::WouldBlock
    );
    let current = fixture
        .peers
        .hard_hard_pair_scope("peer-b", TOKEN)
        .await
        .expect("readiness contention must retain the valid owner");
    assert!(!current.cancellation.is_cancelled());
    assert_eq!(
        current.measurement.evidence.confirmation_snapshot(),
        confirmation_before
    );
    assert!(fixture.udp.pending_probes.lock().await.is_empty());
    assert!(fixture.udp.hard_hard_probe_bindings.lock().await.is_empty());
    assert_eq!(failure.physical_send_errors, 0);
    assert_eq!(failure.physical_send_error_bytes, 0);
    assert_eq!(failure.kind, ProbeSendFailureKind::PreHandoffTimeout);
    assert!(failure.retryable_not_sent());
    {
        let live = live.lock().unwrap();
        assert_eq!(live.counters.physical_datagrams_sent, 0);
        assert_eq!(live.counters.physical_send_errors, 0);
        assert_eq!(live.counters.physical_send_error_bytes, 0);
        assert!(live.first_send_at_ms.is_none());
    }
    fixture.cleanup().await;
}

#[tokio::test]
async fn hard_hard_hh2_classified_syscall_failure_keeps_physical_error() {
    let _serial = crate::tests::HARD_HARD_E2E_SERIAL.acquire().await.unwrap();
    let fixture = WinnerFixture::with_protocol(true, true).await;
    let selected = pair(&fixture, 0, fixture.remote.local_addr().unwrap());
    assert!(observe(&fixture, &selected, HardHardPairEvidence::ConnectivityAck).await);
    let _send_failures = fixture.udp.set_probe_send_failures_for_test([1]);
    let live = Arc::new(StdMutex::new(LiveBirthdayProgress::default()));
    let failure = fixture
        .udp
        .send_probe_on_socket_result_with_hard_hard_token_classified(
            selected.socket_index,
            fixture.sockets[0].clone(),
            Some("peer-b"),
            selected.remote_endpoint,
            true,
            PendingProbePurpose::HardHardNomination,
            Some(TOKEN),
            true,
            Some(BirthdayLiveRecorder::new(live.clone())),
        )
        .await
        .unwrap_err();
    assert_eq!(failure.kind, ProbeSendFailureKind::PhysicalSend);
    assert!(failure.retryable_not_sent());
    assert_eq!(failure.physical_send_errors, 1);
    assert!(failure.physical_send_error_bytes > 0);
    {
        let live = live.lock().unwrap();
        assert_eq!(live.counters.physical_datagrams_sent, 0);
        assert_eq!(live.counters.physical_send_errors, 1);
        assert_eq!(
            live.counters.physical_send_error_bytes,
            failure.physical_send_error_bytes
        );
        assert!(live.first_send_at_ms.is_none());
    }
    let mut bytes = [0; 256];
    assert_eq!(
        fixture.remote.try_recv_from(&mut bytes).unwrap_err().kind(),
        std::io::ErrorKind::WouldBlock
    );
    assert!(fixture
        .peers
        .hard_hard_pair_scope("peer-b", TOKEN)
        .await
        .is_some());
    fixture.cleanup().await;
}

#[tokio::test]
async fn hard_hard_hh2_typed_owner_rejection_does_not_claim_physical_send() {
    let _serial = crate::tests::HARD_HARD_E2E_SERIAL.acquire().await.unwrap();
    let fixture = WinnerFixture::with_protocol(true, true).await;
    let selected = pair(&fixture, 0, fixture.remote.local_addr().unwrap());
    assert!(observe(&fixture, &selected, HardHardPairEvidence::ConnectivityAck).await);
    let failure = fixture
        .udp
        .send_hh2_probe_datagram(
            selected.socket_index,
            &fixture.sockets[0],
            b"not-sent",
            "peer-b",
            selected.remote_endpoint,
            "superseded-token",
            PendingProbePurpose::HardHardNomination,
            true,
        )
        .await
        .unwrap_err();
    assert_eq!(failure.kind, ProbeSendFailureKind::SocketRevoked);
    assert!(!failure.retryable_not_sent());
    assert_eq!(failure.physical_send_errors, 0);
    assert_eq!(failure.physical_send_error_bytes, 0);
    let mut bytes = [0; 128];
    assert_eq!(
        fixture.remote.try_recv_from(&mut bytes).unwrap_err().kind(),
        std::io::ErrorKind::WouldBlock
    );
    assert!(fixture
        .peers
        .hard_hard_pair_scope("peer-b", TOKEN)
        .await
        .is_some());
    fixture.cleanup().await;
}

#[tokio::test]
async fn hard_hard_hh2_real_syscall_error_is_typed_as_physical_send() {
    let _serial = crate::tests::HARD_HARD_E2E_SERIAL.acquire().await.unwrap();
    let fixture = WinnerFixture::with_protocol(true, true).await;
    let selected = pair(&fixture, 0, fixture.remote.local_addr().unwrap());
    assert!(observe(&fixture, &selected, HardHardPairEvidence::ConnectivityAck).await);
    // This exceeds the IPv4 UDP payload maximum and reaches a real loopback
    // send syscall, with no failure hook or outbound interface changes.
    let oversized = vec![0; 65_536];
    let failure = fixture
        .udp
        .send_hh2_probe_datagram(
            selected.socket_index,
            &fixture.sockets[0],
            &oversized,
            "peer-b",
            selected.remote_endpoint,
            TOKEN,
            PendingProbePurpose::HardHardNomination,
            true,
        )
        .await
        .unwrap_err();
    assert_eq!(failure.kind, ProbeSendFailureKind::PhysicalSend);
    assert!(failure.retryable_not_sent());
    assert_eq!(failure.physical_send_errors, 1);
    assert_eq!(failure.physical_send_error_bytes, oversized.len() as u64);
    let mut bytes = [0; 128];
    assert_eq!(
        fixture.remote.try_recv_from(&mut bytes).unwrap_err().kind(),
        std::io::ErrorKind::WouldBlock
    );
    assert!(fixture
        .peers
        .hard_hard_pair_scope("peer-b", TOKEN)
        .await
        .is_some());
    fixture.cleanup().await;
}

struct MirrorCheckedCommit<'a> {
    inner: super::super::super::hard_hard_pair_commit::HardHardDirectCommit<'a>,
    fixture: &'a WinnerFixture,
    finished: bool,
}

impl DirectCommitHooks for MirrorCheckedCommit<'_> {
    fn is_current(&self) -> bool {
        self.inner.is_current()
    }
    fn committed(&mut self) {
        self.inner.committed();
        assert!(
            self.fixture.udp.socket_state.try_lock().is_err(),
            "cleanup must remain fenced inside the reducer closure"
        );
    }
    fn finish(&mut self) {
        assert!(
            self.fixture.peers.is_direct_sync("peer-b"),
            "Direct mirror must precede socket unlock"
        );
        assert!(self
            .fixture
            .peers
            .direct_commit_pair_snapshot_sync("peer-b")
            .is_some());
        assert!(self.fixture.udp.socket_state.try_lock().is_err());
        self.inner.finish();
        assert!(self.fixture.udp.socket_state.try_lock().is_ok());
        self.finished = true;
    }
}

#[tokio::test]
async fn hard_hard_hh2_direct_mirrors_precede_winner_unlock_and_stale_cleanup() {
    let _serial = crate::tests::HARD_HARD_E2E_SERIAL.acquire().await.unwrap();
    let fixture = WinnerFixture::with_protocol(true, true).await;
    let scope = confirmed(&fixture).await;
    let epoch = fixture.udp.network_epoch_gate.lock().await;
    assert!(
        fixture
            .peers
            .learn_authenticated_endpoint_in_epoch(&epoch, "peer-b", scope.pair.remote_endpoint)
            .await
    );
    fixture
        .peers
        .record_direct_probe_success_with_local_endpoint(
            "peer-b",
            scope.pair.remote_endpoint,
            Some(scope.pair.local_endpoint),
        )
        .await;
    let remote_epoch = fixture
        .peers
        .current_remote_candidate_epoch("peer-b")
        .await
        .unwrap();
    let inner = fixture
        .udp
        .prepare_hh2_direct_commit(&epoch, "peer-b", Some(&scope))
        .await
        .unwrap()
        .unwrap();
    let mut hooks = MirrorCheckedCommit {
        inner,
        fixture: &fixture,
        finished: false,
    };
    assert!(
        fixture
            .peers
            .record_direct_success_with_commit_hooks(
                &epoch,
                "peer-b",
                Some(scope.pair.remote_endpoint),
                scope.generation,
                Some(scope.pair.local_endpoint),
                Some(Duration::from_millis(1)),
                Some(remote_epoch),
                None,
                Some(&mut hooks)
            )
            .await
    );
    assert!(hooks.finished && hooks.inner.committed);
    drop(hooks);
    drop(epoch);
    fixture.assert_winner().await;
    let snapshot = fixture
        .peers
        .direct_commit_pair_snapshot_sync("peer-b")
        .unwrap();
    assert!(snapshot.path_revision.is_some());
    assert_eq!(snapshot.remote_endpoint, scope.pair.remote_endpoint);
    assert_eq!(snapshot.peer_session_generation, scope.peer_session);
    // Both pre-decrypt tuple admission and post-decrypt ordinary admission
    // use the synchronous exact projection even under connection contention.
    let connections = fixture.peers.hold_connections_writer_for_test().await;
    timeout(Duration::from_millis(100), async {
        assert!(
            fixture
                .udp
                .hh2_validation_pair_matches(
                    "peer-b",
                    scope.pair.socket_index,
                    scope.pair.remote_endpoint
                )
                .await
        );
        assert!(
            fixture
                .udp
                .permits_hh2_encrypted_ingress(
                    "peer-b",
                    scope.pair.socket_index,
                    scope.pair.remote_endpoint,
                    false
                )
                .await
        );
        let wrong_remote = "127.0.0.1:1".parse().unwrap();
        assert!(
            !fixture
                .udp
                .permits_hh2_encrypted_ingress(
                    "peer-b",
                    scope.pair.socket_index,
                    wrong_remote,
                    false
                )
                .await
        );
        let wrong_local = HardHardPairKey {
            local_endpoint: wrong_remote,
            ..scope.pair.clone()
        };
        assert!(!fixture.peers.hard_hard_committed_pair_is_current_sync(
            "peer-b",
            &wrong_local,
            scope.generation
        ));
    })
    .await
    .unwrap();
    drop(connections);
    // Model a cleanup descriptor that computed preserve=None before the ACK.
    assert!(
        fixture
            .peers
            .hard_hard_retire_session("peer-b", "winner-cleanup-session", TOKEN)
            .await
    );
    fixture
        .udp
        .detach_hard_hard_sockets_for_token("peer-b", TOKEN, None, "stale_discard_decision")
        .await;
    assert!(
        fixture
            .udp
            .permits_ordinary_send_on_socket("peer-b", scope.pair.socket_index, &fixture.sockets[0])
            .await
    );
    assert!(
        fixture
            .udp
            .hh2_validation_pair_matches(
                "peer-b",
                scope.pair.socket_index,
                scope.pair.remote_endpoint
            )
            .await
    );
    fixture.peers.remove_peer("peer-b").await;
    assert!(!fixture.peers.hard_hard_committed_pair_is_current_sync(
        "peer-b",
        &scope.pair,
        scope.generation
    ));
    fixture.cleanup().await;
}
