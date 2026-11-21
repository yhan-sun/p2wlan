// Actual original UDP cores. These fixtures stop at local receipt/decrypt;
// they grant no final ACK, current-owner or physical NIC/remote delivery credit.
use super::super::test_support::establish_sessions;
use super::*;
use crate::dataplane::DataPlane;
use crate::overlay_requests::{PhysicalInputQualification, PhysicalPublicationState};
use crate::request_carriage::test_probe::{HandoffArgumentPoint, RequestHandoffArgumentProbe};
use crate::request_carriage::test_support::{mint_input_request, InputRequestFixture};
use crate::request_carriage::test_support::{mint_routed_request, RoutedRequestFixture, PEER};
use crate::udp::UdpSendFence;

async fn direct_fixture(
    lan: bool,
) -> (
    RoutedRequestFixture,
    WireGuardTransport,
    UdpTransport,
    tokio::net::UdpSocket,
    p2pnet_wireguard::TransportSession,
) {
    direct_fixture_with_compatibility_commit(lan, true).await
}

async fn direct_fixture_with_compatibility_commit(
    lan: bool,
    compatibility_commit: bool,
) -> (
    RoutedRequestFixture,
    WireGuardTransport,
    UdpTransport,
    tokio::net::UdpSocket,
    p2pnet_wireguard::TransportSession,
) {
    let f = mint_routed_request().await;
    let receiver = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let endpoint = receiver.local_addr().unwrap();
    let udp = UdpTransport::bind("127.0.0.1:0".parse().unwrap(), f.peers.clone())
        .await
        .unwrap();
    if lan {
        f.peers
            .set_local_interface_networks(vec![p2pnet_nat::LocalNetwork::new(
                "127.0.0.1".parse().unwrap(),
                8,
            )])
            .await;
    }
    f.peers
        .add_candidates_with_sources(
            PEER,
            &[endpoint.to_string()],
            &HashMap::from([(
                endpoint.to_string(),
                if lan { "host" } else { "srflx" }.to_string(),
            )]),
        )
        .await;
    f.peers
        .record_direct_probe_success_with_latency_and_local_endpoint(
            PEER,
            endpoint,
            Some(Duration::from_millis(1)),
            Some(udp.local_addr().unwrap()),
        )
        .await;
    if compatibility_commit {
        f.peers
            .record_direct_success_with_local_endpoint(
                PEER,
                Some(endpoint),
                Some(udp.local_addr().unwrap()),
            )
            .await;
    }
    let (session, remote) = establish_sessions();
    let (transport, _rx) = WireGuardTransport::new_with_request_carriage();
    transport
        .replace_session_for_lifecycle(PEER, session, f.record.expected_target_lifecycle().unwrap())
        .await;
    (f, transport, udp, receiver, remote)
}
async fn receive_original(
    receiver: &tokio::net::UdpSocket,
    remote: &mut p2pnet_wireguard::TransportSession,
    f: &RoutedRequestFixture,
) -> usize {
    let mut wire = [0u8; 2048];
    let (n, _) = receiver.recv_from(&mut wire).await.unwrap();
    assert_eq!(
        remote.decrypt_from_bytes(&wire[..n]).unwrap(),
        f.record.original_packet()
    );
    n
}

#[tokio::test]
async fn b17_slow_actual_udp_success_fixed_b_g_and_legacy_unknown() {
    tokio::time::timeout(Duration::from_secs(1), async {
        let (f, transport, udp, receiver, mut remote) = direct_fixture(false).await;
        let instance = transport
            .session_status(PEER)
            .await
            .active_session_instance
            .unwrap();
        let udps = RwLock::new(Some(udp.clone()));
        let relays = RwLock::new(None);
        assert!(matches!(
            encrypt_then_send_with_deadline(
                f.delivery.clone(),
                &transport,
                &f.peers,
                f.record.generation,
                true,
                &udps,
                &relays,
                false,
                Some(Instant::now() + Duration::from_secs(1)),
                None
            )
            .await,
            EncryptSendOutcome::Sent
        ));
        let n = receive_original(&receiver, &mut remote, &f).await;
        let record = f.record.physical_publication.record().unwrap();
        assert_eq!(record.encryption().session_instance(), instance);
        assert_eq!(
            record.encryption().authorized_peer_lifecycle(),
            f.record.expected_target_lifecycle()
        );
        assert_eq!(record.encryption_generation(), f.record.generation);
        assert_eq!(
            record
                .udp()
                .expect("genuine UDP record")
                .transport_instance(),
            udp.transport_instance_id()
        );
        assert_eq!(record.udp().expect("genuine UDP record").sent(), n);
        assert_eq!(
            record.udp().expect("genuine UDP record").endpoint(),
            receiver.local_addr().unwrap()
        );
        assert_eq!(
            record.udp().expect("genuine UDP record").fence(),
            UdpSendFence::LegacyUnknown
        );
        assert_eq!(
            record
                .udp()
                .expect("genuine UDP record")
                .publication_owner(),
            None
        );
        assert_eq!(
            record.qualify(&f.record, Instant::now()),
            PhysicalInputQualification::UnknownUdpPublication
        );
        assert!(
            record.encryption().encrypted_at()
                <= record.udp().expect("genuine UDP record").syscall_started()
        );
        assert!(
            record.udp().expect("genuine UDP record").syscall_started()
                <= record
                    .udp()
                    .expect("genuine UDP record")
                    .syscall_completed()
        );
        assert!(transport.try_acquire_outbound_emit_guard(PEER).is_some());
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn b17_slow_full_syscall_then_original_diagnostics_wait_external_cancel_publishes() {
    tokio::time::timeout(Duration::from_secs(1), async {
        let (f, transport, udp, receiver, mut remote) = direct_fixture(false).await;
        let diagnostics = udp.hold_primary_socket_diagnostics_for_test().await;
        let udps = RwLock::new(Some(udp.clone()));
        let relays = RwLock::new(None);
        let mut send = Box::pin(encrypt_then_send_with_deadline(f.delivery.clone(), &transport, &f.peers, f.record.generation, true, &udps, &relays, false, Some(Instant::now()+Duration::from_secs(1)), None));
        let received = tokio::select! {
            n = receive_original(&receiver, &mut remote, &f) => n,
            _ = &mut send => panic!("original diagnostic guard must still block the completed syscall's business future"),
        };
        assert_eq!(f.record.physical_publication.state(), PhysicalPublicationState::Open);
        assert!(transport.try_acquire_outbound_emit_guard(PEER).is_none());
        // No timeout allowance change or new seam: destroy the actual future.
        drop(send);
        assert!(transport.try_acquire_outbound_emit_guard(PEER).is_some());
        assert!(f.peers.network_epoch_gate().try_lock_owned().is_ok());
        assert!(udps.try_write().is_ok());
        let record = f.record.physical_publication.record().unwrap();
        assert_eq!(record.udp().expect("genuine UDP record").sent(), received);
        assert_eq!(record.udp().expect("genuine UDP record").publication_owner(), None);
        assert_eq!(f.record.physical_publication.state(), PhysicalPublicationState::Recorded);
        drop(diagnostics);
    }).await.unwrap();
}

#[tokio::test]
async fn b17_fast_actual_full_and_synthetic_wouldblock_retry_has_new_b_and_counter() {
    tokio::time::timeout(Duration::from_secs(1), async {
        let (f, transport, udp, receiver, mut remote) = direct_fixture(true).await;
        udp.set_inbound_publication_owner(717);
        let (_, socket) = udp
            .socket_for_peer_endpoint(Some(PEER), Some(receiver.local_addr().unwrap()))
            .await
            .unwrap();
        socket.writable().await.unwrap();
        let _attempts = udp.inject_direct_business_would_block_for_test(PEER, 1);
        let udps = RwLock::new(Some(udp.clone()));
        let mut paths = HashMap::new();
        let mut ineligible = HashMap::new();
        let first = super::super::fast_path::try_lan_direct_fast_path(
            f.delivery.clone(),
            &transport,
            &f.peers,
            true,
            &udps,
            &mut paths,
            &mut ineligible,
        );
        let super::super::fast_path::FastPathAttempt::Fallback(retry) = first else {
            panic!("synthetic WouldBlock returns original plaintext");
        };
        assert_eq!(
            f.record.physical_publication.state(),
            PhysicalPublicationState::DefinitelyNotHanded
        );
        assert!(f.record.physical_publication.record().is_none());
        assert_eq!(retry.packet, f.record.original_packet());
        let second = super::super::fast_path::try_lan_direct_fast_path(
            retry,
            &transport,
            &f.peers,
            true,
            &udps,
            &mut paths,
            &mut ineligible,
        );
        assert!(matches!(
            second,
            super::super::fast_path::FastPathAttempt::Sent
        ));
        let mut wire = [0u8; 2048];
        let (n, _) = receiver.recv_from(&mut wire).await.unwrap();
        assert_eq!(crate::transport::wire_counter(&wire[..n]), Some(1));
        assert_eq!(
            remote.decrypt_from_bytes(&wire[..n]).unwrap(),
            f.record.original_packet()
        );
        let record = f.record.physical_publication.record().unwrap();
        assert_eq!(record.attempt_id(), 2);
        assert_eq!(
            record.udp().expect("genuine UDP record").fence(),
            UdpSendFence::LanPublication
        );
        assert_eq!(
            record
                .udp()
                .expect("genuine UDP record")
                .publication_owner(),
            Some(717)
        );
        assert_eq!(record.encryption_generation(), f.record.generation);
        assert_eq!(
            record.qualify(&f.record, Instant::now()),
            PhysicalInputQualification::AcceptedInput
        );
        assert!(transport.try_acquire_outbound_emit_guard(PEER).is_some());
        assert!(f.peers.network_epoch_gate().try_lock_owned().is_ok());
        assert!(udps.try_write().is_ok());
    })
    .await
    .unwrap();
}

// BASE/runtime ACK installation is a synthetic prerequisite control. The
// business encryption, managed writer and UDP receipt/decrypt below are real.
async fn install_managed_base(f: &RoutedRequestFixture, udp: &UdpTransport, endpoint: SocketAddr) {
    let generation = f.peers.current_network_generation_sync();
    let life = f.peers.peer_session_generation_sync(PEER).unwrap();
    let remote_epoch = f.peers.current_remote_candidate_epoch(PEER).await.unwrap();
    let epoch = crate::peer::PathEpoch::new(generation, life, remote_epoch);
    assert!(
        f.peers
            .mark_direct_validation_started(
                PEER,
                crate::peer::DirectValidationIdentity::owned(epoch, 817, Some(17), Some(endpoint))
            )
            .await
    );
    let validation = crate::peer::DirectValidationIdentity::authenticated_ack(
        epoch,
        817,
        17,
        Some(endpoint),
        endpoint,
    );
    let gate = f.peers.network_epoch_gate();
    let held = gate.lock().await;
    assert!(f.peers.record_direct_success_for_generation_with_local_endpoint_and_latency_in_epoch_for_remote_epoch(&held, PEER, Some(endpoint), generation, Some(udp.local_addr().unwrap()), None, Some(remote_epoch), Some(validation)).await);
    drop(held);
    let identity = crate::dplpmtud::DplpmtudPathIdentity::from_committed_validation(
        PEER,
        validation,
        endpoint,
        udp.local_addr().unwrap(),
        udp.transport_instance_id(),
        0,
    )
    .unwrap();
    assert!(udp.mark_peer_dplpmtud_supported(PEER, life));
    let runtime = udp.dplpmtud_runtime();
    let now = tokio::time::Instant::now();
    let lease = runtime
        .install_path(identity.clone(), true, now)
        .worker
        .unwrap();
    let plan = runtime
        .schedule_probe(PEER, &identity, lease.worker_owner_token, now)
        .unwrap();
    assert!(runtime.begin_probe_send(&plan, now));
    runtime.finish_probe_send(&plan, Ok(()), now + Duration::from_millis(1));
    assert_eq!(
        runtime.try_accept_ack(
            PEER,
            &identity,
            plan.wire_token,
            crate::dplpmtud::DplpmtudAckIngress {
                remote_endpoint: endpoint,
                local_endpoint: udp.local_addr().unwrap(),
                socket: identity.socket
            },
            now + Duration::from_millis(2)
        ),
        crate::dplpmtud::DplpmtudTransitionDecision::Applied
    );
    assert!(udp.direct_business_budget_ready_for_peer(PEER));
    // The managed writer performs a nonblocking try_send_to. Wait for the
    // genuine exact socket inside the caller's existing one-second fixture.
    let (socket_index, socket) = udp
        .socket_for_peer_endpoint(Some(PEER), Some(endpoint))
        .await
        .unwrap();
    assert_eq!(socket_index, identity.socket.socket_index);
    assert_eq!(socket.local_addr().unwrap(), identity.local_endpoint);
    socket.writable().await.unwrap();
}

#[tokio::test]
async fn b17_managed_original_core_full_fact_and_synthetic_emsgsize_has_no_fact() {
    tokio::time::timeout(Duration::from_secs(1), async {
        // Begin owned validation from the genuine probe state, before any
        // compatibility commit can legitimately reject a different owner.
        let (f, transport, udp, receiver, mut remote) =
            direct_fixture_with_compatibility_commit(false, false).await;
        let udp = udp.with_dplpmtud_local_virtual_ip("10.20.0.1".parse().unwrap());
        udp.set_inbound_publication_owner(817);
        install_managed_base(&f, &udp, receiver.local_addr().unwrap()).await;
        let udps = RwLock::new(Some(udp.clone()));
        let relays = RwLock::new(None);
        let result = encrypt_then_send_with_deadline(
            f.delivery.clone(),
            &transport,
            &f.peers,
            f.record.generation,
            true,
            &udps,
            &relays,
            false,
            Some(Instant::now() + Duration::from_secs(1)),
            None,
        )
        .await;
        assert!(
            matches!(&result, EncryptSendOutcome::Sent),
            "managed fixture expected Sent; actual {}",
            match &result {
                EncryptSendOutcome::Sent => "Sent".to_string(),
                EncryptSendOutcome::BudgetPending { reason, .. } => {
                    format!("BudgetPending: {reason}")
                }
                EncryptSendOutcome::Retryable {
                    reason_code,
                    reason,
                    ..
                } => {
                    format!("Retryable [{reason_code}]: {reason}")
                }
                EncryptSendOutcome::RetryableLocalBackpressure { reason, .. } => {
                    format!("RetryableLocalBackpressure: {reason}")
                }
                EncryptSendOutcome::Terminal {
                    reason_code,
                    reason,
                    ..
                } => {
                    format!("Terminal [{reason_code}]: {reason}")
                }
            }
        );
        let n = receive_original(&receiver, &mut remote, &f).await;
        let record = f.record.physical_publication.record().unwrap();
        assert_eq!(
            record.udp().expect("genuine UDP record").fence(),
            UdpSendFence::ManagedPublication
        );
        assert_eq!(
            record
                .udp()
                .expect("genuine UDP record")
                .publication_owner(),
            Some(817)
        );
        assert_eq!(record.udp().expect("genuine UDP record").sent(), n);
        assert_eq!(record.encryption_generation(), f.record.generation);
        assert_eq!(
            record.qualify(&f.record, Instant::now()),
            PhysicalInputQualification::AcceptedInput
        );
        let (g, gt, gu, gr, _remote) = direct_fixture_with_compatibility_commit(false, false).await;
        let gu = gu.with_dplpmtud_local_virtual_ip("10.20.0.1".parse().unwrap());
        gu.set_inbound_publication_owner(818);
        install_managed_base(&g, &gu, gr.local_addr().unwrap()).await;
        gu.inject_direct_business_emsgsize_once_for_test();
        let slots = RwLock::new(Some(gu));
        let result = encrypt_then_send_with_deadline(
            g.delivery,
            &gt,
            &g.peers,
            g.record.generation,
            true,
            &slots,
            &relays,
            false,
            Some(Instant::now() + Duration::from_secs(1)),
            None,
        )
        .await;
        assert!(matches!(
            result,
            EncryptSendOutcome::Terminal {
                reason_code: REASON_DIRECT_BUSINESS_EMSGSIZE,
                ..
            }
        ));
        assert_eq!(
            g.record.physical_publication.state(),
            PhysicalPublicationState::DefinitelyNotHanded
        );
        assert!(g.record.physical_publication.record().is_none());
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn b17_pending_socket_cancel_and_unavailable_relay_never_infer_full_or_all_not_handed() {
    tokio::time::timeout(Duration::from_secs(1), async {
        let (f, transport, udp, receiver, mut remote) = direct_fixture(false).await;
        let _polls = udp.inject_udp_send_pending_for_test(PEER);
        let slots = RwLock::new(Some(udp.clone())); let relays = RwLock::new(None);
        let mut pending = Box::pin(encrypt_then_send_with_deadline(f.delivery.clone(), &transport, &f.peers, f.record.generation, true, &slots, &relays, false, Some(Instant::now()+Duration::from_secs(1)), None));
        assert!(matches!(futures_util::poll!(pending.as_mut()), std::task::Poll::Pending));
        assert_eq!(f.record.physical_publication.state(), PhysicalPublicationState::Open);
        drop(pending);
        assert_eq!(f.record.physical_publication.state(), PhysicalPublicationState::CancelledOrUncertain);
        assert!(f.record.physical_publication.record().is_none());
        assert!(transport.try_acquire_outbound_emit_guard(PEER).is_some());
        udp.release_udp_send_pending_for_test(PEER);
        let mut bytes = [0u8;2048];
        assert!(matches!(receiver.try_recv_from(&mut bytes), Err(e) if e.kind()==std::io::ErrorKind::WouldBlock));
        assert!(matches!(encrypt_then_send_with_deadline(f.delivery.clone(), &transport, &f.peers, f.record.generation, true, &slots, &relays, false, Some(Instant::now()+Duration::from_secs(1)), None).await, EncryptSendOutcome::Sent));
        let (n,_) = receiver.recv_from(&mut bytes).await.unwrap();
        assert_eq!(crate::transport::wire_counter(&bytes[..n]), Some(1));
        assert_eq!(remote.decrypt_from_bytes(&bytes[..n]).unwrap(), f.record.original_packet());
        assert_eq!(f.record.physical_publication.state(), PhysicalPublicationState::CancelledOrUncertain);
        assert!(f.record.physical_publication.record().is_none(), "business retry cannot reopen uncertain metadata");
        let g = mint_routed_request().await;
        let (session, _) = establish_sessions(); let (gt, _rx) = WireGuardTransport::new_with_request_carriage();
        gt.replace_session_for_lifecycle(PEER, session, g.record.expected_target_lifecycle().unwrap()).await;
        let none = RwLock::new(None);
        assert!(matches!(encrypt_then_send_with_deadline(g.delivery, &gt, &g.peers, g.record.generation, false, &none, &relays, true, Some(Instant::now()+Duration::from_secs(1)), None).await, EncryptSendOutcome::Retryable { .. }));
        assert_eq!(g.record.physical_publication.state(), PhysicalPublicationState::CancelledOrUncertain);
        assert!(g.record.physical_publication.record().is_none());
    }).await.unwrap();
}

#[tokio::test]
async fn b17_actual_minter_pending_acceptance_requalifies_the_same_physical_record() {
    tokio::time::timeout(Duration::from_secs(1), async {
        use crate::overlay_requests::{send_overlay_payloads_with_publication_gate_for_test, InjectionPublicationGate};
        use crate::request_carriage::test_support::{mint_input_request, LOCAL_VIP};
        use crate::dataplane::DataPlane;
        let input = mint_input_request().await;
        let peers = input.peers.clone();
        let (mut plane, mut routed) = DataPlane::new_with_request_carriage(input.tun, peers.clone());
        // Drain the genuine first input from the shared helper before minting
        // the gated one; independent random payloads are never compared.
        plane.read_and_route_once(&mut [0u8;512]).await.unwrap();
        drop(routed.recv().await.unwrap());
        drop(input.record);
        let receiver = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let endpoint = receiver.local_addr().unwrap();
        let udp = UdpTransport::bind("127.0.0.1:0".parse().unwrap(), peers.clone()).await.unwrap();
        peers.add_candidates_with_sources(PEER, &[endpoint.to_string()], &HashMap::from([(endpoint.to_string(), "srflx".to_string())])).await;
        peers.record_direct_probe_success_with_latency_and_local_endpoint(PEER, endpoint, Some(Duration::from_millis(1)), Some(udp.local_addr().unwrap())).await;
        peers.record_direct_success_with_local_endpoint(PEER, Some(endpoint), Some(udp.local_addr().unwrap())).await;
        let gate = InjectionPublicationGate::new();
        let mut nonce = 0x17_0000; let mut seq = 17;
        let mut stats = crate::OverlayStats { sent:0, received_valid:0, received_invalid:0, verified_round_trips:0, last_seq:0 };
        let mut retained = HashMap::new(); let mut order = std::collections::VecDeque::new();
        let mut minter = Box::pin(send_overlay_payloads_with_publication_gate_for_test(&input.controller, &peers, LOCAL_VIP, true, None, &mut nonce, &mut seq, &mut stats, &mut retained, &mut order, &gate));
        tokio::select! { () = gate.reached.notified() => {}, _ = &mut minter => panic!("original injection must pause after real Ok") }
        plane.read_and_route_once(&mut [0u8;512]).await.unwrap();
        let delivery = routed.recv().await.unwrap();
        let request = delivery.binding().unwrap().token().request().unwrap();
        assert!(!request.injection_accepted());
        let (session, mut remote) = establish_sessions();
        let (transport, _rx) = WireGuardTransport::new_with_request_carriage();
        transport.replace_session_for_lifecycle(PEER, session, request.expected_target_lifecycle().unwrap()).await;
        let slots = RwLock::new(Some(udp)); let relays = RwLock::new(None);
        assert!(matches!(encrypt_then_send_with_deadline(delivery, &transport, &peers, request.generation, true, &slots, &relays, false, Some(Instant::now()+Duration::from_secs(1)), None).await, EncryptSendOutcome::Sent));
        let mut wire=[0u8;2048];let(n,_) = receiver.recv_from(&mut wire).await.unwrap();
        assert_eq!(remote.decrypt_from_bytes(&wire[..n]).unwrap(), request.original_packet());
        let physical = request.physical_publication.record().unwrap();
        assert_eq!(physical.qualify(&request, Instant::now()), PhysicalInputQualification::PendingInjection);
        gate.release.notify_one(); assert_eq!(minter.await, 1);
        assert!(Arc::ptr_eq(retained.get(&nonce).unwrap(), &request));
        assert!(std::ptr::eq(physical, request.physical_publication.record().unwrap()));
        assert_eq!(physical.qualify(&request, Instant::now()), PhysicalInputQualification::UnknownUdpPublication);
        assert!(request.injection_accepted());
    }).await.unwrap();
}

#[tokio::test]
async fn b17_original_pipeline_minter_mock_route_actor_actual_udp_decrypt_and_canonical_fact() {
    let InputRequestFixture {
        peers,
        controller,
        tun,
        record,
    } = mint_input_request().await;
    let receiver = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let endpoint = receiver.local_addr().unwrap();
    // Register the actual receiver through the existing candidate owner. A
    // non-host source keeps this control on the original slow selector path.
    peers
        .add_candidates_with_sources(
            PEER,
            &[endpoint.to_string()],
            &HashMap::from([(endpoint.to_string(), "srflx".to_string())]),
        )
        .await;
    let udp = UdpTransport::bind("127.0.0.1:0".parse().unwrap(), peers.clone())
        .await
        .unwrap();
    let local_endpoint = udp.local_addr().unwrap();
    peers
        .record_direct_probe_success_with_latency_and_local_endpoint(
            PEER,
            endpoint,
            Some(Duration::from_millis(1)),
            Some(local_endpoint),
        )
        .await;
    peers
        .record_direct_success_with_local_endpoint(PEER, Some(endpoint), Some(local_endpoint))
        .await;
    let selection = peers
        .select_path_for_data_with_local_endpoint(PEER, true, false, Some(local_endpoint))
        .await;
    assert_eq!(selection.path, Some(NetworkPath::Direct));
    assert!(selection.direct_confirmed);
    assert!(peers
        .active_direct_path_snapshot(PEER, record.generation, true)
        .await
        .is_none());
    assert!(!udp.peer_requires_direct_business_budget(PEER));
    let (session, mut remote) = establish_sessions();
    let probe = Arc::new(RequestHandoffArgumentProbe::new());
    let (transport, raw_rx) = WireGuardTransport::new_with_request_carriage();
    let transport = transport.with_request_handoff_probe(probe.clone());
    let life = record.expected_target_lifecycle().unwrap();
    let _ = transport
        .replace_session_for_lifecycle(PEER, session, life)
        .await;
    let instance = transport
        .session_status(PEER)
        .await
        .active_session_instance
        .unwrap();
    let (mut dataplane, dp_rx) = DataPlane::new_with_request_carriage(tun, peers.clone());
    let forward_transport = transport.clone();
    let forward = tokio::spawn(async move {
        forward_transport
            .run_outbound_with_request_carriage(dp_rx)
            .await
    });
    let (relay_tx, relay_rx) = watch::channel(false);
    let (kick_tx, _kick_rx) = watch::channel(0u64);
    let worker = tokio::spawn(super::super::run_network_outbound_with_request_carriage(
        raw_rx.into(),
        transport.clone(),
        peers.clone(),
        true,
        Arc::new(RwLock::new(Some(udp))),
        Arc::new(RwLock::new(None)),
        relay_rx,
        RelayStartupWait {
            relay_expected: false,
            timeout: None,
        },
        kick_tx,
        ConnectionTimeline::new("carriage-slow-chain", 0),
    ));
    let before = Instant::now();
    tokio::time::timeout(
        Duration::from_secs(1),
        dataplane.read_and_route_once(&mut [0u8; 512]),
    )
    .await
    .unwrap()
    .unwrap();
    let mut wire = [0u8; 2048];
    let (n, _) = tokio::time::timeout(Duration::from_secs(1), async {
        let received = receiver.recv_from(&mut wire).await?;
        // The original emit gate is a completion barrier after the real UDP
        // syscall. Receipt and completion share the existing one-second budget.
        let emit = transport.acquire_outbound_emit_guard(PEER).await;
        drop(emit);
        Ok::<_, std::io::Error>(received)
    })
    .await
    .unwrap()
    .unwrap();
    let after = Instant::now();
    assert_eq!(
        remote.decrypt_from_bytes(&wire[..n]).unwrap(),
        record.original_packet()
    );
    let observed = probe
        .recorded
        .lock()
        .unwrap()
        .take()
        .expect("real original bounded argument was observed");
    assert_eq!(observed.point, HandoffArgumentPoint::SlowBoundedEntry);
    assert!(Arc::ptr_eq(
        &observed.token.unwrap().request().unwrap(),
        &record
    ));
    let b = observed.source.unwrap();
    assert_eq!(b.peer_id, PEER);
    assert_eq!(b.session_instance, instance);
    assert_eq!(b.authorized_peer_lifecycle, Some(life));
    assert!(b.encrypted_at >= before && b.encrypted_at <= after);
    assert!(b.belongs_to_transport);
    let physical = record
        .physical_publication
        .record()
        .expect("actual original actor publishes its full UDP fact");
    assert_eq!(physical.udp().expect("genuine UDP record").sent(), n);
    assert_eq!(physical.encryption_generation(), record.generation);
    assert_eq!(physical.encryption().session_instance(), instance);
    assert_eq!(
        physical
            .udp()
            .expect("genuine UDP record")
            .publication_owner(),
        None
    );
    assert_eq!(
        physical.qualify(&record, Instant::now()),
        PhysicalInputQualification::UnknownUdpPublication
    );
    // Keep the original input/forward/actor ownership alive through the strict
    // live qualification, then retire that same pipeline without a keeper.
    drop(dataplane);
    tokio::time::timeout(Duration::from_secs(1), forward)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    // Closing the original lifecycle watch retires the actual actor; no extra
    // metadata observer task or queue is used for this chain.
    drop(relay_tx);
    tokio::time::timeout(Duration::from_secs(1), worker)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        physical.qualify(&record, Instant::now()),
        PhysicalInputQualification::Retired
    );
    drop(controller);
}

#[tokio::test]
async fn b17_real_legacy_key_unknown_auth_l_stays_unknown_after_full_udp() {
    tokio::time::timeout(Duration::from_secs(1), async {
        let (f, _authorized_transport, udp, receiver, _remote) = direct_fixture(false).await;
        let (session, mut remote) = establish_sessions();
        let (transport, _rx) = WireGuardTransport::new_with_request_carriage();
        // Actual existing legacy session installation, not a fabricated Some B.
        transport.add_session(PEER, session).await;
        let slots = RwLock::new(Some(udp));
        let relays = RwLock::new(None);
        assert!(matches!(
            encrypt_then_send_with_deadline(
                f.delivery.clone(),
                &transport,
                &f.peers,
                f.record.generation,
                true,
                &slots,
                &relays,
                false,
                Some(Instant::now() + Duration::from_secs(1)),
                None
            )
            .await,
            EncryptSendOutcome::Sent
        ));
        receive_original(&receiver, &mut remote, &f).await;
        let record = f.record.physical_publication.record().unwrap();
        assert_eq!(record.encryption().authorized_peer_lifecycle(), None);
        assert!(f.record.expected_target_lifecycle().is_some());
        assert_eq!(
            record.qualify(&f.record, Instant::now()),
            PhysicalInputQualification::UnknownOriginalAuthorization
        );
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn b17_record_rejects_other_genuine_a_with_same_peer_owner_g_l_and_ttl() {
    tokio::time::timeout(Duration::from_secs(1), async {
        use crate::request_carriage::test_support::LOCAL_VIP;
        let input = mint_input_request().await;
        let peers = input.peers.clone();
        let (mut plane, mut routed) =
            DataPlane::new_with_request_carriage(input.tun, peers.clone());
        plane.read_and_route_once(&mut [0u8; 512]).await.unwrap();
        let first = routed.recv().await.unwrap();
        let receiver = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let endpoint = receiver.local_addr().unwrap();
        let udp = UdpTransport::bind("127.0.0.1:0".parse().unwrap(), peers.clone())
            .await
            .unwrap();
        udp.set_inbound_publication_owner(919);
        peers
            .set_local_interface_networks(vec![p2pnet_nat::LocalNetwork::new(
                "127.0.0.1".parse().unwrap(),
                8,
            )])
            .await;
        peers
            .add_candidates_with_sources(
                PEER,
                &[endpoint.to_string()],
                &HashMap::from([(endpoint.to_string(), "host".to_string())]),
            )
            .await;
        peers
            .record_direct_probe_success_with_latency_and_local_endpoint(
                PEER,
                endpoint,
                Some(Duration::from_millis(1)),
                Some(udp.local_addr().unwrap()),
            )
            .await;
        peers
            .record_direct_success_with_local_endpoint(
                PEER,
                Some(endpoint),
                Some(udp.local_addr().unwrap()),
            )
            .await;
        // Mint A2 BEFORE A1 encryption so both original times genuinely precede
        // the same B. Wrong A cannot be rejected merely by clock/owner mismatch.
        let mut nonce = 0x17_1000;
        let mut seq = 117;
        let mut stats = crate::OverlayStats {
            sent: 0,
            received_valid: 0,
            received_invalid: 0,
            verified_round_trips: 0,
            last_seq: 0,
        };
        let mut retained = HashMap::new();
        let mut order = std::collections::VecDeque::new();
        assert_eq!(
            crate::overlay_requests::send_overlay_payloads(
                &input.controller,
                &peers,
                LOCAL_VIP,
                true,
                None,
                &mut nonce,
                &mut seq,
                &mut stats,
                &mut retained,
                &mut order
            )
            .await,
            1
        );
        plane.read_and_route_once(&mut [0u8; 512]).await.unwrap();
        let other = routed.recv().await.unwrap();
        let a2 = other.binding().unwrap().token().request().unwrap();
        assert!(!Arc::ptr_eq(&input.record, &a2));
        assert_eq!(input.record.peer_id, a2.peer_id);
        assert_eq!(input.record.generation, a2.generation);
        assert_eq!(
            input.record.expected_target_lifecycle(),
            a2.expected_target_lifecycle()
        );
        assert!(input.record.belongs_to(&peers) && a2.belongs_to(&peers));
        let (session, mut remote) = establish_sessions();
        let (transport, _rx) = WireGuardTransport::new_with_request_carriage();
        transport
            .replace_session_for_lifecycle(
                PEER,
                session,
                input.record.expected_target_lifecycle().unwrap(),
            )
            .await;
        let (_, socket) = udp
            .socket_for_peer_endpoint(Some(PEER), Some(endpoint))
            .await
            .unwrap();
        socket.writable().await.unwrap();
        let slots = RwLock::new(Some(udp));
        let mut paths = HashMap::new();
        let mut ineligible = HashMap::new();
        assert!(matches!(
            super::super::fast_path::try_lan_direct_fast_path(
                first,
                &transport,
                &peers,
                true,
                &slots,
                &mut paths,
                &mut ineligible
            ),
            super::super::fast_path::FastPathAttempt::Sent
        ));
        let mut bytes = [0u8; 2048];
        let (n, _) = receiver.recv_from(&mut bytes).await.unwrap();
        assert_eq!(
            remote.decrypt_from_bytes(&bytes[..n]).unwrap(),
            input.record.original_packet()
        );
        let record = input.record.physical_publication.record().unwrap();
        assert!(a2.sent_at <= record.encryption().encrypted_at());
        assert_eq!(
            record.qualify(&input.record, Instant::now()),
            PhysicalInputQualification::AcceptedInput
        );
        assert_eq!(
            record.qualify(&a2, Instant::now()),
            PhysicalInputQualification::OriginalMismatch
        );
        assert!(a2.physical_publication.record().is_none());
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn b26_managed_original_token_survives_same_revision_budget_replace_and_revoke() {
    tokio::time::timeout(Duration::from_secs(2), async {
        let (f, transport, udp, receiver, mut remote) =
            direct_fixture_with_compatibility_commit(false, false).await;
        let udp = udp.with_dplpmtud_local_virtual_ip("10.20.0.1".parse().unwrap());
        udp.set_inbound_publication_owner(817);
        let endpoint = receiver.local_addr().unwrap();
        install_managed_base(&f, &udp, endpoint).await;
        let runtime = udp.dplpmtud_runtime();
        let mut facts = Vec::new();
        for smaller in [false, true] {
            if smaller {
                let old = facts
                    .first()
                    .and_then(crate::udp::UdpFullSendFact::original_managed_token)
                    .unwrap();
                // Existing explicit seam changes sizes without changing revision.
                // The actual next prepared token/syscall must carry this value.
                assert!(runtime.force_coherent_business_budget_for_test(
                    PEER,
                    crate::dplpmtud::UdpDatagramSize(old.max_udp_datagram_size.0 - 1)
                ));
                assert!(matches!(
                    udp.try_original_direct_publication_guard(
                        PEER,
                        f.record.generation,
                        None,
                        facts.first()
                    ),
                    Err(crate::udp::DirectOriginFailure::Stale)
                ));
            }
            let crate::udp::DirectBusinessBudgetGate::Ready(prepared) =
                udp.prepare_direct_business_send(PEER, endpoint).await
            else {
                panic!("managed fixture must prepare")
            };
            let packet = transport
                .encrypt_outbound(crate::dataplane::OutboundPacket {
                    room_authorization: None,
                    peer_id: PEER.into(),
                    dst_ip: f.record.target_vip().into(),
                    packet: f.record.original_packet().to_vec(),
                    trace: None,
                })
                .await
                .unwrap()
                .unwrap();
            let mut capture = crate::udp::UdpSendCapture::new();
            assert_eq!(
                udp.try_send_direct_business_packet_with_origin(
                    &prepared,
                    &packet,
                    Some(&mut capture)
                )
                .unwrap(),
                packet.wire_bytes.len()
            );
            assert_eq!(
                receive_original(&receiver, &mut remote, &f).await,
                packet.wire_bytes.len()
            );
            let fact = capture.take().unwrap();
            assert_eq!(fact.original_managed_token(), Some(&prepared.token));
            assert!(matches!(
                udp.try_original_direct_publication_guard(
                    "wrong-peer",
                    f.record.generation,
                    None,
                    Some(&fact)
                ),
                Err(crate::udp::DirectOriginFailure::Stale)
            ));
            assert!(matches!(
                udp.try_original_direct_publication_guard(
                    PEER,
                    f.record.generation + 1,
                    None,
                    Some(&fact)
                ),
                Err(crate::udp::DirectOriginFailure::Stale)
            ));
            assert!(udp
                .try_original_direct_publication_guard(PEER, f.record.generation, None, Some(&fact))
                .is_ok());
            let held = runtime.try_original_business_publication_guard().unwrap();
            assert!(matches!(
                udp.try_original_direct_publication_guard(
                    PEER,
                    f.record.generation,
                    None,
                    Some(&fact)
                ),
                Err(crate::udp::DirectOriginFailure::ContendedPublication)
            ));
            drop(held);
            facts.push(fact);
        }
        let old = facts[0].original_managed_token().unwrap();
        let fresh = facts[1].original_managed_token().unwrap();
        assert_eq!(old.budget_revision, fresh.budget_revision);
        assert_ne!(old.max_udp_datagram_size, fresh.max_udp_datagram_size);
        assert!(udp.invalidate_direct_business_budget(fresh));
        assert!(matches!(
            udp.try_original_direct_publication_guard(
                PEER,
                f.record.generation,
                None,
                Some(&facts[1])
            ),
            Err(crate::udp::DirectOriginFailure::Stale)
        ));
        assert_eq!(
            facts[0].original_managed_token(),
            Some(old),
            "original token cannot inherit the replacement"
        );
        assert!(udp.clear_inbound_publication_owner_if_matches(817));
        assert!(matches!(
            udp.try_original_direct_publication_guard(
                PEER,
                f.record.generation,
                None,
                Some(&facts[1])
            ),
            Err(crate::udp::DirectOriginFailure::Stale)
        ));
    })
    .await
    .unwrap();
}
