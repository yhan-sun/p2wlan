// Actual original slow crypto/caller and both genuine full TCP writers.
// Barriers, legacy bridge and ledger faults are explicitly cfg(test) only.
// This is not the shared actor/FIFO whole pipeline, partial TCP, ACK or credit.
use super::*;
use crate::overlay_requests::{PhysicalInputQualification, PhysicalPublicationState};
use crate::relay::publication_test_support::{
    cryptographic_fixture, encrypt_existing, sessions, Budget, Fixture, WriterPath,
};
use crate::relay::RelayCaptureOutcome;
use crate::request_carriage::test_support::{RoutedRequestFixture, PEER};
use std::future::{poll_fn, Future};
use std::task::Poll;

async fn admitted(
    path: WriterPath,
    budget: Budget,
) -> (
    RoutedRequestFixture,
    WireGuardTransport,
    Fixture,
    p2pnet_wireguard::TransportSession,
) {
    let (f, transport, remote) = cryptographic_fixture(budget, true).await;
    let fixture = Fixture::start(path, f.peers.clone(), budget).await;
    budget
        .step(f.peers.mark_relay_transport_ready(
            PEER,
            fixture.transport().endpoint(),
            f.record.generation,
        ))
        .await;
    assert!(
        budget
            .step(f.peers.confirm_relay_peer(
                PEER,
                fixture.transport().endpoint(),
                f.record.generation
            ))
            .await
    );
    (f, transport, fixture, remote)
}
async fn actual_slow(path: WriterPath) {
    let budget = Budget::new();
    let (f, transport, mut fixture, mut remote) = admitted(path, budget).await;
    let instance = budget
        .step(transport.session_status(PEER))
        .await
        .active_session_instance
        .unwrap();
    let udps = RwLock::new(None);
    let relays = RwLock::new(Some(fixture.transport().clone()));
    let count = fixture.client_count();
    assert!(matches!(
        budget
            .step(encrypt_then_send_with_deadline(
                f.delivery.clone(),
                &transport,
                &f.peers,
                f.record.generation,
                false,
                &udps,
                &relays,
                true,
                Some(Instant::now() + Duration::from_secs(1)),
                None,
            ))
            .await,
        EncryptSendOutcome::Sent
    ));
    let frame = fixture.next_frame(budget).await;
    let (destination, bytes) = frame.parse_forward_payload().unwrap();
    assert_eq!(destination, PEER);
    assert_eq!(
        remote.decrypt_from_bytes(bytes).unwrap(),
        f.record.original_packet()
    );
    let record = f.record.physical_publication.record().unwrap();
    assert_eq!(record.attempt_id(), 1);
    assert!(record.udp().is_none());
    let full = record.relay().unwrap();
    assert_eq!(
        full.wire(),
        (
            bytes.len(),
            crate::transport::wire_counter(bytes),
            crate::transport::wire_fingerprint(bytes)
        )
    );
    assert_eq!(full.original().unwrap().destination(), PEER);
    assert_eq!(full.original().unwrap().data_len(), bytes.len());
    assert_eq!(full.endpoint(), fixture.transport().endpoint());
    assert_eq!(full.connection_id(), fixture.transport().connection_id());
    assert_eq!(record.encryption().session_instance(), instance);
    assert_eq!(record.encryption_generation(), f.record.generation);
    assert_eq!(
        record.encryption().authorized_peer_lifecycle(),
        f.record.expected_target_lifecycle()
    );
    assert!(record.encryption().encrypted_at() <= full.original().unwrap().write_started_at());
    assert!(full.original().unwrap().write_started_at() <= full.original().unwrap().completed_at());
    assert_eq!(
        record.qualify(&f.record, Instant::now()),
        PhysicalInputQualification::UnknownRelayPublication
    );
    assert_eq!(
        fixture.client_count(),
        count,
        "capture has no source keeper"
    );
    assert_eq!(Arc::strong_count(&f.record), 1, "capture has no A keeper");
    assert!(transport.try_acquire_outbound_emit_guard(PEER).is_some());
    assert!(f.peers.network_epoch_gate().try_lock_owned().is_ok());
    assert!(relays.try_write().is_ok());
    drop(relays);
    fixture.finish(budget).await;
}
#[tokio::test]
async fn b19_general_canonical_full_original_slow_a_b_g() {
    actual_slow(WriterPath::General).await;
}
#[tokio::test]
async fn b19_legacy_canonical_full_original_writer_a_b_g() {
    actual_slow(WriterPath::LegacyAddress).await;
}

#[tokio::test]
async fn b19_public_none_preserves_original_business_tail() {
    let budget = Budget::new();
    let (f, transport, mut fixture, mut remote) = admitted(WriterPath::General, budget).await;
    let udps = RwLock::new(None);
    let relays = RwLock::new(Some(fixture.transport().clone()));
    let raw = (*f.delivery).clone();
    assert!(matches!(
        budget
            .step(encrypt_then_send_with_deadline(
                raw,
                &transport,
                &f.peers,
                f.record.generation,
                false,
                &udps,
                &relays,
                true,
                Some(Instant::now() + Duration::from_secs(1)),
                None,
            ))
            .await,
        EncryptSendOutcome::Sent
    ));
    let frame = fixture.next_frame(budget).await;
    assert_eq!(
        remote
            .decrypt_from_bytes(frame.parse_forward_payload().unwrap().1)
            .unwrap(),
        f.record.original_packet()
    );
    assert_eq!(
        f.record.physical_publication.state(),
        PhysicalPublicationState::Idle
    );
    assert!(f.record.physical_publication.record().is_none());
    let (packet, _unopened) = encrypt_existing(&f, &transport, budget).await;
    let started = AtomicBool::new(false);
    assert!(matches!(
        budget
            .step(send_via_relay(
                fixture.transport(),
                &packet,
                &f.peers,
                f.record.generation,
                &started,
                None
            ))
            .await,
        SendOutcome::Sent
    ));
    let frame = fixture.frame(&packet, budget).await;
    assert_eq!(
        remote
            .decrypt_from_bytes(frame.parse_forward_payload().unwrap().1)
            .unwrap(),
        f.record.original_packet()
    );
    assert!(started.load(Ordering::Acquire));
    assert_eq!(
        f.record.physical_publication.state(),
        PhysicalPublicationState::Idle
    );
    assert!(f.record.physical_publication.record().is_none());
    drop(relays);
    fixture.finish(budget).await;
    conflicting_transport_capture_is_metadata_failed(budget).await;
}

// Deliberate synthetic owner-path conflict. A genuine UDP full plus any Some
// Relay metadata outcome is rejected as MetadataFailed; no fact is preferred.
// The helper's encryption emit was released, so this is not an actual slow
// caller lifecycle positive and never establishes earliest physical delivery.
async fn conflicting_transport_capture_is_metadata_failed(budget: Budget) {
    let (f, transport, mut remote) = cryptographic_fixture(budget, true).await;
    let (packet, prepared) = encrypt_existing(&f, &transport, budget).await;
    let emit = budget
        .step(transport.acquire_outbound_emit_guard(PEER))
        .await;
    let mut owner = PhysicalAttempt::new(emit, Some(prepared));
    let _relay = owner.slow_capture().unwrap().relay_for_test(&packet);
    let receiver = budget
        .step(tokio::net::UdpSocket::bind("127.0.0.1:0"))
        .await
        .unwrap();
    let udp = budget
        .step(UdpTransport::bind(
            "127.0.0.1:0".parse().unwrap(),
            f.peers.clone(),
        ))
        .await
        .unwrap();
    let endpoint = receiver.local_addr().unwrap();
    assert_eq!(
        budget
            .step(udp.send_packet_to_with_origin(&packet, endpoint, owner.capture()))
            .await
            .unwrap(),
        packet.wire_bytes.len()
    );
    let mut bytes = [0u8; 512];
    let (len, _) = budget.step(receiver.recv_from(&mut bytes)).await.unwrap();
    assert_eq!(
        remote.decrypt_from_bytes(&bytes[..len]).unwrap(),
        f.record.original_packet()
    );
    owner.finish(false);
    assert_eq!(
        f.record.physical_publication.state(),
        PhysicalPublicationState::MetadataFailed
    );
    assert!(f.record.physical_publication.record().is_none());
    assert!(transport.try_acquire_outbound_emit_guard(PEER).is_some());
}

async fn full_then_owner_cancel(path: WriterPath) {
    let budget = Budget::new();
    let (f, transport, mut fixture, mut remote) = admitted(path, budget).await;
    let instance = budget
        .step(transport.session_status(PEER))
        .await
        .active_session_instance
        .unwrap();
    let (entered_tx, entered_rx) = tokio::sync::oneshot::channel();
    let (release_tx, release_rx) = std::sync::mpsc::sync_channel(1);
    let (capture_tx, capture_rx) = tokio::sync::oneshot::channel();
    let _setup = install_relay_capture_setup_for_test(&f.record, move |storage, packet| {
        let capture = storage.relay_for_test(packet);
        capture.after_full_for_test(move || {
            let _ = entered_tx.send(());
            release_rx
                .recv_timeout(Duration::from_secs(1))
                .expect("explicit synthetic completion loss release");
        });
        let _ = capture_tx.send(capture);
    });
    let udps = RwLock::new(None);
    let relays = RwLock::new(Some(fixture.transport().clone()));
    // Poll and cancel the actual original slow caller. It owns continuous emit
    // from real encryption through its PhysicalAttempt; no manual publisher.
    let mut send = Box::pin(encrypt_then_send_with_deadline(
        f.delivery.clone(),
        &transport,
        &f.peers,
        f.record.generation,
        false,
        &udps,
        &relays,
        true,
        Some(Instant::now() + Duration::from_secs(1)),
        None,
    ));
    assert!(
        budget
            .step(poll_fn(|cx| Poll::Ready(matches!(
                send.as_mut().poll(cx),
                Poll::Pending
            ))))
            .await
    );
    budget.step(entered_rx).await.unwrap();
    let capture = budget.step(capture_rx).await.unwrap();
    assert_eq!(
        f.record.physical_publication.state(),
        PhysicalPublicationState::Open
    );
    assert!(transport.try_acquire_outbound_emit_guard(PEER).is_none());
    assert!(capture.branches().unwrap()[0].original().is_some());
    drop(send);
    assert!(transport.try_acquire_outbound_emit_guard(PEER).is_some());
    assert!(f.peers.network_epoch_gate().try_lock_owned().is_ok());
    assert!(relays.try_write().is_ok());
    let record = f.record.physical_publication.record().unwrap();
    assert!(record.udp().is_none());
    assert_eq!(record.encryption_generation(), f.record.generation);
    assert_eq!(record.encryption().session_instance(), instance);
    assert!(
        record.encryption().encrypted_at()
            <= record
                .relay()
                .unwrap()
                .original()
                .unwrap()
                .write_started_at()
    );
    let pointer = record as *const _;
    release_tx.send(()).unwrap();
    let frame = fixture.next_frame(budget).await;
    let wire = frame.parse_forward_payload().unwrap().1;
    assert_eq!(
        record.relay().unwrap().wire(),
        (
            wire.len(),
            crate::transport::wire_counter(wire),
            crate::transport::wire_fingerprint(wire)
        )
    );
    assert_eq!(
        remote.decrypt_from_bytes(wire).unwrap(),
        f.record.original_packet()
    );
    assert_eq!(
        record.qualify(&f.record, Instant::now()),
        PhysicalInputQualification::UnknownRelayPublication
    );
    assert_eq!(
        pointer,
        f.record.physical_publication.record().unwrap() as *const _
    );
    assert_eq!(Arc::strong_count(&f.record), 1);
    drop(relays);
    fixture.finish(budget).await;
    // The synthetic synchronous hook blocks one worker for at most 1s. Both
    // registered variants explicitly use two workers; this is no global
    // emit-acquisition→Recorded visibility fence for unrelated observers.
}
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn b19_actual_full_completion_loss_owner_cancel_records() {
    full_then_owner_cancel(WriterPath::General).await;
}
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn b19_multiworker_owner_drop_seals_releases_emit_and_publishes() {
    full_then_owner_cancel(WriterPath::LegacyAddress).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn b19_accepted_pending_cancel_late_full_is_history_only() {
    let budget = Budget::new();
    let (f, transport, mut fixture, mut remote) = admitted(WriterPath::General, budget).await;
    let (capture_tx, mut capture_rx) = tokio::sync::oneshot::channel();
    let _setup = install_relay_capture_setup_for_test(&f.record, move |storage, packet| {
        let _ = capture_tx.send(storage.relay_for_test(packet));
    });
    let gate = fixture.gate();
    let udps = RwLock::new(None);
    let relays = RwLock::new(Some(fixture.transport().clone()));
    let (late_tx, late_rx) = tokio::sync::oneshot::channel();
    let capture;
    {
        // Explicit original prewrite gate barrier. No await in this lexical
        // std Mutex guard scope; destroy the actual original outer future.
        let _guard = gate.lock().unwrap();
        let mut send = Box::pin(encrypt_then_send_with_deadline(
            f.delivery.clone(),
            &transport,
            &f.peers,
            f.record.generation,
            false,
            &udps,
            &relays,
            true,
            Some(Instant::now() + Duration::from_secs(1)),
            None,
        ));
        let mut context = std::task::Context::from_waker(std::task::Waker::noop());
        assert!(matches!(send.as_mut().poll(&mut context), Poll::Pending));
        capture = capture_rx
            .try_recv()
            .expect("actual original owner setup reached before handoff");
        let cell = &capture.branches().unwrap()[0];
        cell.after_original_for_test(move || {
            let _ = late_tx.send(());
        });
        assert!(cell.original().is_none());
        assert!(transport.try_acquire_outbound_emit_guard(PEER).is_none());
        drop(send);
        assert_eq!(
            f.record.physical_publication.state(),
            PhysicalPublicationState::CancelledOrUncertain
        );
        assert!(f.record.physical_publication.record().is_none());
        assert!(transport.try_acquire_outbound_emit_guard(PEER).is_some());
    }
    budget.step(late_rx).await.unwrap();
    let cell = &capture.branches().unwrap()[0];
    assert!(cell.original().is_some());
    assert!(matches!(capture.finish(), RelayCaptureOutcome::Uncertain));
    assert_eq!(
        f.record.physical_publication.state(),
        PhysicalPublicationState::CancelledOrUncertain
    );
    assert!(f.record.physical_publication.record().is_none());
    let frame = fixture.next_frame(budget).await;
    assert_eq!(
        remote
            .decrypt_from_bytes(frame.parse_forward_payload().unwrap().1)
            .unwrap(),
        f.record.original_packet()
    );
    let (_next, prepared) = encrypt_existing(&f, &transport, budget).await;
    assert!(
        prepared.open().is_err(),
        "late old fact cannot reopen a canonical terminal"
    );
    drop(relays);
    fixture.finish(budget).await;
}

#[tokio::test]
async fn b19_typed_prewrite_retry_uses_new_b_counter_and_attempt() {
    let budget = Budget::new();
    let (f, transport, mut fixture, mut remote) = admitted(WriterPath::General, budget).await;
    let udps = RwLock::new(None);
    let relays = RwLock::new(Some(fixture.transport().clone()));
    fixture.set_live(false);
    let first = budget
        .step(encrypt_then_send_with_deadline(
            f.delivery.clone(),
            &transport,
            &f.peers,
            f.record.generation,
            false,
            &udps,
            &relays,
            true,
            Some(Instant::now() + Duration::from_secs(1)),
            None,
        ))
        .await;
    let retry = match first {
        EncryptSendOutcome::Retryable {
            packet,
            reason_code: REASON_RELAY_SEND_NOT_HANDED,
            ..
        } => packet,
        _ => panic!("actual original typed prewrite must retain plaintext"),
    };
    assert_eq!(
        f.record.physical_publication.state(),
        PhysicalPublicationState::DefinitelyNotHanded
    );
    assert!(f.record.physical_publication.record().is_none());
    assert_eq!(retry.packet, f.record.original_packet());
    assert!(transport.try_acquire_outbound_emit_guard(PEER).is_some());
    let second_started = Instant::now();
    fixture.set_live(true);
    assert!(matches!(
        budget
            .step(encrypt_then_send_with_deadline(
                retry,
                &transport,
                &f.peers,
                f.record.generation,
                false,
                &udps,
                &relays,
                true,
                Some(Instant::now() + Duration::from_secs(1)),
                None
            ))
            .await,
        EncryptSendOutcome::Sent
    ));
    let frame = fixture.next_frame(budget).await;
    let wire = frame.parse_forward_payload().unwrap().1;
    assert_eq!(crate::transport::wire_counter(wire), Some(1));
    assert_eq!(
        remote.decrypt_from_bytes(wire).unwrap(),
        f.record.original_packet()
    );
    let record = f.record.physical_publication.record().unwrap();
    assert_eq!(record.attempt_id(), 2);
    assert!(record.encryption().encrypted_at() >= second_started);
    assert!(record.udp().is_none());
    assert_eq!(record.relay().unwrap().wire().1, Some(1));
    assert_eq!(
        record.qualify(&f.record, Instant::now()),
        PhysicalInputQualification::UnknownRelayPublication
    );
    drop(relays);
    fixture.finish(budget).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn b19_original_fanout_first_full_with_other_unknown() {
    let budget = Budget::new();
    let (f, transport, mut first, mut remote) = admitted(WriterPath::General, budget).await;
    let mut second = Fixture::start(WriterPath::LegacyAddress, f.peers.clone(), budget).await;
    // This first ciphertext is used only by an explicitly synthetic PREWRITE
    // rejection that stalls the second original writer, never a full fact.
    let (stall_packet, unused_prepared) = encrypt_existing(&f, &transport, budget).await;
    drop(unused_prepared);
    let (stalled_rx, release_tx, stall_task) = second.stall_writer((*stall_packet).clone());
    eprintln!("B19 phase=fanout-stall-entered");
    budget.step(stalled_rx).await.unwrap();
    first.fanout_with(&second);
    let (full_tx, full_rx) = tokio::sync::oneshot::channel();
    let (capture_tx, capture_rx) = tokio::sync::oneshot::channel();
    let _setup = install_relay_capture_setup_for_test(&f.record, move |storage, packet| {
        let capture = storage.relay_for_test(packet);
        capture.after_full_for_test(move || {
            let _ = full_tx.send(());
        });
        let _ = capture_tx.send(capture);
    });
    let udps = RwLock::new(None);
    let relays = RwLock::new(Some(first.transport().clone()));
    let pending_send = encrypt_then_send_with_deadline(
        f.delivery.clone(),
        &transport,
        &f.peers,
        f.record.generation,
        false,
        &udps,
        &relays,
        true,
        Some(Instant::now() + Duration::from_secs(1)),
        None,
    );
    // Force the first Pending before writer enqueue; retain the deadline above.
    let mut send = Box::pin(async move {
        tokio::task::yield_now().await;
        pending_send.await
    });
    eprintln!("B19 phase=fanout-initial-send-pending");
    assert!(
        budget
            .step(poll_fn(|cx| Poll::Ready(matches!(
                send.as_mut().poll(cx),
                Poll::Pending
            ))))
            .await
    );
    eprintln!("B19 phase=fanout-first-full-drive");
    budget
        .step(async {
            tokio::select! {
                biased;
                full = full_rx => full.unwrap(),
                _ = &mut send => panic!("B19 original caller completed before first FULL"),
            }
        })
        .await;
    eprintln!("B19 phase=fanout-capture");
    let capture = budget.step(capture_rx).await.unwrap();
    let branches = capture.branches().unwrap();
    assert_eq!(branches.len(), 2);
    let late_cell = branches
        .iter()
        .find(|cell| cell.endpoint() == second.transport().endpoint())
        .unwrap()
        .clone();
    assert!(late_cell.original().is_none());
    let (late_tx, late_rx) = tokio::sync::oneshot::channel();
    late_cell.after_original_for_test(move || {
        let _ = late_tx.send(());
    });
    drop(send);
    let record = f.record.physical_publication.record().unwrap();
    assert_eq!(
        record.relay().unwrap().endpoint(),
        first.transport().endpoint()
    );
    let pointer = record as *const _;
    eprintln!("B19 phase=fanout-first-frame");
    let a = first.next_frame(budget).await;
    let wire = a.parse_forward_payload().unwrap().1;
    assert_eq!(crate::transport::wire_counter(wire), Some(1));
    assert_eq!(
        remote.decrypt_from_bytes(wire).unwrap(),
        f.record.original_packet()
    );
    eprintln!("B19 phase=fanout-release-before-join");
    release_tx.send(()).unwrap();
    eprintln!("B19 phase=fanout-stall-owned-join");
    assert!(matches!(
        budget.step(stall_task).await.unwrap(),
        Err(crate::error::DaemonError::RelaySend {
            error: p2pnet_relay::RelayError::WriteBoundaryRejected,
            ..
        })
    ));
    eprintln!("B19 phase=fanout-late-original-cell");
    budget.step(late_rx).await.unwrap();
    assert!(late_cell.original().is_some());
    eprintln!("B19 phase=fanout-second-frame");
    let b = second.next_frame(budget).await;
    assert_eq!(b.parse_forward_payload().unwrap().1, wire);
    assert!(matches!(capture.finish(), RelayCaptureOutcome::Uncertain));
    assert_eq!(
        pointer,
        f.record.physical_publication.record().unwrap() as *const _
    );
    assert_eq!(
        record.relay().unwrap().endpoint(),
        first.transport().endpoint()
    );
    assert!(record.udp().is_none());
    assert!(transport.try_acquire_outbound_emit_guard(PEER).is_some());
    drop(relays);
    eprintln!("B19 phase=fanout-first-fixture-finish");
    first.finish(budget).await;
    eprintln!("B19 phase=fanout-second-fixture-finish");
    second.finish(budget).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
async fn b19_stall_writer_allows_runtime_sibling_progress() {
    let budget = Budget::new();
    let (f, transport, fixture, _remote) = admitted(WriterPath::General, budget).await;
    let (packet, unused_prepared) = encrypt_existing(&f, &transport, budget).await;
    drop(unused_prepared);
    let (entered_rx, release_tx, stall_task) = fixture.stall_writer((*packet).clone());
    eprintln!("B19 phase=stall-control-entered");
    budget.step(entered_rx).await.unwrap();

    let (marker_tx, marker_rx) = std::sync::mpsc::sync_channel(1);
    // This owned observer always releases the callback before reporting.
    // 250ms is strictly below the unchanged one-second stall barrier.
    let observer = std::thread::spawn(move || {
        let progressed = marker_rx.recv_timeout(Duration::from_millis(250)).is_ok();
        let released = release_tx.send(()).is_ok();
        (progressed, released)
    });
    let sibling = tokio::spawn(async move {
        let _ = marker_tx.send(());
    });

    // The test's multithread block_on caller joins the bounded std observer.
    // No release sender remains retained by cleanup after this join.
    let (progressed, released) = observer.join().expect("B19 owned observer join");
    eprintln!(
        "B19 phase=stall-control-release-before-cleanup progressed={progressed} released={released}"
    );
    budget.step(sibling).await.unwrap();
    let stall_outcome = budget.step(stall_task).await.unwrap();
    fixture.finish(budget).await;

    // Both Tokio handles and the fixture server are joined before assertions.
    assert!(released, "B19 stall control release must precede cleanup");
    assert!(
        progressed,
        "B19 runtime sibling must run while synthetic PREWRITE remains stalled"
    );
    assert!(matches!(
        stall_outcome,
        Err(crate::error::DaemonError::RelaySend {
            error: p2pnet_relay::RelayError::WriteBoundaryRejected,
            ..
        })
    ));
}

#[tokio::test]
async fn b19_actual_pending_injection_release_keeps_finite_qualification() {
    use crate::dataplane::DataPlane;
    use crate::overlay_requests::{
        send_overlay_payloads_with_publication_gate_for_test, InjectionPublicationGate,
    };
    use crate::request_carriage::test_support::{mint_input_request, LOCAL_VIP};
    let budget = Budget::new();
    let input = budget.step(mint_input_request()).await;
    let peers = input.peers.clone();
    let (mut plane, mut routed) = DataPlane::new_with_request_carriage(input.tun, peers.clone());
    budget
        .step(plane.read_and_route_once(&mut [0u8; 512]))
        .await
        .unwrap();
    drop(budget.step(routed.recv()).await.unwrap());
    drop(input.record);
    let mut fixture = Fixture::start(WriterPath::General, peers.clone(), budget).await;
    let generation = peers.current_network_generation_sync();
    budget
        .step(peers.mark_relay_transport_ready(PEER, fixture.transport().endpoint(), generation))
        .await;
    assert!(
        budget
            .step(peers.confirm_relay_peer(PEER, fixture.transport().endpoint(), generation))
            .await
    );
    let gate = InjectionPublicationGate::new();
    let mut nonce = 0x19_0000;
    let mut seq = 19;
    let mut stats = crate::OverlayStats {
        sent: 0,
        received_valid: 0,
        received_invalid: 0,
        verified_round_trips: 0,
        last_seq: 0,
    };
    let mut retained = HashMap::new();
    let mut order = std::collections::VecDeque::new();
    let mut minter = Box::pin(send_overlay_payloads_with_publication_gate_for_test(
        &input.controller,
        &peers,
        LOCAL_VIP,
        true,
        None,
        &mut nonce,
        &mut seq,
        &mut stats,
        &mut retained,
        &mut order,
        &gate,
    ));
    budget.step(async { tokio::select! { ()=gate.reached.notified()=>{}, _=&mut minter=>panic!("real injection must pause at original publication gate") } }).await;
    budget
        .step(plane.read_and_route_once(&mut [0u8; 512]))
        .await
        .unwrap();
    let delivery = budget.step(routed.recv()).await.unwrap();
    let request = delivery.binding().unwrap().token().request().unwrap();
    assert!(!request.injection_accepted());
    let (session, mut remote) = sessions();
    let (transport, _rx) = WireGuardTransport::new_with_request_carriage();
    budget
        .step(transport.replace_session_for_lifecycle(
            PEER,
            session,
            request.expected_target_lifecycle().unwrap(),
        ))
        .await;
    let udps = RwLock::new(None);
    let relays = RwLock::new(Some(fixture.transport().clone()));
    assert!(matches!(
        budget
            .step(encrypt_then_send_with_deadline(
                delivery,
                &transport,
                &peers,
                request.generation,
                false,
                &udps,
                &relays,
                true,
                Some(Instant::now() + Duration::from_secs(1)),
                None
            ))
            .await,
        EncryptSendOutcome::Sent
    ));
    let frame = fixture.next_frame(budget).await;
    assert_eq!(
        remote
            .decrypt_from_bytes(frame.parse_forward_payload().unwrap().1)
            .unwrap(),
        request.original_packet()
    );
    let record = request.physical_publication.record().unwrap();
    assert!(record.udp().is_none());
    assert!(record.relay().is_some());
    assert_eq!(
        record.qualify(&request, Instant::now()),
        PhysicalInputQualification::PendingInjection
    );
    gate.release.notify_one();
    assert_eq!(budget.step(minter).await, 1);
    assert!(Arc::ptr_eq(retained.get(&nonce).unwrap(), &request));
    assert!(std::ptr::eq(
        record,
        request.physical_publication.record().unwrap()
    ));
    assert_eq!(
        record.qualify(&request, Instant::now()),
        PhysicalInputQualification::UnknownRelayPublication
    );
    drop(relays);
    fixture.finish(budget).await;
}
