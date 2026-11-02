//! Real loopback ACKs exercise the original reader, matching and health owner.
use super::*;
use std::future::{poll_fn, Future};
use std::task::Poll;
use tokio::time::{timeout_at, Instant as TokioInstant};

async fn fixture() -> (UdpTransport, UdpSocket, Arc<ConsentTrace>, PendingProbe) {
    fixture_with_reachable_peer(true).await
}

async fn fixture_with_reachable_peer(
    reachable: bool,
) -> (UdpTransport, UdpSocket, Arc<ConsentTrace>, PendingProbe) {
    let peers = peer_manager();
    let remote = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let endpoint = remote.local_addr().unwrap();
    peers
        .add_peer(&peer("peer-b", "10.20.0.2", Some(endpoint)))
        .await;
    if reachable {
        peers
            .record_direct_probe_success_with_latency(
                "peer-b",
                endpoint,
                Some(Duration::from_millis(5)),
            )
            .await;
        peers.record_direct_success("peer-b", Some(endpoint)).await;
    }
    let mut udp = UdpTransport::bind("127.0.0.1:0".parse().unwrap(), peers.clone())
        .await
        .unwrap();
    let trace = Arc::new(ConsentTrace::new());
    udp.consent_trace = Some(trace.clone());
    let sent_at = Instant::now();
    let pending = PendingProbe {
        validation_preflight: None,
        sent_at,
        expires_at: sent_at + DIRECT_KEEPALIVE_ACK_TIMEOUT,
        endpoint,
        local_endpoint: Some(udp.local_addr().unwrap()),
        socket_index: 0,
        generation: peers.current_network_generation_sync(),
        remote_candidate_epoch: peers
            .current_remote_candidate_epoch("peer-b")
            .await
            .unwrap(),
        probe_session_id: None,
        peer_id: Some("peer-b".into()),
        purpose: PendingProbePurpose::ConsentCheck,
        accepts_authenticated_ack: false,
        accepts_legacy_ack: true,
        socket_epoch: 0,
        cleanup_epoch: udp.peer_probe_cleanup_epoch("peer-b").await,
        direct_commit_seq: peers.direct_commit_seq_sync("peer-b").unwrap_or(0),
    };
    (udp, remote, trace, pending)
}

async fn receive_ack(
    udp: &UdpTransport,
    remote: &UdpSocket,
    nonce: ProbeNonce,
    trace: &ConsentTrace,
    terminal: ConsentStage,
    end: TokioInstant,
) {
    let before = trace.snapshot().0.into_iter().flatten().count();
    let (tx, _rx) = mpsc::channel::<ReceivedEncryptedPacket>(1);
    let (shutdown, mut stop) = watch::channel(false);
    let mut reader =
        Box::pin(udp.run_inbound_socket_inner(0, udp.socket.clone(), tx, Some(&mut stop), None));
    let ack = build_punch_ack(nonce);
    assert_eq!(
        remote
            .send_to(&ack, udp.local_addr().unwrap())
            .await
            .unwrap(),
        ack.len()
    );
    // Poll the actual reader future itself. No bridge task, readiness sleep,
    // deadline renewal, or trace callback drives the protocol.
    timeout_at(
        end,
        poll_fn(|cx| {
            assert!(reader.as_mut().poll(cx).is_pending());
            let (events, dropped) = trace.snapshot();
            assert_eq!(dropped, 0);
            if events
                .into_iter()
                .flatten()
                .skip(before)
                .any(|event| event.nonce == nonce && event.stage == terminal)
            {
                Poll::Ready(())
            } else {
                Poll::Pending
            }
        }),
    )
    .await
    .expect("actual single ACK must reach its typed terminal before the original end");
    drop(shutdown);
    timeout_at(end, reader.as_mut()).await.unwrap().unwrap();
    // The locally owned future is collected, not a detached reader task.
}

fn stages(trace: &ConsentTrace, nonce: ProbeNonce) -> Vec<ConsentStage> {
    let (events, dropped) = trace.snapshot();
    assert_eq!(dropped, 0);
    let events: Vec<_> = events.into_iter().flatten().collect();
    assert!(events
        .windows(2)
        .all(|pair| pair[0].elapsed <= pair[1].elapsed));
    events
        .into_iter()
        .filter(|event| event.nonce == nonce)
        .map(|event| event.stage)
        .collect()
}

fn consent_ack_count(conn: &crate::peer::PeerConnection) -> usize {
    conn.direct_events
        .iter()
        .filter(|event| event.stage == "consent_ack_received")
        .count()
}

#[tokio::test]
async fn consent_trace_real_unanswered_round_records_removal_and_collects_original_burst() {
    let end = TokioInstant::now() + Duration::from_secs(2);
    let work_end = end - Duration::from_secs(1);
    let (mut udp, _remote, trace, _pending) = fixture().await;
    let _report = ConsentTraceReport(trace.clone());
    let bursts = Arc::new(ProbeBurstCaptureForTest::new());
    udp.probe_burst_capture_for_test = Some(bursts.clone());
    let before = udp.peers.get_connection("peer-b").await.unwrap();
    // Exercise the existing real send and timeout owner with no ACK producer.
    // Collect its original retransmit task even if the timed body fails.
    let round = timeout_at(
        work_end,
        udp.run_keepalive_round(Duration::from_millis(500)),
    )
    .await;
    let (count, joined) = bursts.abort_and_join_until(end).await;
    assert!(joined);
    assert_eq!(count, 1);
    round.expect("one original unanswered round must finish within work end");
    let (events, dropped) = trace.snapshot();
    assert_eq!(dropped, 0);
    let events: Vec<_> = events.into_iter().flatten().collect();
    assert_eq!(events.len(), 2);
    assert_eq!(events[0].nonce, events[1].nonce);
    assert_eq!(
        stages(&trace, events[0].nonce),
        [
            ConsentStage::SendReturned,
            ConsentStage::RoundRemovedPending
        ]
    );
    assert!(udp.pending_probes.lock().await.is_empty());
    let after = udp.peers.get_connection("peer-b").await.unwrap();
    assert_eq!(
        after.direct_health.success_count,
        before.direct_health.success_count
    );
    assert_eq!(
        after.direct_health.failure_count,
        before.direct_health.failure_count + 1
    );
    assert_eq!(after.direct_health.consecutive_failures, 1);
    assert_eq!(after.state, ConnectionState::Direct);
}

#[tokio::test]
async fn consent_trace_real_ack_commits_once_and_duplicate_or_missing_nonce_cannot_commit() {
    let end = TokioInstant::now() + Duration::from_secs(2);
    let (udp, remote, trace, pending) = fixture().await;
    let _report = ConsentTraceReport(trace.clone());
    let nonce = [0x41; 8];
    let missing = [0x42; 8];
    let before = udp.peers.get_connection("peer-b").await.unwrap();
    udp.pending_probes.lock().await.insert(nonce, pending);
    receive_ack(
        &udp,
        &remote,
        nonce,
        &trace,
        ConsentStage::HealthCommitted,
        end,
    )
    .await;
    assert_eq!(
        stages(&trace, nonce),
        [
            ConsentStage::AckDecoded,
            ConsentStage::AckHandlerEntered,
            ConsentStage::PendingLookup,
            ConsentStage::AdoptionAcquired,
            ConsentStage::EpochAcquired,
            ConsentStage::Matched,
            ConsentStage::HealthCommitted
        ]
    );
    assert!(!udp.pending_probes.lock().await.contains_key(&nonce));
    receive_ack(
        &udp,
        &remote,
        nonce,
        &trace,
        ConsentStage::NoPeerOwnedPending,
        end,
    )
    .await;
    receive_ack(
        &udp,
        &remote,
        missing,
        &trace,
        ConsentStage::NoPeerOwnedPending,
        end,
    )
    .await;
    let after = udp.peers.get_connection("peer-b").await.unwrap();
    assert_eq!(consent_ack_count(&before), 0);
    assert_eq!(consent_ack_count(&after), 1);
    assert_eq!(
        after.direct_health.success_count,
        before.direct_health.success_count + 1
    );
    assert_eq!(
        after.direct_health.failure_count,
        before.direct_health.failure_count
    );
    assert_eq!(after.state, ConnectionState::Direct);
    assert_eq!(
        stages(&trace, nonce)
            .iter()
            .filter(|s| **s == ConsentStage::HealthCommitted)
            .count(),
        1
    );
    assert_eq!(
        stages(&trace, missing),
        [
            ConsentStage::AckDecoded,
            ConsentStage::AckHandlerEntered,
            ConsentStage::PendingLookup,
            ConsentStage::NoPeerOwnedPending
        ]
    );
    let rx = udp.probe_rx_snapshot().await;
    assert_eq!(rx.legacy_probe_acks_observed, 3);
    assert_eq!(rx.legacy_probe_acks_unmatched, 2);
    assert_eq!(rx.probe_acks_received, 1);
}

#[tokio::test]
async fn consent_ack_event_survives_cancellation_after_original_health_commit() {
    let end = TokioInstant::now() + Duration::from_secs(2);
    let (udp, remote, trace, pending) = fixture_with_reachable_peer(false).await;
    let nonce = [0x45; 8];
    let endpoint = remote.local_addr().unwrap();
    let generation = pending.generation;
    let before = udp.peers.get_connection("peer-b").await.unwrap();
    udp.pending_probes.lock().await.insert(nonce, pending);
    // The original ACK commits the first reachable pair, then waits for this
    // existing feedback writer. No new production hook or scheduling sleep.
    let feedback = udp.peers.hold_recovery_ack_feedback_for_test().await;
    let connections = udp.peers.connection_map_for_test();
    let (tx, _rx) = mpsc::channel::<ReceivedEncryptedPacket>(1);
    let (shutdown, mut stop) = watch::channel(false);
    let mut reader =
        Box::pin(udp.run_inbound_socket_inner(0, udp.socket.clone(), tx, Some(&mut stop), None));
    let ack = build_punch_ack(nonce);
    let sent_at = Instant::now();
    assert_eq!(
        remote
            .send_to(&ack, udp.local_addr().unwrap())
            .await
            .unwrap(),
        ack.len()
    );
    let committed = timeout_at(
        end,
        poll_fn(|cx| {
            assert!(reader.as_mut().poll(cx).is_pending());
            let current = connections
                .try_read()
                .expect("health writer must be released");
            let conn = current.get("peer-b").unwrap();
            if conn.direct_health.success_count == before.direct_health.success_count + 1 {
                Poll::Ready(conn.clone())
            } else {
                Poll::Pending
            }
        }),
    )
    .await
    .expect("original health commit must precede the held feedback writer");
    assert!(!stages(&trace, nonce).contains(&ConsentStage::HealthCommitted));
    assert!(!udp.pending_probes.lock().await.contains_key(&nonce));
    assert_eq!(consent_ack_count(&committed), 1);
    let event = committed
        .direct_events
        .iter()
        .find(|e| e.stage == "consent_ack_received")
        .unwrap();
    assert_eq!(event.endpoint, Some(endpoint));
    assert_eq!(event.network_generation, generation);
    assert!(event.recorded_at >= sent_at && event.recorded_at <= Instant::now());
    drop(reader); // Cancel before the original handler can finish feedback.
    drop(shutdown);
    drop(feedback);
    let after = udp.peers.get_connection("peer-b").await.unwrap();
    assert_eq!(
        after.direct_health.success_count,
        committed.direct_health.success_count
    );
    assert_eq!(consent_ack_count(&after), 1);
}

#[tokio::test]
async fn ordinary_matched_probe_ack_cannot_create_consent_event() {
    let end = TokioInstant::now() + Duration::from_secs(2);
    let (udp, remote, trace, mut pending) = fixture().await;
    pending.purpose = PendingProbePurpose::ConnectivityCheck;
    let nonce = [0x46; 8];
    let before = udp.peers.get_connection("peer-b").await.unwrap();
    udp.pending_probes.lock().await.insert(nonce, pending);
    receive_ack(
        &udp,
        &remote,
        nonce,
        &trace,
        ConsentStage::HealthCommitted,
        end,
    )
    .await;
    let after = udp.peers.get_connection("peer-b").await.unwrap();
    assert_eq!(
        after.direct_health.success_count,
        before.direct_health.success_count + 1
    );
    assert_eq!(consent_ack_count(&after), 0);
}

#[tokio::test]
async fn consent_trace_expired_real_ack_retires_nonce_without_health_commit() {
    let end = TokioInstant::now() + Duration::from_secs(2);
    let (udp, remote, trace, mut pending) = fixture().await;
    let _report = ConsentTraceReport(trace.clone());
    let nonce = [0x43; 8];
    // Seed an already terminal pending entry, never a synthetic successful RTT.
    pending.expires_at = pending.sent_at;
    let before = udp.peers.get_connection("peer-b").await.unwrap();
    udp.pending_probes.lock().await.insert(nonce, pending);
    receive_ack(&udp, &remote, nonce, &trace, ConsentStage::Expired, end).await;
    assert_eq!(
        stages(&trace, nonce),
        [
            ConsentStage::AckDecoded,
            ConsentStage::AckHandlerEntered,
            ConsentStage::PendingLookup,
            ConsentStage::AdoptionAcquired,
            ConsentStage::EpochAcquired,
            ConsentStage::Expired
        ]
    );
    assert!(!udp.pending_probes.lock().await.contains_key(&nonce));
    let after = udp.peers.get_connection("peer-b").await.unwrap();
    assert_eq!(consent_ack_count(&after), 0);
    assert_eq!(
        after.direct_health.success_count,
        before.direct_health.success_count
    );
    assert_eq!(
        after.direct_health.failure_count,
        before.direct_health.failure_count
    );
    assert_eq!(udp.probe_rx_snapshot().await.probe_acks_received, 0);
}

#[tokio::test]
async fn consent_trace_real_ack_fences_all_seven_pending_identity_mismatches() {
    for control in 0..7 {
        let end = TokioInstant::now() + Duration::from_secs(2);
        let (udp, remote, trace, mut pending) = fixture().await;
        let _report = ConsentTraceReport(trace.clone());
        match control {
            0 => pending.generation += 1,
            1 => pending.remote_candidate_epoch += 1,
            2 => pending.cleanup_epoch += 1,
            3 => pending.direct_commit_seq += 1,
            4 => pending.socket_index += 1,
            5 => pending.endpoint.set_ip("127.0.0.2".parse().unwrap()),
            6 => pending.accepts_legacy_ack = false,
            _ => unreachable!(),
        }
        let nonce = [0x50 + control; 8];
        let before = udp.peers.get_connection("peer-b").await.unwrap();
        udp.pending_probes.lock().await.insert(nonce, pending);
        receive_ack(&udp, &remote, nonce, &trace, ConsentStage::Mismatch, end).await;
        assert_eq!(
            stages(&trace, nonce),
            [
                ConsentStage::AckDecoded,
                ConsentStage::AckHandlerEntered,
                ConsentStage::PendingLookup,
                ConsentStage::AdoptionAcquired,
                ConsentStage::EpochAcquired,
                ConsentStage::Mismatch
            ]
        );
        assert!(udp.pending_probes.lock().await.contains_key(&nonce));
        let after = udp.peers.get_connection("peer-b").await.unwrap();
        assert_eq!(consent_ack_count(&after), 0);
        assert_eq!(
            after.direct_health.success_count,
            before.direct_health.success_count
        );
        assert_eq!(
            after.direct_health.failure_count,
            before.direct_health.failure_count
        );
        assert_eq!(after.endpoint, before.endpoint);
        let rx = udp.probe_rx_snapshot().await;
        assert_eq!(rx.probe_acks_received, 0);
        assert_eq!(rx.legacy_probe_acks_unmatched, 1);
    }
}

#[tokio::test]
async fn consent_trace_actual_decode_precedes_diagnostics_wait_and_handler_then_commits() {
    let end = TokioInstant::now() + Duration::from_secs(2);
    let (udp, remote, trace, pending) = fixture().await;
    let _report = ConsentTraceReport(trace.clone());
    let nonce = [0x61; 8];
    let before = udp.peers.get_connection("peer-b").await.unwrap();
    udp.pending_probes.lock().await.insert(nonce, pending);
    let diagnostics = udp.hold_primary_socket_diagnostics_for_test().await;
    let (tx, _rx) = mpsc::channel::<ReceivedEncryptedPacket>(1);
    let (shutdown, mut stop) = watch::channel(false);
    let mut reader =
        Box::pin(udp.run_inbound_socket_inner(0, udp.socket.clone(), tx, Some(&mut stop), None));
    let ack = build_punch_ack(nonce);
    assert_eq!(
        remote
            .send_to(&ack, udp.local_addr().unwrap())
            .await
            .unwrap(),
        ack.len()
    );
    timeout_at(
        end,
        poll_fn(|cx| {
            assert!(reader.as_mut().poll(cx).is_pending());
            if !stages(&trace, nonce).is_empty() {
                Poll::Ready(())
            } else {
                Poll::Pending
            }
        }),
    )
    .await
    .expect("original reader must decode while diagnostics are held");
    assert_eq!(stages(&trace, nonce), [ConsentStage::AckDecoded]);
    assert!(udp.pending_probes.lock().await.contains_key(&nonce));
    assert_eq!(
        udp.peers
            .get_connection("peer-b")
            .await
            .unwrap()
            .direct_health
            .success_count,
        before.direct_health.success_count
    );
    drop(diagnostics);
    timeout_at(
        end,
        poll_fn(|cx| {
            assert!(reader.as_mut().poll(cx).is_pending());
            if stages(&trace, nonce).contains(&ConsentStage::HealthCommitted) {
                Poll::Ready(())
            } else {
                Poll::Pending
            }
        }),
    )
    .await
    .expect("original handler must commit after the real diagnostics lock is released");
    drop(shutdown);
    timeout_at(end, reader.as_mut()).await.unwrap().unwrap();
    assert_eq!(
        stages(&trace, nonce),
        [
            ConsentStage::AckDecoded,
            ConsentStage::AckHandlerEntered,
            ConsentStage::PendingLookup,
            ConsentStage::AdoptionAcquired,
            ConsentStage::EpochAcquired,
            ConsentStage::Matched,
            ConsentStage::HealthCommitted
        ]
    );
    assert_eq!(
        udp.peers
            .get_connection("peer-b")
            .await
            .unwrap()
            .direct_health
            .success_count,
        before.direct_health.success_count + 1
    );
}
