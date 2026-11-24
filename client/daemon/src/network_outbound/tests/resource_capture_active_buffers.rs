//! Actual slow-send owners; no modeled counter calls replace the path hooks.

use super::super::test_support::*;
use super::*;
use crate::config::Config;
use crate::dataplane_resources::{
    BufferSnapshot, BufferStage, ResidencySnapshot, ResidencyStage, ResourceCapture,
};
use crate::relay::publication_test_support::{Budget, Fixture, WriterPath};
use futures_util::FutureExt;
use std::panic::AssertUnwindSafe;
use tokio::net::UdpSocket;
use tokio::sync::oneshot;
use tokio::time::{timeout_at, Instant as TokioInstant};

const STAGES: [BufferStage; 4] = [
    BufferStage::ActiveOriginal,
    BufferStage::RetryPlaintext,
    BufferStage::PreparationPlaintext,
    BufferStage::SerializedWire,
];

#[derive(Clone, Copy)]
struct Position {
    buffers: [BufferSnapshot; 4],
    observed: [bool; 4],
    valid: bool,
    residency: ResidencySnapshot,
}

fn position(capture: &ResourceCapture) -> Position {
    let snapshot = capture.snapshot();
    Position {
        buffers: STAGES.map(|stage| snapshot.buffer(stage)),
        observed: STAGES.map(|stage| snapshot.buffer_scope_observed(stage)),
        valid: snapshot.valid,
        residency: capture.residency_snapshot(),
    }
}

fn raw_packet() -> Vec<u8> {
    Ipv4Packet::build_icmp_echo_request(
        "10.20.0.1".parse().unwrap(),
        "10.20.0.2".parse().unwrap(),
        3,
        4,
        b"active-owner",
    )
}

fn packet(raw: Vec<u8>) -> OutboundPacket {
    OutboundPacket {
        room_authorization: None,
        peer_id: "peer-a".into(),
        dst_ip: "10.20.0.2".into(),
        packet: raw,
        trace: None,
    }
}

fn assert_released(capture: &ResourceCapture) {
    let snapshot = capture.snapshot();
    assert!(snapshot.valid);
    let owners = capture.residency_snapshot();
    assert!(owners.coherent && owners.valid);
    assert_eq!(owners.total.unwrap().live_buffers, 0);
    assert_eq!(owners.gap_bits, 0);
    assert!(!snapshot.coherent);
    assert!(!snapshot.active_attempt_bytes_measured);
    assert!(!snapshot.total_pipeline_bytes_measured);
    assert!(!snapshot.relay_writer_bytes_measured);
    assert!(!snapshot.crypto_temporaries_measured);
    for stage in STAGES {
        assert_eq!(snapshot.buffer(stage), BufferSnapshot::default());
    }
}

#[tokio::test]
async fn actual_preparation_live_owners_cancel_and_join_release_before_positive_assertion() {
    let cleanup = TokioInstant::now() + Duration::from_secs(5);
    let work = cleanup - Duration::from_secs(1);
    let capture = ResourceCapture::new([0xc1; 16]);
    let peers = Arc::new(PeerManager::new(
        Config::generate_default("https://ctrl.test", "net1").unwrap(),
    ));
    peers
        .add_peer(&test_peer("peer-a", "127.0.0.1:41000".parse().unwrap()))
        .await;
    let (session, _) = establish_sessions();
    let (transport, mut receiver) = WireGuardTransport::new();
    let transport = transport.with_resource_capture(capture.clone()).unwrap();
    assert!(!transport.add_session("peer-a", session).await);
    let held = timeout_at(work, transport.acquire_outbound_emit_guard("peer-a"))
        .await
        .unwrap();
    let raw = raw_packet();
    let len = raw.len() as u64;
    let capacity = raw.capacity() as u64;
    let (ready, ready_rx) = oneshot::channel();
    let worker_transport = transport.clone();
    let worker_peers = peers.clone();
    let mut worker = tokio::spawn(async move {
        let udps = RwLock::new(None);
        let relays = RwLock::new(None);
        let mut attempt = Box::pin(encrypt_then_send_with_deadline(
            packet(raw),
            &worker_transport,
            &worker_peers,
            worker_peers.current_network_generation_sync(),
            true,
            &udps,
            &relays,
            false,
            Some(Instant::now() + Duration::from_secs(3)),
            None,
        ));
        // Readiness comes from polling the original future, independently of
        // whether any new observation hook exists in a negative-control source.
        let pending = matches!(
            futures_util::poll!(attempt.as_mut()),
            std::task::Poll::Pending
        );
        let _ = ready.send(pending);
        std::future::pending::<()>().await;
    });
    let ready = timeout_at(work, ready_rx).await;
    let live = position(&capture);
    worker.abort();
    let joined = timeout_at(cleanup, &mut worker).await;
    drop(held);
    capture.finish();
    assert!(joined.unwrap().unwrap_err().is_cancelled());
    assert!(
        ready.unwrap().unwrap(),
        "actual held preparation must be pending"
    );
    assert!(matches!(
        receiver.try_recv(),
        Err(mpsc::error::TryRecvError::Empty)
    ));
    assert_released(&capture);
    assert!(live.valid);
    for (i, stage) in STAGES.iter().enumerate().take(3) {
        assert!(
            live.observed[i],
            "real preparation owner {:?} hook missing after cleanup",
            stage
        );
        assert_eq!(live.buffers[i].live_buffers, 1);
        assert_eq!(live.buffers[i].len, len);
        assert!(live.buffers[i].capacity >= len);
    }
    assert_eq!(live.buffers[0].capacity, capacity);
    assert!(live.residency.coherent && live.residency.valid);
    assert_eq!(live.residency.unknown_bits, 1); // This fixture starts at the send entry.
    assert_eq!(live.residency.total.unwrap().live_buffers, 3);
    assert_eq!(live.residency.total.unwrap().len_bytes, 3 * len);
    assert_eq!(
        live.residency.total.unwrap().capacity_bytes,
        live.buffers[..3].iter().map(|b| b.capacity).sum::<u64>()
    );
    for stage in [
        ResidencyStage::DetachedRaw,
        ResidencyStage::RetryPlaintext,
        ResidencyStage::PreparationPlaintext,
    ] {
        assert_eq!(live.residency.stage(stage).unwrap().live_buffers, 1);
    }
    assert_eq!(live.residency.clone_ops, Some(2));
    assert!(!live.observed[3]);
    assert_eq!(live.buffers[3], BufferSnapshot::default());
}

#[tokio::test]
async fn actual_successful_udp_slow_send_observes_each_local_owner_and_releases() {
    timeout(Duration::from_secs(3), async {
        let capture = ResourceCapture::new([0xc2; 16]);
        let receiver = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let endpoint = receiver.local_addr().unwrap();
        let peers = Arc::new(PeerManager::new(
            Config::generate_default("https://ctrl.test", "net1").unwrap(),
        ));
        peers.add_peer(&test_peer("peer-a", endpoint)).await;
        let udp = UdpTransport::bind("127.0.0.1:0".parse().unwrap(), peers.clone())
            .await
            .unwrap();
        peers
            .record_direct_probe_success_with_latency_and_local_endpoint(
                "peer-a",
                endpoint,
                Some(Duration::from_millis(1)),
                Some(udp.local_addr().unwrap()),
            )
            .await;
        peers
            .record_direct_success_with_local_endpoint(
                "peer-a",
                Some(endpoint),
                Some(udp.local_addr().unwrap()),
            )
            .await;
        let (_, socket) = udp.socket_for_peer(None).await.unwrap();
        let weak_socket = Arc::downgrade(&socket);
        drop(socket);
        let (session, mut remote) = establish_sessions();
        let (transport, _raw) = WireGuardTransport::new();
        let transport = transport.with_resource_capture(capture.clone()).unwrap();
        assert!(!transport.add_session("peer-a", session).await);
        let raw = raw_packet();
        let udps = RwLock::new(Some(udp));
        let relays = RwLock::new(None);
        let result = encrypt_then_send_with_deadline(
            packet(raw.clone()),
            &transport,
            &peers,
            peers.current_network_generation_sync(),
            true,
            &udps,
            &relays,
            false,
            Some(Instant::now() + Duration::from_secs(2)),
            None,
        )
        .await;
        let mut bytes = [0; 2048];
        let (n, _) = receiver.recv_from(&mut bytes).await.unwrap();
        let decrypted = remote.decrypt_from_bytes(&bytes[..n]).unwrap();
        drop(udps);
        drop(receiver);
        drop(transport);
        timeout(Duration::from_secs(1), async {
            while weak_socket.strong_count() != 0 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("original local UDP socket owner released");
        capture.finish();
        assert!(matches!(result, EncryptSendOutcome::Sent));
        assert_eq!(decrypted, raw);
        assert_released(&capture);
        for stage in STAGES {
            assert!(capture.snapshot().buffer_scope_observed(stage));
        }
    })
    .await
    .expect("bounded actual UDP owner workflow");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn actual_relay_writer_wait_retains_only_retry_and_serialized_local_owners() {
    let budget = Budget::new();
    let capture = ResourceCapture::new([0xc3; 16]);
    // This is a Relay writer ownership case. Configure the original selector
    // before peer admission; prefer_direct=false at send time does not clear
    // an already-started Direct-first preference window.
    let mut config = Config::generate_default("https://ctrl.test", "net1").unwrap();
    config.relay.path_policy = crate::config::PathPolicy::RelayOnly;
    let peers = Arc::new(PeerManager::new(config));
    budget
        .step(peers.add_peer(&test_peer("peer-a", "127.0.0.1:41000".parse().unwrap())))
        .await;
    let mut fixture = Fixture::start(WriterPath::General, peers.clone(), budget).await;
    budget
        .step(peers.mark_relay_transport_ready(
            "peer-a",
            fixture.transport().endpoint(),
            peers.current_network_generation_sync(),
        ))
        .await;
    assert!(
        budget
            .step(peers.confirm_relay_peer(
                "peer-a",
                fixture.transport().endpoint(),
                peers.current_network_generation_sync()
            ))
            .await
    );
    let (session, mut remote) = establish_sessions();
    let (transport, _raw) = WireGuardTransport::new();
    let transport = transport.with_resource_capture(capture.clone()).unwrap();
    assert!(!budget.step(transport.add_session("peer-a", session)).await);
    let (entered, release, blocker) = fixture.stall_writer(EncryptedPeerPacket {
        room_authorization: None,
        peer_id: "peer-a".into(),
        dst_ip: "10.20.0.2".into(),
        wire_bytes: vec![0; 32],
        is_business: true,
    });
    let mut blocker = Some(blocker);
    let mut release = Some(release);
    let body = AssertUnwindSafe(async {
        budget.step(entered).await.unwrap();
        let raw = raw_packet();
        let udps = RwLock::new(None);
        let relays = RwLock::new(Some(fixture.transport().clone()));
        let weak_client = fixture.weak_client();
        let mut attempt = Box::pin(encrypt_then_send_with_deadline(
            packet(raw.clone()),
            &transport,
            &peers,
            peers.current_network_generation_sync(),
            false,
            &udps,
            &relays,
            true,
            Some(Instant::now() + Duration::from_secs(1)),
            None,
        ));
        let pending = match futures_util::poll!(attempt.as_mut()) {
            std::task::Poll::Pending => true,
            std::task::Poll::Ready(outcome) => {
                // Preserve the actual premature result; never poll a completed
                // send future again. The outer catch still joins held owners.
                let reason = match outcome {
                    EncryptSendOutcome::Sent | EncryptSendOutcome::SentWithTuning(_) => {
                        "Sent".to_string()
                    }
                    EncryptSendOutcome::BudgetPending { reason, .. }
                    | EncryptSendOutcome::Retryable { reason, .. }
                    | EncryptSendOutcome::RetryableLocalBackpressure { reason, .. }
                    | EncryptSendOutcome::Terminal { reason, .. } => reason,
                };
                panic!("original Relay send completed before held writer observation: {reason}");
            }
        };
        let live = position(&capture);
        let released = release.take().unwrap().send(());
        let blocked = budget.step(blocker.as_mut().unwrap()).await;
        drop(blocker.take());
        let result = budget.step(attempt).await;
        let frame = fixture.next_frame(budget).await;
        let (destination, bytes) = frame.parse_forward_payload().unwrap();
        let destination = destination.to_string();
        let decrypted = remote.decrypt_from_bytes(bytes).unwrap();
        drop(relays);
        drop(transport);
        fixture.finish_joined(budget).await;
        budget
            .step(async {
                while weak_client.strong_count() != 0 {
                    tokio::task::yield_now().await;
                }
            })
            .await;
        capture.finish();
        assert!(released.is_ok());
        assert!(blocked.unwrap().is_err());
        assert!(pending);
        assert!(matches!(result, EncryptSendOutcome::Sent));
        assert_eq!(destination, "peer-a");
        assert_eq!(decrypted, raw);
        assert_released(&capture);
        assert!(live.valid);
        assert!(live.residency.coherent && live.residency.valid);
        assert_eq!(live.residency.total.unwrap().live_buffers, 2);
        assert_eq!(
            live.residency.total.unwrap().capacity_bytes,
            live.buffers[1].capacity + live.buffers[3].capacity
        );
        assert_eq!(
            live.residency
                .stage(ResidencyStage::RetryPlaintext)
                .unwrap()
                .live_buffers,
            1
        );
        assert_eq!(
            live.residency
                .stage(ResidencyStage::SerializedWire)
                .unwrap()
                .live_buffers,
            1
        );
        assert_eq!(
            live.residency
                .stage(ResidencyStage::DetachedRaw)
                .unwrap()
                .live_buffers,
            0
        );
        assert_eq!(
            live.residency
                .stage(ResidencyStage::PreparationPlaintext)
                .unwrap()
                .live_buffers,
            0
        );
        assert_eq!(live.residency.clone_ops, Some(2));
        assert_eq!(live.buffers[0], BufferSnapshot::default());
        assert_eq!(live.buffers[2], BufferSnapshot::default());
        for i in [1, 3] {
            assert!(
                live.observed[i],
                "real held send owner {:?} hook missing after cleanup",
                STAGES[i]
            );
            assert_eq!(live.buffers[i].live_buffers, 1);
            assert!(live.buffers[i].len > 0);
            assert!(live.buffers[i].capacity >= live.buffers[i].len);
        }
    })
    .catch_unwind()
    .await;
    // The positive Budget remains 2s/1s. Failure cleanup releases the actual
    // blocking callback before aborting and joining its retained original task.
    if let Some(release) = release.take() {
        let _ = release.send(());
    }
    let cleanup = TokioInstant::now() + Duration::from_secs(1);
    let joined = if let Some(task) = blocker.as_mut() {
        task.abort();
        let result = timeout_at(cleanup, task).await;
        if result.is_ok() {
            drop(blocker.take());
        }
        Some(result)
    } else {
        None
    };
    let server = fixture.abort_and_join_server(cleanup).await;
    if let Some(joined) = joined {
        assert!(
            matches!(joined, Ok(Ok(_)))
                || matches!(joined, Ok(Err(ref error)) if error.is_cancelled()),
            "actual held Relay task did not join after cleanup: {joined:?}"
        );
    }
    assert!(
        server.is_ok(),
        "actual fixture server did not join: {server:?}"
    );
    if let Err(panic) = body {
        std::panic::resume_unwind(panic);
    }
}
