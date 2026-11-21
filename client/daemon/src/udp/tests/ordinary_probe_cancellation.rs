use super::*;
use crate::udp::ordinary_probe_cost::OrdinaryProducerSettlement;

struct OrdinaryFixture {
    udp: Arc<UdpTransport>,
    receiver: UdpSocket,
    socket: Arc<UdpSocket>,
    index: usize,
    destination: SocketAddr,
    cost: OrdinaryProbeCost,
}

impl OrdinaryFixture {
    async fn new() -> Self {
        let local = NodeIdentity::generate();
        let remote = NodeIdentity::generate();
        let receiver = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let destination = receiver.local_addr().unwrap();
        let peers = Arc::new(PeerManager::new(config_for_identity(&local, "peer-a")));
        peers
            .add_peer(&peer_with_public_key(
                "peer-b",
                "10.20.0.2",
                hex::encode(remote.public_key()),
                Some(destination),
            ))
            .await;
        let udp = Arc::new(
            UdpTransport::bind("127.0.0.1:0".parse().unwrap(), peers.clone())
                .await
                .unwrap()
                .with_local_node_id("peer-a"),
        );
        assert!(peers.peer_requires_legacy_probe("peer-b").await);
        let (index, socket) = udp.socket_for_peer(Some("peer-b")).await.unwrap();
        let cost = udp.ordinary_probe_cost(71, 0, PeerSessionGeneration::for_test(3), 8);
        Self {
            udp,
            receiver,
            socket,
            index,
            destination,
            cost,
        }
    }

    fn start(
        &self,
        deadline: tokio::time::Instant,
    ) -> (
        OrdinaryProbeTask,
        oneshot::Receiver<std::result::Result<ProbeSendResult, ProbeSendFailure>>,
    ) {
        let (tx, rx) = oneshot::channel();
        let udp = self.udp.clone();
        let socket = self.socket.clone();
        let cost = self.cost.clone();
        let index = self.index;
        let destination = self.destination;
        let task = OrdinaryProbeTask::spawn(self.cost.clone(), deadline, async move {
            // No reader, ACK task or retransmit: use_candidate remains false.
            let result = udp
                .send_ordinary_probe_classified_observed(
                    index,
                    socket,
                    Some("peer-b"),
                    destination,
                    false,
                    PendingProbePurpose::ConnectivityCheck,
                    false,
                    &cost,
                )
                .await;
            let _ = tx.send(result);
        });
        (task, rx)
    }

    async fn receive(&self, count: usize) -> std::io::Result<Vec<(usize, SocketAddr)>> {
        let mut received = Vec::new();
        for _ in 0..count {
            let mut bytes = [0u8; 2048];
            received.push(self.receiver.recv_from(&mut bytes).await?);
        }
        Ok(received)
    }
}

async fn cancelled_after_result(
    stage: OrdinaryProbeTestStage,
    expected: usize,
    kernel_error: bool,
) {
    let fixture = OrdinaryFixture::new().await;
    let gate = fixture.cost.install_gate(stage);
    if kernel_error {
        // Test-only target selection, followed by the real original IPv4
        // socket send_to against an incompatible IPv6 destination. Not an
        // injected Err or an assertion of network delivery.
        fixture
            .cost
            .set_compatibility_target("[::1]:9".parse().unwrap());
    }
    let source = fixture.socket.local_addr().unwrap();
    let identity = fixture.cost.snapshot().identity;
    let deadline = tokio::time::Instant::now() + Duration::from_secs(1);
    let (mut task, mut returned) = fixture.start(deadline);
    let observed = tokio::time::timeout_at(deadline, async {
        gate.reached.notified().await;
        fixture.receive(expected).await
    })
    .await;
    let join = task.finish(true).await;
    let snapshot = fixture.cost.snapshot();
    let returned = returned.try_recv().is_ok();
    drop(task);
    drop(fixture);
    // Every failure assertion follows original-child cancellation and join.
    let received = observed
        .expect("real loopback receipt must precede cancellation deadline")
        .expect("original receiver failed");
    assert!(join.is_some_and(|error| error.is_cancelled()));
    assert_eq!(
        snapshot.producer_settlement,
        OrdinaryProducerSettlement::CancelledJoined
    );
    assert!(!snapshot.producer_active);
    assert_eq!(snapshot.identity, identity);
    assert_eq!(snapshot.primary.accepted_datagrams, 1);
    assert_eq!(snapshot.primary.accepted_bytes, received[0].0 as u64);
    assert!(snapshot.primary.first_result_at_ms.is_some());
    assert_eq!(snapshot.primary.active_operations, 0);
    assert_eq!(snapshot.primary.missing_completions, 0);
    assert_eq!(snapshot.primary.returned_errors, 0);
    assert!(received.iter().all(|(_, actual)| *actual == source));
    assert_eq!(
        snapshot.compatibility.accepted_datagrams,
        (expected - 1) as u64
    );
    assert_eq!(
        snapshot.compatibility.accepted_bytes,
        received.iter().skip(1).map(|v| v.0 as u64).sum::<u64>()
    );
    assert_eq!(
        snapshot.compatibility.returned_errors,
        u64::from(kernel_error)
    );
    assert_eq!(
        snapshot.compatibility.error_requested_bytes,
        if kernel_error {
            build_punch_packet_with_nonce([0; 8]).len() as u64
        } else {
            0
        }
    );
    assert_eq!(snapshot.compatibility.missing_completions, 0);
    assert_eq!(snapshot.active_calls, 0);
    assert_eq!(snapshot.returned_calls, 0);
    assert_eq!(snapshot.dropped_calls, 1);
    assert!(
        !returned,
        "cancelled call need not produce a returned summary"
    );
    assert!(!snapshot.counters_saturated);
}

#[tokio::test]
async fn n01_cancel_after_actual_primary_retains_original_owner_cost() {
    let _serial = crate::tests::HARD_HARD_E2E_SERIAL.acquire().await.unwrap();
    cancelled_after_result(OrdinaryProbeTestStage::PrimaryResult, 1, false).await;
}

#[tokio::test]
async fn n01_cancel_after_actual_compatibility_retains_both_results_once() {
    let _serial = crate::tests::HARD_HARD_E2E_SERIAL.acquire().await.unwrap();
    cancelled_after_result(OrdinaryProbeTestStage::CompatibilityResult, 2, false).await;
}

#[tokio::test]
async fn n01_cancel_after_actual_compatibility_family_error_keeps_primary() {
    let _serial = crate::tests::HARD_HARD_E2E_SERIAL.acquire().await.unwrap();
    cancelled_after_result(OrdinaryProbeTestStage::CompatibilityResult, 1, true).await;
}

#[tokio::test]
async fn n01_normal_live_and_returned_views_overlap_without_a_second_total() {
    let _serial = crate::tests::HARD_HARD_E2E_SERIAL.acquire().await.unwrap();
    let fixture = OrdinaryFixture::new().await;
    let source = fixture.socket.local_addr().unwrap();
    let deadline = tokio::time::Instant::now() + Duration::from_secs(1);
    let (mut task, mut returned) = fixture.start(deadline);
    let received = tokio::time::timeout_at(deadline, fixture.receive(2)).await;
    let join = task.finish(false).await;
    let snapshot = fixture.cost.snapshot();
    let result = returned.try_recv();
    let repeated_snapshot = fixture.cost.snapshot();
    drop(task);
    drop(fixture);
    let received = received.unwrap().unwrap();
    let result = result.unwrap().unwrap();
    let mut summary = FreshMappingProbeSummary::default();
    summary.record_call();
    summary.record_success(&result);
    assert!(join.is_none());
    assert_eq!(snapshot, repeated_snapshot);
    assert_eq!(
        snapshot.producer_settlement,
        OrdinaryProducerSettlement::Joined
    );
    assert!(!snapshot.producer_active);
    assert_eq!(
        snapshot.primary.accepted_datagrams + snapshot.compatibility.accepted_datagrams,
        summary.success_cost.datagrams
    );
    assert_eq!(
        snapshot.primary.accepted_bytes + snapshot.compatibility.accepted_bytes,
        summary.success_cost.bytes
    );
    assert_eq!(
        summary.success_cost.bytes,
        received.iter().map(|r| r.0 as u64).sum::<u64>()
    );
    assert!(received.iter().all(|r| r.1 == source));
    assert_eq!(snapshot.primary.first_result_at_ms, result.first_send_at_ms);
    assert_eq!(snapshot.calls_started, 1);
    assert_eq!(snapshot.returned_calls, 1);
    assert_eq!(snapshot.dropped_calls, 0);
}

#[tokio::test]
async fn n01_real_unadmitted_dynamic_socket_is_proven_pre_handoff_unsent() {
    let _serial = crate::tests::HARD_HARD_E2E_SERIAL.acquire().await.unwrap();
    let fixture = OrdinaryFixture::new().await;
    let (index, socket) = fixture.udp.bind_fresh_punch_socket().await.unwrap();
    // A real freshly bound socket without its original dynamic ownership
    // entry cannot dispatch. The genuine classified fence is authoritative.
    let hook = fixture.udp.set_probe_send_failures_for_test([usize::MAX]);
    let deadline = tokio::time::Instant::now() + Duration::from_secs(1);
    let result = tokio::time::timeout_at(
        deadline,
        fixture.udp.send_ordinary_probe_classified_observed(
            index,
            socket,
            Some("peer-b"),
            fixture.destination,
            false,
            PendingProbePurpose::ConnectivityCheck,
            true,
            &fixture.cost,
        ),
    )
    .await;
    let actual_invocations = fixture
        .udp
        .probe_send_failure_hook
        .lock()
        .unwrap()
        .as_ref()
        .unwrap()
        .physical_send_attempt;
    let snapshot = fixture.cost.snapshot();
    drop(hook);
    drop(fixture);
    assert_eq!(
        result.unwrap().unwrap_err().kind,
        ProbeSendFailureKind::SocketUnavailable
    );
    assert_eq!(actual_invocations, 0);
    assert_eq!(snapshot.proven_pre_handoff_rejections, 1);
    assert_eq!(
        snapshot.first_pre_handoff_rejection,
        Some(ProbeSendFailureKind::SocketUnavailable)
    );
    assert_eq!(snapshot.primary.entered_operations, 0);
    assert_eq!(snapshot.primary.accepted_datagrams, 0);
    assert_eq!(snapshot.primary.missing_completions, 0);
}

#[tokio::test]
async fn n01_dropped_unresolved_operation_is_missing_not_zero_or_error() {
    let _serial = crate::tests::HARD_HARD_E2E_SERIAL.acquire().await.unwrap();
    let fixture = OrdinaryFixture::new().await;
    // Deterministic unresolved-operation seam; no fabricated kernel result.
    let gate = fixture
        .cost
        .install_gate(OrdinaryProbeTestStage::PrimaryAwait);
    let deadline = tokio::time::Instant::now() + Duration::from_secs(1);
    let (mut task, _returned) = fixture.start(deadline);
    let reached = tokio::time::timeout_at(deadline, gate.reached.notified()).await;
    let join = task.finish(true).await;
    let snapshot = fixture.cost.snapshot();
    drop(task);
    drop(fixture);
    assert!(reached.is_ok());
    assert!(join.is_some_and(|e| e.is_cancelled()));
    assert_eq!(
        snapshot.producer_settlement,
        OrdinaryProducerSettlement::CancelledJoined
    );
    assert!(!snapshot.producer_active);
    assert_eq!(snapshot.primary.entered_operations, 1);
    assert_eq!(snapshot.primary.missing_completions, 1);
    assert!(snapshot.primary.missing_completion_requested_bytes > 0);
    assert_eq!(snapshot.primary.accepted_datagrams, 0);
    assert_eq!(snapshot.primary.returned_errors, 0);
    assert_eq!(snapshot.proven_pre_handoff_rejections, 0);
    assert_eq!(snapshot.primary.first_result_at_ms, None);
}
