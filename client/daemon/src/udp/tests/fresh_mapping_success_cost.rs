use super::*;

async fn actual_returned_probe_cost(compatibility_error: bool) {
    let _serial = crate::tests::HARD_HARD_E2E_SERIAL.acquire().await.unwrap();
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
    let udp = UdpTransport::bind("127.0.0.1:0".parse().unwrap(), peers.clone())
        .await
        .unwrap()
        .with_local_node_id("peer-a");
    // No inbound reader or burst task is started. This ConnectivityCheck has
    // use_candidate=false and thus exercises only the original returned call.
    let (index, socket) = udp.socket_for_peer(Some("peer-b")).await.unwrap();
    let source = socket.local_addr().unwrap();
    let legacy = peers.peer_requires_legacy_probe("peer-b").await;
    assert!(
        legacy,
        "fixture must exercise the original compatibility send"
    );
    // This original classification control injects Err; it is not evidence
    // of a genuine kernel compatibility error (covered separately).
    let _failure = compatibility_error.then(|| udp.set_probe_send_failures_for_test([2]));
    let result = udp
        .send_probe_on_socket_result_with_hard_hard_token_classified(
            index,
            socket,
            Some("peer-b"),
            destination,
            false,
            PendingProbePurpose::ConnectivityCheck,
            None,
            false,
            None,
        )
        .await
        .unwrap();
    let mut summary = FreshMappingProbeSummary::default();
    summary.record_call();
    summary.record_success(&result);
    let expected = if compatibility_error { 1 } else { 2 };
    let mut physical_bytes = 0;
    for _ in 0..expected {
        let mut bytes = [0u8; 2048];
        let (length, actual_source) =
            timeout(Duration::from_secs(1), receiver.recv_from(&mut bytes))
                .await
                .unwrap()
                .unwrap();
        assert_eq!(actual_source, source);
        physical_bytes += length as u64;
    }
    // Assertions use actual receiver lengths, not a fabricated successful result.
    assert_eq!(summary.successful_primary_sends, 1);
    assert_eq!(summary.success_cost.datagrams, expected);
    assert_eq!(summary.success_cost.bytes, physical_bytes);
    assert_eq!(summary.success_cost.first_socket_index, Some(index));
    assert!(!summary.success_cost.multiple_socket_indices);
    assert_eq!(summary.success_cost.missing_primary_timestamps, 0);
    assert_eq!(
        summary.success_cost.first_observed_primary_at_ms,
        result.first_send_at_ms
    );
    assert_eq!(
        summary.success_cost.last_observed_primary_at_ms,
        result.first_send_at_ms
    );
    assert!(result
        .first_send_at_ms
        .is_some_and(|at| at <= monotonic_millis()));
    assert_eq!(summary.physical_send_errors, u64::from(compatibility_error));
    assert_eq!(
        summary.physical_send_error_bytes,
        if compatibility_error {
            build_punch_packet_with_nonce(result.nonce).len() as u64
        } else {
            0
        }
    );
    assert!(!summary.counters_saturated);
}

#[tokio::test]
async fn n01_returned_success_counts_actual_primary_and_compatibility_datagrams() {
    actual_returned_probe_cost(false).await;
}

#[tokio::test]
async fn n01_returned_compatibility_failure_keeps_actual_primary_cost() {
    actual_returned_probe_cost(true).await;
}

#[test]
fn n01_returned_success_preserves_missing_times_socket_changes_and_saturation() {
    let mut summary = FreshMappingProbeSummary::default();
    for (socket_index, first_send_at_ms) in [(1, Some(8)), (2, None), (1, Some(3))] {
        summary.record_success(&ProbeSendResult {
            nonce: [0; 8],
            datagrams_sent: 2,
            physical_bytes_sent: 100,
            socket_index,
            first_send_at_ms,
            physical_send_errors: 0,
            physical_send_error_bytes: 0,
        });
    }
    assert_eq!(summary.success_cost.datagrams, 6);
    assert_eq!(summary.success_cost.bytes, 300);
    assert_eq!(summary.success_cost.first_observed_primary_at_ms, Some(3));
    assert_eq!(summary.success_cost.last_observed_primary_at_ms, Some(8));
    assert_eq!(summary.success_cost.missing_primary_timestamps, 1);
    assert_eq!(summary.success_cost.first_socket_index, Some(1));
    assert!(summary.success_cost.multiple_socket_indices);
    summary.success_cost.datagrams = u64::MAX;
    summary.success_cost.bytes = u64::MAX;
    summary.record_success(&ProbeSendResult {
        nonce: [0; 8],
        datagrams_sent: 1,
        physical_bytes_sent: 1,
        socket_index: 1,
        first_send_at_ms: None,
        physical_send_errors: 0,
        physical_send_error_bytes: 0,
    });
    assert_eq!(summary.success_cost.datagrams, u64::MAX);
    assert_eq!(summary.success_cost.bytes, u64::MAX);
    assert!(summary.counters_saturated);
    assert!(
        FreshMappingOutcome::Rejected(FreshMappingRejection::Superseded)
            .ordinary_probe_summary()
            .is_none()
    );
}
