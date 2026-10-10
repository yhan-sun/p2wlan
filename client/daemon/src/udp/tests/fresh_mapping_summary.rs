use super::*;

const PEER: &str = "peer-b";

// An independent fixture: no visibility change to the frozen red tests.
struct PayloadFixture {
    peers: Arc<PeerManager>,
    udp: Arc<UdpTransport>,
    nat: SimulatedNat,
    _peer_receiver: UdpSocket,
    predecessor: FreshMappingResult,
    pin: PeerSocketPin,
    socket: Arc<UdpSocket>,
}

impl PayloadFixture {
    async fn new() -> Self {
        let (peers, udp, mut nat) = generation_env().await;
        let peer_receiver = nat.take_peer_private_socket();
        let predecessor = accepted_result(
            udp.run_fresh_mapping_generation(
                PEER,
                &nat.observers,
                Duration::from_millis(500),
                &[nat.peer_public],
                Duration::ZERO,
                1,
                None,
            )
            .await,
        )
        .await;
        let (index, socket) = udp.socket_for_peer(Some(PEER)).await.unwrap();
        assert_eq!(index, predecessor.socket_index);
        let pin = udp.socket_state.lock().await.affinity[PEER];
        let key = peers.probe_key_for_peer(PEER).await.unwrap();
        timeout(Duration::from_secs(1), async {
            let mut bytes = [0u8; 2048];
            loop {
                let (length, source) = peer_receiver.recv_from(&mut bytes).await.unwrap();
                if nat
                    .mapping_sources
                    .lock()
                    .await
                    .get(&source.port())
                    .copied()
                    != Some(predecessor.socket_local_endpoint)
                {
                    continue;
                }
                let Some(packet) = decode_authenticated_punch_packet(&bytes[..length], &key) else {
                    continue;
                };
                assert_eq!(packet.kind, PunchPacketKind::Punch);
                assert_eq!(packet.source_node_id.as_deref(), Some("peer-a"));
                assert_eq!(packet.target_node_id.as_deref(), Some(PEER));
                assert_eq!(packet.generation, Some(predecessor.network_generation));
                assert!(packet.authenticated && packet.use_candidate);
                break;
            }
        })
        .await
        .expect("real predecessor authenticated Probe must reach the modeled peer");
        Self {
            peers,
            udp,
            nat,
            _peer_receiver: peer_receiver,
            predecessor,
            pin,
            socket,
        }
    }

    async fn replacement(&self, attempts: u32) -> FreshMappingOutcome {
        self.udp
            .run_fresh_mapping_generation(
                PEER,
                &self.nat.observers,
                Duration::from_millis(500),
                &[self.nat.peer_public],
                Duration::ZERO,
                attempts,
                None,
            )
            .await
    }

    async fn assert_preserved(&self, marker: &[u8]) {
        {
            let state = self.udp.socket_state.lock().await;
            assert_eq!(state.dynamic.len(), 1);
            assert_eq!(state.affinity[PEER], self.pin);
            assert_eq!(
                state.committed_punch_generations[PEER],
                self.predecessor.punch_generation
            );
            let entry = &state.dynamic[&self.predecessor.socket_index];
            assert_eq!(entry.phase, DynamicSocketPhase::Finalized);
            assert_eq!(entry.peer_id, PEER);
            assert_eq!(
                entry.network_generation,
                self.predecessor.network_generation
            );
            assert_eq!(entry.punch_generation, self.predecessor.punch_generation);
            assert!(Arc::ptr_eq(&entry.socket, &self.socket));
            assert!(!entry.reader.is_finished());
        }
        assert!(self
            .udp
            .pending_probes
            .lock()
            .await
            .values()
            .all(|probe| probe.socket_index == self.predecessor.socket_index));
        let prediction = self.peers.fresh_mapping_for_peer(PEER).await.unwrap();
        assert_eq!(
            prediction.punch_generation,
            self.predecessor.punch_generation
        );
        assert_eq!(prediction.socket_index, self.predecessor.socket_index);
        assert_eq!(
            prediction.socket_local_endpoint,
            self.predecessor.socket_local_endpoint
        );
        assert!(!self.peers.is_direct(PEER).await);
        let (index, socket) = self.udp.socket_for_peer(Some(PEER)).await.unwrap();
        assert_eq!(index, self.predecessor.socket_index);
        assert!(Arc::ptr_eq(&socket, &self.socket));
        let receiver = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        socket
            .send_to(marker, receiver.local_addr().unwrap())
            .await
            .unwrap();
        let mut bytes = [0u8; 128];
        let (length, source) = timeout(Duration::from_secs(1), receiver.recv_from(&mut bytes))
            .await
            .expect("original selected socket must still deliver on real UDP")
            .unwrap();
        assert_eq!(&bytes[..length], marker);
        assert_eq!(source, self.predecessor.socket_local_endpoint);
    }
}

fn returned_summary(outcome: FreshMappingOutcome) -> FreshMappingProbeSummary {
    match outcome {
        FreshMappingOutcome::Rejected(FreshMappingRejection::NoProbesSent(summary)) => {
            assert_eq!(
                FreshMappingRejection::NoProbesSent(summary).label(),
                "no_probes_sent"
            );
            summary
        }
        other => panic!("expected completed zero-success typed payload, got {other:?}"),
    }
}

#[tokio::test]
async fn fresh_mapping_returned_physical_failure_summary_has_exact_cost() {
    let fixture = PayloadFixture::new().await;
    let key = fixture.peers.probe_key_for_peer(PEER).await.unwrap();
    let bytes = build_authenticated_punch_packet_with_nomination(
        "peer-a",
        PEER,
        fixture.predecessor.network_generation,
        true,
        &key,
    )
    .0
    .len() as u64;
    let _errors = fixture.udp.set_probe_send_failures_for_test([1, 2]);
    let summary = returned_summary(fixture.replacement(2).await);
    fixture.assert_preserved(b"n01-06-typed-physical").await;
    assert_eq!(
        summary,
        FreshMappingProbeSummary {
            logical_calls_attempted: 2,
            first_failure: Some(ProbeSendFailureKind::PhysicalSend),
            failures: FreshMappingProbeFailureCounts {
                physical_send: 2,
                ..Default::default()
            },
            physical_send_errors: 2,
            physical_send_error_bytes: bytes * 2,
            ..Default::default()
        }
    );
}

#[tokio::test]
async fn fresh_mapping_returned_zero_attempt_summary_has_no_invented_cause() {
    let fixture = PayloadFixture::new().await;
    let _errors = fixture.udp.set_probe_send_failures_for_test([1]);
    let summary = returned_summary(fixture.replacement(0).await);
    fixture.assert_preserved(b"n01-06-typed-zero").await;
    assert_eq!(summary, FreshMappingProbeSummary::default());
    assert_eq!(
        fixture
            .udp
            .probe_send_failure_hook
            .lock()
            .unwrap()
            .as_ref()
            .unwrap()
            .physical_send_attempt,
        0
    );
}

#[tokio::test]
async fn fresh_mapping_returned_revoked_summary_has_zero_physical_cost() {
    let fixture = PayloadFixture::new().await;
    let _errors = fixture.udp.set_probe_send_failures_for_test([1]);
    let (mut gate, arrived) = fixture
        .udp
        .set_fresh_mapping_gate_for_test(FreshMappingGateStage::AfterModelBeforeProbe, PEER);
    let (outcome, ()) = tokio::join!(
        timeout(Duration::from_secs(5), fixture.replacement(2)),
        async {
            let context = timeout(Duration::from_secs(1), arrived)
                .await
                .unwrap()
                .unwrap();
            assert_eq!(context.peer_id, PEER);
            assert_eq!(
                context.network_generation,
                fixture.predecessor.network_generation
            );
            assert!(context.punch_generation > fixture.predecessor.punch_generation);
            assert_ne!(context.socket_index, fixture.predecessor.socket_index);
            assert!(
                fixture
                    .udp
                    .reserve_hard_hard_socket(PEER, context.socket_index)
                    .await
            );
            gate.release();
        }
    );
    let summary = returned_summary(outcome.unwrap());
    fixture.assert_preserved(b"n01-06-typed-revoked").await;
    assert_eq!(
        summary,
        FreshMappingProbeSummary {
            logical_calls_attempted: 2,
            first_failure: Some(ProbeSendFailureKind::SocketRevoked),
            failures: FreshMappingProbeFailureCounts {
                socket_revoked: 2,
                ..Default::default()
            },
            ..Default::default()
        }
    );
    assert_eq!(
        fixture
            .udp
            .probe_send_failure_hook
            .lock()
            .unwrap()
            .as_ref()
            .unwrap()
            .physical_send_attempt,
        0
    );
}

#[test]
fn summary_preserves_all_twelve_typed_kinds_and_first_failure() {
    // Pure enum inputs test the aggregator, not twelve real ordinary races.
    let kinds = [
        ProbeSendFailureKind::PhysicalSend,
        ProbeSendFailureKind::PreHandoffTimeout,
        ProbeSendFailureKind::NetworkGenerationChanged,
        ProbeSendFailureKind::CandidateEpochChanged,
        ProbeSendFailureKind::LocalProfileGenerationChanged,
        ProbeSendFailureKind::RemoteProfileGenerationChanged,
        ProbeSendFailureKind::PeerSessionChanged,
        ProbeSendFailureKind::SessionRetired,
        ProbeSendFailureKind::SocketUnavailable,
        ProbeSendFailureKind::SocketRevoked,
        ProbeSendFailureKind::ProbeRegistrationFailed,
        ProbeSendFailureKind::ProbeEncodingFailed,
    ];
    let mut summary = FreshMappingProbeSummary::default();
    for kind in kinds {
        let error = DaemonError::Network("pure typed input".into());
        let failure = if kind == ProbeSendFailureKind::PhysicalSend {
            ProbeSendFailure::with_physical_send_error(error, 137)
        } else {
            ProbeSendFailure::new(kind, error)
        };
        summary.record_call();
        summary.record_failure(&failure);
    }
    assert_eq!(
        summary.first_failure,
        Some(ProbeSendFailureKind::PhysicalSend)
    );
    assert_eq!(summary.logical_calls_attempted, 12);
    assert_eq!(summary.successful_primary_sends, 0);
    assert_eq!(summary.physical_send_errors, 1);
    assert_eq!(summary.physical_send_error_bytes, 137);
    assert_eq!(
        summary.failures,
        FreshMappingProbeFailureCounts {
            physical_send: 1,
            pre_handoff_timeout: 1,
            network_generation_changed: 1,
            candidate_epoch_changed: 1,
            local_profile_generation_changed: 1,
            remote_profile_generation_changed: 1,
            peer_session_changed: 1,
            session_retired: 1,
            socket_unavailable: 1,
            socket_revoked: 1,
            probe_registration_failed: 1,
            probe_encoding_failed: 1,
        }
    );
    assert_eq!(summary.outer_stop, None);
    assert!(!summary.counters_saturated);
    let failure = ProbeSendFailure::new(
        ProbeSendFailureKind::SocketRevoked,
        DaemonError::Network("later different cause".into()),
    );
    summary.record_call();
    summary.record_failure(&failure);
    assert_eq!(
        summary.first_failure,
        Some(ProbeSendFailureKind::PhysicalSend)
    );
    assert_eq!(summary.failures.socket_revoked, 2);
    assert_eq!(summary.physical_send_errors, 1);
    assert_eq!(summary.physical_send_error_bytes, 137);
}

#[test]
fn summary_outer_stops_are_separate_from_classified_failure() {
    for stop in [
        FreshMappingProbeStopCause::Cancelled,
        FreshMappingProbeStopCause::DirectConfirmed,
        FreshMappingProbeStopCause::NetworkGenerationChanged,
    ] {
        let mut summary = FreshMappingProbeSummary::default();
        summary.record_outer_stop(stop);
        assert_eq!(summary.outer_stop, Some(stop));
        assert_eq!(summary.first_failure, None);
        assert_eq!(summary.logical_calls_attempted, 0);
        assert_eq!(summary.failures, FreshMappingProbeFailureCounts::default());
        assert_eq!(summary.physical_send_errors, 0);
        assert_eq!(summary.physical_send_error_bytes, 0);
        summary.record_call();
        summary.record_failure(&ProbeSendFailure::new(
            ProbeSendFailureKind::NetworkGenerationChanged,
            DaemonError::Network("pure classified fence".into()),
        ));
        assert_eq!(summary.outer_stop, Some(stop));
        assert_eq!(
            summary.first_failure,
            Some(ProbeSendFailureKind::NetworkGenerationChanged)
        );
        assert_eq!(summary.failures.network_generation_changed, 1);
        assert_eq!(summary.physical_send_errors, 0);
    }
}

#[test]
fn summary_partial_copy_error_keeps_primary_success() {
    let mut summary = FreshMappingProbeSummary::default();
    for (datagrams_sent, errors, error_bytes) in [(2, 0, 0), (1, 1, 57)] {
        let result = ProbeSendResult {
            nonce: [0; 8],
            datagrams_sent,
            physical_bytes_sent: 200,
            socket_index: 123,
            first_send_at_ms: Some(7),
            physical_send_errors: errors,
            physical_send_error_bytes: error_bytes,
        };
        summary.record_call();
        summary.record_success(&result);
    }
    assert_eq!(summary.logical_calls_attempted, 2);
    assert_eq!(summary.successful_primary_sends, 2);
    assert_eq!(summary.first_failure, None);
    assert_eq!(summary.failures, FreshMappingProbeFailureCounts::default());
    assert_eq!(summary.physical_send_errors, 1);
    assert_eq!(summary.physical_send_error_bytes, 57);
    assert!(!summary.counters_saturated);
}

#[test]
fn summary_zero_and_saturated_counters_do_not_claim_exact_overflow() {
    let mut summary = FreshMappingProbeSummary::default();
    assert_eq!(summary.first_failure, None);
    assert_eq!(summary.outer_stop, None);
    assert_eq!(summary.logical_calls_attempted, 0);
    assert_eq!(summary.physical_send_errors, 0);
    assert_eq!(summary.physical_send_error_bytes, 0);
    assert!(!summary.counters_saturated);
    summary.logical_calls_attempted = u64::MAX;
    summary.record_call();
    assert_eq!(summary.logical_calls_attempted, u64::MAX);
    assert!(summary.counters_saturated);
    assert_eq!(summary.first_failure, None);
    summary.physical_send_error_bytes = u64::MAX - 1;
    summary.record_failure(&ProbeSendFailure::with_physical_send_error(
        DaemonError::Network("pure overflow input".into()),
        2,
    ));
    assert_eq!(summary.physical_send_error_bytes, u64::MAX);
    assert!(summary.counters_saturated);
}
