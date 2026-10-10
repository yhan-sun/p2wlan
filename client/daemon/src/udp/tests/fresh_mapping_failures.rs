use super::*;

const PEER: &str = "peer-b";

struct Fixture {
    peers: Arc<PeerManager>,
    transport: Arc<UdpTransport>,
    nat: SimulatedNat,
    peer_receiver: UdpSocket,
    predecessor: FreshMappingResult,
    predecessor_socket: Arc<UdpSocket>,
    predecessor_pin: PeerSocketPin,
    prediction_created_at: Instant,
    event_count: usize,
}

impl Fixture {
    async fn new() -> Self {
        let (peers, transport, mut nat) = generation_env().await;
        let peer_receiver = nat.take_peer_private_socket();
        let predecessor = accepted_result(
            transport
                .run_fresh_mapping_generation(
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
        let (index, predecessor_socket) = transport.socket_for_peer(Some(PEER)).await.unwrap();
        assert_eq!(index, predecessor.socket_index);
        assert_eq!(
            predecessor_socket.local_addr().unwrap(),
            predecessor.socket_local_endpoint
        );
        let predecessor_pin = {
            let state = transport.socket_state.lock().await;
            assert_eq!(state.dynamic.len(), 1);
            assert_eq!(state.dynamic[&index].phase, DynamicSocketPhase::Finalized);
            *state.affinity.get(PEER).unwrap()
        };
        let prediction_created_at = peers.fresh_mapping_for_peer(PEER).await.unwrap().created_at;
        let event_count = peers
            .diagnostics()
            .await
            .into_iter()
            .find(|peer| peer.node_id == PEER)
            .expect("the fixture peer must be present in diagnostics")
            .direct_events
            .len();
        let fixture = Self {
            peers,
            transport,
            nat,
            peer_receiver,
            predecessor,
            predecessor_socket,
            predecessor_pin,
            prediction_created_at,
            event_count,
        };
        // This is a real authenticated Probe received beyond the simulated
        // NAT. Kernel acceptance alone is not used as the fixture's wire proof.
        fixture
            .observe_probe(fixture.predecessor.socket_local_endpoint)
            .await;
        fixture
    }

    async fn replacement(&self, attempts: u32) -> FreshMappingOutcome {
        self.transport
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

    async fn replacement_with_cancellation(
        &self,
        attempts: u32,
        cancellation: &Arc<crate::PunchSessionCancellation>,
    ) -> FreshMappingOutcome {
        self.transport
            .run_fresh_mapping_generation(
                PEER,
                &self.nat.observers,
                Duration::from_millis(500),
                &[self.nat.peer_public],
                Duration::ZERO,
                attempts,
                Some(cancellation),
            )
            .await
    }

    async fn assert_gate_context(&self, context: &FreshMappingGateContext) {
        assert_eq!(context.peer_id, PEER);
        assert_ne!(context.socket_index, self.predecessor.socket_index);
        assert_eq!(
            context.network_generation,
            self.predecessor.network_generation
        );
        assert!(context.punch_generation > self.predecessor.punch_generation);
        let state = self.transport.socket_state.lock().await;
        let entry = state
            .dynamic
            .get(&context.socket_index)
            .expect("gate must identify the real attached provisional socket");
        assert_eq!(entry.peer_id, context.peer_id);
        assert_eq!(entry.network_generation, context.network_generation);
        assert_eq!(entry.punch_generation, context.punch_generation);
        assert_eq!(entry.phase, DynamicSocketPhase::Provisional);
        assert_eq!(entry.authenticated_evidence, 0);
        assert!(!entry.hard_hard_exclusive);
    }

    async fn observe_probe(&self, expected_local: SocketAddr) {
        let key = self.peers.probe_key_for_peer(PEER).await.unwrap();
        let generation = self.peers.current_network_generation_sync();
        timeout(Duration::from_secs(1), async {
            let mut bytes = [0u8; 2048];
            loop {
                let (length, source) = self.peer_receiver.recv_from(&mut bytes).await.unwrap();
                let actual_local = self
                    .nat
                    .mapping_sources
                    .lock()
                    .await
                    .get(&source.port())
                    .copied();
                if actual_local != Some(expected_local) {
                    continue;
                }
                let Some(packet) = decode_authenticated_punch_packet(&bytes[..length], &key) else {
                    continue;
                };
                assert_eq!(packet.kind, PunchPacketKind::Punch);
                assert_eq!(packet.source_node_id.as_deref(), Some("peer-a"));
                assert_eq!(packet.target_node_id.as_deref(), Some(PEER));
                assert_eq!(packet.generation, Some(generation));
                assert!(packet.authenticated && packet.use_candidate);
                assert_eq!(source.ip(), self.nat.nat_ip);
                return;
            }
        })
        .await
        .expect("the exact measured source socket must deliver an authenticated peer-facing Probe");
    }

    async fn assert_predecessor_and_cleanup(&self, marker: &[u8]) {
        {
            let state = self.transport.socket_state.lock().await;
            assert_eq!(
                state.dynamic.len(),
                1,
                "rejected generation must remove its provisional entry"
            );
            assert_eq!(state.affinity.get(PEER), Some(&self.predecessor_pin));
            assert_eq!(
                state.committed_punch_generations.get(PEER),
                Some(&self.predecessor.punch_generation)
            );
            let entry = &state.dynamic[&self.predecessor.socket_index];
            assert_eq!(entry.peer_id, PEER);
            assert_eq!(
                entry.network_generation,
                self.predecessor.network_generation
            );
            assert_eq!(entry.punch_generation, self.predecessor.punch_generation);
            assert_eq!(entry.phase, DynamicSocketPhase::Finalized);
            assert!(
                !entry.reader.is_finished(),
                "the predecessor reader must remain live"
            );
            assert!(Arc::ptr_eq(&entry.socket, &self.predecessor_socket));
        }
        {
            let pending = self.transport.pending_probes.lock().await;
            assert!(
                pending
                    .values()
                    .all(|probe| probe.socket_index == self.predecessor.socket_index),
                "no pending probe may retain the failed replacement's socket"
            );
        }
        assert!(self
            .transport
            .hard_hard_probe_bindings
            .lock()
            .await
            .is_empty());
        let prediction = self.peers.fresh_mapping_for_peer(PEER).await.unwrap();
        assert_eq!(
            prediction.punch_generation,
            self.predecessor.punch_generation
        );
        assert_eq!(
            prediction.network_generation,
            self.predecessor.network_generation
        );
        assert_eq!(prediction.socket_index, self.predecessor.socket_index);
        assert_eq!(
            prediction.socket_local_endpoint,
            self.predecessor.socket_local_endpoint
        );
        assert_eq!(prediction.predicted_ports, self.predecessor.predicted_ports);
        assert_eq!(prediction.public_ip, self.predecessor.public_ip);
        assert_eq!(prediction.created_at, self.prediction_created_at);
        assert!(
            !self.peers.is_direct(PEER).await,
            "zero-success replacement cannot promote Direct"
        );

        // Both rounds may have STUN mappings. Only the predecessor may have
        // a peer-facing mapping: a failed replacement emitted no peer probe.
        let sources = self
            .nat
            .mappings
            .lock()
            .await
            .keys()
            .filter(|(_, destination)| *destination == self.nat.peer_public)
            .map(|(source, _)| *source)
            .collect::<HashSet<_>>();
        assert_eq!(
            sources,
            HashSet::from([self.predecessor.socket_local_endpoint])
        );

        let (index, socket) = self.transport.socket_for_peer(Some(PEER)).await.unwrap();
        assert_eq!(index, self.predecessor.socket_index);
        assert!(Arc::ptr_eq(&socket, &self.predecessor_socket));
        let receiver = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        assert_eq!(
            socket
                .send_to(marker, receiver.local_addr().unwrap())
                .await
                .unwrap(),
            marker.len()
        );
        let mut bytes = [0u8; 128];
        let (length, source) = timeout(Duration::from_secs(1), receiver.recv_from(&mut bytes))
            .await
            .expect("preserved predecessor must still deliver a real datagram")
            .unwrap();
        assert_eq!(&bytes[..length], marker);
        assert_eq!(source, self.predecessor.socket_local_endpoint);
    }

    async fn skipped_event(&self) -> crate::peer::DirectTraversalEventDiagnostics {
        self.peers
            .diagnostics()
            .await
            .into_iter()
            .find(|peer| peer.node_id == PEER)
            .expect("the fixture peer must remain present in diagnostics")
            .direct_events
            .into_iter()
            .skip(self.event_count)
            .find(|event| event.stage == "fresh_mapping_skipped")
            .expect("zero-success generation must retain its existing skipped event")
    }

    fn physical_calls(&self) -> usize {
        self.transport
            .probe_send_failure_hook
            .lock()
            .unwrap()
            .as_ref()
            .expect("the per-transport failure seam is armed")
            .physical_send_attempt
    }

    async fn assert_successful_replacement(&self, replacement: FreshMappingResult) {
        assert!(replacement.punch_generation > self.predecessor.punch_generation);
        assert_ne!(replacement.socket_index, self.predecessor.socket_index);
        assert_eq!(replacement.model.confidence, 95);
        assert_eq!(replacement.model.deltas, vec![1, 1]);
        self.observe_probe(replacement.socket_local_endpoint).await;
        let (index, socket) = self.transport.socket_for_peer(Some(PEER)).await.unwrap();
        assert_eq!(index, replacement.socket_index);
        assert_eq!(
            socket.local_addr().unwrap(),
            replacement.socket_local_endpoint
        );
        let state = self.transport.socket_state.lock().await;
        assert_eq!(state.affinity[PEER].socket_index, replacement.socket_index);
        assert_eq!(state.dynamic.len(), 1);
        assert_eq!(state.dynamic[&index].phase, DynamicSocketPhase::Finalized);
        assert!(!state.dynamic.contains_key(&self.predecessor.socket_index));
        assert!(Arc::ptr_eq(&state.dynamic[&index].socket, &socket));
        drop(state);
        assert!(
            self.peers
                .diagnostics()
                .await
                .into_iter()
                .find(|peer| peer.node_id == PEER)
                .expect("the replacement peer must remain present in diagnostics")
                .direct_events
                .iter()
                .skip(self.event_count)
                .all(|event| event.stage != "fresh_mapping_skipped"),
            "a successful primary must not enter the zero-success rejection branch"
        );
    }
}

fn assert_rejected_label(outcome: &FreshMappingOutcome) {
    match outcome {
        FreshMappingOutcome::Rejected(reason) => assert_eq!(reason.label(), "no_probes_sent"),
        FreshMappingOutcome::Accepted(..) => {
            panic!("zero successful probes must never return Accepted")
        }
    }
}

// Only an output contract is examined here. These strings are never parsed
// to choose a send, owner, path, cleanup, budget or test injection. Once the
// production payload exists, typed assertions can supplement this contract.
fn assert_display_fields(event: &crate::peer::DirectTraversalEventDiagnostics, fields: &[String]) {
    for field in fields {
        assert!(
            event
                .detail
                .split_ascii_whitespace()
                .any(|token| token == field.as_str()),
            "fresh_mapping_skipped must preserve {field}; actual detail: {:?}",
            event.detail
        );
    }
    assert_eq!(
        event.sent_probes,
        Some(0),
        "the known zero successful-send count must be explicit"
    );
}

#[tokio::test]
async fn fresh_mapping_physical_failures_preserve_predecessor_and_report_costs() {
    let fixture = Fixture::new().await;
    let key = fixture.peers.probe_key_for_peer(PEER).await.unwrap();
    let packet_length = p2pnet_nat::build_authenticated_punch_packet_with_nomination(
        "peer-a",
        PEER,
        fixture.predecessor.network_generation,
        true,
        &key,
    )
    .0
    .len();
    let _failures = fixture.transport.set_probe_send_failures_for_test([1, 2]);
    let outcome = fixture.replacement(2).await;
    assert_rejected_label(&outcome);
    assert_eq!(
        fixture.physical_calls(),
        2,
        "both primary sends must reach the actual send abstraction"
    );
    fixture
        .assert_predecessor_and_cleanup(b"n01-06-physical-predecessor")
        .await;
    let event = fixture.skipped_event().await;
    assert_eq!(event.endpoint, Some(fixture.nat.peer_public.to_string()));
    assert_eq!(event.candidate_count, Some(1));
    assert_display_fields(
        &event,
        &[
            "first_failure=physical_send".into(),
            "logical_calls_attempted=2".into(),
            "successful_primary_sends=0".into(),
            "physical_send_errors=2".into(),
            format!("physical_send_error_bytes={}", packet_length * 2),
        ],
    );
}

#[tokio::test]
async fn fresh_mapping_zero_attempts_report_empty_failure_costs_and_keep_predecessor() {
    let fixture = Fixture::new().await;
    // Arm a real seam so its call count is observable; attempts=0 must never
    // consume it. STUN measurement does not use this peer-Probe abstraction.
    let _failures = fixture.transport.set_probe_send_failures_for_test([1]);
    let outcome = fixture.replacement(0).await;
    assert_rejected_label(&outcome);
    assert_eq!(
        fixture.physical_calls(),
        0,
        "zero attempts cannot invent a failed syscall"
    );
    fixture
        .assert_predecessor_and_cleanup(b"n01-06-zero-attempt-predecessor")
        .await;
    let event = fixture.skipped_event().await;
    assert_display_fields(
        &event,
        &[
            "first_failure=none".into(),
            "logical_calls_attempted=0".into(),
            "successful_primary_sends=0".into(),
            "physical_send_errors=0".into(),
            "physical_send_error_bytes=0".into(),
        ],
    );
}

#[tokio::test]
async fn fresh_mapping_successful_replacement_delivers_authenticated_probe_control() {
    let fixture = Fixture::new().await;
    assert!(fixture
        .transport
        .probe_send_failure_hook
        .lock()
        .unwrap()
        .is_none());
    let replacement = accepted_result(fixture.replacement(1).await).await;
    fixture.assert_successful_replacement(replacement).await;
}

#[tokio::test]
async fn fresh_mapping_primary_success_survives_compatibility_send_failure_control() {
    let fixture = Fixture::new().await;
    // The first primary send succeeds; only its compatibility copy fails.
    // Retransmit tasks use socket.send_to directly and do not consume this
    // transaction's per-transport failure seam.
    let _failures = fixture.transport.set_probe_send_failures_for_test([2]);
    let replacement = accepted_result(fixture.replacement(1).await).await;
    assert_eq!(fixture.physical_calls(), 2);
    fixture.assert_successful_replacement(replacement).await;
}

#[tokio::test]
async fn fresh_mapping_reserved_socket_reports_revoked_without_physical_cost() {
    let fixture = Fixture::new().await;
    let _failures = fixture.transport.set_probe_send_failures_for_test([1]);
    let (mut gate, arrived) = fixture
        .transport
        .set_fresh_mapping_gate_for_test(FreshMappingGateStage::AfterModelBeforeProbe, PEER);
    let (outcome, ()) = tokio::join!(
        timeout(Duration::from_secs(5), fixture.replacement(2)),
        async {
            let context = timeout(Duration::from_secs(1), arrived)
                .await
                .expect("the real model must reach the pre-Probe gate")
                .expect("the generation must report its attached socket identity");
            fixture.assert_gate_context(&context).await;
            assert!(
                fixture
                    .transport
                    .reserve_hard_hard_socket(PEER, context.socket_index)
                    .await
            );
            {
                let state = fixture.transport.socket_state.lock().await;
                let entry = state.dynamic.get(&context.socket_index).unwrap();
                assert!(entry.hard_hard_exclusive);
                assert_eq!(entry.authenticated_evidence, 0);
            }
            gate.release();
        }
    );
    let outcome = outcome.expect("the reserved ordinary generation must complete within 5s");
    assert_rejected_label(&outcome);
    assert_eq!(
        fixture.physical_calls(),
        0,
        "actual reserved-socket registration must reject before physical send"
    );
    fixture
        .assert_predecessor_and_cleanup(b"n01-06-reserved-predecessor")
        .await;
    let event = fixture.skipped_event().await;
    assert_eq!(event.endpoint, Some(fixture.nat.peer_public.to_string()));
    assert_eq!(event.candidate_count, Some(1));
    assert_display_fields(
        &event,
        &[
            "first_failure=socket_revoked".into(),
            "logical_calls_attempted=2".into(),
            "successful_primary_sends=0".into(),
            "physical_send_errors=0".into(),
            "physical_send_error_bytes=0".into(),
        ],
    );
}

#[tokio::test]
async fn fresh_mapping_cancelled_after_zero_send_snapshot_is_superseded_after_cleanup() {
    let fixture = Fixture::new().await;
    let cancellation = Arc::new(crate::PunchSessionCancellation::default());
    let _failures = fixture.transport.set_probe_send_failures_for_test([1, 2]);
    let (mut gate, arrived) = fixture
        .transport
        .set_fresh_mapping_gate_for_test(FreshMappingGateStage::BeforeZeroCleanup, PEER);
    let (outcome, ()) = tokio::join!(
        timeout(
            Duration::from_secs(5),
            fixture.replacement_with_cancellation(2, &cancellation)
        ),
        async {
            let context = timeout(Duration::from_secs(1), arrived)
                .await
                .expect("both actual failed sends must reach the cached-cancel cleanup gate")
                .expect("the generation must report its attached socket identity");
            fixture.assert_gate_context(&context).await;
            assert!(
                !cancellation.is_cancelled(),
                "the old cancellation snapshot must be false"
            );
            assert_eq!(fixture.physical_calls(), 2);
            cancellation.cancel();
            assert!(cancellation.is_cancelled());
            gate.release();
        }
    );
    let outcome = outcome.expect("explicitly cancelled generation must finish cleanup within 5s");
    assert_eq!(fixture.physical_calls(), 2);
    fixture
        .assert_predecessor_and_cleanup(b"n01-06-late-cancel-predecessor")
        .await;
    let event = fixture.skipped_event().await;
    assert_eq!(event.endpoint, Some(fixture.nat.peer_public.to_string()));
    assert_eq!(event.candidate_count, Some(1));
    assert_eq!(
        event.network_generation,
        fixture.predecessor.network_generation
    );
    assert!(
        event.detail.contains("attempts=2"),
        "existing zero-send producer event must precede the terminal outcome assertion"
    );
    // Do not assert the currently missing cost display before this specific
    // cancellation regression: the real old cached-false outcome is the RED.
    assert!(
        matches!(
            &outcome,
            FreshMappingOutcome::Rejected(FreshMappingRejection::Superseded)
        ),
        "cancellation during cleanup must return unit Superseded, got {outcome:?}"
    );
}

#[tokio::test]
async fn fresh_mapping_cancelled_while_real_detach_waits_is_superseded_after_cleanup() {
    let fixture = Fixture::new().await;
    let cancellation = Arc::new(crate::PunchSessionCancellation::default());
    let _failures = fixture.transport.set_probe_send_failures_for_test([1, 2]);
    let (mut gate, arrived) = fixture
        .transport
        .set_fresh_mapping_gate_for_test(FreshMappingGateStage::BeforeZeroCleanup, PEER);
    let workflow_deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    // This is the original future, polled directly. No spawned wrapper can
    // advance the cleanup beyond the state-lock boundary behind our back.
    let mut generation = Box::pin(fixture.replacement_with_cancellation(2, &cancellation));
    let context = timeout(Duration::from_secs(1), async {
        tokio::select! {
            arrival = arrived => arrival.expect("generation must report its real socket identity"),
            outcome = generation.as_mut() => {
                panic!("generation must park before cleanup, got {outcome:?}");
            }
        }
    })
    .await
    .expect("actual model and failed sends must reach cleanup gate within 1s");
    fixture.assert_gate_context(&context).await;
    assert!(!cancellation.is_cancelled());
    assert_eq!(fixture.physical_calls(), 2);

    // Hold the actual registry mutex, then advance the original future past
    // the gate and synchronous producer event into detach's first real await.
    let state = fixture.transport.socket_state.lock().await;
    gate.release();
    assert!(futures_util::poll!(generation.as_mut()).is_pending());
    let event_before_cancel = fixture.skipped_event().await;
    assert_eq!(
        event_before_cancel.endpoint,
        Some(fixture.nat.peer_public.to_string())
    );
    assert_eq!(event_before_cancel.candidate_count, Some(1));
    assert_eq!(
        event_before_cancel.network_generation,
        context.network_generation
    );
    assert!(event_before_cancel.detail.contains("attempts=2"));
    assert!(
        !cancellation.is_cancelled(),
        "cancel must occur inside the actual cleanup await"
    );
    assert_eq!(fixture.physical_calls(), 2);
    let entry = state
        .dynamic
        .get(&context.socket_index)
        .expect("the held registry must still contain the undetached provisional entry");
    assert_eq!(entry.peer_id, context.peer_id);
    assert_eq!(entry.network_generation, context.network_generation);
    assert_eq!(entry.punch_generation, context.punch_generation);
    assert_eq!(entry.phase, DynamicSocketPhase::Provisional);
    cancellation.cancel();
    assert!(cancellation.is_cancelled());
    drop(state);

    let outcome = tokio::time::timeout_at(workflow_deadline, generation.as_mut())
        .await
        .expect("the same original future must finish cleanup within its original 5s test bound");
    assert_eq!(fixture.physical_calls(), 2);
    fixture
        .assert_predecessor_and_cleanup(b"n01-06-detach-await-predecessor")
        .await;
    let event_after_cleanup = fixture.skipped_event().await;
    assert_eq!(event_after_cleanup.stage, event_before_cancel.stage);
    assert_eq!(event_after_cleanup.detail, event_before_cancel.detail);
    assert_eq!(event_after_cleanup.endpoint, event_before_cancel.endpoint);
    assert!(
        matches!(
            &outcome,
            FreshMappingOutcome::Rejected(FreshMappingRejection::Superseded)
        ),
        "cancellation inside the real detach await must return unit Superseded, got {outcome:?}"
    );
}
