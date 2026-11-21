// Actual selected scheduler-child cancellation; no writer callback fault.
// General Relay only. Physical history is not current-owner/native ACK credit.

use crate::connection_timeline::ConnectionTimeline;
use crate::dataplane::DataPlane;
use crate::dataplane_resources::{QueueStage, ResourceCapture, VecSite};
use crate::network_outbound::{run_network_outbound_with_request_carriage, RelayStartupWait};
use crate::overlay_requests::{
    send_overlay_payloads, CanonicalOverlayRequest, PhysicalInputQualification,
    PhysicalPublicationState,
};
use crate::peer::PeerManager;
use crate::relay::publication_test_support::{ping_original_writer, sessions, Budget};
use crate::relay::RelayTransport;
use crate::request_carriage::test_probe::{HandoffArgumentPoint, RequestHandoffArgumentProbe};
use crate::request_carriage::test_support::{
    mint_input_request, InputRequestFixture, LOCAL_VIP, PEER,
};
use crate::transport::{
    ResourceQueueTestGate, WireGuardTransport, WorkerLossObservation, WorkerLossPoint,
};
use futures_util::FutureExt;
use p2pnet_relay::protocol::{read_frame, Frame, MSG_FORWARD, MSG_PING, MSG_REGISTER};
use p2pnet_relay::RelayMessage;
use p2pnet_tun::MockTunDevice;
use std::collections::{HashMap, VecDeque};
use std::panic::AssertUnwindSafe;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::io::AsyncWriteExt;
use tokio::net::TcpListener;
use tokio::sync::{mpsc, oneshot, watch, RwLock};
use tokio::task::JoinHandle;
use tokio::time::{timeout_at, Instant as TokioInstant};

type TestResult<T> = std::result::Result<T, String>;

#[derive(Default)]
struct OriginalRelay {
    transport: Option<RelayTransport>,
    inbound: Option<mpsc::Receiver<RelayMessage>>,
    server: Option<JoinHandle<()>>,
    stop: Option<oneshot::Sender<()>>,
    frames: Option<mpsc::Receiver<Frame>>,
    ping: Option<oneshot::Receiver<()>>,
    ping_armed: Arc<AtomicBool>,
}

impl OriginalRelay {
    async fn start(&mut self, peers: Arc<PeerManager>, budget: Budget) -> TestResult<()> {
        let listener = budget
            .step(TcpListener::bind("127.0.0.1:0"))
            .await
            .map_err(|e| e.to_string())?;
        let endpoint = format!(
            "tcp://{}",
            listener.local_addr().map_err(|e| e.to_string())?
        );
        let (frames, receiver) = mpsc::channel(4); // Same original fixture bound.
        let (stop, stopped) = oneshot::channel();
        let (ping, pinged) = oneshot::channel();
        let armed = self.ping_armed.clone();
        self.frames = Some(receiver);
        self.stop = Some(stop);
        self.ping = Some(pinged);
        // Register the real server handle in the external owner before any
        // connect/register await can fail, time out or unwind.
        self.server = Some(tokio::spawn(async move {
            let mut ping = Some(ping);
            tokio::select! {
                biased;
                _ = stopped => {},
                _ = async {
                    let (mut stream, _) = listener.accept().await.unwrap();
                    let registration = read_frame(&mut stream).await.unwrap();
                    assert_eq!(registration.msg_type, MSG_REGISTER);
                    let node = std::str::from_utf8(&registration.payload).unwrap();
                    stream.write_all(&Frame::registered(node).encode()).await.unwrap();
                    while let Ok(frame) = read_frame(&mut stream).await {
                        match frame.msg_type {
                            MSG_FORWARD => { if frames.send(frame).await.is_err() { break; } },
                            MSG_PING => {
                                if armed.load(Ordering::Acquire) {
                                    if let Some(ping) = ping.take() { let _ = ping.send(()); }
                                }
                                if stream.write_all(&Frame::new(p2pnet_relay::protocol::MSG_PONG, frame.payload).encode()).await.is_err() { break; }
                            },
                            other => panic!("unexpected original worker-loss frame {other}"),
                        }
                    }
                } => {},
            }
        }));
        let (transport, inbound) = budget
            .step(RelayTransport::connect(&endpoint, "loss-general", peers))
            .await
            .map_err(|e| e.to_string())?;
        self.transport = Some(transport);
        self.inbound = Some(inbound);
        Ok(())
    }

    fn transport(&self) -> &RelayTransport {
        self.transport.as_ref().unwrap()
    }

    async fn frame(&mut self, budget: Budget) -> Frame {
        budget
            .step(self.frames.as_mut().unwrap().recv())
            .await
            .expect("original real TCP frame")
    }
}

impl Drop for OriginalRelay {
    fn drop(&mut self) {
        if let Some(transport) = self.transport.take() {
            transport.abort_writer();
        }
        if let Some(stop) = self.stop.take() {
            let _ = stop.send(());
        }
        if let Some(task) = self.server.as_ref() {
            task.abort();
        }
    }
}

#[derive(Default)]
struct Owners {
    relay: OriginalRelay,
    plane: Option<DataPlane<MockTunDevice>>,
    forward: Option<JoinHandle<crate::error::Result<()>>>,
    actor: Option<JoinHandle<()>>,
    available: Option<watch::Sender<bool>>,
    relays: Option<Arc<RwLock<Option<RelayTransport>>>>,
    gate: Option<Arc<ResourceQueueTestGate>>,
    probe_kicks: Option<watch::Receiver<u64>>,
}

impl Drop for Owners {
    fn drop(&mut self) {
        if let Some(gate) = self.gate.as_ref() {
            gate.request_children_abort();
            gate.release();
            gate.release_loss();
        }
        if let Some(task) = self.forward.as_ref() {
            task.abort();
        }
        if let Some(task) = self.actor.as_ref() {
            task.abort();
        }
    }
}

struct Cleanup {
    explicit_tasks_held: usize,
    explicit_tasks_joined: usize,
    forward_joined: bool,
    forward_ok: bool,
    actor_joined: bool,
    server_joined: bool,
    ping_barrier: bool,
    frames_disconnected: bool,
    unexpected_frames: Vec<Frame>,
    selected_joined: bool,
    errors: Vec<String>,
}

async fn join_original<T>(
    slot: &mut Option<JoinHandle<T>>,
    end: TokioInstant,
) -> TestResult<Option<T>> {
    let Some(task) = slot.as_mut() else {
        return Ok(None);
    };
    let result = timeout_at(end, task)
        .await
        .map_err(|_| "original join deadline exceeded".to_string())?;
    drop(slot.take()); // Ready result consumed once, even on panic/cancel.
    result
        .map(Some)
        .map_err(|error| format!("original task returned JoinError: {error}"))
}

impl Owners {
    fn start_pipeline(
        &mut self,
        tun: MockTunDevice,
        transport: WireGuardTransport,
        peers: Arc<PeerManager>,
    ) {
        let (plane, routed) = DataPlane::new_with_request_carriage(tun, peers.clone());
        self.plane = Some(plane);
        let forward_transport = transport.clone();
        self.forward = Some(tokio::spawn(async move {
            forward_transport
                .run_outbound_with_request_carriage(routed)
                .await
        }));
        // The caller supplies the same original raw receiver separately.
    }

    async fn cleanup(&mut self, end: TokioInstant) -> Cleanup {
        let had_forward = self.forward.is_some();
        let had_actor = self.actor.is_some();
        let had_server = self.relay.server.is_some();
        let explicit_tasks_held =
            usize::from(had_forward) + usize::from(had_actor) + usize::from(had_server);
        if let Some(gate) = self.gate.as_ref() {
            gate.request_children_abort();
            gate.release();
            gate.release_loss();
        }
        drop(self.plane.take());
        drop(self.available.take());
        let forward = join_original(&mut self.forward, end).await;
        let actor = join_original(&mut self.actor, end).await;
        let mut errors = Vec::new();
        let forward_joined = self.forward.is_none();
        let forward_ok = matches!(&forward, Ok(Some(Ok(()))));
        if let Err(error) = forward {
            errors.push(format!("forward: {error}"));
        }
        let actor_joined = self.actor.is_none();
        if let Err(error) = actor {
            errors.push(format!("actor: {error}"));
        }
        // After the original actor joined its JoinSet, this original writer
        // PING is an ordered finite-stream barrier, not another business send.
        let ping_barrier = if actor_joined {
            if let Some(transport) = self.relay.transport.as_ref() {
                self.relay.ping_armed.store(true, Ordering::Release);
                match timeout_at(end, ping_original_writer(transport)).await {
                    Ok(Ok(())) => match timeout_at(end, self.relay.ping.as_mut().unwrap()).await {
                        Ok(Ok(())) => true,
                        other => {
                            errors.push(format!("original writer ping read: {other:?}"));
                            false
                        }
                    },
                    other => {
                        errors.push(format!("original writer ping admission: {other:?}"));
                        false
                    }
                }
            } else {
                false
            }
        } else {
            false
        };
        if let Some(relays) = self.relays.as_ref() {
            match timeout_at(end, relays.write()).await {
                Ok(mut slot) => {
                    if let Some(relay) = slot.take() {
                        relay.abort_writer();
                    }
                }
                Err(error) => errors.push(format!("original relay slot cleanup: {error}")),
            }
        }
        drop(self.relays.take());
        if let Some(transport) = self.relay.transport.take() {
            transport.abort_writer();
        }
        drop(self.relay.inbound.take());
        if let Some(stop) = self.relay.stop.take() {
            let _ = stop.send(());
        }
        let server = join_original(&mut self.relay.server, end).await;
        let server_joined = self.relay.server.is_none();
        if let Err(error) = server {
            errors.push(format!("server: {error}"));
        }
        let mut unexpected_frames = Vec::new();
        let mut frames_disconnected = self.relay.frames.is_none();
        if let Some(frames) = self.relay.frames.as_mut() {
            for _ in 0..4 {
                match frames.try_recv() {
                    Ok(frame) => unexpected_frames.push(frame),
                    Err(mpsc::error::TryRecvError::Disconnected) => {
                        frames_disconnected = true;
                        break;
                    }
                    Err(mpsc::error::TryRecvError::Empty) => break,
                }
            }
            if !frames_disconnected {
                frames_disconnected = matches!(
                    frames.try_recv(),
                    Err(mpsc::error::TryRecvError::Disconnected)
                );
            }
        }
        let selected_joined = self
            .gate
            .as_ref()
            .is_some_and(|gate| gate.selected_joined());
        let explicit_tasks_joined = usize::from(had_forward && forward_joined)
            + usize::from(had_actor && actor_joined)
            + usize::from(had_server && server_joined);
        eprintln!("b01_worker_loss_owned_cleanup: explicit_tasks_joined={explicit_tasks_joined}/{explicit_tasks_held} forward_joined={forward_joined} actor_joined={actor_joined} server_joined={server_joined} selected_child_joined={selected_joined} original_end_unchanged=true errors={errors:?}");
        Cleanup {
            explicit_tasks_held,
            explicit_tasks_joined,
            forward_joined,
            forward_ok,
            actor_joined,
            server_joined,
            ping_barrier,
            frames_disconnected,
            unexpected_frames,
            selected_joined,
            errors,
        }
    }
}

async fn mint_next(
    controller: &p2pnet_tun::mock::MockTunController,
    peers: &Arc<PeerManager>,
    previous: &CanonicalOverlayRequest,
    budget: Budget,
) -> Arc<CanonicalOverlayRequest> {
    let mut nonce = previous.nonce;
    let mut seq = previous.seq;
    let mut stats = crate::OverlayStats {
        sent: 0,
        received_valid: 0,
        received_invalid: 0,
        verified_round_trips: 0,
        last_seq: 0,
    };
    let mut retained = HashMap::new();
    let mut order = VecDeque::new();
    let count = budget
        .step(send_overlay_payloads(
            controller,
            peers,
            LOCAL_VIP,
            true,
            None,
            &mut nonce,
            &mut seq,
            &mut stats,
            &mut retained,
            &mut order,
        ))
        .await;
    assert_eq!(
        count, 1,
        "original minter must actually inject this fresh request"
    );
    retained.remove(&nonce).unwrap()
}

struct Received {
    destination: String,
    wire: (usize, Option<u64>, u64),
    plaintext: Vec<u8>,
}

fn receive(frame: Frame, remote: &mut p2pnet_wireguard::TransportSession) -> Received {
    let (destination, wire) = frame.parse_forward_payload().unwrap();
    Received {
        destination: destination.to_string(),
        wire: (
            wire.len(),
            crate::transport::wire_counter(wire),
            crate::transport::wire_fingerprint(wire),
        ),
        plaintext: remote.decrypt_from_bytes(wire).unwrap(),
    }
}

struct Observed {
    first: Arc<CanonicalOverlayRequest>,
    second: Arc<CanonicalOverlayRequest>,
    third: Arc<CanonicalOverlayRequest>,
    before_phase: PhysicalPublicationState,
    after_phase: PhysicalPublicationState,
    original_record_pointer: Option<usize>,
    pointer_after_join: Option<usize>,
    handoff_exact: bool,
    handoff_wire: (usize, Option<u64>, u64),
    instance: u64,
    selected_task_id: tokio::task::Id,
    queued_second_phase: PhysicalPublicationState,
    loss: WorkerLossObservation,
    a2_same: bool,
    old_deadline: Option<Instant>,
    held_actor_len: u64,
    held_actor_capacity: u64,
    held_valid: bool,
    held_observed: bool,
    emit_released: bool,
    reopening_refused: bool,
    frames: Vec<Received>,
    final_resources_valid: bool,
    final_actor_packets: u64,
    final_task_packets: u64,
}

async fn exercise(point: WorkerLossPoint) {
    let budget = Budget::new();
    let end = budget.original_end();
    let work_end = end - Duration::from_millis(200);
    let gate = Arc::new(ResourceQueueTestGate::for_worker_loss(work_end, point));
    let mut owners = Owners::default();
    owners.gate = Some(gate.clone());
    let body = timeout_at(
        work_end,
        AssertUnwindSafe(async {
            let InputRequestFixture {
                peers,
                controller,
                tun,
                record: first,
            } = budget.step(mint_input_request()).await;
            let second = mint_next(&controller, &peers, &first, budget).await;
            owners.relay.start(peers.clone(), budget).await?;
            budget
                .step(peers.mark_relay_transport_ready(
                    PEER,
                    owners.relay.transport().endpoint(),
                    first.generation,
                ))
                .await;
            if !budget
                .step(peers.confirm_relay_peer(
                    PEER,
                    owners.relay.transport().endpoint(),
                    first.generation,
                ))
                .await
            {
                return Err("real Relay peer admission rejected".to_string());
            }
            let resources = ResourceCapture::new([0xb1; 16]);
            let probe = Arc::new(RequestHandoffArgumentProbe::new());
            let (transport, raw) = WireGuardTransport::new_with_request_carriage();
            let transport = transport
                .with_resource_capture(resources.clone())
                .unwrap()
                .with_resource_queue_gate_for_test(gate.clone())
                .with_request_handoff_probe(probe.clone());
            let (session, mut remote) = sessions();
            budget
                .step(transport.replace_session_for_lifecycle(
                    PEER,
                    session,
                    first.expected_target_lifecycle().unwrap(),
                ))
                .await;
            let instance = budget
                .step(transport.session_status(PEER))
                .await
                .active_session_instance
                .unwrap();
            owners.start_pipeline(tun, transport.clone(), peers.clone());
            let relays = Arc::new(RwLock::new(Some(owners.relay.transport().clone())));
            owners.relays = Some(relays.clone());
            let (available, available_rx) = watch::channel(true);
            owners.available = Some(available);
            let (probe_tx, probe_rx) = watch::channel(0);
            owners.probe_kicks = Some(probe_rx);
            let actor_transport = transport.clone();
            let actor_peers = peers.clone();
            owners.actor = Some(tokio::spawn(async move {
                run_network_outbound_with_request_carriage(
                    raw.into(),
                    actor_transport,
                    actor_peers,
                    false,
                    Arc::new(RwLock::new(None)),
                    relays,
                    available_rx,
                    RelayStartupWait {
                        relay_expected: true,
                        timeout: Some(Duration::from_secs(1)),
                    },
                    probe_tx,
                    ConnectionTimeline::new("real-worker-loss", 0),
                )
                .await;
            }));
            budget
                .step(
                    owners
                        .plane
                        .as_mut()
                        .unwrap()
                        .read_and_route_once(&mut [0u8; 512]),
                )
                .await
                .unwrap();
            budget.step(gate.wait_entered()).await;
            let task = gate.task();
            let selected_task_id = task.id();
            let before_phase = first.physical_publication.state();
            let required_phase = if point == WorkerLossPoint::BeforePhysicalHandoff {
                PhysicalPublicationState::Open
            } else {
                PhysicalPublicationState::Recorded
            };
            if before_phase != required_phase {
                // A wrong entry/callback boundary is an actual state failure,
                // never a later wait for a frame which cannot exist. Still abort
                // and observe the real selected child before external cleanup.
                task.abort();
                let _ = budget.step(gate.take_loss()).await;
                gate.release_loss();
                return Err(format!(
                "saved original before-abort phase {before_phase:?}; required {required_phase:?}"
            ));
            }
            let original_record_pointer = first
                .physical_publication
                .record()
                .map(|record| record as *const _ as usize);
            let (handoff_exact, handoff_wire) = {
                let arguments = probe.recorded.lock().unwrap();
                let arguments = arguments.as_ref().unwrap();
                let request_exact = arguments
                    .token
                    .as_ref()
                    .and_then(|token| token.request())
                    .is_some_and(|original| Arc::ptr_eq(&original, &first));
                let source_exact = arguments.source.as_ref().is_some_and(|source| {
                    source.peer_id == PEER
                        && source.session_instance == instance
                        && source.authorized_peer_lifecycle == first.expected_target_lifecycle()
                        && source.belongs_to_transport
                });
                (
                    arguments.point == HandoffArgumentPoint::SlowBoundedEntry
                        && request_exact
                        && source_exact,
                    arguments.wire,
                )
            };
            budget
                .step(
                    owners
                        .plane
                        .as_mut()
                        .unwrap()
                        .read_and_route_once(&mut [0u8; 512]),
                )
                .await
                .unwrap();
            budget
                .step(async {
                    while resources
                        .snapshot()
                        .fifo(QueueStage::ActorFifo)
                        .live_packets
                        != 1
                    {
                        tokio::task::yield_now().await;
                    }
                })
                .await;
            let held = resources.snapshot();
            let queued_second_phase = second.physical_publication.state();
            let old_deadline = gate.original_delivery_deadline();
            task.abort(); // The actual original scheduler child, not a callback.
            let loss = budget.step(gate.take_loss()).await;
            let a2_same = loss
                .front_token
                .as_ref()
                .and_then(|token| token.request())
                .is_some_and(|original| Arc::ptr_eq(&original, &second));
            let after_phase = first.physical_publication.state();
            let pointer_after_join = first
                .physical_publication
                .record()
                .map(|record| record as *const _ as usize);
            let emit_released = transport.try_acquire_outbound_emit_guard(PEER).is_some();
            // Call the original CAS only for an already terminal/history owner.
            // A wrong Idle boundary must never open a synthetic first attempt.
            let reopening_refused = matches!(
                after_phase,
                PhysicalPublicationState::CancelledOrUncertain | PhysicalPublicationState::Recorded
            ) && first
                .physical_publication
                .original_reopen_is_occupied_for_test();
            gate.release_loss();
            let mut frames = Vec::new();
            if point == WorkerLossPoint::AfterRecordedSent {
                frames.push(receive(owners.relay.frame(budget).await, &mut remote));
            }
            frames.push(receive(owners.relay.frame(budget).await, &mut remote));
            budget
                .step(async {
                    while second.physical_publication.record().is_none() {
                        tokio::task::yield_now().await;
                    }
                })
                .await;
            let third = mint_next(&controller, &peers, &second, budget).await;
            budget
                .step(
                    owners
                        .plane
                        .as_mut()
                        .unwrap()
                        .read_and_route_once(&mut [0u8; 512]),
                )
                .await
                .unwrap();
            frames.push(receive(owners.relay.frame(budget).await, &mut remote));
            budget
                .step(async {
                    while third.physical_publication.record().is_none() {
                        tokio::task::yield_now().await;
                    }
                })
                .await;
            let final_position = resources.snapshot();
            // Cumulative original crypto hooks remain operation observations;
            // they do not reconstruct destroyed-child FIFO loss accounting.
            let final_resources_valid = final_position.valid
                && final_position
                    .vec_site(VecSite::TxPreparationCopy)
                    .materialization_ops
                    == 3;
            Ok::<_, String>(Observed {
                first,
                second,
                third,
                before_phase,
                after_phase,
                original_record_pointer,
                pointer_after_join,
                handoff_exact,
                handoff_wire,
                instance,
                selected_task_id,
                queued_second_phase,
                loss,
                a2_same,
                old_deadline,
                held_actor_len: held.fifo(QueueStage::ActorFifo).plaintext_len,
                held_actor_capacity: held.fifo(QueueStage::ActorFifo).vec_capacity,
                held_valid: held.valid,
                held_observed: held.fifo_scope_observed(QueueStage::ActorFifo),
                emit_released,
                reopening_refused,
                frames,
                final_resources_valid,
                final_actor_packets: final_position.fifo(QueueStage::ActorFifo).live_packets,
                final_task_packets: final_position
                    .fifo(QueueStage::TaskOrUnjoinedFifo)
                    .live_packets,
            })
        })
        .catch_unwind(),
    )
    .await;
    let cleanup = owners.cleanup(end).await;
    drop(owners);
    let observed = match body {
        Ok(Ok(result)) => result.expect("real worker-loss body failed after owned cleanup"),
        Ok(Err(panic)) => std::panic::resume_unwind(panic),
        Err(error) => {
            panic!("original 2s window reserved cleanup; body exceeded work bound: {error}")
        }
    };
    assert!(
        cleanup.errors.is_empty(),
        "original owned joins failed: {:?}",
        cleanup.errors
    );
    assert_eq!(
        (cleanup.explicit_tasks_held, cleanup.explicit_tasks_joined),
        (3, 3)
    );
    assert!(
        cleanup.forward_joined
            && cleanup.forward_ok
            && cleanup.actor_joined
            && cleanup.server_joined
            && cleanup.selected_joined
            && cleanup.ping_barrier
            && cleanup.frames_disconnected
    );
    assert!(
        cleanup.unexpected_frames.is_empty(),
        "unexpected old ciphertext after finite original writer barrier"
    );
    assert!(observed.handoff_exact && observed.emit_released && observed.reopening_refused);
    assert!(observed.loss.cancelled && observed.loss.active_removed && observed.a2_same);
    assert_eq!(
        observed.loss.task_id, observed.selected_task_id,
        "the real JoinError must be from the selected original scheduler child"
    );
    assert_eq!(
        observed.queued_second_phase,
        PhysicalPublicationState::Idle,
        "A2 must remain untouched in the original actor FIFO before child loss"
    );
    assert_eq!(observed.loss.actor_packets, 1);
    assert_eq!(
        observed.loss.front_len,
        observed.second.original_packet().len()
    );
    assert_eq!(
        observed.loss.front_capacity as u64,
        observed.held_actor_capacity
    );
    assert_eq!(observed.loss.generation, Some(observed.second.generation));
    assert!(observed.old_deadline.is_some());
    assert_eq!(observed.loss.delivery_deadline, observed.old_deadline);
    assert!(observed.loss.wait_deadline.is_none());
    assert!(observed.held_valid && observed.held_observed && observed.final_resources_valid);
    assert_eq!(
        observed.held_actor_len,
        observed.second.original_packet().len() as u64
    );
    assert_eq!(
        (observed.final_actor_packets, observed.final_task_packets),
        (0, 0)
    );
    assert_ne!(observed.first.nonce, observed.second.nonce);
    assert_ne!(observed.second.nonce, observed.third.nonce);
    assert_eq!(observed.handoff_wire.1, Some(0));
    let expected = if point == WorkerLossPoint::BeforePhysicalHandoff {
        assert_eq!(observed.before_phase, PhysicalPublicationState::Open);
        assert_eq!(
            observed.after_phase,
            PhysicalPublicationState::CancelledOrUncertain
        );
        assert!(observed.first.physical_publication.record().is_none());
        assert!(
            observed.original_record_pointer.is_none() && observed.pointer_after_join.is_none()
        );
        vec![&observed.second, &observed.third]
    } else {
        assert_eq!(observed.before_phase, PhysicalPublicationState::Recorded);
        assert_eq!(observed.after_phase, PhysicalPublicationState::Recorded);
        assert!(observed.original_record_pointer.is_some());
        assert_eq!(
            observed
                .first
                .physical_publication
                .record()
                .unwrap()
                .relay()
                .unwrap()
                .wire(),
            observed.handoff_wire,
            "the recorded original Full must match the real pre-handoff encrypted argument"
        );
        assert_eq!(
            observed.original_record_pointer,
            observed.pointer_after_join
        );
        assert_eq!(
            observed
                .first
                .physical_publication
                .record()
                .map(|record| record as *const _ as usize),
            observed.original_record_pointer
        );
        vec![&observed.first, &observed.second, &observed.third]
    };
    assert_eq!(observed.frames.len(), expected.len());
    for (received, request) in observed.frames.iter().zip(expected) {
        assert_eq!(received.destination, PEER);
        assert_eq!(received.plaintext, request.original_packet());
        assert_eq!(
            request.physical_publication.state(),
            PhysicalPublicationState::Recorded
        );
        let record = request.physical_publication.record().unwrap();
        assert_eq!(record.attempt_id(), 1);
        assert_eq!(record.encryption().session_instance(), observed.instance);
        assert_eq!(record.relay().unwrap().wire(), received.wire);
        assert!(record.relay().unwrap().original().is_some());
        assert_eq!(
            record.qualify(request, Instant::now()),
            PhysicalInputQualification::Retired
        );
    }
    let counters: Vec<_> = observed.frames.iter().map(|frame| frame.wire.1).collect();
    assert_eq!(
        counters,
        if point == WorkerLossPoint::BeforePhysicalHandoff {
            vec![Some(1), Some(2)]
        } else {
            vec![Some(0), Some(1), Some(2)]
        }
    );
    assert_eq!(Arc::strong_count(&observed.first), 1);
    assert_eq!(Arc::strong_count(&observed.second), 1);
    assert_eq!(Arc::strong_count(&observed.third), 1);
    // No assertion invents old child FIFO loss bytes. Main's real JoinError
    // path remains accounting_complete=false / old_task_fifo_unknown=true.
}

#[tokio::test]
async fn general_actual_child_loss_before_full_preserves_a2_and_sends_fresh_a3() {
    exercise(WorkerLossPoint::BeforePhysicalHandoff).await;
}

#[tokio::test]
async fn general_actual_child_loss_after_recorded_full_preserves_a2_and_sends_fresh_a3() {
    exercise(WorkerLossPoint::AfterRecordedSent).await;
}
