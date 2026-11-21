// Design draft: actual graceful actor shutdown, with genuine A1 full and A2 discard.
// The bounded synchronous after-full barrier is a synthetic completion fault only.
// It is not a worker-loss, partial TCP, finalowner or ACK control.
use futures_util::FutureExt;
use std::collections::{HashMap, VecDeque};
use std::panic::AssertUnwindSafe;
use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::sync::{mpsc, watch, RwLock};
use tokio::task::JoinHandle;

use crate::connection_timeline::ConnectionTimeline;
use crate::dataplane::DataPlane;
use crate::dataplane_resources::{QueueStage, ResourceCapture, VecSite};
use crate::network_outbound::{
    run_network_outbound_with_request_carriage, RelayStartupWait, REASON_OUTBOUND_WORKER_STOPPED,
};
use crate::overlay_requests::{
    send_overlay_payloads, CanonicalOverlayRequest, PhysicalInputQualification,
    PhysicalPublicationState,
};
use crate::peer::PeerManager;
use crate::relay::publication_test_support::{sessions, Budget, Fixture, WriterPath};
use crate::relay::RelayTransport;
use crate::request_carriage::test_support::{
    mint_input_request, InputRequestFixture, LOCAL_VIP, PEER,
};
use crate::request_carriage::RawRequestDelivery;
use crate::transport::WireGuardTransport;

// Retain both handles while Budget borrows them. A timeout or assertion panic
// then aborts the actual original owners, rather than detaching a taken handle.
struct OriginalPipeline {
    forward: Option<JoinHandle<crate::error::Result<()>>>,
    actor: Option<JoinHandle<()>>,
    available: Option<watch::Sender<bool>>,
    relays: Arc<RwLock<Option<RelayTransport>>>,
    _probe_kicks: watch::Receiver<u64>,
}

impl Drop for OriginalPipeline {
    fn drop(&mut self) {
        if let Some(task) = self.forward.as_ref() {
            task.abort();
        }
        if let Some(task) = self.actor.as_ref() {
            task.abort();
        }
    }
}

impl OriginalPipeline {
    fn tracked(
        routed: mpsc::Receiver<RawRequestDelivery>,
        raw: mpsc::Receiver<RawRequestDelivery>,
        transport: WireGuardTransport,
        peers: Arc<PeerManager>,
        relay: RelayTransport,
    ) -> Self {
        let forward_transport = transport.clone();
        let forward = tokio::spawn(async move {
            forward_transport
                .run_outbound_with_request_carriage(routed)
                .await
        });
        let relays = Arc::new(RwLock::new(Some(relay)));
        let actor_relays = relays.clone();
        let (available, available_rx) = watch::channel(true);
        let (probe_tx, probe_rx) = watch::channel(0);
        let actor = tokio::spawn(async move {
            run_network_outbound_with_request_carriage(
                raw.into(),
                transport,
                peers,
                false,
                Arc::new(RwLock::new(None)),
                actor_relays,
                available_rx,
                RelayStartupWait {
                    relay_expected: true,
                    timeout: Some(Duration::from_secs(1)),
                },
                probe_tx,
                ConnectionTimeline::new("c06-graceful-drain", 0),
            )
            .await;
        });
        Self {
            forward: Some(forward),
            actor: Some(actor),
            available: Some(available),
            relays,
            _probe_kicks: probe_rx,
        }
    }

    async fn join_forwarder(&mut self, budget: Budget) {
        let result = budget.step(self.forward.as_mut().unwrap()).await;
        drop(self.forward.take());
        result.unwrap().unwrap();
    }

    fn close_availability(&mut self) {
        drop(self.available.take());
    }

    async fn join_actor(&mut self, budget: Budget) {
        let result = budget.step(self.actor.as_mut().unwrap()).await;
        drop(self.actor.take());
        result.unwrap();
    }

    async fn abort_and_join(
        &mut self,
        end: tokio::time::Instant,
    ) -> (Result<(), String>, Result<(), String>) {
        self.close_availability();
        // Abort both original owners before awaiting either one. One common
        // cleanup deadline cannot extend the existing positive-test budget.
        if let Some(task) = self.forward.as_ref() {
            task.abort();
        }
        if let Some(task) = self.actor.as_ref() {
            task.abort();
        }
        let forward = join_aborted(&mut self.forward, end).await;
        let actor = join_aborted(&mut self.actor, end).await;
        (forward, actor)
    }

    async fn retire_relay(&self, budget: Budget) {
        let mut relay = budget.step(self.relays.write()).await;
        drop(relay.take());
    }
}

async fn join_aborted<T>(
    owner: &mut Option<JoinHandle<T>>,
    end: tokio::time::Instant,
) -> Result<(), String> {
    let Some(task) = owner.as_mut() else {
        return Ok(());
    };
    let joined = tokio::time::timeout_at(end, task)
        .await
        .map_err(|_| "original owner cleanup deadline exceeded".to_string())?;
    drop(owner.take());
    match joined {
        Ok(_) => Ok(()),
        Err(error) if error.is_cancelled() => Ok(()),
        Err(error) => Err(format!("original owner panicked: {error}")),
    }
}

async fn admit_actual_relay(
    peers: &PeerManager,
    request: &CanonicalOverlayRequest,
    fixture: &Fixture,
    budget: Budget,
) {
    budget
        .step(peers.mark_relay_transport_ready(
            PEER,
            fixture.transport().endpoint(),
            request.generation,
        ))
        .await;
    assert!(
        budget
            .step(peers.confirm_relay_peer(
                PEER,
                fixture.transport().endpoint(),
                request.generation,
            ))
            .await
    );
}

async fn install_original_session(
    transport: &WireGuardTransport,
    request: &CanonicalOverlayRequest,
    budget: Budget,
) -> (p2pnet_wireguard::TransportSession, u64) {
    let (session, remote) = sessions();
    budget
        .step(transport.replace_session_for_lifecycle(
            PEER,
            session,
            request.expected_target_lifecycle().unwrap(),
        ))
        .await;
    let instance = budget
        .step(transport.session_status(PEER))
        .await
        .active_session_instance
        .unwrap();
    (remote, instance)
}

fn assert_canonical_full(
    request: &Arc<CanonicalOverlayRequest>,
    wire: &[u8],
    instance: u64,
    fixture: &Fixture,
) -> usize {
    assert!(request.injection_accepted());
    assert_eq!(
        request.physical_publication.state(),
        PhysicalPublicationState::Recorded
    );
    let record = request.physical_publication.record().unwrap();
    assert_eq!(record.attempt_id(), 1);
    assert!(record.udp().is_none());
    let full = record.relay().unwrap();
    assert_eq!(
        full.wire(),
        (
            wire.len(),
            crate::transport::wire_counter(wire),
            crate::transport::wire_fingerprint(wire)
        ),
    );
    assert_eq!(full.endpoint(), fixture.transport().endpoint());
    assert_eq!(full.connection_id(), fixture.transport().connection_id());
    let original = full.original().unwrap();
    assert_eq!(original.destination(), PEER);
    assert_eq!(original.data_len(), wire.len());
    assert_eq!(record.encryption().peer_id(), PEER);
    assert_eq!(record.encryption().session_instance(), instance);
    assert_eq!(record.encryption_generation(), request.generation);
    assert_eq!(
        record.encryption().authorized_peer_lifecycle(),
        request.expected_target_lifecycle()
    );
    assert!(record.encryption().encrypted_at() <= original.write_started_at());
    assert!(original.write_started_at() <= original.completed_at());
    assert_eq!(
        record.qualify(request, Instant::now()),
        PhysicalInputQualification::UnknownRelayPublication,
    );
    assert_eq!(
        Arc::strong_count(request),
        1,
        "original canonical has no capture keeper"
    );
    record as *const _ as usize
}

fn assert_retired_history(request: &Arc<CanonicalOverlayRequest>, pointer: usize) {
    let record = request.physical_publication.record().unwrap();
    assert_eq!(record as *const _ as usize, pointer);
    assert_eq!(
        record.qualify(request, Instant::now()),
        PhysicalInputQualification::Retired
    );
}

// The signal has the same capacity and one-second maximum as the existing
// after-full controls. Unwind also releases the writer before Fixture cleanup.
struct CompletionRelease(Option<std::sync::mpsc::SyncSender<()>>);
impl CompletionRelease {
    fn release(&mut self) {
        if let Some(sender) = self.0.take() {
            let _ = sender.send(());
        }
    }
}
impl Drop for CompletionRelease {
    fn drop(&mut self) {
        self.release();
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn relay_c06_original_actor_graceful_drain_full_then_idle_worker_stopped() {
    let budget = Budget::new();
    let InputRequestFixture {
        peers,
        controller,
        tun,
        record: first,
    } = budget.step(mint_input_request()).await;
    let mut nonce = first.nonce;
    let mut seq = first.seq;
    let mut stats = crate::OverlayStats {
        sent: 0,
        received_valid: 0,
        received_invalid: 0,
        verified_round_trips: 0,
        last_seq: 0,
    };
    let mut retained = HashMap::new();
    let mut order = VecDeque::new();
    assert_eq!(
        budget
            .step(send_overlay_payloads(
                &controller,
                &peers,
                LOCAL_VIP,
                true,
                None,
                &mut nonce,
                &mut seq,
                &mut stats,
                &mut retained,
                &mut order,
            ))
            .await,
        1
    );
    let second = retained.remove(&nonce).unwrap();
    assert!(!Arc::ptr_eq(&first, &second));
    assert_ne!(first.original_packet(), second.original_packet());
    assert_eq!(first.generation, second.generation);
    let before_loss = budget.step(peers.outbound_loss_stats()).await;
    assert!(before_loss.drops.is_empty());
    let mut fixture = Fixture::start(WriterPath::General, peers.clone(), budget).await;
    admit_actual_relay(&peers, &first, &fixture, budget).await;
    let resources = ResourceCapture::new([0xc6; 16]);
    let (transport, raw) = WireGuardTransport::new_with_request_carriage();
    let transport = transport.with_resource_capture(resources.clone()).unwrap();
    let (mut remote, instance) = install_original_session(&transport, &first, budget).await;
    let (entered_tx, entered_rx) = tokio::sync::oneshot::channel();
    let (release_tx, release_rx) = std::sync::mpsc::sync_channel(1);
    let mut release = CompletionRelease(Some(release_tx));
    let (capture_tx, capture_rx) = tokio::sync::oneshot::channel();
    let _setup = super::install_relay_capture_setup_for_test(&first, move |storage, packet| {
        let capture = storage.relay_for_test(packet);
        capture.after_full_for_test(move || {
            let _ = entered_tx.send(());
            release_rx
                .recv_timeout(Duration::from_secs(1))
                .expect("explicit synthetic completion barrier before graceful drain");
        });
        let _ = capture_tx.send(capture);
    });
    let (mut plane, routed) = DataPlane::new_with_request_carriage(tun, peers.clone());
    let mut pipeline = OriginalPipeline::tracked(
        routed,
        raw,
        transport.clone(),
        peers.clone(),
        fixture.transport().clone(),
    );
    // Keep the original handles and completion release outside the caught body.
    // Any failed prerequisite still releases the barrier and awaits the actual
    // owners before the assertion is reported. Positive Budget stays 2s/1s.
    let result = AssertUnwindSafe(async {
        let client_count = fixture.client_count();
        budget
            .step(plane.read_and_route_once(&mut [0u8; 512]))
            .await
            .unwrap();
        budget
            .step(plane.read_and_route_once(&mut [0u8; 512]))
            .await
            .unwrap();
        drop(plane);
        pipeline.join_forwarder(budget).await;
        budget.step(entered_rx).await.unwrap();
        let capture = budget.step(capture_rx).await.unwrap();
        assert!(capture.branches().unwrap()[0].original().is_some());
        budget
            .step(async {
                loop {
                    let snapshot = resources.snapshot();
                    assert!(snapshot.valid);
                    assert_eq!(snapshot.gap_bits, 0);
                    if snapshot.fifo(QueueStage::ActorFifo).live_packets == 1 {
                        assert!(snapshot.fifo_scope_observed(QueueStage::ActorFifo));
                        assert_eq!(
                            snapshot.fifo(QueueStage::ActorFifo).plaintext_len,
                            second.original_packet().len() as u64
                        );
                        assert_eq!(
                            snapshot
                                .vec_site(VecSite::TxPreparationCopy)
                                .materialization_ops,
                            1
                        );
                        // These stable owners are blocked by the explicit full callback
                        // barrier. ResourceSnapshot remains a non-atomic scoped read.
                        assert!(!snapshot.coherent);
                        break;
                    }
                    tokio::task::yield_now().await;
                }
            })
            .await;
        assert_eq!(
            first.physical_publication.state(),
            PhysicalPublicationState::Open
        );
        assert_eq!(
            second.physical_publication.state(),
            PhysicalPublicationState::Idle
        );
        assert!(second.physical_publication.record().is_none());
        pipeline.close_availability();
        // This observes actual original receiver.close(), not a manufactured
        // stopping value or a fixed number of yields. It does not claim that the
        // following stopping.store is already visible to arbitrary threads: A2
        // cannot be scheduled again after this actor has left its main loop, and
        // the original final-drain spawn is ordered after stopping.store.
        budget
        .step(
            crate::transport::actor_shutdown_test_support::wait_tracked_outbound_receiver_closed(
                &transport,
            ),
        )
        .await;
        assert!(!pipeline.actor.as_ref().unwrap().is_finished());
        assert_eq!(
            first.physical_publication.state(),
            PhysicalPublicationState::Open
        );
        assert_eq!(
            second.physical_publication.state(),
            PhysicalPublicationState::Idle
        );
        release.release();
        let frame = fixture.next_frame(budget).await;
        let (destination, wire) = frame.parse_forward_payload().unwrap();
        assert_eq!(destination, PEER);
        assert_eq!(crate::transport::wire_counter(wire), Some(0));
        assert_eq!(
            remote.decrypt_from_bytes(wire).unwrap(),
            first.original_packet()
        );
        pipeline.join_actor(budget).await;
        let pointer = assert_canonical_full(&first, wire, instance, &fixture);
        assert_eq!(
            second.physical_publication.state(),
            PhysicalPublicationState::Idle
        );
        assert!(second.physical_publication.record().is_none());
        assert_eq!(Arc::strong_count(&second), 1);
        let after_loss = budget.step(peers.outbound_loss_stats()).await;
        assert_eq!(after_loss.drops.len(), 1);
        let stopped = after_loss
            .drops
            .get(REASON_OUTBOUND_WORKER_STOPPED)
            .unwrap();
        assert_eq!(
            (stopped.packets, stopped.bytes),
            (1, second.original_packet().len() as u64)
        );
        let snapshot = resources.snapshot();
        assert!(snapshot.valid);
        assert_eq!(snapshot.gap_bits, 0);
        assert_eq!(
            snapshot
                .vec_site(VecSite::TxPreparationCopy)
                .materialization_ops,
            1
        );
        assert_eq!(snapshot.fifo(QueueStage::ActorFifo).live_packets, 0);
        assert_eq!(
            snapshot.fifo(QueueStage::TaskOrUnjoinedFifo).live_packets,
            0
        );
        assert_eq!(fixture.client_count(), client_count);
        assert!(transport.try_acquire_outbound_emit_guard(PEER).is_some());
        pipeline.retire_relay(budget).await;
        fixture.finish_joined(budget).await;
        assert_retired_history(&first, pointer);
        assert_eq!(
            second.physical_publication.state(),
            PhysicalPublicationState::Idle
        );
        resources.finish();
        let first_weak = Arc::downgrade(&first);
        let second_weak = Arc::downgrade(&second);
        drop(controller);
        drop(first);
        drop(second);
        assert!(first_weak.upgrade().is_none());
        assert!(second_weak.upgrade().is_none());
    })
    .catch_unwind()
    .await;
    release.release();
    let cleanup_end = tokio::time::Instant::now() + Duration::from_secs(1);
    let (forward, actor) = pipeline.abort_and_join(cleanup_end).await;
    let server = fixture.abort_and_join_server(cleanup_end).await;
    // Collect all three results first, so one failure never skips another join.
    assert!(
        forward.is_ok(),
        "original forwarder cleanup failed: {forward:?}"
    );
    assert!(actor.is_ok(), "original actor cleanup failed: {actor:?}");
    assert!(
        server.is_ok(),
        "original fixture server cleanup failed: {server:?}"
    );
    if let Err(panic) = result {
        eprintln!("C06 failed body: original forwarder, actor and fixture server joined");
        std::panic::resume_unwind(panic);
    }
}
