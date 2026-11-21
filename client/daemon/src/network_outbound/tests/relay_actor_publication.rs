// Finite original MockTun/minter -> DataPlane -> WG forwarder -> shared actor controls.
// General full remains historical UnknownRelayPublication, without ACK or owner credit.
// All setup, joins and fixture cleanup share the existing two-second/one-second Budget.
use std::collections::{HashMap, VecDeque};
use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::sync::{mpsc, watch, RwLock};
use tokio::task::JoinHandle;

use crate::connection_timeline::ConnectionTimeline;
use crate::dataplane::{DataPlane, OutboundPacket};
use crate::dataplane_resources::{QueueStage, ResourceCapture, VecSite};
use crate::network_outbound::{
    run_network_outbound, run_network_outbound_with_request_carriage, RelayStartupWait,
};
use crate::overlay_requests::{
    send_overlay_payloads, CanonicalOverlayRequest, PhysicalInputQualification,
    PhysicalPublicationState,
};
use crate::peer::PeerManager;
use crate::relay::publication_test_support::{sessions, Budget, Fixture, WriterPath};
use crate::relay::RelayTransport;
use crate::request_carriage::test_probe::{HandoffArgumentPoint, RequestHandoffArgumentProbe};
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
                ConnectionTimeline::new("b20-actor", 0),
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

    fn legacy(
        routed: mpsc::Receiver<OutboundPacket>,
        raw: mpsc::Receiver<OutboundPacket>,
        transport: WireGuardTransport,
        peers: Arc<PeerManager>,
        relay: RelayTransport,
    ) -> Self {
        let forward_transport = transport.clone();
        let forward = tokio::spawn(async move { forward_transport.run_outbound(routed).await });
        let relays = Arc::new(RwLock::new(Some(relay)));
        let actor_relays = relays.clone();
        let (available, available_rx) = watch::channel(true);
        let (probe_tx, probe_rx) = watch::channel(0);
        let actor = tokio::spawn(async move {
            run_network_outbound(
                raw,
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
                ConnectionTimeline::new("b20-legacy-none", 0),
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

    async fn finish(&mut self, budget: Budget) {
        // The caller dropped the actual DataPlane sink after its real reads.
        budget
            .step(self.forward.as_mut().unwrap())
            .await
            .unwrap()
            .unwrap();
        drop(self.forward.take());
        // The external WG clone retains the original raw sender. Close the
        // existing availability watch to request the actor's original drain/join.
        drop(self.available.take());
        budget.step(self.actor.as_mut().unwrap()).await.unwrap();
        drop(self.actor.take());
    }

    async fn retire_relay(&self, budget: Budget) {
        let mut relay = budget.step(self.relays.write()).await;
        drop(relay.take());
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

fn assert_original_handoff(
    probe: &RequestHandoffArgumentProbe,
    request: &Arc<CanonicalOverlayRequest>,
    instance: u64,
) {
    // Synchronous lexical guard; no lock is retained across an await.
    let observed = probe.recorded.lock().unwrap();
    let observed = observed.as_ref().unwrap();
    assert_eq!(observed.point, HandoffArgumentPoint::SlowBoundedEntry);
    assert!(Arc::ptr_eq(
        &observed.token.as_ref().unwrap().request().unwrap(),
        request,
    ));
    let source = observed.source.as_ref().unwrap();
    assert_eq!(source.peer_id, PEER);
    assert_eq!(source.session_instance, instance);
    assert_eq!(
        source.authorized_peer_lifecycle,
        request.expected_target_lifecycle()
    );
    assert!(source.belongs_to_transport);
    assert_eq!(
        source.encrypted_at,
        request
            .physical_publication
            .record()
            .unwrap()
            .encryption()
            .encrypted_at(),
    );
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

#[tokio::test(flavor = "current_thread")]
async fn b20_general_original_actor_fifo_canonical_full() {
    let budget = Budget::new();
    let InputRequestFixture {
        peers,
        controller,
        tun,
        record,
    } = budget.step(mint_input_request()).await;
    let mut fixture = Fixture::start(WriterPath::General, peers.clone(), budget).await;
    admit_actual_relay(&peers, &record, &fixture, budget).await;
    let probe = Arc::new(RequestHandoffArgumentProbe::new());
    let (transport, raw) = WireGuardTransport::new_with_request_carriage();
    let transport = transport.with_request_handoff_probe(probe.clone());
    let (mut remote, instance) = install_original_session(&transport, &record, budget).await;
    let (mut plane, routed) = DataPlane::new_with_request_carriage(tun, peers.clone());
    let mut pipeline = OriginalPipeline::tracked(
        routed,
        raw,
        transport.clone(),
        peers.clone(),
        fixture.transport().clone(),
    );
    let client_count = fixture.client_count();
    budget
        .step(plane.read_and_route_once(&mut [0u8; 512]))
        .await
        .unwrap();
    drop(plane);
    let frame = fixture.next_frame(budget).await;
    let (destination, wire) = frame.parse_forward_payload().unwrap();
    assert_eq!(destination, PEER);
    assert_eq!(crate::transport::wire_counter(wire), Some(0));
    assert_eq!(
        remote.decrypt_from_bytes(wire).unwrap(),
        record.original_packet()
    );
    pipeline.finish(budget).await;
    let pointer = assert_canonical_full(&record, wire, instance, &fixture);
    assert_original_handoff(&probe, &record, instance);
    assert_eq!(
        fixture.client_count(),
        client_count,
        "full has no source keeper"
    );
    assert!(transport.try_acquire_outbound_emit_guard(PEER).is_some());
    pipeline.retire_relay(budget).await;
    fixture.finish(budget).await;
    assert_retired_history(&record, pointer);
    let weak = Arc::downgrade(&record);
    drop(controller);
    drop(record);
    assert!(weak.upgrade().is_none());
}

#[tokio::test(flavor = "current_thread")]
async fn b20_same_peer_two_original_mints_fifo() {
    let budget = Budget::new();
    let InputRequestFixture {
        peers,
        controller,
        tun,
        record: first,
    } = budget.step(mint_input_request()).await;
    // A second independent call of the original minter writes a distinct
    // plaintext/context into the same actual MockTun input FIFO.
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
    assert_ne!(first.nonce, second.nonce);
    assert_ne!(first.seq, second.seq);
    assert_ne!(first.original_packet(), second.original_packet());
    assert_eq!(first.generation, second.generation);
    assert_eq!(
        first.expected_target_lifecycle(),
        second.expected_target_lifecycle()
    );
    let mut fixture = Fixture::start(WriterPath::General, peers.clone(), budget).await;
    admit_actual_relay(&peers, &first, &fixture, budget).await;
    let resources = ResourceCapture::new([0x20; 16]);
    let (transport, raw) = WireGuardTransport::new_with_request_carriage();
    let transport = transport.with_resource_capture(resources.clone()).unwrap();
    let (mut remote, instance) = install_original_session(&transport, &first, budget).await;
    // Hold the original emit lock. Its RAII guard is owned by this test future,
    // so unwind/cancellation releases it after pipeline Drop requests task aborts.
    let held_emit = budget
        .step(transport.acquire_outbound_emit_guard(PEER))
        .await;
    let (mut plane, routed) = DataPlane::new_with_request_carriage(tun, peers.clone());
    let mut pipeline = OriginalPipeline::tracked(
        routed,
        raw,
        transport.clone(),
        peers.clone(),
        fixture.transport().clone(),
    );
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
    budget
        .step(async {
            loop {
                // Only two known inputs exist. PreparationCopy means the older
                // sole peer owner has popped A1 and is blocked at the actual emit
                // lock; ActorFifo=1 is the later A2 in the actor timing shell.
                // This read is stable on current_thread, not an atomic resource
                // transaction or a whole-pipeline byte/allocator measurement.
                let snapshot = resources.snapshot();
                assert!(snapshot.valid);
                assert_eq!(snapshot.gap_bits, 0);
                if snapshot
                    .vec_site(VecSite::TxPreparationCopy)
                    .materialization_ops
                    == 1
                    && snapshot.fifo(QueueStage::ActorFifo).live_packets == 1
                {
                    assert!(snapshot.fifo_scope_observed(QueueStage::ActorFifo));
                    assert_eq!(
                        snapshot.fifo(QueueStage::ActorFifo).plaintext_len,
                        second.original_packet().len() as u64,
                    );
                    assert!(!snapshot.coherent);
                    assert_eq!(
                        first.physical_publication.state(),
                        PhysicalPublicationState::Idle
                    );
                    assert_eq!(
                        second.physical_publication.state(),
                        PhysicalPublicationState::Idle
                    );
                    assert!(first.physical_publication.record().is_none());
                    assert!(second.physical_publication.record().is_none());
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await;
    drop(held_emit);
    let first_frame = fixture.next_frame(budget).await;
    let second_frame = fixture.next_frame(budget).await;
    let (first_destination, first_wire) = first_frame.parse_forward_payload().unwrap();
    let (second_destination, second_wire) = second_frame.parse_forward_payload().unwrap();
    assert_eq!(first_destination, PEER);
    assert_eq!(second_destination, PEER);
    assert_eq!(crate::transport::wire_counter(first_wire), Some(0));
    assert_eq!(crate::transport::wire_counter(second_wire), Some(1));
    assert_eq!(
        remote.decrypt_from_bytes(first_wire).unwrap(),
        first.original_packet()
    );
    assert_eq!(
        remote.decrypt_from_bytes(second_wire).unwrap(),
        second.original_packet()
    );
    pipeline.finish(budget).await;
    let first_pointer = assert_canonical_full(&first, first_wire, instance, &fixture);
    let second_pointer = assert_canonical_full(&second, second_wire, instance, &fixture);
    assert_eq!(
        first
            .physical_publication
            .record()
            .unwrap()
            .qualify(&second, Instant::now()),
        PhysicalInputQualification::OriginalMismatch,
    );
    assert_eq!(
        second
            .physical_publication
            .record()
            .unwrap()
            .qualify(&first, Instant::now()),
        PhysicalInputQualification::OriginalMismatch,
    );
    assert_eq!(
        fixture.client_count(),
        client_count,
        "two captures have no source keeper"
    );
    assert!(transport.try_acquire_outbound_emit_guard(PEER).is_some());
    let final_resources = resources.snapshot();
    assert!(final_resources.valid);
    assert_eq!(final_resources.gap_bits, 0);
    assert_eq!(
        final_resources
            .vec_site(VecSite::TxPreparationCopy)
            .materialization_ops,
        2
    );
    assert_eq!(final_resources.fifo(QueueStage::ActorFifo).live_packets, 0);
    assert_eq!(
        final_resources
            .fifo(QueueStage::TaskOrUnjoinedFifo)
            .live_packets,
        0
    );
    pipeline.retire_relay(budget).await;
    fixture.finish(budget).await;
    assert_retired_history(&first, first_pointer);
    assert_retired_history(&second, second_pointer);
    resources.finish();
    let first_weak = Arc::downgrade(&first);
    let second_weak = Arc::downgrade(&second);
    drop(controller);
    drop(first);
    drop(second);
    assert!(first_weak.upgrade().is_none());
    assert!(second_weak.upgrade().is_none());
}

#[tokio::test(flavor = "current_thread")]
async fn b20_legacy_none_original_pipeline_idle() {
    let budget = Budget::new();
    let InputRequestFixture {
        peers,
        controller,
        tun,
        record,
    } = budget.step(mint_input_request()).await;
    let mut fixture = Fixture::start(WriterPath::General, peers.clone(), budget).await;
    admit_actual_relay(&peers, &record, &fixture, budget).await;
    let probe = Arc::new(RequestHandoffArgumentProbe::new());
    // These original compatibility constructors naturally omit carriage at the
    // DataPlane read and raw receiver boundaries. No tracked binding is stripped.
    let (transport, raw) = WireGuardTransport::new();
    let transport = transport.with_request_handoff_probe(probe.clone());
    let (mut remote, _instance) = install_original_session(&transport, &record, budget).await;
    let (mut plane, routed) = DataPlane::new(tun, peers.clone());
    let mut pipeline = OriginalPipeline::legacy(
        routed,
        raw,
        transport.clone(),
        peers.clone(),
        fixture.transport().clone(),
    );
    let client_count = fixture.client_count();
    budget
        .step(plane.read_and_route_once(&mut [0u8; 512]))
        .await
        .unwrap();
    drop(plane);
    let frame = fixture.next_frame(budget).await;
    let (destination, wire) = frame.parse_forward_payload().unwrap();
    assert_eq!(destination, PEER);
    assert_eq!(crate::transport::wire_counter(wire), Some(0));
    assert_eq!(
        remote.decrypt_from_bytes(wire).unwrap(),
        record.original_packet()
    );
    pipeline.finish(budget).await;
    {
        let observed = probe.recorded.lock().unwrap();
        let observed = observed.as_ref().unwrap();
        assert_eq!(observed.point, HandoffArgumentPoint::SlowBoundedEntry);
        assert!(observed.token.is_none());
        assert!(observed.source.is_none());
    }
    assert!(record.injection_accepted());
    assert_eq!(
        record.physical_publication.state(),
        PhysicalPublicationState::Idle
    );
    assert!(record.physical_publication.record().is_none());
    assert_eq!(Arc::strong_count(&record), 1);
    assert_eq!(fixture.client_count(), client_count);
    assert!(transport.try_acquire_outbound_emit_guard(PEER).is_some());
    pipeline.retire_relay(budget).await;
    fixture.finish(budget).await;
    assert_eq!(
        record.physical_publication.state(),
        PhysicalPublicationState::Idle
    );
    assert!(record.physical_publication.record().is_none());
    let weak = Arc::downgrade(&record);
    drop(controller);
    drop(record);
    assert!(weak.upgrade().is_none());
}
