use super::*;
use crate::dataplane::{DataPlane, OutboundPacket, RequestRouteTestGate};
use crate::overlay_requests::{
    send_overlay_payloads_with_publication_gate_for_test, InjectionPublicationGate,
};
use crate::request_carriage::{
    RawRequestDelivery, RequestBindingFailure, RequestBindingState, RequestInputEligibility,
};
use p2pnet_tun::{MockTunDevice, PacketReadContext};
use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::{AtomicUsize, Ordering};

// Capability controls only: genuine original mint/inject/read and DataPlane
// output, with no WG/socket completion, actual TUN write or ACK credit claim.
const WINDOW: Duration = Duration::from_secs(1);

#[derive(Clone, Copy, Debug)]
enum ReadMutation {
    None,
    Filler,
    Direction,
    Nonce,
    Sequence,
    PayloadChecksum,
    SourceVip,
    DestinationVip,
    TrailingByte,
}

#[derive(Default)]
struct ReadAudit {
    reads: AtomicUsize,
    takes: AtomicUsize,
    contexts: AtomicUsize,
}

struct AuditedMockTun {
    inner: MockTunDevice,
    audit: Arc<ReadAudit>,
    mutation: ReadMutation,
}

impl AuditedMockTun {
    fn new(inner: MockTunDevice, mutation: ReadMutation) -> (Self, Arc<ReadAudit>) {
        let audit = Arc::new(ReadAudit::default());
        (
            Self {
                inner,
                audit: audit.clone(),
                mutation,
            },
            audit,
        )
    }
}

// Existing daemon ControlledMockTun uses these async_trait-expanded signatures;
// this fixture adds no async-trait dependency, fake context factory or queue.
impl VirtualInterface for AuditedMockTun {
    fn read<'life0, 'life1, 'async_trait>(
        &'life0 mut self,
        buf: &'life1 mut [u8],
    ) -> Pin<Box<dyn Future<Output = p2pnet_tun::Result<usize>> + Send + 'async_trait>>
    where
        'life0: 'async_trait,
        'life1: 'async_trait,
        Self: 'async_trait,
    {
        Box::pin(async move {
            let mut size = self.inner.read(buf).await?;
            if size != 0 {
                self.audit.reads.fetch_add(1, Ordering::Relaxed);
            }
            if size >= 51 {
                match self.mutation {
                    ReadMutation::None => {}
                    ReadMutation::Filler => buf[size - 1] ^= 1,
                    ReadMutation::Direction => buf[28 + 6] ^= 1,
                    ReadMutation::Nonce => buf[28 + 7] ^= 1,
                    ReadMutation::Sequence => buf[28 + 15] ^= 1,
                    ReadMutation::PayloadChecksum => buf[28 + 19] ^= 1,
                    ReadMutation::SourceVip => buf[12..16].copy_from_slice(&[192, 168, 1, 9]),
                    ReadMutation::DestinationVip => buf[16..20].copy_from_slice(&[10, 20, 0, 3]),
                    ReadMutation::TrailingByte => {
                        assert!(
                            size < buf.len(),
                            "fixture leaves space for one trailing byte"
                        );
                        buf[size] = 0x5a;
                        size += 1;
                    }
                }
            }
            // This consumes one selected mutation. The next fresh mint/read
            // goes through the same device with the original actual bytes.
            self.mutation = ReadMutation::None;
            Ok(size)
        })
    }

    fn take_last_read_context(&mut self) -> Option<PacketReadContext> {
        self.audit.takes.fetch_add(1, Ordering::Relaxed);
        let context = self.inner.take_last_read_context();
        if context.is_some() {
            self.audit.contexts.fetch_add(1, Ordering::Relaxed);
        }
        assert!(
            self.inner.take_last_read_context().is_none(),
            "real MockTun context is one-shot"
        );
        context
    }

    fn write<'life0, 'life1, 'async_trait>(
        &'life0 mut self,
        buf: &'life1 [u8],
    ) -> Pin<Box<dyn Future<Output = p2pnet_tun::Result<usize>> + Send + 'async_trait>>
    where
        'life0: 'async_trait,
        'life1: 'async_trait,
        Self: 'async_trait,
    {
        Box::pin(async move { self.inner.write(buf).await })
    }

    fn name(&self) -> &str {
        self.inner.name()
    }
    fn mtu(&self) -> u32 {
        self.inner.mtu()
    }
    fn address(&self) -> &str {
        self.inner.address()
    }
    fn is_up(&self) -> bool {
        self.inner.is_up()
    }
}

fn tracked_plane(
    fixture: &mut Fixture,
    peers: Arc<PeerManager>,
    mutation: ReadMutation,
) -> (
    DataPlane<AuditedMockTun>,
    tokio::sync::mpsc::Receiver<RawRequestDelivery>,
    Arc<ReadAudit>,
) {
    let (tun, audit) = AuditedMockTun::new(fixture.tun.take().unwrap(), mutation);
    let (plane, receiver) = DataPlane::new_with_request_carriage(tun, peers);
    assert_eq!(
        receiver.max_capacity(),
        1024,
        "original DataPlane channel remains selected once"
    );
    (plane.with_overlay_cidr("10.20.0.0/16"), receiver, audit)
}

async fn read_routed_once(
    plane: &mut DataPlane<AuditedMockTun>,
    receiver: &mut tokio::sync::mpsc::Receiver<RawRequestDelivery>,
) -> RawRequestDelivery {
    plane.read_and_route_once(&mut [0u8; 512]).await.unwrap();
    receiver
        .try_recv()
        .expect("original business routing emits the actual packet")
}

fn assert_exact_actual_identity(fixture: &Fixture, delivery: &RawRequestDelivery) {
    let binding = delivery
        .binding()
        .expect("actual private producer token survives routing");
    assert_eq!(binding.state(), RequestBindingState::RoutedExact);
    let request = binding
        .token()
        .request()
        .expect("original retained record stays live");
    assert!(Arc::ptr_eq(&request, &fixture.sent_nonces[&request.nonce]));
    assert_eq!(delivery.peer_id, PEER);
    assert_eq!(delivery.dst_ip, PEER_VIP);
    assert_eq!(delivery.packet.as_slice(), request.original_packet());
    assert!(request.belongs_to(&fixture.peers));
    assert!(request.injection_accepted());
    assert_eq!(
        binding.eligibility_at(Instant::now()),
        RequestInputEligibility::AcceptedInput
    );
}

#[derive(Clone, Copy)]
enum PumpEntry {
    Once,
    OutboundRun,
    BidirectionalRun,
}

#[tokio::test]
async fn b14_c01_real_take_and_temporary_arc_end_before_first_route_boundary() {
    tokio::time::timeout(WINDOW, async {
        for entry in [PumpEntry::Once, PumpEntry::OutboundRun, PumpEntry::BidirectionalRun] {
            let mut fixture = Fixture::new().await;
            assert_eq!(fixture.inject_periodic().await, 1);
            let (tun, audit) = AuditedMockTun::new(fixture.tun.take().unwrap(), ReadMutation::None);
            let (mut plane, mut receiver, _keep_bidirectional_sender_open) = match entry {
                PumpEntry::BidirectionalRun => {
                    let (plane, receiver, inbound) = DataPlane::new_bidirectional_with_request_carriage(tun, fixture.peers.clone());
                    (plane, receiver, Some(inbound))
                }
                _ => {
                    let (plane, receiver) = DataPlane::new_with_request_carriage(tun, fixture.peers.clone());
                    (plane, receiver, None)
                }
            };
            assert_eq!(receiver.max_capacity(), 1024);
            let gate = Arc::new(RequestRouteTestGate::new());
            plane = plane.with_request_route_test_gate(gate.clone());
            let mut pump = Box::pin(async {
                match entry {
                    PumpEntry::Once => plane.read_and_route_once(&mut [0u8; 512]).await,
                    _ => plane.run().await,
                }
            });
            tokio::select! {
                () = gate.reached.notified() => {},
                result = &mut pump => panic!("pump completed before real first route boundary: {result:?}"),
            }
            assert_eq!(audit.reads.load(Ordering::Relaxed), 1);
            assert_eq!(audit.takes.load(Ordering::Relaxed), 1);
            assert_eq!(audit.contexts.load(Ordering::Relaxed), 1);
            assert_eq!(Arc::strong_count(fixture.sent_nonces.values().next().unwrap()), 1,
                "synchronous binding upgrade ends before the first route await");
            gate.release.notify_one();
            let delivery = match entry {
                PumpEntry::Once => {
                    pump.await.unwrap();
                    receiver.try_recv().unwrap()
                }
                _ => tokio::select! {
                    delivery = receiver.recv() => delivery.unwrap(),
                    result = &mut pump => panic!("run ended before original output: {result:?}"),
                },
            };
            assert_exact_actual_identity(&fixture, &delivery);
            assert_eq!(audit.takes.load(Ordering::Relaxed), 1);
            // No spawn/observer queue exists. Dropping a pending run after its
            // real output closes this fixture; real resolve is watch/Ready,
            // not a claimed blocked peer-manager lookup.
        }
    }).await.expect("all three real entry controls retain the original 1s fixture window");
}

#[tokio::test]
async fn b14_c02_real_ok_pending_binding_rechecks_after_original_release() {
    tokio::time::timeout(WINDOW, async {
        let mut fixture = Fixture::new().await;
        let peers = fixture.peers.clone();
        let (mut plane, mut receiver, _) = tracked_plane(&mut fixture, peers, ReadMutation::None);
        let gate = InjectionPublicationGate::new();
        let mut minter = Box::pin(send_overlay_payloads_with_publication_gate_for_test(
            &fixture.controller, &fixture.peers, LOCAL_VIP, true, None,
            &mut fixture.next_nonce, &mut fixture.next_seq, &mut fixture.stats,
            &mut fixture.sent_nonces, &mut fixture.nonce_order, &gate,
        ));
        tokio::select! {
            () = gate.reached.notified() => {},
            count = &mut minter => panic!("minter bypassed the real-Ok publication boundary: {count}"),
        }
        let delivery = read_routed_once(&mut plane, &mut receiver).await;
        let binding = delivery.binding().unwrap();
        assert_eq!(binding.state(), RequestBindingState::RoutedExact);
        assert_eq!(binding.eligibility_at(Instant::now()), RequestInputEligibility::PendingInjection);
        assert!(!binding.token().request().unwrap().injection_accepted());
        gate.release.notify_one();
        assert_eq!(minter.await, 1);
        assert_exact_actual_identity(&fixture, &delivery);
        assert_eq!(binding.eligibility_at(Instant::now()), RequestInputEligibility::AcceptedInput);
        assert_eq!(fixture.sent_nonces.len(), 1);
        assert_eq!(fixture.nonce_order.len(), 1);
    }).await.expect("real inject/read/publish uses the original 1s fixture window");
}

#[tokio::test]
async fn b14_c02_cancelled_real_ok_cannot_publish_or_keep_the_request_alive() {
    tokio::time::timeout(WINDOW, async {
        let mut fixture = Fixture::new().await;
        let peers = fixture.peers.clone();
        let (mut plane, mut receiver, _) = tracked_plane(&mut fixture, peers, ReadMutation::None);
        let gate = InjectionPublicationGate::new();
        let mut minter = Box::pin(send_overlay_payloads_with_publication_gate_for_test(
            &fixture.controller,
            &fixture.peers,
            LOCAL_VIP,
            true,
            None,
            &mut fixture.next_nonce,
            &mut fixture.next_seq,
            &mut fixture.stats,
            &mut fixture.sent_nonces,
            &mut fixture.nonce_order,
            &gate,
        ));
        tokio::select! {
            () = gate.reached.notified() => {},
            count = &mut minter => panic!("real-Ok pause was bypassed: {count}"),
        }
        let delivery = read_routed_once(&mut plane, &mut receiver).await;
        let binding = delivery.binding().unwrap();
        assert_eq!(
            binding.eligibility_at(Instant::now()),
            RequestInputEligibility::PendingInjection
        );
        drop(minter);
        assert!(fixture.sent_nonces.is_empty());
        assert!(fixture.nonce_order.is_empty());
        assert!(binding.token().request().is_none());
        assert_eq!(
            binding.eligibility_at(Instant::now()),
            RequestInputEligibility::Retired
        );
        gate.release.notify_one();
        assert_eq!(
            binding.eligibility_at(Instant::now()),
            RequestInputEligibility::Retired
        );
    })
    .await
    .expect("cancellation remains bounded by the original 1s fixture window");
}

#[tokio::test]
async fn b14_c02_real_inject_err_keeps_original_success_and_fifo() {
    tokio::time::timeout(WINDOW, async {
        let mut fixture = Fixture::new().await;
        assert_eq!(fixture.inject_periodic().await, 1);
        let peers = fixture.peers.clone();
        let (mut plane, mut receiver, _) = tracked_plane(&mut fixture, peers, ReadMutation::None);
        let delivery = read_routed_once(&mut plane, &mut receiver).await;
        assert_exact_actual_identity(&fixture, &delivery);
        let order = fixture.nonce_order.clone();
        drop(plane); // Close the actual original read receiver, not a fake Err.
        assert!(fixture.controller.inject(vec![0x45]).await.is_err());
        assert_eq!(fixture.inject_periodic().await, 0);
        fixture.arm_burst();
        fixture.inject_burst_attempts(1).await;
        assert_eq!(fixture.bursts[PEER].sent, 0);
        assert!(fixture.bursts[PEER].nonces.is_empty());
        assert_eq!(fixture.nonce_order, order);
        assert_eq!(fixture.sent_nonces.len(), 1);
        assert_exact_actual_identity(&fixture, &delivery);
        assert!(receiver.try_recv().is_err());
    })
    .await
    .expect("actual closed-channel failures keep the original 1s fixture window");
}

async fn add_real_route_peer(peers: &Arc<PeerManager>, node: &str, vip: &str) {
    peers
        .add_peer(&crate::control::PeerInfo {
            node_id: node.to_string(),
            public_key: "pk".to_string(),
            endpoint: "127.0.0.1:45004".to_string(),
            nat_type: "Unknown".to_string(),
            virtual_ip: vip.to_string(),
            online: true,
            ..crate::control::PeerInfo::default()
        })
        .await;
}

#[tokio::test]
async fn b14_c03_real_full_packet_corruption_stays_same_invalid_weak_then_fresh_is_exact() {
    tokio::time::timeout(WINDOW, async {
        for mutation in [
            ReadMutation::Filler,
            ReadMutation::Direction,
            ReadMutation::Nonce,
            ReadMutation::Sequence,
            ReadMutation::PayloadChecksum,
            ReadMutation::SourceVip,
            ReadMutation::DestinationVip,
            ReadMutation::TrailingByte,
        ] {
            let mut fixture = Fixture::new().await;
            assert_eq!(fixture.inject_periodic().await, 1);
            if matches!(mutation, ReadMutation::DestinationVip) {
                add_real_route_peer(&fixture.peers, "peer-b14-dst", "10.20.0.3").await;
            }
            let peers = fixture.peers.clone();
            let (mut plane, mut receiver, _) = tracked_plane(&mut fixture, peers, mutation);
            let invalid = read_routed_once(&mut plane, &mut receiver).await;
            let binding = invalid
                .binding()
                .expect("corruption never downgrades a real token to Legacy");
            assert_eq!(
                binding.state(),
                RequestBindingState::Invalid(RequestBindingFailure::OriginalBytes)
            );
            assert_eq!(
                binding.eligibility_at(Instant::now()),
                RequestInputEligibility::Invalid(RequestBindingFailure::OriginalBytes)
            );
            let request = binding.token().request().unwrap();
            assert!(Arc::ptr_eq(&request, &fixture.sent_nonces[&request.nonce]));
            assert_eq!(request.peer_id, PEER);
            assert_eq!(request.local_vip(), LOCAL_VIP);
            assert_eq!(request.target_vip(), PEER_VIP);
            assert!(request.injection_accepted());
            if matches!(mutation, ReadMutation::Filler) {
                assert_eq!(
                    &invalid.packet[..51],
                    &request.original_packet()[..51],
                    "filler control leaves original IP/UDP/identity header unchanged"
                );
                assert_ne!(invalid.packet.as_slice(), request.original_packet());
            }
            if matches!(mutation, ReadMutation::TrailingByte) {
                assert_eq!(
                    invalid.packet.as_slice(),
                    request.original_packet(),
                    "original clip can restore bytes but must not heal invalid identity"
                );
            }
            drop(request);
            assert_eq!(fixture.inject_periodic().await, 1);
            // Only the original peer is committed; the added routing-only peer
            // does not produce a second periodic minter target.
            let fresh = read_routed_once(&mut plane, &mut receiver).await;
            assert_exact_actual_identity(&fixture, &fresh);
            assert!(!Arc::ptr_eq(
                &binding.token().request().unwrap(),
                &fresh.binding().unwrap().token().request().unwrap()
            ));
        }
    })
    .await
    .expect("real mutation controls do not widen the original 1s fixture window");
}

#[tokio::test]
async fn b14_c03_real_owner_route_and_normalization_do_not_rebind_original_identity() {
    tokio::time::timeout(WINDOW, async {
        // Same peer/VIP bytes under a genuinely independent existing manager.
        let mut fixture = Fixture::new().await;
        let other = Fixture::new().await;
        assert_eq!(fixture.inject_periodic().await, 1);
        let (mut plane, mut receiver, _) =
            tracked_plane(&mut fixture, other.peers.clone(), ReadMutation::None);
        let delivery = read_routed_once(&mut plane, &mut receiver).await;
        let binding = delivery.binding().unwrap();
        assert_eq!(
            binding.state(),
            RequestBindingState::Invalid(RequestBindingFailure::ForeignOwner)
        );
        let original = binding.token().request().unwrap();
        assert!(original.belongs_to(&fixture.peers));
        assert!(!original.belongs_to(&other.peers));
        assert!(Arc::ptr_eq(
            &original,
            &fixture.sent_nonces[&original.nonce]
        ));
        assert_eq!(
            delivery.peer_id, PEER,
            "original business routing still emits under its actual manager"
        );
        drop(original);

        // Genuine original VIP map changes after mint, with no token relabel.
        let mut fixture = Fixture::new().await;
        assert_eq!(fixture.inject_periodic().await, 1);
        fixture.peers.remove_peer(PEER).await;
        add_real_route_peer(&fixture.peers, "peer-b14-replacement", PEER_VIP).await;
        let peers = fixture.peers.clone();
        let (mut plane, mut receiver, _) = tracked_plane(&mut fixture, peers, ReadMutation::None);
        let delivery = read_routed_once(&mut plane, &mut receiver).await;
        let binding = delivery.binding().unwrap();
        assert_eq!(delivery.peer_id, "peer-b14-replacement");
        assert_eq!(
            binding.state(),
            RequestBindingState::Invalid(RequestBindingFailure::RouteIdentity)
        );
        assert_eq!(binding.token().request().unwrap().peer_id, PEER);

        // Actual minter uses an OS source; the existing normalization algorithm
        // converts it to this TUN address. Read was exact, route bytes change.
        let mut fixture = Fixture::new().await;
        assert_eq!(
            send_overlay_payloads(
                &fixture.controller,
                &fixture.peers,
                "192.168.1.9",
                true,
                None,
                &mut fixture.next_nonce,
                &mut fixture.next_seq,
                &mut fixture.stats,
                &mut fixture.sent_nonces,
                &mut fixture.nonce_order,
            )
            .await,
            1
        );
        let peers = fixture.peers.clone();
        let (mut plane, mut receiver, _) = tracked_plane(&mut fixture, peers, ReadMutation::None);
        let normalized = read_routed_once(&mut plane, &mut receiver).await;
        let binding = normalized.binding().unwrap();
        assert_eq!(
            binding.state(),
            RequestBindingState::Invalid(RequestBindingFailure::RouteBytes)
        );
        let original = binding.token().request().unwrap();
        assert_eq!(original.local_vip(), "192.168.1.9");
        assert_eq!(
            p2pnet_tun::IpPacket::new(&normalized.packet)
                .unwrap()
                .src_addr_string(),
            LOCAL_VIP
        );
        assert_ne!(normalized.packet.as_slice(), original.original_packet());
        assert!(Arc::ptr_eq(
            &original,
            &fixture.sent_nonces[&original.nonce]
        ));
        drop(original);
        assert_eq!(fixture.inject_periodic().await, 1);
        let fresh = read_routed_once(&mut plane, &mut receiver).await;
        assert_exact_actual_identity(&fixture, &fresh);
    })
    .await
    .expect("real owner/map/normalize controls retain the original 1s fixture window");
}

#[tokio::test]
async fn b14_c04_real_burst_eviction_and_view_drop_retire_weak_carriers() {
    tokio::time::timeout(WINDOW, async {
        let mut fixture = Fixture::new().await;
        fixture.arm_burst();
        let peers = fixture.peers.clone();
        let (mut plane, mut receiver, _) = tracked_plane(&mut fixture, peers, ReadMutation::None);
        let count = OVERLAY_NONCE_CAP + 1;
        let (_, deliveries) = tokio::join!(fixture.inject_burst_attempts(count), async {
            let mut deliveries = Vec::new();
            for _ in 0..count {
                deliveries.push(read_routed_once(&mut plane, &mut receiver).await);
            }
            deliveries
        });
        assert_eq!(fixture.sent_nonces.len(), OVERLAY_NONCE_CAP);
        assert_eq!(fixture.bursts[PEER].nonces.len(), count);
        let first = &deliveries[0];
        let first_request = first.binding().unwrap().token().request().unwrap();
        assert!(!fixture.sent_nonces.contains_key(&first_request.nonce));
        assert!(Arc::ptr_eq(&first_request, &fixture.bursts[PEER].nonces[0]));
        drop(first_request);
        assert_eq!(Arc::strong_count(&fixture.bursts[PEER].nonces[0]), 1);
        let parked_clone: RawRequestDelivery = (*first).clone();
        assert_eq!(
            Arc::strong_count(&fixture.bursts[PEER].nonces[0]),
            1,
            "raw packet/carrier clones cannot strongly retain the canonical request"
        );
        fixture.bursts.remove(PEER);
        assert!(first.binding().unwrap().token().request().is_none());
        assert!(parked_clone.binding().unwrap().token().request().is_none());
        assert_eq!(
            first.binding().unwrap().eligibility_at(Instant::now()),
            RequestInputEligibility::Retired
        );
        assert!(deliveries
            .last()
            .unwrap()
            .binding()
            .unwrap()
            .token()
            .request()
            .is_some());
        fixture.sent_nonces.clear();
        fixture.nonce_order.clear();
        assert!(deliveries.iter().all(|delivery| delivery
            .binding()
            .unwrap()
            .token()
            .request()
            .is_none()));
        assert_eq!(fixture.inject_periodic().await, 1);
        let fresh = read_routed_once(&mut plane, &mut receiver).await;
        assert_exact_actual_identity(&fixture, &fresh);
        assert!(
            parked_clone.binding().unwrap().token().request().is_none(),
            "a new same-peer record cannot resurrect the original Weak identity"
        );
        assert_eq!(
            Arc::strong_count(fixture.sent_nonces.values().next().unwrap()),
            1
        );
    })
    .await
    .expect("real 257 burst/read drains original 256 within the unchanged 1s fixture window");
}

#[tokio::test]
async fn b14_c11_support_legacy_literal_default_constructor_and_unknown_any_stay_raw() {
    tokio::time::timeout(WINDOW, async {
        let mut fixture = Fixture::new().await;
        assert_eq!(fixture.inject_periodic().await, 1);
        let original = fixture
            .sent_nonces
            .values()
            .next()
            .unwrap()
            .original_packet()
            .to_vec();
        let (tun, _) = AuditedMockTun::new(fixture.tun.take().unwrap(), ReadMutation::None);
        let (mut plane, mut receiver) = DataPlane::new(tun, fixture.peers.clone());
        assert_eq!(receiver.max_capacity(), 1024);
        plane.read_and_route_once(&mut [0u8; 512]).await.unwrap();
        let raw: OutboundPacket = receiver.try_recv().unwrap();
        assert_eq!(raw.packet, original);
        let literal = OutboundPacket {
            room_authorization: None,
            peer_id: PEER.to_string(),
            dst_ip: PEER_VIP.to_string(),
            packet: raw.packet.clone(),
            trace: None,
        };
        let legacy = RawRequestDelivery::from(literal.clone());
        assert_eq!(legacy.packet, literal.packet);
        assert!(legacy.binding().is_none());

        let mut fixture = Fixture::new().await;
        assert_eq!(fixture.inject_periodic().await, 1);
        let peers = fixture.peers.clone();
        let (mut plane, mut receiver, _) = tracked_plane(&mut fixture, peers, ReadMutation::None);
        let genuine = read_routed_once(&mut plane, &mut receiver).await;
        assert_exact_actual_identity(&fixture, &genuine);
        let bytes = genuine.packet.clone();
        fixture.controller.inject(bytes.clone()).await.unwrap();
        let raw = read_routed_once(&mut plane, &mut receiver).await;
        assert_eq!(raw.packet, bytes);
        assert!(
            raw.binding().is_none(),
            "same known bytes cannot fabricate a missing sealed token"
        );
        fixture
            .controller
            .inject_with_context(bytes.clone(), Box::new(String::from("public Any unknown")))
            .await
            .unwrap();
        let unknown = read_routed_once(&mut plane, &mut receiver).await;
        assert_eq!(unknown.packet, bytes);
        assert!(
            unknown.binding().is_none(),
            "public Any cannot invent a private producer source"
        );
        assert_exact_actual_identity(&fixture, &genuine);
        // Supporting local raw/API evidence only. This does not close C11's
        // complete old regression/interface matrix, C05/C06, or native credit.
    })
    .await
    .expect("legacy/Unknown positive routing keeps the original 1s fixture window");
}
