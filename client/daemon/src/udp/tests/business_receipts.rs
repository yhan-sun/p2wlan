//! Actual loopback UDP/WG/Mock workflow. Missing hooks are executable RED.
//! The bounded observer bridge is fixture-only and forwards the same envelope.

use super::*;
use crate::business_evidence::*;
use futures_util::FutureExt;
use p2pnet_tun::VirtualInterface;
use std::future::Future;
use std::num::NonZeroU64;
use std::pin::Pin;
use tokio::sync::{oneshot, watch};
use tokio::time::{timeout_at, Instant as TokioInstant};

struct ReleaseOnDrop(Option<oneshot::Sender<()>>);

impl ReleaseOnDrop {
    fn release(&mut self) {
        if let Some(sender) = self.0.take() {
            let _ = sender.send(());
        }
    }
}

impl Drop for ReleaseOnDrop {
    fn drop(&mut self) {
        self.release();
    }
}

struct ControlledMockTun {
    inner: MockTunDevice,
    entered: Option<oneshot::Sender<()>>,
    release: Option<oneshot::Receiver<()>>,
    workflow_deadline: TokioInstant,
}

// Matches VirtualInterface's async_trait-expanded signatures without adding
// a dependency or changing the platform-TUN implementation.
impl VirtualInterface for ControlledMockTun {
    fn read<'life0, 'life1, 'async_trait>(
        &'life0 mut self,
        buf: &'life1 mut [u8],
    ) -> Pin<Box<dyn Future<Output = p2pnet_tun::Result<usize>> + Send + 'async_trait>>
    where
        'life0: 'async_trait,
        'life1: 'async_trait,
        Self: 'async_trait,
    {
        Box::pin(async move { self.inner.read(buf).await })
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
        Box::pin(async move {
            if let Some(entered) = self.entered.take() {
                let _ = entered.send(());
            }
            if let Some(release) = self.release.take() {
                let deadline = self
                    .workflow_deadline
                    .min(TokioInstant::now() + Duration::from_secs(2));
                timeout_at(deadline, release)
                    .await
                    .map_err(|_| p2pnet_tun::Error::DeviceClosed)?
                    .map_err(|_| p2pnet_tun::Error::DeviceClosed)?;
            }
            self.inner.write(buf).await
        })
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

struct Children(JoinSet<()>);

impl Children {
    fn new() -> Self {
        Self(JoinSet::new())
    }

    fn spawn<F>(&mut self, future: F)
    where
        F: Future<Output = ()> + Send + 'static,
    {
        self.0.spawn(future);
    }

    async fn abort_join(
        &mut self,
    ) -> std::result::Result<Option<tokio::task::JoinError>, tokio::time::error::Elapsed> {
        self.0.abort_all();
        timeout_at(TokioInstant::now() + Duration::from_secs(1), async {
            let mut first_panic = None;
            while let Some(result) = self.0.join_next().await {
                if let Err(error) = result {
                    if !error.is_cancelled() && first_panic.is_none() {
                        first_panic = Some(error);
                    }
                }
            }
            first_panic
        })
        .await
    }
}

impl Drop for Children {
    fn drop(&mut self) {
        self.0.abort_all();
    }
}

#[derive(Clone, Copy)]
struct EnvelopeObservation {
    source: Option<SocketAddr>,
    local_endpoint: Option<SocketAddr>,
    socket_index: Option<usize>,
    publication: Option<u64>,
    generation: Option<u64>,
    wire: WireTuple,
}

struct FixtureFacts {
    snapshot: SlotSnapshot,
    registered: RegisteredObservation,
    wg_owner: WgEvidenceOwnerId,
    old_sid: u64,
    runtime: u64,
    publication: u64,
    source: SocketAddr,
    local_endpoint: SocketAddr,
    wire: WireTuple,
    target: TunEvidenceIdentity,
    packet_len: usize,
    owner_changed: bool,
}

fn request_packet() -> Vec<u8> {
    // Same P2WUDE1 header fields/filler as the OS tool, no nonce truncation.
    let payload_len = 8u16;
    let total = 20 + 8 + OS_UDP_HEADER_BYTES + usize::from(payload_len);
    let mut raw = vec![0; total];
    raw[0] = 0x45;
    raw[2..4].copy_from_slice(&(total as u16).to_be_bytes());
    raw[6] = 0x40;
    raw[8] = 64;
    raw[9] = 17;
    raw[12..16].copy_from_slice(&[10, 20, 0, 1]);
    raw[16..20].copy_from_slice(&[10, 20, 0, 2]);
    let mut checksum = raw[..20]
        .chunks_exact(2)
        .map(|pair| u32::from(u16::from_be_bytes([pair[0], pair[1]])))
        .sum::<u32>();
    while checksum >> 16 != 0 {
        checksum = (checksum & 0xffff) + (checksum >> 16);
    }
    raw[10..12].copy_from_slice(&(!(checksum as u16)).to_be_bytes());
    raw[20..22].copy_from_slice(&42023u16.to_be_bytes());
    raw[22..24].copy_from_slice(&42123u16.to_be_bytes());
    raw[24..26].copy_from_slice(&((total - 20) as u16).to_be_bytes());
    // Zero UDP checksum is valid for IPv4; the IP header checksum is real.
    let body = &mut raw[28..];
    body[..8].copy_from_slice(b"P2WUDE1\0");
    body[8] = 0;
    body[9..25].fill(0x11);
    body[25..41].fill(0x22);
    body[41..45].copy_from_slice(&7u32.to_be_bytes());
    body[45..61].fill(0x33);
    body[61..63].copy_from_slice(&payload_len.to_be_bytes());
    body[63..].fill(0xa5);
    raw
}

fn actual_wire_tuple(wire: &[u8]) -> WireTuple {
    assert!(wire.len() >= 16 && wire[..4] == [4, 0, 0, 0]);
    WireTuple {
        receiver_index: u32::from_le_bytes(wire[4..8].try_into().unwrap()),
        counter: crate::transport::wire_counter(wire).expect("actual WG counter"),
        wire_len: wire.len() as u32,
    }
}

async fn real_workflow(change_owner: bool) -> FixtureFacts {
    let workflow_deadline = TokioInstant::now() + Duration::from_secs(5);
    let mut children = Children::new();
    let workflow = async {
        let raw = request_packet();
        let parsed = parse_os_udp(&raw).expect("real request must parse before registration");
        let capture = CaptureOwner::arm(
            CaptureScope {
                capture_id: [0x41; 16],
                producer_scope: [0x42; 16],
            },
            &["peer-a"],
            &[Registration {
                key: parsed.key,
                flow: parsed.flow,
                expected_payload_bytes: parsed.payload_bytes,
                peer_slot: 0,
            }],
            Duration::from_secs(10),
        )
        .unwrap();
        let registered = capture.lookup_registered(&raw, "peer-a").unwrap();
        assert!(capture
            .try_read_registered(registered.slot())
            .unwrap()
            .authenticated
            .is_none());
        let peers = peer_manager();
        peers.add_peer(&peer("peer-a", "10.20.0.1", None)).await;
        let generation = peers.current_network_generation().await;
        let (tun, controller) = MockTunDevice::new_pair("receipt-mock", 1420, "10.20.0.2");
        let (entered_tx, entered_rx) = oneshot::channel();
        let (release_tx, release_rx) = oneshot::channel();
        let mut gate = ReleaseOnDrop(Some(release_tx));
        let controlled = ControlledMockTun {
            inner: tun,
            entered: Some(entered_tx),
            release: Some(release_rx),
            workflow_deadline,
        };
        let target = TunEvidenceIdentity {
            instance: NonZeroU64::new(101).unwrap(),
            backend: TunBackend::MockDelivered,
        };
        let (dataplane, _outbound_rx, inbound_tx) =
            DataPlane::new_bidirectional(controlled, peers.clone());
        let mut dataplane = dataplane
            .with_rx_business_capture(capture.clone(), target)
            .unwrap();
        children.spawn(async move {
            dataplane.run().await.expect("actual dataplane worker");
        });

        let (mut sender_session, receiver_session) = establish_sessions();
        let (wireguard, _outbound_rx) = WireGuardTransport::new();
        let wireguard = wireguard.with_rx_business_capture(capture.clone()).unwrap();
        assert!(
            !wireguard.add_session("peer-a", receiver_session).await,
            "first installation has no predecessor to replace"
        );
        let old_sid = wireguard
            .session_status("peer-a")
            .await
            .active_session_instance
            .expect("installed real SID");
        let wg_owner = wireguard.wg_evidence_owner();
        assert_eq!(wireguard.clone().wg_evidence_owner(), wg_owner);
        let udp = UdpTransport::bind("127.0.0.1:0".parse().unwrap(), peers.clone())
            .await
            .unwrap()
            .with_rx_business_capture(capture.clone())
            .unwrap();
        let runtime = udp.transport_instance_id();
        let publication = 9001;
        udp.set_inbound_publication_owner(publication);
        assert_eq!(udp.inbound_publication_owner(), publication);
        let local_endpoint = udp.local_addr().unwrap();
        let (udp_updates, udp_watch) = watch::channel(Some(udp.clone()));
        let (reader_tx, mut reader_rx) = mpsc::channel::<ReceivedEncryptedPacket>(4);
        let (wg_tx, wg_rx) = mpsc::channel(4);
        let (observation_tx, observation_rx) = oneshot::channel();
        children.spawn(async move {
            let mut observation_tx = Some(observation_tx);
            while let Some(envelope) = reader_rx.recv().await {
                let observed = EnvelopeObservation {
                    source: envelope.source,
                    local_endpoint: envelope.local_endpoint,
                    socket_index: envelope.socket_index,
                    publication: envelope.udp_transport_owner,
                    generation: envelope.network_generation,
                    wire: actual_wire_tuple(&envelope.wire_bytes),
                };
                if let Some(sender) = observation_tx.take() {
                    let _ = sender.send(observed);
                }
                wg_tx
                    .send(envelope)
                    .await
                    .expect("same actual envelope forward");
            }
        });
        children.spawn({
            let wireguard = wireguard.clone();
            let peers = peers.clone();
            async move {
                wireguard
                    .run_inbound_with_peers_live_udp(wg_rx, inbound_tx, Some(peers), udp_watch)
                    .await
                    .expect("actual WG inbound worker");
            }
        });
        children.spawn({
            let udp = udp.clone();
            async move {
                udp.run_inbound(reader_tx).await.expect("actual UDP reader");
            }
        });
        let sender = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let source = sender.local_addr().unwrap();
        let wire_bytes = sender_session.encrypt_to_bytes(&raw).unwrap();
        let wire = actual_wire_tuple(&wire_bytes);
        assert_eq!(
            sender.send_to(&wire_bytes, local_endpoint).await.unwrap(),
            wire_bytes.len()
        );
        let observed = timeout_at(
            workflow_deadline.min(TokioInstant::now() + Duration::from_secs(1)),
            observation_rx,
        )
        .await
        .expect("actual encrypted ingress arrived")
        .expect("actual encrypted observation");
        assert_eq!(observed.source, Some(source));
        assert_eq!(observed.local_endpoint, Some(local_endpoint));
        assert_eq!(observed.socket_index, Some(0));
        assert_eq!(observed.publication, Some(publication));
        assert_eq!(observed.generation, Some(generation));
        assert_eq!(observed.wire, wire);
        timeout_at(
            workflow_deadline.min(TokioInstant::now() + Duration::from_secs(1)),
            entered_rx,
        )
        .await
        .expect("authenticated request reached the actual TUN write await")
        .expect("write arrival notification");
        // The original SID is the only installed decrypt owner up to this
        // actual write boundary. This precondition does not fake a receipt.
        assert_eq!(
            wireguard
                .session_status("peer-a")
                .await
                .active_session_instance,
            Some(old_sid)
        );
        assert_eq!(udp.transport_instance_id(), runtime);
        if change_owner {
            let (_, replacement_session) = establish_sessions();
            assert!(
                timeout_at(
                    workflow_deadline.min(TokioInstant::now() + Duration::from_secs(1)),
                    wireguard.add_session("peer-a", replacement_session),
                )
                .await
                .expect("session replacement bounded"),
                "real predecessor was replaced"
            );
            let new_sid = wireguard
                .session_status("peer-a")
                .await
                .active_session_instance
                .unwrap();
            assert_ne!(new_sid, old_sid, "actual session owner must change");
            let replacement = timeout_at(
                workflow_deadline.min(TokioInstant::now() + Duration::from_secs(1)),
                UdpTransport::bind("127.0.0.1:0".parse().unwrap(), peers.clone()),
            )
            .await
            .expect("runtime replacement bounded")
            .unwrap()
            .with_rx_business_capture(capture.clone())
            .unwrap();
            replacement.set_inbound_publication_owner(publication + 1);
            assert_ne!(replacement.transport_instance_id(), runtime);
            udp_updates.send(Some(replacement)).unwrap();
            let live = udp_updates.borrow().clone().unwrap();
            assert_ne!(live.transport_instance_id(), runtime);
            assert_ne!(live.inbound_publication_owner(), publication);
        }
        gate.release();
        let written = timeout_at(
            workflow_deadline.min(TokioInstant::now() + Duration::from_secs(1)),
            controller.recv_written(),
        )
        .await
        .expect("actual Mock full write bounded")
        .expect("actual Mock written bytes");
        assert!(
            written == raw,
            "actual packet bytes differ (length only: {})",
            written.len()
        );
        let delivered = parse_os_udp(&written).unwrap();
        assert!(delivered.key == parsed.key, "full key differs (redacted)");
        assert_eq!(delivered.flow, parsed.flow);
        assert_eq!(delivered.ip_packet_len as usize, raw.len());
        timeout_at(
            workflow_deadline.min(TokioInstant::now() + Duration::from_secs(1)),
            async {
                loop {
                    let connection = peers.get_connection("peer-a").await.unwrap();
                    if connection.bytes_received == raw.len() as u64 {
                        assert_eq!(connection.endpoint, Some(source));
                        assert_ne!(connection.state.to_string(), "direct");
                        break;
                    }
                    tokio::task::yield_now().await;
                }
            },
        )
        .await
        .expect("actual full-write peer accounting must complete");
        let snapshot = capture.try_read_registered(registered.slot()).unwrap();
        FixtureFacts {
            snapshot,
            registered,
            wg_owner,
            old_sid,
            runtime,
            publication,
            source,
            local_endpoint,
            wire,
            target,
            packet_len: raw.len(),
            owner_changed: change_owner,
        }
    };
    // Even unexpected precondition panics/expiry clean up before rethrowing.
    let outcome = timeout_at(
        workflow_deadline,
        std::panic::AssertUnwindSafe(workflow).catch_unwind(),
    )
    .await;
    let cleanup = children.abort_join().await;
    match outcome {
        Ok(Ok(facts)) => match cleanup {
            Ok(None) => facts,
            Ok(Some(error)) => std::panic::resume_unwind(error.into_panic()),
            Err(_) => panic!("fixture children must abort/join within one second"),
        },
        Ok(Err(panic)) => {
            // Preserve the original workflow panic after attempting the same
            // bounded complete drain; report incomplete cleanup separately.
            eprintln!(
                "fixture_cleanup_complete={} fixture_child_panic_present={}",
                cleanup.is_ok(),
                matches!(&cleanup, Ok(Some(_)))
            );
            std::panic::resume_unwind(panic)
        }
        Err(_) => match cleanup {
            Ok(Some(error)) => std::panic::resume_unwind(error.into_panic()),
            Ok(None) => panic!("fixed five-second native fixture deadline expired"),
            Err(_) => panic!("native fixture expired and one-second child cleanup was incomplete"),
        },
    }
}

fn assert_historical_receipts(facts: FixtureFacts) {
    // These target assertions intentionally fail at runtime until real hooks
    // are separately authorized. All physical/full-write assertions precede.
    assert!(
        facts.snapshot.authenticated.is_some(),
        "actual auth/full Mock write requires Auth receipt"
    );
    assert!(
        facts.snapshot.tun_full.is_some(),
        "actual full Mock write requires TunFull receipt"
    );
    let auth = facts.snapshot.authenticated.unwrap();
    let full = facts.snapshot.tun_full.unwrap();
    assert!(!facts.snapshot.ambiguous);
    assert_eq!(auth.registered(), facts.registered);
    assert_eq!(auth.wg_owner(), facts.wg_owner);
    assert_eq!(auth.session_instance().get(), facts.old_sid);
    assert!(!auth.auth_prev_session());
    assert_eq!(auth.wire(), facts.wire);
    assert_eq!(
        auth.physical().ingress(),
        ObservedIngress::DirectUdpObserved
    );
    assert_eq!(
        auth.physical().runtime_instance().map(NonZeroU64::get),
        Some(facts.runtime)
    );
    assert_eq!(
        auth.physical().publication(),
        PublicationObservation::EnqueueObserved {
            owner: NonZeroU64::new(facts.publication),
        }
    );
    assert_eq!(auth.physical().source(), Some(facts.source));
    assert_eq!(auth.physical().local_endpoint(), Some(facts.local_endpoint));
    assert_eq!(auth.physical().socket_index(), Some(0));
    assert_eq!(full.authenticated(), auth);
    assert_eq!(full.target(), facts.target);
    assert_eq!(full.written(), facts.packet_len as u32);
    assert_eq!(full.normalized_flow(), facts.registered.registration().flow);
    if facts.owner_changed {
        assert!(matches!(
            full.current_fence(),
            CurrentFence::Stale | CurrentFence::Unknown
        ));
    }
}

#[tokio::test]
async fn authenticated_os_udp_full_mock_write_keeps_original_context() {
    assert_historical_receipts(real_workflow(false).await);
}

#[tokio::test]
async fn path_and_session_change_during_mock_write_preserves_history() {
    assert_historical_receipts(real_workflow(true).await);
}
