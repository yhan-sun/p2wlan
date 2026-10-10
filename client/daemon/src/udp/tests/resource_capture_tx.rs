//! Native MockTUN TX and encrypted UDP return: business first, resources last.
//! The held original emit guard forces slow sending; fast serialization is
//! outside these two cases. Capture identifiers are diagnostics, not authority.

use super::*;
use crate::connection_timeline::ConnectionTimeline;
use crate::dataplane::InboundPacket;
use crate::dataplane_resources::{QueueStage, ResourceCapture, ResourceSnapshot, VecSite};
use crate::network_outbound::{run_network_outbound, RelayStartupWait};
use crate::peer::NetworkPath;
use futures_util::FutureExt;
use p2pnet_tun::Protocol;
use p2pnet_wireguard::MessageTransport;
use std::any::Any;
use std::future::Future;
use std::sync::Weak;
use tokio::sync::{oneshot, watch, OwnedMutexGuard, RwLock};
use tokio::time::{timeout_at, Instant as TokioInstant};

const PEER: &str = "resource-tx-peer";
const LOCAL_VIP: Ipv4Addr = Ipv4Addr::new(10, 20, 0, 2);
const PEER_VIP: Ipv4Addr = Ipv4Addr::new(10, 20, 0, 1);
const TX_POLLUTED: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 21);
const RX_POLLUTED: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 22);
const TX_BODY: &[u8] = b"resource native tx";
const RX_BODY: &[u8] = b"resource native return";
const PUBLICATION: u64 = 9401;

struct Children(JoinSet<()>);

impl Children {
    fn spawn<F: Future<Output = ()> + Send + 'static>(&mut self, future: F) {
        self.0.spawn(future);
    }

    async fn abort_join(&mut self, deadline: TokioInstant) -> Option<Box<dyn Any + Send>> {
        self.0.abort_all();
        timeout_at(deadline, async {
            let mut first_panic = None;
            while let Some(result) = self.0.join_next().await {
                if let Err(error) = result {
                    if error.is_panic() && first_panic.is_none() {
                        first_panic = Some(error.into_panic());
                    }
                }
            }
            first_panic
        })
        .await
        .expect("cleanup failure: all native TX/RX children must drain within the original five seconds")
    }
}

impl Drop for Children {
    fn drop(&mut self) {
        self.0.abort_all();
    }
}

fn arrival_deadline(work_deadline: TokioInstant) -> TokioInstant {
    work_deadline.min(TokioInstant::now() + Duration::from_secs(1))
}

fn assert_icmp(raw: &[u8], src: Ipv4Addr, dst: Ipv4Addr, id: u16, body: &[u8]) {
    let parsed = Ipv4Packet::new(raw).expect("native business IPv4 parses");
    assert_eq!(usize::from(parsed.total_len()), raw.len());
    assert_eq!(parsed.header_len(), 20);
    assert_eq!(parsed.identification(), id);
    assert_eq!(parsed.tos(), 0);
    assert_eq!(parsed.ttl(), 64);
    assert_eq!(parsed.flags_fragment(), 0x4000);
    assert_eq!(parsed.protocol(), Protocol::Icmp);
    assert!(
        parsed.src_addr() == src && parsed.dst_addr() == dst,
        "native business IPv4 addresses"
    );
    assert!(parsed.verify_checksum(), "native business IPv4 checksum");
    assert!(!parsed.is_fragment());
    let icmp = parsed.payload();
    assert_eq!(icmp.len(), 8 + body.len());
    assert!(icmp[..2] == [8, 0], "native business ICMP type/code");
    assert_eq!(u16::from_be_bytes([icmp[4], icmp[5]]), id);
    assert_eq!(u16::from_be_bytes([icmp[6], icmp[7]]), 1);
    assert!(
        icmp[8..] == *body,
        "native business ICMP payload length {}",
        body.len()
    );
    // Independent read-only checksum verification; no normalization or send
    // implementation is reproduced, and no fixture buffer is observed.
    let mut sum = icmp
        .as_chunks::<2>()
        .0
        .iter()
        .map(|pair| u32::from(u16::from_be_bytes(*pair)))
        .sum::<u32>();
    if !icmp.len().is_multiple_of(2) {
        sum += u32::from(*icmp.last().unwrap()) << 8;
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    assert_eq!(sum, 0xffff, "native business ICMP checksum");
}

struct CaseLengths {
    tx: usize,
    wire: usize,
    rx: usize,
}

/// Setup and observations only: every business transition below executes its
/// original owner. Neither case constructs an OutboundPacket or observes Vecs.
async fn native_workflow(
    normalized: bool,
    resources: Arc<ResourceCapture>,
    children: &mut Children,
    held_emit: &mut Option<OwnedMutexGuard<()>>,
    sockets_to_release: &mut Vec<Weak<UdpSocket>>,
    deadline: TokioInstant,
) -> CaseLengths {
    let peers = peer_manager();
    let remote_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let remote_endpoint = remote_socket.local_addr().unwrap();
    peers
        .add_peer(&peer(PEER, "10.20.0.1", Some(remote_endpoint)))
        .await;
    peers
        .set_local_interface_networks(vec![p2pnet_nat::LocalNetwork::new(
            "127.0.0.1".parse().unwrap(),
            8,
        )])
        .await;
    peers
        .add_candidates_with_sources(
            PEER,
            &[remote_endpoint.to_string()],
            &HashMap::from([(remote_endpoint.to_string(), "host".to_string())]),
        )
        .await;
    let udp = UdpTransport::bind("127.0.0.1:0".parse().unwrap(), peers.clone())
        .await
        .unwrap()
        .with_resource_capture(resources.clone())
        .unwrap();
    udp.set_inbound_publication_owner(PUBLICATION);
    let local_endpoint = udp.local_addr().unwrap();
    let udp_runtime = udp.transport_instance_id();
    assert_ne!(udp_runtime, 0);
    // Bind creates one fixed IPv4 socket and at most one IPv6 socket; no pool,
    // dynamic socket or validation worker is enabled by this fixture.
    assert_eq!(udp.active_sockets().len(), 1);
    sockets_to_release.push(Arc::downgrade(&udp.socket));
    if let Some(socket) = udp.ipv6_socket.as_ref() {
        sockets_to_release.push(Arc::downgrade(socket));
    }
    assert!(sockets_to_release.len() <= 2);
    assert!(!udp.peer_requires_direct_business_budget(PEER));
    peers
        .record_direct_probe_success_with_latency_and_local_endpoint(
            PEER,
            remote_endpoint,
            Some(Duration::from_millis(1)),
            Some(local_endpoint),
        )
        .await;
    peers
        .record_direct_success_with_local_endpoint(
            PEER,
            Some(remote_endpoint),
            Some(local_endpoint),
        )
        .await;
    let generation = peers.current_network_generation_sync();
    let path = peers
        .active_direct_path_snapshot(PEER, generation, true)
        .await
        .expect("authoritative fixture LAN Direct snapshot");
    assert_eq!(path.path, NetworkPath::Direct);
    assert!(path.endpoint == remote_endpoint);
    assert!(peers.active_direct_path_snapshot_is_current_sync(PEER, path));

    let (local_session, mut remote_session) = establish_sessions();
    let local_receiver_index = local_session.our_index();
    let remote_receiver_index = remote_session.our_index();
    let (wireguard, network_rx) = WireGuardTransport::new();
    assert_eq!(network_rx.max_capacity(), 1024);
    let wireguard = wireguard.with_resource_capture(resources.clone()).unwrap();
    assert!(!wireguard.add_session(PEER, local_session).await);
    let sid = wireguard
        .session_status(PEER)
        .await
        .active_session_instance
        .unwrap();
    let wg_owner = wireguard.wg_evidence_owner();
    assert_eq!(wireguard.clone().wg_evidence_owner(), wg_owner);
    // This is the real counter-ordering guard, acquired before TUN injection.
    // Fast admission cannot enter it; its original fallback enters slow prepare.
    *held_emit = Some(wireguard.acquire_outbound_emit_guard(PEER).await);

    let (tun, controller) = MockTunDevice::new_pair("resource-tx-native", 1420, "10.20.0.2");
    let (dataplane, routed_rx, inbound_tx) = DataPlane::new_bidirectional(tun, peers.clone());
    assert_eq!(routed_rx.max_capacity(), 1024);
    assert_eq!(inbound_tx.max_capacity(), 1024);
    let mut dataplane = dataplane
        .with_resource_capture(resources.clone())
        .unwrap()
        .with_overlay_cidr("10.20.0.0/16");
    children.spawn(async move { dataplane.run().await.expect("original DataPlane pump") });
    children.spawn({
        let wireguard = wireguard.clone();
        async move {
            wireguard
                .run_outbound(routed_rx)
                .await
                .expect("original WG RAW forwarding")
        }
    });
    let udp_slot = Arc::new(RwLock::new(Some(udp.clone())));
    let (_relay_available_tx, relay_available_rx) = watch::channel(false);
    let (probe_kick_tx, _probe_kick_rx) = watch::channel(0_u64);
    children.spawn(run_network_outbound(
        network_rx,
        wireguard.clone(),
        peers.clone(),
        true,
        udp_slot.clone(),
        Arc::new(RwLock::new(None)),
        relay_available_rx,
        RelayStartupWait {
            relay_expected: false,
            timeout: None,
        },
        probe_kick_tx,
        ConnectionTimeline::new("resource-tx-native", 0),
    ));

    let (physical_tx, physical_rx) = oneshot::channel();
    let (plaintext_tx, plaintext_rx) = oneshot::channel();
    // Keep the publication sender alive for this complete native workflow.
    let (_udp_updates, udp_watch) = watch::channel(Some(udp.clone()));
    if normalized {
        let (reader_tx, mut reader_rx) = mpsc::channel::<ReceivedEncryptedPacket>(4);
        let (wg_tx, wg_rx) = mpsc::channel(4);
        let (plain_tx, mut plain_rx) = mpsc::channel::<InboundPacket>(4);
        children.spawn({
            let udp = udp.clone();
            async move {
                udp.run_inbound(reader_tx)
                    .await
                    .expect("original UDP reader")
            }
        });
        children.spawn({
            let wireguard = wireguard.clone();
            let peers = peers.clone();
            async move {
                // Bounded bridges inspect original envelopes and move them
                // unchanged. Three futures share one child; no detached task.
                let physical = async move {
                    let mut observed = Some(physical_tx);
                    while let Some(envelope) = reader_rx.recv().await {
                        if let Some(sender) = observed.take() {
                            let _ = sender.send((
                                envelope.source,
                                envelope.local_endpoint,
                                envelope.udp_transport_owner,
                                envelope.network_generation,
                                envelope.socket_index,
                                envelope.wire_bytes.len(),
                                crate::transport::wire_counter(&envelope.wire_bytes),
                            ));
                        }
                        wg_tx
                            .send(envelope)
                            .await
                            .expect("same original UDP envelope");
                    }
                    Ok::<(), crate::error::DaemonError>(())
                };
                let plaintext = async move {
                    let mut observed = Some(plaintext_tx);
                    while let Some(inbound) = plain_rx.recv().await {
                        assert!(inbound.peer_id == PEER);
                        assert_eq!(inbound.session_instance, Some(sid));
                        assert!(!inbound.from_previous_session);
                        assert_icmp(&inbound.packet, RX_POLLUTED, LOCAL_VIP, 0x9402, RX_BODY);
                        if let Some(sender) = observed.take() {
                            let _ = sender.send((inbound.session_instance, inbound.packet.len()));
                        }
                        inbound_tx
                            .send(inbound)
                            .await
                            .expect("same original WG plaintext");
                    }
                    Ok::<(), crate::error::DaemonError>(())
                };
                tokio::try_join!(
                    physical,
                    wireguard.run_inbound_with_peers_live_udp(
                        wg_rx,
                        plain_tx,
                        Some(peers),
                        udp_watch
                    ),
                    plaintext,
                )
                .expect("original live UDP WG inbound and bounded inspection bridges");
            }
        });
    }

    let input = Ipv4Packet::build_icmp_echo_request(
        if normalized { TX_POLLUTED } else { LOCAL_VIP },
        PEER_VIP,
        0x9401,
        1,
        TX_BODY,
    );
    let tx_len = input.len();
    assert_icmp(
        &input,
        if normalized { TX_POLLUTED } else { LOCAL_VIP },
        PEER_VIP,
        0x9401,
        TX_BODY,
    );
    // This comparison reference is fixture-only; the injected business Vec is
    // consumed by MockTUN and counted exclusively at original owner sites.
    let expected = (!normalized).then(|| input.clone());
    timeout_at(arrival_deadline(deadline), controller.inject(input))
        .await
        .expect("original MockTUN injection bound")
        .unwrap();
    timeout_at(arrival_deadline(deadline), async {
        loop {
            let snapshot = resources.snapshot();
            assert!(
                snapshot.valid,
                "existing slow preparation observation remains valid"
            );
            let prepared = snapshot
                .vec_site(VecSite::TxPreparationCopy)
                .materialization_ops;
            assert!(
                prepared <= 1,
                "one native business input must not retry while held"
            );
            if prepared == 1 {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("original slow preparation must reach the held emit guard");
    drop(held_emit.take());

    let mut wire = [0_u8; 2048];
    let (wire_len, source) = timeout_at(
        arrival_deadline(deadline),
        remote_socket.recv_from(&mut wire),
    )
    .await
    .expect("native TX UDP arrival bound")
    .unwrap();
    assert!(
        source == local_endpoint,
        "actual TX uses the original UDP socket"
    );
    let message = MessageTransport::from_bytes(&wire[..wire_len]).expect("actual TX wire parses");
    assert_eq!(message.receiver_index, remote_receiver_index);
    assert_eq!(message.counter, 0);
    let decrypted = remote_session
        .decrypt(&message)
        .expect("paired remote session decrypts actual TX");
    assert_eq!(decrypted.len(), tx_len);
    assert_icmp(&decrypted, LOCAL_VIP, PEER_VIP, 0x9401, TX_BODY);
    if let Some(expected) = expected {
        assert!(
            decrypted == expected,
            "ordinary native TX exact plaintext length {}",
            tx_len
        );
    }
    timeout_at(arrival_deadline(deadline), async {
        loop {
            let connection = peers.get_connection(PEER).await.unwrap();
            if connection.bytes_sent == tx_len as u64 {
                assert_eq!(connection.bytes_received, 0);
                assert!(connection.endpoint == Some(remote_endpoint));
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("original routed TX byte accounting completes");
    assert_eq!(
        wireguard.session_status(PEER).await.active_session_instance,
        Some(sid)
    );
    assert_eq!(wireguard.wg_evidence_owner(), wg_owner);
    assert_eq!(peers.current_network_generation_sync(), generation);
    assert!(peers.active_direct_path_snapshot_is_current_sync(PEER, path));

    let mut rx_len = 0;
    if normalized {
        let returned =
            Ipv4Packet::build_icmp_echo_request(RX_POLLUTED, LOCAL_VIP, 0x9402, 1, RX_BODY);
        rx_len = returned.len();
        let return_wire = remote_session.encrypt_to_bytes(&returned).unwrap();
        let return_message = MessageTransport::from_bytes(&return_wire).unwrap();
        assert_eq!(return_message.receiver_index, local_receiver_index);
        assert_eq!(return_message.counter, 0);
        let sent = timeout_at(
            arrival_deadline(deadline),
            remote_socket.send_to(&return_wire, local_endpoint),
        )
        .await
        .expect("real encrypted return UDP send bound")
        .unwrap();
        assert_eq!(sent, return_wire.len());
        let physical = timeout_at(arrival_deadline(deadline), physical_rx)
            .await
            .expect("original UDP envelope observation bound")
            .unwrap();
        assert!(physical.0 == Some(remote_endpoint) && physical.1 == Some(local_endpoint));
        assert_eq!(physical.2, Some(PUBLICATION));
        assert_eq!(physical.3, Some(generation));
        assert_eq!(physical.4, Some(0));
        assert_eq!(physical.5, return_wire.len());
        assert_eq!(physical.6, Some(0));
        let plaintext = timeout_at(arrival_deadline(deadline), plaintext_rx)
            .await
            .expect("original WG plaintext observation bound")
            .unwrap();
        assert_eq!(plaintext, (Some(sid), rx_len));
        let written = timeout_at(arrival_deadline(deadline), controller.recv_written())
            .await
            .expect("actual full normalized MockTUN write bound")
            .unwrap();
        assert_eq!(written.len(), rx_len);
        assert_icmp(&written, PEER_VIP, LOCAL_VIP, 0x9402, RX_BODY);
        timeout_at(arrival_deadline(deadline), async {
            loop {
                let connection = peers.get_connection(PEER).await.unwrap();
                if connection.bytes_received == rx_len as u64 {
                    assert_eq!(connection.bytes_sent, tx_len as u64);
                    assert!(connection.endpoint == Some(remote_endpoint));
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("original full RX byte accounting completes");
        let current = peers
            .active_direct_path_snapshot(PEER, generation, true)
            .await
            .expect("same authoritative Direct remains current after native RX");
        assert_eq!(current.path, NetworkPath::Direct);
        assert!(current.endpoint == remote_endpoint);
        assert_eq!(
            current.peer_session_generation,
            path.peer_session_generation
        );
        assert!(peers.active_direct_path_snapshot_is_current_sync(PEER, current));
    }
    assert_eq!(
        wireguard.session_status(PEER).await.active_session_instance,
        Some(sid)
    );
    assert_eq!(wireguard.wg_evidence_owner(), wg_owner);
    assert_eq!(peers.current_network_generation_sync(), generation);
    let published = udp_slot.read().await;
    let published = published.as_ref().expect("same actual published UDP owner");
    assert_eq!(published.transport_instance_id(), udp_runtime);
    assert_eq!(published.inbound_publication_owner(), PUBLICATION);
    assert!(published.local_addr().unwrap() == local_endpoint);
    CaseLengths {
        tx: tx_len,
        wire: wire_len,
        rx: rx_len,
    }
}

async fn execute_case(normalized: bool) -> (ResourceSnapshot, CaseLengths) {
    let cleanup_deadline = TokioInstant::now() + Duration::from_secs(5);
    let work_deadline = cleanup_deadline - Duration::from_secs(1);
    let mut children = Children(JoinSet::new());
    let mut held_emit = None;
    let mut sockets_to_release = Vec::with_capacity(2);
    let resources = ResourceCapture::new([if normalized { 0x95 } else { 0x94 }; 16]);
    let result = timeout_at(
        work_deadline,
        std::panic::AssertUnwindSafe(native_workflow(
            normalized,
            resources.clone(),
            &mut children,
            &mut held_emit,
            &mut sockets_to_release,
            work_deadline,
        ))
        .catch_unwind(),
    )
    .await;
    // Release the real guard on success, workflow panic and timeout before
    // aborting. Preserve the first child panic until the complete join drain.
    drop(held_emit.take());
    let drain_deadline = cleanup_deadline.min(TokioInstant::now() + Duration::from_secs(1));
    let child_panic = children.abort_join(drain_deadline).await;
    assert!(
        children.0.is_empty(),
        "all native children joined before resource assertions"
    );
    // Native UDP readers and actor flushes have their own JoinSets. Dropping
    // the parent requests their cancellation; parent join alone cannot prove
    // their completion. Wait for all original socket/capture owners to release
    // within the same final one-second reserve before reporting a RED.
    timeout_at(drain_deadline, async {
        loop {
            if Arc::strong_count(&resources) == 1
                && sockets_to_release
                    .iter()
                    .all(|socket| socket.strong_count() == 0)
            {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("cleanup failure: original nested socket/capture owners must release");
    if let Some(panic) = child_panic {
        std::panic::resume_unwind(panic);
    }
    let lengths = match result {
        Ok(Ok(lengths)) => lengths,
        Ok(Err(panic)) => std::panic::resume_unwind(panic),
        Err(_) => {
            panic!("setup/business failure: original four-second native TX/RX workflow expired")
        }
    };
    resources.finish();
    let snapshot = resources.snapshot();
    assert!(
        snapshot.valid,
        "diagnostic coverage invalid is not a missing-hook RED"
    );
    for stage in [QueueStage::ActorFifo, QueueStage::TaskOrUnjoinedFifo] {
        assert!(
            snapshot.fifo_scope_observed(stage),
            "original slow FIFO lease scope"
        );
        let fifo = snapshot.fifo(stage);
        assert_eq!(fifo.live_packets, 0);
        assert_eq!(fifo.plaintext_len, 0);
        assert_eq!(fifo.vec_capacity, 0);
    }
    // Existing production hooks are controls for actual slow execution. These
    // counts are not OS write syscalls, allocator calls or complete identity.
    for site in [VecSite::TxRetryCopy, VecSite::TxPreparationCopy] {
        assert_copy(&snapshot, site, lengths.tx);
    }
    if normalized {
        assert_copy(&snapshot, VecSite::RxTunPacketCopy, lengths.rx);
    }
    (snapshot, lengths)
}

fn assert_copy(snapshot: &ResourceSnapshot, site: VecSite, length: usize) {
    let measured = snapshot.vec_site(site);
    assert_eq!(
        measured.materialization_ops, 1,
        "actual native Vec site {site:?}"
    );
    assert_eq!(measured.copy_ops, 1);
    assert_eq!(measured.destination_len_observed_sum, length as u64);
    assert!(measured.destination_capacity_observed_sum >= length as u64);
    assert!(measured.copied_bytes_known);
    assert_eq!(measured.known_copied_bytes, length as u64);
}

fn assert_wire(snapshot: &ResourceSnapshot, length: usize) {
    let measured = snapshot.vec_site(VecSite::TxSerializedWire);
    assert_eq!(
        measured.materialization_ops, 1,
        "actual native serialized wire Vec"
    );
    assert_eq!(measured.copy_ops, 0);
    assert_eq!(measured.destination_len_observed_sum, length as u64);
    assert!(measured.destination_capacity_observed_sum >= length as u64);
    assert!(!measured.copied_bytes_known);
    assert_eq!(measured.known_copied_bytes, 0);
    assert!(!snapshot.allocator_alloc_calls_measured);
    assert!(!snapshot.total_pipeline_bytes_measured);
}

#[tokio::test]
async fn actual_mock_tun_tx_requires_executed_vec_observations() {
    let (snapshot, lengths) = execute_case(false).await;
    // The sole designated first missing-hook failure. Later assertions are
    // requirements, not independently executed REDs when this one fails.
    assert_eq!(
        snapshot
            .vec_site(VecSite::TxTunReadCopy)
            .materialization_ops,
        1,
        "B03_MISSING_TX_TUN_READ: native business and full join completed"
    );
    assert_copy(&snapshot, VecSite::TxTunReadCopy, lengths.tx);
    assert_copy(&snapshot, VecSite::TxRoutedPacketCopy, lengths.tx);
    assert_eq!(
        snapshot
            .vec_site(VecSite::TxNormalizedPacketCopy)
            .materialization_ops,
        0
    );
    assert_eq!(
        snapshot
            .vec_site(VecSite::RxNormalizedPacketCopy)
            .materialization_ops,
        0
    );
    assert_wire(&snapshot, lengths.wire);
}

#[tokio::test]
async fn actual_normalized_tx_and_udp_return_require_executed_vec_observations() {
    let (snapshot, lengths) = execute_case(true).await;
    assert_eq!(
        snapshot
            .vec_site(VecSite::RxNormalizedPacketCopy)
            .materialization_ops,
        1,
        "B03_MISSING_RX_NORMALIZED: native TX/UDP return/Mock write and full join completed"
    );
    assert_copy(&snapshot, VecSite::RxNormalizedPacketCopy, lengths.rx);
    assert_copy(&snapshot, VecSite::TxTunReadCopy, lengths.tx);
    assert_copy(&snapshot, VecSite::TxNormalizedPacketCopy, lengths.tx);
    // normalize_outbound_source's Vec is moved, not deep-cloned by routing.
    assert_eq!(
        snapshot
            .vec_site(VecSite::TxRoutedPacketCopy)
            .materialization_ops,
        0
    );
    assert_wire(&snapshot, lengths.wire);
}
