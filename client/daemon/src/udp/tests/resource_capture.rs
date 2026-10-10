//! Actual UDP -> authenticated WG -> full MockTUN resource-coverage tests.

use super::*;
use crate::business_evidence::{
    parse_os_udp, CaptureOwner, CaptureScope, Registration, TunBackend, TunEvidenceIdentity,
    OS_UDP_HEADER_BYTES,
};
use crate::dataplane_resources::{EnableError, ResourceCapture, VecSite};
use futures_util::FutureExt;
use std::future::Future;
use std::num::NonZeroU64;
use tokio::sync::{oneshot, watch};
use tokio::time::{timeout_at, Instant as TokioInstant};

struct Children(JoinSet<()>);

impl Children {
    fn spawn<F: Future<Output = ()> + Send + 'static>(&mut self, future: F) {
        self.0.spawn(future);
    }

    async fn abort_join(&mut self, deadline: TokioInstant) {
        self.0.abort_all();
        timeout_at(deadline, async {
            let mut panic = None;
            while let Some(result) = self.0.join_next().await {
                if let Err(error) = result {
                    if !error.is_cancelled() && panic.is_none() {
                        panic = Some(error);
                    }
                }
            }
            if let Some(error) = panic {
                std::panic::resume_unwind(error.into_panic());
            }
        })
        .await
        .expect("all actual UDP/WG/Mock children must drain within one second");
    }
}

impl Drop for Children {
    fn drop(&mut self) {
        self.0.abort_all();
    }
}

fn registered_packet() -> Vec<u8> {
    let total = 28 + OS_UDP_HEADER_BYTES + 8;
    let mut raw = vec![0; total];
    raw[0] = 0x45;
    raw[2..4].copy_from_slice(&(total as u16).to_be_bytes());
    raw[6] = 0x40;
    raw[8] = 64;
    raw[9] = 17;
    raw[12..16].copy_from_slice(&[10, 20, 0, 1]);
    raw[16..20].copy_from_slice(&[10, 20, 0, 2]);
    raw[20..22].copy_from_slice(&42023_u16.to_be_bytes());
    raw[22..24].copy_from_slice(&42123_u16.to_be_bytes());
    raw[24..26].copy_from_slice(&((total - 20) as u16).to_be_bytes());
    let body = &mut raw[28..];
    body[..8].copy_from_slice(b"P2WUDE1\0");
    body[9..25].fill(0x71);
    body[25..41].fill(0x72);
    body[41..45].copy_from_slice(&7_u32.to_be_bytes());
    body[45..61].fill(0x73);
    body[61..63].copy_from_slice(&8_u16.to_be_bytes());
    body[63..].fill(0xa5);
    let mut sum = raw[..20]
        .chunks_exact(2)
        .map(|pair| u32::from(u16::from_be_bytes([pair[0], pair[1]])))
        .sum::<u32>();
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    raw[10..12].copy_from_slice(&(!(sum as u16)).to_be_bytes());
    raw
}

#[tokio::test]
async fn actual_udp_wg_full_mock_write_requires_executed_vec_observations() {
    let cleanup_deadline = TokioInstant::now() + Duration::from_secs(5);
    let deadline = cleanup_deadline - Duration::from_secs(1);
    let mut children = Children(JoinSet::new());
    let resources = ResourceCapture::new([0x74; 16]);
    let workflow = async {
        let raw = registered_packet();
        let parsed = parse_os_udp(&raw).expect("actual IPv4 UDP request parses");
        let receipts = CaptureOwner::arm(
            CaptureScope {
                capture_id: [0x75; 16],
                producer_scope: [0x76; 16],
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
        let registered = receipts.lookup_registered(&raw, "peer-a").unwrap();
        let peers = peer_manager();
        peers.add_peer(&peer("peer-a", "10.20.0.1", None)).await;
        let generation = peers.current_network_generation_sync();
        let (tun, controller) = MockTunDevice::new_pair("resource-mock", 1420, "10.20.0.2");
        let (dataplane, _outbound, inbound) = DataPlane::new_bidirectional(tun, peers.clone());
        assert_eq!(inbound.max_capacity(), 1024);
        let mut dataplane = dataplane
            .with_resource_capture(resources.clone())
            .unwrap()
            .with_rx_business_capture(
                receipts.clone(),
                TunEvidenceIdentity {
                    instance: NonZeroU64::new(301).unwrap(),
                    backend: TunBackend::MockDelivered,
                },
            )
            .unwrap();
        children.spawn(async move {
            dataplane.run().await.expect("actual dataplane worker");
        });
        let (mut sender_session, receiver_session) = establish_sessions();
        let (wireguard, _outbound) = WireGuardTransport::new();
        let wireguard = wireguard
            .with_resource_capture(resources.clone())
            .unwrap()
            .with_rx_business_capture(receipts.clone())
            .unwrap();
        assert!(!wireguard.add_session("peer-a", receiver_session).await);
        let sid = wireguard
            .session_status("peer-a")
            .await
            .active_session_instance
            .unwrap();
        let wg_owner = wireguard.wg_evidence_owner();
        let udp = UdpTransport::bind("127.0.0.1:0".parse().unwrap(), peers.clone())
            .await
            .unwrap()
            .with_resource_capture(resources.clone())
            .unwrap()
            .with_rx_business_capture(receipts.clone())
            .unwrap();
        udp.set_inbound_publication_owner(9301);
        let runtime = udp.transport_instance_id();
        let destination = udp.local_addr().unwrap();
        let (_udp_updates, udp_watch) = watch::channel(Some(udp.clone()));
        let (reader_tx, mut reader_rx) = mpsc::channel::<ReceivedEncryptedPacket>(4);
        let (wg_tx, wg_rx) = mpsc::channel(4);
        let (observed_tx, observed_rx) = oneshot::channel();
        children.spawn(async move {
            let mut observed_tx = Some(observed_tx);
            while let Some(envelope) = reader_rx.recv().await {
                if let Some(sender) = observed_tx.take() {
                    let _ = sender.send((
                        envelope.source,
                        envelope.udp_transport_owner,
                        envelope.network_generation,
                        envelope.wire_bytes.clone(),
                    ));
                }
                wg_tx
                    .send(envelope)
                    .await
                    .expect("same actual UDP envelope");
            }
        });
        children.spawn({
            let wireguard = wireguard.clone();
            let peers = peers.clone();
            async move {
                wireguard
                    .run_inbound_with_peers_live_udp(wg_rx, inbound, Some(peers), udp_watch)
                    .await
                    .expect("actual WG inbound worker");
            }
        });
        children.spawn(async move { udp.run_inbound(reader_tx).await.expect("actual UDP reader") });
        let sender = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let source = sender.local_addr().unwrap();
        let wire = sender_session.encrypt_to_bytes(&raw).unwrap();
        assert_eq!(
            sender.send_to(&wire, destination).await.unwrap(),
            wire.len()
        );
        let observed = timeout_at(
            deadline.min(TokioInstant::now() + Duration::from_secs(1)),
            observed_rx,
        )
        .await
        .expect("actual reader arrival bound")
        .unwrap();
        assert_eq!(observed.0, Some(source));
        assert_eq!(observed.1, Some(9301));
        assert_eq!(observed.2, Some(generation));
        assert!(
            observed.3 == wire,
            "actual wire bytes must match, lengths {}/{}",
            observed.3.len(),
            wire.len()
        );
        let written = timeout_at(
            deadline.min(TokioInstant::now() + Duration::from_secs(1)),
            controller.recv_written(),
        )
        .await
        .expect("actual full Mock write bound")
        .unwrap();
        assert!(
            written == raw,
            "actual Mock bytes must match, lengths {}/{}",
            written.len(),
            raw.len()
        );
        timeout_at(
            deadline.min(TokioInstant::now() + Duration::from_secs(1)),
            async {
                loop {
                    let connection = peers.get_connection("peer-a").await.unwrap();
                    if connection.bytes_received == raw.len() as u64 {
                        assert_eq!(connection.endpoint, Some(source));
                        break;
                    }
                    tokio::task::yield_now().await;
                }
            },
        )
        .await
        .expect("original full-write accounting completes");
        let receipt = receipts.try_read_registered(registered.slot()).unwrap();
        let auth = receipt
            .authenticated
            .expect("same actual WG authentication receipt");
        let full = receipt.tun_full.expect("same actual full Mock receipt");
        assert!(!receipt.ambiguous);
        assert_eq!(auth.wg_owner(), wg_owner);
        assert_eq!(auth.session_instance().get(), sid);
        assert_eq!(auth.physical().runtime_instance().unwrap().get(), runtime);
        assert_eq!(auth.physical().source(), Some(source));
        assert_eq!(
            auth.wire().counter,
            crate::transport::wire_counter(&wire).unwrap()
        );
        assert_eq!(full.authenticated(), auth);
        assert_eq!(full.written() as usize, raw.len());
        assert_eq!(
            wireguard
                .session_status("peer-a")
                .await
                .active_session_instance,
            Some(sid)
        );
        (raw.len(), wire.len())
    };
    let result = timeout_at(
        deadline,
        std::panic::AssertUnwindSafe(workflow).catch_unwind(),
    )
    .await;
    children.abort_join(cleanup_deadline).await;
    let (raw_len, wire_len) = match result {
        Ok(Ok(lengths)) => lengths,
        Ok(Err(panic)) => std::panic::resume_unwind(panic),
        Err(_) => panic!("fixed four-second actual UDP/WG/Mock workflow expired"),
    };
    resources.finish();
    let snapshot = resources.snapshot();
    assert!(snapshot.valid);
    // No fixture calls observe_vec: these require the original owners' hooks.
    for (site, length, copied) in [
        (VecSite::UdpWireCopy, wire_len, true),
        (VecSite::RxParsedPayloadCopy, wire_len - 16, true),
        (VecSite::RxAuthenticatedPlaintext, raw_len, false),
        (VecSite::RxTunPacketCopy, raw_len, true),
    ] {
        let measured = snapshot.vec_site(site);
        assert_eq!(
            measured.materialization_ops, 1,
            "actual executed Vec site {site:?} missing"
        );
        assert_eq!(measured.destination_len_observed_sum, length as u64);
        assert!(measured.destination_capacity_observed_sum >= length as u64);
        assert_eq!(measured.copied_bytes_known, copied);
        assert_eq!(
            measured.known_copied_bytes,
            if copied { length as u64 } else { 0 }
        );
    }
    assert!(
        snapshot
            .vec_site(VecSite::UdpReaderBuffer)
            .materialization_ops
            >= 1
    );
    assert!(!snapshot.allocator_alloc_calls_measured);
    assert!(!snapshot.total_pipeline_bytes_measured);
}

#[tokio::test]
async fn default_none_and_consuming_builders_keep_independent_scopes() {
    let capture = ResourceCapture::new([0x79; 16]);
    let peers = peer_manager();
    let (tun, _controller) = MockTunDevice::new_pair("resource-default", 1420, "10.20.0.2");
    let (dataplane, _) = DataPlane::new(tun, peers.clone());
    assert!(dataplane.resource_capture().is_none());
    let dataplane = dataplane.with_resource_capture(capture.clone()).unwrap();
    assert!(matches!(
        dataplane.with_resource_capture(capture.clone()),
        Err(EnableError::AlreadyEnabled)
    ));
    let (wireguard, _) = WireGuardTransport::new();
    assert!(wireguard.resource_capture().is_none());
    let wireguard = wireguard.with_resource_capture(capture.clone()).unwrap();
    assert!(Arc::ptr_eq(
        wireguard.clone().resource_capture().unwrap(),
        &capture
    ));
    assert!(matches!(
        wireguard.with_resource_capture(capture.clone()),
        Err(EnableError::AlreadyEnabled)
    ));
    let udp = UdpTransport::bind("127.0.0.1:0".parse().unwrap(), peers)
        .await
        .unwrap();
    assert!(udp.resource_capture().is_none());
    let udp = udp.with_resource_capture(capture.clone()).unwrap();
    assert!(Arc::ptr_eq(
        udp.clone().resource_capture().unwrap(),
        &capture
    ));
    assert!(matches!(
        udp.with_resource_capture(capture.clone()),
        Err(EnableError::AlreadyEnabled)
    ));
    capture.finish();
    let (wireguard, _) = WireGuardTransport::new();
    assert!(matches!(
        wireguard.with_resource_capture(capture.clone()),
        Err(EnableError::CaptureFinished)
    ));
    assert_eq!(
        capture
            .snapshot()
            .vec_site(VecSite::UdpWireCopy)
            .materialization_ops,
        0
    );
}
