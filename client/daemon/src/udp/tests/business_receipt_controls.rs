//! Actual loopback UDP/WG/Mock control: absent physical metadata affects
//! observation coverage, while the existing business delivery still succeeds.

use super::*;
use crate::business_evidence::*;
use futures_util::FutureExt;
use std::future::Future;
use std::num::NonZeroU64;
use tokio::sync::oneshot;
use tokio::time::{timeout_at, Instant as TokioInstant};

struct Children(JoinSet<()>);

impl Children {
    fn spawn<F: Future<Output = ()> + Send + 'static>(&mut self, future: F) {
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

fn checksum(bytes: &[u8]) -> u16 {
    let mut sum = bytes
        .chunks(2)
        .map(|chunk| {
            u32::from(u16::from_be_bytes([
                chunk[0],
                chunk.get(1).copied().unwrap_or(0),
            ]))
        })
        .sum::<u32>();
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

fn request_packet() -> Vec<u8> {
    let payload_bytes = 8;
    let total = 28 + OS_UDP_HEADER_BYTES + payload_bytes;
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
    body[8] = 0;
    body[9..25].fill(0xc1);
    body[25..41].fill(0xc2);
    body[41..45].copy_from_slice(&7_u32.to_be_bytes());
    body[45..61].fill(0xc3);
    body[61..63].copy_from_slice(&(payload_bytes as u16).to_be_bytes());
    body[63..].fill(0xa5);
    let ip_sum = checksum(&raw[..20]);
    raw[10..12].copy_from_slice(&ip_sum.to_be_bytes());
    let mut pseudo = Vec::with_capacity(12 + total - 20);
    pseudo.extend_from_slice(&raw[12..20]);
    pseudo.extend_from_slice(&[0, 17]);
    pseudo.extend_from_slice(&raw[24..26]);
    pseudo.extend_from_slice(&raw[20..]);
    let udp_sum = checksum(&pseudo);
    raw[26..28].copy_from_slice(&if udp_sum == 0 { u16::MAX } else { udp_sum }.to_be_bytes());
    raw
}

#[tokio::test]
async fn missing_physical_metadata_keeps_actual_mock_delivery_and_typed_gap() {
    let deadline = TokioInstant::now() + Duration::from_secs(5);
    let mut children = Children(JoinSet::new());
    let workflow = async {
        let raw = request_packet();
        let parsed = parse_os_udp(&raw).unwrap();
        let capture = CaptureOwner::arm(
            CaptureScope {
                capture_id: [0xb1; 16],
                producer_scope: [0xb2; 16],
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
        let peers = peer_manager();
        peers.add_peer(&peer("peer-a", "10.20.0.1", None)).await;
        let (tun, controller) = MockTunDevice::new_pair("receipt-gap-mock", 1420, "10.20.0.2");
        let (dataplane, _outbound_rx, inbound_tx) =
            DataPlane::new_bidirectional(tun, peers.clone());
        let mut dataplane = dataplane
            .with_rx_business_capture(
                capture.clone(),
                TunEvidenceIdentity {
                    instance: NonZeroU64::new(103).unwrap(),
                    backend: TunBackend::MockDelivered,
                },
            )
            .unwrap();
        children.spawn(async move {
            dataplane.run().await.expect("actual dataplane worker");
        });
        let (mut sender_session, receiver_session) = establish_sessions();
        let (wireguard, _outbound_rx) = WireGuardTransport::new();
        let wireguard = wireguard.with_rx_business_capture(capture.clone()).unwrap();
        assert!(!wireguard.add_session("peer-a", receiver_session).await);
        let original_sid = wireguard
            .session_status("peer-a")
            .await
            .active_session_instance
            .unwrap();
        // The original UDP owner uses its default None recorder. No metadata
        // is deleted or manufactured in the forwarding fixture.
        let udp = UdpTransport::bind("127.0.0.1:0".parse().unwrap(), peers.clone())
            .await
            .unwrap();
        let destination = udp.local_addr().unwrap();
        let (reader_tx, mut reader_rx) = mpsc::channel::<ReceivedEncryptedPacket>(4);
        let (wg_tx, wg_rx) = mpsc::channel(4);
        let (observed_tx, observed_rx) = oneshot::channel();
        children.spawn(async move {
            let mut observed_tx = Some(observed_tx);
            while let Some(envelope) = reader_rx.recv().await {
                assert!(
                    envelope.physical_ingress.is_none(),
                    "default reader has no metadata allocation"
                );
                if let Some(sender) = observed_tx.take() {
                    let _ = sender.send((envelope.source, envelope.wire_bytes.clone()));
                }
                wg_tx
                    .send(envelope)
                    .await
                    .expect("same actual envelope forwarded");
            }
        });
        children.spawn({
            let wireguard = wireguard.clone();
            let peers = peers.clone();
            async move {
                wireguard
                    .run_inbound_with_peers(wg_rx, inbound_tx, Some(peers), None)
                    .await
                    .expect("actual WG inbound worker");
            }
        });
        children.spawn(async move {
            udp.run_inbound(reader_tx).await.expect("actual UDP reader");
        });
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
        .expect("actual encrypted ingress bounded")
        .unwrap();
        assert_eq!(observed.0, Some(source));
        assert!(
            observed.1 == wire,
            "actual encrypted bytes differ (observed/expected lengths: {}/{})",
            observed.1.len(),
            wire.len()
        );
        let written = timeout_at(
            deadline.min(TokioInstant::now() + Duration::from_secs(1)),
            controller.recv_written(),
        )
        .await
        .expect("actual Mock full write bounded")
        .unwrap();
        assert!(
            written == raw,
            "actual Mock bytes differ (written/expected lengths: {}/{})",
            written.len(),
            raw.len()
        );
        assert_eq!(parse_os_udp(&written).unwrap().key, parsed.key);
        timeout_at(
            deadline.min(TokioInstant::now() + Duration::from_secs(1)),
            async {
                loop {
                    if peers.get_connection("peer-a").await.unwrap().bytes_received
                        == raw.len() as u64
                    {
                        break;
                    }
                    tokio::task::yield_now().await;
                }
            },
        )
        .await
        .expect("actual full-write statistics bounded");
        assert_eq!(
            wireguard
                .session_status("peer-a")
                .await
                .active_session_instance,
            Some(original_sid)
        );
        let snapshot = capture.try_read_registered(registered.slot()).unwrap();
        assert!(snapshot.authenticated.is_none());
        assert!(snapshot.tun_full.is_none());
        assert!(!snapshot.ambiguous);
        assert_eq!(
            capture.coverage().count(RecordDisposition::IdentityMissing),
            2
        );
    };
    let outcome = timeout_at(
        deadline,
        std::panic::AssertUnwindSafe(workflow).catch_unwind(),
    )
    .await;
    let cleanup = children.abort_join().await;
    match outcome {
        Ok(Ok(())) => match cleanup {
            Ok(None) => (),
            Ok(Some(error)) => std::panic::resume_unwind(error.into_panic()),
            Err(_) => panic!("all fixture children must drain within one cleanup second"),
        },
        Ok(Err(panic)) => {
            eprintln!(
                "fixture_cleanup_complete={} fixture_child_panic_present={}",
                cleanup.is_ok(),
                matches!(&cleanup, Ok(Some(_)))
            );
            std::panic::resume_unwind(panic);
        }
        Err(_) => match cleanup {
            Ok(Some(error)) => std::panic::resume_unwind(error.into_panic()),
            Ok(None) => panic!("fixed five-second metadata-gap workflow expired"),
            Err(_) => panic!("workflow expired and bounded child drain was incomplete"),
        },
    }
}
