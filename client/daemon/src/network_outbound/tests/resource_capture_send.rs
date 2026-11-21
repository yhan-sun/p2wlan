//! Poll the real slow preparation while the real emit owner is held.

use super::super::test_support::*;
use super::*;
use crate::config::Config;
use crate::dataplane_resources::{ResourceCapture, VecSite};
use tokio::net::UdpSocket;
use tokio::time::{timeout_at, Instant as TokioInstant};

#[tokio::test]
async fn actual_preparation_cancellation_requires_both_plaintext_copy_observations() {
    let deadline = TokioInstant::now() + Duration::from_secs(5);
    timeout_at(deadline, async {
        let resources = ResourceCapture::new([0x91; 16]);
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let endpoint = socket.local_addr().unwrap();
        let peers = Arc::new(PeerManager::new(
            Config::generate_default("https://ctrl.test", "net1").unwrap(),
        ));
        peers.add_peer(&test_peer("peer-a", endpoint)).await;
        let (session, mut remote_session) = establish_sessions();
        let (transport, mut raw_outbound) = WireGuardTransport::new();
        let transport = transport.with_resource_capture(resources.clone()).unwrap();
        assert!(!transport.add_session("peer-a", session).await);
        let sid = transport
            .session_status("peer-a")
            .await
            .active_session_instance
            .unwrap();
        let raw = Ipv4Packet::build_icmp_echo_request(
            "10.20.0.1".parse().unwrap(),
            "10.20.0.2".parse().unwrap(),
            3,
            4,
            b"copy-runtime",
        );
        let input = OutboundPacket {
            room_authorization: None,
            peer_id: "peer-a".into(),
            dst_ip: "10.20.0.2".into(),
            packet: raw.clone(),
            trace: None,
        };
        let udp = UdpTransport::bind("127.0.0.1:0".parse().unwrap(), peers.clone())
            .await
            .unwrap();
        let udp_source = Arc::new(RwLock::new(Some(udp)));
        let relay_source = Arc::new(RwLock::new(None));
        let held = timeout_at(
            deadline.min(TokioInstant::now() + Duration::from_secs(1)),
            transport.acquire_outbound_emit_guard("peer-a"),
        )
        .await
        .unwrap();
        let mut preparation = Box::pin(encrypt_then_send_with_deadline(
            input,
            &transport,
            &peers,
            peers.current_network_generation_sync(),
            true,
            &udp_source,
            &relay_source,
            false,
            Some(Instant::now() + Duration::from_secs(1)),
            None,
        ));
        // Both real clones precede the first held emit-lock await. This poll
        // reaches that await and never calls the resource API itself.
        assert!(matches!(
            futures_util::poll!(preparation.as_mut()),
            std::task::Poll::Pending
        ));
        drop(preparation);
        drop(held);
        assert!(matches!(
            raw_outbound.try_recv(),
            Err(mpsc::error::TryRecvError::Empty)
        ));
        let mut bytes = [0; 2048];
        assert_eq!(
            socket.try_recv_from(&mut bytes).unwrap_err().kind(),
            std::io::ErrorKind::WouldBlock
        );
        assert_eq!(
            transport
                .session_status("peer-a")
                .await
                .active_session_instance,
            Some(sid)
        );
        resources.finish();
        // The original session's first subsequently allocated counter is 0:
        // cancelled pre-handoff preparation did not consume a WG counter.
        let control = transport
            .encrypt_outbound(OutboundPacket {
                room_authorization: None,
                peer_id: "peer-a".into(),
                dst_ip: "10.20.0.2".into(),
                packet: raw.clone(),
                trace: None,
            })
            .await
            .unwrap()
            .unwrap();
        assert_eq!(crate::transport::wire_counter(&control.wire_bytes), Some(0));
        assert!(
            remote_session
                .decrypt_from_bytes(&control.wire_bytes)
                .unwrap()
                == raw,
            "actual control decrypt must preserve original bytes"
        );
        let snapshot = resources.snapshot();
        assert!(snapshot.valid);
        for site in [VecSite::TxRetryCopy, VecSite::TxPreparationCopy] {
            let measured = snapshot.vec_site(site);
            assert_eq!(
                measured.materialization_ops, 1,
                "real cancelled preparation copy {site:?} missing"
            );
            assert_eq!(measured.copy_ops, 1);
            assert_eq!(measured.known_copied_bytes, raw.len() as u64);
            assert_eq!(measured.destination_len_observed_sum, raw.len() as u64);
            assert!(measured.destination_capacity_observed_sum >= raw.len() as u64);
            assert!(measured.copied_bytes_known);
        }
    })
    .await
    .expect("fixed five-second real preparation workflow");
}
