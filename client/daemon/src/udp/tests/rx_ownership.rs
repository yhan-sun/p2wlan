//! Original socket/decrypt/pump futures, with no observer forwarding task.
use super::*;
use crate::dataplane_resources::{
    EncryptedRxSink, ResidencyStage, ResourceCapture, RuntimeResourceCapture,
};
use std::{
    future::{poll_fn, Future},
    task::Poll,
};
use tokio::sync::{oneshot, watch};

async fn observed_workload(enabled: bool) -> serde_json::Value {
    // Fixed order and denominator. These are correctness/cost observations,
    // not a throughput benchmark, RSS measurement, or release performance gate.
    const PACKETS: usize = 16;
    const READS_PER_PACKET: usize = 4;
    let end = tokio::time::Instant::now() + Duration::from_secs(5);
    let run = RuntimeResourceCapture::from_config(&crate::config::DiagnosticsConfig {
        enabled,
        resource_capture: enabled,
        ..Default::default()
    });
    let capture = run.as_ref().map(|r| r.capture().clone());
    let peers = peer_manager();
    peers.add_peer(&peer("peer-a", "10.20.0.1", None)).await;
    let (tun, controller) = MockTunDevice::new_pair("rx-workload", 1420, "10.20.0.2");
    let (mut plane, _out, inbound) =
        DataPlane::new_bidirectional_for_daemon(tun, peers.clone(), false, capture.clone());
    plane = plane.with_overlay_cidr("10.20.0.0/16");
    assert_eq!(inbound.max_capacity(), 1024);
    let (wg, _out) = WireGuardTransport::new_for_daemon(false, capture.clone());
    let (mut remote, local) = establish_sessions();
    assert!(!wg.add_session("peer-a", local).await);
    let udp = UdpTransport::bind("127.0.0.1:0".parse().unwrap(), peers.clone())
        .await
        .unwrap();
    let udp = if let Some(c) = &capture {
        udp.with_resource_capture(c.clone()).unwrap()
    } else {
        udp
    };
    udp.set_inbound_publication_owner(9401);
    let destination = udp.local_addr().unwrap();
    let (_updates, watch) = watch::channel(Some(udp.clone()));
    let (tx, rx) = EncryptedRxSink::channel(1024, capture.clone());
    assert_eq!(tx.max_capacity(), 1024);
    let (ready, mut readiness) = oneshot::channel();
    let (_shutdown, mut shutdown_rx) = watch::channel(false);
    let mut reader = Box::pin(udp.run_inbound_socket_inner(
        0,
        udp.socket.clone(),
        tx,
        Some(&mut shutdown_rx),
        Some(ready),
    ));
    let mut decrypt = Box::pin(wg.run_inbound_with_peers_live_udp_and_relay(
        rx,
        inbound,
        Some(peers.clone()),
        watch,
        None,
    ));
    let mut pump = Box::pin(plane.run());
    poll_fn(|cx| {
        assert!(reader.as_mut().poll(cx).is_pending());
        assert!(decrypt.as_mut().poll(cx).is_pending());
        assert!(pump.as_mut().poll(cx).is_pending());
        Poll::Ready(())
    })
    .await;
    assert!(readiness.try_recv().unwrap());
    let sender = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let mut latency_us = Vec::with_capacity(PACKETS);
    let mut readouts = Vec::with_capacity(PACKETS * READS_PER_PACKET);
    let mut expected_bytes = 0;
    for seq in 0..PACKETS {
        let src = if seq % 2 == 0 {
            Ipv4Addr::new(10, 20, 0, 1)
        } else {
            Ipv4Addr::new(100, 84, 190, 40)
        };
        let dst = Ipv4Addr::new(10, 20, 0, 2);
        let raw = Ipv4Packet::build_icmp_echo_request(
            src,
            dst,
            0x6161,
            seq as u16,
            b"fixed-original-rx-workload",
        );
        let expected = Ipv4Packet::build_icmp_echo_request(
            Ipv4Addr::new(10, 20, 0, 1),
            dst,
            0x6161,
            seq as u16,
            b"fixed-original-rx-workload",
        );
        let wire = remote.encrypt_to_bytes(&raw).unwrap();
        let start = std::time::Instant::now();
        assert_eq!(
            sender.send_to(&wire, destination).await.unwrap(),
            wire.len()
        );
        let actual = tokio::time::timeout_at(end, async {
            tokio::select! {
                value=controller.recv_written()=>value.unwrap(),
                value=reader.as_mut()=>panic!("reader ended: {value:?}"),
                value=decrypt.as_mut()=>panic!("decrypt ended: {value:?}"),
                value=pump.as_mut()=>panic!("pump ended: {value:?}"),
            }
        })
        .await
        .unwrap();
        latency_us.push(start.elapsed().as_micros() as u64);
        assert_eq!(actual, expected);
        expected_bytes += expected.len() as u64;
        poll_fn(|cx| {
            assert!(pump.as_mut().poll(cx).is_pending());
            Poll::Ready(())
        })
        .await;
        for _ in 0..READS_PER_PACKET {
            let start = std::time::Instant::now();
            let readout = run
                .as_ref()
                .map(|r| r.readout())
                .unwrap_or_else(|| serde_json::json!({"enabled":false,"capture":null}));
            let bytes = serde_json::to_vec(&readout).unwrap();
            let owners = &readout["capture"]["observed_owner_residency"];
            readouts.push(serde_json::json!({"us":start.elapsed().as_micros(),"bytes":bytes.len(),"coherent":owners["coherent"],"valid":owners["valid"],"total":owners["total"]}));
        }
    }
    assert_eq!(latency_us.len(), PACKETS);
    assert_eq!(readouts.len(), PACKETS * READS_PER_PACKET);
    assert_eq!(
        peers
            .get_connection("peer-a")
            .await
            .unwrap()
            .bytes_received
            .get(),
        expected_bytes
    );
    if let Some(c) = &capture {
        let s = c.residency_snapshot();
        assert!(s.coherent && s.valid);
        assert_eq!(s.unknown_bits, 0);
        assert_eq!(s.total.unwrap().live_buffers, 2);
        assert_eq!(s.total.unwrap().capacity_bytes, 2 * 65_535);
        for stage in [
            ResidencyStage::RxWireAdmission,
            ResidencyStage::RxWireChannel,
            ResidencyStage::RxWireActive,
            ResidencyStage::RxParsedPayload,
            ResidencyStage::RxAuthenticatedPlaintext,
            ResidencyStage::RxPlaintextAdmission,
            ResidencyStage::RxPlaintextChannel,
            ResidencyStage::RxPlaintextActive,
            ResidencyStage::RxTunPacket,
            ResidencyStage::RxTunNormalized,
        ] {
            assert!(s.observed[stage as usize], "missing actual stage {stage:?}");
            assert_eq!(s.stage(stage).unwrap().live_buffers, 0);
        }
        assert!(s.capacity_high_water_bytes.unwrap() > 2 * 65_535);
        assert!(!s.whole_pipeline_bytes_measured);
        c.finish();
        assert_eq!(c.residency_snapshot().total, s.total);
    }
    drop(pump);
    drop(decrypt);
    drop(reader);
    if let Some(c) = &capture {
        let s = c.residency_snapshot();
        assert!(s.coherent && s.valid);
        assert_eq!(s.total.unwrap().live_buffers, 0);
        assert_eq!(s.total.unwrap().capacity_bytes, 0);
    }
    serde_json::json!({"enabled":enabled,"packets":PACKETS,"delivered":PACKETS,"readout_denominator":PACKETS*READS_PER_PACKET,"latency_us":latency_us,"all_readouts":readouts,"whole_pipeline_or_performance_claim":false})
}

#[tokio::test]
async fn rx_ownership_real_udp_wg_mock_fixed_off_on_workload_keeps_all_readout_denominators() {
    for enabled in [false, true] {
        eprintln!("rx_ownership_workload={}", observed_workload(enabled).await);
    }
}

#[tokio::test]
async fn rx_ownership_real_udp_waiting_wire_and_queued_wire_drop_on_cancel_or_close() {
    for close in [false, true] {
        let end = tokio::time::Instant::now() + Duration::from_secs(2);
        let c = ResourceCapture::new([0xe6; 16]);
        let udp = UdpTransport::bind("127.0.0.1:0".parse().unwrap(), peer_manager())
            .await
            .unwrap()
            .with_resource_capture(c.clone())
            .unwrap();
        let (tx, rx) = EncryptedRxSink::channel(1, Some(c.clone()));
        let (txready, mut ready) = oneshot::channel();
        let (_shutdown, mut shutdown_rx) = watch::channel(false);
        let mut reader = Box::pin(udp.run_inbound_socket_inner(
            0,
            udp.socket.clone(),
            tx,
            Some(&mut shutdown_rx),
            Some(txready),
        ));
        poll_fn(|cx| {
            assert!(reader.as_mut().poll(cx).is_pending());
            Poll::Ready(())
        })
        .await;
        assert!(ready.try_recv().unwrap());
        let sender = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let (mut remote, _) = establish_sessions();
        for seq in 0..2 {
            let wire = remote.encrypt_to_bytes(&[0x45, seq]).unwrap();
            sender
                .send_to(&wire, udp.local_addr().unwrap())
                .await
                .unwrap();
            tokio::time::timeout_at(end, async {
                loop {
                    poll_fn(|cx| {
                        assert!(reader.as_mut().poll(cx).is_pending());
                        Poll::Ready(())
                    })
                    .await;
                    let s = c.residency_snapshot();
                    if s.stage(if seq == 0 {
                        ResidencyStage::RxWireChannel
                    } else {
                        ResidencyStage::RxWireAdmission
                    })
                    .unwrap()
                    .live_buffers
                        == 1
                    {
                        break;
                    }
                    tokio::task::yield_now().await;
                }
            })
            .await
            .unwrap();
        }
        let s = c.residency_snapshot();
        assert!(s.coherent && s.valid);
        assert_eq!(s.unknown_bits, 0);
        assert_eq!(s.total.unwrap().live_buffers, 3);
        c.finish();
        if close {
            drop(rx);
            assert_eq!(c.residency_snapshot().total.unwrap().live_buffers, 2);
            assert!(matches!(
                tokio::time::timeout_at(end, reader.as_mut()).await.unwrap(),
                Err(crate::error::DaemonError::Network(_))
            ));
            assert_eq!(c.residency_snapshot().total.unwrap().live_buffers, 0);
            drop(reader);
        } else {
            drop(reader);
            assert_eq!(c.residency_snapshot().total.unwrap().live_buffers, 1);
            drop(rx);
        }
        assert_eq!(c.residency_snapshot().total.unwrap().live_buffers, 0);
    }
}
