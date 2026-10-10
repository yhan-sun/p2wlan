use std::net::Ipv4Addr;
use std::time::Duration;

use p2pnet_tun::{Ipv4Packet, MockTunDevice};
use tokio::time::timeout;

use super::*;
use crate::config::{AclConfig, AclRule, Config};
use crate::control::PeerInfo;

fn peer(node_id: &str, virtual_ip: &str) -> PeerInfo {
    PeerInfo {
        capabilities: crate::control::PeerCapabilities::default(),
        registration_seq: 0,
        node_id: node_id.to_string(),
        device_name: String::new(),
        app_version: String::new(),
        public_key: "pk".to_string(),
        endpoint: String::new(),
        nat_type: String::new(),
        virtual_ip: virtual_ip.to_string(),
        online: true,
        last_seen: 0,
        relay_rtt_ms: None,
    }
}

#[tokio::test]
async fn routes_tun_packet_to_peer_by_virtual_ip() {
    let peers = Arc::new(PeerManager::new(
        Config::generate_default("http://ctrl.test", "default").unwrap(),
    ));
    peers.add_peer(&peer("peer-b", "10.20.0.2")).await;

    let (tun, ctrl) = MockTunDevice::new_pair("test0", 1420, "10.20.0.1");
    let (mut dataplane, mut outbound_rx) = DataPlane::new(tun, peers.clone());
    let task = tokio::spawn(async move { dataplane.run().await });

    let packet = Ipv4Packet::build_icmp_echo_request(
        Ipv4Addr::new(10, 20, 0, 1),
        Ipv4Addr::new(10, 20, 0, 2),
        0x1234,
        1,
        b"ping",
    );
    ctrl.inject(packet.clone()).await.unwrap();

    let routed = timeout(Duration::from_secs(1), outbound_rx.recv())
        .await
        .unwrap()
        .unwrap();

    assert_eq!(routed.peer_id, "peer-b");
    assert_eq!(routed.dst_ip, "10.20.0.2");
    assert_eq!(routed.packet, packet);

    let conn = peers.get_connection("peer-b").await.unwrap();
    assert_eq!(conn.bytes_sent, routed.packet.len() as u64);

    task.abort();
}

#[tokio::test]
async fn does_not_lose_tun_packets_when_inbound_work_is_ready() {
    const BURST: usize = 256;
    let peers = Arc::new(PeerManager::new(
        Config::generate_default("http://ctrl.test", "default").unwrap(),
    ));
    peers.add_peer(&peer("peer-b", "10.20.0.2")).await;

    let (tun, ctrl) = MockTunDevice::new_pair("test0", 1420, "10.20.0.1");
    let (mut dataplane, mut outbound_rx, inbound_tx) = DataPlane::new_bidirectional(tun, peers);
    let task = tokio::spawn(async move { dataplane.run().await });

    // Keep the inbound branch continuously ready while the TUN side is
    // under load.  Before the read/route split, cancellation after a TUN
    // recv but before peer resolution could silently consume one packet.
    let drain_ctrl = ctrl.clone();
    let drain_task = tokio::spawn(async move {
        for _ in 0..BURST {
            timeout(Duration::from_secs(1), drain_ctrl.recv_written())
                .await
                .expect("inbound packet was not written to TUN")
                .expect("mock TUN write side closed");
        }
    });
    let inbound_task = tokio::spawn(async move {
        for id in 0..BURST {
            let packet = Ipv4Packet::build_icmp_echo_request(
                Ipv4Addr::new(10, 20, 0, 2),
                Ipv4Addr::new(10, 20, 0, 1),
                0x5000 + id as u16,
                id as u16,
                b"inbound",
            );
            inbound_tx
                .send(InboundPacket {
                    peer_id: "peer-b".to_string(),
                    packet,
                    session_instance: None,
                    from_previous_session: false,
                    trace: None,
                })
                .await
                .expect("inbound channel closed");
        }
    });

    let expected: Vec<Vec<u8>> = (0..BURST)
        .map(|id| {
            Ipv4Packet::build_icmp_echo_request(
                Ipv4Addr::new(10, 20, 0, 1),
                Ipv4Addr::new(10, 20, 0, 2),
                0x4000 + id as u16,
                id as u16,
                b"outbound",
            )
        })
        .collect();
    for packet in &expected {
        ctrl.inject(packet.clone()).await.unwrap();
    }

    for expected_packet in expected {
        let routed = timeout(Duration::from_secs(2), outbound_rx.recv())
            .await
            .expect("TUN packet was silently lost")
            .expect("outbound channel closed");
        assert_eq!(routed.peer_id, "peer-b");
        assert_eq!(routed.packet, expected_packet);
    }

    inbound_task.await.unwrap();
    drain_task.await.unwrap();
    task.abort();
}

async fn poll_packet_pump_once(
    mut pump: std::pin::Pin<&mut impl std::future::Future<Output = Result<()>>>,
) {
    std::future::poll_fn(|cx| {
        assert!(std::future::Future::poll(pump.as_mut(), cx).is_pending());
        std::task::Poll::Ready(())
    })
    .await;
}

async fn assert_feedback_cannot_cancel_consumed_fallback_packet(close_inbound: bool) {
    let peers = Arc::new(PeerManager::new(
        Config::generate_default("http://ctrl.test", "default").unwrap(),
    ));
    peers.add_peer(&peer("peer-b", "10.20.0.2")).await;
    let acl = Arc::new(RwLock::new(AclEngine::allow_all()));
    let acl_guard = acl.write().await;
    let (tun, ctrl) = MockTunDevice::new_pair("test0", 1420, "10.20.0.1");
    let (dataplane, mut outbound_rx) = if close_inbound {
        let (dataplane, outbound_rx, inbound_tx) = DataPlane::new_bidirectional(tun, peers);
        drop(inbound_tx);
        (dataplane, outbound_rx)
    } else {
        DataPlane::new(tun, peers)
    };
    let mut dataplane = dataplane.with_acl(acl.clone(), "local-node");
    let (feedback_tx, feedback_rx) = tokio::sync::broadcast::channel(1);
    dataplane.local_feedback_rx = Some(feedback_rx);
    let mut pump = Box::pin(dataplane.run());
    // With no TUN packet yet, a closed inbound channel is the only ready
    // branch. This poll enters the outbound-only fallback before the race.
    poll_packet_pump_once(pump.as_mut()).await;

    let packet = Ipv4Packet::build_icmp_echo_request(
        Ipv4Addr::new(10, 20, 0, 1),
        Ipv4Addr::new(10, 20, 0, 2),
        0x1234,
        1,
        b"must-survive-feedback",
    );
    ctrl.inject(packet.clone()).await.unwrap();
    // TUN read completes synchronously; routing then waits for the held ACL
    // lock. No timing or task scheduling assumption drives this interleaving.
    poll_packet_pump_once(pump.as_mut()).await;
    assert!(outbound_rx.try_recv().is_err());
    let feedback = crate::business_mtu::build_local_mtu_feedback(
        &packet,
        crate::business_mtu::LocalMtuFeedbackKind::PacketTooBig { inner_ip_mtu: 1280 },
    )
    .unwrap();
    feedback_tx.send(feedback.clone()).unwrap();
    poll_packet_pump_once(pump.as_mut()).await;

    drop(acl_guard);
    poll_packet_pump_once(pump.as_mut()).await;
    let routed = outbound_rx
        .try_recv()
        .expect("local PMTU feedback cancelled a packet already consumed from TUN");
    assert_eq!(routed.packet, packet);
    assert_eq!(routed.peer_id, "peer-b");
    assert!(outbound_rx.try_recv().is_err(), "packet was routed twice");
    assert_eq!(
        timeout(Duration::from_secs(1), ctrl.recv_written())
            .await
            .expect("local PMTU feedback was not written after routing completed")
            .unwrap(),
        feedback
    );
}

#[tokio::test]
async fn outbound_only_feedback_cannot_cancel_consumed_tun_packet() {
    assert_feedback_cannot_cancel_consumed_fallback_packet(false).await;
}

#[tokio::test]
async fn closed_inbound_feedback_cannot_cancel_consumed_tun_packet() {
    assert_feedback_cannot_cancel_consumed_fallback_packet(true).await;
}

async fn assert_closed_feedback_keeps_packet_pump_running(bidirectional: bool) {
    let peers = Arc::new(PeerManager::new(
        Config::generate_default("http://ctrl.test", "default").unwrap(),
    ));
    peers.add_peer(&peer("peer-b", "10.20.0.2")).await;
    let (tun, ctrl) = MockTunDevice::new_pair("test0", 1420, "10.20.0.1");
    let (mut dataplane, mut outbound_rx, inbound_tx) = if bidirectional {
        let (dataplane, outbound_rx, inbound_tx) = DataPlane::new_bidirectional(tun, peers);
        (dataplane, outbound_rx, Some(inbound_tx))
    } else {
        let (dataplane, outbound_rx) = DataPlane::new(tun, peers);
        (dataplane, outbound_rx, None)
    };
    let (feedback_tx, feedback_rx) = tokio::sync::broadcast::channel(1);
    dataplane.local_feedback_rx = Some(feedback_rx);
    let mut pump = Box::pin(dataplane.run());
    poll_packet_pump_once(pump.as_mut()).await;
    drop(feedback_tx);
    // A permanently closed feedback receiver is disabled. Polling the pump
    // must still yield, and must preserve the live inbound channel.
    poll_packet_pump_once(pump.as_mut()).await;

    let outbound = Ipv4Packet::build_icmp_echo_request(
        Ipv4Addr::new(10, 20, 0, 1),
        Ipv4Addr::new(10, 20, 0, 2),
        0x1234,
        1,
        b"outbound-after-feedback-close",
    );
    let inbound = Ipv4Packet::build_icmp_echo_request(
        Ipv4Addr::new(10, 20, 0, 2),
        Ipv4Addr::new(10, 20, 0, 1),
        0x5678,
        1,
        b"inbound-after-feedback-close",
    );
    ctrl.inject(outbound.clone()).await.unwrap();
    if let Some(inbound_tx) = inbound_tx.as_ref() {
        inbound_tx
            .try_send(InboundPacket {
                peer_id: "peer-b".into(),
                packet: inbound.clone(),
                session_instance: None,
                from_previous_session: false,
                trace: None,
            })
            .expect("feedback closure discarded the live inbound receiver");
    }
    poll_packet_pump_once(pump.as_mut()).await;
    assert_eq!(outbound_rx.try_recv().unwrap().packet, outbound);
    assert!(outbound_rx.try_recv().is_err(), "packet was routed twice");
    if bidirectional {
        assert_eq!(
            timeout(Duration::from_secs(1), ctrl.recv_written())
                .await
                .expect("feedback closure prevented inbound TUN delivery")
                .unwrap(),
            inbound
        );
    }

    // Closing TUN remains terminal even after feedback has been disabled.
    drop(ctrl);
    assert!(matches!(pump.await, Err(DaemonError::Network(_))));
}

#[tokio::test]
async fn closed_feedback_keeps_outbound_only_tun_active() {
    assert_closed_feedback_keeps_packet_pump_running(false).await;
}

#[tokio::test]
async fn closed_feedback_keeps_bidirectional_tun_active() {
    assert_closed_feedback_keeps_packet_pump_running(true).await;
}

#[tokio::test]
async fn drops_packet_for_unknown_virtual_ip() {
    let peers = Arc::new(PeerManager::new(
        Config::generate_default("http://ctrl.test", "default").unwrap(),
    ));

    let (tun, ctrl) = MockTunDevice::new_pair("test0", 1420, "10.20.0.1");
    let (mut dataplane, mut outbound_rx) = DataPlane::new(tun, peers);
    let task = tokio::spawn(async move { dataplane.run().await });

    let packet = Ipv4Packet::build_icmp_echo_request(
        Ipv4Addr::new(10, 20, 0, 1),
        Ipv4Addr::new(10, 20, 0, 99),
        0x1234,
        1,
        b"ping",
    );
    ctrl.inject(packet).await.unwrap();

    let no_packet = timeout(Duration::from_millis(200), outbound_rx.recv()).await;
    assert!(no_packet.is_err());

    task.abort();
}

#[tokio::test]
async fn writes_inbound_peer_packet_to_tun() {
    let peers = Arc::new(PeerManager::new(
        Config::generate_default("http://ctrl.test", "default").unwrap(),
    ));
    peers.add_peer(&peer("peer-b", "10.20.0.2")).await;

    let (tun, ctrl) = MockTunDevice::new_pair("test0", 1420, "10.20.0.1");
    let (mut dataplane, _outbound_rx, inbound_tx) =
        DataPlane::new_bidirectional(tun, peers.clone());
    let task = tokio::spawn(async move { dataplane.run().await });

    let packet = Ipv4Packet::build_icmp_echo_request(
        Ipv4Addr::new(10, 20, 0, 2),
        Ipv4Addr::new(10, 20, 0, 1),
        0x1234,
        1,
        b"pong",
    );

    inbound_tx
        .send(InboundPacket {
            peer_id: "peer-b".to_string(),
            packet: packet.clone(),
            session_instance: None,
            from_previous_session: false,
            trace: None,
        })
        .await
        .unwrap();

    let written = timeout(Duration::from_secs(1), ctrl.recv_written())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(written, packet);

    let conn = peers.get_connection("peer-b").await.unwrap();
    assert_eq!(conn.bytes_received, written.len() as u64);

    task.abort();
}

#[tokio::test]
async fn drops_inbound_packet_with_spoofed_peer_virtual_ip() {
    let peers = Arc::new(PeerManager::new(
        Config::generate_default("http://ctrl.test", "default").unwrap(),
    ));
    peers.add_peer(&peer("peer-b", "10.20.0.2")).await;

    let (tun, ctrl) = MockTunDevice::new_pair("test0", 1420, "10.20.0.1");
    let (mut dataplane, _outbound_rx, inbound_tx) =
        DataPlane::new_bidirectional(tun, peers.clone());
    let task = tokio::spawn(async move { dataplane.run().await });
    let packet = Ipv4Packet::build_icmp_echo_request(
        Ipv4Addr::new(10, 20, 0, 99),
        Ipv4Addr::new(10, 20, 0, 1),
        0x1234,
        1,
        b"spoofed",
    );

    inbound_tx
        .send(InboundPacket {
            peer_id: "peer-b".to_string(),
            packet,
            session_instance: None,
            from_previous_session: false,
            trace: None,
        })
        .await
        .unwrap();

    assert!(timeout(Duration::from_millis(100), ctrl.recv_written())
        .await
        .is_err());
    assert_eq!(
        peers.get_connection("peer-b").await.unwrap().bytes_received,
        0
    );
    task.abort();
}

#[tokio::test]
async fn normalizes_inbound_non_overlay_source_pollution() {
    let peers = Arc::new(PeerManager::new(
        Config::generate_default("http://ctrl.test", "default").unwrap(),
    ));
    peers.add_peer(&peer("peer-b", "10.20.0.2")).await;

    let (tun, ctrl) = MockTunDevice::new_pair("test0", 1420, "10.20.0.1");
    let (dataplane, _outbound_rx, inbound_tx) = DataPlane::new_bidirectional(tun, peers.clone());
    let mut dataplane = dataplane.with_overlay_cidr("10.20.0.0/16");
    let task = tokio::spawn(async move { dataplane.run().await });

    let packet = Ipv4Packet::build_icmp_echo_request(
        Ipv4Addr::new(100, 84, 190, 40),
        Ipv4Addr::new(10, 20, 0, 1),
        0x1234,
        1,
        b"vpn-polluted",
    );

    inbound_tx
        .send(InboundPacket {
            peer_id: "peer-b".to_string(),
            packet,
            session_instance: None,
            from_previous_session: false,
            trace: None,
        })
        .await
        .unwrap();

    let written = timeout(Duration::from_secs(1), ctrl.recv_written())
        .await
        .unwrap()
        .unwrap();
    let parsed = Ipv4Packet::new(&written).unwrap();
    assert_eq!(parsed.src_addr(), Ipv4Addr::new(10, 20, 0, 2));
    assert_eq!(parsed.dst_addr(), Ipv4Addr::new(10, 20, 0, 1));
    assert!(parsed.verify_checksum());
    assert_eq!(
        peers.get_connection("peer-b").await.unwrap().bytes_received,
        written.len() as u64
    );
    task.abort();
}

#[tokio::test]
async fn keeps_blocking_inbound_overlay_source_spoofing() {
    let peers = Arc::new(PeerManager::new(
        Config::generate_default("http://ctrl.test", "default").unwrap(),
    ));
    peers.add_peer(&peer("peer-b", "10.20.0.2")).await;

    let (tun, ctrl) = MockTunDevice::new_pair("test0", 1420, "10.20.0.1");
    let (dataplane, _outbound_rx, inbound_tx) = DataPlane::new_bidirectional(tun, peers.clone());
    let mut dataplane = dataplane.with_overlay_cidr("10.20.0.0/16");
    let task = tokio::spawn(async move { dataplane.run().await });

    let packet = Ipv4Packet::build_icmp_echo_request(
        Ipv4Addr::new(10, 20, 0, 99),
        Ipv4Addr::new(10, 20, 0, 1),
        0x1234,
        1,
        b"overlay-spoofed",
    );

    inbound_tx
        .send(InboundPacket {
            peer_id: "peer-b".to_string(),
            packet,
            session_instance: None,
            from_previous_session: false,
            trace: None,
        })
        .await
        .unwrap();

    assert!(timeout(Duration::from_millis(100), ctrl.recv_written())
        .await
        .is_err());
    assert_eq!(
        peers.get_connection("peer-b").await.unwrap().bytes_received,
        0
    );
    task.abort();
}

#[tokio::test]
async fn normalizes_outbound_non_overlay_source_pollution() {
    let peers = Arc::new(PeerManager::new(
        Config::generate_default("http://ctrl.test", "default").unwrap(),
    ));
    peers.add_peer(&peer("peer-b", "10.20.0.2")).await;

    let (tun, ctrl) = MockTunDevice::new_pair("test0", 1420, "10.20.0.1");
    let (dataplane, mut outbound_rx) = DataPlane::new(tun, peers.clone());
    let mut dataplane = dataplane.with_overlay_cidr("10.20.0.0/16");
    let task = tokio::spawn(async move { dataplane.run().await });

    let packet = Ipv4Packet::build_icmp_echo_request(
        Ipv4Addr::new(100, 84, 190, 40),
        Ipv4Addr::new(10, 20, 0, 2),
        0x1234,
        1,
        b"vpn-polluted",
    );
    ctrl.inject(packet).await.unwrap();

    let routed = timeout(Duration::from_secs(1), outbound_rx.recv())
        .await
        .unwrap()
        .unwrap();
    let parsed = Ipv4Packet::new(&routed.packet).unwrap();
    assert_eq!(routed.peer_id, "peer-b");
    assert_eq!(parsed.src_addr(), Ipv4Addr::new(10, 20, 0, 1));
    assert_eq!(parsed.dst_addr(), Ipv4Addr::new(10, 20, 0, 2));
    assert!(parsed.verify_checksum());
    assert_eq!(
        peers.get_connection("peer-b").await.unwrap().bytes_sent,
        routed.packet.len() as u64
    );
    task.abort();
}

#[tokio::test]
async fn keeps_blocking_outbound_overlay_source_spoofing() {
    let peers = Arc::new(PeerManager::new(
        Config::generate_default("http://ctrl.test", "default").unwrap(),
    ));
    peers.add_peer(&peer("peer-b", "10.20.0.2")).await;

    let (tun, ctrl) = MockTunDevice::new_pair("test0", 1420, "10.20.0.1");
    let (dataplane, mut outbound_rx) = DataPlane::new(tun, peers.clone());
    let mut dataplane = dataplane.with_overlay_cidr("10.20.0.0/16");
    let task = tokio::spawn(async move { dataplane.run().await });

    let packet = Ipv4Packet::build_icmp_echo_request(
        Ipv4Addr::new(10, 20, 0, 99),
        Ipv4Addr::new(10, 20, 0, 2),
        0x1234,
        1,
        b"overlay-spoofed",
    );
    ctrl.inject(packet).await.unwrap();

    assert!(timeout(Duration::from_millis(100), outbound_rx.recv())
        .await
        .is_err());
    assert_eq!(peers.get_connection("peer-b").await.unwrap().bytes_sent, 0);
    task.abort();
}

#[tokio::test]
async fn live_acl_denies_matching_inbound_packet() {
    let peers = Arc::new(PeerManager::new(
        Config::generate_default("http://ctrl.test", "default").unwrap(),
    ));
    peers.add_peer(&peer("peer-b", "10.20.0.2")).await;
    let acl = Arc::new(RwLock::new(AclEngine::from_config(&AclConfig {
        enabled: true,
        rules: vec![AclRule {
            action: "deny".to_string(),
            src: "peer-b".to_string(),
            dst: "local-node".to_string(),
            proto: "icmp".to_string(),
            port: "*".to_string(),
        }],
    })));

    let (tun, ctrl) = MockTunDevice::new_pair("test0", 1420, "10.20.0.1");
    let (dataplane, _outbound_rx, inbound_tx) = DataPlane::new_bidirectional(tun, peers.clone());
    let mut dataplane = dataplane.with_acl(acl, "local-node");
    let task = tokio::spawn(async move { dataplane.run().await });
    let packet = Ipv4Packet::build_icmp_echo_request(
        Ipv4Addr::new(10, 20, 0, 2),
        Ipv4Addr::new(10, 20, 0, 1),
        0x1234,
        1,
        b"denied",
    );

    inbound_tx
        .send(InboundPacket {
            peer_id: "peer-b".to_string(),
            packet,
            session_instance: None,
            from_previous_session: false,
            trace: None,
        })
        .await
        .unwrap();

    assert!(timeout(Duration::from_millis(100), ctrl.recv_written())
        .await
        .is_err());
    assert_eq!(
        peers.get_connection("peer-b").await.unwrap().bytes_received,
        0
    );
    task.abort();
}

#[tokio::test]
async fn room_revocation_blocks_both_directions_even_with_cached_peers() {
    let peers = Arc::new(PeerManager::new(
        Config::generate_default("http://ctrl.test", "room-test").unwrap(),
    ));
    peers.add_peer(&peer("peer-b", "10.21.1.3")).await;
    let authorization = Arc::new(crate::rooms::RoomAuthorization::new("room-test"));
    assert!(authorization.replace(
        "10.21.1.2",
        [("peer-b".into(), "10.21.1.3".into())],
        std::time::Instant::now(),
        30
    ));
    let (tun, ctrl) = MockTunDevice::new_pair("room0", 1420, "10.21.1.2");
    let (dataplane, mut outbound_rx, inbound_tx) = DataPlane::new_bidirectional(tun, peers.clone());
    let mut dataplane = dataplane.with_room_authorization(authorization.clone());
    let task = tokio::spawn(async move { dataplane.run().await });
    let outbound = Ipv4Packet::build_icmp_echo_request(
        Ipv4Addr::new(10, 21, 1, 2),
        Ipv4Addr::new(10, 21, 1, 3),
        1,
        1,
        b"room",
    );
    let inbound = Ipv4Packet::build_icmp_echo_request(
        Ipv4Addr::new(10, 21, 1, 3),
        Ipv4Addr::new(10, 21, 1, 2),
        1,
        1,
        b"room",
    );
    ctrl.inject(outbound.clone()).await.unwrap();
    assert_eq!(
        timeout(Duration::from_secs(1), outbound_rx.recv())
            .await
            .unwrap()
            .unwrap()
            .packet,
        outbound
    );
    inbound_tx
        .send(InboundPacket {
            peer_id: "peer-b".into(),
            packet: inbound.clone(),
            session_instance: None,
            from_previous_session: false,
            trace: None,
        })
        .await
        .unwrap();
    assert_eq!(
        timeout(Duration::from_secs(1), ctrl.recv_written())
            .await
            .unwrap()
            .unwrap(),
        inbound
    );
    authorization.invalidate();
    assert!(peers.get_connection("peer-b").await.is_some());
    ctrl.inject(outbound).await.unwrap();
    inbound_tx
        .send(InboundPacket {
            peer_id: "peer-b".into(),
            packet: inbound,
            session_instance: None,
            from_previous_session: false,
            trace: None,
        })
        .await
        .unwrap();
    assert!(timeout(Duration::from_millis(100), outbound_rx.recv())
        .await
        .is_err());
    assert!(timeout(Duration::from_millis(100), ctrl.recv_written())
        .await
        .is_err());
    task.abort();
}

#[tokio::test]
async fn room_dataplane_rejects_cross_network_source_before_normalization() {
    let peers = Arc::new(PeerManager::new(
        Config::generate_default("http://ctrl.test", "room-test").unwrap(),
    ));
    peers.add_peer(&peer("peer-b", "10.21.1.3")).await;
    let authorization = Arc::new(crate::rooms::RoomAuthorization::new("room-test"));
    assert!(authorization.replace(
        "10.21.1.2",
        [("peer-b".into(), "10.21.1.3".into())],
        std::time::Instant::now(),
        30
    ));
    let (tun, ctrl) = MockTunDevice::new_pair("room0", 1420, "10.21.1.2");
    let (dataplane, mut outbound_rx) = DataPlane::new(tun, peers);
    let mut dataplane = dataplane.with_room_authorization(authorization);
    let task = tokio::spawn(async move { dataplane.run().await });
    for source in [Ipv4Addr::new(10, 20, 0, 2), Ipv4Addr::new(10, 21, 2, 2)] {
        let packet = Ipv4Packet::build_icmp_echo_request(
            source,
            Ipv4Addr::new(10, 21, 1, 3),
            1,
            1,
            b"cross-room",
        );
        ctrl.inject(packet).await.unwrap();
    }
    assert!(timeout(Duration::from_millis(100), outbound_rx.recv())
        .await
        .is_err());
    task.abort();
}

#[tokio::test]
async fn audit_room_outbound_must_recheck_after_acl_wait() {
    let peers = Arc::new(PeerManager::new(
        Config::generate_default("http://ctrl.test", "room-test").unwrap(),
    ));
    peers.add_peer(&peer("peer-b", "10.21.1.3")).await;
    let auth = Arc::new(crate::rooms::RoomAuthorization::new("room-test"));
    assert!(auth.replace(
        "10.21.1.2",
        [("peer-b".into(), "10.21.1.3".into())],
        std::time::Instant::now(),
        30
    ));
    let acl = Arc::new(RwLock::new(crate::acl::AclEngine::from_config(
        &AclConfig::default(),
    )));
    let guard = acl.write().await;
    let (tun, _ctrl) = MockTunDevice::new_pair("room0", 1420, "10.21.1.2");
    let (dp, mut rx) = DataPlane::new(tun, peers);
    let mut dp = dp
        .with_room_authorization(auth.clone())
        .with_acl(acl.clone(), "local");
    let packet = Ipv4Packet::build_icmp_echo_request(
        Ipv4Addr::new(10, 21, 1, 2),
        Ipv4Addr::new(10, 21, 1, 3),
        1,
        1,
        b"secret-after-revocation",
    );
    let now = std::time::Instant::now();
    let mut routing = Box::pin(dp.route_outbound_packet(&packet, now, now));
    // Poll through the first authorization check to the held ACL read lock.
    std::future::poll_fn(|cx| {
        assert!(std::future::Future::poll(routing.as_mut(), cx).is_pending());
        std::task::Poll::Ready(())
    })
    .await;
    auth.invalidate();
    drop(guard);
    routing.await.unwrap();
    assert!(
        rx.try_recv().is_err(),
        "packet was queued for transport after room authorization was revoked"
    );
}
