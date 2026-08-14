use std::net::Ipv4Addr;
    use std::time::Duration;

    use p2pnet_tun::{Ipv4Packet, MockTunDevice};
    use tokio::time::timeout;

    use super::*;
    use crate::config::{AclConfig, AclRule, Config};
    use crate::control::PeerInfo;

    fn peer(node_id: &str, virtual_ip: &str) -> PeerInfo {
        PeerInfo {
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
        let (mut dataplane, mut outbound_rx, inbound_tx) =
            DataPlane::new_bidirectional(tun, peers);
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
        let (dataplane, _outbound_rx, inbound_tx) =
            DataPlane::new_bidirectional(tun, peers.clone());
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
        let (dataplane, _outbound_rx, inbound_tx) =
            DataPlane::new_bidirectional(tun, peers.clone());
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
        let (dataplane, _outbound_rx, inbound_tx) =
            DataPlane::new_bidirectional(tun, peers.clone());
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
