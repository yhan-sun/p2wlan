use super::*;
use crate::{config::Config, control::PeerInfo, rooms::RoomAuthorization};
use p2pnet_tun::{mock::MockTunController, Ipv4Packet, MockTunDevice};
use std::time::{Duration, Instant};

struct Fixture {
    plane: DataPlane<MockTunDevice>,
    controller: MockTunController,
    outbound: mpsc::Receiver<OutboundPacket>,
    auth: Arc<RoomAuthorization>,
}

impl Fixture {
    async fn new() -> Self {
        let peers = Arc::new(PeerManager::new(
            Config::generate_default("http://ctrl.test", "room-data").unwrap(),
        ));
        peers
            .add_peer(&PeerInfo {
                node_id: "b".into(),
                virtual_ip: "10.21.1.3".into(),
                public_key: "pk".into(),
                device_name: String::new(),
                app_version: String::new(),
                endpoint: String::new(),
                nat_type: String::new(),
                online: true,
                last_seen: 0,
                relay_rtt_ms: None,
            })
            .await;
        let auth = Arc::new(RoomAuthorization::new("room-data"));
        assert!(auth.replace(
            "10.21.1.2",
            [("b".into(), "10.21.1.3".into())],
            Instant::now(),
            30
        ));
        let (tun, controller) = MockTunDevice::new_pair("p2r1", 1420, "10.21.1.2");
        let (plane, outbound) = DataPlane::new(tun, peers);
        let plane = plane
            .with_overlay_cidr("10.21.1.0/24")
            .with_room_authorization(auth.clone())
            .with_local_source_addresses(
                ["192.168.50.2", "10.21.2.2", "10.20.0.2"].map(|ip| ip.parse().unwrap()),
            );
        Self {
            plane,
            controller,
            outbound,
            auth,
        }
    }

    async fn send(&mut self, source: &str, destination: &str) {
        self.controller
            .inject(echo(source, destination))
            .await
            .unwrap();
        self.plane
            .read_and_route_once(&mut [0u8; 2048])
            .await
            .unwrap();
    }

    fn drops(&self, reason: &str) -> u64 {
        self.auth
            .diagnostics("10.21.1.2")
            .unwrap()
            .drops
            .get(reason)
            .copied()
            .unwrap_or(0)
    }
}

fn echo(source: &str, destination: &str) -> Vec<u8> {
    Ipv4Packet::build_icmp_echo_request(
        source.parse().unwrap(),
        destination.parse().unwrap(),
        123,
        1,
        b"room-ping",
    )
}

#[tokio::test]
async fn room_authorizes_the_safely_normalized_local_source() {
    let mut f = Fixture::new().await;
    f.send("192.168.50.2", "10.21.1.3").await;
    let routed = f
        .outbound
        .try_recv()
        .expect("local source was rejected before normalization");
    assert_eq!(routed.packet, echo("10.21.1.2", "10.21.1.3"));
    assert!(routed.room_authorization.unwrap().is_valid());
    let d = f.auth.diagnostics("10.21.1.2").unwrap();
    assert_eq!(d.peers[0].tx_queued_packets, 1);
    assert_eq!(d.peers[0].rx_delivered_packets, 0);
    assert!(d.drops.is_empty());
}

#[tokio::test]
async fn room_never_normalizes_other_overlay_or_unowned_sources() {
    let mut f = Fixture::new().await;
    for source in ["10.21.1.9", "10.21.2.2", "10.20.0.2", "192.168.50.99"] {
        f.send(source, "10.21.1.3").await;
        assert!(f.outbound.try_recv().is_err());
    }
    assert_eq!(f.drops("overlay_source_rejected"), 3);
    assert_eq!(f.drops("source_not_local"), 1);
}

#[tokio::test]
async fn room_revocation_and_unknown_route_are_observable_and_fail_closed() {
    let mut f = Fixture::new().await;
    f.send("10.21.1.2", "10.21.1.99").await;
    assert_eq!(f.drops("unknown_virtual_ip"), 1);
    f.auth.invalidate();
    f.send("192.168.50.2", "10.21.1.3").await;
    assert!(f.outbound.try_recv().is_err());
    assert_eq!(f.drops("authorization_missing"), 1);
}

#[tokio::test]
async fn room_inbound_requires_exact_sender_ip_and_records_tun_delivery_only() {
    let mut f = Fixture::new().await;
    for source in ["192.168.50.2", "10.21.2.3", "10.21.1.3"] {
        f.plane
            .write_inbound(InboundPacket {
                peer_id: "b".into(),
                packet: echo(source, "10.21.1.2"),
                session_instance: None,
                from_previous_session: false,
                trace: None,
            })
            .await
            .unwrap();
    }
    assert_eq!(f.drops("peer_ip_mismatch"), 2);
    assert_eq!(
        tokio::time::timeout(Duration::from_secs(1), f.controller.recv_written())
            .await
            .unwrap()
            .unwrap(),
        echo("10.21.1.3", "10.21.1.2")
    );
    let d = f.auth.diagnostics("10.21.1.2").unwrap();
    assert_eq!(d.peers[0].rx_delivered_packets, 1);
    assert_eq!(d.peers[0].tx_queued_packets, 0);
    assert!(
        tokio::time::timeout(Duration::from_millis(10), f.controller.recv_written())
            .await
            .is_err()
    );
}
