//! Shared bounded controls mint through the real original periodic algorithm.

use std::collections::{HashMap, VecDeque};
use std::sync::Arc;
use std::time::Duration;

use p2pnet_tun::mock::{MockTunController, MockTunDevice};

use crate::config::{Config, PathPolicy};
use crate::control::PeerInfo;
use crate::dataplane::DataPlane;
use crate::overlay_requests::{send_overlay_payloads, CanonicalOverlayRequest};
use crate::peer::PeerManager;
use crate::request_carriage::RawRequestDelivery;
use crate::OverlayStats;

pub(crate) const PEER: &str = "peer-carriage";
pub(crate) const LOCAL_VIP: &str = "10.20.0.1";
pub(crate) const TARGET_VIP: &str = "10.20.0.2";

pub(crate) fn peer_info() -> PeerInfo {
    PeerInfo {
        node_id: PEER.to_string(),
        public_key: "pk".to_string(),
        endpoint: "127.0.0.1:45003".to_string(),
        nat_type: "Unknown".to_string(),
        virtual_ip: TARGET_VIP.to_string(),
        online: true,
        ..PeerInfo::default()
    }
}

pub(crate) struct RoutedRequestFixture {
    pub(crate) peers: Arc<PeerManager>,
    pub(crate) controller: MockTunController,
    pub(crate) record: Arc<CanonicalOverlayRequest>,
    pub(crate) delivery: RawRequestDelivery,
}

pub(crate) struct InputRequestFixture {
    pub(crate) peers: Arc<PeerManager>,
    pub(crate) controller: MockTunController,
    pub(crate) tun: MockTunDevice,
    pub(crate) record: Arc<CanonicalOverlayRequest>,
}

pub(crate) async fn mint_input_request() -> InputRequestFixture {
    let mut config = Config::generate_default("http://ctrl.test", "default").unwrap();
    config.relay.path_policy = PathPolicy::Auto;
    let peers = Arc::new(PeerManager::new(config));
    peers.add_peer(&peer_info()).await;
    let generation = peers.current_network_generation_sync();
    let relay = "tcp://relay.test:443";
    peers
        .mark_relay_transport_ready(PEER, relay, generation)
        .await;
    assert!(peers.confirm_relay_peer(PEER, relay, generation).await);
    let (tun, controller) = MockTunDevice::new_pair("carriage", 1420, LOCAL_VIP);
    let mut stats = OverlayStats {
        sent: 0,
        received_valid: 0,
        received_invalid: 0,
        verified_round_trips: 0,
        last_seq: 0,
    };
    let mut sent = HashMap::new();
    let mut order = VecDeque::new();
    let mut nonce = 0x14_0000;
    let mut seq = 14;
    assert_eq!(
        send_overlay_payloads(
            &controller,
            &peers,
            LOCAL_VIP,
            true,
            None,
            &mut nonce,
            &mut seq,
            &mut stats,
            &mut sent,
            &mut order
        )
        .await,
        1
    );
    let record = sent
        .remove(&nonce)
        .expect("only true inject Ok inserts the original canonical");
    InputRequestFixture {
        peers,
        controller,
        tun,
        record,
    }
}

pub(crate) async fn mint_routed_request() -> RoutedRequestFixture {
    let InputRequestFixture {
        peers,
        controller,
        tun,
        record,
    } = mint_input_request().await;
    let (mut dataplane, mut routed_rx) = DataPlane::new_with_request_carriage(tun, peers.clone());
    let mut bytes = [0u8; 512];
    tokio::time::timeout(
        Duration::from_secs(1),
        dataplane.read_and_route_once(&mut bytes),
    )
    .await
    .unwrap()
    .unwrap();
    let delivery = routed_rx
        .recv()
        .await
        .expect("original route hands off to its one 1024 queue");
    assert!(Arc::ptr_eq(
        &record,
        &delivery.binding().unwrap().token().request().unwrap()
    ));
    assert_eq!(delivery.packet, record.original_packet());
    RoutedRequestFixture {
        peers,
        controller,
        record,
        delivery,
    }
}
