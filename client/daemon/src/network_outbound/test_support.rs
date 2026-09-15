use super::*;

use crate::control::PeerInfo;

use p2pnet_crypto::NodeIdentity;

use p2pnet_wireguard::{HandshakeInitiator, HandshakeResponder, TransportSession};
pub(super) fn establish_sessions() -> (TransportSession, TransportSession) {
    let node_a = NodeIdentity::generate();
    let node_b = NodeIdentity::generate();
    let mut initiator = HandshakeInitiator::new(node_a, node_b.public_key(), None);
    let mut responder = HandshakeResponder::new(node_b, None);
    let initiation = initiator.create_initiation().unwrap();
    let (response, node_b_keys) = responder
        .consume_initiation_and_respond(&initiation)
        .unwrap();
    let node_a_keys = initiator.consume_response(&response).unwrap();
    (
        TransportSession::new(node_a_keys),
        TransportSession::new(node_b_keys),
    )
}
pub(super) fn test_peer(node_id: &str, endpoint: SocketAddr) -> PeerInfo {
    PeerInfo {
        node_id: node_id.to_string(),
        device_name: String::new(),
        app_version: String::new(),
        public_key: "pk".to_string(),
        endpoint: endpoint.to_string(),
        nat_type: "Unknown".to_string(),
        virtual_ip: "10.20.0.2".to_string(),
        online: true,
        last_seen: 0,
        relay_rtt_ms: None,
    }
}
