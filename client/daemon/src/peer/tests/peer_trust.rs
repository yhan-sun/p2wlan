use super::*;
use crate::config::{PeerIdentityPin, PeerTrustConfig, PeerTrustMode};

#[tokio::test]
async fn strict_peer_trust_is_enforced_by_owner_and_revokes_replaced_lifecycle() {
    let mut config = test_config();
    let remote = NodeIdentity::generate();
    let info = PeerInfo {
        node_id: "pinned-node".into(),
        public_key: hex::encode(remote.public_key()),
        virtual_ip: "10.20.0.2".into(),
        online: true,
        ..PeerInfo::default()
    };
    config.network.peer_trust = PeerTrustConfig {
        mode: PeerTrustMode::Strict,
        network_id: config.network.network_id.clone(),
        peers: vec![PeerIdentityPin {
            node_id: info.node_id.clone(),
            public_key: info.public_key.clone(),
            virtual_ip: info.virtual_ip.clone(),
        }],
    };
    let peers = PeerManager::new(config);
    assert!(!peers.signal_sender_identity_matches_peer_sync("unknown-node", None));
    let mut alias = info.clone();
    alias.node_id = "server-renamed-node".into();
    assert!(peers.add_peer(&alias).await.last_seen_only);
    assert!(!peers.peer_exists_sync(&alias.node_id));

    assert!(peers.add_peer(&info).await.is_new);
    let lifecycle = peers.peer_session_generation_sync(&info.node_id).unwrap();
    assert!(peers.signal_sender_identity_matches_peer_sync(&info.node_id, None));
    assert!(peers.signal_sender_identity_matches_peer_sync(&info.node_id, Some(&info.public_key)));
    let mut replacement = info.clone();
    replacement.public_key = hex::encode(NodeIdentity::generate().public_key());
    assert!(peers.add_peer(&replacement).await.last_seen_only);
    assert!(!peers.peer_exists_sync(&info.node_id));
    assert!(!peers.peer_session_is_current_sync(&info.node_id, lifecycle));
    assert!(!peers.signal_sender_identity_matches_peer_sync(&info.node_id, None));

    assert!(peers.add_peer(&info).await.is_new);
    let mut moved = info.clone();
    moved.virtual_ip = "10.20.0.3".into();
    assert!(peers.add_peer(&moved).await.last_seen_only);
    assert!(!peers.peer_exists_sync(&info.node_id));
}

#[tokio::test]
async fn default_peer_trust_preserves_legacy_roster_and_signal_compatibility() {
    let peers = PeerManager::new(test_config());
    assert!(peers.signal_sender_identity_matches_peer_sync("legacy-missing-peer", None));
    let info = PeerInfo {
        node_id: "legacy-peer".into(),
        public_key: "legacy-key".into(),
        virtual_ip: "10.20.0.2".into(),
        ..PeerInfo::default()
    };
    assert!(peers.add_peer(&info).await.is_new);
    assert!(peers.peer_exists_sync(&info.node_id));
}

#[tokio::test]
async fn strict_peer_trust_invalid_direct_owner_configuration_fails_closed() {
    let mut config = test_config();
    let info = PeerInfo {
        node_id: "duplicate-pin".into(),
        public_key: "42".repeat(32),
        virtual_ip: "10.20.0.2".into(),
        ..PeerInfo::default()
    };
    let pin = PeerIdentityPin {
        node_id: info.node_id.clone(),
        public_key: info.public_key.clone(),
        virtual_ip: info.virtual_ip.clone(),
    };
    config.network.peer_trust = PeerTrustConfig {
        mode: PeerTrustMode::Strict,
        network_id: config.network.network_id.clone(),
        peers: vec![pin.clone(), pin],
    };
    assert!(config.network.validate_peer_trust().is_err());
    let peers = PeerManager::new(config);
    assert!(peers.add_peer(&info).await.last_seen_only);
    assert!(!peers.peer_exists_sync(&info.node_id));
}
