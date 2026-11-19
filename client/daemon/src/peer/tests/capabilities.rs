use super::*;

#[tokio::test]
async fn capability_declarations_are_fenced_by_registration_and_membership() {
    let manager = PeerManager::new(test_config());
    let mut peer = test_peer("cap-peer", "192.0.2.1:51820".parse().unwrap());
    peer.public_key = hex::encode(NodeIdentity::generate().public_key());
    manager.add_peer(&peer).await;
    assert!(!manager.peer_supports_hh2(&peer.node_id).await);
    let legacy_life = manager.peer_session_generation_sync(&peer.node_id).unwrap();
    peer.registration_seq = 2;
    peer.capabilities = crate::control::PeerCapabilities {
        hh2_pair_nomination: true,
        hh2_plan_v2: true,
        probe_opaque_ids_v1: false,
    };
    let update = manager.add_peer(&peer).await;
    assert!(update.registration_changed);
    assert!(!manager.peer_session_is_current_sync(&peer.node_id, legacy_life));
    assert!(manager.peer_supports_hh2(&peer.node_id).await);
    let supported = peer.clone();
    let prior_life = manager.peer_session_generation_sync(&peer.node_id).unwrap();
    peer.registration_seq = 3;
    peer.capabilities = crate::control::PeerCapabilities::default();
    let update = manager.add_peer(&peer).await;
    assert!(update.registration_changed);
    assert!(!manager.peer_session_is_current_sync(&peer.node_id, prior_life));
    assert!(!manager.peer_supports_hh2(&peer.node_id).await);
    manager.add_peer(&supported).await;
    assert!(!manager.peer_supports_hh2(&peer.node_id).await);
    manager.remove_peer(&peer.node_id).await;
    manager.add_peer(&supported).await;
    assert!(!manager.peer_supports_hh2(&peer.node_id).await);
    peer.registration_seq = 4;
    peer.capabilities = crate::control::PeerCapabilities {
        hh2_pair_nomination: true,
        hh2_plan_v2: true,
        probe_opaque_ids_v1: false,
    };
    manager.add_peer(&peer).await;
    assert!(manager.peer_supports_hh2(&peer.node_id).await);
    peer.online = false;
    manager.add_peer(&peer).await;
    assert!(!manager.peer_supports_hh2(&peer.node_id).await);
}

#[tokio::test]
async fn same_registration_cannot_restore_a_revoked_capability() {
    let manager = PeerManager::new(test_config());
    let mut peer = test_peer("cap-revoke", "192.0.2.2:51820".parse().unwrap());
    peer.public_key = hex::encode(NodeIdentity::generate().public_key());
    peer.registration_seq = 1;
    peer.capabilities = crate::control::PeerCapabilities {
        hh2_pair_nomination: true,
        hh2_plan_v2: true,
        probe_opaque_ids_v1: false,
    };
    manager.add_peer(&peer).await;
    let enabled = peer.clone();
    peer.capabilities.hh2_plan_v2 = false;
    manager.add_peer(&peer).await;
    manager.add_peer(&enabled).await;
    assert!(!manager.peer_supports_hh2(&peer.node_id).await);
}
