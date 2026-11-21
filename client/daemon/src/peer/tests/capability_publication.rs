use super::*;
use std::sync::Barrier;

async fn manager_with_two_peers() -> Arc<PeerManager> {
    let manager = Arc::new(PeerManager::new(test_config()));
    for (id, vip) in [("cap-a", "10.20.0.2"), ("cap-b", "10.20.0.3")] {
        let mut peer = test_peer(id, "192.0.2.1:51820".parse().unwrap());
        peer.virtual_ip = vip.to_owned();
        manager.add_peer(&peer).await;
    }
    manager
}

#[tokio::test]
async fn original_capability_gate_refuses_contention_and_releases_membership() {
    let manager = manager_with_two_peers().await;
    let life = manager.peer_session_generation_sync("cap-a").unwrap();
    manager.mark_dplpmtud_capable_sync("cap-a", life);
    let publication = manager.dplpmtud_capability.gate.lock().unwrap();
    let outcome = manager.try_peer_dplpmtud_capability("cap-a");
    let membership_released = manager.peer_membership.try_lock().is_ok();
    drop(publication);
    assert_eq!(outcome, PeerDplpmtudCapability::Contended);
    assert!(
        membership_released,
        "failed qualification must release earlier guards"
    );
    assert_eq!(
        manager.try_peer_dplpmtud_capability("cap-a"),
        PeerDplpmtudCapability::Supported
    );
    let membership = manager.peer_membership.lock().unwrap();
    let outcome = manager.try_peer_dplpmtud_capability("cap-a");
    let publication_released = manager.dplpmtud_capability.gate.try_lock().is_ok();
    drop(membership);
    assert_eq!(outcome, PeerDplpmtudCapability::Contended);
    assert!(publication_released);
    assert_eq!(
        manager.try_peer_dplpmtud_capability("cap-a"),
        PeerDplpmtudCapability::Supported
    );
    assert_eq!(
        manager.try_peer_dplpmtud_capability("absent"),
        PeerDplpmtudCapability::Unknown
    );
    assert_eq!(
        manager.try_peer_dplpmtud_capability("cap-b"),
        PeerDplpmtudCapability::Unsupported
    );
}

#[tokio::test]
async fn concurrent_original_capability_publishers_preserve_both_live_entries() {
    for _ in 0..16 {
        let manager = manager_with_two_peers().await;
        let start = Arc::new(Barrier::new(3));
        let mut workers = Vec::new();
        for id in ["cap-a", "cap-b"] {
            let manager = manager.clone();
            let start = start.clone();
            let life = manager.peer_session_generation_sync(id).unwrap();
            workers.push(std::thread::spawn(move || {
                start.wait();
                manager.mark_dplpmtud_capable_sync(id, life);
            }));
        }
        start.wait();
        let joined = workers
            .into_iter()
            .map(|worker| worker.join())
            .collect::<Vec<_>>();
        assert!(
            joined.iter().all(Result::is_ok),
            "both original publishers must be joined"
        );
        for id in ["cap-a", "cap-b"] {
            assert_eq!(
                manager.try_peer_dplpmtud_capability(id),
                PeerDplpmtudCapability::Supported
            );
        }
        assert_eq!(manager.dplpmtud_capability.sender.borrow().len(), 2);
    }
}

#[tokio::test]
async fn delayed_old_capability_publisher_cannot_overwrite_current_lifecycle() {
    let manager = manager_with_two_peers().await;
    let old = manager.peer_session_generation_sync("cap-a").unwrap();
    manager.mark_dplpmtud_capable_sync("cap-a", old);
    manager.remove_peer("cap-a").await;
    assert_eq!(
        manager.try_peer_dplpmtud_capability("cap-a"),
        PeerDplpmtudCapability::Unknown
    );
    manager
        .add_peer(&test_peer("cap-a", "192.0.2.1:51820".parse().unwrap()))
        .await;
    let current = manager.peer_session_generation_sync("cap-a").unwrap();
    assert_ne!(old, current);
    manager.mark_dplpmtud_capable_sync("cap-a", current);
    let other = manager.peer_session_generation_sync("cap-b").unwrap();
    manager.mark_dplpmtud_capable_sync("cap-b", other);
    manager.mark_dplpmtud_capable_sync("cap-a", old);
    assert!(manager.peer_supports_dplpmtud_sync("cap-a", current));
    assert!(!manager.peer_supports_dplpmtud_sync("cap-a", old));
    assert_eq!(
        manager.try_peer_dplpmtud_capability("cap-a"),
        PeerDplpmtudCapability::Supported
    );
    assert_eq!(
        manager.try_peer_dplpmtud_capability("cap-b"),
        PeerDplpmtudCapability::Supported
    );
    manager.remove_peer("cap-b").await;
    manager.mark_dplpmtud_capable_sync("cap-b", other);
    assert_eq!(
        manager.try_peer_dplpmtud_capability("cap-b"),
        PeerDplpmtudCapability::Unknown
    );
    assert_eq!(
        manager.try_peer_dplpmtud_capability("cap-a"),
        PeerDplpmtudCapability::Supported
    );
}
