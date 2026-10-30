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
async fn original_capability_qualification_shares_membership_readers() {
    let manager = manager_with_two_peers().await;
    let life = manager.peer_session_generation_sync("cap-a").unwrap();
    manager.mark_dplpmtud_capable_sync("cap-a", life);
    let membership = manager.peer_membership.read().unwrap();
    assert_eq!(
        manager.try_peer_dplpmtud_capability("cap-a"),
        PeerDplpmtudCapability::Supported
    );
    assert!(manager.peer_membership.try_read().is_ok());
    assert!(matches!(
        manager.peer_membership.try_write(),
        Err(std::sync::TryLockError::WouldBlock)
    ));
    drop(membership);
    assert!(manager.peer_membership.try_write().is_ok());
}

#[tokio::test]
async fn original_capability_gate_refuses_contention_and_releases_membership() {
    let manager = manager_with_two_peers().await;
    let life = manager.peer_session_generation_sync("cap-a").unwrap();
    manager.mark_dplpmtud_capable_sync("cap-a", life);
    let publication = manager.dplpmtud_capability.gate.lock().unwrap();
    let outcome = manager.try_peer_dplpmtud_capability("cap-a");
    let membership_released = manager.peer_membership.try_write().is_ok();
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
    let membership = manager.peer_membership.write().unwrap();
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

// The fixture holds the actual membership owner. A publisher which has entered
// the original publication gate cannot yet validate or publish its snapshot.
fn wait_for_original_capability_publisher(manager: &PeerManager) -> bool {
    let end = Instant::now() + Duration::from_secs(2);
    while Instant::now() < end {
        match manager.dplpmtud_capability.gate.try_lock() {
            Err(std::sync::TryLockError::WouldBlock) => return true,
            Err(std::sync::TryLockError::Poisoned(_)) => return false,
            Ok(guard) => drop(guard),
        }
        std::thread::yield_now();
    }
    false
}

#[tokio::test]
async fn capability_unlocked_copy_rechecks_rotated_membership_before_any_publication() {
    for previously_published in [false, true] {
        let manager = manager_with_two_peers().await;
        let old = manager.peer_session_generation_sync("cap-a").unwrap();
        if previously_published {
            manager.mark_dplpmtud_capable_sync("cap-a", old);
        }
        let receiver = manager.dplpmtud_capability.sender.subscribe();
        let original = manager.dplpmtud_capability.sender.borrow().clone();
        let mut membership = manager.peer_membership.write().unwrap();
        let worker = std::thread::spawn({
            let manager = manager.clone();
            move || manager.mark_dplpmtud_capable_sync("cap-a", old)
        });
        let entered = wait_for_original_capability_publisher(&manager);
        let current = membership.publish("cap-a", true, true).unwrap();
        drop(membership);
        let joined = worker.join();
        assert!(entered && joined.is_ok());
        assert_ne!(old, current);
        assert!(!receiver.has_changed().unwrap());
        assert!(Arc::ptr_eq(
            &original,
            &manager.dplpmtud_capability.sender.borrow()
        ));
        assert!(!manager.peer_supports_dplpmtud_sync("cap-a", current));
        assert_eq!(
            manager.try_peer_dplpmtud_capability("cap-a"),
            PeerDplpmtudCapability::Unsupported
        );
        assert!(manager.peer_membership.try_write().is_ok());
        assert!(manager.dplpmtud_capability.gate.try_lock().is_ok());
    }
}

#[tokio::test]
async fn capability_unlocked_copy_prunes_only_against_original_current_membership() {
    let manager = manager_with_two_peers().await;
    for id in ["cap-a", "cap-b"] {
        let life = manager.peer_session_generation_sync(id).unwrap();
        manager.mark_dplpmtud_capable_sync(id, life);
    }
    let mut third = test_peer("cap-c", "192.0.2.1:51820".parse().unwrap());
    third.virtual_ip = "10.20.0.4".to_owned();
    manager.add_peer(&third).await;
    let third_life = manager.peer_session_generation_sync("cap-c").unwrap();
    let receiver = manager.dplpmtud_capability.sender.subscribe();
    let mut membership = manager.peer_membership.write().unwrap();
    let worker = std::thread::spawn({
        let manager = manager.clone();
        move || manager.mark_dplpmtud_capable_sync("cap-c", third_life)
    });
    let entered = wait_for_original_capability_publisher(&manager);
    membership.publish("cap-b", false, false).unwrap();
    drop(membership);
    let joined = worker.join();
    assert!(entered && joined.is_ok());
    assert!(receiver.has_changed().unwrap());
    let published = manager.dplpmtud_capability.sender.borrow().clone();
    assert_eq!(published.len(), 2);
    assert!(!published.contains_key("cap-b"));
    for id in ["cap-a", "cap-c"] {
        assert_eq!(
            manager.try_peer_dplpmtud_capability(id),
            PeerDplpmtudCapability::Supported
        );
    }
    assert_eq!(
        manager.try_peer_dplpmtud_capability("cap-b"),
        PeerDplpmtudCapability::Unknown
    );
    assert!(manager.peer_membership.try_write().is_ok());
    assert!(manager.dplpmtud_capability.gate.try_lock().is_ok());
}
