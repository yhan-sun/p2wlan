use super::*;
use std::future::Future;
use std::task::Poll;

async fn setup() -> (PeerManager, PeerInfo) {
    let manager = PeerManager::new(test_config());
    let mut peer = test_peer("heartbeat-metadata", "192.0.2.1:51820".parse().unwrap());
    peer.last_seen = 10;
    manager.add_peer(&peer).await;
    (manager, peer)
}

#[tokio::test(flavor = "current_thread")]
async fn advanced_timestamp_does_not_wait_for_epoch_or_ip_writer_or_publish_path() {
    let (manager, mut peer) = setup().await;
    let before = manager.get_connection(&peer.node_id).await.unwrap();
    let lifecycle = manager.peer_session_generation_sync(&peer.node_id);
    let routes = manager.ip_to_node_snapshot.borrow().clone();
    let epoch = manager.network_epoch_gate.lock().await;
    let ip_writer = manager.ip_to_node.write().await;
    peer.last_seen = 11;
    let mut update = Box::pin(manager.add_peer(&peer));
    let result = std::future::poll_fn(|cx| Poll::Ready(update.as_mut().poll(cx))).await;
    drop(update);
    let Poll::Ready(result) = result else {
        panic!("advisory heartbeat joined the epoch or routing writer queue");
    };
    assert!(result.last_seen_only);
    assert!(!result.registration_changed && !result.is_new && !result.was_offline);
    assert_eq!(
        result.previous_virtual_ip.as_deref(),
        Some(peer.virtual_ip.as_str())
    );
    let after = manager.connections.try_read().unwrap();
    let after = after.get(&peer.node_id).unwrap();
    assert_eq!(after.last_seen.get(), 11);
    assert_eq!(after.path_state_snapshot(), before.path_state_snapshot());
    assert_eq!(after.remote_nat_profile, before.remote_nat_profile);
    assert_eq!(
        manager.peer_session_generation_sync(&peer.node_id),
        lifecycle
    );
    assert!(Arc::ptr_eq(&routes, &manager.ip_to_node_snapshot.borrow()));
    drop(ip_writer);
    drop(epoch);
}

#[tokio::test(flavor = "current_thread")]
async fn changed_correctness_or_other_metadata_fields_keep_original_epoch_fence() {
    let (manager, peer) = setup().await;
    let mut changes = Vec::new();
    macro_rules! changed {
        ($field:ident, $value:expr) => {{
            let mut changed = peer.clone();
            changed.last_seen = 11;
            changed.$field = $value;
            changes.push(changed);
        }};
    }
    changed!(online, false);
    changed!(virtual_ip, "10.20.0.3".into());
    changed!(public_key, "different".into());
    changed!(registration_seq, 1);
    changed!(endpoint, "192.0.2.2:51820".into());
    changed!(endpoint, "invalid endpoint".into());
    changed!(device_name, "renamed".into());
    changed!(app_version, "new".into());
    changed!(nat_type, "FullCone".into());
    changed!(relay_rtt_ms, Some(30));
    changed!(
        capabilities,
        crate::control::PeerCapabilities {
            hh2_pair_nomination: true,
            hh2_plan_v2: true,
        }
    );
    let epoch = manager.network_epoch_gate.lock().await;
    for changed in changes {
        let mut update = Box::pin(manager.add_peer(&changed));
        std::future::poll_fn(|cx| {
            assert!(update.as_mut().poll(cx).is_pending());
            Poll::Ready(())
        })
        .await;
        drop(update);
        assert_eq!(
            manager
                .connections
                .try_read()
                .unwrap()
                .get(&peer.node_id)
                .unwrap()
                .last_seen
                .get(),
            10
        );
    }
    drop(epoch);
}

#[tokio::test]
async fn busy_original_metadata_owners_never_partially_refresh_timestamp() {
    let (manager, mut peer) = setup().await;
    peer.last_seen = 11;
    let membership = manager.peer_membership.lock().unwrap();
    assert!(manager.try_refresh_peer_last_seen(&peer).is_none());
    drop(membership);
    let ledger = manager.remote_identity_ledger.lock().unwrap();
    assert!(manager.try_refresh_peer_last_seen(&peer).is_none());
    drop(ledger);
    let writer = manager.connections.write().await;
    assert!(manager.try_refresh_peer_last_seen(&peer).is_none());
    assert_eq!(writer.get(&peer.node_id).unwrap().last_seen.get(), 10);
    drop(writer);
    assert!(manager.add_peer(&peer).await.last_seen_only);
}

#[tokio::test]
async fn retired_membership_generation_and_missing_profile_cannot_use_heartbeat_path() {
    let (manager, mut peer) = setup().await;
    peer.last_seen = 11;
    manager
        .peer_membership
        .lock()
        .unwrap()
        .publish(&peer.node_id, false, true);
    assert!(manager.try_refresh_peer_last_seen(&peer).is_none());
    manager.add_peer(&peer).await;
    peer.last_seen = 12;
    {
        let mut connections = manager.connections.write().await;
        let conn = connections.get_mut(&peer.node_id).unwrap();
        conn.remote_nat_profile = None;
    }
    assert!(manager.try_refresh_peer_last_seen(&peer).is_none());
    manager.add_peer(&peer).await;
    peer.last_seen = 13;
    manager
        .connections
        .write()
        .await
        .get_mut(&peer.node_id)
        .unwrap()
        .state = ConnectionState::Closed;
    assert!(manager.try_refresh_peer_last_seen(&peer).is_none());
}

#[tokio::test]
async fn unchanged_or_older_timestamp_and_newer_registration_floor_use_original_path() {
    let (manager, mut peer) = setup().await;
    assert!(manager.try_refresh_peer_last_seen(&peer).is_none());
    peer.last_seen = 9;
    assert!(manager.try_refresh_peer_last_seen(&peer).is_none());
    peer.last_seen = 11;
    manager
        .remote_identity_ledger
        .lock()
        .unwrap()
        .record_registration_seq(&peer.node_id, &peer.public_key, 2);
    assert!(manager.try_refresh_peer_last_seen(&peer).is_none());
    assert_eq!(
        manager
            .get_connection(&peer.node_id)
            .await
            .unwrap()
            .last_seen
            .get(),
        10
    );
    assert!(manager.add_peer(&peer).await.last_seen_only);
    assert_eq!(
        manager
            .get_connection(&peer.node_id)
            .await
            .unwrap()
            .last_seen
            .get(),
        10
    );
}

#[tokio::test]
async fn real_offline_rejoin_and_registration_change_still_rotate_original_lifecycle() {
    let (manager, mut peer) = setup().await;
    let first = manager.peer_session_generation_sync(&peer.node_id).unwrap();
    peer.online = false;
    peer.last_seen = 11;
    assert!(!manager.add_peer(&peer).await.last_seen_only);
    assert!(!manager.peer_session_is_current_sync(&peer.node_id, first));
    peer.online = true;
    peer.last_seen = 12;
    manager.add_peer(&peer).await;
    let second = manager.peer_session_generation_sync(&peer.node_id).unwrap();
    assert_ne!(first, second);
    peer.registration_seq = 1;
    peer.last_seen = 13;
    assert!(manager.add_peer(&peer).await.registration_changed);
    assert!(!manager.peer_session_is_current_sync(&peer.node_id, second));
}

#[tokio::test]
async fn heartbeat_refresh_shares_original_peer_read_lock_and_freezes_snapshot_time() {
    let (manager, mut peer) = setup().await;
    let manager = Arc::new(manager);
    let snapshot = manager.get_connection(&peer.node_id).await.unwrap();
    let reader = manager.connections.read().await;
    peer.last_seen = 11;
    assert!(
        manager
            .try_refresh_peer_last_seen(&peer)
            .unwrap()
            .last_seen_only
    );
    assert_eq!(reader.get(&peer.node_id).unwrap().last_seen.get(), 11);
    assert_eq!(snapshot.last_seen.get(), 10);
    let original = manager
        .try_capture_original_kernel_read_peer(
            &peer.node_id,
            peer.virtual_ip.parse().unwrap(),
            #[cfg(any(target_os = "linux", all(unix, test)))]
            None,
        )
        .unwrap();
    assert!(original.try_identity_at(&manager, Instant::now()).is_ok());
    // Shared reads cannot conceal a real writer or create current-owner credit.
    drop(reader);
    let writer = manager.connections.write().await;
    assert_eq!(
        original.try_identity_at(&manager, Instant::now()),
        Err(OverlayCreditOutcome::Contended(CreditLock::Connections))
    );
    drop(writer);
}
