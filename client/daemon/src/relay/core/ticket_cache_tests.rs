use super::*;

fn cache() -> RelayTicketCache {
    RelayTicketCache::new(crate::control::ControlClient::disabled_for_test())
}
fn key(n: usize) -> RelayTicketKey {
    RelayTicketKey::checked(&format!("audience-{n}"), "fixture-region").unwrap()
}

#[tokio::test]
async fn active_refresh_keys_are_bounded_and_same_key_keeps_its_original_lock() {
    let cache = cache();
    let mut owners = Vec::new();
    for n in 0..MAX_RELAY_TICKET_KEYS {
        owners.push(cache.refresh_lock_for(&key(n)).await.unwrap());
    }
    assert!(Arc::ptr_eq(
        &owners[0],
        &cache.refresh_lock_for(&key(0)).await.unwrap()
    ));
    assert!(matches!(
        cache.refresh_lock_for(&key(MAX_RELAY_TICKET_KEYS)).await,
        Err(DaemonError::ResourceLimit {
            resource: "relay_ticket_refresh_keys",
            limit: MAX_RELAY_TICKET_KEYS
        })
    ));
    assert_eq!(
        cache.refresh_locks.lock().await.len(),
        MAX_RELAY_TICKET_KEYS
    );
    owners.pop();
    assert!(cache
        .refresh_lock_for(&key(MAX_RELAY_TICKET_KEYS))
        .await
        .is_ok());
    assert_eq!(
        cache.refresh_locks.lock().await.len(),
        MAX_RELAY_TICKET_KEYS
    );
}

#[tokio::test]
async fn cancelled_and_rotating_idle_refreshes_reclaim_without_new_background_tasks() {
    let cache = cache();
    let original = cache.refresh_lock_for(&key(0)).await.unwrap();
    let held = original.clone().lock_owned().await;
    let mut cancelled = Box::pin(original.lock_owned());
    assert!(futures_util::poll!(cancelled.as_mut()).is_pending());
    drop(cancelled);
    drop(held);
    assert_eq!(
        Arc::strong_count(cache.refresh_locks.lock().await.get(&key(0)).unwrap()),
        1
    );
    for n in 0..(MAX_RELAY_TICKET_KEYS * 3) {
        let original = cache.refresh_lock_for(&key(n)).await.unwrap();
        assert!(Arc::ptr_eq(
            &original,
            &cache.refresh_lock_for(&key(n)).await.unwrap()
        ));
        drop(original);
        assert!(cache.refresh_locks.lock().await.len() <= MAX_RELAY_TICKET_KEYS);
    }
}

#[tokio::test]
async fn queued_waiter_prevents_replacing_the_same_refresh_owner() {
    let cache = cache();
    let original = cache.refresh_lock_for(&key(0)).await.unwrap();
    let weak = Arc::downgrade(&original);
    let held = original.clone().lock_owned().await;
    let mut waiter = Box::pin(original.lock_owned());
    assert!(futures_util::poll!(waiter.as_mut()).is_pending());
    drop(held);
    // Only the actual queued future and map now retain this lock. Key churn
    // must not install a second owner before that future is polled again.
    for n in 1..=MAX_RELAY_TICKET_KEYS {
        drop(cache.refresh_lock_for(&key(n)).await.unwrap());
    }
    assert!(Arc::ptr_eq(
        &weak.upgrade().unwrap(),
        &cache.refresh_lock_for(&key(0)).await.unwrap()
    ));
    let _acquired = waiter.await;
}

#[tokio::test]
async fn ticket_entry_eviction_is_bounded_and_keeps_already_returned_credentials() {
    let cache = cache();
    let expiry = now_unix() + 3600;
    for n in 0..MAX_RELAY_TICKET_KEYS {
        cache
            .cache_ticket(key(n), "fixture-ticket", expiry + n as i64)
            .await
            .unwrap();
    }
    let retained = cache.cached_ticket(&key(0)).await.unwrap();
    cache
        .cache_ticket(
            key(MAX_RELAY_TICKET_KEYS),
            "new-fixture-ticket",
            expiry + 999,
        )
        .await
        .unwrap();
    assert_eq!(retained, ("fixture-ticket".to_owned(), expiry));
    assert!(cache.cached_ticket(&key(0)).await.is_none());
    assert_eq!(cache.entries.lock().await.len(), MAX_RELAY_TICKET_KEYS);
}

#[tokio::test]
async fn expired_entries_and_oversize_key_or_ticket_do_not_grow_cache() {
    let cache = cache();
    cache
        .cache_ticket(key(0), "expired-fixture", 1)
        .await
        .unwrap();
    cache
        .cache_ticket(key(1), "fixture-ticket", now_unix() + 3600)
        .await
        .unwrap();
    assert_eq!(cache.entries.lock().await.len(), 1);
    assert!(matches!(
        RelayTicketKey::checked(&"a".repeat(MAX_RELAY_TICKET_AUDIENCE_BYTES + 1), "r"),
        Err(DaemonError::ResourceLimit { .. })
    ));
    assert!(matches!(
        RelayTicketKey::checked("a", &"r".repeat(MAX_RELAY_TICKET_REGION_BYTES + 1)),
        Err(DaemonError::ResourceLimit { .. })
    ));
    assert!(matches!(
        cache
            .cache_ticket(
                key(2),
                &"t".repeat(MAX_RELAY_TICKET_BYTES + 1),
                now_unix() + 3600
            )
            .await,
        Err(DaemonError::ResourceLimit {
            resource: "relay_ticket_bytes",
            ..
        })
    ));
    assert_eq!(cache.entries.lock().await.len(), 1);
}

#[tokio::test]
async fn candidate_retains_same_ticket_expiry_after_intervening_cache_eviction() {
    let cache = Arc::new(cache());
    let expiry = now_unix() + 3600;
    cache
        .cache_ticket(key(0), "fixture-ticket", expiry)
        .await
        .unwrap();
    let candidate = RelayCandidate {
        index: 0,
        region: "fixture-region".into(),
        audience: Some("audience-0".into()),
        endpoint: "tcp://127.0.0.1:41235".into(),
        preference_rank: 0,
    };
    let returned = relay_ticket_for_candidate(&candidate, Some(cache.clone()), None)
        .await
        .ok()
        .flatten()
        .expect("cached candidate retains its original ticket and expiry");
    for n in 1..=MAX_RELAY_TICKET_KEYS {
        cache
            .cache_ticket(key(n), "other-fixture-ticket", expiry + n as i64)
            .await
            .unwrap();
    }
    assert!(cache.cached_ticket(&key(0)).await.is_none());
    assert_eq!(returned, ("fixture-ticket".to_owned(), expiry));
}
