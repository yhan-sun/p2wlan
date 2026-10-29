use super::*;
use crate::relay_runtime::test_support::test_supervisor;

async fn select_for_test(
    supervisor: &RelaySupervisor,
    cooldowns: &HashMap<String, Instant>,
) -> RelayReadSelectionOutcome<OriginalRelayDelivery> {
    select_relay_with_cooldowns_for_read::<OriginalRelayDelivery>(
        &supervisor.relay_candidates,
        &supervisor.preferred_regions,
        supervisor.selection_timeout,
        &supervisor.node_id,
        supervisor.peers.clone(),
        None,
        None,
        true,
        None,
        cooldowns,
    )
    .await
}

#[tokio::test]
async fn consumed_connection_edge_releases_other_relay_cooldowns_for_selection() {
    let primary = p2pnet_relay::RelayServer::start_random().await.unwrap();
    let standby = p2pnet_relay::RelayServer::start_random().await.unwrap();
    let mut supervisor = test_supervisor(None);
    supervisor.relay_candidates = vec![
        RelayCandidateConfig::legacy(format!("primary@{}", primary.addr)),
        RelayCandidateConfig::legacy(format!("standby@{}", standby.addr)),
    ];
    supervisor.preferred_regions = vec!["primary".into()];
    let mut cooldowns = HashMap::new();
    assert!(record_connection_cooldown(
        &mut cooldowns,
        &primary.addr.to_string(),
        2,
        &Ok(())
    ));
    let before = select_for_test(&supervisor, &cooldowns).await;
    assert_eq!(
        before.transport.as_ref().unwrap().endpoint(),
        standby.addr.to_string()
    );
    assert_eq!(
        before.diagnostics.candidates[0].error_code.as_deref(),
        Some("cooling_down")
    );
    drop(before);

    // The connection owner has already consumed the Android/desktop edge.
    // A subsequent retry therefore cannot rely on receiving that hint again.
    let changed = Err(DaemonError::RelayRouteChanged {
        endpoint: standby.addr.to_string(),
        signature: vec!["new-network".into()],
    });
    assert!(!record_connection_cooldown(
        &mut cooldowns,
        &standby.addr.to_string(),
        2,
        &changed
    ));
    let after = select_for_test(&supervisor, &cooldowns).await;
    assert_eq!(
        after.transport.as_ref().unwrap().endpoint(),
        primary.addr.to_string()
    );
    assert!(after
        .diagnostics
        .candidates
        .iter()
        .all(|candidate| candidate.cooldown_remaining_ms.is_none()));
    drop(after);
    primary.shutdown().await;
    standby.shutdown().await;
}

#[tokio::test(start_paused = true)]
async fn queued_android_edge_clears_cooldowns_only_after_auth_deadline() {
    let mut supervisor = test_supervisor(None);
    let (sender, receiver) = tokio::sync::broadcast::channel(8);
    let receiver = Arc::new(tokio::sync::Mutex::new(receiver));
    supervisor.android_network_change_rx = Some(receiver.clone());
    let mut cooldowns = HashMap::new();
    cooldowns.insert("primary".into(), Instant::now() + Duration::from_secs(10));
    cooldowns.insert("standby".into(), Instant::now() + Duration::from_secs(10));
    // This edge arrives before a selection reports permanent auth failure.
    sender
        .send(crate::AndroidNetworkChangeHint {
            kotlin_network_generation: 1,
            network_identity_hash: "new-network".into(),
        })
        .unwrap();
    let mut routes = connection::RelayRouteMonitor::new(vec!["old-route".into()]);
    let mut retry = Box::pin(retry::wait_for_retry(
        Duration::from_secs(30),
        Some(receiver),
        &mut routes,
        false,
    ));
    assert!(futures_util::poll!(retry.as_mut()).is_pending());
    tokio::time::advance(Duration::from_secs(29)).await;
    assert!(futures_util::poll!(retry.as_mut()).is_pending());
    assert_eq!(cooldowns.len(), 2);
    tokio::time::advance(Duration::from_secs(1)).await;
    assert!(!retry.await);
    assert!(
        supervisor
            .absorb_network_change_before_attempt(&mut cooldowns)
            .await
    );
    assert!(cooldowns.is_empty());
    assert!(
        !supervisor
            .absorb_network_change_before_attempt(&mut cooldowns)
            .await
    );
}

#[tokio::test(start_paused = true)]
async fn successful_relay_adopts_pending_route_before_recording_later_failure() {
    let old_route = vec!["old-route".to_string()];
    let new_route = vec!["new-route".to_string()];
    let mut routes = connection::RelayRouteMonitor::new(old_route);
    let mut cooldowns = HashMap::new();
    record_connection_cooldown(&mut cooldowns, "old-relay", 2, &Ok(()));

    // A short failed attempt recorded just one observation of the new route.
    let mut pending =
        Box::pin(routes.wait_for_change_with(|| std::future::ready(new_route.clone())));
    assert!(futures_util::poll!(pending.as_mut()).is_pending());
    drop(pending);
    adopt_connected_relay_route(&mut routes, &mut cooldowns, &new_route);
    assert!(
        cooldowns.is_empty(),
        "successful handover must release old-network failures"
    );

    // The successful connection may live for hours before this real failure.
    // Its later retry must not complete the old handover and erase this entry.
    record_connection_cooldown(&mut cooldowns, "new-relay", 2, &Ok(()));
    assert!(tokio::time::timeout(
        Duration::from_secs(3),
        routes.wait_for_change_with(|| std::future::ready(new_route.clone())),
    )
    .await
    .is_err());
    adopt_connected_relay_route(&mut routes, &mut cooldowns, &new_route);
    assert!(
        cooldowns.contains_key("new-relay"),
        "same-network success preserves failure cooldowns"
    );
}

#[tokio::test(start_paused = true)]
async fn same_network_or_unknown_success_drops_pending_samples_without_clearing_cooldowns() {
    for known_route in [false, true] {
        let baseline = vec!["current-route".to_string()];
        let alternate = vec!["unconfirmed-route".to_string()];
        let mut routes = connection::RelayRouteMonitor::new(baseline.clone());
        let mut cooldowns = HashMap::new();
        record_connection_cooldown(&mut cooldowns, "current-relay", 2, &Ok(()));
        let mut pending =
            Box::pin(routes.wait_for_change_with(|| std::future::ready(alternate.clone())));
        assert!(futures_util::poll!(pending.as_mut()).is_pending());
        drop(pending);
        adopt_connected_relay_route(
            &mut routes,
            &mut cooldowns,
            if known_route { &baseline } else { &[] },
        );
        assert!(cooldowns.contains_key("current-relay"));
        let mut changed =
            Box::pin(routes.wait_for_change_with(|| std::future::ready(alternate.clone())));
        assert!(futures_util::poll!(changed.as_mut()).is_pending());
        tokio::time::advance(RELAY_ROUTE_POLL_INTERVAL).await;
        assert!(
            futures_util::poll!(changed.as_mut()).is_pending(),
            "success must discard the earlier unconfirmed observation"
        );
        tokio::time::advance(RELAY_ROUTE_POLL_INTERVAL).await;
        assert_eq!(changed.await, alternate);
    }
}

#[tokio::test(start_paused = true)]
async fn renewal_route_is_adopted_before_new_runtime_failure_cooldown() {
    let initial = vec!["initial-route".to_string()];
    let renewed = vec!["renewed-route".to_string()];
    let mut routes = connection::RelayRouteMonitor::new(initial.clone());
    let mut cooldowns = HashMap::new();
    adopt_connected_relay_route(&mut routes, &mut cooldowns, &initial);
    record_connection_cooldown(&mut cooldowns, "old-alternative", 2, &Ok(()));
    // The live owner can publish a renewal on a new route without returning
    // to selection. The final committed transport supplies this baseline.
    adopt_connected_relay_route(&mut routes, &mut cooldowns, &renewed);
    assert!(cooldowns.is_empty());
    record_connection_cooldown(&mut cooldowns, "renewed-relay", 2, &Ok(()));
    assert!(tokio::time::timeout(
        Duration::from_secs(3),
        routes.wait_for_change_with(|| std::future::ready(renewed.clone())),
    )
    .await
    .is_err());
    assert!(cooldowns.contains_key("renewed-relay"));
}
