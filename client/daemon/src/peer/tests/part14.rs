#[tokio::test]
async fn relay_backed_peer_keeps_flat_retry_cadence_after_consecutive_failures() {
    // Regression (dual-CGNAT black hole, 2026-08-16): a relay-backed peer in
    // the wide scatter stage grew an exponential retry backoff across
    // consecutive no-ACK windows, pacing the background scan at the 7-8s
    // exponential cap.  When the transient UDP black hole cleared, the first
    // probe that matched was the next retry tick — the backoff only delayed
    // the eventual hit.  `retry_due_relay_flat` must keep the cadence flat
    // (one base interval, no doubling) once the relay carries the data plane.
    let config = test_config();
    let manager = PeerManager::new(config);
    let endpoint: SocketAddr = "8.8.8.8:41834".parse().unwrap();

    manager.add_peer(&test_peer("peer1", endpoint)).await;
    manager.set_relay("peer1", "127.0.0.1:9000").await;
    assert!(manager.has_relay_safety_net("peer1").await);

    manager
        .record_direct_failure_with_code("peer1", REASON_DIRECT_PROBE_FAILED, "no ACK")
        .await;
    manager
        .record_direct_failure_with_code("peer1", REASON_DIRECT_PROBE_FAILED, "still no ACK")
        .await;

    let conn = manager.get_connection("peer1").await.unwrap();
    assert_eq!(conn.direct_health.consecutive_failures, 2);

    let base = Duration::from_secs(1);

    // Immediately after the second failure the flat cadence is not yet due
    // (the base interval has not elapsed), matching the non-flat behavior
    // for a just-failed peer.
    assert!(!conn.direct_retry_due_relay_flat(base));

    // The non-flat cadence would now hold the peer out for 2s (base * 2^1);
    // the flat cadence is due as soon as the single base interval elapses.
    tokio::time::sleep(base + Duration::from_millis(120)).await;
    let conn = manager.get_connection("peer1").await.unwrap();
    assert!(
        conn.direct_retry_due_relay_flat(base),
        "relay-backed retry must be due after exactly one base interval, not a doubled backoff"
    );
    assert!(
        !conn.direct_retry_due(base),
        "the classic exponential backoff must remain in effect for non-relay peers"
    );
    assert_eq!(conn.direct_retry_after(base), Duration::from_secs(2));
}

#[tokio::test]
async fn relay_backed_scatter_peer_targets_due_at_flat_interval() {
    // End-to-end scheduler check: a relay-backed peer whose episodes keep
    // failing must still yield recovery targets on the flat interval instead
    // of being suppressed by the exponential retry_after.
    let config = test_config();
    let manager = PeerManager::new(config);
    let endpoint: SocketAddr = "8.8.8.8:41835".parse().unwrap();

    manager.add_peer(&test_peer("peer1", endpoint)).await;
    manager.set_relay("peer1", "127.0.0.1:9000").await;

    manager
        .record_direct_failure_with_code("peer1", REASON_DIRECT_PROBE_FAILED, "no ACK")
        .await;
    manager
        .record_direct_failure_with_code("peer1", REASON_DIRECT_PROBE_FAILED, "still no ACK")
        .await;

    // Immediately after the second failure no target is due.
    let none_due = manager
        .direct_probe_targets_due(Duration::from_secs(1))
        .await;
    assert!(none_due.is_empty());

    tokio::time::sleep(Duration::from_secs(2)).await;
    let due = manager
        .direct_probe_targets_due(Duration::from_secs(1))
        .await;
    assert_eq!(due.len(), 1);
    assert_eq!(due[0].peer_id, "peer1");
    assert!(
        due[0].candidates.contains(&endpoint),
        "relay-backed peer must remain on the recovery scheduler at the flat cadence"
    );
}

#[tokio::test(flavor = "current_thread")]
async fn direct_probe_targets_due_completes_with_writer_queued_behind_snapshot_reader() {
    // Regression: `direct_probe_targets_due` held one `connections` read
    // guard and called `has_relay_safety_net().await`, which tried to acquire
    // the same writer-preferring RwLock for reading again.  The queue below is
    // deliberately ordered as outer reader -> writer: the old nested reader
    // then queued behind the writer and deadlocked with it permanently.
    let manager = Arc::new(PeerManager::new(test_config()));
    let endpoint: SocketAddr = "8.8.8.8:41836".parse().unwrap();

    manager.add_peer(&test_peer("peer1", endpoint)).await;
    manager.set_relay("peer1", "127.0.0.1:9000").await;

    // Stop the planner immediately before its retry-eligibility connection
    // snapshot.  On the single-thread runtime, one yield lets it run through
    // the uncontended prechecks and queue on this recovery-epoch writer.
    let recovery_gate = manager.recovery_epochs.write().await;
    let planner_manager = Arc::clone(&manager);
    let mut planner = tokio::spawn(async move {
        planner_manager
            .direct_probe_targets_due(Duration::ZERO)
            .await
    });
    tokio::task::yield_now().await;

    // Hold the connection map while the planner is released from the epoch
    // gate.  The epoch sentinel can acquire only after admission has released
    // its writer; by then the planner has queued its connection-map reader.
    let connection_gate = manager.connections.write().await;
    let (epoch_passed_tx, epoch_passed_rx) = tokio::sync::oneshot::channel();
    let epoch_sentinel_manager = Arc::clone(&manager);
    let epoch_sentinel = tokio::spawn(async move {
        let _guard = epoch_sentinel_manager.recovery_epochs.write().await;
        let _ = epoch_passed_tx.send(());
    });
    drop(recovery_gate);
    epoch_passed_rx
        .await
        .expect("recovery admission should release the epoch lock");
    epoch_sentinel.await.unwrap();

    // Queue a writer behind the planner's reader before allowing that reader
    // to acquire the map.  Sending `writer_queued` and polling `write().await`
    // happen in the same task poll, so receipt proves the waiter was enqueued.
    let (writer_queued_tx, writer_queued_rx) = tokio::sync::oneshot::channel();
    let writer_manager = Arc::clone(&manager);
    let mut writer = tokio::spawn(async move {
        let _ = writer_queued_tx.send(());
        let connections = writer_manager.connections.write().await;
        assert!(connections.contains_key("peer1"));
    });
    writer_queued_rx
        .await
        .expect("connection writer should reach the lock wait");
    drop(connection_gate);

    let targets = match tokio::time::timeout(Duration::from_secs(1), &mut planner).await {
        Ok(result) => result.expect("probe planner task should not panic"),
        Err(_) => {
            planner.abort();
            writer.abort();
            panic!("direct_probe_targets_due deadlocked behind the queued connection writer");
        }
    };
    tokio::time::timeout(Duration::from_secs(1), &mut writer)
        .await
        .expect("queued connection writer should complete")
        .expect("connection writer task should not panic");

    assert_eq!(targets.len(), 1);
    assert_eq!(targets[0].peer_id, "peer1");
    assert!(targets[0].candidates.contains(&endpoint));
}

#[tokio::test]
async fn preferred_fast_candidates_merge_advertised_neighborhood_without_predicted_window() {
    // Regression (dual-CGNAT black hole, 2026-08-16): with no fresh
    // prediction window, the stable side's fast prefix carried only the
    // exact advertised/learned ports.  After the black hole cleared, the
    // first matching probe was a NEIGHBOR of an advertised base, so the
    // bounded fast prefix must merge the ±8 neighborhood of every advertised
    // authoritative public endpoint so the first post-hole probe can hit.
    let config = test_config();
    let manager = PeerManager::new(config);
    let advertised: SocketAddr = "8.8.8.8:41000".parse().unwrap();

    manager.add_peer(&test_peer("peer1", advertised)).await;

    // `add_candidates` installs explicitly signaled (authoritative) sources.
    manager
        .add_candidates(
            "peer1",
            &[advertised.to_string(), "8.8.8.8:43012".to_string()],
        )
        .await;
    manager
        .add_candidates_with_sources(
            "peer1",
            &["8.8.8.8:43012".to_string()],
            &[("8.8.8.8:43012".to_string(), "learned".to_string())]
                .into_iter()
                .collect(),
        )
        .await;

    let conn = manager.get_connection("peer1").await.unwrap();
    let candidates = conn.preferred_fast_candidates(&[
        advertised,
        "8.8.8.8:43012".parse().unwrap(),
    ]);

    assert!(
        !conn.has_explicit_predicted_window(),
        "test precondition: no fresh prediction window"
    );
    assert!(candidates.contains(&"8.8.8.8:43012".parse().unwrap()));
    // ±8 neighborhood of the advertised base must be merged in.
    for delta in 1..=8_i32 {
        let plus = u16::try_from(u32::from(advertised.port()) + delta as u32).unwrap();
        let minus = u16::try_from(u32::from(advertised.port()) - delta as u32).unwrap();
        assert!(
            candidates.contains(&SocketAddr::new(advertised.ip(), plus)),
            "advertised +{delta} must be in the fast prefix without a prediction window"
        );
        assert!(
            candidates.contains(&SocketAddr::new(advertised.ip(), minus)),
            "advertised -{delta} must be in the fast prefix without a prediction window"
        );
    }
}

#[tokio::test]
async fn advertised_neighborhood_merge_skipped_when_predicted_window_exists() {
    // When a fresh prediction window IS advertised, the predicted/learned
    // sources own the fast prefix and the advertised ±8 merge must not
    // pollute the ordering with neighborhood noise.
    let config = test_config();
    let manager = PeerManager::new(config);
    let advertised: SocketAddr = "8.8.8.8:42000".parse().unwrap();
    let predicted: SocketAddr = "8.8.8.8:42019".parse().unwrap();

    manager.add_peer(&test_peer("peer1", advertised)).await;
    manager
        .add_candidates(
            "peer1",
            &[advertised.to_string(), "8.8.8.8:42019".to_string()],
        )
        .await;
    manager
        .add_candidates_with_sources(
            "peer1",
            &["8.8.8.8:42019".to_string()],
            &[("8.8.8.8:42019".to_string(), "predicted".to_string())]
                .into_iter()
                .collect(),
        )
        .await;

    let conn = manager.get_connection("peer1").await.unwrap();
    assert!(conn.has_explicit_predicted_window());
    let candidates = conn.preferred_fast_candidates(&[
        advertised,
        predicted,
        "8.8.8.8:42002".parse().unwrap(),
    ]);

    // The predicted source leads; the neighborhood merge is skipped.
    assert_eq!(candidates.first(), Some(&predicted));
    assert!(!candidates.contains(&"8.8.8.8:42002".parse().unwrap()));
}

#[tokio::test]
async fn host_candidate_is_not_starved_by_predicted_fast_window() {
    let config = test_config();
    let manager = PeerManager::new(config);
    let host: SocketAddr = "192.168.31.20:51820".parse().unwrap();
    let predicted = (40_000..40_040)
        .map(|port| format!("203.0.113.10:{port}"))
        .collect::<Vec<_>>();
    // Put the public prediction first in the input deliberately.  The fast
    // selector, not the caller's incidental ordering, must put a directly
    // connected LAN endpoint ahead of the UU/public candidates.
    let mut candidates = predicted.clone();
    candidates.push(host.to_string());
    let sources = candidates
        .iter()
        .cloned()
        .map(|endpoint| {
            let source = if endpoint == host.to_string() {
                "host"
            } else {
                "predicted"
            };
            (endpoint, source.to_string())
        })
        .collect::<HashMap<_, _>>();

    manager.add_peer(&test_peer("peer1", host)).await;
    manager
        .set_local_interface_networks(vec![p2pnet_nat::LocalNetwork::new(
            "192.168.31.10".parse().unwrap(),
            24,
        )])
        .await;
    manager
        .add_candidates_with_sources("peer1", &candidates, &sources)
        .await;

    let conn = manager.get_connection("peer1").await.unwrap();
    let parsed = candidates
        .iter()
        .map(|candidate| candidate.parse::<SocketAddr>().unwrap())
        .collect::<Vec<_>>();
    let preferred = conn.preferred_fast_candidates(&parsed);

    assert!(
        preferred.contains(&host),
        "a physical Host candidate must have a bounded fast-lane slot even when predictions are present"
    );
    assert_eq!(
        preferred.first(),
        Some(&host),
        "an on-link candidate must lead the latency-sensitive prefix"
    );
}

#[test]
fn destination_route_relevance_prefers_on_link_host_over_global_and_overlay_hosts() {
    let mut conn = PeerConnection::new("peer-route", "10.20.0.2");
    conn.set_local_interface_networks(vec![p2pnet_nat::LocalNetwork::new(
        "10.23.176.87".parse().unwrap(),
        24,
    )]);

    let candidates = [
        ("20.0.3.148:58079", CandidatePairSource::Host),
        ("100.127.99.28:58079", CandidatePairSource::Host),
        ("10.23.176.16:58079", CandidatePairSource::Host),
    ];
    conn.candidates = candidates
        .iter()
        .map(|(endpoint, _)| (*endpoint).to_string())
        .collect();
    conn.candidate_sources = candidates
        .iter()
        .map(|(endpoint, source)| ((*endpoint).to_string(), *source))
        .collect();
    for (endpoint, source) in candidates {
        conn.ensure_candidate_pair_with_source(endpoint.parse().unwrap(), 0, source);
    }

    let (ordered, _) = conn.candidate_probe_endpoints(
        0,
        &TraversalHistory::default(),
        None,
        ProbeTargetMode::Synchronized,
        None,
    );

    assert_eq!(ordered.first().copied(), Some("10.23.176.16:58079".parse().unwrap()));
    assert!(ordered.contains(&"20.0.3.148:58079".parse().unwrap()));
    assert!(ordered.contains(&"100.127.99.28:58079".parse().unwrap()));
}
