async fn bind_test_udp_direct(
    bind: SocketAddr,
    peers: Arc<PeerManager>,
) -> Result<UdpDirectBinding> {
    Ok(UdpDirectBinding {
        udp: UdpTransport::bind(bind, peers).await?,
        route_signature: Vec::new(),
    })
}

#[tokio::test]
async fn queued_android_edges_are_absorbed_before_the_first_udp_bind() {
    let daemon = Daemon::new(Config::generate_default("https://ctrl.test", "net1").unwrap());
    let candidate_guard = daemon.candidate_refresh_lock.lock().await;
    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let (network_tx, network_rx) = broadcast::channel(32);
    let mut context = test_context(&daemon, shutdown_rx);
    let network_rx = Arc::new(Mutex::new(network_rx));
    context.android_network_change_rx = Some(network_rx.clone());
    for generation in [40, 1] {
        network_tx
            .send(AndroidNetworkChangeHint {
                kotlin_network_generation: generation,
                network_identity_hash: format!("authorized-{generation}"),
            })
            .unwrap();
    }
    let attempts = Arc::new(AtomicUsize::new(0));
    let binder_attempts = attempts.clone();
    let mut publication = daemon.udp_transport_publication.subscribe();
    let worker = tokio::spawn(run_udp_direct_task_with_binder(
        context,
        move |bind, peers| {
            binder_attempts.fetch_add(1, Ordering::SeqCst);
            bind_test_udp_direct(bind, peers)
        },
    ));
    timeout(Duration::from_secs(2), publication.changed())
        .await
        .unwrap()
        .unwrap();
    assert!(publication.borrow().is_some());
    // The original lifecycle receives shutdown while waiting on the real
    // refresh lock. Any leftover queued edge would win the biased select and
    // force another bind before shutdown is observed.
    shutdown_tx.send(true).unwrap();
    timeout(Duration::from_secs(2), worker)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert_eq!(attempts.load(Ordering::SeqCst), 1);
    assert_eq!(daemon.peers.current_network_generation_sync(), 0);
    assert!(matches!(
        network_rx.lock().await.try_recv(),
        Err(broadcast::error::TryRecvError::Empty)
    ));
    drop(candidate_guard);
}

#[tokio::test]
async fn network_edge_during_bind_discards_the_unpublished_socket() {
    let daemon = Daemon::new(Config::generate_default("https://ctrl.test", "net1").unwrap());
    let candidate_guard = daemon.candidate_refresh_lock.lock().await;
    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let (network_tx, network_rx) = broadcast::channel(32);
    let mut context = test_context(&daemon, shutdown_rx);
    context.android_network_change_rx = Some(Arc::new(Mutex::new(network_rx)));
    let attempts = Arc::new(AtomicUsize::new(0));
    let binder_attempts = attempts.clone();
    let mut publication = daemon.udp_transport_publication.subscribe();
    let worker = tokio::spawn(run_udp_direct_task_with_binder(
        context,
        move |bind, peers| {
            let first = binder_attempts.fetch_add(1, Ordering::SeqCst) == 0;
            let network_tx = network_tx.clone();
            async move {
                let binding = bind_test_udp_direct(bind, peers).await?;
                if first {
                    network_tx
                        .send(AndroidNetworkChangeHint {
                            kotlin_network_generation: 1,
                            network_identity_hash: "new-network-during-bind".into(),
                        })
                        .unwrap();
                }
                Ok(binding)
            }
        },
    ));
    timeout(Duration::from_secs(2), publication.changed())
        .await
        .unwrap()
        .unwrap();
    assert!(publication.borrow().is_some());
    assert_eq!(attempts.load(Ordering::SeqCst), 2);
    assert_eq!(
        daemon.peers.current_network_generation_sync(),
        0,
        "an unpublished discarded bind must not manufacture a live generation"
    );
    shutdown_tx.send(true).unwrap();
    timeout(Duration::from_secs(2), worker)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    drop(candidate_guard);
}

#[tokio::test]
async fn network_hint_cancels_startup_while_profile_commit_is_queued() {
    let daemon = Daemon::new(Config::generate_default("https://ctrl.test", "net1").unwrap());
    let binding = bind_test_udp_direct("127.0.0.1:0".parse().unwrap(), daemon.peers.clone())
        .await
        .unwrap();
    let profile_reader = daemon.nat_profile.read().await;
    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let (network_tx, network_rx) = broadcast::channel(8);
    let mut context = test_context(&daemon, shutdown_rx);
    context.android_network_change_rx = Some(Arc::new(Mutex::new(network_rx)));
    let observed = context.android_network_change_observed.clone();
    let mut binding = Some(binding);
    let mut worker = Box::pin(run_udp_direct_task_with_binder(context, move |_, _| {
        std::future::ready(
            binding
                .take()
                .ok_or_else(|| DaemonError::Network("no replacement needed".into())),
        )
    }));
    assert!(futures_util::poll!(worker.as_mut()).is_pending());
    assert!(
        daemon.nat_profile.try_read().is_err(),
        "startup must have queued its real profile writer behind the held read lock"
    );
    network_tx
        .send(AndroidNetworkChangeHint {
            kotlin_network_generation: 2,
            network_identity_hash: "new-network".into(),
        })
        .unwrap();
    assert!(futures_util::poll!(worker.as_mut()).is_pending());
    assert_eq!(
        observed.load(Ordering::Acquire),
        1,
        "network cancellation must run without waiting for the startup profile writer"
    );
    assert!(
        daemon.nat_profile.try_read().is_ok(),
        "cancelled startup must release the queued writer"
    );
    shutdown_tx.send(true).unwrap();
    timeout(Duration::from_secs(2), worker)
        .await
        .unwrap()
        .unwrap();
    assert!(daemon
        .udp_transport_publication
        .current_owner()
        .await
        .is_none());
    drop(profile_reader);
}

#[tokio::test(start_paused = true)]
async fn route_handover_during_startup_keeps_the_socket_bind_baseline() {
    let daemon = Daemon::new(Config::generate_default("https://ctrl.test", "net1").unwrap());
    let binding = UdpDirectBinding {
        udp: UdpTransport::bind("127.0.0.1:0".parse().unwrap(), daemon.peers.clone())
            .await
            .unwrap(),
        route_signature: vec!["physical:eth0:192.0.2.1".into()],
    };
    // The socket exists before discovery finishes. Network B becomes stable
    // during that work; monitoring must compare B with the original bind A.
    tokio::time::sleep(Duration::from_secs(3)).await;
    let new_route = vec!["physical:eth1:198.51.100.1".to_string()];
    let samples = Arc::new(AtomicUsize::new(0));
    let sample_count = samples.clone();
    let expected = new_route.clone();
    let changed = timeout(
        Duration::from_secs(4),
        wait_for_network_route_change_with_sampler(binding.route_signature, move || {
            sample_count.fetch_add(1, Ordering::SeqCst);
            std::future::ready(new_route.clone())
        }),
    )
    .await
    .expect("a handover during startup must not become the socket's new baseline");
    assert_eq!(changed, expected);
    assert_eq!(samples.load(Ordering::SeqCst), 2);
}

#[tokio::test(start_paused = true)]
async fn network_hint_skips_one_wait_but_later_bind_failures_keep_backoff() {
    let daemon = Daemon::new(Config::generate_default("https://ctrl.test", "net1").unwrap());
    // Hold startup before discovery: the lifecycle hint remains observable
    // and no observer, gateway or control request is needed by this fixture.
    let candidate_guard = daemon.candidate_refresh_lock.lock().await;
    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let (network_tx, network_rx) = broadcast::channel(8);
    let mut context = test_context(&daemon, shutdown_rx);
    context.android_network_change_rx = Some(Arc::new(Mutex::new(network_rx)));
    let mut publications = daemon.udp_transport_publication.subscribe();
    let (attempt_tx, mut attempt_rx) = mpsc::channel(4);
    let mut attempt = 0;
    let worker = tokio::spawn(run_udp_direct_task_with_binder(
        context,
        move |bind, peers| {
            let index = attempt;
            attempt += 1;
            let attempts = attempt_tx.clone();
            async move {
                attempts
                    .send((index, tokio::time::Instant::now()))
                    .await
                    .unwrap();
                if index == 0 {
                    bind_test_udp_direct(bind, peers).await
                } else {
                    Err(DaemonError::Network(
                        "injected post-handover bind failure".into(),
                    ))
                }
            }
        },
    ));
    timeout(Duration::from_secs(2), publications.changed())
        .await
        .unwrap()
        .unwrap();
    assert!(publications.borrow().is_some());
    assert_eq!(attempt_rx.recv().await.unwrap().0, 0);
    network_tx
        .send(AndroidNetworkChangeHint {
            kotlin_network_generation: 2,
            network_identity_hash: "handover".into(),
        })
        .unwrap();
    let first_failure = timeout(Duration::from_secs(2), attempt_rx.recv())
        .await
        .unwrap()
        .unwrap();
    let second_failure = timeout(Duration::from_secs(2), attempt_rx.recv())
        .await
        .unwrap()
        .unwrap();
    assert_eq!((first_failure.0, second_failure.0), (1, 2));
    assert!(
        second_failure.1.duration_since(first_failure.1) >= udp_direct_retry_initial_delay(),
        "a one-off immediate handover must not leave exponential backoff at zero"
    );
    shutdown_tx.send(true).unwrap();
    timeout(Duration::from_secs(2), worker)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    drop(candidate_guard);
}

#[tokio::test]
async fn gateway_candidate_commit_rechecks_identity_after_snapshot_contention() {
    for replace_transport in [false, true] {
        let daemon = Daemon::new(Config::generate_default("https://ctrl.test", "net1").unwrap());
        let binding = bind_test_udp_direct("127.0.0.1:0".parse().unwrap(), daemon.peers.clone())
            .await
            .unwrap();
        let lease = daemon.udp_transport_publication.publish(binding.udp).await;
        let generation = daemon.peers.current_network_generation_sync();
        daemon
            .publish_candidate_snapshot_with_readiness(
                vec!["192.0.2.1:4000".into()],
                HashMap::new(),
                vec!["original".into()],
                false,
            )
            .await;
        let writer = daemon.candidate_snapshot.write().await;
        let mut commit = Box::pin(commit_gateway_mapping_candidates(
            &daemon.udp_transport_publication,
            lease.owner(),
            &daemon.peers,
            generation,
            &daemon.candidate_refresh_lock,
            &daemon.candidate_snapshot,
            &daemon.local_candidates,
            &daemon.local_candidate_sources,
            vec!["198.51.100.1:5000".into()],
            HashMap::new(),
        ));
        assert!(futures_util::poll!(commit.as_mut()).is_pending());
        if replace_transport {
            let replacement =
                bind_test_udp_direct("127.0.0.1:0".parse().unwrap(), daemon.peers.clone())
                    .await
                    .unwrap();
            daemon
                .udp_transport_publication
                .publish(replacement.udp)
                .await;
        } else {
            daemon
                .peers
                .advance_network_generation("gateway commit handover")
                .await;
        }
        drop(writer);
        assert_eq!(
            commit.await,
            Err(if replace_transport {
                "udp_transport_replaced"
            } else {
                "network_generation_changed"
            })
        );
        let snapshot = daemon.candidate_snapshot.read().await.clone().unwrap();
        assert_eq!(snapshot.candidates, ["192.0.2.1:4000"]);
        assert_eq!(snapshot.version, 1);
        assert!(!snapshot.initial_gather_complete);
        assert!(daemon.local_candidates.read().await.is_empty());
        daemon.udp_transport_publication.clear_current().await;
    }
}

#[tokio::test(start_paused = true)]
async fn gateway_commit_is_bounded_and_does_not_refresh_retained_stun_age() {
    let daemon = Daemon::new(Config::generate_default("https://ctrl.test", "net1").unwrap());
    let binding = bind_test_udp_direct("127.0.0.1:0".parse().unwrap(), daemon.peers.clone())
        .await
        .unwrap();
    let lease = daemon.udp_transport_publication.publish(binding.udp).await;
    let generation = daemon.peers.current_network_generation_sync();
    daemon
        .publish_candidate_snapshot_with_readiness(
            vec!["192.0.2.1:4000".into()],
            HashMap::new(),
            vec!["original".into()],
            false,
        )
        .await;
    let before = daemon.candidate_snapshot.read().await.clone().unwrap();
    let sources = HashMap::from([("198.51.100.1:5000".into(), "port_mapping".into())]);
    let writer = daemon.local_candidate_sources.write().await;
    let mut commit = Box::pin(commit_gateway_mapping_candidates(
        &daemon.udp_transport_publication,
        lease.owner(),
        &daemon.peers,
        generation,
        &daemon.candidate_refresh_lock,
        &daemon.candidate_snapshot,
        &daemon.local_candidates,
        &daemon.local_candidate_sources,
        vec!["198.51.100.1:5000".into()],
        sources.clone(),
    ));
    assert!(futures_util::poll!(commit.as_mut()).is_pending());
    tokio::time::advance(Duration::from_millis(101)).await;
    assert_eq!(commit.await, Err("candidate_commit_contended"));
    drop(writer);
    assert_eq!(
        daemon
            .candidate_snapshot
            .read()
            .await
            .as_ref()
            .unwrap()
            .version,
        before.version
    );
    assert!(daemon.local_candidates.read().await.is_empty());
    assert_eq!(
        commit_gateway_mapping_candidates(
            &daemon.udp_transport_publication,
            lease.owner(),
            &daemon.peers,
            generation,
            &daemon.candidate_refresh_lock,
            &daemon.candidate_snapshot,
            &daemon.local_candidates,
            &daemon.local_candidate_sources,
            vec!["198.51.100.1:5000".into()],
            sources,
        )
        .await,
        Ok(())
    );
    let after = daemon.candidate_snapshot.read().await.clone().unwrap();
    assert_eq!(after.version, before.version + 1);
    assert_eq!(after.gathered_at, before.gathered_at);
    assert!(!after.initial_gather_complete);
    assert_eq!(after.network_identity, before.network_identity);
    assert_eq!(after.candidates, *daemon.local_candidates.read().await);
    assert_eq!(
        after.candidate_sources,
        *daemon.local_candidate_sources.read().await
    );
    daemon.udp_transport_publication.clear_current().await;
}

#[tokio::test(start_paused = true)]
async fn network_hint_interrupts_bind_backoff_and_preserves_later_fault_delay() {
    let daemon = Daemon::new(Config::generate_default("https://ctrl.test", "net1").unwrap());
    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let (network_tx, network_rx) = broadcast::channel(8);
    let mut context = test_context(&daemon, shutdown_rx);
    context.android_network_change_rx = Some(Arc::new(Mutex::new(network_rx)));
    let observed = context.android_network_change_observed.clone();
    let attempts = Arc::new(AtomicUsize::new(0));
    let bind_attempts = attempts.clone();
    let mut worker = Box::pin(run_udp_direct_task_with_binder(context, move |_, _| {
        bind_attempts.fetch_add(1, Ordering::SeqCst);
        std::future::ready(Err(DaemonError::Network("network unavailable".into())))
    }));

    assert!(futures_util::poll!(worker.as_mut()).is_pending());
    for delay_ms in [10, 20, 40, 80] {
        tokio::time::advance(Duration::from_millis(delay_ms)).await;
        assert!(futures_util::poll!(worker.as_mut()).is_pending());
    }
    assert_eq!(attempts.load(Ordering::SeqCst), 5);
    let handover_at = tokio::time::Instant::now();
    for generation in [40, 1] {
        network_tx
            .send(AndroidNetworkChangeHint {
                kotlin_network_generation: generation,
                network_identity_hash: format!("new-network-{generation}"),
            })
            .unwrap();
    }
    assert!(futures_util::poll!(worker.as_mut()).is_pending());
    assert_eq!(
        attempts.load(Ordering::SeqCst),
        6,
        "a physical network becoming available must wake the original bind backoff"
    );
    assert_eq!(tokio::time::Instant::now(), handover_at);
    assert_eq!(observed.load(Ordering::Acquire), 1);
    assert!(futures_util::poll!(worker.as_mut()).is_pending());
    assert_eq!(attempts.load(Ordering::SeqCst), 6);
    tokio::time::advance(udp_direct_retry_initial_delay()).await;
    assert!(futures_util::poll!(worker.as_mut()).is_pending());
    assert_eq!(attempts.load(Ordering::SeqCst), 7);
    shutdown_tx.send(true).unwrap();
    worker.await.unwrap();
    assert!(daemon
        .udp_transport_publication
        .current_owner()
        .await
        .is_none());
}
