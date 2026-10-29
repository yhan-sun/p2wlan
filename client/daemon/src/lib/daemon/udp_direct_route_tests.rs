fn test_route(name: &str) -> Vec<String> {
    vec![format!("physical:{name}:192.0.2.1")]
}

async fn next_udp_publication(
    updates: &mut watch::Receiver<Option<UdpTransport>>,
    previous: Option<u64>,
) -> UdpTransport {
    timeout(Duration::from_secs(3), async {
        loop {
            if let Some(udp) = updates.borrow_and_update().clone() {
                if Some(udp.transport_instance_id()) != previous {
                    return udp;
                }
            }
            updates.changed().await.unwrap();
        }
    })
    .await
    .expect("the supervisor must publish its replacement socket")
}

#[test]
fn empty_route_baseline_requires_two_samples_and_return_to_old_route_is_a_change() {
    let mut confirmation = RouteChangeConfirmation::new(Vec::new());
    assert_eq!(confirmation.observe(test_route("en0")), None);
    assert_eq!(confirmation.observe(Vec::new()), None);
    assert_eq!(confirmation.observe(test_route("en0")), None);
    assert_eq!(
        confirmation.observe(test_route("en0")),
        Some(test_route("en0"))
    );
    let mut replacement = RouteChangeConfirmation::new(test_route("en1"));
    assert_eq!(replacement.observe(test_route("en0")), None);
    assert_eq!(
        replacement.observe(test_route("en0")),
        Some(test_route("en0"))
    );
}

#[tokio::test]
async fn empty_route_recovery_rebinds_and_reresolves_initially_empty_stun_sources() {
    let daemon = Daemon::new(Config::generate_default("https://ctrl.test", "net1").unwrap());
    // Keep the existing candidate worker from reaching its own DNS recovery.
    // Only the route-triggered supervisor rebind can refill the shared list.
    let candidate_guard = daemon.candidate_refresh_lock.lock().await;
    let observer = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let mut context = test_context(&daemon, shutdown_rx);
    context.stun_server_specs = vec![format!(
        "localhost:{}",
        observer.local_addr().unwrap().port()
    )];
    context.stun_timeout = Duration::from_secs(1);
    assert!(context.stun_servers.is_empty());
    let route = Arc::new(std::sync::Mutex::new(Vec::new()));
    let bind_route = route.clone();
    let sampled_route = route.clone();
    let attempts = Arc::new(AtomicUsize::new(0));
    let bind_attempts = attempts.clone();
    let mut updates = daemon.udp_transport_publication.subscribe();
    let worker = tokio::spawn(run_udp_direct_task_with_binder_and_route_sampler(
        context,
        move |bind, peers| {
            bind_attempts.fetch_add(1, Ordering::SeqCst);
            let signature = bind_route.lock().unwrap().clone();
            async move {
                Ok(UdpDirectBinding {
                    udp: UdpTransport::bind(bind, peers).await?,
                    route_signature: signature,
                })
            }
        },
        move || std::future::ready(sampled_route.lock().unwrap().clone()),
    ));
    let old = next_udp_publication(&mut updates, None).await;
    assert!(daemon.runtime_stun_servers.read().await.is_empty());
    *route.lock().unwrap() = test_route("en0");
    let replacement = next_udp_publication(&mut updates, Some(old.transport_instance_id())).await;
    assert_ne!(
        replacement.transport_instance_id(),
        old.transport_instance_id()
    );
    assert_eq!(old.inbound_publication_owner(), 0);
    assert_eq!(attempts.load(Ordering::SeqCst), 2);
    assert_eq!(daemon.peers.current_network_generation_sync(), 1);
    assert!(daemon
        .runtime_stun_servers
        .read()
        .await
        .iter()
        .any(|address| *address == observer.local_addr().unwrap()));
    shutdown_tx.send(true).unwrap();
    timeout(Duration::from_secs(3), worker)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    drop(candidate_guard);
}

#[tokio::test(start_paused = true)]
async fn stable_route_cancels_initial_live_stun_wait_before_it_finishes() {
    let mut config = Config::generate_default("https://ctrl.test", "net1").unwrap();
    config.network.gather_host_candidates = false;
    let daemon = Daemon::new(config);
    let observer = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let mut context = test_context(&daemon, shutdown_rx);
    context.stun_servers = vec![observer.local_addr().unwrap()];
    context.stun_server_specs = vec![observer.local_addr().unwrap().to_string()];
    context.stun_timeout = Duration::from_secs(30);
    let route = Arc::new(std::sync::Mutex::new(test_route("en0")));
    let bind_route = route.clone();
    let sampled_route = route.clone();
    let updates = daemon.udp_transport_publication.subscribe();
    // Drive the actual supervisor without spawning it, so waiting for local
    // UDP I/O cannot auto-advance paused time and expire the initial STUN wait.
    let mut worker = Box::pin(run_udp_direct_task_with_binder_and_route_sampler(
        context,
        move |bind, peers| {
            let signature = bind_route.lock().unwrap().clone();
            async move {
                Ok(UdpDirectBinding {
                    udp: UdpTransport::bind(bind, peers).await?,
                    route_signature: signature,
                })
            }
        },
        move || std::future::ready(sampled_route.lock().unwrap().clone()),
    ));
    let started_at = tokio::time::Instant::now();
    let mut request = [0; 2048];
    let receive = observer.recv_from(&mut request);
    tokio::pin!(receive);
    let mut received = false;
    for _ in 0..100 {
        assert!(futures_util::poll!(worker.as_mut()).is_pending());
        if futures_util::poll!(receive.as_mut()).is_ready() {
            received = true;
            break;
        }
        tokio::task::yield_now().await;
    }
    assert!(received, "startup must send a real STUN request");
    assert_eq!(started_at.elapsed(), Duration::ZERO);
    let old = updates.borrow().clone().unwrap();
    *route.lock().unwrap() = test_route("en1");
    for _ in 0..2 {
        tokio::time::advance(udp_route_poll_interval()).await;
        assert!(futures_util::poll!(worker.as_mut()).is_pending());
    }
    // Cleanup may await workers, but must not need another timer tick. Only
    // 20ms have elapsed: the unanswered initial STUN request still has 330ms.
    for _ in 0..100 {
        assert!(futures_util::poll!(worker.as_mut()).is_pending());
        if updates
            .borrow()
            .as_ref()
            .is_some_and(|udp| udp.transport_instance_id() != old.transport_instance_id())
        {
            break;
        }
        tokio::task::yield_now().await;
    }
    let replacement = updates
        .borrow()
        .clone()
        .expect("replacement must be published");
    assert_ne!(
        replacement.transport_instance_id(),
        old.transport_instance_id()
    );
    assert_eq!(started_at.elapsed(), udp_route_poll_interval() * 2);
    assert!(started_at.elapsed() < DIRECT_STARTUP_STUN_TIMEOUT);
    assert_eq!(old.inbound_publication_owner(), 0);
    assert_eq!(daemon.peers.current_network_generation_sync(), 1);
    shutdown_tx.send(true).unwrap();
    worker.await.unwrap();
}

#[tokio::test(start_paused = true)]
async fn shutdown_cancels_pending_route_sampling_and_bind_before_publication() {
    for pending_sampler in [true, false] {
        let daemon = Daemon::new(Config::generate_default("https://ctrl.test", "net1").unwrap());
        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        let context = test_context(&daemon, shutdown_rx);
        let attempts = Arc::new(AtomicUsize::new(0));
        let bind_attempts = attempts.clone();
        let mut worker = Box::pin(run_udp_direct_task_with_binder_and_route_sampler(
            context,
            move |_, _| {
                bind_attempts.fetch_add(1, Ordering::SeqCst);
                std::future::pending::<Result<UdpDirectBinding>>()
            },
            move || async move {
                if pending_sampler {
                    std::future::pending::<Vec<String>>().await
                } else {
                    test_route("en0")
                }
            },
        ));
        assert!(futures_util::poll!(worker.as_mut()).is_pending());
        assert_eq!(
            attempts.load(Ordering::SeqCst),
            usize::from(!pending_sampler)
        );
        shutdown_tx.send(true).unwrap();
        timeout(Duration::from_millis(1), worker)
            .await
            .expect("shutdown must cancel pending platform work")
            .unwrap();
        assert!(daemon
            .udp_transport_publication
            .subscribe()
            .borrow()
            .is_none());
    }
}

#[tokio::test(start_paused = true)]
async fn desktop_route_wakes_bind_backoff_and_next_failure_keeps_nonzero_delay() {
    let daemon = Daemon::new(Config::generate_default("https://ctrl.test", "net1").unwrap());
    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let context = test_context(&daemon, shutdown_rx);
    let route = Arc::new(std::sync::Mutex::new(test_route("en0")));
    let sampled_route = route.clone();
    let attempts = Arc::new(AtomicUsize::new(0));
    let bind_attempts = attempts.clone();
    let mut worker = Box::pin(run_udp_direct_task_with_binder_and_route_sampler(
        context,
        move |_, _| {
            bind_attempts.fetch_add(1, Ordering::SeqCst);
            std::future::ready(Err(DaemonError::Network("network unavailable".into())))
        },
        move || std::future::ready(sampled_route.lock().unwrap().clone()),
    ));
    assert!(futures_util::poll!(worker.as_mut()).is_pending());
    for delay in [10, 20, 40, 80] {
        tokio::time::advance(Duration::from_millis(delay)).await;
        assert!(futures_util::poll!(worker.as_mut()).is_pending());
    }
    assert_eq!(attempts.load(Ordering::SeqCst), 5);
    *route.lock().unwrap() = test_route("en1");
    tokio::time::advance(udp_route_poll_interval()).await;
    assert!(futures_util::poll!(worker.as_mut()).is_pending());
    assert_eq!(
        attempts.load(Ordering::SeqCst),
        5,
        "one sample cannot wake retry"
    );
    tokio::time::advance(udp_route_poll_interval()).await;
    assert!(futures_util::poll!(worker.as_mut()).is_pending());
    assert_eq!(
        attempts.load(Ordering::SeqCst),
        6,
        "two stable samples wake before the 100ms fault delay"
    );
    assert!(futures_util::poll!(worker.as_mut()).is_pending());
    assert_eq!(attempts.load(Ordering::SeqCst), 6);
    tokio::time::advance(udp_direct_retry_initial_delay()).await;
    assert!(futures_util::poll!(worker.as_mut()).is_pending());
    assert_eq!(attempts.load(Ordering::SeqCst), 7);
    shutdown_tx.send(true).unwrap();
    worker.await.unwrap();
}

#[tokio::test]
async fn initial_empty_stun_sources_recover_when_route_is_already_online() {
    let mut config = Config::generate_default("https://ctrl.test", "net1").unwrap();
    config.network.gather_host_candidates = false;
    let daemon = Daemon::new(config);
    let observer = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let mut context = test_context(&daemon, shutdown_rx);
    context.stun_server_specs = vec![format!(
        "localhost:{}",
        observer.local_addr().unwrap().port()
    )];
    context.stun_timeout = Duration::from_secs(1);
    let attempts = Arc::new(AtomicUsize::new(0));
    let bind_attempts = attempts.clone();
    let mut updates = daemon.udp_transport_publication.subscribe();
    let worker = tokio::spawn(run_udp_direct_task_with_binder_and_route_sampler(
        context,
        move |bind, peers| {
            bind_attempts.fetch_add(1, Ordering::SeqCst);
            async move {
                Ok(UdpDirectBinding {
                    udp: UdpTransport::bind(bind, peers).await?,
                    route_signature: test_route("en0"),
                })
            }
        },
        || std::future::ready(test_route("en0")),
    ));
    let udp = next_udp_publication(&mut updates, None).await;
    let mut request = [0; 2048];
    let (_, source) = timeout(Duration::from_secs(3), observer.recv_from(&mut request))
        .await
        .expect("the existing candidate worker must resolve and query STUN without a route edge")
        .unwrap();
    assert_eq!(source.port(), udp.local_addr().unwrap().port());
    assert!(daemon
        .runtime_stun_servers
        .read()
        .await
        .contains(&observer.local_addr().unwrap()));
    assert_eq!(
        attempts.load(Ordering::SeqCst),
        1,
        "DNS recovery does not create another lifecycle owner or socket"
    );
    shutdown_tx.send(true).unwrap();
    timeout(Duration::from_secs(3), worker)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
}
