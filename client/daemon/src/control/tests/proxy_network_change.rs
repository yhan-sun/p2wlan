#[test]
fn environment_route_observation_preserves_proxy_binding_policy() {
    for physical_interface in [None, Some("physical0".to_string())] {
        let routes = crate::netenv::DirectRouteSnapshot {
            signature: vec!["same-gateway:new-local-address".into()],
            physical_route_interface: physical_interface.clone(),
            tun_capture: true,
            ..Default::default()
        };
        let environment =
            control_route_binding_from_snapshot(ControlProxyMode::Environment, routes.clone());
        assert_eq!(environment.signature, routes.signature);
        assert!(environment.outbound_interface.is_none());
        assert!(!environment.fail_closed);
        let direct = control_route_binding_from_snapshot(ControlProxyMode::Direct, routes);
        assert_eq!(direct.outbound_interface, physical_interface);
        assert_eq!(direct.fail_closed, physical_interface.is_none());
    }
    // Private control servers also follow physical handovers; only loopback
    // endpoints have no remote network path for this observer to manage.
    assert!(!control_server_is_local("http://192.168.1.4:8080"));
    assert!(!control_server_is_local("http://[fd00::4]:8080"));
}

#[tokio::test(start_paused = true)]
async fn environment_worker_rebuilds_after_stable_route_without_force_feedback() {
    use crate::control::network_change::{ControlNetworkChanges, ControlRouteChangeNotifier};
    use crate::control::ControlCommand;

    let changes = Arc::new(ControlNetworkChanges::default());
    let (commands, mut command_rx) = mpsc::unbounded_channel();
    let notifier = ControlRouteChangeNotifier::new(changes.clone(), commands);
    let timing = Arc::new(ServerClockEstimate::default());
    let replacement = test_binding("same-gateway:new-address", None);
    let (inspected, mut inspections) = mpsc::unbounded_channel();
    let (primary, candidate) = route_aware_control_http_clients_with_inspector(
        ControlProxyMode::Environment,
        "http://192.168.1.4:8080",
        Some(timing.clone()),
        Some(notifier),
        ControlRouteBinding {
            signature: Vec::new(),
            outbound_interface: None,
            fail_closed: false,
        },
        move || {
            let _ = inspected.send(());
            std::future::ready(Ok(replacement.clone()))
        },
    );
    let old_pool = primary.current_with_pool_id().unwrap().1;
    inspections.recv().await.unwrap();
    assert_eq!(primary.current_with_pool_id().unwrap().1, old_pool);
    assert!(command_rx.is_empty(), "one sample is not a confirmed route");
    assert!(timing.request_identity(Some(1), old_pool).is_none());

    tokio::time::advance(CONTROL_ROUTE_POLL_INTERVAL).await;
    assert!(matches!(
        command_rx.recv().await,
        Some(ControlCommand::NetworkChanged(_))
    ));
    inspections.recv().await.unwrap();
    let new_pool = primary.current_with_pool_id().unwrap().1;
    assert_ne!(new_pool, old_pool);
    assert_eq!(candidate.current_with_pool_id().unwrap().1, new_pool);
    assert!(timing.request_identity(Some(1), new_pool).is_some());
    let (edge, changed) = changes.begin_registration();
    assert!(changed);
    assert!(changes.take_pending(true).is_none());

    let mut pools = primary.state_rx.clone();
    pools.borrow_and_update();
    for _ in 0..2 {
        primary.notify_network_changed();
        pools.changed().await.unwrap();
        inspections.recv().await.unwrap();
        assert!(
            command_rx.is_empty(),
            "a forced rebuild must not create another edge"
        );
        assert!(changes.commit_if_current(&edge, || {}));
    }
    tokio::time::advance(CONTROL_ROUTE_POLL_INTERVAL).await;
    inspections.recv().await.unwrap();
    assert!(command_rx.is_empty());
    drop(pools);
    drop(primary);
    drop(candidate);
    assert!(
        inspections.recv().await.is_none(),
        "last client drop must stop the observer"
    );
}

struct ProxyEnvironmentRestore(Vec<(&'static str, Option<std::ffi::OsString>)>);

impl ProxyEnvironmentRestore {
    fn set(values: &[(&'static str, &str)]) -> Self {
        let previous = values
            .iter()
            .map(|(key, _)| (*key, std::env::var_os(key)))
            .collect();
        for (key, value) in values {
            std::env::set_var(key, value);
        }
        Self(previous)
    }
}

impl Drop for ProxyEnvironmentRestore {
    fn drop(&mut self) {
        for (key, value) in self.0.drain(..) {
            match value {
                Some(value) => std::env::set_var(key, value),
                None => std::env::remove_var(key),
            }
        }
    }
}

#[tokio::test]
#[allow(clippy::await_holding_lock)]
async fn environment_rebuilt_pools_preserve_proxy_and_no_proxy_requests() {
    let _lock = PROXY_ENV_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let (proxy_addr, mut proxy_requests) = fake_proxy().await;
    let (direct_addr, mut direct_requests) = fake_proxy().await;
    let _restore = ProxyEnvironmentRestore::set(&[
        ("HTTP_PROXY", &proxy_addr),
        ("http_proxy", &proxy_addr),
        ("NO_PROXY", "127.0.0.1"),
        ("no_proxy", "127.0.0.1"),
    ]);
    for route in ["network-a", "network-b"] {
        let binding = control_route_binding_from_snapshot(
            ControlProxyMode::Environment,
            crate::netenv::DirectRouteSnapshot {
                signature: vec![route.into()],
                physical_route_interface: Some("nonexistent-test-interface".into()),
                tun_capture: true,
                ..Default::default()
            },
        );
        let pools = build_control_http_pools(
            ControlProxyMode::Environment,
            "http://control.invalid",
            binding,
        );
        for client in [pools.primary.unwrap(), pools.candidate.unwrap()] {
            let response = client
                .get("http://example.invalid/control/health")
                .timeout(Duration::from_secs(2))
                .send()
                .await
                .unwrap();
            assert!(response.status().is_success());
            let line = proxy_requests.recv().await.unwrap();
            assert!(line.contains("example.invalid"));
            let response = client
                .get(format!("http://{direct_addr}/control/health"))
                .timeout(Duration::from_secs(2))
                .send()
                .await
                .unwrap();
            assert!(response.status().is_success());
            assert!(direct_requests
                .recv()
                .await
                .unwrap()
                .starts_with("GET /control/health "));
            assert!(
                proxy_requests.is_empty(),
                "NO_PROXY must retain its direct path"
            );
        }
    }
}
