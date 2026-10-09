async fn next_restart_event(events: &mut mpsc::UnboundedReceiver<ControlEvent>) -> ControlEvent {
    let event = events
        .recv()
        .await
        .expect("control runtime must stay alive");
    assert!(
        !matches!(event, ControlEvent::ReauthRequired { .. }),
        "a temporary control outage must not request a new login: {event:?}"
    );
    event
}

#[tokio::test]
async fn control_outage_recovers_with_original_device_credential_without_login() {
    let unavailable = Arc::new(AtomicBool::new(false));
    let (registration_during_outage, mut registration_seen) = watch::channel(false);
    let server = ControlStub::start({
        let unavailable = unavailable.clone();
        move |line| {
            if unavailable.load(Ordering::Acquire) {
                if line.starts_with("POST /api/v1/devices ") {
                    registration_during_outage.send_replace(true);
                }
                return (
                    503,
                    r#"{"error":"authentication temporarily unavailable","error_code":"authentication_unavailable"}"#.into(),
                );
            }
            let body = if line.starts_with("POST /api/v1/devices ") {
                r#"{"success":true,"node_id":"restart-node","virtual_ip":"10.20.0.2","cidr":"10.20.0.0/16","relay_servers":[]}"#
            } else if line.starts_with("GET /api/v1/nodes") {
                r#"{"nodes":[],"authorization_lease_seconds":30}"#
            } else if line.starts_with("GET /api/v1/signals") {
                r#"{"signals":[],"server_time_ms":0}"#
            } else {
                r#"{"success":true}"#
            };
            (200, body.into())
        }
    })
    .await;
    let mut config = test_config();
    config.control.server_url = server.base_url.clone();
    // An expired account JWT must not be needed while the persisted device
    // credential is valid. A false 401 would switch to this rejected login.
    config.control.auth_token = "expired-account-token".into();
    config.control.device_credential = "dc-persisted-restart-credential".into();
    config.control.credential_issued = true;
    config.control.heartbeat_interval_secs = 1;
    let health = crate::tasks::HealthState::new();
    let (client, mut events) = ControlClient::new_with_health(
        &config,
        true,
        None,
        None,
        ConnectionTimeline::new("restart-node", 0),
        Some(health.clone()),
        None,
    );
    client.mark_event_loop_ready();
    timeout(Duration::from_secs(5), async {
        while !matches!(
            next_restart_event(&mut events).await,
            ControlEvent::ControlHealthy
        ) {}
    })
    .await
    .expect("initial control registration must become healthy");

    unavailable.store(true, Ordering::Release);
    timeout(Duration::from_secs(20), async {
        let retry_seen = registration_seen.wait_for(|seen| *seen);
        tokio::pin!(retry_seen);
        loop {
            tokio::select! {
                result = &mut retry_seen => {
                    result.expect("outage observation owner must remain alive");
                    break;
                }
                _ = next_restart_event(&mut events) => {}
            }
        }
    })
    .await
    .expect("a persistent outage must reach bounded re-registration recovery");
    assert!(!health.snapshot(&[]).await.reauth_required);

    unavailable.store(false, Ordering::Release);
    timeout(Duration::from_secs(8), async {
        // Ignore healthy events already queued before the outage. A fresh
        // registration and its following poll must both finish after recovery.
        while !matches!(
            next_restart_event(&mut events).await,
            ControlEvent::Registered { .. }
        ) {}
        while !matches!(
            next_restart_event(&mut events).await,
            ControlEvent::ControlHealthy
        ) {}
    })
    .await
    .expect("control must recover without restarting the client or logging in");
    let snapshot = health.snapshot(&[]).await;
    assert!(snapshot.control_connected);
    assert!(snapshot.device_lease_healthy);
    assert!(!snapshot.reauth_required);
    assert_eq!(
        client.registration_rx.borrow().as_ref().unwrap().token,
        config.control.device_credential,
        "recovery must retain the original device credential"
    );
    assert!(!server.saw("POST /api/v1/login"));
    assert!(!server.saw("POST /api/v1/challenges"));
    client.shutdown().await.unwrap();
}
