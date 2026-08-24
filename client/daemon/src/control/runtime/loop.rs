#[allow(clippy::too_many_arguments)]
async fn run_control_loop(
    mut config: Config,
    http: RouteAwareControlHttpClient,
    timeline: Arc<ConnectionTimeline>,
    event_tx: &mpsc::UnboundedSender<ControlEvent>,
    state: Arc<RwLock<ClientState>>,
    cmd_rx: &mut mpsc::UnboundedReceiver<ControlCommand>,
    config_path: Option<PathBuf>,
    relay_selection: Option<Arc<RwLock<RelaySelectionDiagnostics>>>,
    critical_auth_tx: watch::Sender<Option<CriticalControlAuth>>,
    health: Option<Arc<crate::tasks::HealthState>>,
) {
    let base_url = normalize_http_base_url(&config.control.server_url);

    // Prefer an existing device credential; fall back to user JWT for first registration.
    let mut token = if !config.control.device_credential.trim().is_empty() {
        config.control.device_credential.clone()
    } else {
        config.control.auth_token.clone()
    };
    let user_token = if !config.control.auth_token.trim().is_empty() {
        config.control.auth_token.clone()
    } else {
        token.clone()
    };
    let signal_signing_identity = SignalSigningIdentity::from_config(&config);
    // Bounded cache of recently processed signal IDs: a redelivered batch
    // (lost ACK, expired lease) is deduped by signal id.
    let recent_signal_ids: Arc<tokio::sync::Mutex<SignalDeliveryTracker>> =
        Arc::new(tokio::sync::Mutex::new(SignalDeliveryTracker::default()));

    info!("Connecting to control plane at {base_url}");

    // Outer recovery loop: re-registers after transient disconnects.
    loop {
        // The critical lane must never reuse a node id/token from a previous
        // registration generation while this loop is reconnecting.
        let _ = critical_auth_tx.send(None);
        // ---- Registration with exponential backoff ----
        let self_node_id = {
            let mut attempt: u32 = 0;
            loop {
                let registration = async {
                    let current_http = http.current()?;
                    register_device(&current_http, &base_url, &token, &config).await
                }
                .await;
                match registration {
                    Ok((node_id, virtual_ip, cidr, server_relay_servers, relay_catalog)) => {
                        if let Some(health) = health.as_ref() {
                            health.mark_device_lease_success().await;
                        }
                        timeline.emit(
                            "control_registered",
                            None,
                            None,
                            Some(format!("node_id={node_id} virtual_ip={virtual_ip}")),
                        );
                        {
                            let mut s = state.write().await;
                            s.registered = true;
                            s.virtual_ip = Some(virtual_ip.clone());
                        }
                        if !server_relay_servers.is_empty() {
                            config.relay.servers = server_relay_servers.clone();
                        }
                        let mut config_changed = false;
                        if !config.network.manual {
                            if config.network.virtual_ip != virtual_ip {
                                config.network.virtual_ip = virtual_ip.clone();
                                config_changed = true;
                            }
                            if config.network.cidr != cidr {
                                config.network.cidr = cidr.clone();
                                config_changed = true;
                            }
                        }
                        if config_changed {
                            if let Some(ref path) = config_path {
                                let mut persisted = config.clone();
                                persisted.control.auth_token.clear();
                                if let Err(e) = persisted.save_to_file(path) {
                                    warn!("Failed to save control-assigned network config: {e}");
                                }
                            }
                        }
                        let relay_servers = if server_relay_servers.is_empty() {
                            config.relay.servers.clone()
                        } else {
                            server_relay_servers
                        };

                        let _ = event_tx.send(ControlEvent::Registered {
                            node_id: Some(node_id.clone()),
                            virtual_ip: virtual_ip.clone(),
                            cidr: Some(cidr.clone()),
                            relay_servers,
                            relay_catalog,
                        });

                        // Candidate refresh and relay-first setup may begin
                        // as soon as registration succeeds.  Publish the
                        // currently authoritative registration token before
                        // the optional Ed25519 credential challenge; the
                        // later update below replaces it atomically if the
                        // challenge issues a device credential.
                        let _ = critical_auth_tx.send(Some(CriticalControlAuth {
                            base_url: base_url.clone(),
                            token: token.clone(),
                            self_node_id: node_id.clone(),
                            signal_signing_identity: signal_signing_identity.clone(),
                        }));

                        // Attempt Ed25519 challenge for device credential
                        if !config.control.credential_issued
                            && !config.node.ed25519_private_key.is_empty()
                            && !config.node.ed25519_public_key.is_empty()
                        {
                            info!("Attempting Ed25519 challenge for device credential...");
                            let credential_result = async {
                                let current_http = http.current()?;
                                obtain_device_credential(
                                    &current_http,
                                    &base_url,
                                    &user_token,
                                    &node_id,
                                    &config.node.ed25519_private_key,
                                    &config.node.ed25519_public_key,
                                )
                                .await
                            }
                            .await;
                            match credential_result {
                                Ok(device_credential) => {
                                    info!("Device credential obtained successfully");
                                    config.control.device_credential = device_credential.clone();
                                    config.control.credential_issued = true;
                                    token = device_credential;
                                    if let Some(ref path) = config_path {
                                        let mut persisted = config.clone();
                                        persisted.control.auth_token.clear();
                                        if let Err(e) = persisted.save_to_file(path) {
                                            warn!(
                                                "Failed to save config with device credential: {e}"
                                            );
                                        }
                                    }
                                }
                                Err(e) => {
                                    warn!("Failed to obtain device credential (non-fatal): {e}");
                                }
                            }
                        }

                        // Publish only after credential issuance has had a
                        // chance to replace the user token.  The independent
                        // handshake worker must sign as this exact
                        // server-assigned node identity, never config.node_id.
                        let _ = critical_auth_tx.send(Some(CriticalControlAuth {
                            base_url: base_url.clone(),
                            token: token.clone(),
                            self_node_id: node_id.clone(),
                            signal_signing_identity: signal_signing_identity.clone(),
                        }));

                        break node_id;
                    }
                    Err(err) => {
                        let err_str = err.to_string();
                        if is_permanent_auth_error(&err_str) {
                            if token != user_token && !user_token.trim().is_empty() {
                                warn!(
                                    "Stored device credential was rejected; retrying registration with user token"
                                );
                                token = user_token.clone();
                                config.control.device_credential.clear();
                                config.control.credential_issued = false;
                                continue;
                            }
                            error!(
                                "Control registration permanent auth failure — re-authentication required: {err_str}"
                            );
                            let _ =
                                event_tx.send(ControlEvent::ReauthRequired { message: err_str });
                            // Stop fast retries; wait for Shutdown or a long pause then re-check.
                            loop {
                                tokio::select! {
                                    Some(cmd) = cmd_rx.recv() => {
                                        if matches!(cmd, ControlCommand::Shutdown) {
                                            let _ = event_tx.send(ControlEvent::Disconnected);
                                            return;
                                        }
                                    }
                                    _ = tokio::time::sleep(Duration::from_secs(60)) => {
                                        // Allow operator to fix credentials and retry once per minute.
                                        warn!("Retrying registration after permanent-auth cooldown");
                                        break;
                                    }
                                    else => {
                                        let _ = event_tx.send(ControlEvent::Disconnected);
                                        return;
                                    }
                                }
                            }
                            // After cooldown, try again (outer attempt loop).
                            continue;
                        }

                        attempt = attempt.saturating_add(1);
                        let delay = backoff_delay(attempt.saturating_sub(1));
                        warn!(
                            "Control registration failed (attempt {attempt}); retrying in {delay:?}: {err_str}"
                        );
                        // Interruptible sleep so Shutdown is honoured.
                        tokio::select! {
                            _ = tokio::time::sleep(delay) => {}
                            Some(cmd) = cmd_rx.recv() => {
                                if matches!(cmd, ControlCommand::Shutdown) {
                                    let _ = event_tx.send(ControlEvent::Disconnected);
                                    return;
                                }
                            }
                            else => {
                                let _ = event_tx.send(ControlEvent::Disconnected);
                                return;
                            }
                        }
                    }
                }
            }
        };

        // ---- Polling cycle ----
        // Initial poll
        let initial_peer_poll = async {
            let current_http = http.current()?;
            poll_peers(
                &current_http,
                &base_url,
                &token,
                &config,
                &self_node_id,
                &state,
                event_tx,
            )
            .await
        }
        .await;
        if let Err(err) = initial_peer_poll {
            warn!("Initial peer polling failed: {err}");
            if let Some(health) = health.as_ref() {
                health.set_control_connected(false);
            }
            let _ = event_tx.send(ControlEvent::Disconnected);
        } else {
            if let Some(health) = health.as_ref() {
                health.mark_control_success().await;
            }
            let _ = event_tx.send(ControlEvent::ControlHealthy);
        }
        let initial_signal_poll = async {
            let current_http = http.current()?;
            poll_signals(
                &current_http,
                &base_url,
                &token,
                &self_node_id,
                event_tx,
                0,
                &recent_signal_ids,
            )
            .await
        }
        .await;
        if let Err(err) = initial_signal_poll {
            warn!("Initial signal polling failed: {err}");
            if let Some(health) = health.as_ref() {
                health.set_control_connected(false);
            }
            let _ = event_tx.send(ControlEvent::Disconnected);
        } else {
            if let Some(health) = health.as_ref() {
                health.mark_control_success().await;
            }
            let _ = event_tx.send(ControlEvent::ControlHealthy);
        }

        let signal_ws_connected = Arc::new(AtomicBool::new(false));
        let (signal_wake_tx, mut signal_wake_rx) = mpsc::channel(SIGNAL_WS_WAKE_QUEUE);
        let signal_ws_task = token.starts_with("dc-").then(|| {
            spawn_signal_websocket(
                &base_url,
                &token,
                &self_node_id,
                &config.network.network_id,
                signal_wake_tx.clone(),
                signal_ws_connected.clone(),
            )
        });
        drop(signal_wake_tx);

        // Lease refresh/endpoint publication follows the configured
        // heartbeat. Peer roster discovery is intentionally independent: it
        // gates relay-first handshake admission and must not inherit a
        // multi-second lease interval.
        let heartbeat_interval_secs = config.control.heartbeat_interval_secs.max(1);
        let mut heartbeat_tick = time::interval(Duration::from_secs(heartbeat_interval_secs));
        heartbeat_tick.set_missed_tick_behavior(time::MissedTickBehavior::Skip);
        let mut peer_roster_tick =
            time::interval(Duration::from_secs(PEER_ROSTER_POLL_INTERVAL_SECS));
        peer_roster_tick.set_missed_tick_behavior(time::MissedTickBehavior::Skip);
        let mut signal_tick = time::interval(SIGNAL_FALLBACK_TICK);
        signal_tick.set_missed_tick_behavior(time::MissedTickBehavior::Skip);
        let mut poll_failures: u32 = 0;
        let mut signal_failures: u32 = 0;
        let mut heartbeat_failures: u32 = 0;
        let mut advertised_endpoint = String::new();
        let mut advertised_nat_type = "unknown".to_string();
        loop {
            tokio::select! {
                _ = heartbeat_tick.tick() => {
                    let relay_rtt_ms = current_relay_rtt_ms(relay_selection.as_ref()).await;
                    let heartbeat_result = async {
                        let current_http = http.current()?;
                        update_endpoint(
                            &current_http,
                            &base_url,
                            &token,
                            &self_node_id,
                            &advertised_endpoint,
                            &advertised_nat_type,
                            relay_rtt_ms,
                        )
                        .await
                    }
                    .await;
                    match heartbeat_result {
                        Ok(()) => {
                            if heartbeat_failures > 0 {
                                info!(
                                    "Device lease refresh recovered after {} failures",
                                    heartbeat_failures
                                );
                            }
                            heartbeat_failures = 0;
                            if let Some(health) = health.as_ref() {
                                health.mark_device_lease_success().await;
                            }
                            let _ = event_tx.send(ControlEvent::ControlHealthy);
                        }
                        Err(err) => {
                            heartbeat_failures = heartbeat_failures.saturating_add(1);
                            let err_str = err.to_string();
                            warn!(
                                "Device lease refresh failed (attempt {heartbeat_failures}): {err_str}"
                            );
                            if let Some(health) = health.as_ref() {
                                health.set_control_api_reachable(false);
                                health.set_device_lease_healthy(false);
                            }
                            let _ = event_tx.send(ControlEvent::Disconnected);

                            // The server uses the endpoint PATCH as the device
                            // lease heartbeat. Merely continuing to poll the
                            // node list can therefore leave this process looking
                            // healthy locally while the server marks it offline
                            // and the relay drops its registration. Re-register
                            // after a short bounded run of failures so the
                            // server-issued node/session is refreshed.
                            if is_permanent_auth_error(&err_str) || heartbeat_failures >= 3 {
                                warn!(
                                    "Device lease refresh failed {heartbeat_failures} times; re-registering with control plane"
                                );
                                break;
                            }
                        }
                    }
                }
                _ = peer_roster_tick.tick() => {
                    let poll_result = async {
                        let current_http = http.current()?;
                        poll_peers(&current_http, &base_url, &token, &config, &self_node_id, &state, event_tx).await
                    }
                    .await;
                    match &poll_result {
                        Err(e) => {
                            let err_str = e.to_string();
                            if is_permanent_auth_error(&err_str) {
                                error!("Permanent auth failure during polling: {err_str}");
                                if let Some(health) = health.as_ref() {
                                    health.set_reauth_required(true);
                                }
                                let _ = event_tx.send(ControlEvent::ReauthRequired {
                                    message: err_str,
                                });
                                tokio::select! {
                                    Some(cmd) = cmd_rx.recv() => {
                                        if matches!(cmd, ControlCommand::Shutdown) {
                                            let _ = event_tx.send(ControlEvent::Disconnected);
                                            return;
                                        }
                                    }
                                    _ = tokio::time::sleep(Duration::from_secs(60)) => {}
                                    else => {
                                        let _ = event_tx.send(ControlEvent::Disconnected);
                                        return;
                                    }
                                }
                                break;
                            }
                            poll_failures = poll_failures.saturating_add(1);
                            let delay = backoff_delay(poll_failures.saturating_sub(1));
                            warn!("Polling failed (attempt {poll_failures}); retrying in {delay:?}: {err_str}");
                            if let Some(health) = health.as_ref() {
                                health.set_control_connected(false);
                            }
                            let _ = event_tx.send(ControlEvent::Disconnected);
                            // After several consecutive failures, force a full re-register
                            // so device session and peer map are refreshed after control restart.
                            if poll_failures >= 3 {
                                warn!("Polling failed {poll_failures} times; re-registering with control plane");
                                break;
                            }
                            tokio::time::sleep(delay).await;
                        }
                        Ok(_) => {
                            if poll_failures > 0 {
                                info!("Polling recovered after {poll_failures} failures");
                                let vip = state.read().await.virtual_ip.clone().unwrap_or_default();
                                let _ = event_tx.send(ControlEvent::ControlRecovered {
                                    node_id: Some(self_node_id.clone()),
                                    virtual_ip: vip,
                                    cidr: None,
                                });
                            }
                            poll_failures = 0;
                            if let Some(health) = health.as_ref() {
                                health.mark_control_success().await;
                            }
                            let _ = event_tx.send(ControlEvent::ControlHealthy);
                        }
                    }
                }
                Some(()) = signal_wake_rx.recv() => {
                    let signal_result = async {
                        let current_http = http.current()?;
                        poll_signals(&current_http, &base_url, &token, &self_node_id, event_tx, 0, &recent_signal_ids).await
                    }
                    .await;
                    match signal_result {
                        Ok(()) => {
                            signal_failures = 0;
                            if let Some(health) = health.as_ref() {
                                health.mark_control_success().await;
                            }
                            let _ = event_tx.send(ControlEvent::ControlHealthy);
                        }
                        Err(e) => {
                            let err_str = e.to_string();
                            if is_permanent_auth_error(&err_str) {
                                error!("Permanent auth failure after WebSocket signal wake: {err_str}");
                                if let Some(health) = health.as_ref() {
                                    health.set_reauth_required(true);
                                }
                                let _ = event_tx.send(ControlEvent::ReauthRequired {
                                    message: err_str,
                                });
                                break;
                            }
                            signal_failures = signal_failures.saturating_add(1);
                            warn!("Signal fetch after WebSocket wake failed: {err_str}");
                            if let Some(health) = health.as_ref() {
                                health.set_control_connected(false);
                            }
                            let _ = event_tx.send(ControlEvent::Disconnected);
                        }
                    }
                }
                _ = signal_tick.tick() => {
                    let ws_connected = signal_ws_connected.load(Ordering::Acquire);
                    // A WebSocket notification is only a latency hint.  Keep
                    // polling the durable REST queue even when it is
                    // connected; a legacy/partially deployed server can
                    // accept WS connections but fail to emit a wake-up for a
                    // successfully queued signal.
                    let wait_ms = signal_poll_wait_ms(ws_connected);
                    let signal_result = async {
                        let current_http = http.current()?;
                        poll_signals(&current_http, &base_url, &token, &self_node_id, event_tx, wait_ms, &recent_signal_ids).await
                    }
                    .await;
                    match signal_result {
                        Ok(()) => {
                            signal_failures = 0;
                            if let Some(health) = health.as_ref() {
                                health.mark_control_success().await;
                            }
                            let _ = event_tx.send(ControlEvent::ControlHealthy);
                        }
                        Err(e) => {
                            let err_str = e.to_string();
                            if is_permanent_auth_error(&err_str) {
                                error!("Permanent auth failure during signal polling: {err_str}");
                                if let Some(health) = health.as_ref() {
                                    health.set_reauth_required(true);
                                }
                                let _ = event_tx.send(ControlEvent::ReauthRequired {
                                    message: err_str,
                                });
                                tokio::select! {
                                    Some(cmd) = cmd_rx.recv() => {
                                        if matches!(cmd, ControlCommand::Shutdown) {
                                            let _ = event_tx.send(ControlEvent::Disconnected);
                                            return;
                                        }
                                    }
                                    _ = tokio::time::sleep(Duration::from_secs(60)) => {}
                                    else => {
                                        let _ = event_tx.send(ControlEvent::Disconnected);
                                        return;
                                    }
                                }
                                break;
                            }

                            signal_failures = signal_failures.saturating_add(1);
                            warn!(
                                "Signal polling failed (attempt {signal_failures}); continuing: {err_str}"
                            );
                            if let Some(health) = health.as_ref() {
                                health.set_control_connected(false);
                            }
                            let _ = event_tx.send(ControlEvent::Disconnected);
                            if signal_failures >= 3 {
                                warn!("Signal polling failed {signal_failures} times; re-registering with control plane");
                                break;
                            }
                        }
                    }
                }
                Some(cmd) = cmd_rx.recv() => {
                    include!("commands.rs");

                }
                else => {
                    // Command channel closed — exit.
                    if let Some(health) = health.as_ref() {
                        health.set_control_api_reachable(false);
                        health.set_device_lease_healthy(false);
                    }
                    let _ = event_tx.send(ControlEvent::Disconnected);
                    return;
                }
            }
        }

        drop(signal_ws_task);

        // Reached here by breaking the poll loop (auth failure or consecutive poll failures).
        // Mark unregistered so peers are refreshed on next successful register/poll.
        let _ = critical_auth_tx.send(None);
        {
            let mut s = state.write().await;
            s.registered = false;
        }
        if let Some(health) = health.as_ref() {
            health.set_control_api_reachable(false);
            health.set_device_lease_healthy(false);
        }
        let _ = event_tx.send(ControlEvent::Disconnected);
        info!("Re-entering control registration cycle");
        // brief pause before re-register to avoid hammering a restarting server
        tokio::time::sleep(Duration::from_secs(1)).await;
    } // end outer loop — will hit the `return` inside on Shutdown, or loop around
}
