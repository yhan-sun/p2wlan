#[allow(clippy::too_many_arguments)]
async fn run_control_loop(
    mut config: Config,
    http: reqwest::Client,
    timeline: Arc<ConnectionTimeline>,
    event_tx: &mpsc::UnboundedSender<ControlEvent>,
    state: Arc<RwLock<ClientState>>,
    cmd_rx: &mut mpsc::UnboundedReceiver<ControlCommand>,
    config_path: Option<PathBuf>,
    relay_selection: Option<Arc<RwLock<RelaySelectionDiagnostics>>>,
    critical_auth_tx: watch::Sender<Option<CriticalControlAuth>>,
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
    let recent_signal_ids: Arc<tokio::sync::Mutex<VecDeque<String>>> =
        Arc::new(tokio::sync::Mutex::new(VecDeque::new()));

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
                match register_device(&http, &base_url, &token, &config).await {
                    Ok((node_id, virtual_ip, cidr, server_relay_servers, relay_catalog)) => {
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
                                if let Err(e) = config.save_to_file(path) {
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

                        // Attempt Ed25519 challenge for device credential
                        if !config.control.credential_issued
                            && !config.node.ed25519_private_key.is_empty()
                            && !config.node.ed25519_public_key.is_empty()
                        {
                            info!("Attempting Ed25519 challenge for device credential...");
                            match obtain_device_credential(
                                &http,
                                &base_url,
                                &user_token,
                                &node_id,
                                &config.node.ed25519_private_key,
                                &config.node.ed25519_public_key,
                            )
                            .await
                            {
                                Ok(device_credential) => {
                                    info!("Device credential obtained successfully");
                                    config.control.device_credential = device_credential.clone();
                                    config.control.credential_issued = true;
                                    token = device_credential;
                                    if let Some(ref path) = config_path {
                                        if let Err(e) = config.save_to_file(path) {
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
        if let Err(err) = poll_peers(
            &http,
            &base_url,
            &token,
            &config,
            &self_node_id,
            &state,
            event_tx,
        )
        .await
        {
            warn!("Initial peer polling failed: {err}");
            let _ = event_tx.send(ControlEvent::Disconnected);
        } else {
            let _ = event_tx.send(ControlEvent::ControlHealthy);
        }
        if let Err(err) = poll_signals(&http, &base_url, &token, &self_node_id, event_tx, 0, &recent_signal_ids).await {
            warn!("Initial signal polling failed: {err}");
            let _ = event_tx.send(ControlEvent::Disconnected);
        } else {
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

        let peer_interval_secs = config
            .control
            .heartbeat_interval_secs
            .max(MIN_PEER_POLL_INTERVAL_SECS);
        let mut peer_tick = time::interval(Duration::from_secs(peer_interval_secs));
        peer_tick.set_missed_tick_behavior(time::MissedTickBehavior::Skip);
        let mut signal_tick = time::interval(SIGNAL_FALLBACK_TICK);
        signal_tick.set_missed_tick_behavior(time::MissedTickBehavior::Skip);
        let mut last_signal_reconcile = Instant::now();

        let mut poll_failures: u32 = 0;
        let mut signal_failures: u32 = 0;
        let mut advertised_endpoint = String::new();
        let mut advertised_nat_type = "unknown".to_string();
        loop {
            tokio::select! {
                _ = peer_tick.tick() => {
                    let relay_rtt_ms = current_relay_rtt_ms(relay_selection.as_ref()).await;
                    if let Err(err) = update_endpoint(
                        &http,
                        &base_url,
                        &token,
                        &self_node_id,
                        &advertised_endpoint,
                        &advertised_nat_type,
                        relay_rtt_ms,
                    )
                    .await
                    {
                        warn!("Device lease refresh failed: {err}");
                    }
                    let poll_result = poll_peers(&http, &base_url, &token, &config, &self_node_id, &state, event_tx).await;
                    match &poll_result {
                        Err(e) => {
                            let err_str = e.to_string();
                            if is_permanent_auth_error(&err_str) {
                                error!("Permanent auth failure during polling: {err_str}");
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
                            let _ = event_tx.send(ControlEvent::ControlHealthy);
                        }
                    }
                }
                Some(()) = signal_wake_rx.recv() => {
                    match poll_signals(&http, &base_url, &token, &self_node_id, event_tx, 0, &recent_signal_ids).await {
                        Ok(()) => {
                            signal_failures = 0;
                            last_signal_reconcile = Instant::now();
                            let _ = event_tx.send(ControlEvent::ControlHealthy);
                        }
                        Err(e) => {
                            let err_str = e.to_string();
                            if is_permanent_auth_error(&err_str) {
                                error!("Permanent auth failure after WebSocket signal wake: {err_str}");
                                let _ = event_tx.send(ControlEvent::ReauthRequired {
                                    message: err_str,
                                });
                                break;
                            }
                            signal_failures = signal_failures.saturating_add(1);
                            warn!("Signal fetch after WebSocket wake failed: {err_str}");
                            let _ = event_tx.send(ControlEvent::Disconnected);
                        }
                    }
                }
                _ = signal_tick.tick() => {
                    let ws_connected = signal_ws_connected.load(Ordering::Acquire);
                    if ws_connected && last_signal_reconcile.elapsed() < SIGNAL_WS_RECONCILE_INTERVAL {
                        continue;
                    }
                    let wait_ms = if ws_connected { 0 } else { SIGNAL_LONG_POLL_WAIT_MS };
                    match poll_signals(&http, &base_url, &token, &self_node_id, event_tx, wait_ms, &recent_signal_ids).await {
                        Ok(()) => {
                            signal_failures = 0;
                            if ws_connected {
                                last_signal_reconcile = Instant::now();
                            }
                            let _ = event_tx.send(ControlEvent::ControlHealthy);
                        }
                        Err(e) => {
                            let err_str = e.to_string();
                            if is_permanent_auth_error(&err_str) {
                                error!("Permanent auth failure during signal polling: {err_str}");
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
        let _ = event_tx.send(ControlEvent::Disconnected);
        info!("Re-entering control registration cycle");
        // brief pause before re-register to avoid hammering a restarting server
        tokio::time::sleep(Duration::from_secs(1)).await;
    } // end outer loop — will hit the `return` inside on Shutdown, or loop around
}
