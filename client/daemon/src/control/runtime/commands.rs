// Control-command handling for the polling cycle.
//
// `control/runtime.rs` splices this file into the `control` module with
// `include!`, so it shares that module's imports and private items. Unlike the
// former version of this file — a bare `match` statement spliced directly into
// the polling loop's `select!` arm — it is a complete set of Rust items, which
// is what lets `rustfmt` (and the `check_include_format` gate) inspect it.
//
// The splice used to hide one more thing: `break` and `return` inside those
// arms silently borrowed the enclosing loop's control flow, so "re-register"
// and "stop the control loop" were spelled the same way as ordinary loop
// bookkeeping. Every arm now returns an explicit `ControlCommandDisposition`.

/// What the polling loop must do once a command has been handled.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ControlCommandDisposition {
    /// Keep serving the current polling cycle.
    Continue,
    /// Leave the polling cycle so the outer loop re-registers with the control
    /// plane (the destination of the former `break`).
    Reregister,
    /// Leave `run_control_loop` entirely (the destination of the former
    /// `return`).
    Exit,
}

/// Handle one [`ControlCommand`] from the control channel.
///
/// Every mutation this function performs belongs to the caller: the peer-roster
/// tick is re-armed in place, `poll_failures` is the caller's consecutive
/// failure counter, and all other state is behind the shared handles the
/// polling loop already owns. No new state owner is introduced here.
#[allow(clippy::too_many_arguments)]
async fn handle_control_command(
    cmd: ControlCommand,
    http: &RouteAwareControlHttpClient,
    base_url: &str,
    token: &str,
    config: &Config,
    self_node_id: &str,
    registration_seq: Option<u64>,
    state: &Arc<RwLock<ClientState>>,
    event_tx: &mpsc::UnboundedSender<ControlEvent>,
    health: Option<&Arc<crate::tasks::HealthState>>,
    relay_selection: Option<&Arc<RwLock<RelaySelectionDiagnostics>>>,
    advertised_snapshot: &Arc<std::sync::Mutex<AdvertisedEndpointSnapshot>>,
    peer_roster_tick: &mut time::Interval,
    signal_ws_task: Option<&websocket::SignalWebSocketTask>,
    poll_failures: &mut u32,
) -> ControlCommandDisposition {
    match cmd {
        ControlCommand::PollPeersNow => {
            // A signal arrived from a peer that the daemon has not
            // registered yet: bring the peer list current immediately
            // instead of waiting out the regular poll cadence, then
            // re-arm the regular tick so this does not create a poll
            // burst.
            peer_roster_tick.reset();
            let poll_result = async {
                let current_http = http.current()?;
                poll_peers(
                    &current_http,
                    base_url,
                    token,
                    config,
                    self_node_id,
                    registration_seq,
                    state,
                    event_tx,
                )
                .await
            }
            .await;
            match &poll_result {
                Ok(_) => {
                    *poll_failures = 0;
                    if let Some(health) = health {
                        health.mark_control_success().await;
                    }
                    let _ = event_tx.send(ControlEvent::ControlHealthy);
                    ControlCommandDisposition::Continue
                }
                Err(err) => {
                    let err_str = err.to_string();
                    if is_registration_conflict_error(&err_str) {
                        emit_registration_lifecycle_conflict(health, event_tx, err_str).await;
                        return ControlCommandDisposition::Exit;
                    }
                    warn!("Immediate peer polling failed: {err_str}");
                    *poll_failures = poll_failures.saturating_add(1);
                    ControlCommandDisposition::Continue
                }
            }
        }
        ControlCommand::NetworkChanged => {
            http.notify_network_changed();
            if let Some(task) = signal_ws_task {
                task.abort();
            }
            info!(
                "Android physical network changed; restarting control registration and signaling transports"
            );
            ControlCommandDisposition::Reregister
        }
        ControlCommand::CreateTunnel {
            protocol,
            local_port,
            remote_port,
        } => {
            let res = async {
                let current_http = http.current()?;
                create_tunnel(
                    &current_http,
                    base_url,
                    token,
                    self_node_id,
                    registration_seq,
                    &protocol,
                    local_port,
                    remote_port,
                )
                .await
            }
            .await;
            match res {
                Ok((tunnel_id, public_endpoint)) => {
                    let _ = event_tx.send(ControlEvent::TunnelCreated {
                        tunnel_id,
                        public_endpoint,
                    });
                    ControlCommandDisposition::Continue
                }
                Err(err) => {
                    let err_str = err.to_string();
                    if is_registration_conflict_error(&err_str) {
                        emit_registration_lifecycle_conflict(health, event_tx, err_str).await;
                        return ControlCommandDisposition::Exit;
                    }
                    let code = if is_permanent_auth_error(&err_str) {
                        401u16
                    } else {
                        3000u16
                    };
                    let _ = event_tx.send(ControlEvent::ServerError {
                        code,
                        message: err_str,
                    });
                    if code == 401 {
                        // A rejected credential cannot be retried in this
                        // polling cycle; re-register instead of looping.
                        ControlCommandDisposition::Reregister
                    } else {
                        ControlCommandDisposition::Continue
                    }
                }
            }
        }
        ControlCommand::UpdateEndpoint {
            endpoint,
            nat_type,
            response_tx,
        } => {
            let relay_rtt_ms = current_relay_rtt_ms(relay_selection).await;
            let published_nat_type =
                control_label_with_registration_seq(&nat_type, registration_seq);
            let res = async {
                let current_http = http.current()?;
                update_endpoint(
                    &current_http,
                    base_url,
                    token,
                    self_node_id,
                    &endpoint,
                    &published_nat_type,
                    relay_rtt_ms,
                    registration_seq,
                )
                .await
            }
            .await;
            match &res {
                Ok(()) => {
                    advertised_snapshot
                        .lock()
                        .unwrap()
                        .update(endpoint.clone(), published_nat_type.clone());
                    debug!(
                        "Updated endpoint for {self_node_id}: {endpoint} ({published_nat_type})"
                    );
                    if let Some(health) = health {
                        health.mark_device_lease_success().await;
                    }
                    let _ = event_tx.send(ControlEvent::ControlHealthy);
                }
                Err(err) => {
                    let err_str = err.to_string();
                    if let Some(health) = health {
                        // Endpoint PATCH is the server-side
                        // online lease heartbeat. A failed
                        // PATCH must remain visible even if a
                        // later roster/signal GET succeeds.
                        health.set_device_lease_healthy(false);
                    }
                    let _ = event_tx.send(ControlEvent::ServerError {
                        code: 2000,
                        message: err_str.clone(),
                    });
                    if is_permanent_auth_error(&err_str) {
                        // Ordering is preserved from the spliced arm: the
                        // polling loop was left before the caller's response
                        // channel was answered, so the requester observes a
                        // dropped sender rather than a `Result`.
                        return ControlCommandDisposition::Reregister;
                    }
                }
            }
            let lifecycle_conflict = res
                .as_ref()
                .err()
                .is_some_and(|err| is_registration_conflict_error(&err.to_string()));
            let _ = response_tx.send(res);
            if lifecycle_conflict {
                emit_registration_lifecycle_conflict(
                    health,
                    event_tx,
                    "endpoint update rejected by the current registration lifecycle".into(),
                )
                .await;
                return ControlCommandDisposition::Exit;
            }
            ControlCommandDisposition::Continue
        }
        ControlCommand::SendPeerReflexive {
            to_node_id,
            observed_endpoint,
            punch_at_ms,
            response_tx,
        } => {
            let candidates = vec![observed_endpoint.clone()];
            let candidate_sources =
                HashMap::from([(observed_endpoint.clone(), "peer_reflexive".to_string())]);
            let res = async {
                let current_http = http.current()?;
                send_signal(
                    &current_http,
                    base_url,
                    token,
                    registration_seq,
                    self_node_id,
                    &to_node_id,
                    "peer_reflexive",
                    &candidates,
                    &candidate_sources,
                    &[],
                    punch_at_ms,
                    None,
                    None,
                    None,
                    None,
                )
                .await
            }
            .await;
            match &res {
                Ok(()) => {
                    debug!(
                        "Sent peer-reflexive observation to {to_node_id}: {observed_endpoint} punch_at_ms={punch_at_ms:?}"
                    );
                }
                Err(err) => {
                    let err_str = err.to_string();
                    let _ = event_tx.send(ControlEvent::ServerError {
                        code: 4002,
                        message: err_str.clone(),
                    });
                    if is_permanent_auth_error(&err_str) {
                        // Ordering is preserved from the spliced arm: the
                        // polling loop was left before the caller's response
                        // channel was answered.
                        return ControlCommandDisposition::Reregister;
                    }
                }
            }
            let lifecycle_conflict = res
                .as_ref()
                .err()
                .is_some_and(|err| is_registration_conflict_error(&err.to_string()));
            let _ = response_tx.send(res);
            if lifecycle_conflict {
                emit_registration_lifecycle_conflict(
                    health,
                    event_tx,
                    "peer-reflexive signal rejected by the current registration lifecycle".into(),
                )
                .await;
                return ControlCommandDisposition::Exit;
            }
            ControlCommandDisposition::Continue
        }
        ControlCommand::DeleteTunnel { tunnel_id } => {
            debug!("Tunnel deletion queued locally for {tunnel_id}");
            ControlCommandDisposition::Continue
        }
        ControlCommand::FetchRelayTicket {
            audience,
            region,
            response_tx,
        } => {
            let result = async {
                let current_http = http.current()?;
                fetch_relay_ticket_http(
                    &current_http,
                    base_url,
                    token,
                    registration_seq,
                    &audience,
                    &region,
                )
                .await
            }
            .await;
            let lifecycle_conflict = result
                .as_ref()
                .err()
                .is_some_and(|err| is_registration_conflict_error(&err.to_string()));
            let _ = response_tx.send(result);
            if lifecycle_conflict {
                emit_registration_lifecycle_conflict(
                    health,
                    event_tx,
                    "relay ticket request rejected by the current registration lifecycle".into(),
                )
                .await;
                return ControlCommandDisposition::Exit;
            }
            ControlCommandDisposition::Continue
        }
        ControlCommand::Shutdown { response_tx } => {
            let release_result = async {
                let current_http = http.current()?;
                release_presence(
                    &current_http,
                    base_url,
                    token,
                    self_node_id,
                    registration_seq,
                )
                .await
            }
            .await;
            if let Err(err) = release_result {
                warn!(
                    "Best-effort device presence release failed for {}: {}",
                    self_node_id, err
                );
            }
            let _ = response_tx.send(());
            let _ = event_tx.send(ControlEvent::Disconnected);
            ControlCommandDisposition::Exit
        }
        ControlCommand::LifecycleConflict { message } => {
            emit_registration_lifecycle_conflict(health, event_tx, message).await;
            ControlCommandDisposition::Exit
        }
    }
}
