#[derive(Clone, Copy)]
enum ControlRecoveryDelay {
    Transient(Duration),
    PermanentAuth,
}

/// Recovery owns no business work: rejected commands are dropped, while a
/// physical-network notification must still reach the HTTP pool owner. The
/// original cooldown deadline survives every command, including more hints.
/// Only transient failures may retry early on a new physical network.
async fn wait_control_recovery(
    delay: ControlRecoveryDelay,
    http: &RouteAwareControlHttpClient,
    cmd_rx: &mut mpsc::UnboundedReceiver<ControlCommand>,
    event_tx: &mpsc::UnboundedSender<ControlEvent>,
    critical_auth_tx: &watch::Sender<Option<CriticalControlAuth>>,
    server_clock: &ServerClockEstimate,
    signal_ws_task: Option<&websocket::SignalWebSocketTask>,
) -> bool {
    let duration = match delay {
        ControlRecoveryDelay::Transient(duration) => duration,
        ControlRecoveryDelay::PermanentAuth => Duration::from_secs(60),
    };
    let deadline = time::Instant::now() + duration;
    // Polling can enter recovery with the previous registration still
    // published. Revoke it before waiting, and never restore it here; only a
    // successful registration may authorize the critical lanes again.
    server_clock.invalidate_registration();
    critical_auth_tx.send_replace(None);
    if let Some(task) = signal_ws_task {
        task.abort();
    }
    loop {
        if time::Instant::now() >= deadline {
            return true;
        }
        tokio::select! {
            biased;
            cmd = cmd_rx.recv() => match cmd {
                Some(ControlCommand::Shutdown { response_tx }) => {
                    let _ = response_tx.send(());
                    let _ = event_tx.send(ControlEvent::Disconnected);
                    return false;
                }
                Some(ControlCommand::NetworkChanged(changes)) => {
                    // This also invalidates in-flight timing samples. On
                    // Android the route signature may be empty, so the
                    // explicit pool-rebuild hint cannot be discarded.
                    if let Some(edge) = changes.take_pending(true) {
                        if edge.requires_http_rebuild() {
                            http.notify_network_changed();
                        }
                        if matches!(delay, ControlRecoveryDelay::Transient(_)) {
                            return true;
                        }
                    }
                }
                Some(_) => {}
                None => {
                    let _ = event_tx.send(ControlEvent::Disconnected);
                    return false;
                }
            },
            _ = time::sleep_until(deadline) => return true,
        }
    }
}
