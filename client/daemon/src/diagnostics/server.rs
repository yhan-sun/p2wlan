/// Run the local diagnostics HTTP endpoint until the listener fails.
pub async fn run_diagnostics_server(
    bind: String,
    context: DiagnosticsContext,
    shutdown_rx: tokio::sync::watch::Receiver<bool>,
) -> Result<()> {
    let mut ready_tx = None;
    run_diagnostics_server_once(bind, context, shutdown_rx, &mut ready_tx).await
}

async fn run_diagnostics_server_once(
    bind: String,
    context: DiagnosticsContext,
    shutdown_rx: tokio::sync::watch::Receiver<bool>,
    ready_tx: &mut Option<tokio::sync::oneshot::Sender<()>>,
) -> Result<()> {
    let listener = TcpListener::bind(&bind).await.map_err(|e| {
        DaemonError::Network(format!(
            "failed to bind diagnostics endpoint at {bind}: {e}"
        ))
    })?;
    let local_addr = listener
        .local_addr()
        .map_err(|e| DaemonError::Network(format!("failed to read diagnostics local addr: {e}")))?;
    info!("[diagnostics] listening at http://{local_addr}/status");
    if let Some(sender) = ready_tx.take() {
        let _ = sender.send(());
    }

    serve_diagnostics(listener, context, shutdown_rx).await
}

/// Run the diagnostics endpoint, retrying transient bind failures.
///
/// During app-driven restarts the replacement daemon can start before the old
/// process has released the loopback diagnostics port. A single bind failure
/// should not leave the new daemon permanently invisible to the UI.
pub async fn run_diagnostics_server_with_retry(
    bind: String,
    context: DiagnosticsContext,
    shutdown_rx: tokio::sync::watch::Receiver<bool>,
) -> Result<()> {
    run_diagnostics_server_with_retry_ready(bind, context, shutdown_rx, None).await
}

/// Same retry loop as [`run_diagnostics_server_with_retry`], with an optional
/// one-shot notification after the first listener is actually bound. The
/// daemon uses this only during startup so `[startup] ready` cannot race a
/// diagnostics bind failure.
pub async fn run_diagnostics_server_with_retry_ready(
    bind: String,
    context: DiagnosticsContext,
    mut shutdown_rx: tokio::sync::watch::Receiver<bool>,
    ready_tx: Option<tokio::sync::oneshot::Sender<()>>,
) -> Result<()> {
    let mut ready_tx = ready_tx;
    let mut attempt = 0usize;
    loop {
        if *shutdown_rx.borrow() {
            return Ok(());
        }

        match run_diagnostics_server_once(
            bind.clone(),
            context.clone(),
            shutdown_rx.clone(),
            &mut ready_tx,
        )
        .await
        {
            Ok(()) => return Ok(()),
            Err(err) => {
                if *shutdown_rx.borrow() {
                    return Ok(());
                }
                if ready_tx.is_some() {
                    // During startup a bind failure is fatal. Runtime
                    // restarts still use the retry loop after the first
                    // listener has successfully notified the daemon.
                    return Err(err);
                }
                attempt = attempt.saturating_add(1);
                warn!(
                    "Diagnostics endpoint start failed on {bind} (attempt {attempt}); retrying in {} ms: {err}",
                    DIAGNOSTICS_BIND_RETRY_INTERVAL.as_millis()
                );
            }
        }

        tokio::select! {
            _ = sleep(DIAGNOSTICS_BIND_RETRY_INTERVAL) => {}
            _ = shutdown_rx.changed() => {
                if *shutdown_rx.borrow() {
                    return Ok(());
                }
            }
        }
    }
}

async fn serve_diagnostics(
    listener: TcpListener,
    context: DiagnosticsContext,
    shutdown_rx: tokio::sync::watch::Receiver<bool>,
) -> Result<()> {
    let mut shutdown_rx = shutdown_rx;
    loop {
        tokio::select! {
            _ = shutdown_rx.changed() => {
                if *shutdown_rx.borrow() {
                    info!("Diagnostics server received shutdown signal");
                    break;
                }
            }
            result = listener.accept() => {
                let (stream, _remote_addr) = result
                    .map_err(|e| DaemonError::Network(format!("diagnostics accept failed: {e}")))?;

                let context = context.clone();
                tokio::spawn(async move {
                    if let Err(err) = handle_connection(stream, context).await {
                        debug!("diagnostics request failed: {err}");
                    }
                });
            }
        }
    }
    Ok(())
}

async fn handle_connection(mut stream: TcpStream, context: DiagnosticsContext) -> Result<()> {
    let mut buffer = [0u8; 1024];
    let n = timeout(Duration::from_secs(3), stream.read(&mut buffer))
        .await
        .map_err(|_| DaemonError::Network("diagnostics request timed out".to_string()))?
        .map_err(|e| DaemonError::Network(format!("diagnostics read failed: {e}")))?;

    let request = String::from_utf8_lossy(&buffer[..n]);
    // Native clients only (Flutter / tray / CLI): no browser origin is ever
    // allowed. No web origin is trusted, so CORS headers are never emitted.
    let cors_origin = no_browser_cors(&request);
    let (method, target) = request
        .lines()
        .next()
        .and_then(|line| {
            let mut parts = line.split_whitespace();
            match (parts.next(), parts.next()) {
                (Some(method), Some(path)) => Some((method, path)),
                _ => None,
            }
        })
        .unwrap_or(("GET", "/"));
    let (path, query) = split_request_target(target);

    let public = is_public_endpoint(method, path);
    let authenticated = auth_matches(context.auth_token.as_deref(), bearer_token(&request));
    if !public && !authenticated {
        write_unauthorized(&mut stream, cors_origin).await?;
        return Ok(());
    }

    // A valid session secret does not turn an unsupported method/path pair
    // into an operation. Keep that distinction explicit for callers: 401 is
    // authentication failure, 403 is an authenticated but disallowed action.
    if authenticated && !is_supported_endpoint(method, path) {
        write_response(&mut stream, 403, "text/plain", "forbidden\n", cors_origin).await?;
        return Ok(());
    }

    if method == "GET" {
        if let Some(peer_id) = path.strip_prefix("/status/peer/") {
            if peer_id.is_empty() || peer_id.contains('/') {
                write_response(&mut stream, 400, "text/plain", "invalid peer id\n", cors_origin)
                    .await?;
                return Ok(());
            }
            match timeout(DIAGNOSTICS_SNAPSHOT_TIMEOUT, build_peer_scoped_snapshot(context, peer_id)).await {
                Ok(snapshot) => {
                    let status = if snapshot.peer.is_some() { 200 } else { 404 };
                    let body = serde_json::to_string_pretty(&snapshot)?;
                    write_response(&mut stream, status, "application/json", &body, cors_origin)
                        .await?;
                }
                Err(_) => {
                    let body = diagnostics_snapshot_timeout_body();
                    write_response(&mut stream, 503, "application/json", &body, cors_origin)
                        .await?;
                }
            }
            return Ok(());
        }
    }

    match (method, path) {
        ("GET", "/health") => {
            write_response(&mut stream, 200, "text/plain", "ok\n", cors_origin).await?
        }
        ("GET", "/status.version") => {
            let body = serde_json::json!({
                "version": env!("CARGO_PKG_VERSION"),
                "name": "p2wlan-daemon",
                "build": crate::build_info::current(),
            })
            .to_string();
            write_response(&mut stream, 200, "application/json", &body, cors_origin).await?;
        }
        ("GET", "/status.runtime") => {
            let snapshot = build_runtime_snapshot(context).await;
            let body = serde_json::to_string_pretty(&snapshot)?;
            write_response(&mut stream, 200, "application/json", &body, cors_origin).await?;
        }
        ("GET", "/status") => {
            match timeout(DIAGNOSTICS_SNAPSHOT_TIMEOUT, build_snapshot(context)).await {
                Ok(snapshot) => {
                    let body = serde_json::to_string_pretty(&StatusResponse::from_snapshot(snapshot))?;
                    write_response(&mut stream, 200, "application/json", &body, cors_origin)
                        .await?;
                }
                Err(_) => {
                    let body = diagnostics_snapshot_timeout_body();
                    write_response(&mut stream, 503, "application/json", &body, cors_origin)
                        .await?;
                }
            }
        }
        ("POST", "/speedtest") => {
            match run_speedtest_from_query(context, query).await {
                Ok(result) => {
                    let body = serde_json::to_string_pretty(&result)?;
                    write_response(&mut stream, 200, "application/json", &body, cors_origin)
                        .await?;
                }
                Err(message) => {
                    let status = speedtest_error_status(&message);
                    let body = serde_json::json!({ "error": message }).to_string();
                    write_response(&mut stream, status, "application/json", &body, cors_origin)
                        .await?;
                }
            }
        }
        ("POST", "/shutdown") => {
            write_response(
                &mut stream,
                200,
                "text/plain",
                "shutting down\n",
                cors_origin,
            )
            .await?;
            let _ = context.shutdown_tx.send(true);
        }
        ("GET", "/routes") => {
            let body = serde_json::to_string_pretty(&describe_overlay_routes(&context))?;
            write_response(&mut stream, 200, "application/json", &body, cors_origin).await?;
        }
        ("POST", "/routes/verify") => {
            // Read-only: observe the live system routing table without changing it.
            let body = serde_json::to_string_pretty(&describe_overlay_routes(&context))?;
            write_response(&mut stream, 200, "application/json", &body, cors_origin).await?;
        }
        ("POST", "/routes/repair") => {
            // Repairs missing/conflicting routes only; never restarts the daemon,
            // the TUN, or peer sessions. `changed` is true only when the route
            // actually transitioned to `Installed`; a repair that ends in
            // Missing/Conflict/Unknown returns a non-2xx status so the caller
            // never sees a false success.
            let cidr = context.config.network.cidr.clone();
            let before = context.route_manager.describe_overlay_route(&cidr);
            let after = context.route_manager.repair_overlay_route(&cidr);
            let (status, body) = route_repair_report(before, after);
            let body = serde_json::to_string_pretty(&body)?;
            write_response(&mut stream, status, "application/json", &body, cors_origin).await?;
        }
        ("GET", "/events") => {
            let since = query_param(query, "since")
                .and_then(|v| v.parse::<u64>().ok())
                .unwrap_or(0);
            let events = context
                .status_events
                .wait_or_poll(since, Duration::from_secs(25))
                .await;
            let body = serde_json::to_string_pretty(&EventsResponse::new(
                context.status_events.current_seq(),
                events,
            ))?;
            write_response(&mut stream, 200, "application/json", &body, cors_origin).await?;
        }
        ("GET", "/peers") => {
            let cursor = query_param(query, "cursor");
            let limit = query_param(query, "limit")
                .and_then(|v| v.parse::<usize>().ok())
                .unwrap_or(100)
                .clamp(1, 1000);
            let all = context.peers.diagnostics().await;
            let total = all.len();
            let start = match cursor.as_ref() {
                Some(cursor) => all
                    .iter()
                    .position(|p| p.node_id > *cursor)
                    .unwrap_or(all.len()),
                None => 0,
            };
            let page: Vec<_> = all.iter().skip(start).take(limit).cloned().collect();
            let next_cursor = page.last().map(|p| p.node_id.clone());
            let body = serde_json::to_string_pretty(&PeersPageResponse::new(
                page,
                total,
                cursor,
                next_cursor,
            ))?;
            write_response(&mut stream, 200, "application/json", &body, cors_origin).await?;
        }
        ("GET", "/logs/tail") => {
            let lines = query_param(query, "lines")
                .and_then(|v| v.parse::<usize>().ok())
                .unwrap_or(120)
                .clamp(1, 1000);
            let max_bytes = query_param(query, "max_bytes")
                .and_then(|v| v.parse::<u64>().ok())
                .unwrap_or(262144)
                .clamp(4096, 2 * 1024 * 1024);
            let body = bounded_log_tail(&context.log_path, lines, max_bytes).await;
            let (status, text) = match body {
                Ok(text) => (200, text),
                Err(reason) if reason.contains("no log file") => {
                    (404, format!("error: {reason}\n"))
                }
                Err(reason) => (500, format!("error: {reason}\n")),
            };
            write_response(&mut stream, status, "text/plain", &text, cors_origin).await?;
        }
        _ => {
            warn!("Unknown diagnostics path requested: {path}");
            write_response(&mut stream, 404, "text/plain", "not found\n", cors_origin).await?;
        }
    }

    Ok(())
}

fn diagnostics_snapshot_timeout_body() -> String {
    serde_json::json!({
        "error": "diagnostics snapshot timed out",
        "reason_code": "status_snapshot_timeout"
    })
    .to_string()
}

fn split_request_target(target: &str) -> (&str, Option<&str>) {
    match target.split_once('?') {
        Some((path, query)) => (path, Some(query)),
        None => (target, None),
    }
}

/// Authoritative overlay-route state for `/routes` and `/routes/verify`.
/// Reports the TUN interface, configured MTU, and the live system-route state
/// for the overlay CIDR — computed from the routing table, never inferred.
fn describe_overlay_routes(context: &DiagnosticsContext) -> RoutesResponse {
    let cidr = context.config.network.cidr.clone();
    let obs = context.route_manager.describe_overlay_route(&cidr);
    let healthy = obs.state == crate::route::RouteState::Installed;
    let conflict_count = usize::from(obs.state == crate::route::RouteState::Conflict);
    let entries = vec![RouteEntryResponse {
        cidr: obs.cidr,
        expected_interface: obs.expected_interface.clone(),
        actual_interface: obs.actual_interface,
        state: obs.state,
        owned: obs.owned,
    }];
    RoutesResponse::new(
        obs.expected_interface,
        context.config.network.mtu,
        healthy,
        conflict_count,
        entries,
    )
}

/// Compute the `/routes/repair` report and HTTP status from the before/after
/// route observations. `changed` is only true when the route actually
/// transitioned to `Installed`; any repair that ends in `Missing`, `Conflict`,
/// or `Unknown` is a failure and maps to a non-2xx status so the UI can never
/// present a false success. `attempted` records whether a change was attempted.
fn route_repair_report(
    before: crate::route::RouteObservation,
    after: crate::route::RouteObservation,
) -> (u16, RouteRepairResponse) {
    use crate::route::RouteState;
    let attempted = matches!(before.state, RouteState::Missing | RouteState::Conflict);
    let changed = before.state != RouteState::Installed && after.state == RouteState::Installed;
    let (status, reason) = match after.state {
        RouteState::Installed => (200, "installed"),
        RouteState::Missing => (409, "add_failed"),
        RouteState::Conflict => (409, "conflict_remains"),
        RouteState::Unknown => (503, "state_unknown"),
    };
    (
        status,
        RouteRepairResponse::new(
            after.cidr,
            changed,
            attempted,
            before.state.as_str().to_string(),
            after.state.as_str().to_string(),
            reason.to_string(),
        ),
    )
}

/// The diagnostics endpoint is loopback-bound and consumed exclusively by
/// native clients (Flutter / tray / CLI), which do not send an `Origin` header.
/// No browser origin is trusted and no `Access-Control-Allow-Origin` header is
/// ever emitted.
fn no_browser_cors(_request: &str) -> Option<&str> {
    None
}

fn is_public_endpoint(method: &str, path: &str) -> bool {
    method == "GET" && matches!(path, "/health" | "/status.version")
}

fn is_supported_endpoint(method: &str, path: &str) -> bool {
    match (method, path) {
        ("GET", "/health" | "/status.version" | "/status.runtime" | "/status")
        | ("GET", "/routes" | "/events" | "/peers" | "/logs/tail")
        | ("POST", "/speedtest" | "/shutdown" | "/routes/verify" | "/routes/repair") => {
            true
        }
        ("GET", path) if path.starts_with("/status/peer/") => true,
        _ => false,
    }
}

async fn write_unauthorized(stream: &mut TcpStream, cors_origin: Option<&str>) -> Result<()> {
    write_response_with_headers(
        stream,
        401,
        "text/plain",
        "unauthorized\n",
        cors_origin,
        "WWW-Authenticate: Bearer\r\n",
    )
    .await
}

/// Extract a `Bearer <token>` value from the request's `Authorization` header,
/// if present.
fn bearer_token(request: &str) -> Option<&str> {
    request.lines().find_map(|line| {
        let (name, value) = line.split_once(':')?;
        if !name.eq_ignore_ascii_case("authorization") {
            return None;
        }
        let value = value.trim();
        value
            .strip_prefix("Bearer ")
            .or_else(|| value.strip_prefix("bearer "))
            .map(str::trim)
    })
}

/// Bounded tail of the daemon's own log file: read at most `max_bytes` from the
/// end and return the last `lines` complete lines. Returns `Err("no log file
/// configured")` when the operator did not set `--log-file`.
async fn bounded_log_tail(
    log_path: &Option<std::path::PathBuf>,
    lines: usize,
    max_bytes: u64,
) -> std::result::Result<String, String> {
    let path = log_path
        .as_ref()
        .ok_or_else(|| "no log file configured".to_string())?;
    let metadata = tokio::fs::metadata(path)
        .await
        .map_err(|e| format!("failed to stat log file: {e}"))?;
    let len = metadata.len();
    if len == 0 {
        return Ok(String::new());
    }
    let start = len.saturating_sub(max_bytes);
    let mut file = tokio::fs::File::open(path)
        .await
        .map_err(|e| format!("failed to open log file: {e}"))?;
    let mut buf = Vec::with_capacity((len - start) as usize);
    if start > 0 {
        use tokio::io::AsyncSeekExt;
        file.seek(std::io::SeekFrom::Start(start))
            .await
            .map_err(|e| format!("failed to seek log file: {e}"))?;
    }
    file.read_to_end(&mut buf)
        .await
        .map_err(|e| format!("failed to read log file: {e}"))?;
    let text = String::from_utf8_lossy(&buf);
    let tail: Vec<&str> = text.lines().rev().take(lines).collect();
    Ok(tail.into_iter().rev().collect::<Vec<_>>().join("\n"))
}

fn speedtest_error_status(message: &str) -> u16 {
    if message.contains("missing") || message.contains("invalid") || message.contains("local virtual IP") {
        400
    } else if message.contains("offline")
        || message.contains("confirmed direct")
        || message.contains("current catalog")
    {
        409
    } else {
        503
    }
}
