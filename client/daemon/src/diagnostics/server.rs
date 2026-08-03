/// Run the local diagnostics HTTP endpoint until the listener fails.
pub async fn run_diagnostics_server(
    bind: String,
    context: DiagnosticsContext,
    shutdown_rx: tokio::sync::watch::Receiver<bool>,
) -> Result<()> {
    let listener = TcpListener::bind(&bind).await.map_err(|e| {
        DaemonError::Network(format!(
            "failed to bind diagnostics endpoint at {bind}: {e}"
        ))
    })?;
    let local_addr = listener
        .local_addr()
        .map_err(|e| DaemonError::Network(format!("failed to read diagnostics local addr: {e}")))?;
    info!("Diagnostics endpoint listening at http://{local_addr}/status");

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
    mut shutdown_rx: tokio::sync::watch::Receiver<bool>,
) -> Result<()> {
    let mut attempt = 0usize;
    loop {
        if *shutdown_rx.borrow() {
            return Ok(());
        }

        match run_diagnostics_server(bind.clone(), context.clone(), shutdown_rx.clone()).await {
            Ok(()) => return Ok(()),
            Err(err) => {
                if *shutdown_rx.borrow() {
                    return Ok(());
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
    let cors_origin = allowed_cors_origin(&request);
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

    match (method, path) {
        ("GET", "/health") => {
            write_response(&mut stream, 200, "text/plain", "ok\n", cors_origin).await?
        }
        ("GET", "/status") => {
            let snapshot = build_snapshot(context).await;
            let body = serde_json::to_string_pretty(&snapshot)?;
            write_response(&mut stream, 200, "application/json", &body, cors_origin).await?;
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
        _ => {
            warn!("Unknown diagnostics path requested: {path}");
            write_response(&mut stream, 404, "text/plain", "not found\n", cors_origin).await?;
        }
    }

    Ok(())
}

fn split_request_target(target: &str) -> (&str, Option<&str>) {
    match target.split_once('?') {
        Some((path, query)) => (path, Some(query)),
        None => (target, None),
    }
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

fn allowed_cors_origin(request: &str) -> Option<&str> {
    request.lines().find_map(|line| {
        let (name, value) = line.split_once(':')?;
        if !name.eq_ignore_ascii_case("origin") {
            return None;
        }
        let origin = value.trim();
        matches!(
            origin,
            "http://localhost:14327"
                | "http://127.0.0.1:14327"
                | "http://localhost:1420"
                | "http://127.0.0.1:1420"
        )
        .then_some(origin)
    })
}
