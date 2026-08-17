#[tokio::main]
async fn main() -> p2pnet_daemon::Result<()> {
    // Parse arguments BEFORE any side effects (including logging setup)
    // This guarantees --help and --version exit cleanly without side effects.
    let cli = Cli::parse();

    if let Err(e) = validate_cli(&cli) {
        eprintln!("Configuration Error: {}", e);
        std::process::exit(1);
    }

    // Resolve this before any generated config is saved.  The token file keeps
    // credentials out of `ps`, shell history, and the audited daemon command
    // line. It is the only supported way to supply a control-plane token (the
    // old `--token` flag was removed).
    let token_file_value = if let Some(path) = cli.token_file.as_ref() {
        Some(read_launch_token_file(path)?)
    } else if cli.token_stdin {
        Some(read_launch_token_stdin()?)
    } else {
        None
    };

    // --build-info must print PURE JSON on stdout before any logging is
    // initialized, so build scripts and CI can parse it verbatim.
    if cli.build_info {
        println!(
            "{}",
            serde_json::to_string_pretty(p2pnet_daemon::build_info::current()).map_err(|e| {
                DaemonError::Config(format!("failed to serialize build info: {e}"))
            })?
        );
        return Ok(());
    }

    // Initialize logging
    let env_filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info"));
    if let Some(ref log_file) = cli.log_file {
        if let Some(parent) = log_file.parent() {
            std::fs::create_dir_all(parent).map_err(|e| {
                DaemonError::Config(format!(
                    "failed to create log directory {}: {e}",
                    parent.display()
                ))
            })?;
        }
        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(log_file)
            .map_err(|e| {
                DaemonError::Config(format!(
                    "failed to open log file {}: {e}",
                    log_file.display()
                ))
            })?;
        tracing_subscriber::fmt()
            .with_env_filter(env_filter)
            .with_ansi(false)
            .with_writer(move || {
                file.try_clone()
                    .expect("failed to clone daemon log file handle")
            })
            .init();
    } else {
        // When stdout is redirected (harness logs, service managers), emit
        // plain text: ANSI escape codes corrupt line-oriented parsers that
        // grep `re.match`-style at the start of a log line.
        use std::io::IsTerminal;
        tracing_subscriber::fmt()
            .with_env_filter(env_filter)
            .with_ansi(std::io::stdout().is_terminal())
            .init();
    }

    info!("P2WLAN daemon starting...");
    info!("Platform: {}", std::env::consts::OS);

    // Check for --init flag (generate new config)
    if cli.init {
        let mut config = Config::generate_default(cli.control_url(), cli.network_id())?;
        apply_cli_overrides(&mut config, &cli);
        if let Some(ref token) = token_file_value {
            config.control.auth_token = token.clone();
        }
        let config_path = &cli.config;
        config.config_path = Some(config_path.clone());
        let mut persisted = config.clone();
        if token_file_value.is_some() {
            // A one-time launch credential is process input, never daemon
            // configuration. Persist an empty field and keep the real value
            // only in the in-memory runtime config.
            persisted.control.auth_token.clear();
        }
        persisted.save_to_file(config_path)?;
        info!("Config saved to {}", config_path.display());
        info!("Node ID: {}", config.node.node_id);
        return Ok(());
    }

    // Load config
    let config_path = &cli.config;

    let config = if config_path.exists() {
        match Config::load_from_file(config_path) {
            Ok(mut c) => {
                info!("Loaded config from {}", config_path.display());
                c.config_path = Some(config_path.clone());
                c
            }
            Err(e) => {
                error!("Failed to load config: {}", e);
                info!("Use --init to generate a new config");
                return Err(e);
            }
        }
    } else if cli.status {
        Config::generate_default("http://127.0.0.1", "default")?
    } else {
        info!("No config file found. Generating default config...");
        let mut config = Config::generate_default(cli.control_url(), cli.network_id())?;
        apply_cli_overrides(&mut config, &cli);
        if let Some(ref token) = token_file_value {
            config.control.auth_token = token.clone();
        }
        config.config_path = Some(config_path.clone());
        let mut persisted = config.clone();
        if token_file_value.is_some() {
            persisted.control.auth_token.clear();
        }
        persisted.save_to_file(config_path)?;
        info!("Saved default config to {}", config_path.display());
        config
    };

    let mut config = config;
    apply_cli_overrides(&mut config, &cli);
    if let Some(ref token) = token_file_value {
        config.control.auth_token = token.clone();
    }
    // Expose the operator-configured log file to the diagnostics server so
    // `GET /logs/tail` can read it with a bounded tail. In-process only; never
    // persisted to the config file.
    config.diagnostics.log_path = cli.log_file.clone();

    if cli.status {
        print_status(&config, &cli, config_path).await?;
        return Ok(());
    }

    // Keep one owner for the TUN, control session, and UDP socket set associated
    // with this device identity. A duplicate daemon can consume the other
    // process's offer/answer signals and invalidate authenticated probe MACs.
    let instance_lock = DaemonInstanceLock::acquire(config_path)?;
    info!(
        "Acquired daemon instance lock at {}",
        instance_lock.path.display()
    );

    // The instance lock must be held before a diagnostics session file is
    // refreshed. A second daemon therefore cannot overwrite or remove the
    // first daemon's active session secret.
    let _diagnostics_auth = DiagnosticsAuthGuard::prepare(&mut config, config_path)?;

    info!("Node ID: {}", config.node.node_id);
    info!("Network: {}", config.network.network_id);

    // Create and run the daemon with a shared shutdown signal.
    let mut daemon = Daemon::new(config);
    let shutdown_tx = daemon.shutdown_sender();

    // Graceful shutdown: wait for SIGINT/SIGTERM or daemon exit.
    // Pin the join future so we can select without moving the handle twice.
    let mut daemon_handle = tokio::spawn(async move { daemon.run().await });

    let shutdown_reason = {
        #[cfg(unix)]
        {
            let mut sigterm =
                tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
                    .expect("failed to install SIGTERM handler");
            tokio::select! {
                result = &mut daemon_handle => {
                    match result {
                        Ok(Ok(())) => {
                            info!("Daemon exited cleanly");
                            None
                        }
                        Ok(Err(e)) => {
                            error!("Daemon exited with error: {e}");
                            return Err(e);
                        }
                        Err(e) => {
                            error!("Daemon task failed: {e}");
                            return Err(DaemonError::TaskCrash(e.to_string()));
                        }
                    }
                }
                _ = tokio::signal::ctrl_c() => {
                    info!("Received SIGINT, shutting down...");
                    Some("SIGINT")
                }
                _ = sigterm.recv() => {
                    info!("Received SIGTERM, shutting down...");
                    Some("SIGTERM")
                }
            }
        }
        #[cfg(not(unix))]
        {
            tokio::select! {
                result = &mut daemon_handle => {
                    match result {
                        Ok(Ok(())) => {
                            info!("Daemon exited cleanly");
                            None
                        }
                        Ok(Err(e)) => {
                            error!("Daemon exited with error: {e}");
                            return Err(e);
                        }
                        Err(e) => {
                            error!("Daemon task failed: {e}");
                            return Err(DaemonError::TaskCrash(e.to_string()));
                        }
                    }
                }
                _ = tokio::signal::ctrl_c() => {
                    info!("Received SIGINT, shutting down...");
                    Some("SIGINT")
                }
            }
        }
    };

    if let Some(reason) = shutdown_reason {
        let _ = shutdown_tx.send(true);
        match tokio::time::timeout(std::time::Duration::from_secs(10), daemon_handle).await {
            Ok(Ok(Ok(()))) => info!("Daemon exited cleanly after {reason}"),
            Ok(Ok(Err(e))) => {
                error!("Daemon exited with error after {reason}: {e}");
                return Err(e);
            }
            Ok(Err(e)) => {
                error!("Daemon task failed after {reason}: {e}");
                return Err(DaemonError::TaskCrash(e.to_string()));
            }
            Err(_) => {
                warn!("Timed out waiting for daemon to stop after {reason}");
            }
        }
    }

    info!("Shutdown complete.");
    Ok(())
}

async fn print_status(
    config: &Config,
    cli: &Cli,
    config_path: &std::path::Path,
) -> p2pnet_daemon::Result<()> {
    let url = cli
        .diagnostics_url
        .clone()
        .unwrap_or_else(|| format!("http://{}/status", config.diagnostics.bind));

    let auth_dir = cli
        .log_file
        .as_ref()
        .and_then(|path| path.parent().map(std::path::Path::to_path_buf))
        .or_else(|| config_path.parent().map(std::path::Path::to_path_buf))
        .unwrap_or_else(|| std::path::PathBuf::from("."));
    let auth_path = auth_dir.join("p2wlan-daemon.diag-auth");
    let client = reqwest::Client::builder()
        .no_proxy()
        .build()
        .map_err(|error| DaemonError::Network(format!("failed to create diagnostics client: {error}")))?;

    let body = 'request: {
        for attempt in 0..2 {
            let token = std::fs::read_to_string(&auth_path)
                .map_err(|_| DaemonError::Network("diagnostics session token file is missing; daemon session may have changed".to_string()))?;
            let token = token.trim();
            if token.is_empty() {
                return Err(DaemonError::Network(
                    "diagnostics session token file is empty; daemon session may have changed"
                        .to_string(),
                ));
            }
            let response = client
                .get(&url)
                .bearer_auth(token)
                .send()
                .await
                .map_err(|error| {
                    DaemonError::Network(format!("failed to query diagnostics at {url}: {error}"))
                })?;
            if response.status() == reqwest::StatusCode::UNAUTHORIZED && attempt == 0 {
                continue;
            }
            let status = response.status();
            let body = response.text().await.map_err(|error| {
                DaemonError::Network(format!(
                    "failed to read diagnostics response from {url}: {error}"
                ))
            })?;
            if !status.is_success() {
                return Err(DaemonError::Network(format!(
                    "diagnostics endpoint {url} returned HTTP {status}: {body}"
                )));
            }
            break 'request body;
        }
        return Err(DaemonError::Network(
            "diagnostics session changed; daemon returned HTTP 401 twice".to_string(),
        ));
    };

    match serde_json::from_str::<serde_json::Value>(&body) {
        Ok(value) => println!("{}", serde_json::to_string_pretty(&value)?),
        Err(_) => println!("{body}"),
    }
    Ok(())
}

const MAX_LAUNCH_TOKEN_BYTES: usize = 16 * 1024;

fn read_launch_token_file(path: &std::path::Path) -> p2pnet_daemon::Result<String> {
    let result = (|| -> std::io::Result<String> {
        restrict_auth_file(path)?;
        let metadata = std::fs::metadata(path)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            if metadata.permissions().mode() & 0o077 != 0 {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::PermissionDenied,
                    "launch token file is not owner-only",
                ));
            }
        }
        if metadata.len() > MAX_LAUNCH_TOKEN_BYTES as u64 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "launch token file is too large",
            ));
        }
        let value = std::fs::read_to_string(path)?;
        let token = value.trim();
        if token.is_empty() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "launch token file is empty",
            ));
        }
        Ok(token.to_string())
    })();
    let remove_result = std::fs::remove_file(path);
    if let Err(error) = remove_result {
        return Err(DaemonError::Config(format!(
            "failed to remove one-time launch token file {}: {error}",
            path.display()
        )));
    }
    result.map_err(|error| {
        DaemonError::Config(format!(
            "failed to read one-time launch token file {}: {error}",
            path.display()
        ))
    })
}

fn read_launch_token_stdin() -> p2pnet_daemon::Result<String> {
    use std::io::Read;
    let mut bytes = Vec::with_capacity(MAX_LAUNCH_TOKEN_BYTES + 1);
    let read_result = std::io::stdin()
        .take((MAX_LAUNCH_TOKEN_BYTES + 1) as u64)
        .read_to_end(&mut bytes);
    let result = read_result
        .map_err(|error| DaemonError::Config(format!("failed to read token from stdin: {error}")))
        .and_then(|size| {
            if size > MAX_LAUNCH_TOKEN_BYTES {
                return Err(DaemonError::Config(
                    "stdin launch token exceeds the 16 KiB limit".to_string(),
                ));
            }
            let value = String::from_utf8(std::mem::take(&mut bytes))
                .map_err(|_| DaemonError::Config("stdin launch token is not valid UTF-8".to_string()))?;
            let token = value.trim();
            if token.is_empty() {
                return Err(DaemonError::Config("stdin launch token is empty".to_string()));
            }
            Ok(token.to_string())
        });
    bytes.fill(0);
    result
}
