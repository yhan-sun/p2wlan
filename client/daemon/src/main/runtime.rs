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
    let token_file_value = cli
        .token_file
        .as_ref()
        .map(|path| {
            std::fs::read_to_string(path)
                .map_err(|e| DaemonError::Config(format!("failed to read token file {}: {e}", path.display())))
                .and_then(|value| {
                    let token = value.trim();
                    if token.is_empty() {
                        Err(DaemonError::Config(format!(
                            "token file {} is empty",
                            path.display()
                        )))
                    } else {
                        Ok(token.to_string())
                    }
                })
        })
        .transpose()?;

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
        config.save_to_file(config_path)?;
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
        config.save_to_file(config_path)?;
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
        print_status(&config, &cli).await?;
        return Ok(());
    }

    // Generate the per-process diagnostics mutation token and write it to a
    // 0600 file for local callers (Flutter / tray). It never appears on the
    // command line or in the persisted config, and it is removed on graceful
    // shutdown below.
    let diagnostics_auth_path = prepare_diagnostics_auth(&mut config, config_path);

    // Keep one owner for the TUN, control session, and UDP socket set associated
    // with this device identity. A duplicate daemon can consume the other
    // process's offer/answer signals and invalidate authenticated probe MACs.
    let instance_lock = DaemonInstanceLock::acquire(config_path)?;
    info!(
        "Acquired daemon instance lock at {}",
        instance_lock.path.display()
    );

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
    if let Some(path) = diagnostics_auth_path {
        remove_diagnostics_auth(&path);
    }
    Ok(())
}

/// Generate a fresh random per-process diagnostics mutation token and write it
/// to a 0600 file next to the daemon's log file (falling back to the config
/// directory). Returns the file path for shutdown cleanup, or `None` when the
/// diagnostics endpoint is disabled.
fn prepare_diagnostics_auth(config: &mut Config, config_path: &Path) -> Option<PathBuf> {
    if !config.diagnostics.enabled {
        return None;
    }
    use rand::RngCore;
    let mut bytes = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut bytes);
    let token = hex::encode(bytes);
    config.diagnostics.auth_token = Some(token.clone());

    let dir = config
        .diagnostics
        .log_path
        .as_ref()
        .and_then(|log| log.parent().map(Path::to_path_buf))
        .or_else(|| config_path.parent().map(Path::to_path_buf))
        .unwrap_or_else(|| PathBuf::from("."));
    let path = dir.join("p2wlan-daemon.diag-auth");

    let result = std::fs::create_dir_all(&dir)
        .and_then(|_| {
            let mut file = std::fs::File::create(&path)?;
            file.write_all(token.as_bytes())?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let mut perms = file.metadata()?.permissions();
                perms.set_mode(0o600);
                file.set_permissions(perms)?;
            }
            Ok(())
        });
    match result {
        Ok(()) => {
            config.diagnostics.auth_token_path = Some(path.clone());
            info!(
                "Diagnostics mutation auth token written to {}",
                path.display()
            );
            Some(path)
        }
        Err(e) => {
            warn!(
                "Failed to write diagnostics auth token to {}: {e}; mutations will fail closed",
                path.display()
            );
            // Fail closed: no token file means the server rejects all POSTs.
            config.diagnostics.auth_token = None;
            None
        }
    }
}

/// Best-effort removal of the per-process diagnostics auth token file.
fn remove_diagnostics_auth(path: &Path) {
    match std::fs::remove_file(path) {
        Ok(()) => info!("Removed diagnostics auth token file {}", path.display()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => warn!(
            "Failed to remove diagnostics auth token file {}: {e}",
            path.display()
        ),
    }
}

async fn print_status(config: &Config, cli: &Cli) -> p2pnet_daemon::Result<()> {
    let url = cli
        .diagnostics_url
        .clone()
        .unwrap_or_else(|| format!("http://{}/status", config.diagnostics.bind));

    let res = reqwest::get(&url)
        .await
        .map_err(|e| DaemonError::Network(format!("failed to query diagnostics at {url}: {e}")))?;

    let status = res.status();
    let body = res.text().await.map_err(|e| {
        DaemonError::Network(format!(
            "failed to read diagnostics response from {url}: {e}"
        ))
    })?;

    if !status.is_success() {
        return Err(DaemonError::Network(format!(
            "diagnostics endpoint {url} returned HTTP {status}: {body}"
        )));
    }

    match serde_json::from_str::<serde_json::Value>(&body) {
        Ok(value) => println!("{}", serde_json::to_string_pretty(&value)?),
        Err(_) => println!("{body}"),
    }
    Ok(())
}
