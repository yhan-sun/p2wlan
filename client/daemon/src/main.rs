//! # P2PNet Daemon
//!
//! The main client daemon that runs the P2P virtual network.

use clap::Parser;
use p2pnet_daemon::{Config, Daemon, DaemonError};
use std::fs::OpenOptions;
use std::path::PathBuf;
use tracing::{error, info, warn};

#[derive(Parser, Debug, Clone)]
#[command(name = "p2pnet-daemon")]
#[command(version)]
#[command(about = "P2PNet client daemon", long_about = None)]
struct Cli {
    /// Run with default config or specify config file path
    #[arg(long, default_value = "p2pnet-config.json")]
    config: PathBuf,

    /// Generate a new config
    #[arg(long)]
    init: bool,

    /// Control plane server URL
    #[arg(long, default_value = "https://control.p2pnet.io")]
    control: String,

    /// Network ID to join or initialize
    #[arg(long, default_value = "default")]
    network: String,

    /// Query local runtime status
    #[arg(long)]
    status: bool,

    /// Override auth token
    #[arg(long)]
    token: Option<String>,

    /// Override interface name
    #[arg(long)]
    interface: Option<String>,

    /// Override virtual IP address
    #[arg(long)]
    address: Option<String>,

    /// Run in manual/offline mode (disable control-plane auto-assignment)
    #[arg(long)]
    manual: bool,

    /// Override subnet mask
    #[arg(long)]
    netmask: Option<String>,

    /// Override MTU
    #[arg(long)]
    mtu: Option<u32>,

    /// Override heartbeat interval (seconds)
    #[arg(long, name = "heartbeat-interval")]
    heartbeat_interval: Option<u64>,

    /// Override local UDP bind address
    #[arg(long, name = "udp-bind")]
    udp_bind: Option<String>,

    /// Override UDP advertised endpoint
    #[arg(long, name = "udp-advertise")]
    udp_advertise: Option<String>,

    /// Override STUN servers (comma-separated)
    #[arg(long)]
    stun: Option<String>,

    /// Override STUN timeout (ms)
    #[arg(long, name = "stun-timeout-ms")]
    stun_timeout_ms: Option<u64>,

    /// Override hole punch interval (ms)
    #[arg(long, name = "punch-interval-ms")]
    punch_interval_ms: Option<u64>,

    /// Override hole punch attempts
    #[arg(long, name = "punch-attempts")]
    punch_attempts: Option<u32>,

    /// Override keepalive interval (seconds)
    #[arg(long, name = "keepalive-interval-secs")]
    keepalive_interval_secs: Option<u64>,

    /// Override relay servers (comma-separated)
    #[arg(long)]
    relay: Option<String>,

    /// Override preferred relay regions (comma-separated)
    #[arg(long, name = "relay-regions")]
    relay_regions: Option<String>,

    /// Override relay selection timeout (ms)
    #[arg(long, name = "relay-selection-timeout-ms")]
    relay_selection_timeout_ms: Option<u64>,

    /// Override relay fallback timeout (ms)
    #[arg(long, name = "relay-fallback-timeout-ms")]
    relay_fallback_timeout_ms: Option<u64>,

    /// Override diagnostics bind address
    #[arg(long, name = "diagnostics-bind")]
    diagnostics_bind: Option<String>,

    /// Disable diagnostics endpoint
    #[arg(long, name = "diagnostics-disable")]
    diagnostics_disable: bool,

    /// Prefer relay path instead of direct UDP
    #[arg(long, name = "prefer-relay")]
    prefer_relay: bool,

    /// Prefer direct UDP path instead of relay fallback
    #[arg(long, name = "prefer-direct")]
    prefer_direct: bool,

    /// Override device name
    #[arg(long, name = "device-name")]
    device_name: Option<String>,

    /// Diagnostics URL to query status
    #[arg(long, name = "diagnostics-url")]
    diagnostics_url: Option<String>,

    /// Write daemon logs to a file instead of stderr/stdout
    #[arg(long, name = "log-file")]
    log_file: Option<PathBuf>,
}

fn validate_cli(cli: &Cli) -> std::result::Result<(), String> {
    // Validate control plane URL
    let control_url = match reqwest::Url::parse(&cli.control) {
        Ok(url) => url,
        Err(_) => return Err(format!("Invalid URL for --control: {}", cli.control)),
    };
    if control_url.scheme() != "http" && control_url.scheme() != "https" {
        return Err(format!(
            "Only http and https schemes are allowed for --control: {}",
            cli.control
        ));
    }
    if let Some(ref addr) = cli.address {
        if addr.parse::<std::net::Ipv4Addr>().is_err() {
            return Err(format!("Invalid IP address for --address: {}", addr));
        }
    }
    if let Some(ref mask) = cli.netmask {
        if mask.parse::<std::net::Ipv4Addr>().is_err() {
            return Err(format!("Invalid netmask: {}", mask));
        }
    }
    if let Some(mtu) = cli.mtu {
        if !(576..=65535).contains(&mtu) {
            return Err(format!("MTU must be between 576 and 65535, got {}", mtu));
        }
    }
    if let Some(ref bind) = cli.udp_bind {
        if bind.parse::<std::net::SocketAddr>().is_err() {
            return Err(format!(
                "Invalid SocketAddr for --udp-bind (expected IP:port): {}",
                bind
            ));
        }
    }
    if let Some(ref adv) = cli.udp_advertise {
        if adv.parse::<std::net::SocketAddr>().is_err() {
            return Err(format!(
                "Invalid SocketAddr for --udp-advertise (expected IP:port): {}",
                adv
            ));
        }
    }
    if let Some(ref dbind) = cli.diagnostics_bind {
        if dbind.parse::<std::net::SocketAddr>().is_err() {
            return Err(format!(
                "Invalid SocketAddr for --diagnostics-bind (expected IP:port): {}",
                dbind
            ));
        }
    }
    if let Some(ref stun) = cli.stun {
        for s in stun.split(',').map(str::trim).filter(|x| !x.is_empty()) {
            if !is_valid_stun_server_spec(s) {
                return Err(format!(
                    "Invalid STUN server in --stun (expected host:port or IP:port): {}",
                    s
                ));
            }
        }
    }
    if let Some(ref relay) = cli.relay {
        for r in relay.split(',').map(str::trim).filter(|x| !x.is_empty()) {
            let endpoint = match r.split_once('@') {
                Some((region, ep)) => {
                    if region.is_empty() {
                        return Err(format!("Empty region in relay spec '{}'", r));
                    }
                    ep
                }
                None => r,
            };
            if endpoint.parse::<std::net::SocketAddr>().is_err() {
                return Err(format!(
                    "Invalid Relay server endpoint in '{}' (expected [region@]IP:port): {}",
                    r, endpoint
                ));
            }
        }
    }
    if let Some(ref durl) = cli.diagnostics_url {
        let parsed = match reqwest::Url::parse(durl) {
            Ok(url) => url,
            Err(_) => return Err(format!("Invalid URL for --diagnostics-url: {}", durl)),
        };
        if parsed.scheme() != "http" && parsed.scheme() != "https" {
            return Err(format!(
                "Only http and https schemes are allowed for --diagnostics-url: {}",
                durl
            ));
        }
    }
    Ok(())
}

fn is_valid_stun_server_spec(value: &str) -> bool {
    let value = value.trim();
    if matches!(
        value.to_ascii_lowercase().as_str(),
        "none" | "off" | "false" | "clear" | "unset" | "disable" | "disabled"
    ) {
        return true;
    }
    if value.parse::<std::net::SocketAddr>().is_ok() {
        return true;
    }
    let Some((host, port)) = value.rsplit_once(':') else {
        return false;
    };
    !host.is_empty()
        && !host.contains(char::is_whitespace)
        && !host.contains('/')
        && !host.contains('@')
        && port.parse::<u16>().is_ok_and(|port| port > 0)
}

#[tokio::main]
async fn main() -> p2pnet_daemon::Result<()> {
    // Parse arguments BEFORE any side effects (including logging setup)
    // This guarantees --help and --version exit cleanly without side effects.
    let cli = Cli::parse();

    if let Err(e) = validate_cli(&cli) {
        eprintln!("Configuration Error: {}", e);
        std::process::exit(1);
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
        tracing_subscriber::fmt().with_env_filter(env_filter).init();
    }

    info!("P2PNet Daemon starting...");
    info!("Platform: {}", std::env::consts::OS);

    // Check for --init flag (generate new config)
    if cli.init {
        let mut config = Config::generate_default(&cli.control, &cli.network)?;
        apply_cli_overrides(&mut config, &cli);
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
        let mut config = Config::generate_default(&cli.control, &cli.network)?;
        apply_cli_overrides(&mut config, &cli);
        config.config_path = Some(config_path.clone());
        config.save_to_file(config_path)?;
        info!("Saved default config to {}", config_path.display());
        config
    };

    let mut config = config;
    apply_cli_overrides(&mut config, &cli);

    if cli.status {
        print_status(&config, &cli).await?;
        return Ok(());
    }

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

fn apply_cli_overrides(config: &mut Config, cli: &Cli) {
    if let Some(ref token) = cli.token {
        config.control.auth_token = token.clone();
    }
    if let Some(ref interface) = cli.interface {
        config.network.interface = interface.clone();
    }
    if let Some(ref address) = cli.address {
        config.network.virtual_ip = address.clone();
    }
    if cli.manual {
        config.network.manual = true;
    }
    if let Some(ref netmask) = cli.netmask {
        config.network.netmask = netmask.clone();
    }
    if let Some(mtu) = cli.mtu {
        config.network.mtu = mtu;
    }
    if let Some(interval) = cli.heartbeat_interval {
        config.control.heartbeat_interval_secs = interval;
    }
    if let Some(ref udp_bind) = cli.udp_bind {
        config.network.udp_bind = udp_bind.clone();
    }
    if let Some(ref udp_advertise) = cli.udp_advertise {
        config.network.udp_advertise = Some(udp_advertise.clone());
    }
    if let Some(ref stun_servers) = cli.stun {
        config.network.stun_servers = stun_servers
            .split(',')
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(ToString::to_string)
            .collect();
    }
    if let Some(timeout_ms) = cli.stun_timeout_ms {
        config.network.stun_timeout_ms = timeout_ms;
    }
    if let Some(interval_ms) = cli.punch_interval_ms {
        config.network.punch_interval_ms = interval_ms;
    }
    if let Some(attempts) = cli.punch_attempts {
        config.network.punch_attempts = attempts;
    }
    if let Some(interval_secs) = cli.keepalive_interval_secs {
        config.network.keepalive_interval_secs = interval_secs;
    }
    if let Some(ref relay_servers) = cli.relay {
        config.relay.servers = relay_servers
            .split(',')
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(ToString::to_string)
            .collect();
    }
    if let Some(ref preferred_regions) = cli.relay_regions {
        config.relay.preferred_regions = preferred_regions
            .split(',')
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(ToString::to_string)
            .collect();
    }
    if let Some(timeout_ms) = cli.relay_selection_timeout_ms {
        config.relay.selection_timeout_ms = timeout_ms;
    }
    if let Some(timeout_ms) = cli.relay_fallback_timeout_ms {
        config.relay.fallback_timeout_ms = timeout_ms;
    }
    if let Some(ref bind) = cli.diagnostics_bind {
        config.diagnostics.enabled = true;
        config.diagnostics.bind = bind.clone();
    }
    if cli.diagnostics_disable {
        config.diagnostics.enabled = false;
    }
    if cli.prefer_relay {
        config.relay.prefer_direct = false;
    }
    if cli.prefer_direct {
        config.relay.prefer_direct = true;
    }
    if let Some(ref name) = cli.device_name {
        config.node.device_name = name.clone();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn network_arguments_override_generated_config() {
        let mut config = Config::generate_default("http://127.0.0.1", "default").unwrap();
        let cli = Cli {
            config: PathBuf::from("p2pnet-config.json"),
            init: false,
            control: "http://127.0.0.1".to_string(),
            network: "default".to_string(),
            status: false,
            token: None,
            interface: None,
            address: None,
            manual: false,
            netmask: Some("255.255.255.255".to_string()),
            mtu: None,
            heartbeat_interval: None,
            udp_bind: None,
            udp_advertise: None,
            stun: None,
            stun_timeout_ms: None,
            punch_interval_ms: None,
            punch_attempts: None,
            keepalive_interval_secs: None,
            relay: Some("cn-east@127.0.0.1:8080,us-west@127.0.0.1:8081".to_string()),
            relay_regions: Some("cn-east,us-west".to_string()),
            relay_selection_timeout_ms: Some(750),
            relay_fallback_timeout_ms: None,
            diagnostics_bind: None,
            diagnostics_disable: false,
            prefer_relay: false,
            prefer_direct: false,
            device_name: None,
            diagnostics_url: None,
            log_file: None,
        };

        apply_cli_overrides(&mut config, &cli);

        assert_eq!(config.network.netmask, "255.255.255.255");
        assert_eq!(
            config.relay.servers,
            vec![
                "cn-east@127.0.0.1:8080".to_string(),
                "us-west@127.0.0.1:8081".to_string()
            ]
        );
        assert_eq!(config.relay.preferred_regions, vec!["cn-east", "us-west"]);
        assert_eq!(config.relay.selection_timeout_ms, 750);
    }

    #[test]
    fn test_validate_cli_invalid_cases() {
        // Create base Cli
        let base_cli = Cli {
            config: PathBuf::from("p2pnet-config.json"),
            init: false,
            control: "https://control.p2pnet.io".to_string(),
            network: "default".to_string(),
            status: false,
            token: None,
            interface: None,
            address: None,
            manual: false,
            netmask: None,
            mtu: None,
            heartbeat_interval: None,
            udp_bind: None,
            udp_advertise: None,
            stun: None,
            stun_timeout_ms: None,
            punch_interval_ms: None,
            punch_attempts: None,
            keepalive_interval_secs: None,
            relay: None,
            relay_regions: None,
            relay_selection_timeout_ms: None,
            relay_fallback_timeout_ms: None,
            diagnostics_bind: None,
            diagnostics_disable: false,
            prefer_relay: false,
            prefer_direct: false,
            device_name: None,
            diagnostics_url: None,
            log_file: None,
        };

        // 1. Invalid control URL
        let mut cli = base_cli.clone();
        cli.control = "not-a-url".to_string();
        assert!(validate_cli(&cli).is_err());

        // 2. Invalid address
        let mut cli = base_cli.clone();
        cli.address = Some("999.999.999.999".to_string());
        assert!(validate_cli(&cli).is_err());

        // 3. Invalid netmask
        let mut cli = base_cli.clone();
        cli.netmask = Some("bad-netmask".to_string());
        assert!(validate_cli(&cli).is_err());

        // 4. Invalid MTU
        let mut cli = base_cli.clone();
        cli.mtu = Some(100);
        assert!(validate_cli(&cli).is_err());

        // 5. Invalid udp-bind
        let mut cli = base_cli.clone();
        cli.udp_bind = Some("bad-bind".to_string());
        assert!(validate_cli(&cli).is_err());

        // 6. Invalid udp-advertise
        let mut cli = base_cli.clone();
        cli.udp_advertise = Some("bad:99999".to_string());
        assert!(validate_cli(&cli).is_err());

        // 7. Invalid relay server endpoint format
        let mut cli = base_cli.clone();
        cli.relay = Some("bad:99999".to_string());
        assert!(validate_cli(&cli).is_err());

        let mut cli = base_cli.clone();
        cli.relay = Some("cn-east@bad:99999".to_string());
        assert!(validate_cli(&cli).is_err());

        // 8. Empty region in relay spec
        let mut cli = base_cli.clone();
        cli.relay = Some("@127.0.0.1:8080".to_string());
        assert!(validate_cli(&cli).is_err());

        // 9. Invalid control scheme (non-http/https)
        let mut cli = base_cli.clone();
        cli.control = "ftp://127.0.0.1".to_string();
        assert!(validate_cli(&cli).is_err());

        // Valid cases should pass
        let mut cli = base_cli.clone();
        cli.control = "http://127.0.0.1:18080".to_string();
        cli.address = Some("10.20.0.2".to_string());
        cli.netmask = Some("255.255.255.0".to_string());
        cli.mtu = Some(1420);
        cli.udp_bind = Some("0.0.0.0:51820".to_string());
        cli.udp_advertise = Some("203.0.113.10:51820".to_string());
        cli.stun = Some("stun.l.google.com:19302,74.125.250.129:19302".to_string());
        cli.relay = Some("cn-east@127.0.0.1:8080,us-west@127.0.0.1:8081".to_string());
        assert!(validate_cli(&cli).is_ok());

        cli.stun = Some("not-a-stun-server".to_string());
        assert!(validate_cli(&cli).is_err());
    }

    #[test]
    fn test_clap_parsing() {
        use clap::Parser;

        // Verify valid parsing
        let parsed = Cli::try_parse_from([
            "p2pnet-daemon",
            "--config",
            "custom.json",
            "--control",
            "http://127.0.0.1:8080",
            "--network",
            "testnet",
            "--init",
        ]);
        assert!(parsed.is_ok());
        let cli = parsed.unwrap();
        assert_eq!(cli.config, PathBuf::from("custom.json"));
        assert_eq!(cli.control, "http://127.0.0.1:8080");
        assert_eq!(cli.network, "testnet");
        assert!(cli.init);

        // Verify version and help parse cleanly
        let parsed_help = Cli::try_parse_from(["p2pnet-daemon", "--help"]);
        assert!(parsed_help.is_err()); // Clap returns an Error of kind DisplayHelp
        assert_eq!(
            parsed_help.unwrap_err().kind(),
            clap::error::ErrorKind::DisplayHelp
        );

        let parsed_version = Cli::try_parse_from(["p2pnet-daemon", "--version"]);
        assert!(parsed_version.is_err());
        assert_eq!(
            parsed_version.unwrap_err().kind(),
            clap::error::ErrorKind::DisplayVersion
        );
    }
}
