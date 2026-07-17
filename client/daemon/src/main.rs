//! # P2PNet Daemon
//!
//! The main client daemon that runs the P2P virtual network.
//!
//! ## Current Status (Phase 5)
//!
//! All subsystems integrated:
//! - TUN virtual interface creation and packet I/O
//! - WireGuard encryption & handshake
//! - NAT traversal (STUN / ICE / hole punching)
//! - Relay fallback (DERP-like)
//! - Control plane client (signaling, peer discovery)
//! - Peer connection management
//! - ACL (access control)
//! - DNS resolver
//! - Port mapping (FRP-like)
//!
//! ## Usage
//!
//! ```sh
//! # Run with default config
//! p2pnet-daemon --config config.json
//!
//! # Generate a new config
//! p2pnet-daemon --init --control https://control.p2pnet.io --network net123
//!
//! # Run as Administrator/root
//! p2pnet-daemon --interface p2pnet0 --address 10.20.0.1 --netmask 255.255.255.0 --mtu 1420 --udp-bind 0.0.0.0:51820 --udp-advertise 203.0.113.10:51820 --stun 1.1.1.1:3478 --relay cn-shanghai@198.51.100.10:8080,cn-hongkong@203.0.113.20:8080 --relay-regions cn-shanghai,cn-hongkong --diagnostics-bind 127.0.0.1:39277 --relay-fallback-timeout-ms 5000 --punch-attempts 10
//!
//! # Query local runtime status
//! p2pnet-daemon --status --diagnostics-url http://127.0.0.1:39277/status
//! ```

use p2pnet_daemon::{Config, Daemon, DaemonError};
use tracing::{error, info};

#[tokio::main]
async fn main() -> p2pnet_daemon::Result<()> {
    // Initialize logging
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    info!("P2PNet Daemon starting...");
    info!("Platform: {}", std::env::consts::OS);

    // Parse arguments
    let args: Vec<String> = std::env::args().collect();
    let status_requested = args.iter().any(|a| a == "--status");

    // Check for --init flag (generate new config)
    if args.iter().any(|a| a == "--init") {
        let control_url = args
            .iter()
            .position(|a| a == "--control")
            .and_then(|i| args.get(i + 1))
            .map(|s| s.as_str())
            .unwrap_or("https://control.p2pnet.io");

        let network_id = args
            .iter()
            .position(|a| a == "--network")
            .and_then(|i| args.get(i + 1))
            .map(|s| s.as_str())
            .unwrap_or("default");

        let mut config = Config::generate_default(control_url, network_id)?;
        apply_arg_overrides(&mut config, &args);
        let config_path = std::path::Path::new("p2pnet-config.json");
        config.save_to_file(config_path)?;
        info!("Config saved to {}", config_path.display());
        info!("Node ID: {}", config.node.node_id);
        return Ok(());
    }

    // Load config
    let config_path = args
        .iter()
        .position(|a| a == "--config")
        .and_then(|i| args.get(i + 1))
        .map(|s| std::path::PathBuf::from(s))
        .unwrap_or_else(|| std::path::PathBuf::from("p2pnet-config.json"));

    let config = if config_path.exists() {
        match Config::load_from_file(&config_path) {
            Ok(c) => {
                info!("Loaded config from {}", config_path.display());
                c
            }
            Err(e) => {
                error!("Failed to load config: {}", e);
                info!("Use --init to generate a new config");
                return Err(e);
            }
        }
    } else if status_requested {
        Config::generate_default("http://127.0.0.1", "default")?
    } else {
        info!("No config file found. Generating default config...");
        let control_url = args
            .iter()
            .position(|a| a == "--control")
            .and_then(|i| args.get(i + 1))
            .map(|s| s.as_str())
            .unwrap_or("https://control.p2pnet.io");

        let network_id = args
            .iter()
            .position(|a| a == "--network")
            .and_then(|i| args.get(i + 1))
            .map(|s| s.as_str())
            .unwrap_or("default");

        let mut config = Config::generate_default(control_url, network_id)?;
        apply_arg_overrides(&mut config, &args);
        config.save_to_file(&config_path)?;
        info!("Saved default config to {}", config_path.display());
        config
    };

    let mut config = config;
    apply_arg_overrides(&mut config, &args);

    if status_requested {
        print_status(&config, &args).await?;
        return Ok(());
    }

    info!("Node ID: {}", config.node.node_id);
    info!("Network: {}", config.network.network_id);

    // Create and run the daemon
    let mut daemon = Daemon::new(config);
    daemon.run().await
}

fn arg_value<'a>(args: &'a [String], name: &str) -> Option<&'a str> {
    args.iter()
        .position(|a| a == name)
        .and_then(|i| args.get(i + 1))
        .map(|s| s.as_str())
}

async fn print_status(config: &Config, args: &[String]) -> p2pnet_daemon::Result<()> {
    let url = arg_value(args, "--diagnostics-url")
        .map(ToString::to_string)
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

fn apply_arg_overrides(config: &mut Config, args: &[String]) {
    if let Some(token) = arg_value(args, "--token") {
        config.control.auth_token = token.to_string();
    }
    if let Some(interface) = arg_value(args, "--interface") {
        config.network.interface = interface.to_string();
    }
    if let Some(address) = arg_value(args, "--address") {
        config.network.virtual_ip = address.to_string();
    }
    if let Some(netmask) = arg_value(args, "--netmask") {
        config.network.netmask = netmask.to_string();
    }
    if let Some(mtu) = arg_value(args, "--mtu").and_then(|s| s.parse::<u32>().ok()) {
        config.network.mtu = mtu;
    }
    if let Some(interval) =
        arg_value(args, "--heartbeat-interval").and_then(|s| s.parse::<u64>().ok())
    {
        config.control.heartbeat_interval_secs = interval;
    }
    if let Some(udp_bind) = arg_value(args, "--udp-bind") {
        config.network.udp_bind = udp_bind.to_string();
    }
    if let Some(udp_advertise) = arg_value(args, "--udp-advertise") {
        config.network.udp_advertise = Some(udp_advertise.to_string());
    }
    if let Some(stun_servers) = arg_value(args, "--stun") {
        config.network.stun_servers = stun_servers
            .split(',')
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(ToString::to_string)
            .collect();
    }
    if let Some(timeout_ms) =
        arg_value(args, "--stun-timeout-ms").and_then(|s| s.parse::<u64>().ok())
    {
        config.network.stun_timeout_ms = timeout_ms;
    }
    if let Some(interval_ms) =
        arg_value(args, "--punch-interval-ms").and_then(|s| s.parse::<u64>().ok())
    {
        config.network.punch_interval_ms = interval_ms;
    }
    if let Some(attempts) = arg_value(args, "--punch-attempts").and_then(|s| s.parse::<u32>().ok())
    {
        config.network.punch_attempts = attempts;
    }
    if let Some(interval_secs) =
        arg_value(args, "--keepalive-interval-secs").and_then(|s| s.parse::<u64>().ok())
    {
        config.network.keepalive_interval_secs = interval_secs;
    }
    if let Some(relay_servers) = arg_value(args, "--relay") {
        config.relay.servers = relay_servers
            .split(',')
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(ToString::to_string)
            .collect();
    }
    if let Some(preferred_regions) = arg_value(args, "--relay-regions") {
        config.relay.preferred_regions = preferred_regions
            .split(',')
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(ToString::to_string)
            .collect();
    }
    if let Some(timeout_ms) =
        arg_value(args, "--relay-selection-timeout-ms").and_then(|s| s.parse::<u64>().ok())
    {
        config.relay.selection_timeout_ms = timeout_ms;
    }
    if let Some(timeout_ms) =
        arg_value(args, "--relay-fallback-timeout-ms").and_then(|s| s.parse::<u64>().ok())
    {
        config.relay.fallback_timeout_ms = timeout_ms;
    }
    if let Some(bind) = arg_value(args, "--diagnostics-bind") {
        config.diagnostics.enabled = true;
        config.diagnostics.bind = bind.to_string();
    }
    if args.iter().any(|a| a == "--diagnostics-disable") {
        config.diagnostics.enabled = false;
    }
    if args.iter().any(|a| a == "--prefer-relay") {
        config.relay.prefer_direct = false;
    }
    if args.iter().any(|a| a == "--prefer-direct") {
        config.relay.prefer_direct = true;
    }
    if let Some(name) = arg_value(args, "--device-name") {
        config.node.device_name = name.to_string();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn network_arguments_override_generated_config() {
        let mut config = Config::generate_default("http://127.0.0.1", "default").unwrap();
        let args = vec![
            "p2pnet-daemon".to_string(),
            "--netmask".to_string(),
            "255.255.255.255".to_string(),
            "--relay".to_string(),
            "cn-east@127.0.0.1:8080,us-west@127.0.0.1:8081".to_string(),
            "--relay-regions".to_string(),
            "cn-east,us-west".to_string(),
            "--relay-selection-timeout-ms".to_string(),
            "750".to_string(),
        ];

        apply_arg_overrides(&mut config, &args);

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
}
