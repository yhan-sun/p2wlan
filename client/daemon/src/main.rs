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
//! p2pnet-daemon --interface p2pnet0 --address 10.20.0.1 --mtu 1420
//! ```

use p2pnet_daemon::{Config, Daemon};
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

        let config = Config::generate_default(control_url, network_id)?;
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

        let config = Config::generate_default(control_url, network_id)?;
        config.save_to_file(&config_path)?;
        info!("Saved default config to {}", config_path.display());
        config
    };

    info!("Node ID: {}", config.node.node_id);
    info!("Network: {}", config.network.network_id);

    // Create and run the daemon
    let mut daemon = Daemon::new(config);
    daemon.run().await
}
