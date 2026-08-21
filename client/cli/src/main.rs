use clap::{Args, Parser, Subcommand};
use p2pnet_daemon::Config;
use reqwest::Url;
use serde::Deserialize;
use serde_json::Value;
use std::env;
use std::ffi::OsString;
use std::fs::{self, File, OpenOptions};
#[cfg(unix)]
use std::io;
use std::io::Read;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode, Stdio};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

mod formatting;
use formatting::*;

const DEFAULT_CONTROL_SERVER: &str = "http://47.109.40.237:18080";
const DEFAULT_NETWORK: &str = "default";
const DEFAULT_DIAGNOSTICS_BIND: &str = "127.0.0.1:39277";
const DEFAULT_UPDATE_REPO: &str = "yhan-sun/p2wlan";
const DEFAULT_INSTALL_DIR: &str = "/usr/local/bin";
const SUPPORTED_CONFIG_KEYS: &str = "control、network、device-name、interface、mtu、udp-bind、udp-advertise、stun、port-mapping/upnp、birthday-probing、socket-pool、diagnostics、relay、relay-policy、relay-startup-timeout";

#[derive(Parser, Debug)]
#[command(name = "p2wlan", version, about = "p2wlan Linux command-line client")]
struct Cli {
    /// Use a custom daemon configuration file
    #[arg(long, global = true, value_name = "PATH")]
    config: Option<PathBuf>,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Log in to the control server and save the session
    Login(AuthArgs),
    /// Create an account and save the session
    Register(AuthArgs),
    /// Remove the saved control-server session
    Logout,
    /// Start the TUN daemon in the background
    #[command(alias = "start")]
    Up,
    /// Stop the running TUN daemon
    #[command(alias = "stop")]
    Down,
    /// Show daemon and peer status
    Status {
        /// Print the complete diagnostics response as JSON
        #[arg(long)]
        json: bool,
    },
    /// Read daemon logs
    Logs {
        /// Number of recent lines to print
        #[arg(short = 'n', long, default_value_t = 100)]
        lines: usize,
        /// Continue following the log file
        #[arg(short = 'f', long)]
        follow: bool,
    },
    /// View or update persistent settings
    Config {
        #[command(subcommand)]
        command: ConfigCommand,
    },
    /// Diagnose local config, daemon status, direct UDP, and relay fallback
    Doctor,
    /// Download and install the latest Linux CLI release
    Update(UpdateArgs),
    /// Internal elevated launcher used by `p2wlan up`
    #[command(name = "__start-daemon", hide = true)]
    InternalStart(InternalStartArgs),
}

#[derive(Args, Debug)]
struct AuthArgs {
    /// Account email address
    #[arg(short = 'u', long = "username", alias = "email")]
    username: String,
    /// Account password. Omit this option to enter it without terminal echo.
    #[arg(short = 'p', long)]
    password: Option<String>,
    /// Control server URL
    #[arg(short = 's', long, value_name = "URL")]
    server: Option<String>,
}

#[derive(Subcommand, Debug)]
enum ConfigCommand {
    /// Show the effective configuration with secrets redacted
    Show,
    /// Print the configuration file path
    Path,
    /// Set one supported configuration value
    Set {
        /// control, network, device-name, interface, mtu, udp-bind, udp-advertise, stun, port-mapping/upnp, birthday-probing, socket-pool, diagnostics, relay, relay-policy, or relay-startup-timeout
        key: String,
        value: String,
    },
}

#[derive(Args, Debug)]
struct UpdateArgs {
    /// GitHub repository, for example yhan-sun/p2wlan
    #[arg(long, default_value = DEFAULT_UPDATE_REPO)]
    repo: String,
    /// Install a specific release tag instead of the latest release
    #[arg(long, value_name = "TAG")]
    version: Option<String>,
    /// Installation directory for p2wlan and p2wlan-daemon
    #[arg(long, value_name = "DIR")]
    install_dir: Option<PathBuf>,
    /// Only print what would be installed
    #[arg(long)]
    dry_run: bool,
}

#[derive(Args, Debug)]
struct InternalStartArgs {
    #[arg(long)]
    config: PathBuf,
    #[arg(long)]
    state_dir: PathBuf,
    #[arg(long)]
    daemon: PathBuf,
}

#[derive(Debug, Deserialize)]
struct AuthResponse {
    success: Option<bool>,
    token: Option<String>,
    error: Option<String>,
}

#[derive(Debug, Deserialize)]
struct GitHubRelease {
    tag_name: String,
    html_url: Option<String>,
    assets: Vec<GitHubAsset>,
}

#[derive(Debug, Deserialize)]
struct GitHubAsset {
    name: String,
    browser_download_url: String,
}

#[tokio::main]
async fn main() -> ExitCode {
    match run(Cli::parse()).await {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("错误：{error}");
            ExitCode::FAILURE
        }
    }
}

async fn run(cli: Cli) -> Result<(), String> {
    let config_path = cli.config.unwrap_or_else(default_config_path);
    match cli.command {
        Commands::Login(args) => authenticate(&config_path, args, false).await,
        Commands::Register(args) => authenticate(&config_path, args, true).await,
        Commands::Logout => logout(&config_path).await,
        Commands::Up => start(&config_path).await,
        Commands::Down => stop(&config_path).await,
        Commands::Status { json } => status(&config_path, json).await,
        Commands::Logs { lines, follow } => logs(lines, follow),
        Commands::Config { command } => config_command(&config_path, command),
        Commands::Doctor => doctor(&config_path).await,
        Commands::Update(args) => update(&config_path, args).await,
        Commands::InternalStart(args) => start_daemon_as_root(args).await,
    }
}

include!("main/auth.rs");
include!("main/daemon.rs");
include!("main/diagnostics.rs");
include!("main/update.rs");
include!("main/config.rs");
include!("main/paths.rs");

#[cfg(test)]
#[path = "main/tests.rs"]
mod tests;
