#[derive(Parser, Debug, Clone)]
#[command(name = "p2wlan-daemon")]
#[command(version)]
#[command(about = "P2WLAN client daemon", long_about = None)]
struct Cli {
    /// Run with default config or specify config file path
    #[arg(long, default_value = "p2wlan-config.json")]
    config: PathBuf,

    /// Generate a new config
    #[arg(long)]
    init: bool,

    /// Control plane server URL
    #[arg(long)]
    control: Option<String>,

    /// Network ID to join or initialize
    #[arg(long)]
    network: Option<String>,

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

    /// Run in managed mode (enable control-plane auto-assignment)
    #[arg(long, conflicts_with = "manual")]
    managed: bool,

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

    /// Override UDP observer endpoints (comma-separated, STUN-compatible)
    #[arg(long, name = "udp-observer")]
    udp_observer: Option<String>,

    /// Override STUN timeout (ms)
    #[arg(long, name = "stun-timeout-ms")]
    stun_timeout_ms: Option<u64>,

    /// Override hole punch interval (ms)
    #[arg(long, name = "punch-interval-ms")]
    punch_interval_ms: Option<u64>,

    /// Override hole punch attempts
    #[arg(long, name = "punch-attempts")]
    punch_attempts: Option<u32>,

    /// Enable bounded UDP socket pool for hard NATs: off, on, or 2-4
    #[arg(long, name = "socket-pool")]
    socket_pool: Option<String>,

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

    /// Allow loopback endpoints in the fresh-mapping generation (NAT-sim
    /// harnesses only; see config.network.fresh_mapping_harness_loopback).
    #[arg(long, name = "fresh-mapping-harness-loopback")]
    fresh_mapping_harness_loopback: bool,

    /// Do not gather the local socket address as a Host candidate
    /// (NAT-simulation harnesses only).
    #[arg(long, name = "no-host-candidates")]
    no_host_candidates: bool,

    /// Drive a real encrypted overlay payload through the production
    /// dataplane via an in-memory mock TUN (independent validation
    /// harnesses only; off by default in production).
    #[arg(long, name = "validate-overlay")]
    validate_overlay: bool,

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

impl Cli {
    fn control_url(&self) -> &str {
        self.control.as_deref().unwrap_or(DEFAULT_CONTROL_SERVER)
    }

    fn network_id(&self) -> &str {
        self.network.as_deref().unwrap_or(DEFAULT_NETWORK_ID)
    }
}
