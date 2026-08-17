#[derive(Parser, Debug, Clone)]
#[command(name = "p2wlan-daemon")]
#[command(version = concat!(env!("CARGO_PKG_VERSION"), " (git ", env!("P2WLAN_GIT_COMMIT"), ")"))]
#[command(about = "P2WLAN client daemon", long_about = None)]
struct Cli {
    /// Run with default config or specify config file path
    #[arg(long, default_value = "p2wlan-config.json")]
    config: PathBuf,

    /// Print the full build identity (git commit, build id, binary SHA-256)
    /// as JSON and exit without touching config or state.
    #[arg(long)]
    build_info: bool,

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

    /// Read the auth token from a permission-protected file instead of
    /// exposing it in the daemon command line.  Intended for service
    /// managers, the Flutter client, and the audited dual-end harness.
    /// This is the ONLY supported way to supply a control-plane token.
    #[arg(long, name = "token-file")]
    token_file: Option<PathBuf>,

    /// Read one control-plane token from stdin, then close stdin. The token is
    /// bounded, never appears in process arguments, and is not persisted.
    #[arg(long, conflicts_with = "token-file")]
    token_stdin: bool,

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

    /// Override relay startup timeout (ms): how long the first business packet
    /// waits for a relay transport before dropping with a stable reason code.
    /// The old `--relay-fallback-timeout-ms` name is accepted as an alias.
    #[arg(
        long,
        name = "relay-startup-timeout-ms",
        alias = "relay-fallback-timeout-ms"
    )]
    relay_startup_timeout_ms: Option<u64>,

    /// Override diagnostics bind address
    #[arg(long, name = "diagnostics-bind")]
    diagnostics_bind: Option<String>,

    /// Disable diagnostics endpoint
    #[arg(long, name = "diagnostics-disable")]
    diagnostics_disable: bool,

    /// Start business traffic on the confirmed relay while Direct keeps
    /// probing in the background and may be promoted after encrypted ACK.
    #[arg(
        long,
        name = "prefer-relay",
        conflicts_with_all = ["prefer-direct", "relay-only"]
    )]
    prefer_relay: bool,

    /// Allow Direct to be selected as soon as its encrypted validation is
    /// confirmed; Relay remains the fallback.
    #[arg(
        long,
        name = "prefer-direct",
        conflicts_with_all = ["prefer-relay", "relay-only"]
    )]
    prefer_direct: bool,

    /// Disable Direct data-path promotion entirely. Direct candidate and
    /// validation workers are not started for this explicit diagnostic mode.
    #[arg(
        long,
        name = "relay-only",
        conflicts_with_all = ["prefer-relay", "prefer-direct"]
    )]
    relay_only: bool,

    /// Allow loopback endpoints in the fresh-mapping generation (NAT-sim
    /// harnesses only; see config.network.fresh_mapping_harness_loopback).
    #[arg(long, name = "fresh-mapping-harness-loopback")]
    fresh_mapping_harness_loopback: bool,

    /// Do not gather the local socket address as a Host candidate
    /// (NAT-simulation harnesses only).
    #[arg(long, name = "no-host-candidates")]
    no_host_candidates: bool,

    /// Disable the fresh-socket measure-then-punch strategy. This is intended
    /// for controlled traversal ablations; production defaults to enabled.
    #[arg(long, name = "disable-fresh-mapping-punch")]
    disable_fresh_mapping_punch: bool,

    /// Do not advertise extrapolated server-reflexive candidates inferred
    /// from STUN observations. Intended for controlled static-STUN baselines.
    #[arg(long, name = "disable-predicted-candidates")]
    disable_predicted_candidates: bool,

    /// Disable bounded birthday probing. This is intended for controlled
    /// traversal ablations; production defaults to enabled.
    #[arg(long, name = "disable-birthday-probing")]
    disable_birthday_probing: bool,

    /// Drive a real encrypted overlay payload through the production
    /// dataplane via an in-memory mock TUN (independent validation
    /// harnesses only; off by default in production).
    #[arg(long, name = "validate-overlay")]
    validate_overlay: bool,

    /// With --validate-overlay, target every online peer with a WireGuard
    /// session (independent validation harnesses only).  Off by default: the
    /// overlay loop then only sends over confirmed Direct paths.
    #[arg(long, name = "overlay-any-path")]
    overlay_any_path: bool,

    /// With --validate-overlay, fire one burst of N business payloads per
    /// peer right after the first usable evidence and verify every echo
    /// (zero loss/duplicate/reorder; independent validation harnesses only).
    #[arg(long, name = "overlay-burst", default_value_t = 0)]
    overlay_burst: usize,

    /// Control-plane HTTP proxy policy: `direct` (default, never reads
    /// environment proxies) or `environment` (explicitly honors
    /// HTTP_PROXY/HTTPS_PROXY/ALL_PROXY).  WebSocket signaling is always
    /// direct-only regardless of this value.
    #[arg(long, name = "proxy-mode", value_parser = ["direct", "environment"])]
    proxy_mode: Option<String>,

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
