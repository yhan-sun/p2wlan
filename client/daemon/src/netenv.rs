//! Network-environment proxy detection.
//!
//! A laptop on a broadband line can silently egress through an HTTP/SOCKS
//! proxy or a TUN-mode VPN/proxy client (Surge, Clash TUN, Tailscale, ...).
//! That changes the meaning of every STUN observation: the "public" endpoint
//! is the proxy egress, hairpin and port-preservation semantics are no longer
//! the local NAT's, and UDP may be filtered or blackholed entirely.  The
//! daemon cannot route around that, but it must be able to *say* so instead
//! of reporting a misleading NAT profile.
//!
//! Detection is intentionally best-effort and non-intrusive: environment
//! variables, the macOS system proxy dictionary, the default route, and
//! representative public-destination routes. TUN clients commonly install
//! two `/1` routes (or a larger split set) while leaving the literal default
//! route on Wi-Fi/Ethernet, so checking only `default` is not sufficient.
//! Everything here is a fast, synchronous probe; nothing opens a connection.

use std::collections::HashMap;
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant};

#[cfg(any(target_os = "macos", target_os = "linux"))]
use std::process::Command;

/// Proxy / TUN-capture environment verdict.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ProxyEnvironment {
    /// Proxy URLs observed in HTTP_PROXY / HTTPS_PROXY / ALL_PROXY /
    /// SOCKS_PROXY and lowercase variants, in the order found.
    pub env_proxies: Vec<String>,
    /// Human-readable system proxy description (macOS scutil --proxy), if
    /// the system dictionary reports an enabled HTTP/HTTPS/SOCKS proxy.
    pub system_proxy: Option<String>,
    /// Egress interface name for the default route, if readable.
    pub default_route_interface: Option<String>,
    /// Physical interface selected for socket-level TUN bypass.
    pub physical_route_interface: Option<String>,
    /// Interfaces selected by route lookup for representative public IPs.
    pub public_route_interfaces: Vec<String>,
    /// Whether the default route egress looks like a virtual capture
    /// interface (utun/tun/tap/wg/ppp...) that is not one of the
    /// excluded interfaces (the daemon's own TUN).
    pub tun_capture: bool,
    /// The first egress interface name that matched the virtual pattern
    /// (useful for the log message even when it also matches `excluded`).
    pub capture_iface: Option<String>,
}

/// Route-only snapshot for latency-sensitive socket selection and handover
/// monitoring. Unlike [`detect_proxy_environment`], this does not invoke
/// system proxy discovery (`scutil --proxy`) or read proxy environment values.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct DirectRouteSnapshot {
    pub signature: Vec<String>,
    pub default_route_interface: Option<String>,
    pub physical_route_interface: Option<String>,
    pub public_route_interfaces: Vec<String>,
    pub tun_capture: bool,
    pub capture_iface: Option<String>,
}

/// Public destinations used only for local route lookup. No packet is sent.
/// The mix avoids treating a provider-specific exception as the global path.
const PUBLIC_ROUTE_PROBES: &[&str] = &["1.1.1.1", "8.8.8.8", "223.5.5.5", "119.29.29.29"];
const DIRECT_ROUTE_CACHE_TTL: Duration = Duration::from_millis(500);

struct CachedDirectRouteSnapshot {
    captured_at: Instant,
    snapshot: DirectRouteSnapshot,
}

static DIRECT_ROUTE_CACHE: OnceLock<Mutex<HashMap<Vec<String>, CachedDirectRouteSnapshot>>> =
    OnceLock::new();

impl ProxyEnvironment {
    /// Short human label for diagnostics logs.
    pub fn label(&self) -> String {
        let mut parts = Vec::new();
        if self.tun_capture {
            parts.push("tun_capture");
        }
        if !self.env_proxies.is_empty() {
            parts.push("env_proxy");
        }
        if self.system_proxy.is_some() {
            parts.push("system_proxy");
        }
        if parts.is_empty() {
            "direct".to_string()
        } else {
            parts.join("+")
        }
    }

    /// True when egress is likely intercepted by a proxy or TUN client.
    pub fn intercepted(&self) -> bool {
        self.tun_capture || self.system_proxy.is_some() || !self.env_proxies.is_empty()
    }

    /// Select the physical interface for a direct socket. A foreign TUN with
    /// no known physical egress is a hard error: returning `None` in that
    /// state would silently send the supposedly direct socket into the TUN.
    pub fn direct_socket_interface(&self) -> std::result::Result<Option<String>, String> {
        if self.tun_capture && self.physical_route_interface.is_none() {
            return Err(format!(
                "foreign TUN capture detected on {:?}, but no physical bypass interface was found",
                self.capture_iface
            ));
        }
        Ok(self.physical_route_interface.clone())
    }
}

impl DirectRouteSnapshot {
    pub fn direct_socket_interface(&self) -> std::result::Result<Option<String>, String> {
        if self.tun_capture && self.physical_route_interface.is_none() {
            return Err(format!(
                "foreign TUN capture detected on {:?}, but no physical bypass interface was found",
                self.capture_iface
            ));
        }
        Ok(self.physical_route_interface.clone())
    }
}

/// Proxy-related environment variables, both cases, in priority order.
const PROXY_ENV_NAMES: &[&str] = &[
    "ALL_PROXY",
    "HTTPS_PROXY",
    "HTTP_PROXY",
    "SOCKS_PROXY",
    "all_proxy",
    "https_proxy",
    "http_proxy",
    "socks_proxy",
];

/// Interface name patterns that indicate a virtual capture device.
const VIRTUAL_CAPTURE_PREFIXES: &[&str] = &[
    "utun",
    "tun",
    "tap",
    "wg",
    "ppp",
    "gpd",
    "clat",
    "tailscale",
    "ipsec",
    "tunl",
];

/// Read proxy URLs from the environment.
pub fn env_proxies() -> Vec<String> {
    PROXY_ENV_NAMES
        .iter()
        .filter_map(|name| std::env::var(name).ok())
        .filter(|value| !value.is_empty() && *value != "none")
        .collect()
}

/// Whether an interface name is virtual, regardless of ownership.
///
/// This deliberately does not know about the daemon's own TUN.  Physical
/// interface selection must reject *all* virtual devices, including our own;
/// otherwise an excluded `utun` can be selected as the bypass and create a
/// routing loop.
fn is_virtual_interface_name(name: &str) -> bool {
    let name = name.trim().to_ascii_lowercase();
    if name.is_empty() {
        return false;
    }
    VIRTUAL_CAPTURE_PREFIXES
        .iter()
        .any(|prefix| name == *prefix || name.starts_with(prefix))
}

/// Whether an interface name is a virtual capture device not owned by the
/// caller.
pub fn is_virtual_capture_interface(name: &str, excluded: &[String]) -> bool {
    is_virtual_interface_name(name)
        && !excluded
            .iter()
            .any(|excluded| excluded.trim().eq_ignore_ascii_case(name.trim()))
}

/// macOS `scutil --proxy` dictionary output → enabled proxy description.
///
/// ```text
/// <dictionary> {
///   HTTPEnable : 1
///   HTTPPort : 7890
///   HTTPProxy : 127.0.0.1
///   ... }
/// ```
pub fn parse_scutil_proxy_output(output: &str) -> Option<String> {
    let mut found: Vec<String> = Vec::new();
    let mut dictionary: Vec<(String, String)> = Vec::new();
    for line in output.lines() {
        let line = line.trim();
        if let Some((key, value)) = line.split_once(':') {
            dictionary.push((key.trim().to_string(), value.trim().to_string()));
        }
    }
    for (key, value) in &dictionary {
        match (key.as_str(), value.as_str()) {
            ("HTTPEnable" | "HTTPSEnable" | "SOCKSEnable", "1") => {}
            ("HTTPProxy" | "HTTPSProxy" | "SOCKSServer", proxy)
                if !proxy.is_empty()
                    && proxy != "0.0.0.0"
                    && proxy != "empty"
                    && dictionary.iter().any(|(enable_key, enable_value)| {
                        let enable_key = enable_key.as_str();
                        enable_value == "1"
                            && matches!(
                                (enable_key, key.as_str()),
                                ("HTTPEnable", "HTTPProxy")
                                    | ("HTTPSEnable", "HTTPSProxy")
                                    | ("SOCKSEnable", "SOCKSServer")
                            )
                    }) =>
            {
                let port = dictionary
                    .iter()
                    .find(|(port_key, _)| {
                        matches!(
                            (port_key.as_str(), key.as_str()),
                            ("HTTPPort", "HTTPProxy")
                                | ("HTTPSPort", "HTTPSProxy")
                                | ("SOCKSPort", "SOCKSServer")
                        )
                    })
                    .map(|(_, port)| port.as_str())
                    .unwrap_or("");
                found.push(format!("{key}={proxy}:{port}"));
            }
            _ => {}
        }
    }
    if found.is_empty() {
        None
    } else {
        Some(found.join(", "))
    }
}

/// macOS `route -n get default` output → egress interface name.
///
/// ```text
///    route to: default
/// destination: default
///        mask: default
///     gateway: 192.168.1.1
///   interface: en0
/// ```
pub fn parse_route_get_interface(output: &str) -> Option<String> {
    output
        .lines()
        .find_map(|line| {
            let trimmed = line.trim();
            let (key, value) = trimmed.split_once(':')?;
            (key.trim() == "interface").then(|| value.trim().to_string())
        })
        .filter(|name| !name.is_empty())
}

#[cfg(any(target_os = "macos", target_os = "linux"))]
fn parse_route_get_gateway(output: &str) -> Option<String> {
    output
        .lines()
        .find_map(|line| {
            let (key, value) = line.trim().split_once(':')?;
            (key.trim() == "gateway").then(|| value.trim().to_string())
        })
        .filter(|gateway| !gateway.is_empty())
}

/// `ip route show default` / `route -n` output → egress interface name
/// (Linux, BSD variants).
///
/// Linux: `default via 192.168.1.1 dev en0 proto dhcp metric 100`
/// BSD: `default            192.168.1.1        UGScg           en0`
pub fn parse_route_default_interface(output: &str) -> Option<String> {
    parse_route_default_path(output).map(|(interface, _)| interface)
}

fn parse_route_default_path(output: &str) -> Option<(String, Option<String>)> {
    for line in output.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        // Linux "dev <iface>".
        if let Some(pos) = trimmed.find(" dev ") {
            let rest = trimmed[pos + 5..].trim();
            let iface = rest.split_whitespace().next().unwrap_or_default();
            if !iface.is_empty() {
                let gateway = trimmed
                    .split_whitespace()
                    .collect::<Vec<_>>()
                    .windows(2)
                    .find_map(|pair| (pair[0] == "via").then(|| pair[1].to_string()));
                return Some((iface.to_string(), gateway));
            }
        }
        // BSD/macOS `route -n` table line: last whitespace token is the iface.
        let tokens: Vec<&str> = trimmed.split_whitespace().collect();
        if tokens.len() >= 2 && tokens[0] == "default" {
            let iface = tokens[tokens.len() - 1];
            if is_candidate_route_iface_token(iface) {
                let gateway = tokens
                    .get(1)
                    .filter(|gateway| **gateway != "default" && !gateway.eq_ignore_ascii_case("-"));
                return Some((iface.to_string(), gateway.map(|value| value.to_string())));
            }
        }
    }
    None
}

#[cfg(any(target_os = "macos", target_os = "linux"))]
fn parse_physical_default_path(output: &str) -> Option<(String, Option<String>)> {
    output.lines().find_map(|line| {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            return None;
        }
        let (interface, gateway) = parse_route_default_path(trimmed)?;
        (is_candidate_route_iface_token(&interface) && !is_virtual_interface_name(&interface))
            .then_some((interface, gateway))
    })
}

fn is_candidate_route_iface_token(token: &str) -> bool {
    token.starts_with("en")
        || token.starts_with("eth")
        || token.starts_with("wl")
        || token.starts_with("wlan")
        || token.starts_with("wwan")
        || token.starts_with("usb")
        || token.starts_with("rmnet")
        || token.starts_with("bridge")
        || token.starts_with("br")
        || token.starts_with("bond")
        || token.starts_with("vlan")
        || token.starts_with("em")
        || is_virtual_capture_interface(token, &[])
}

/// Best-effort default-route egress interface.
#[cfg(any(target_os = "macos", target_os = "linux"))]
pub fn default_route_interface() -> Option<String> {
    // Prefer `route -n get default` (macOS/BSD) because it also works for
    // rootless users; fall back to `ip route show default`.
    if cfg!(target_os = "macos") {
        if let Ok(output) = Command::new("route")
            .args(["-n", "get", "default"])
            .output()
        {
            if let Some(iface) = parse_route_get_interface(&String::from_utf8_lossy(&output.stdout))
            {
                return Some(iface);
            }
        }
    }
    if let Ok(output) = Command::new("ip")
        .args(["route", "show", "default"])
        .output()
    {
        if let Some(iface) = parse_route_default_interface(&String::from_utf8_lossy(&output.stdout))
        {
            return Some(iface);
        }
    }
    None
}

#[cfg(not(any(target_os = "macos", target_os = "linux")))]
pub fn default_route_interface() -> Option<String> {
    None
}

/// Best-effort route path (`interface`, `gateway`) for a concrete destination.
#[cfg(any(target_os = "macos", target_os = "linux"))]
fn route_path_for_destination(destination: &str) -> Option<(String, Option<String>)> {
    if cfg!(target_os = "macos") {
        let output = Command::new("route")
            .args(["-n", "get", destination])
            .output()
            .ok()?;
        let text = String::from_utf8_lossy(&output.stdout);
        return parse_route_get_interface(&text)
            .map(|interface| (interface, parse_route_get_gateway(&text)));
    }

    if destination == "default" {
        let output = Command::new("ip")
            .args(["route", "show", "default"])
            .output()
            .ok()?;
        let text = String::from_utf8_lossy(&output.stdout);
        return parse_route_default_path(&text);
    }

    let output = Command::new("ip")
        .args(["route", "get", destination])
        .output()
        .ok()?;
    let text = String::from_utf8_lossy(&output.stdout);
    let interface = parse_route_default_interface(&text)?;
    let tokens = text.split_whitespace().collect::<Vec<_>>();
    let gateway = tokens
        .windows(2)
        .find_map(|pair| (pair[0] == "via").then(|| pair[1].to_string()));
    Some((interface, gateway))
}

#[cfg(not(any(target_os = "macos", target_os = "linux")))]
fn route_path_for_destination(_destination: &str) -> Option<(String, Option<String>)> {
    None
}

/// Select the underlying non-virtual default interface. This remains useful
/// when public destinations are captured by more-specific TUN routes.
pub fn physical_route_interface(excluded: &[String]) -> Option<String> {
    physical_route_interface_from_default(default_route_interface(), excluded)
}

fn physical_route_path_from_default(
    default_path: Option<(String, Option<String>)>,
) -> Option<(String, Option<String>)> {
    if let Some(path) = default_path.filter(|(interface, _)| !is_virtual_interface_name(interface))
    {
        return Some(path);
    }

    #[cfg(target_os = "macos")]
    if let Ok(output) = Command::new("netstat").args(["-rn", "-f", "inet"]).output() {
        if let Some(path) = parse_physical_default_path(&String::from_utf8_lossy(&output.stdout)) {
            return Some(path);
        }
    }
    #[cfg(target_os = "linux")]
    if let Ok(output) = Command::new("ip")
        .args(["route", "show", "default"])
        .output()
    {
        if let Some(path) = parse_physical_default_path(&String::from_utf8_lossy(&output.stdout)) {
            return Some(path);
        }
    }
    None
}

fn physical_route_interface_from_default(
    default_interface: Option<String>,
    _excluded: &[String],
) -> Option<String> {
    physical_route_path_from_default(default_interface.map(|interface| (interface, None)))
        .map(|(interface, _)| interface)
}

fn capture_interface(
    default_route_interface: Option<&String>,
    public_route_interfaces: &[String],
    excluded: &[String],
) -> Option<String> {
    default_route_interface
        .into_iter()
        .chain(public_route_interfaces.iter())
        .find(|interface| is_virtual_capture_interface(interface, excluded))
        .cloned()
}

/// Stable local route signature used to notice interface/gateway/TUN changes.
/// It includes gateways so switching between two networks on the same `en0`
/// still causes the UDP transport to be rebuilt in the common case.
pub fn network_route_signature(excluded: &[String]) -> Vec<String> {
    direct_route_snapshot(excluded).signature
}

/// Capture the route paths and physical bypass interface once. Callers that
/// need both TUN detection and a handover signature should use this instead of
/// launching the same route commands twice.
pub fn direct_route_snapshot(excluded: &[String]) -> DirectRouteSnapshot {
    let mut cache_key = excluded
        .iter()
        .map(|interface| interface.trim().to_ascii_lowercase())
        .filter(|interface| !interface.is_empty())
        .collect::<Vec<_>>();
    cache_key.sort();
    cache_key.dedup();

    // Route consumers (UDP, Relay, control HTTP, WebSocket and liveness)
    // commonly sample on the same one-second cadence. Serialize one short
    // capture per exclusion set and let the others reuse it for 500ms instead
    // of launching dozens of identical `route`/`ip` processes each second.
    let cache = DIRECT_ROUTE_CACHE.get_or_init(|| Mutex::new(HashMap::new()));
    let mut cache = cache
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    if let Some(cached) = cache.get(&cache_key) {
        if cached.captured_at.elapsed() < DIRECT_ROUTE_CACHE_TTL {
            return cached.snapshot.clone();
        }
    }

    let snapshot = capture_direct_route_snapshot(excluded);
    cache.retain(|_, cached| cached.captured_at.elapsed() < Duration::from_secs(10));
    cache.insert(
        cache_key,
        CachedDirectRouteSnapshot {
            captured_at: Instant::now(),
            snapshot: snapshot.clone(),
        },
    );
    snapshot
}

fn capture_direct_route_snapshot(excluded: &[String]) -> DirectRouteSnapshot {
    let mut signature = Vec::new();
    let default_path = route_path_for_destination("default");
    if let Some((interface, gateway)) = &default_path {
        signature.push(format!(
            "default:{interface}:{}",
            gateway.as_deref().unwrap_or_default()
        ));
    }
    let default_route_interface = default_path
        .as_ref()
        .map(|(interface, _)| interface.clone())
        .or_else(default_route_interface);
    let physical_route_path = physical_route_path_from_default(default_path.clone());
    let physical_route_interface = physical_route_path
        .as_ref()
        .map(|(interface, _)| interface.clone());
    let mut public_route_interfaces = Vec::new();
    for destination in PUBLIC_ROUTE_PROBES {
        if let Some((interface, gateway)) = route_path_for_destination(destination) {
            public_route_interfaces.push(interface.clone());
            signature.push(format!(
                "{destination}:{interface}:{}",
                gateway.unwrap_or_default()
            ));
        }
    }
    if let Some(interface) = &physical_route_interface {
        signature.push(format!(
            "physical:{interface}:{}",
            physical_route_path
                .as_ref()
                .and_then(|(_, gateway)| gateway.as_deref())
                .unwrap_or_default()
        ));
    }
    signature.sort();
    signature.dedup();
    let capture_iface = capture_interface(
        default_route_interface.as_ref(),
        &public_route_interfaces,
        excluded,
    );
    DirectRouteSnapshot {
        signature,
        default_route_interface,
        physical_route_interface,
        public_route_interfaces,
        tun_capture: capture_iface.is_some(),
        capture_iface,
    }
}

/// System proxy dictionary on macOS.
#[cfg(target_os = "macos")]
pub fn system_proxy() -> Option<String> {
    let output = Command::new("scutil").arg("--proxy").output().ok()?;
    parse_scutil_proxy_output(&String::from_utf8_lossy(&output.stdout))
}

#[cfg(not(target_os = "macos"))]
pub fn system_proxy() -> Option<String> {
    None
}

/// Run all cheap probes and assemble the environment verdict.
///
/// `excluded` should contain the daemon's own TUN interface name(s) so a
/// self-owned utun/p2wlan device is not mistaken for a capture client.
pub fn detect_proxy_environment(excluded: &[String]) -> ProxyEnvironment {
    let env_proxies = env_proxies();
    let system_proxy = system_proxy();
    let routes = direct_route_snapshot(excluded);
    ProxyEnvironment {
        env_proxies,
        system_proxy,
        default_route_interface: routes.default_route_interface,
        physical_route_interface: routes.physical_route_interface,
        public_route_interfaces: routes.public_route_interfaces,
        tun_capture: routes.tun_capture,
        capture_iface: routes.capture_iface,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;
    use std::sync::MutexGuard;

    // Tests mutate process environment variables; serialize them so parallel
    // runs cannot observe each other's leftovers.
    fn env_guard() -> MutexGuard<'static, ()> {
        static ENV_LOCK: Mutex<()> = Mutex::new(());
        ENV_LOCK
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    fn clear_proxy_environment() -> Vec<(&'static str, Option<String>)> {
        let previous = PROXY_ENV_NAMES
            .iter()
            .copied()
            .map(|name| (name, std::env::var(name).ok()))
            .collect::<Vec<_>>();
        for name in PROXY_ENV_NAMES {
            std::env::remove_var(name);
        }
        previous
    }

    fn restore_proxy_environment(previous: Vec<(&'static str, Option<String>)>) {
        for (name, value) in previous {
            match value {
                Some(value) => std::env::set_var(name, value),
                None => std::env::remove_var(name),
            }
        }
    }

    #[test]
    fn env_proxies_collects_configured_variables() {
        let _guard = env_guard();
        let previous = clear_proxy_environment();
        std::env::set_var("HTTP_PROXY", "http://127.0.0.1:7890");
        std::env::set_var("ALL_PROXY", "socks5://127.0.0.1:7891");
        std::env::set_var("HTTPS_PROXY", "");
        let proxies = env_proxies();
        assert!(proxies.contains(&"http://127.0.0.1:7890".to_string()));
        assert!(proxies.contains(&"socks5://127.0.0.1:7891".to_string()));
        restore_proxy_environment(previous);
    }

    #[test]
    fn env_proxies_ignores_none_sentinel() {
        let _guard = env_guard();
        let previous = clear_proxy_environment();
        std::env::set_var("HTTPS_PROXY", "none");
        assert!(env_proxies().is_empty());
        restore_proxy_environment(previous);
    }

    #[test]
    fn scutil_proxy_output_parses_enabled_proxy() {
        let output = "<dictionary> {
  HTTPEnable : 0
  HTTPSEnable : 1
  HTTPSPort : 7890
  HTTPSProxy : 127.0.0.1
  SOCKSEnable : 0
}";
        let parsed = parse_scutil_proxy_output(output).unwrap();
        assert!(parsed.contains("HTTPSProxy=127.0.0.1:7890"), "{parsed}");
    }

    #[test]
    fn scutil_proxy_output_ignores_disabled_proxy() {
        let output = "<dictionary> {
  HTTPEnable : 0
  HTTPPort : 7890
  HTTPProxy : 127.0.0.1
  SOCKSEnable : 0
}";
        assert!(parse_scutil_proxy_output(output).is_none());
    }

    #[test]
    fn route_get_interface_parses_macos_output() {
        let output = "   route to: default
destination: default
       mask: default
    gateway: 192.168.1.1
  interface: utun4
";
        assert_eq!(parse_route_get_interface(output).as_deref(), Some("utun4"));
    }

    #[test]
    fn ip_route_default_parses_linux_output() {
        let output = "default via 192.168.1.1 dev en0 proto dhcp metric 100\n";
        assert_eq!(
            parse_route_default_interface(output).as_deref(),
            Some("en0")
        );
        let tun_output = "default via 10.0.0.1 dev tun0 proto static\n";
        assert_eq!(
            parse_route_default_interface(tun_output).as_deref(),
            Some("tun0")
        );
        assert_eq!(
            parse_route_default_path(output),
            Some(("en0".to_string(), Some("192.168.1.1".to_string())))
        );
    }

    #[test]
    fn route_table_output_parses_bsd_style() {
        let output = "Routing tables

Internet:
Destination        Gateway            Flags        Netif Expire
default            192.168.1.1        UGScg            en0
default            10.0.0.1           UGScg           utun3
";
        assert_eq!(
            parse_route_default_interface(output).as_deref(),
            Some("en0")
        );
    }

    #[cfg(any(target_os = "macos", target_os = "linux"))]
    #[test]
    fn physical_default_parser_skips_split_tun_route() {
        let output = "default 10.0.0.1 UGScg utun23\n\
default 192.168.0.1 UGScg en5\n";
        assert_eq!(
            parse_physical_default_path(output),
            Some(("en5".to_string(), Some("192.168.0.1".to_string())))
        );
    }

    #[cfg(any(target_os = "macos", target_os = "linux"))]
    #[test]
    fn physical_selection_rejects_own_excluded_tun() {
        let output = "default 10.0.0.1 UGScg utun9\n\
default 192.168.0.1 UGScg en5\n";
        // Exclusion is intentionally irrelevant to physical selection: an
        // excluded/self TUN is still virtual and must never be returned as a
        // socket bypass.
        assert_eq!(
            parse_physical_default_path(output),
            Some(("en5".to_string(), Some("192.168.0.1".to_string())))
        );
    }

    #[test]
    fn split_public_routes_are_detected_even_when_default_is_physical() {
        let default = "en5".to_string();
        let public = vec!["utun23".to_string(), "utun23".to_string()];
        assert_eq!(
            capture_interface(Some(&default), &public, &[]).as_deref(),
            Some("utun23")
        );
    }

    #[test]
    fn virtual_capture_interface_excludes_self_tun() {
        let none: Vec<String> = vec![];
        assert!(is_virtual_capture_interface("utun4", &none));
        assert!(is_virtual_capture_interface(
            "tun0",
            &["p2wlan0".to_string()]
        ));
        assert!(!is_virtual_capture_interface(
            "utun4",
            &["utun4".to_string()]
        ));
        assert!(!is_virtual_capture_interface("en0", &none));
        assert!(!is_virtual_capture_interface("", &none));
    }

    #[test]
    fn detect_marks_tun_capture_and_excludes_self() {
        let _guard = env_guard();
        let previous = clear_proxy_environment();
        std::env::set_var("HTTP_PROXY", "http://127.0.0.1:7890");
        let env = detect_proxy_environment(&["utun9".to_string()]);
        assert!(!env.env_proxies.is_empty());
        assert!(env.label().contains("env_proxy"));
        assert!(env.intercepted());
        restore_proxy_environment(previous);
    }

    #[test]
    fn direct_environment_label() {
        let env = ProxyEnvironment {
            env_proxies: vec![],
            system_proxy: None,
            default_route_interface: Some("en0".to_string()),
            physical_route_interface: Some("en0".to_string()),
            public_route_interfaces: vec!["en0".to_string()],
            tun_capture: false,
            capture_iface: None,
        };
        assert_eq!(env.label(), "direct");
        assert!(!env.intercepted());
    }

    #[test]
    fn direct_socket_interface_fails_closed_without_tun_bypass() {
        let captured = ProxyEnvironment {
            tun_capture: true,
            capture_iface: Some("utun23".to_string()),
            ..Default::default()
        };
        assert!(captured.direct_socket_interface().is_err());

        let bypassable = ProxyEnvironment {
            tun_capture: true,
            capture_iface: Some("utun23".to_string()),
            physical_route_interface: Some("en5".to_string()),
            ..Default::default()
        };
        assert_eq!(
            bypassable.direct_socket_interface().unwrap().as_deref(),
            Some("en5")
        );
    }
}
