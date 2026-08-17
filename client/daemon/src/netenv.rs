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
//! variables, the macOS system proxy dictionary, and the default-route egress
//! interface name.  Everything here is a fast, synchronous probe that is safe
//! to run on the control-plane path; nothing opens a network connection.

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
    /// Whether the default route egress looks like a virtual capture
    /// interface (utun/tun/tap/wg/ppp...) that is not one of the
    /// excluded interfaces (the daemon's own TUN).
    pub tun_capture: bool,
    /// The first egress interface name that matched the virtual pattern
    /// (useful for the log message even when it also matches `excluded`).
    pub capture_iface: Option<String>,
}

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

/// Interface name patterns that indicate a virtual capture device.  The
/// daemon's own TUN is filtered by the caller via `excluded`.
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

/// Whether an interface name matches a virtual capture pattern.
pub fn is_virtual_capture_interface(name: &str, excluded: &[String]) -> bool {
    let name = name.trim().to_ascii_lowercase();
    if name.is_empty() || excluded.iter().any(|e| e.eq_ignore_ascii_case(&name)) {
        return false;
    }
    VIRTUAL_CAPTURE_PREFIXES
        .iter()
        .any(|prefix| name == *prefix || name.starts_with(prefix))
}

/// macOS `scutil --proxy` dictionary output → enabled proxy description.
///
/// ```
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
/// ```
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

/// `ip route show default` / `route -n` output → egress interface name
/// (Linux, BSD variants).
///
/// Linux: `default via 192.168.1.1 dev en0 proto dhcp metric 100`
/// BSD: `default            192.168.1.1        UGScg           en0`
pub fn parse_route_default_interface(output: &str) -> Option<String> {
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
                return Some(iface.to_string());
            }
        }
        // BSD/macOS `route -n` table line: last whitespace token is the iface.
        let tokens: Vec<&str> = trimmed.split_whitespace().collect();
        if tokens.len() >= 2 && tokens[0] == "default" {
            let iface = tokens[tokens.len() - 1];
            if is_candidate_route_iface_token(iface) {
                return Some(iface.to_string());
            }
        }
    }
    None
}

fn is_candidate_route_iface_token(token: &str) -> bool {
    token.starts_with("en")
        || token.starts_with("eth")
        || token.starts_with("wl")
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
    let default_route_interface = default_route_interface();
    let capture_iface = default_route_interface
        .as_ref()
        .filter(|iface| is_virtual_capture_interface(iface, excluded))
        .cloned();
    ProxyEnvironment {
        env_proxies,
        system_proxy,
        default_route_interface,
        tun_capture: capture_iface.is_some(),
        capture_iface,
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
        ENV_LOCK.lock().unwrap()
    }

    #[test]
    fn env_proxies_collects_configured_variables() {
        let _guard = env_guard();
        std::env::set_var("HTTP_PROXY", "http://127.0.0.1:7890");
        std::env::set_var("ALL_PROXY", "socks5://127.0.0.1:7891");
        std::env::set_var("HTTPS_PROXY", "");
        let proxies = env_proxies();
        assert!(proxies.contains(&"http://127.0.0.1:7890".to_string()));
        assert!(proxies.contains(&"socks5://127.0.0.1:7891".to_string()));
        std::env::remove_var("HTTP_PROXY");
        std::env::remove_var("ALL_PROXY");
        std::env::remove_var("HTTPS_PROXY");
    }

    #[test]
    fn env_proxies_ignores_none_sentinel() {
        let _guard = env_guard();
        std::env::set_var("HTTPS_PROXY", "none");
        assert!(env_proxies().is_empty());
        std::env::remove_var("HTTPS_PROXY");
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
        std::env::set_var("HTTP_PROXY", "http://127.0.0.1:7890");
        let env = detect_proxy_environment(&["utun9".to_string()]);
        assert!(!env.env_proxies.is_empty());
        assert_eq!(env.label(), "env_proxy");
        assert!(env.intercepted());
        std::env::remove_var("HTTP_PROXY");
    }

    #[test]
    fn direct_environment_label() {
        let env = ProxyEnvironment {
            env_proxies: vec![],
            system_proxy: None,
            default_route_interface: Some("en0".to_string()),
            tun_capture: false,
            capture_iface: None,
        };
        assert_eq!(env.label(), "direct");
        assert!(!env.intercepted());
    }
}
