use std::net::Ipv4Addr;
#[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
use std::process::Command;
use std::sync::Mutex;
#[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
use tracing::info;
#[cfg(target_os = "windows")]
use tracing::warn;

/// Platform-abstracted command runner for route operations.
///
/// Production uses the real `Command` to invoke `ip`.
/// Tests can swap in a mock that records calls and
/// simulates success/failure/pre-existence.
pub trait RouteCommandRunner: std::fmt::Debug + Send + Sync {
    /// Run `ip route show to <cidr>` and return stdout (trimmed), or an error.
    fn route_show(&self, cidr: &str) -> Result<String, crate::DaemonError>;
    /// Run `ip route add <cidr> dev <interface>` and return whether it succeeded.
    fn route_add(&self, cidr: &str, interface: &str) -> Result<bool, crate::DaemonError>;
    /// Run `ip route del <cidr> dev <interface>`.
    fn route_del(&self, cidr: &str, interface: &str);
}

#[cfg(target_os = "linux")]
#[derive(Debug)]
pub struct RealCommandRunner;

#[cfg(target_os = "linux")]
impl RouteCommandRunner for RealCommandRunner {
    fn route_show(&self, cidr: &str) -> Result<String, crate::DaemonError> {
        let output = Command::new("ip")
            .args(["route", "show", "to", cidr])
            .output()
            .map_err(|e| {
                crate::DaemonError::Network(format!("failed to run ip route show: {e}"))
            })?;
        Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
    }

    fn route_add(&self, cidr: &str, interface: &str) -> Result<bool, crate::DaemonError> {
        let status = Command::new("ip")
            .args(["route", "add", cidr, "dev", interface])
            .status()
            .map_err(|e| crate::DaemonError::Network(format!("failed to run ip route add: {e}")))?;
        Ok(status.success())
    }

    fn route_del(&self, cidr: &str, interface: &str) {
        let _ = Command::new("ip")
            .args(["route", "del", cidr, "dev", interface])
            .status();
    }
}

#[derive(Debug)]
#[allow(dead_code)] // fields used on Linux; non-Linux builds only construct the type
pub struct RouteManager {
    interface: Mutex<String>,
    routes_added: Mutex<Vec<(Ipv4Addr, Ipv4Addr)>>,
    #[cfg(target_os = "linux")]
    runner: Box<dyn RouteCommandRunner>,
}

impl RouteManager {
    pub fn new(interface: String) -> Self {
        Self {
            interface: Mutex::new(interface),
            routes_added: Mutex::new(Vec::new()),
            #[cfg(target_os = "linux")]
            runner: Box::new(RealCommandRunner),
        }
    }

    pub fn set_interface(&self, interface: String) {
        if let Ok(mut current) = self.interface.lock() {
            *current = interface;
        }
    }

    fn interface(&self) -> String {
        self.interface.lock().unwrap().clone()
    }

    #[cfg(all(test, target_os = "linux"))]
    fn new_with_runner(interface: String, runner: Box<dyn RouteCommandRunner>) -> Self {
        Self {
            interface: Mutex::new(interface),
            routes_added: Mutex::new(Vec::new()),
            runner,
        }
    }
}

#[allow(dead_code)]
fn parse_cidr_to_ip_mask(cidr: &str) -> Option<(Ipv4Addr, Ipv4Addr)> {
    let (ip_str, prefix_str) = cidr.split_once('/')?;
    let ip: Ipv4Addr = ip_str.parse().ok()?;
    let prefix: u32 = prefix_str.parse().ok()?;
    if prefix > 32 {
        return None;
    }
    let mask_u32 = if prefix == 0 {
        0
    } else {
        !0u32 << (32 - prefix)
    };
    let mask = Ipv4Addr::from(mask_u32);
    Some((ip, mask))
}

#[allow(dead_code)]
fn ip_mask_to_prefix(mask: Ipv4Addr) -> u32 {
    let octets = mask.octets();
    let mask_u32 = ((octets[0] as u32) << 24)
        | ((octets[1] as u32) << 16)
        | ((octets[2] as u32) << 8)
        | (octets[3] as u32);
    mask_u32.count_ones()
}

#[cfg(target_os = "linux")]
impl RouteManager {
    pub fn add_cidr_route(&self, cidr: &str) -> crate::Result<()> {
        if std::env::var("P2WLAN_DISABLE_TUN").as_deref() == Ok("1") {
            return Ok(());
        }

        // Check if route already exists
        let route_line = self.runner.route_show(cidr)?;

        if !route_line.is_empty() {
            let interface = self.interface();
            if route_line.contains(&interface) {
                info!(
                    "Route for {cidr} already exists on {} — treating as idempotent, not owned",
                    interface
                );
                // Pre-existing routes are NOT recorded to routes_added.
                // They will NOT be deleted during cleanup since only
                // routes we actually added via `ip route add` go in there.
                return Ok(());
            } else {
                return Err(crate::DaemonError::Network(format!(
                    "routing conflict: route to {cidr} already exists on another interface: {route_line}"
                )));
            }
        }

        let interface = self.interface();
        info!("Adding route for {cidr} via {}", interface);
        let success = self.runner.route_add(cidr, &interface)?;

        if !success {
            return Err(crate::DaemonError::Network(format!(
                "ip route add failed for {cidr}"
            )));
        }

        // Only after a successful `ip route add` do we record ownership.
        if let Ok(mut added) = self.routes_added.lock() {
            if let Some((ip, mask)) = parse_cidr_to_ip_mask(cidr) {
                added.push((ip, mask));
            }
        }

        Ok(())
    }

    pub fn cleanup(&self) {
        if std::env::var("P2WLAN_DISABLE_TUN").as_deref() == Ok("1") {
            return;
        }

        let routes = {
            let mut added = self.routes_added.lock().unwrap();
            let routes_copy = added.clone();
            added.clear();
            routes_copy
        };

        for (ip, mask) in routes {
            let cidr = format!("{}/{}", ip, ip_mask_to_prefix(mask));
            let interface = self.interface();
            info!("Cleaning up route for {cidr} via {}", interface);
            self.runner.route_del(&cidr, &interface);
        }
    }
}

#[cfg(target_os = "macos")]
impl RouteManager {
    pub fn add_cidr_route(&self, cidr: &str) -> crate::Result<()> {
        if std::env::var("P2WLAN_DISABLE_TUN").as_deref() == Ok("1") {
            return Ok(());
        }

        let Some((network, mask)) = parse_cidr_to_ip_mask(cidr) else {
            return Err(crate::DaemonError::Network(format!(
                "invalid route CIDR: {cidr}"
            )));
        };
        let interface = self.interface();
        info!("Adding macOS route for {cidr} via {interface}");

        let status = Command::new("/sbin/route")
            .args([
                "-n",
                "add",
                "-net",
                &network.to_string(),
                "-netmask",
                &mask.to_string(),
                "-interface",
                &interface,
            ])
            .status()
            .map_err(|e| crate::DaemonError::Network(format!("failed to run route add: {e}")))?;

        if !status.success() {
            let route_line = macos_route_get(&network.to_string()).unwrap_or_default();
            if route_line.contains(&format!("interface: {interface}")) {
                info!(
                    "Route for {cidr} already exists on {interface} — treating as idempotent, not owned"
                );
                return Ok(());
            }
            return Err(crate::DaemonError::Network(format!(
                "route add failed for {cidr} via {interface}; existing route: {route_line}"
            )));
        }

        if let Ok(mut added) = self.routes_added.lock() {
            added.push((network, mask));
        }

        Ok(())
    }

    pub fn cleanup(&self) {
        if std::env::var("P2WLAN_DISABLE_TUN").as_deref() == Ok("1") {
            return;
        }

        let routes = {
            let mut added = self.routes_added.lock().unwrap();
            let routes_copy = added.clone();
            added.clear();
            routes_copy
        };

        for (network, mask) in routes {
            let interface = self.interface();
            info!(
                "Cleaning up macOS route for {}/{} via {}",
                network,
                ip_mask_to_prefix(mask),
                interface
            );
            let _ = Command::new("/sbin/route")
                .args([
                    "-n",
                    "delete",
                    "-net",
                    &network.to_string(),
                    "-netmask",
                    &mask.to_string(),
                    "-interface",
                    &interface,
                ])
                .status();
        }
    }
}

#[cfg(target_os = "macos")]
fn macos_route_get(destination: &str) -> std::io::Result<String> {
    let output = Command::new("/sbin/route")
        .args(["-n", "get", destination])
        .output()?;
    Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
}

#[cfg(target_os = "windows")]
impl RouteManager {
    pub fn add_cidr_route(&self, cidr: &str) -> crate::Result<()> {
        if std::env::var("P2WLAN_DISABLE_TUN").as_deref() == Ok("1") {
            return Ok(());
        }

        let Some((network, mask)) = parse_cidr_to_ip_mask(cidr) else {
            return Err(crate::DaemonError::Network(format!(
                "invalid route CIDR: {cidr}"
            )));
        };
        let prefix = ip_mask_to_prefix(mask);
        let destination_prefix = format!("{network}/{prefix}");
        let interface = self.interface();

        let mut existing = windows_get_route_aliases(&destination_prefix)?;
        if windows_remove_stale_managed_routes(&destination_prefix, &interface, &existing) {
            existing = windows_get_route_aliases(&destination_prefix)?;
        }

        if !existing.is_empty() {
            if existing
                .iter()
                .any(|alias| windows_interface_alias_eq(alias, &interface))
            {
                info!(
                    "Route for {destination_prefix} already exists on {interface} — treating as idempotent, not owned"
                );
                windows_ensure_icmp_echo_firewall_rule(&destination_prefix);
                return Ok(());
            }
            return Err(crate::DaemonError::Network(format!(
                "routing conflict: route to {destination_prefix} already exists on another interface: {}",
                existing.join(", ")
            )));
        }

        info!("Adding Windows route for {destination_prefix} via {interface}");
        let output = windows_powershell_command(&format!(
            "$ErrorActionPreference = 'Stop'; New-NetRoute -DestinationPrefix '{}' -InterfaceAlias '{}' -NextHop '0.0.0.0' -PolicyStore ActiveStore -ErrorAction Stop | Out-Null",
            ps_quote(&destination_prefix),
            ps_quote(&interface)
        ))
            .output()
            .map_err(|e| crate::DaemonError::Network(format!("failed to run New-NetRoute: {e}")))?;

        if !output.status.success() {
            if windows_route_already_exists(&output) {
                let mut existing_after = windows_get_route_aliases(&destination_prefix)
                    .unwrap_or_else(|err| {
                        info!(
                            "New-NetRoute reported an existing route for {destination_prefix}, but follow-up route query failed: {err}"
                        );
                        Vec::new()
                    });
                if windows_remove_stale_managed_routes(
                    &destination_prefix,
                    &interface,
                    &existing_after,
                ) {
                    existing_after = windows_get_route_aliases(&destination_prefix)
                        .unwrap_or_else(|err| {
                            info!(
                                "Windows stale route cleanup for {destination_prefix} ran, but follow-up route query failed: {err}"
                            );
                            Vec::new()
                        });
                }

                if existing_after.is_empty()
                    || existing_after
                        .iter()
                        .any(|alias| windows_interface_alias_eq(alias, &interface))
                {
                    info!(
                        "Windows route for {destination_prefix} via {interface} already exists — treating New-NetRoute as idempotent"
                    );
                    windows_ensure_icmp_echo_firewall_rule(&destination_prefix);
                    if let Ok(mut added) = self.routes_added.lock() {
                        added.push((network, mask));
                    }
                    return Ok(());
                }

                return Err(crate::DaemonError::Network(format!(
                    "routing conflict: route to {destination_prefix} already exists on another interface: {}",
                    existing_after.join(", ")
                )));
            }

            return Err(crate::DaemonError::Network(format!(
                "New-NetRoute failed for {destination_prefix} via {interface}: {}",
                powershell_failure_detail(&output)
            )));
        }

        if let Ok(mut added) = self.routes_added.lock() {
            added.push((network, mask));
        }
        windows_ensure_icmp_echo_firewall_rule(&destination_prefix);

        Ok(())
    }

    pub fn cleanup(&self) {
        if std::env::var("P2WLAN_DISABLE_TUN").as_deref() == Ok("1") {
            return;
        }

        let routes = {
            let mut added = self.routes_added.lock().unwrap();
            let routes_copy = added.clone();
            added.clear();
            routes_copy
        };

        for (network, mask) in routes {
            let destination_prefix = format!("{}/{}", network, ip_mask_to_prefix(mask));
            let interface = self.interface();
            info!("Cleaning up Windows route for {destination_prefix} via {interface}");
            let _ = windows_powershell_command(&format!(
                "$ErrorActionPreference = 'SilentlyContinue'; Get-NetRoute -DestinationPrefix '{}' -InterfaceAlias '{}' -NextHop '0.0.0.0' -ErrorAction SilentlyContinue 2>$null | Remove-NetRoute -Confirm:$false -ErrorAction SilentlyContinue; exit 0",
                ps_quote(&destination_prefix),
                ps_quote(&interface)
            ))
                .status();
        }
    }
}

#[cfg(target_os = "windows")]
fn windows_get_route_aliases(destination_prefix: &str) -> crate::Result<Vec<String>> {
    let output = windows_powershell_command(&format!(
        "$ErrorActionPreference = 'SilentlyContinue'; Get-NetRoute -AddressFamily IPv4 -DestinationPrefix '{}' -ErrorAction SilentlyContinue 2>$null | ForEach-Object {{ $_.InterfaceAlias }}; exit 0",
        ps_quote(destination_prefix)
    ))
        .output()
        .map_err(|e| crate::DaemonError::Network(format!("failed to run Get-NetRoute: {e}")))?;

    if !output.status.success() {
        return Err(crate::DaemonError::Network(format!(
            "Get-NetRoute failed for {destination_prefix}: {}",
            powershell_failure_detail(&output)
        )));
    }

    Ok(String::from_utf8_lossy(&output.stdout)
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .map(ToString::to_string)
        .collect())
}

#[cfg(target_os = "windows")]
fn windows_remove_stale_managed_routes(
    destination_prefix: &str,
    current_interface: &str,
    aliases: &[String],
) -> bool {
    let stale_aliases: Vec<&str> = aliases
        .iter()
        .map(String::as_str)
        .filter(|alias| !windows_interface_alias_eq(alias, current_interface))
        .filter(|alias| windows_is_managed_interface_alias(alias))
        .collect();

    for alias in &stale_aliases {
        info!(
            "Removing stale Windows route for {destination_prefix} via {alias} before using {current_interface}"
        );
        let output = windows_powershell_command(&format!(
            "$ErrorActionPreference = 'SilentlyContinue'; Get-NetRoute -AddressFamily IPv4 -DestinationPrefix '{}' -InterfaceAlias '{}' -ErrorAction SilentlyContinue 2>$null | Remove-NetRoute -Confirm:$false -ErrorAction SilentlyContinue; exit 0",
            ps_quote(destination_prefix),
            ps_quote(alias)
        ))
        .output();

        match output {
            Ok(output) if output.status.success() => {}
            Ok(output) => {
                warn!(
                    "Could not remove stale Windows route for {destination_prefix} via {alias}: {}",
                    powershell_failure_detail(&output)
                );
            }
            Err(err) => {
                warn!(
                    "Could not run stale Windows route cleanup for {destination_prefix} via {alias}: {err}"
                );
            }
        }
    }

    !stale_aliases.is_empty()
}

#[cfg(any(target_os = "windows", test))]
fn windows_is_managed_interface_alias(alias: &str) -> bool {
    let alias = alias.trim().to_ascii_lowercase();
    alias == "p2wlan" || alias.starts_with("p2wlan-") || alias.starts_with("p2pnet")
}

#[cfg(target_os = "windows")]
fn windows_route_already_exists(output: &std::process::Output) -> bool {
    windows_route_already_exists_message(
        &String::from_utf8_lossy(&output.stdout),
        &String::from_utf8_lossy(&output.stderr),
    )
}

#[cfg(any(target_os = "windows", test))]
fn windows_route_already_exists_message(stdout: &str, stderr: &str) -> bool {
    let text = format!("{stdout}\n{stderr}").to_ascii_lowercase();
    text.contains("already exists")
        || (text.contains("msft_netroute") && text.contains("system error 87"))
}

#[cfg(target_os = "windows")]
fn windows_interface_alias_eq(left: &str, right: &str) -> bool {
    left.trim().eq_ignore_ascii_case(right.trim())
}

#[cfg(target_os = "windows")]
fn windows_ensure_icmp_echo_firewall_rule(destination_prefix: &str) {
    const RULE_NAME: &str = "p2wlan Overlay ICMPv4 Echo Request";
    let output = windows_powershell_command(&format!(
        "$ErrorActionPreference = 'Stop'; $name = '{}'; $cidr = '{}'; $rule = Get-NetFirewallRule -DisplayName $name -ErrorAction SilentlyContinue | Select-Object -First 1; if ($null -eq $rule) {{ New-NetFirewallRule -DisplayName $name -Direction Inbound -Action Allow -Protocol ICMPv4 -IcmpType 8 -LocalAddress $cidr -RemoteAddress $cidr -Profile Any | Out-Null }} else {{ Enable-NetFirewallRule -DisplayName $name | Out-Null }}",
        ps_quote(RULE_NAME),
        ps_quote(destination_prefix)
    ))
    .output();

    match output {
        Ok(output) if output.status.success() => {
            info!("Windows firewall rule ensured for ICMPv4 echo on overlay {destination_prefix}");
        }
        Ok(output) => {
            warn!(
                "Could not ensure Windows firewall ICMPv4 echo rule for {destination_prefix}: {}",
                powershell_failure_detail(&output)
            );
        }
        Err(err) => {
            warn!(
                "Could not run Windows firewall ICMPv4 echo rule command for {destination_prefix}: {err}"
            );
        }
    }
}

#[cfg(target_os = "windows")]
fn powershell_failure_detail(output: &std::process::Output) -> String {
    let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
    let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();
    match (stderr.is_empty(), stdout.is_empty(), output.status.code()) {
        (false, false, code) => format!(
            "exit={}; stderr={}; stdout={}",
            code.map_or_else(|| "unknown".to_string(), |code| code.to_string()),
            stderr,
            stdout
        ),
        (false, true, code) => format!(
            "exit={}; stderr={}",
            code.map_or_else(|| "unknown".to_string(), |code| code.to_string()),
            stderr
        ),
        (true, false, code) => format!(
            "exit={}; stdout={}",
            code.map_or_else(|| "unknown".to_string(), |code| code.to_string()),
            stdout
        ),
        (true, true, code) => format!(
            "exit={}; no PowerShell output",
            code.map_or_else(|| "unknown".to_string(), |code| code.to_string())
        ),
    }
}

#[cfg(target_os = "windows")]
fn ps_quote(value: &str) -> String {
    value.replace('\'', "''")
}

#[cfg(target_os = "windows")]
fn windows_powershell_command(script: &str) -> Command {
    use std::os::windows::process::CommandExt;

    const CREATE_NO_WINDOW: u32 = 0x08000000;
    let mut command = Command::new("powershell.exe");
    command.creation_flags(CREATE_NO_WINDOW).args([
        "-NoProfile",
        "-NonInteractive",
        "-ExecutionPolicy",
        "Bypass",
        "-Command",
        script,
    ]);
    command
}

#[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
impl RouteManager {
    pub fn add_cidr_route(&self, _cidr: &str) -> crate::Result<()> {
        if std::env::var("P2WLAN_DISABLE_TUN").as_deref() == Ok("1") {
            return Ok(());
        }
        Err(crate::DaemonError::Network(
            "routing configuration is not supported on this platform. Please use Linux or set P2WLAN_DISABLE_TUN=1."
                .to_string(),
        ))
    }

    pub fn cleanup(&self) {}
}

// ============================================================
// Tests
// ============================================================

#[cfg(test)]
#[cfg(target_os = "linux")]
mod tests {
    use super::*;

    /// A mock runner that simulates route table state.
    #[derive(Debug, Default)]
    struct MockRunner {
        preexisting: Mutex<Vec<String>>,
        owned_added: Mutex<Vec<String>>,
        add_fail: Mutex<Vec<String>>,
        last_show: Mutex<Option<String>>,
    }

    impl MockRunner {
        fn with_preexisting(cidr: &str) -> Self {
            Self {
                preexisting: Mutex::new(vec![cidr.to_string()]),
                ..Default::default()
            }
        }
        fn with_add_fail(cidr: &str) -> Self {
            Self {
                add_fail: Mutex::new(vec![cidr.to_string()]),
                ..Default::default()
            }
        }
    }

    impl RouteCommandRunner for MockRunner {
        fn route_show(&self, cidr: &str) -> Result<String, crate::DaemonError> {
            let mut last = self.last_show.lock().unwrap();
            *last = Some(cidr.to_string());
            if self.preexisting.lock().unwrap().iter().any(|p| p == cidr) {
                // Simulate: route exists on the target interface
                Ok(format!("{cidr} dev p2pnet0 scope link"))
            } else {
                Ok(String::new())
            }
        }

        fn route_add(&self, cidr: &str, _interface: &str) -> Result<bool, crate::DaemonError> {
            if self.add_fail.lock().unwrap().iter().any(|f| f == cidr) {
                Ok(false)
            } else {
                self.owned_added.lock().unwrap().push(cidr.to_string());
                Ok(true)
            }
        }

        fn route_del(&self, cidr: &str, _interface: &str) {
            // Simulate successful delete
            let mut owned = self.owned_added.lock().unwrap();
            owned.retain(|o| o != cidr);
        }
    }

    #[test]
    fn test_add_new_route_records_ownership() {
        let runner = Box::new(MockRunner::default());
        let rm = RouteManager::new_with_runner("p2pnet0".into(), runner);

        rm.add_cidr_route("10.20.0.0/16").unwrap();

        let added = rm.routes_added.lock().unwrap();
        assert_eq!(added.len(), 1, "new route should be recorded as owned");
    }

    #[test]
    fn test_preexisting_route_not_recorded() {
        let runner = Box::new(MockRunner::with_preexisting("10.20.0.0/16"));
        let rm = RouteManager::new_with_runner("p2pnet0".into(), runner);

        rm.add_cidr_route("10.20.0.0/16").unwrap();

        let added = rm.routes_added.lock().unwrap();
        assert_eq!(
            added.len(),
            0,
            "pre-existing route on same interface must not be recorded as owned"
        );
    }

    #[test]
    fn test_conflicting_route_on_different_interface_errors() {
        let runner = Box::new(MockRunner::with_preexisting("10.20.0.0/16"));
        // Same preexisting entry but MockRunner always reports dev p2pnet0,
        // so to test conflict we need a different interface RouteManager.
        let rm = RouteManager::new_with_runner("p2pnet1".into(), runner);

        let result = rm.add_cidr_route("10.20.0.0/16");
        assert!(result.is_err(), "conflicting route should return error");
        let err = result.unwrap_err().to_string();
        assert!(err.contains("conflict"), "error should mention conflict");
    }

    #[test]
    fn test_cleanup_only_removes_owned_routes() {
        let runner = Box::new(MockRunner::default());
        let rm = RouteManager::new_with_runner("p2pnet0".into(), runner);

        rm.add_cidr_route("10.20.0.0/16").unwrap();
        rm.add_cidr_route("192.168.0.0/24").unwrap();

        rm.cleanup();

        let added = rm.routes_added.lock().unwrap();
        assert!(added.is_empty(), "cleanup should clear all owned routes");
    }

    #[test]
    fn test_add_failure_not_recorded() {
        let runner = Box::new(MockRunner::with_add_fail("10.20.0.0/16"));
        let rm = RouteManager::new_with_runner("p2pnet0".into(), runner);

        let result = rm.add_cidr_route("10.20.0.0/16");
        assert!(result.is_err(), "add failure should propagate");

        let added = rm.routes_added.lock().unwrap();
        assert_eq!(
            added.len(),
            0,
            "failed route add must not be recorded as owned"
        );
    }
}

#[cfg(test)]
mod windows_helper_tests {
    use super::*;

    #[test]
    fn detects_managed_windows_interface_aliases() {
        assert!(windows_is_managed_interface_alias("p2wlan"));
        assert!(windows_is_managed_interface_alias("P2WLAN-test"));
        assert!(windows_is_managed_interface_alias("p2pnet0"));
        assert!(!windows_is_managed_interface_alias("Ethernet"));
        assert!(!windows_is_managed_interface_alias("Wi-Fi"));
    }

    #[test]
    fn detects_windows_route_duplicate_errors() {
        assert!(windows_route_already_exists_message(
            "",
            "New-NetRoute : Instance MSFT_NetRoute already exists"
        ));
        assert!(windows_route_already_exists_message(
            "",
            "FullyQualifiedErrorId : Windows System Error 87,New-NetRoute\nMSFT_NetRoute"
        ));
        assert!(!windows_route_already_exists_message(
            "",
            "New-NetRoute : Access is denied"
        ));
    }
}
