use std::net::Ipv4Addr;
#[cfg(target_os = "linux")]
use std::process::Command;
#[cfg(target_os = "linux")]
use tracing::{info, warn};

#[allow(dead_code)]
pub struct RouteManager {
    interface: String,
    routes_added: std::sync::Mutex<Vec<(Ipv4Addr, Ipv4Addr)>>,
}

impl RouteManager {
    pub fn new(interface: String) -> Self {
        Self {
            interface,
            routes_added: std::sync::Mutex::new(Vec::new()),
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
        let output = Command::new("ip")
            .args(&["route", "show", "to", cidr])
            .output()
            .map_err(|e| crate::DaemonError::Network(format!("failed to run ip route show: {e}")))?;

        let stdout = String::from_utf8_lossy(&output.stdout);
        let route_line = stdout.trim();

        if !route_line.is_empty() {
            if route_line.contains(&self.interface) {
                info!("Route for {cidr} already exists on {}, keeping it", self.interface);
                // Record it so we clean it up on exit anyway
                if let Ok(mut added) = self.routes_added.lock() {
                    if let Some((ip, mask)) = parse_cidr_to_ip_mask(cidr) {
                        added.push((ip, mask));
                    }
                }
                return Ok(());
            } else {
                return Err(crate::DaemonError::Network(format!(
                    "routing conflict: route to {cidr} already exists on another interface: {route_line}"
                )));
            }
        }

        info!("Adding route for {cidr} via {}", self.interface);
        let status = Command::new("ip")
            .args(&["route", "add", cidr, "dev", &self.interface])
            .status()
            .map_err(|e| crate::DaemonError::Network(format!("failed to run ip route add: {e}")))?;

        if !status.success() {
            return Err(crate::DaemonError::Network(format!(
                "ip route add failed with status: {status}"
            )));
        }

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
            info!("Cleaning up route for {cidr} via {}", self.interface);
            let _ = Command::new("ip")
                .args(&["route", "del", &cidr, "dev", &self.interface])
                .status();
        }
    }
}

#[cfg(not(target_os = "linux"))]
impl RouteManager {
    pub fn add_cidr_route(&self, _cidr: &str) -> crate::Result<()> {
        if std::env::var("P2WLAN_DISABLE_TUN").as_deref() == Ok("1") {
            return Ok(());
        }
        Err(crate::DaemonError::Network(format!(
            "routing configuration is not supported on this platform. Please use Linux or set P2WLAN_DISABLE_TUN=1."
        )))
    }

    pub fn cleanup(&self) {}
}
