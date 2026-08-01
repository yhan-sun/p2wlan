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
