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

        // `route add` on macOS can print `File exists` while still returning a
        // successful process status.  That is dangerous for a second daemon:
        // the new utun is up, but the kernel keeps the overlay CIDR on an old
        // utun and every real business packet is then routed into the wrong
        // process.  Always verify the selected interface after the command,
        // regardless of the exit status.
        let route_line = macos_route_get(&network.to_string()).unwrap_or_default();
        if !route_line.contains(&format!("interface: {interface}")) {
            return Err(crate::DaemonError::Network(format!(
                "overlay route conflict for {cidr}: expected interface {interface}; existing route: {route_line}"
            )));
        }

        if status.success() {
            if let Ok(mut added) = self.routes_added.lock() {
                added.push((network, mask));
            }
            return Ok(());
        }

        info!(
            "Route for {cidr} already exists on {interface} — treating as idempotent, not owned"
        );
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

    /// Read the live system routing table for `cidr` and report its state
    /// relative to the expected TUN interface.
    pub fn describe_overlay_route(&self, cidr: &str) -> RouteObservation {
        let expected = self.interface();
        let Some((network, _mask)) = parse_cidr_to_ip_mask(cidr) else {
            return RouteObservation {
                cidr: cidr.to_string(),
                expected_interface: expected,
                actual_interface: None,
                state: RouteState::Unknown,
                owned: self.owns_cidr(cidr),
            };
        };
        let output = match macos_route_get(&network.to_string()) {
            Ok(output) => output,
            Err(_) => {
                return RouteObservation {
                    cidr: cidr.to_string(),
                    expected_interface: expected,
                    actual_interface: None,
                    state: RouteState::Unknown,
                    owned: self.owns_cidr(cidr),
                };
            }
        };
        let actual = output
            .lines()
            .find_map(|line| {
                let line = line.trim();
                let value = line.strip_prefix("interface:")?;
                Some(value.split_whitespace().next()?.to_string())
            })
            .filter(|iface| !iface.is_empty());
        let state = match actual.as_deref() {
            Some(iface) if iface == expected => RouteState::Installed,
            Some(_) => RouteState::Conflict,
            None => RouteState::Missing,
        };
        RouteObservation {
            cidr: cidr.to_string(),
            expected_interface: expected,
            actual_interface: actual,
            state,
            owned: self.owns_cidr(cidr),
        }
    }

    /// Remove only this process's owned route for `cidr`, without touching the
    /// TUN or sessions.
    pub fn remove_cidr_route(&self, cidr: &str) {
        if std::env::var("P2WLAN_DISABLE_TUN").as_deref() == Ok("1") {
            return;
        }
        let Some((network, mask)) = parse_cidr_to_ip_mask(cidr) else {
            return;
        };
        if !self.owns_cidr(cidr) {
            return;
        }
        let interface = self.interface();
        info!(
            "Removing owned macOS route for {}/{} via {}",
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
        if let Ok(mut added) = self.routes_added.lock() {
            added.retain(|(ip, m)| *ip != network || *m != mask);
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
