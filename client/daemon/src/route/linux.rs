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

    /// Read the live system routing table for `cidr` and report its state.
    pub fn describe_overlay_route(&self, cidr: &str) -> RouteObservation {
        let expected = self.interface();
        let line = match self.runner.route_show(cidr) {
            Ok(line) => line,
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
        if line.is_empty() {
            return RouteObservation {
                cidr: cidr.to_string(),
                expected_interface: expected,
                actual_interface: None,
                state: RouteState::Missing,
                owned: self.owns_cidr(cidr),
            };
        }
        let actual = line
            .split_whitespace()
            .position(|tok| tok == "dev")
            .and_then(|idx| {
                let split: Vec<&str> = line.split_whitespace().collect();
                split.get(idx + 1).map(str::to_string)
            });
        let state = match actual.as_deref() {
            Some(iface) if iface == &expected => RouteState::Installed,
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

    /// Remove only this process's owned route for `cidr`.
    pub fn remove_cidr_route(&self, cidr: &str) {
        if std::env::var("P2WLAN_DISABLE_TUN").as_deref() == Ok("1") {
            return;
        }
        if !self.owns_cidr(cidr) {
            return;
        }
        let interface = self.interface();
        info!("Removing owned route for {cidr} via {interface}");
        self.runner.route_del(cidr, &interface);
        if let Some((ip, mask)) = parse_cidr_to_ip_mask(cidr) {
            if let Ok(mut added) = self.routes_added.lock() {
                added.retain(|(a, m)| *a != ip || *m != mask);
            }
        }
    }
}
