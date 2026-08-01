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
