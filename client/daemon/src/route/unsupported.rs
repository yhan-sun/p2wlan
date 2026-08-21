#[cfg(not(any(
    target_os = "linux",
    target_os = "macos",
    target_os = "windows",
    target_os = "android"
)))]
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

    pub fn describe_overlay_route(&self, cidr: &str) -> RouteObservation {
        RouteObservation {
            cidr: cidr.to_string(),
            expected_interface: self.interface(),
            actual_interface: None,
            state: RouteState::Unknown,
            owned: self.owns_cidr(cidr),
        }
    }

    pub fn remove_cidr_route(&self, _cidr: &str) {}
}

/// Android installs the overlay route atomically as part of
/// `VpnService.Builder`. The daemon must not invoke shell route commands or
/// report the route as unknown after the VPN service has handed us its fd.
#[cfg(target_os = "android")]
impl RouteManager {
    pub fn add_cidr_route(&self, cidr: &str) -> crate::Result<()> {
        let Some(route) = parse_cidr_to_ip_mask(cidr) else {
            return Err(crate::DaemonError::Network(format!(
                "invalid overlay CIDR: {cidr}"
            )));
        };
        let mut owned = self
            .routes_added
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if !owned.contains(&route) {
            owned.push(route);
        }
        Ok(())
    }

    pub fn cleanup(&self) {
        self.routes_added
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clear();
    }

    pub fn describe_overlay_route(&self, cidr: &str) -> RouteObservation {
        RouteObservation {
            cidr: cidr.to_string(),
            expected_interface: self.interface(),
            actual_interface: Some(self.interface()),
            state: if self.owns_cidr(cidr) {
                RouteState::Installed
            } else {
                // The add operation is called immediately after the Android
                // service establishes the route. This branch is retained for
                // diagnostics during an early startup failure.
                RouteState::Missing
            },
            owned: self.owns_cidr(cidr),
        }
    }

    pub fn remove_cidr_route(&self, cidr: &str) {
        if let Some(route) = parse_cidr_to_ip_mask(cidr) {
            self.routes_added
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .retain(|owned| *owned != route);
        }
    }
}
