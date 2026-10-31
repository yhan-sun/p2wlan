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

/// Android installs overlay routes as part of `VpnService.Builder`. Its
/// route intent is available to this process when the fd is handed over.
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

/// HarmonyOS route operations must be backed by the exact immutable route
/// snapshot from the current successful `VpnConnection.create(config)`.
/// Route additions/removals require destroying and recreating that VPN.
#[cfg(target_env = "ohos")]
impl RouteManager {
    pub fn add_cidr_route(&self, cidr: &str) -> crate::Result<()> {
        let authority = self
            .ohos_route_authority
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let authority = authority
            .as_ref()
            .ok_or(crate::DaemonError::OhosRouteConfirmationMissing)?;
        authority.ensure_configured(cidr)
    }

    pub fn cleanup(&self) {
        *self
            .ohos_route_authority
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = None;
    }

    pub fn describe_overlay_route(&self, cidr: &str) -> RouteObservation {
        let expected_interface = self.interface();
        let authority = self
            .ohos_route_authority
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let (state, owned) = authority
            .as_ref()
            .map(|authority| authority.state_for(cidr))
            .unwrap_or((RouteState::Unknown, false));
        RouteObservation {
            cidr: cidr.to_string(),
            expected_interface: expected_interface.clone(),
            actual_interface: (state == RouteState::Installed).then_some(expected_interface),
            state,
            owned,
        }
    }

    /// Harmony route configuration is part of the VPN create call and cannot
    /// be removed from this process. Keep the confirmation immutable until
    /// cleanup destroys the current route authority.
    pub fn remove_cidr_route(&self, _cidr: &str) {}
}
