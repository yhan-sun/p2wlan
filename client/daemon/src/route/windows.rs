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

        let mut existing = windows_get_route_aliases(&destination_prefix).unwrap_or_else(|err| {
            warn!(
                "Windows route pre-check for {destination_prefix} failed: {err}; continuing with route install"
            );
            Vec::new()
        });
        if windows_remove_stale_managed_routes(&destination_prefix, &interface, &existing) {
            existing = windows_get_route_aliases(&destination_prefix).unwrap_or_else(|err| {
                warn!(
                    "Windows route query after stale cleanup for {destination_prefix} failed: {err}; continuing with route install"
                );
                Vec::new()
            });
        }

        if existing.is_empty()
            && windows_netsh_route_exists_on_interface(&destination_prefix, &interface)
        {
            info!(
                "Route for {destination_prefix} already exists on {interface} according to netsh — treating as idempotent, not owned"
            );
            windows_ensure_icmp_echo_firewall_rule(&destination_prefix);
            return Ok(());
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
        let route_script = format!(
            "$ErrorActionPreference = 'Stop'; New-NetRoute -DestinationPrefix '{}' -InterfaceAlias '{}' -NextHop '0.0.0.0' -PolicyStore ActiveStore -ErrorAction Stop | Out-Null",
            ps_quote(&destination_prefix),
            ps_quote(&interface)
        );
        let output = match windows_powershell_output(
            &route_script,
            std::time::Duration::from_secs(8),
        ) {
            Ok(output) => output,
            Err(err) => {
                warn!(
                    "New-NetRoute did not complete for {destination_prefix} via {interface}: {err}; trying netsh fallback"
                );
                windows_netsh_add_route(&destination_prefix, &interface, network, mask, self)?;
                windows_ensure_icmp_echo_firewall_rule(&destination_prefix);
                return Ok(());
            }
        };

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

            let primary_error = powershell_failure_detail(&output);
            warn!(
                "New-NetRoute failed for {destination_prefix} via {interface}: {primary_error}; trying netsh fallback"
            );
            if let Err(fallback_error) =
                windows_netsh_add_route(&destination_prefix, &interface, network, mask, self)
            {
                return Err(crate::DaemonError::Network(format!(
                    "New-NetRoute failed for {destination_prefix} via {interface}: {primary_error}; netsh fallback failed: {fallback_error}"
                )));
            }
            windows_ensure_icmp_echo_firewall_rule(&destination_prefix);
            return Ok(());
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
            let _ = windows_powershell_output(&format!(
                "$ErrorActionPreference = 'SilentlyContinue'; Get-NetRoute -DestinationPrefix '{}' -InterfaceAlias '{}' -NextHop '0.0.0.0' -ErrorAction SilentlyContinue 2>$null | Remove-NetRoute -Confirm:$false -ErrorAction SilentlyContinue; exit 0",
                ps_quote(&destination_prefix),
                ps_quote(&interface)
            ), WINDOWS_ROUTE_QUERY_TIMEOUT);
        }
    }

    /// Read the live system routing table for `cidr` and report its state.
    pub fn describe_overlay_route(&self, cidr: &str) -> RouteObservation {
        let expected = self.interface();
        let Some((network, mask)) = parse_cidr_to_ip_mask(cidr) else {
            return RouteObservation {
                cidr: cidr.to_string(),
                expected_interface: expected,
                actual_interface: None,
                state: RouteState::Unknown,
                owned: self.owns_cidr(cidr),
            };
        };
        let destination_prefix = format!("{network}/{}", ip_mask_to_prefix(mask));
        let aliases = match windows_get_route_aliases(&destination_prefix) {
            Ok(aliases) => aliases,
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
        if aliases.is_empty() {
            return RouteObservation {
                cidr: cidr.to_string(),
                expected_interface: expected,
                actual_interface: None,
                state: RouteState::Missing,
                owned: self.owns_cidr(cidr),
            };
        }
        let on_expected = aliases
            .iter()
            .any(|alias| windows_interface_alias_eq(alias, &expected));
        let (state, actual) = if on_expected {
            (RouteState::Installed, aliases.into_iter().next())
        } else {
            (RouteState::Conflict, aliases.into_iter().next())
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
        let Some((network, mask)) = parse_cidr_to_ip_mask(cidr) else {
            return;
        };
        let destination_prefix = format!("{network}/{}", ip_mask_to_prefix(mask));
        let interface = self.interface();
        info!("Removing owned Windows route for {destination_prefix} via {interface}");
        let _ = windows_powershell_output(&format!(
            "$ErrorActionPreference = 'SilentlyContinue'; Get-NetRoute -DestinationPrefix '{}' -InterfaceAlias '{}' -NextHop '0.0.0.0' -ErrorAction SilentlyContinue 2>$null | Remove-NetRoute -Confirm:$false -ErrorAction SilentlyContinue; exit 0",
            ps_quote(&destination_prefix),
            ps_quote(&interface)
        ), WINDOWS_ROUTE_QUERY_TIMEOUT);
        if let Ok(mut added) = self.routes_added.lock() {
            added.retain(|(ip, m)| *ip != network || *m != mask);
        }
    }
}

include!("windows/helpers.rs");
