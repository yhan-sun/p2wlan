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

#[cfg(all(target_os = "linux", not(target_env = "ohos")))]
#[derive(Debug)]
pub struct RealCommandRunner;

#[cfg(all(target_os = "linux", not(target_env = "ohos")))]
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
    #[cfg(target_env = "ohos")]
    ohos_route_authority: Mutex<Option<OhosRouteAuthority>>,
    #[cfg(all(target_os = "linux", not(target_env = "ohos")))]
    runner: Box<dyn RouteCommandRunner>,
}

impl RouteManager {
    pub fn new(interface: String) -> Self {
        Self {
            interface: Mutex::new(interface),
            routes_added: Mutex::new(Vec::new()),
            #[cfg(target_env = "ohos")]
            ohos_route_authority: Mutex::new(None),
            #[cfg(all(target_os = "linux", not(target_env = "ohos")))]
            runner: Box::new(RealCommandRunner),
        }
    }

    /// Bind immutable route evidence to the VPN instance that owns this
    /// manager. This can only be set once, before daemon startup.
    #[cfg(target_env = "ohos")]
    pub fn bind_ohos_vpn(
        &self,
        identity: OhosVpnIdentity,
        confirmation: Option<OhosVpnRouteConfirmation>,
    ) -> crate::Result<()> {
        let mut authority = self
            .ohos_route_authority
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if authority.is_some() {
            return Err(crate::DaemonError::OhosRouteAuthorityAlreadyBound);
        }
        *authority = Some(OhosRouteAuthority::new(identity, confirmation));
        Ok(())
    }

    /// The interface the overlay route should be (and, once installed, is) on.
    /// On macOS this is the kernel-assigned `utunN`; on Linux/Windows it is the
    /// configured name.
    pub fn current_interface(&self) -> String {
        self.interface()
    }

    /// Routes this process recorded as having installed itself. `None`-safe:
    /// returns a clone.
    pub fn owned_routes(&self) -> Vec<(Ipv4Addr, Ipv4Addr)> {
        self.routes_added
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .clone()
    }

    /// Whether this process recorded itself as having installed `cidr`.
    fn owns_cidr(&self, cidr: &str) -> bool {
        match parse_cidr_to_ip_mask(cidr) {
            Some(pair) => self.owned_routes().contains(&pair),
            None => false,
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

    #[cfg(all(test, target_os = "linux", not(target_env = "ohos")))]
    fn new_with_runner(interface: String, runner: Box<dyn RouteCommandRunner>) -> Self {
        Self {
            interface: Mutex::new(interface),
            routes_added: Mutex::new(Vec::new()),
            #[cfg(target_env = "ohos")]
            ohos_route_authority: Mutex::new(None),
            runner,
        }
    }
}

/// Stable identity for one HarmonyOS VPN creation generation.
///
/// The constructor rejects empty identities and generation zero. Keep the
/// fields private so callers cannot accidentally bypass that validation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OhosVpnIdentity {
    instance_id: String,
    generation: u64,
}

impl OhosVpnIdentity {
    pub fn new(instance_id: impl Into<String>, generation: u64) -> crate::Result<Self> {
        let instance_id = instance_id.into();
        if instance_id.trim().is_empty() || instance_id.contains('\0') || generation == 0 {
            return Err(crate::DaemonError::OhosVpnIdentityInvalid);
        }
        Ok(Self {
            instance_id,
            generation,
        })
    }

    pub fn instance_id(&self) -> &str {
        &self.instance_id
    }

    pub fn generation(&self) -> u64 {
        self.generation
    }
}

/// Immutable snapshot of routes from the exact successful
/// `VpnConnection.create(config)` call for one VPN identity.
///
/// Construct this only after that create promise resolves. The route list is
/// normalized before storage so later checks compare network prefixes rather
/// than caller formatting.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OhosVpnRouteConfirmation {
    identity: OhosVpnIdentity,
    routes: BTreeSet<String>,
}

impl OhosVpnRouteConfirmation {
    pub fn after_successful_create(
        identity: OhosVpnIdentity,
        routes: impl IntoIterator<Item = String>,
    ) -> crate::Result<Self> {
        let mut normalized_routes = BTreeSet::new();
        for cidr in routes {
            let normalized = normalize_cidr(&cidr)
                .ok_or(crate::DaemonError::OhosRouteConfirmationInvalid { cidr })?;
            normalized_routes.insert(normalized);
        }
        Ok(Self {
            identity,
            routes: normalized_routes,
        })
    }

    pub fn identity(&self) -> &OhosVpnIdentity {
        &self.identity
    }

    pub fn routes(&self) -> impl Iterator<Item = &str> {
        self.routes.iter().map(String::as_str)
    }
}

/// Pure route-authority logic shared with host tests. The live OHOS manager
/// uses this value to decide which observations may be reported as Installed.
#[derive(Debug, Clone)]
pub struct OhosRouteAuthority {
    current_identity: OhosVpnIdentity,
    confirmation: Option<OhosVpnRouteConfirmation>,
}

impl OhosRouteAuthority {
    pub fn new(
        current_identity: OhosVpnIdentity,
        confirmation: Option<OhosVpnRouteConfirmation>,
    ) -> Self {
        Self {
            current_identity,
            confirmation,
        }
    }

    fn current_confirmation(&self) -> crate::Result<&OhosVpnRouteConfirmation> {
        let confirmation = self
            .confirmation
            .as_ref()
            .ok_or(crate::DaemonError::OhosRouteConfirmationMissing)?;
        if confirmation.identity != self.current_identity {
            return Err(crate::DaemonError::OhosRouteConfirmationStale {
                current_instance_id: self.current_identity.instance_id.clone(),
                current_generation: self.current_identity.generation,
                confirmed_instance_id: confirmation.identity.instance_id.clone(),
                confirmed_generation: confirmation.identity.generation,
            });
        }
        Ok(confirmation)
    }

    fn normalized_route(&self, cidr: &str) -> crate::Result<String> {
        normalize_cidr(cidr)
            .ok_or_else(|| crate::DaemonError::Network(format!("invalid overlay CIDR: {cidr}")))
    }

    /// Validate that an add request is already configured in the current VPN.
    /// OHOS route state is immutable until the VPN is destroyed and recreated.
    pub fn ensure_configured(&self, cidr: &str) -> crate::Result<()> {
        let normalized = self.normalized_route(cidr)?;
        let confirmation = self.current_confirmation()?;
        if confirmation.routes.contains(&normalized) {
            return Ok(());
        }
        Err(crate::DaemonError::OhosRouteNotConfigured {
            cidr: normalized,
            generation: self.current_identity.generation,
        })
    }

    #[cfg(any(target_env = "ohos", test))]
    fn state_for(&self, cidr: &str) -> (RouteState, bool) {
        let Some(normalized) = normalize_cidr(cidr) else {
            return (RouteState::Unknown, false);
        };
        let Ok(confirmation) = self.current_confirmation() else {
            return (RouteState::Unknown, false);
        };
        if confirmation.routes.contains(&normalized) {
            (RouteState::Installed, true)
        } else {
            (RouteState::Missing, false)
        }
    }
}

fn normalize_cidr(cidr: &str) -> Option<String> {
    let (address, prefix) = cidr.split_once('/')?;
    if prefix.is_empty() || prefix.contains('/') {
        return None;
    }
    let prefix = prefix.parse::<u8>().ok()?;
    match address.parse::<IpAddr>().ok()? {
        IpAddr::V4(address) if prefix <= 32 => {
            let mask = if prefix == 0 {
                0
            } else {
                u32::MAX << (32 - prefix)
            };
            Some(format!(
                "{}/{}",
                Ipv4Addr::from(u32::from(address) & mask),
                prefix
            ))
        }
        IpAddr::V6(address) if prefix <= 128 => {
            let mask = if prefix == 0 {
                0
            } else {
                u128::MAX << (128 - prefix)
            };
            Some(format!(
                "{}/{}",
                Ipv6Addr::from(u128::from(address) & mask),
                prefix
            ))
        }
        _ => None,
    }
}

#[cfg(test)]
mod ohos_route_authority_tests {
    use super::*;

    fn identity(instance_id: &str, generation: u64) -> OhosVpnIdentity {
        OhosVpnIdentity::new(instance_id, generation).unwrap()
    }

    fn confirmation(
        instance_id: &str,
        generation: u64,
        routes: &[&str],
    ) -> OhosVpnRouteConfirmation {
        OhosVpnRouteConfirmation::after_successful_create(
            identity(instance_id, generation),
            routes.iter().map(|route| (*route).to_string()),
        )
        .unwrap()
    }

    #[test]
    fn identity_rejects_empty_nul_and_zero_generation() {
        for (instance_id, generation) in [("", 1), ("  \t", 1), ("vpn\0a", 1), ("vpn-a", 0)] {
            assert!(matches!(
                OhosVpnIdentity::new(instance_id, generation),
                Err(crate::DaemonError::OhosVpnIdentityInvalid)
            ));
        }
    }

    #[test]
    fn missing_confirmation_is_unknown_and_add_fails_closed() {
        let authority = OhosRouteAuthority::new(identity("vpn-a", 1), None);
        assert_eq!(
            authority.state_for("10.20.0.1/16"),
            (RouteState::Unknown, false)
        );
        assert!(matches!(
            authority.ensure_configured("10.20.0.1/16"),
            Err(crate::DaemonError::OhosRouteConfirmationMissing)
        ));
    }

    #[test]
    fn invalid_route_input_and_confirmation_are_rejected() {
        assert!(matches!(
            OhosVpnRouteConfirmation::after_successful_create(
                identity("vpn-a", 1),
                vec!["10.20.0.0/33".to_string()],
            ),
            Err(crate::DaemonError::OhosRouteConfirmationInvalid { .. })
        ));

        let authority = OhosRouteAuthority::new(
            identity("vpn-a", 1),
            Some(confirmation("vpn-a", 1, &["10.20.0.0/16"])),
        );
        assert_eq!(
            authority.state_for("not-a-cidr"),
            (RouteState::Unknown, false)
        );
        assert!(matches!(
            authority.ensure_configured("not-a-cidr"),
            Err(crate::DaemonError::Network(_))
        ));
    }

    #[test]
    fn confirmation_is_bound_to_full_identity_and_generation() {
        let stale_generation = OhosRouteAuthority::new(
            identity("vpn-a", 2),
            Some(confirmation("vpn-a", 1, &["10.20.0.0/16"])),
        );
        assert_eq!(
            stale_generation.state_for("10.20.0.0/16"),
            (RouteState::Unknown, false)
        );
        assert!(matches!(
            stale_generation.ensure_configured("10.20.0.0/16"),
            Err(crate::DaemonError::OhosRouteConfirmationStale {
                current_generation: 2,
                confirmed_generation: 1,
                ..
            })
        ));

        let stale_identity = OhosRouteAuthority::new(
            identity("vpn-b", 1),
            Some(confirmation("vpn-a", 1, &["10.20.0.0/16"])),
        );
        assert_eq!(
            stale_identity.state_for("10.20.0.0/16"),
            (RouteState::Unknown, false)
        );
    }

    #[test]
    fn only_confirmed_normalized_routes_are_installed() {
        let authority = OhosRouteAuthority::new(
            identity("vpn-a", 3),
            Some(confirmation("vpn-a", 3, &["10.20.0.7/16"])),
        );
        assert_eq!(
            authority.state_for("10.20.9.5/16"),
            (RouteState::Installed, true)
        );
        assert!(authority.ensure_configured("10.20.9.5/16").is_ok());
        assert_eq!(
            authority.state_for("10.21.0.0/16"),
            (RouteState::Missing, false)
        );
        assert!(matches!(
            authority.ensure_configured("10.21.0.0/16"),
            Err(crate::DaemonError::OhosRouteNotConfigured { generation: 3, .. })
        ));
    }

    #[test]
    fn ipv6_confirmation_is_normalized_before_route_lookup() {
        let authority = OhosRouteAuthority::new(
            identity("vpn-v6", 1),
            Some(confirmation("vpn-v6", 1, &["2001:db8:1234:5678::42/64"])),
        );
        assert_eq!(
            authority.state_for("2001:db8:1234:5678::/64"),
            (RouteState::Installed, true)
        );
        assert!(authority
            .ensure_configured("2001:db8:1234:5678::abcd/64")
            .is_ok());
        assert_eq!(
            authority.state_for("2001:db8:1234:5679::1/64"),
            (RouteState::Missing, false)
        );
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

/// Authoritative install state for one overlay route, derived from the live
/// system routing table (never inferred from "daemon running + virtual IP").
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RouteState {
    /// Present on the expected interface.
    Installed,
    /// Not present in the system routing table at all.
    Missing,
    /// Present, but on a different interface than expected.
    Conflict,
    /// Could not be determined (platform unsupported, or the query failed).
    Unknown,
}

impl RouteState {
    pub fn as_str(self) -> &'static str {
        match self {
            RouteState::Installed => "installed",
            RouteState::Missing => "missing",
            RouteState::Conflict => "conflict",
            RouteState::Unknown => "unknown",
        }
    }
}

/// One authoritative route observation returned by `GET /routes` and
/// `POST /routes/verify`.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct RouteObservation {
    pub cidr: String,
    /// Interface the overlay route is expected to live on (the TUN name).
    pub expected_interface: String,
    /// Interface the system routing table actually reports, if any.
    pub actual_interface: Option<String>,
    pub state: RouteState,
    /// Whether this process installed (owns) this route.
    pub owned: bool,
}

impl RouteManager {
    /// Repair the single overlay route for `cidr` **without** touching the TUN,
    /// the encrypted sessions, or peer state:
    ///   - `Installed` -> no-op;
    ///   - `Missing`   -> add it;
    ///   - `Conflict`  -> remove then re-add (best effort);
    ///   - `Unknown`   -> no-op (cannot safely decide).
    ///
    /// Returns the post-repair observation.
    pub fn repair_overlay_route(&self, cidr: &str) -> RouteObservation {
        let initial = self.describe_overlay_route(cidr);
        match initial.state {
            RouteState::Installed => return initial,
            RouteState::Missing => {
                let _ = self.add_cidr_route(cidr);
            }
            RouteState::Conflict => {
                self.remove_cidr_route(cidr);
                let _ = self.add_cidr_route(cidr);
            }
            RouteState::Unknown => return initial,
        }
        self.describe_overlay_route(cidr)
    }
}
