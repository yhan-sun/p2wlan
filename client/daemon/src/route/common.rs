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
