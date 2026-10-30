pub(super) async fn default_ipv4_gateway() -> Option<Ipv4Addr> {
    tokio::task::spawn_blocking(default_ipv4_gateway_blocking)
        .await
        .ok()
        .flatten()
}

fn default_ipv4_gateway_blocking() -> Option<Ipv4Addr> {
    #[cfg(any(target_os = "macos", target_os = "ios", target_os = "freebsd"))]
    {
        let output = Command::new("/sbin/route")
            .args(["-n", "get", "default"])
            .output()
            .ok()?;
        if !output.status.success() {
            return None;
        }
        return parse_first_ipv4(&String::from_utf8_lossy(&output.stdout));
    }

    #[cfg(any(
        all(target_os = "linux", not(target_env = "ohos")),
        target_os = "android"
    ))]
    {
        let output = Command::new("ip")
            .args(["route", "show", "default"])
            .output()
            .ok()?;
        if !output.status.success() {
            return None;
        }
        return parse_first_ipv4(&String::from_utf8_lossy(&output.stdout));
    }

    #[cfg(target_os = "windows")]
    {
        use std::os::windows::process::CommandExt;

        // This query runs during daemon startup. The daemon is launched from
        // a GUI process, so PowerShell must not attach/create a console while
        // it determines the host's default gateway.
        const CREATE_NO_WINDOW: u32 = 0x08000000;
        let mut command = Command::new("powershell.exe");
        command.creation_flags(CREATE_NO_WINDOW);
        let output = command
            .args([
                "-NoProfile",
                "-Command",
                "(Get-NetRoute -DestinationPrefix '0.0.0.0/0' | Sort-Object RouteMetric,InterfaceMetric | Select-Object -First 1).NextHop",
            ])
            .output()
            .ok()?;
        if !output.status.success() {
            return None;
        }
        return parse_first_ipv4(&String::from_utf8_lossy(&output.stdout));
    }

    #[allow(unreachable_code)]
    None
}

pub(super) fn parse_first_ipv4(text: &str) -> Option<Ipv4Addr> {
    text.split_whitespace().find_map(parse_ipv4_token)
}

fn parse_ipv4_token(token: &str) -> Option<Ipv4Addr> {
    token
        .trim_matches(|ch: char| !(ch.is_ascii_digit() || ch == '.'))
        .parse()
        .ok()
}

pub(super) fn subnet_prefix_score(a: Ipv4Addr, b: Ipv4Addr) -> u8 {
    let ao = a.octets();
    let bo = b.octets();
    if ao[0] == bo[0] && ao[1] == bo[1] && ao[2] == bo[2] {
        24
    } else if ao[0] == bo[0] && ao[1] == bo[1] {
        16
    } else if ao[0] == 10 && bo[0] == 10 {
        8
    } else {
        0
    }
}

pub(super) fn resolve_physical_lan_ipv4_for_port_with_addresses(
    port: u16,
    gateway: Option<Ipv4Addr>,
    addresses: &[IpAddr],
) -> Option<SocketAddr> {
    if port == 0 {
        return None;
    }

    if let Some(gw) = gateway {
        // 1. Subnet matching against known/provided interface addresses
        let mut best_match: Option<(Ipv4Addr, u8)> = None;
        for addr in addresses {
            if let IpAddr::V4(v4) = *addr {
                let candidate = SocketAddr::new(IpAddr::V4(v4), port);
                if is_port_mapping_local_addr(candidate) {
                    let score = subnet_prefix_score(v4, gw);
                    if score > 0 && best_match.as_ref().is_none_or(|(_, s)| score > *s) {
                        best_match = Some((v4, score));
                    }
                }
            }
        }
        if let Some((v4, _)) = best_match {
            return Some(SocketAddr::new(IpAddr::V4(v4), port));
        }

        // 2. Try an OS routing probe to the gateway if no provided address
        // matched.  A wildcard-bound socket has no interface affinity of its
        // own, so the route to the gateway is the only authoritative fallback.
        let probe_target = SocketAddr::new(IpAddr::V4(gw), 80);
        if let Ok(socket) = std::net::UdpSocket::bind("0.0.0.0:0") {
            if socket.connect(probe_target).is_ok() {
                if let Ok(local) = socket.local_addr() {
                    if let IpAddr::V4(v4) = local.ip() {
                        let candidate = SocketAddr::new(IpAddr::V4(v4), port);
                        if is_port_mapping_local_addr(candidate) {
                            return Some(candidate);
                        }
                    }
                }
            }
        }

        // Do not fall through to an arbitrary LAN address when we know which
        // gateway will receive the mapping protocol packets.  On multi-NIC
        // hosts that would send UPnP/PCP/NAT-PMP from one interface to the
        // gateway on another, and leave a deceptively usable-looking but
        // unreachable mapped candidate behind.
        return None;
    } else {
        // Probe route to public IP to find outgoing default interface
        let public_target = SocketAddr::from(([8, 8, 8, 8], 53));
        if let Ok(socket) = std::net::UdpSocket::bind("0.0.0.0:0") {
            if socket.connect(public_target).is_ok() {
                if let Ok(local) = socket.local_addr() {
                    if let IpAddr::V4(v4) = local.ip() {
                        let candidate = SocketAddr::new(IpAddr::V4(v4), port);
                        if is_port_mapping_local_addr(candidate) {
                            return Some(candidate);
                        }
                    }
                }
            }
        }
    }

    // Fallback: any valid LAN address
    for addr in addresses {
        if let IpAddr::V4(v4) = *addr {
            let candidate = SocketAddr::new(IpAddr::V4(v4), port);
            if is_port_mapping_local_addr(candidate) {
                return Some(candidate);
            }
        }
    }
    None
}

#[allow(dead_code)]
pub(super) fn resolve_physical_lan_ipv4_for_port(
    port: u16,
    gateway: Option<Ipv4Addr>,
) -> Option<SocketAddr> {
    resolve_physical_lan_ipv4_for_port_with_addresses(
        port,
        gateway,
        &p2pnet_nat::gather_local_addresses(),
    )
}

pub(super) fn port_mapping_local_addr(
    udp_local_addr: Option<SocketAddr>,
    candidates: &[String],
    candidate_sources: &HashMap<String, String>,
    gateway: Option<Ipv4Addr>,
) -> Option<SocketAddr> {
    port_mapping_local_addr_with_addresses(
        udp_local_addr,
        candidates,
        candidate_sources,
        gateway,
        &p2pnet_nat::gather_local_addresses(),
    )
}

pub(super) fn port_mapping_local_addr_with_addresses(
    udp_local_addr: Option<SocketAddr>,
    candidates: &[String],
    candidate_sources: &HashMap<String, String>,
    gateway: Option<Ipv4Addr>,
    addresses: &[IpAddr],
) -> Option<SocketAddr> {
    let target_port = udp_local_addr.map(|addr| addr.port()).filter(|&p| p > 0);

    if udp_local_addr.is_some_and(is_port_mapping_local_addr) {
        return udp_local_addr;
    }

    let port = target_port?;

    let host_candidate = |require_gateway_match: bool| {
        candidates.iter().find_map(|candidate| {
            if candidate_sources.get(candidate).map(String::as_str) != Some("host") {
                return None;
            }
            let endpoint = candidate.parse::<SocketAddr>().ok()?;
            if !is_port_mapping_local_addr(endpoint) {
                return None;
            }
            if require_gateway_match
                && !gateway.is_some_and(|gw| match endpoint.ip() {
                    IpAddr::V4(ip) => subnet_prefix_score(ip, gw) > 0,
                    IpAddr::V6(_) => false,
                })
            {
                return None;
            }
            Some(SocketAddr::new(endpoint.ip(), port))
        })
    };

    if gateway.is_some() {
        // Both a host candidate and an interface-enumeration fallback may be
        // present here.  Prefer the physical interface selected for the
        // gateway, so candidate ordering cannot make a stale VPN/secondary
        // interface drive gateway mapping traffic.
        return resolve_physical_lan_ipv4_for_port_with_addresses(port, gateway, addresses)
            .or_else(|| host_candidate(true));
    }

    // Without a discoverable gateway a current host candidate is still the
    // best concrete binding hint.  It must use the active socket port, never
    // the port captured by an older candidate snapshot.
    host_candidate(false)
        .or_else(|| resolve_physical_lan_ipv4_for_port_with_addresses(port, None, addresses))
}

fn is_port_mapping_local_addr(endpoint: SocketAddr) -> bool {
    endpoint.port() > 0
        && matches!(
            endpoint.ip(),
            IpAddr::V4(ip)
                if !ip.is_loopback()
                    && !ip.is_unspecified()
                    && !ip.is_multicast()
                    && !ip.is_link_local()
                    && !ip.is_broadcast()
        )
}

fn local_addr_ipv4(endpoint: SocketAddr) -> Option<Ipv4Addr> {
    match endpoint.ip() {
        IpAddr::V4(ip) if is_port_mapping_local_addr(endpoint) => Some(ip),
        _ => None,
    }
}

fn is_shared_ipv4(ip: std::net::Ipv4Addr) -> bool {
    let octets = ip.octets();
    octets[0] == 100 && (64..=127).contains(&octets[1])
}
