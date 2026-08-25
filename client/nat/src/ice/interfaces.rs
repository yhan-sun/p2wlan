/// Compute the ICE priority for a candidate.
///
/// RFC 8445 §6.1.2.3: `PRIORITY = 2^24 * G + 2^8 * local_preference +
/// (256 - component_id)`, where `G` is the type preference.  The final term is
/// `256 - component_id` (not `component_id`): for a single component (id 1)
/// this is 255, and a higher component_id must rank *lower*, which the bare
/// `+ component_id` term got backwards.
pub fn compute_priority(candidate_type: CandidateType) -> u32 {
    let type_pref = match candidate_type {
        CandidateType::Host => PREF_HOST,
        CandidateType::PortMapped => PREF_PORT_MAPPED,
        CandidateType::PeerReflexive => PREF_PEER_REFLEXIVE,
        CandidateType::ServerReflexive => PREF_SERVER_REFLEXIVE,
        CandidateType::Relay => PREF_RELAY,
    };
    (1u32 << 24) * type_pref + (1u32 << 8) * LOCAL_PREF + (256 - COMPONENT_ID)
}

/// One local interface address and its directly-connected network prefix.
///
/// This is deliberately kept separate from the advertised Host candidate. A
/// remote private address is only an on-link fast-path candidate when it falls
/// inside one of these prefixes; RFC1918/ULA classification alone is not
/// sufficient on a machine with several LANs or an overlay interface.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct LocalNetwork {
    pub address: IpAddr,
    pub prefix_len: u8,
}

impl LocalNetwork {
    pub const fn new(address: IpAddr, prefix_len: u8) -> Self {
        Self {
            address,
            prefix_len,
        }
    }

    pub fn contains(&self, remote: IpAddr) -> bool {
        match (self.address, remote) {
            (IpAddr::V4(local), IpAddr::V4(remote)) => {
                let prefix_len = self.prefix_len.min(32);
                let mask = if prefix_len == 0 {
                    0
                } else {
                    u32::MAX << (32 - prefix_len)
                };
                (u32::from(local) & mask) == (u32::from(remote) & mask)
            }
            (IpAddr::V6(local), IpAddr::V6(remote)) => {
                let prefix_len = self.prefix_len.min(128);
                let mask = if prefix_len == 0 {
                    0
                } else {
                    u128::MAX << (128 - prefix_len)
                };
                (u128::from(local) & mask) == (u128::from(remote) & mask)
            }
            _ => false,
        }
    }
}

/// Gather local network interface addresses.
///
/// Enumerates interface addresses first, then supplements them with UDP route
/// probes. Interface enumeration is important on hosts with VPN/utun routes
/// that hijack every public route probe, while the actual LAN address remains
/// available on a physical interface.
pub fn gather_local_addresses() -> Vec<IpAddr> {
    let interfaces = interface_addresses();
    let mut route_probes = Vec::new();

    for probe in ["1.1.1.1:53", "8.8.8.8:53", "223.5.5.5:53"] {
        if let Some(ip) = route_probe_source_ip("0.0.0.0:0", probe) {
            push_unique(&mut route_probes, ip);
        }
    }

    for probe in ["[2606:4700:4700::1111]:53", "[2001:4860:4860::8888]:53"] {
        if let Some(ip) = route_probe_source_ip("[::]:0", probe) {
            push_unique(&mut route_probes, ip);
        }
    }

    select_local_addresses(&interfaces, &route_probes)
}

/// Gather directly-connected networks for on-link Host candidate selection.
/// When interface enumeration fails, the fallback is an exact-address host
/// (/32 or /128), which is safe but does not make unrelated private endpoints
/// look local.
pub fn gather_local_networks() -> Vec<LocalNetwork> {
    let interfaces = interface_networks();
    let mut networks = interfaces
        .iter()
        .filter(|(name, ip, _)| is_candidate_interface_name(name) && is_candidate_host_ip(*ip))
        .map(|(_, ip, prefix_len)| LocalNetwork::new(*ip, *prefix_len))
        .collect::<Vec<_>>();

    if networks.is_empty() {
        for probe in ["1.1.1.1:53", "8.8.8.8:53", "223.5.5.5:53"] {
            if let Some(ip) = route_probe_source_ip("0.0.0.0:0", probe) {
                push_unique_network(&mut networks, LocalNetwork::new(ip, 32));
            }
        }
        for probe in ["[2606:4700:4700::1111]:53", "[2001:4860:4860::8888]:53"] {
            if let Some(ip) = route_probe_source_ip("[::]:0", probe) {
                push_unique_network(&mut networks, LocalNetwork::new(ip, 128));
            }
        }
    }

    networks.sort_by_key(|network| (network.address, network.prefix_len));
    networks.dedup();
    networks
}

fn select_local_addresses(interfaces: &[(String, IpAddr)], route_probes: &[IpAddr]) -> Vec<IpAddr> {
    let allowed = interfaces
        .iter()
        .filter(|(name, ip)| is_candidate_interface_name(name) && is_candidate_host_ip(*ip))
        .map(|(_, ip)| *ip)
        .collect::<HashSet<_>>();
    let mut addresses = allowed.iter().copied().collect::<Vec<_>>();
    addresses.sort();

    // A route probe may select a VPN/utun source even though interface-name
    // filtering rejected it. Trust probes only when interface enumeration
    // failed entirely, otherwise require the source to be in the allow-list.
    for ip in route_probes {
        if (interfaces.is_empty() || allowed.contains(ip)) && is_candidate_host_ip(*ip) {
            push_unique(&mut addresses, *ip);
        }
    }

    addresses
}

fn interface_addresses() -> Vec<(String, IpAddr)> {
    match if_addrs::get_if_addrs() {
        Ok(interfaces) => interfaces
            .into_iter()
            .map(|iface| {
                let ip = match iface.addr {
                    IfAddr::V4(v4) => IpAddr::V4(v4.ip),
                    IfAddr::V6(v6) => IpAddr::V6(v6.ip),
                };
                (iface.name, ip)
            })
            .collect(),
        Err(err) => {
            debug!("failed to enumerate local interfaces: {}", err);
            Vec::new()
        }
    }
}

fn interface_networks() -> Vec<(String, IpAddr, u8)> {
    match if_addrs::get_if_addrs() {
        Ok(interfaces) => interfaces
            .into_iter()
            .map(|iface| {
                let (ip, prefix_len) = match iface.addr {
                    IfAddr::V4(v4) => (IpAddr::V4(v4.ip), v4.prefixlen),
                    IfAddr::V6(v6) => (IpAddr::V6(v6.ip), v6.prefixlen),
                };
                (iface.name, ip, prefix_len)
            })
            .collect(),
        Err(err) => {
            debug!("failed to enumerate local interface networks: {}", err);
            Vec::new()
        }
    }
}

fn route_probe_source_ip(bind: &str, probe: &str) -> Option<IpAddr> {
    let socket = std::net::UdpSocket::bind(bind).ok()?;
    socket.connect(probe).ok()?;
    let ip = socket.local_addr().ok()?.ip();
    if is_candidate_host_ip(ip) {
        Some(ip)
    } else {
        None
    }
}

fn push_unique(addresses: &mut Vec<IpAddr>, ip: IpAddr) {
    if !addresses.contains(&ip) {
        addresses.push(ip);
    }
}

fn push_unique_network(networks: &mut Vec<LocalNetwork>, network: LocalNetwork) {
    if !networks.contains(&network) {
        networks.push(network);
    }
}

fn is_candidate_host_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ip) => is_candidate_ipv4(ip),
        IpAddr::V6(ip) => is_candidate_ipv6(ip),
    }
}

fn is_candidate_ipv4(ip: Ipv4Addr) -> bool {
    !ip.is_loopback()
        && !ip.is_unspecified()
        && !ip.is_multicast()
        && !ip.is_broadcast()
        && !ip.is_link_local()
}

fn is_candidate_ipv6(ip: Ipv6Addr) -> bool {
    !ip.is_loopback()
        && !ip.is_unspecified()
        && !ip.is_multicast()
        && !is_ipv6_unicast_link_local(ip)
}

fn is_ipv6_unicast_link_local(ip: Ipv6Addr) -> bool {
    (ip.segments()[0] & 0xffc0) == 0xfe80
}

fn is_candidate_interface_name(name: &str) -> bool {
    let name = name.to_ascii_lowercase();
    ![
        "lo", "utun", "tun", "tap", "wg", "p2pnet", "p2wlan", "wintun", "docker", "br-", "veth",
        "llw", "awdl",
    ]
    .iter()
    .any(|prefix| name.starts_with(prefix))
}
