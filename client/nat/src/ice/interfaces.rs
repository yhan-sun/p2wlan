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
        CandidateType::PeerReflexive => PREF_PEER_REFLEXIVE,
        CandidateType::ServerReflexive => PREF_SERVER_REFLEXIVE,
        CandidateType::Relay => PREF_RELAY,
    };
    (1u32 << 24) * type_pref + (1u32 << 8) * LOCAL_PREF + (256 - COMPONENT_ID)
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
