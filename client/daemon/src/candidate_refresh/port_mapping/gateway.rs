async fn default_ipv4_gateway() -> Option<Ipv4Addr> {
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

    #[cfg(any(target_os = "linux", target_os = "android"))]
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

fn port_mapping_local_addr(
    udp_local_addr: Option<SocketAddr>,
    candidates: &[String],
    candidate_sources: &HashMap<String, String>,
) -> Option<SocketAddr> {
    if udp_local_addr.is_some_and(is_port_mapping_local_addr) {
        return udp_local_addr;
    }

    candidates.iter().find_map(|candidate| {
        if candidate_sources.get(candidate).map(String::as_str) != Some("host") {
            return None;
        }
        let endpoint = candidate.parse::<SocketAddr>().ok()?;
        is_port_mapping_local_addr(endpoint).then_some(endpoint)
    })
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
