async fn discover_pcp_or_nat_pmp_udp_candidate(
    local_addr: SocketAddr,
) -> (
    std::result::Result<PortMappingCandidate, String>,
    std::result::Result<PortMappingCandidate, String>,
) {
    let gateway = match default_ipv4_gateway().await {
        Some(gateway) => gateway,
        None => {
            debug!("No default IPv4 gateway found for PCP/NAT-PMP discovery");
            let error = "no default IPv4 gateway found".to_string();
            return (Err(error.clone()), Err(error));
        }
    };
    let Some(local_ip) = local_addr_ipv4(local_addr) else {
        let error = "no usable LAN IPv4 source address".to_string();
        return (Err(error.clone()), Err(error));
    };

    let pcp = discover_pcp_udp_candidate(local_ip, local_addr.port(), gateway);
    let nat_pmp = discover_nat_pmp_udp_candidate(local_ip, local_addr.port(), gateway);
    let (pcp, nat_pmp) = tokio::join!(pcp, nat_pmp);
    (pcp, nat_pmp)
}

async fn discover_nat_pmp_udp_candidate(
    local_ip: Ipv4Addr,
    local_port: u16,
    gateway: Ipv4Addr,
) -> std::result::Result<PortMappingCandidate, String> {
    let gateway_addr = SocketAddr::new(IpAddr::V4(gateway), NAT_MAPPING_CONTROL_PORT);
    let bind_addr = SocketAddr::new(IpAddr::V4(local_ip), 0);
    let socket = match UdpSocket::bind(bind_addr).await {
        Ok(socket) => socket,
        Err(error) => {
            debug!("NAT-PMP bind failed on {bind_addr}: {error}");
            return Err(format!("bind {bind_addr} failed: {error}"));
        }
    };

    let public_request = [0u8, 0u8];
    if let Err(error) = socket.send_to(&public_request, gateway_addr).await {
        return Err(format!("public address request send failed: {error}"));
    }
    let mut response = [0u8; 64];
    let (len, from) = match timeout(
        NAT_MAPPING_DISCOVERY_TIMEOUT,
        socket.recv_from(&mut response),
    )
    .await
    {
        Ok(Ok(result)) => result,
        Ok(Err(error)) => {
            debug!("NAT-PMP public address receive failed: {error}");
            return Err(format!("public address receive failed: {error}"));
        }
        Err(_) => return Err("public address request timed out".to_string()),
    };
    if from.ip() != IpAddr::V4(gateway) {
        return Err(format!(
            "public address response came from unexpected {from}"
        ));
    }
    let external_ip = parse_nat_pmp_public_address_response(&response[..len])
        .ok_or_else(|| "invalid NAT-PMP public address response".to_string())?;

    let mut map_request = [0u8; 12];
    map_request[1] = 1; // Map UDP.
    map_request[4..6].copy_from_slice(&local_port.to_be_bytes());
    map_request[6..8].copy_from_slice(&local_port.to_be_bytes());
    map_request[8..12].copy_from_slice(&PORT_MAPPING_LEASE_SECS.to_be_bytes());
    if let Err(error) = socket.send_to(&map_request, gateway_addr).await {
        return Err(format!("UDP mapping request send failed: {error}"));
    }
    let (len, from) = match timeout(
        NAT_MAPPING_DISCOVERY_TIMEOUT,
        socket.recv_from(&mut response),
    )
    .await
    {
        Ok(Ok(result)) => result,
        Ok(Err(error)) => {
            debug!("NAT-PMP UDP mapping receive failed: {error}");
            return Err(format!("UDP mapping receive failed: {error}"));
        }
        Err(_) => return Err("UDP mapping request timed out".to_string()),
    };
    if from.ip() != IpAddr::V4(gateway) {
        return Err(format!("UDP mapping response came from unexpected {from}"));
    }
    let external_port = parse_nat_pmp_mapping_response(&response[..len], local_port)
        .ok_or_else(|| "invalid NAT-PMP UDP mapping response".to_string())?;
    let endpoint = SocketAddr::new(IpAddr::V4(external_ip), external_port);
    is_public_udp_candidate(endpoint)
        .then_some(PortMappingCandidate {
            endpoint: endpoint.to_string(),
            source: "nat_pmp",
        })
        .ok_or_else(|| format!("gateway returned non-public endpoint {endpoint}"))
}

async fn discover_pcp_udp_candidate(
    local_ip: Ipv4Addr,
    local_port: u16,
    gateway: Ipv4Addr,
) -> std::result::Result<PortMappingCandidate, String> {
    let gateway_addr = SocketAddr::new(IpAddr::V4(gateway), NAT_MAPPING_CONTROL_PORT);
    let bind_addr = SocketAddr::new(IpAddr::V4(local_ip), 0);
    let socket = match UdpSocket::bind(bind_addr).await {
        Ok(socket) => socket,
        Err(error) => {
            debug!("PCP bind failed on {bind_addr}: {error}");
            return Err(format!("bind {bind_addr} failed: {error}"));
        }
    };

    let mut request = [0u8; 60];
    request[0] = 2; // PCP version.
    request[1] = 1; // MAP opcode.
    request[4..8].copy_from_slice(&PORT_MAPPING_LEASE_SECS.to_be_bytes());
    request[8..24].copy_from_slice(&ipv4_mapped_octets(local_ip));
    rand::thread_rng().fill_bytes(&mut request[24..36]);
    request[36] = 17; // UDP.
    request[40..42].copy_from_slice(&local_port.to_be_bytes());
    request[42..44].copy_from_slice(&local_port.to_be_bytes());

    if let Err(error) = socket.send_to(&request, gateway_addr).await {
        return Err(format!("MAP request send failed: {error}"));
    }
    let mut response = [0u8; 128];
    let (len, from) = match timeout(
        NAT_MAPPING_DISCOVERY_TIMEOUT,
        socket.recv_from(&mut response),
    )
    .await
    {
        Ok(Ok(result)) => result,
        Ok(Err(error)) => {
            debug!("PCP UDP mapping receive failed: {error}");
            return Err(format!("MAP response receive failed: {error}"));
        }
        Err(_) => return Err("MAP request timed out".to_string()),
    };
    if from.ip() != IpAddr::V4(gateway) {
        return Err(format!("MAP response came from unexpected {from}"));
    }
    let endpoint = parse_pcp_mapping_response(&response[..len], local_port)
        .ok_or_else(|| "invalid PCP MAP response".to_string())?;
    is_public_udp_candidate(endpoint)
        .then_some(PortMappingCandidate {
            endpoint: endpoint.to_string(),
            source: "pcp",
        })
        .ok_or_else(|| format!("gateway returned non-public endpoint {endpoint}"))

}
