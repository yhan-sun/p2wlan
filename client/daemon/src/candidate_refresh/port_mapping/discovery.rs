struct GatewayMappingDiscovery {
    candidate: Option<PortMappingCandidate>,
    upnp: std::result::Result<(), String>,
    pcp: Option<std::result::Result<(), String>>,
    nat_pmp: Option<std::result::Result<(), String>>,
}

async fn discover_port_mapping_udp_candidate(
    local_addr: SocketAddr,
    gateway: Option<Ipv4Addr>,
    pcp_request: ([u8; 12], Option<SocketAddr>),
) -> GatewayMappingDiscovery {
    let (upnp, gateway) = tokio::join!(
        tokio::time::timeout(
            UPNP_DISCOVERY_TIMEOUT + NAT_MAPPING_DISCOVERY_TIMEOUT,
            discover_upnp_udp_candidate(local_addr)
        ),
        tokio::time::timeout(
            NAT_MAPPING_DISCOVERY_TIMEOUT * 3,
            discover_pcp_or_nat_pmp_udp_candidate(local_addr, gateway, pcp_request)
        ),
    );
    let (pcp, nat_pmp) = gateway.unwrap_or_else(|_| {
        (
            Err("PCP discovery deadline elapsed".into()),
            Err("NAT-PMP discovery deadline elapsed".into()),
        )
    });
    let upnp = upnp.unwrap_or_else(|_| Err("UPnP mapping deadline elapsed".into()));
    let candidate = upnp
        .as_ref()
        .ok()
        .or_else(|| pcp.as_ref().ok())
        .or_else(|| nat_pmp.as_ref().ok())
        .cloned();
    GatewayMappingDiscovery {
        candidate,
        upnp: upnp.map(|_| ()),
        pcp: Some(pcp.map(|_| ())),
        nat_pmp: Some(nat_pmp.map(|_| ())),
    }
}

async fn discover_upnp_udp_candidate(
    local_addr: SocketAddr,
) -> std::result::Result<PortMappingCandidate, String> {
    let options = SearchOptions {
        timeout: Some(UPNP_DISCOVERY_TIMEOUT),
        single_search_timeout: Some(UPNP_DISCOVERY_TIMEOUT),
        ..Default::default()
    };
    let gateway = match search_gateway(options).await {
        Ok(gateway) => gateway,
        Err(error) => {
            debug!("UPnP IGD gateway search failed: {error}");
            return Err(format!("gateway discovery failed: {error}"));
        }
    };

    let external_ip = match gateway.get_external_ip().await {
        Ok(ip) if is_public_udp_candidate(SocketAddr::new(ip, 1)) => ip,
        Ok(ip) => {
            debug!("UPnP IGD external IP {ip} is not publicly routable; skipping candidate");
            return Err(format!("gateway reported non-public external IP {ip}"));
        }
        Err(error) => {
            debug!("UPnP IGD external IP lookup failed: {error}");
            return Err(format!("external IP lookup failed: {error}"));
        }
    };

    if gateway
        .add_port(
            PortMappingProtocol::UDP,
            local_addr.port(),
            local_addr,
            PORT_MAPPING_LEASE_SECS,
            "p2wlan direct udp",
        )
        .await
        .is_ok()
    {
        return Ok(PortMappingCandidate {
            endpoint: SocketAddr::new(external_ip, local_addr.port()).to_string(),
            source: "upnp",
            lease_seconds: PORT_MAPPING_LEASE_SECS,
        });
    }

    match gateway
        .get_any_address(
            PortMappingProtocol::UDP,
            local_addr,
            PORT_MAPPING_LEASE_SECS,
            "p2wlan direct udp",
        )
        .await
    {
        Ok(endpoint) if is_public_udp_candidate(endpoint) => Ok(PortMappingCandidate {
            endpoint: endpoint.to_string(),
            source: "upnp",
            lease_seconds: PORT_MAPPING_LEASE_SECS,
        }),
        Ok(endpoint) => {
            debug!("UPnP IGD mapped to non-public endpoint {endpoint}; skipping candidate");
            Err(format!("gateway assigned non-public endpoint {endpoint}"))
        }
        Err(error) => {
            debug!("UPnP IGD UDP port mapping failed: {error}");
            Err(format!("UDP port mapping failed: {error}"))
        }
    }
}
