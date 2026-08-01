struct GatewayMappingDiscovery {
    candidate: Option<PortMappingCandidate>,
    upnp: std::result::Result<(), String>,
    pcp: Option<std::result::Result<(), String>>,
    nat_pmp: Option<std::result::Result<(), String>>,
}

async fn discover_port_mapping_udp_candidate(local_addr: SocketAddr) -> GatewayMappingDiscovery {
    match discover_upnp_udp_candidate(local_addr).await {
        Ok(candidate) => GatewayMappingDiscovery {
            candidate: Some(candidate),
            upnp: Ok(()),
            pcp: None,
            nat_pmp: None,
        },
        Err(upnp) => {
            let (pcp, nat_pmp) = discover_pcp_or_nat_pmp_udp_candidate(local_addr).await;
            let candidate = pcp
                .as_ref()
                .ok()
                .cloned()
                .or_else(|| nat_pmp.as_ref().ok().cloned());
            GatewayMappingDiscovery {
                candidate,
                upnp: Err(upnp),
                pcp: Some(pcp.map(|_| ())),
                nat_pmp: Some(nat_pmp.map(|_| ())),
            }
        }
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
