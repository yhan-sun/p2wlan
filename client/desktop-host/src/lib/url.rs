pub fn normalize_diagnostics_url(value: &str) -> Result<String> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return Err(invalid_url("Diagnostics URL is required"));
    }

    let mut parsed = url::Url::parse(trimmed).map_err(|error| {
        invalid_url("Diagnostics URL is invalid").with_detail(error.to_string())
    })?;

    match parsed.scheme() {
        "http" | "https" => {}
        _ => return Err(invalid_url("Diagnostics URL must use http or https")),
    }

    diagnostics_socket_addr_from_url(parsed.as_str())?;

    if parsed.path().is_empty() || parsed.path() == "/" {
        parsed.set_path("/status");
    }
    parsed.set_fragment(None);

    Ok(parsed.to_string())
}

pub fn health_url_from_status_url(value: &str) -> Result<String> {
    let normalized = normalize_diagnostics_url(value)?;
    let mut parsed = url::Url::parse(&normalized).map_err(|error| {
        invalid_url("Diagnostics URL is invalid").with_detail(error.to_string())
    })?;
    parsed.set_path("/health");
    parsed.set_query(None);
    parsed.set_fragment(None);
    Ok(parsed.to_string())
}

pub fn diagnostics_bind_from_url(value: &str) -> Result<String> {
    Ok(diagnostics_socket_addr_from_url(value)?.to_string())
}

pub fn diagnostics_socket_addr_from_url(value: &str) -> Result<SocketAddr> {
    let parsed = url::Url::parse(value).map_err(|error| {
        invalid_url("Diagnostics URL is invalid").with_detail(error.to_string())
    })?;

    let ip = match parsed.host() {
        Some(url::Host::Ipv4(ip)) => IpAddr::V4(ip),
        Some(url::Host::Ipv6(ip)) => IpAddr::V6(ip),
        Some(url::Host::Domain(host)) if host.eq_ignore_ascii_case("localhost") => {
            IpAddr::V4(std::net::Ipv4Addr::LOCALHOST)
        }
        Some(_) => {
            return Err(invalid_url(
                "Diagnostics URL host must be 127.0.0.1, [::1], or localhost",
            ))
        }
        None => return Err(invalid_url("Diagnostics URL must include a host")),
    };

    if !ip.is_loopback() {
        return Err(invalid_url("Diagnostics URL host must be loopback"));
    }

    let Some(port) = parsed.port() else {
        return Err(invalid_url("Diagnostics URL must include a port"));
    };

    Ok(SocketAddr::new(ip, port))
}
