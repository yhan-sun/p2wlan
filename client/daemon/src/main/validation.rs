fn validate_cli(cli: &Cli) -> std::result::Result<(), String> {
    if cli.manual && cli.managed {
        return Err("--manual and --managed cannot be used together".to_string());
    }

    if let Some(ref control) = cli.control {
        // Validate control plane URL
        let control_url = match reqwest::Url::parse(control) {
            Ok(url) => url,
            Err(_) => return Err(format!("Invalid URL for --control: {}", control)),
        };
        if control_url.scheme() != "http" && control_url.scheme() != "https" {
            return Err(format!(
                "Only http and https schemes are allowed for --control: {}",
                control
            ));
        }
    }
    if let Some(ref network) = cli.network {
        if network.trim().is_empty() {
            return Err("--network cannot be empty".to_string());
        }
    }
    if let Some(ref addr) = cli.address {
        if addr.parse::<std::net::Ipv4Addr>().is_err() {
            return Err(format!("Invalid IP address for --address: {}", addr));
        }
    }
    if let Some(ref mask) = cli.netmask {
        if mask.parse::<std::net::Ipv4Addr>().is_err() {
            return Err(format!("Invalid netmask: {}", mask));
        }
    }
    if let Some(mtu) = cli.mtu {
        if !(576..=65535).contains(&mtu) {
            return Err(format!("MTU must be between 576 and 65535, got {}", mtu));
        }
    }
    if let Some(ref bind) = cli.udp_bind {
        if bind.parse::<std::net::SocketAddr>().is_err() {
            return Err(format!(
                "Invalid SocketAddr for --udp-bind (expected IP:port): {}",
                bind
            ));
        }
    }
    if let Some(ref adv) = cli.udp_advertise {
        if adv.parse::<std::net::SocketAddr>().is_err() {
            return Err(format!(
                "Invalid SocketAddr for --udp-advertise (expected IP:port): {}",
                adv
            ));
        }
    }
    if let Some(ref dbind) = cli.diagnostics_bind {
        if dbind.parse::<std::net::SocketAddr>().is_err() {
            return Err(format!(
                "Invalid SocketAddr for --diagnostics-bind (expected IP:port): {}",
                dbind
            ));
        }
    }
    if let Some(ref stun) = cli.stun {
        for s in stun.split(',').map(str::trim).filter(|x| !x.is_empty()) {
            if !is_valid_stun_server_spec(s) {
                return Err(format!(
                    "Invalid STUN server in --stun (expected host:port or IP:port): {}",
                    s
                ));
            }
        }
    }
    if let Some(ref observers) = cli.udp_observer {
        for observer in observers
            .split(',')
            .map(str::trim)
            .filter(|x| !x.is_empty())
        {
            if !is_valid_stun_server_spec(observer) {
                return Err(format!(
                    "Invalid UDP observer in --udp-observer (expected host:port or IP:port): {}",
                    observer
                ));
            }
        }
    }
    if let Some(ref relay) = cli.relay {
        for r in relay.split(',').map(str::trim).filter(|x| !x.is_empty()) {
            let endpoint = match r.split_once('@') {
                Some((region, ep)) => {
                    if region.is_empty() {
                        return Err(format!("Empty region in relay spec '{}'", r));
                    }
                    ep
                }
                None => r,
            };
            if endpoint.parse::<std::net::SocketAddr>().is_err() {
                return Err(format!(
                    "Invalid Relay server endpoint in '{}' (expected [region@]IP:port): {}",
                    r, endpoint
                ));
            }
        }
    }
    if let Some(ref socket_pool) = cli.socket_pool {
        parse_socket_pool_override(socket_pool)
            .map_err(|error| format!("Invalid --socket-pool: {error}"))?;
    }
    if let Some(ref durl) = cli.diagnostics_url {
        let parsed = match reqwest::Url::parse(durl) {
            Ok(url) => url,
            Err(_) => return Err(format!("Invalid URL for --diagnostics-url: {}", durl)),
        };
        if parsed.scheme() != "http" && parsed.scheme() != "https" {
            return Err(format!(
                "Only http and https schemes are allowed for --diagnostics-url: {}",
                durl
            ));
        }
    }
    Ok(())
}

fn parse_socket_pool_override(value: &str) -> std::result::Result<(bool, usize), String> {
    let normalized = value.trim().to_ascii_lowercase();
    if matches!(
        normalized.as_str(),
        "off" | "no" | "false" | "none" | "disable" | "disabled"
    ) {
        return Ok((false, 1));
    }

    let count = match normalized.as_str() {
        "on" | "yes" | "true" | "auto" => 3,
        raw => raw
            .parse::<usize>()
            .map_err(|_| "expected off, on/auto, or an integer from 2 to 4".to_string())?,
    };
    if !(2..=4).contains(&count) {
        return Err("expected socket count from 2 to 4".to_string());
    }
    Ok((true, count))
}

fn is_valid_stun_server_spec(value: &str) -> bool {
    let value = value.trim();
    if matches!(
        value.to_ascii_lowercase().as_str(),
        "none" | "off" | "false" | "clear" | "unset" | "disable" | "disabled"
    ) {
        return true;
    }
    if value.parse::<std::net::SocketAddr>().is_ok() {
        return true;
    }
    let Some((host, port)) = value.rsplit_once(':') else {
        return false;
    };
    !host.is_empty()
        && !host.contains(char::is_whitespace)
        && !host.contains('/')
        && !host.contains('@')
        && port.parse::<u16>().is_ok_and(|port| port > 0)
}
