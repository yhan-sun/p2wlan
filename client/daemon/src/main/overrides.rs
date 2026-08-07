fn apply_cli_overrides(config: &mut Config, cli: &Cli) {
    if let Some(ref control) = cli.control {
        config.control.server_url = control.clone();
    }
    if let Some(ref network) = cli.network {
        config.network.network_id = network.clone();
    }
    if let Some(ref token) = cli.token {
        config.control.auth_token = token.clone();
    }
    if let Some(ref interface) = cli.interface {
        config.network.interface = interface.clone();
    }
    if let Some(ref address) = cli.address {
        config.network.virtual_ip = address.clone();
    }
    if cli.manual {
        config.network.manual = true;
    }
    if cli.managed {
        config.network.manual = false;
    }
    if let Some(ref netmask) = cli.netmask {
        config.network.netmask = netmask.clone();
    }
    if let Some(mtu) = cli.mtu {
        config.network.mtu = mtu;
    }
    if let Some(interval) = cli.heartbeat_interval {
        config.control.heartbeat_interval_secs = interval;
    }
    if let Some(ref udp_bind) = cli.udp_bind {
        config.network.udp_bind = udp_bind.clone();
    }
    if let Some(ref udp_advertise) = cli.udp_advertise {
        config.network.udp_advertise = Some(udp_advertise.clone());
    }
    if let Some(ref stun_servers) = cli.stun {
        config.network.stun_servers = stun_servers
            .split(',')
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(ToString::to_string)
            .collect();
    }
    if let Some(ref observers) = cli.udp_observer {
        config.network.udp_observers = observers
            .split(',')
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(ToString::to_string)
            .collect();
    }
    if let Some(timeout_ms) = cli.stun_timeout_ms {
        config.network.stun_timeout_ms = timeout_ms;
    }
    if let Some(interval_ms) = cli.punch_interval_ms {
        config.network.punch_interval_ms = interval_ms;
    }
    if let Some(attempts) = cli.punch_attempts {
        config.network.punch_attempts = attempts;
    }
    if let Some(ref socket_pool) = cli.socket_pool {
        if let Ok((enabled, count)) = parse_socket_pool_override(socket_pool) {
            config.network.socket_pool_enabled = enabled;
            config.network.socket_pool_size = count;
        }
    }
    if let Some(interval_secs) = cli.keepalive_interval_secs {
        config.network.keepalive_interval_secs = interval_secs;
    }
    if let Some(ref relay_servers) = cli.relay {
        config.relay.servers = relay_servers
            .split(',')
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(ToString::to_string)
            .collect();
    }
    if let Some(ref preferred_regions) = cli.relay_regions {
        config.relay.preferred_regions = preferred_regions
            .split(',')
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(ToString::to_string)
            .collect();
    }
    if let Some(timeout_ms) = cli.relay_selection_timeout_ms {
        config.relay.selection_timeout_ms = timeout_ms;
    }
    if let Some(timeout_ms) = cli.relay_fallback_timeout_ms {
        config.relay.fallback_timeout_ms = timeout_ms;
    }
    if let Some(ref bind) = cli.diagnostics_bind {
        config.diagnostics.enabled = true;
        config.diagnostics.bind = bind.clone();
    }
    if cli.diagnostics_disable {
        config.diagnostics.enabled = false;
    }
    if cli.prefer_relay {
        config.relay.prefer_direct = false;
    }
    if cli.prefer_direct {
        config.relay.prefer_direct = true;
    }
    if cli.fresh_mapping_harness_loopback {
        config.network.fresh_mapping_harness_loopback = true;
    }
    if cli.no_host_candidates {
        config.network.gather_host_candidates = false;
    }
    if let Some(ref name) = cli.device_name {
        config.node.device_name = name.clone();
    }
}
