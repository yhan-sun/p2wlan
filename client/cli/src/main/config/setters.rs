fn set_config_value(config: &mut Config, key: &str, value: &str) -> Result<(), String> {
    match key {
        "control" => {
            let server = normalize_control_server(value)?;
            if server != config.control.server_url {
                config.control.server_url = server;
                config.control.auth_token.clear();
                clear_device_credential(config);
            }
        }
        "network" => {
            if value.trim().is_empty() {
                return Err("network 不能为空".to_string());
            }
            let network = value.trim();
            if network != config.network.network_id {
                config.network.network_id = network.to_string();
                clear_device_credential(config);
            }
        }
        "device-name" => {
            if value.trim().is_empty() {
                return Err("device-name 不能为空".to_string());
            }
            let name = value.trim();
            if name != config.node.device_name {
                config.node.device_name = name.to_string();
                clear_device_credential(config);
            }
        }
        "interface" => {
            if value.trim().is_empty() || value.len() > 15 {
                return Err("Linux interface 名称必须为 1 到 15 个字符".to_string());
            }
            config.network.interface = value.trim().to_string();
        }
        "mtu" => {
            let mtu = value
                .parse::<u32>()
                .map_err(|_| "mtu 必须是整数".to_string())?;
            if !(576..=65535).contains(&mtu) {
                return Err("mtu 必须在 576 到 65535 之间".to_string());
            }
            config.network.mtu = mtu;
        }
        "udp-bind" => {
            let endpoint = parse_socket_addr(value, "udp-bind")?;
            config.network.udp_bind = endpoint.to_string();
        }
        "udp-advertise" => {
            if is_clear_value(value) {
                config.network.udp_advertise = None;
            } else {
                let endpoint = parse_socket_addr(value, "udp-advertise")?;
                if endpoint.ip().is_unspecified() || endpoint.port() == 0 {
                    return Err("udp-advertise 必须是可被其他设备访问的 ip:port".to_string());
                }
                config.network.udp_advertise = Some(endpoint.to_string());
            }
        }
        "stun" => {
            if is_clear_value(value) {
                config.network.stun_servers = vec!["off".to_string()];
            } else {
                let servers = value
                    .split(',')
                    .map(str::trim)
                    .filter(|item| !item.is_empty())
                    .map(|item| parse_stun_server_spec(item).map(ToString::to_string))
                    .collect::<Result<Vec<_>, _>>()?;
                config.network.stun_servers = servers;
            }
        }
        "port-mapping" | "upnp" => {
            config.network.upnp_enabled = parse_bool_config(value, "port-mapping")?;
        }
        "birthday-probing" => {
            config.network.birthday_probing_enabled = parse_bool_config(value, "birthday-probing")?;
        }
        "socket-pool" => {
            if is_clear_value(value)
                || matches!(
                    value.trim().to_ascii_lowercase().as_str(),
                    "off" | "no" | "false"
                )
            {
                config.network.socket_pool_enabled = false;
                config.network.socket_pool_size = 1;
            } else {
                let count = match value.trim().to_ascii_lowercase().as_str() {
                    "on" | "yes" | "true" => 3,
                    raw => raw
                        .parse::<usize>()
                        .map_err(|_| "socket-pool 必须是 off、on 或 2 到 4 的整数".to_string())?,
                };
                if !(2..=4).contains(&count) {
                    return Err("socket-pool 必须在 2 到 4 之间".to_string());
                }
                config.network.socket_pool_enabled = true;
                config.network.socket_pool_size = count;
            }
        }
        "diagnostics" => {
            let endpoint = parse_socket_addr(value, "diagnostics")?;
            if !endpoint.ip().is_loopback() {
                return Err("diagnostics 必须绑定在 127.0.0.1 或 ::1".to_string());
            }
            config.diagnostics.enabled = true;
            config.diagnostics.bind = endpoint.to_string();
        }
        "relay" => {
            config.relay.servers = value
                .split(',')
                .map(str::trim)
                .filter(|item| !item.is_empty())
                .map(ToString::to_string)
                .collect();
        }
        "relay-policy" => match value {
            "auto" | "direct" => config.relay.prefer_direct = true,
            "relay" => config.relay.prefer_direct = false,
            _ => return Err("relay-policy 只支持 auto、direct 或 relay".to_string()),
        },
        "relay-startup-timeout" | "direct-timeout" => {
            let timeout = parse_millis(value, "relay-startup-timeout")?;
            if !(100..=60000).contains(&timeout) {
                return Err("relay-startup-timeout 必须在 100ms 到 60000ms 之间".to_string());
            }
            config.relay.relay_startup_timeout_ms = timeout;
        }
        _ => {
            return Err(format!(
                "不支持的配置项 {key}；可用项：{SUPPORTED_CONFIG_KEYS}"
            ))
        }
    }
    Ok(())
}
