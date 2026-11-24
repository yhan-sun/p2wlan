fn set_config_value(config: &mut Config, key: &str, value: &str) -> Result<(), String> {
    match key {
        "control" => {
            let server = normalize_control_server(value)?;
            if server != config.control.server_url && config.network.network_id.starts_with("room-")
            {
                return Err("房间身份不能切换服务器，请使用独立配置文件".into());
            }
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
            if network != config.network.network_id
                && (network.starts_with("room-") || config.network.network_id.starts_with("room-"))
            {
                return Err("房间身份不能迁移网络，请使用独立配置文件".into());
            }
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
        "mtu-mode" => {
            let mode = match value.trim() {
                "auto" => Value::String("auto".into()),
                fixed => Value::from(
                    fixed
                        .parse::<u16>()
                        .map_err(|_| "mtu-mode 必须是 auto 或 576 到 65503 的整数")?,
                ),
            };
            config.transport.mtu_mode = serde_json::from_value(mode)
                .map_err(|_| "mtu-mode 必须是 auto 或 576 到 65503 的整数".to_owned())?;
        }
        "mss-clamping" => {
            config.transport.enable_mss_clamping = parse_bool_config(value, key)?;
        }
        "fec-mode" => {
            config.transport.fec_mode = serde_json::from_value(Value::String(value.trim().into()))
                .map_err(|_| "fec-mode 必须是 auto、off、light 或 strong".to_owned())?;
        }
        "compression" => {
            config.transport.compression =
                serde_json::from_value(Value::String(value.trim().into()))
                    .map_err(|_| "compression 必须是 auto 或 off".to_owned())?;
        }
        "qos" => {
            config.transport.enable_qos = parse_bool_config(value, key)?;
        }
        "max-tx-mbps" => {
            config.transport.max_tx_mbps = if is_clear_value(value) {
                None
            } else {
                Some(
                    value
                        .trim()
                        .parse()
                        .map_err(|_| "max-tx-mbps 必须是正整数或 off")?,
                )
            };
        }
        "relay-transport" => {
            config.transport.relay_transport =
                serde_json::from_value(Value::String(value.trim().into()))
                    .map_err(|_| "relay-transport 必须是 auto_udp_first 或 tls_only".to_owned())?;
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
        "disable-sym-hole-punching" => {
            config.network.traversal.disable_sym_hole_punching = parse_bool_config(value, key)?
        }
        "lazy-p2p" => config.network.traversal.lazy_p2p = parse_bool_config(value, key)?,
        "max-punch-pps" => {
            config.network.traversal.max_punch_pps = parse_punch_limit(value, key, 200)?
        }
        "max-punch-sockets" => {
            config.network.traversal.max_punch_sockets = parse_punch_limit(value, key, 30)? as u8
        }
        "linear-scan-count" => {
            config.network.traversal.linear_scan_count = parse_punch_limit(value, key, 256)?
        }
        "firewall-probe-addresses" => {
            let mut addresses = Vec::new();
            if !is_clear_value(value) {
                for item in value.split(',') {
                    let address = parse_socket_addr(item.trim(), key)?;
                    if address.port() == 0
                        || address.ip().is_multicast()
                        || address.ip().is_unspecified()
                    {
                        return Err(format!("{key} 需要有效的单播地址和非零端口"));
                    }
                    if !addresses.contains(&address) {
                        addresses.push(address);
                    }
                    if addresses.len() > 8 {
                        return Err(format!("{key} 最多支持 8 个地址"));
                    }
                }
            }
            config.network.traversal.firewall_probe_addresses = addresses;
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
        "resource-capture" => {
            let enabled = value
                .parse::<bool>()
                .map_err(|_| "resource-capture 必须为 true 或 false".to_string())?;
            config.diagnostics.resource_capture = enabled;
            if enabled {
                config.diagnostics.enabled = true;
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
        "relay-regions" => {
            config.relay.preferred_regions = value
                .split(',')
                .map(str::trim)
                .filter(|item| !item.is_empty())
                .map(ToString::to_string)
                .collect();
        }
        "relay-selection-timeout" | "relay-selection-timeout-ms" => {
            let timeout = parse_millis(value, "relay-selection-timeout")?;
            if !(100..=60000).contains(&timeout) {
                return Err("relay-selection-timeout 必须在 100ms 到 60000ms 之间".to_string());
            }
            config.relay.selection_timeout_ms = timeout;
        }
        "relay-policy" => match value.trim().to_ascii_lowercase().as_str() {
            "direct" | "direct-first" => {
                config.relay.prefer_direct = true;
                config.relay.path_policy = PathPolicy::DirectFirst;
            }
            "auto" => {
                config.relay.prefer_direct = true;
                config.relay.path_policy = PathPolicy::Auto;
            }
            "prefer-relay" | "relay-first" => {
                config.relay.prefer_direct = true;
                config.relay.path_policy = PathPolicy::Auto;
            }
            "relay" | "relay-only" => {
                config.relay.prefer_direct = false;
                config.relay.path_policy = PathPolicy::RelayOnly;
            }
            _ => return Err("relay-policy 只支持 auto、direct、prefer-relay 或 relay".to_string()),
        },
        "prefer-direct" => {
            let prefer_direct = parse_bool_config(value, "prefer-direct")?;
            config.relay.prefer_direct = prefer_direct;
            if prefer_direct && config.relay.path_policy == PathPolicy::RelayOnly {
                config.relay.path_policy = PathPolicy::DirectFirst;
            } else if !prefer_direct {
                config.relay.path_policy = PathPolicy::RelayOnly;
            }
        }
        "path-policy" => {
            let normalized = value.trim().to_ascii_lowercase();
            let policy =
                match normalized.as_str() {
                    "direct-first" | "direct_first" => PathPolicy::DirectFirst,
                    "auto" => PathPolicy::Auto,
                    "adaptive" => PathPolicy::Adaptive,
                    "score" => PathPolicy::Score,
                    "direct-sticky" | "direct_sticky" | "direct" => PathPolicy::DirectSticky,
                    "relay-only" | "relay_only" | "relay" => PathPolicy::RelayOnly,
                    _ => return Err(
                        "path-policy 只支持 direct-first、adaptive、auto、score、direct-sticky 或 relay-only"
                            .to_string(),
                    ),
                };
            config.relay.path_policy = policy;
            config.relay.prefer_direct = policy != PathPolicy::RelayOnly;
        }
        "proxy-mode" => match value.trim().to_ascii_lowercase().as_str() {
            "direct" => {
                config.control.proxy_mode = p2pnet_daemon::config::ControlProxyMode::Direct;
            }
            "environment" | "env" => {
                config.control.proxy_mode = p2pnet_daemon::config::ControlProxyMode::Environment;
            }
            _ => return Err("proxy-mode 只支持 direct 或 environment".to_string()),
        },
        "relay-startup-timeout" | "relay-startup-timeout-ms" | "direct-timeout" => {
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

fn parse_punch_limit(value: &str, key: &str, max: u16) -> Result<u16, String> {
    value
        .trim()
        .parse::<u16>()
        .ok()
        .filter(|v| *v <= max)
        .ok_or_else(|| format!("{key} 必须是 0 到 {max} 的整数"))
}
