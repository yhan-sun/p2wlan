fn config_command(path: &Path, command: ConfigCommand) -> Result<(), String> {
    match command {
        ConfigCommand::Path => {
            println!("{}", path.display());
            Ok(())
        }
        ConfigCommand::ProtectIdentity {
            key_file,
            windows_dpapi,
        } => {
            use p2pnet_daemon::config::IdentityProtection;
            reject_sudo_config_write()?;
            let protection = match (key_file, windows_dpapi) {
                (Some(path), false) => IdentityProtection::KeyFile { path },
                (None, true) => IdentityProtection::WindowsDpapi,
                _ => return Err("请选择一种设备私钥保护方式".to_string()),
            };
            Config::protect_identity_file(path, protection)
                .map_err(|error| format!("无法保护设备私钥：{error}"))?;
            println!("设备私钥已加密保存。现有设备公钥和身份保持有效。");
            Ok(())
        }
        ConfigCommand::Show => {
            let config = load_config(path)?;
            println!("配置文件：{}", path.display());
            println!("control = {}", config.control.server_url);
            println!(
                "logged-in = {}",
                if cli_session_available(path, &config)? {
                    "yes"
                } else {
                    "no"
                }
            );
            println!("network = {}", config.network.network_id);
            println!("device-name = {}", config.node.device_name);
            println!("device-public-key = {}", config.node.public_key);
            println!("identity-protected = {}", config.identity_is_protected());
            println!("proxy-mode = {}", config.control.proxy_mode.as_label());
            println!("interface = {}", config.network.interface);
            println!("mtu = {}", config.network.mtu);
            println!(
                "business-padding-16 = {}",
                config.network.business_padding_16
            );
            println!("udp-bind = {}", config.network.udp_bind);
            println!(
                "udp-advertise = {}",
                config
                    .network
                    .udp_advertise
                    .as_deref()
                    .filter(|value| !value.trim().is_empty())
                    .unwrap_or("(unset)")
            );
            println!(
                "stun = {}",
                if config.network.stun_servers.is_empty() {
                    "(default)".to_string()
                } else if config
                    .network
                    .stun_servers
                    .iter()
                    .all(|value| is_clear_value(value))
                {
                    "(disabled)".to_string()
                } else {
                    config.network.stun_servers.join(",")
                }
            );
            println!(
                "port-mapping = {}",
                if config.network.upnp_enabled {
                    "on"
                } else {
                    "off"
                }
            );
            println!(
                "birthday-probing = {}",
                if config.network.birthday_probing_enabled {
                    "on"
                } else {
                    "off"
                }
            );
            println!(
                "socket-pool = {}",
                if config.network.socket_pool_enabled {
                    format!("{} sockets (experimental)", config.network.socket_pool_size)
                } else {
                    "off".to_string()
                }
            );
            println!("relay = {}", config.relay.servers.join(","));
            println!(
                "relay-regions = {}",
                if config.relay.preferred_regions.is_empty() {
                    "(latency)".to_string()
                } else {
                    config.relay.preferred_regions.join(",")
                }
            );
            println!(
                "relay-selection-timeout = {}ms",
                config.relay.selection_timeout_ms
            );
            println!(
                "relay-policy = {}",
                if config.relay.prefer_direct {
                    "auto"
                } else {
                    "relay"
                }
            );
            println!(
                "path-policy = {}",
                config.relay.effective_path_policy(true).as_label()
            );
            println!(
                "relay-startup-timeout = {}ms",
                config.relay.relay_startup_timeout_ms
            );
            println!("diagnostics = {}", config.diagnostics.bind);
            println!("resource-capture = {}", config.diagnostics.resource_capture);
            Ok(())
        }
        ConfigCommand::Set { key, value } => {
            reject_sudo_config_write()?;
            let mut config = load_or_create_config(path)?;
            let previous_server = config.control.server_url.clone();
            set_config_value(&mut config, &key, &value)?;
            save_config(&config, path)?;
            if key == "control" && config.control.server_url != previous_server {
                // A session token is bound to its issuing server.  It must
                // never survive a server switch and later be sent to the new
                // endpoint by room/support commands.
                clear_cli_session_token(path)?;
            }
            println!("已更新 {key}。重启 p2wlan 后生效。");
            Ok(())
        }
    }
}
