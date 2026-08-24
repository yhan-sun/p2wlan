fn config_command(path: &Path, command: ConfigCommand) -> Result<(), String> {
    match command {
        ConfigCommand::Path => {
            println!("{}", path.display());
            Ok(())
        }
        ConfigCommand::Show => {
            let config = load_config(path)?;
            println!("配置文件：{}", path.display());
            println!("control = {}", config.control.server_url);
            println!(
                "logged-in = {}",
                if config.control.auth_token.is_empty() {
                    "no"
                } else {
                    "yes"
                }
            );
            println!("network = {}", config.network.network_id);
            println!("device-name = {}", config.node.device_name);
            println!("interface = {}", config.network.interface);
            println!("mtu = {}", config.network.mtu);
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
            Ok(())
        }
        ConfigCommand::Set { key, value } => {
            reject_sudo_config_write()?;
            let mut config = load_or_create_config(path)?;
            set_config_value(&mut config, &key, &value)?;
            save_config(&config, path)?;
            println!("已更新 {key}。重启 p2wlan 后生效。");
            Ok(())
        }
    }
}
