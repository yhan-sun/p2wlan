async fn status(config_path: &Path, json: bool) -> Result<(), String> {
    let config = load_config(config_path)?;
    match fetch_status(&status_url(&config)).await {
        Ok(snapshot) if json => {
            println!(
                "{}",
                serde_json::to_string_pretty(&snapshot).map_err(|error| error.to_string())?
            );
            Ok(())
        }
        Ok(snapshot) => {
            let peers = snapshot
                .get("peers")
                .and_then(Value::as_array)
                .map(Vec::len)
                .unwrap_or(0);
            println!("状态：运行中");
            println!("版本：{}", value_text(&snapshot, "version", "未知"));
            println!("虚拟 IP：{}", value_text(&snapshot, "virtual_ip", "未知"));
            println!("网络：{}", value_text(&snapshot, "network_id", "未知"));
            println!("节点：{}", value_text(&snapshot, "node_id", "未知"));
            println!("Peer：{peers}");
            println!(
                "Relay：{}",
                if snapshot
                    .get("relay_connected")
                    .and_then(Value::as_bool)
                    .unwrap_or(false)
                {
                    "已连接"
                } else {
                    "未连接"
                }
            );
            Ok(())
        }
        Err(error) => {
            println!("状态：未运行");
            Err(error)
        }
    }
}

async fn doctor(config_path: &Path) -> Result<(), String> {
    println!("p2wlan doctor");
    println!("版本：{}", env!("CARGO_PKG_VERSION"));
    println!("配置文件：{}", config_path.display());

    if !config_path.exists() {
        println!("配置：不存在");
        println!("建议：先运行 p2wlan login -u <邮箱>");
        return Ok(());
    }

    let config = load_config(config_path)?;
    let mut suggestions = Vec::new();
    println!(
        "登录：{}",
        if config.control.auth_token.is_empty() {
            suggestions.push("运行 p2wlan login -u <邮箱> 完成登录".to_string());
            "no"
        } else {
            "yes"
        }
    );
    println!("控制面：{}", config.control.server_url);
    println!("网络：{}", config.network.network_id);
    println!(
        "虚拟网卡：{} MTU {}",
        config.network.interface, config.network.mtu
    );
    println!("MTU profile：{}", mtu_profile(config.network.mtu));
    suggestions.extend(mtu_config_suggestions(config.network.mtu));
    println!("UDP bind：{}", config.network.udp_bind);
    println!(
        "UDP advertise：{}",
        config
            .network
            .udp_advertise
            .as_deref()
            .filter(|value| !value.trim().is_empty())
            .unwrap_or("(unset)")
    );
    println!(
        "Relay policy：{}",
        if config.relay.prefer_direct {
            "auto/direct-first"
        } else {
            "relay-only"
        }
    );
    println!(
        "Path policy：{}",
        config.relay.effective_path_policy(true).as_label()
    );
    println!(
        "STUN config：{}",
        stun_config_summary(&config.network.stun_servers)
    );
    suggestions.extend(stun_config_suggestions(&config.network.stun_servers));

    if let Ok(bind) = config.network.udp_bind.parse::<SocketAddr>() {
        if bind.port() == 0 {
            suggestions.push(
                "云服务器建议固定 UDP 端口，例如：p2wlan config set udp-bind 0.0.0.0:60207"
                    .to_string(),
            );
        }
    } else {
        suggestions.push("修正 udp-bind，它必须是 ip:port".to_string());
    }
    if config
        .network
        .udp_advertise
        .as_deref()
        .filter(|value| !value.trim().is_empty())
        .is_none()
    {
        suggestions.push(
            "云服务器需要发布公网 UDP 地址，例如：p2wlan config set udp-advertise <公网IP>:60207"
                .to_string(),
        );
    }
    if !config.relay.prefer_direct {
        suggestions
            .push("如果希望优先直连，请运行：p2wlan config set relay-policy auto".to_string());
    }

    match fetch_status(&status_url(&config)).await {
        Ok(snapshot) => {
            println!("Daemon：运行中");
            if let Some(summary) = protocol_boundary_summary(&snapshot) {
                println!("Protocol：{summary}");
            }
            if let Some(summary) = runtime_mtu_summary(&snapshot) {
                println!("Runtime MTU：{summary}");
            }
            println!("虚拟 IP：{}", value_text(&snapshot, "virtual_ip", "未知"));
            println!(
                "网络代际：{}",
                snapshot
                    .get("network_generation")
                    .and_then(Value::as_u64)
                    .unwrap_or(0)
            );
            println!(
                "UDP local：{}",
                value_text(&snapshot, "udp_local_addr", "未知")
            );
            if let Some(summary) = udp_socket_pool_summary(&snapshot) {
                println!("UDP socket pool：{summary}");
            }
            print_nat_diagnostics(&snapshot);
            print_traversal_history(&snapshot);
            println!(
                "Relay：{}",
                if snapshot
                    .get("relay_connected")
                    .and_then(Value::as_bool)
                    .unwrap_or(false)
                {
                    "已连接"
                } else {
                    "未连接"
                }
            );
            let stats = snapshot.get("stats").unwrap_or(&Value::Null);
            println!(
                "Peer：total={} direct={} relay={}",
                value_u64(stats, "total_peers"),
                value_u64(stats, "direct_connections"),
                value_u64(stats, "relay_connections")
            );
            suggestions.extend(protocol_boundary_suggestions(&snapshot));
            suggestions.extend(mtu_snapshot_suggestions(config.network.mtu, &snapshot));
            let mtu_diagnostics = mtu_diagnostic_suggestions(&snapshot);
            if mtu_diagnostics.is_empty() {
                suggestions.extend(mtu_runtime_suggestions(config.network.mtu, stats));
            } else {
                suggestions.extend(mtu_diagnostics);
            }
            print_relay_diagnostics(&snapshot);
            print_peer_diagnostics(&snapshot);
            suggestions.extend(nat_profile_suggestions(
                &snapshot,
                config
                    .network
                    .udp_advertise
                    .as_deref()
                    .is_some_and(|value| !value.trim().is_empty()),
            ));
            suggestions.extend(peer_direct_suggestions(&snapshot));
            if value_u64(stats, "relay_connections") > 0
                && value_u64(stats, "direct_connections") == 0
            {
                suggestions.push(
                    "当前 Peer 只走 Relay。请确认两端云厂商安全组和系统防火墙都放行同一个 UDP 端口"
                        .to_string(),
                );
            }
        }
        Err(error) => {
            println!("Daemon：未运行（{error}）");
            suggestions.push("运行 p2wlan up 启动 TUN daemon".to_string());
        }
    }

    println!("建议：");
    if suggestions.is_empty() {
        println!("- 暂无明显配置问题；如果仍只走 Relay，请检查对端防火墙和云安全组 UDP 入站规则。");
    } else {
        for suggestion in dedupe_strings(suggestions) {
            println!("- {suggestion}");
        }
    }
    Ok(())
}
