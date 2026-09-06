fn query_daemon_state() -> DaemonState {
    let client = match reqwest::blocking::Client::builder()
        .no_proxy()
        .timeout(Duration::from_millis(1200))
        .build()
    {
        Ok(client) => client,
        Err(_) => return DaemonState::offline(),
    };
    let status_url = match p2wlan_desktop_host::normalize_diagnostics_url(STATUS_URL) {
        Ok(url) => url,
        Err(_) => return DaemonState::offline(),
    };
    let health_url = match p2wlan_desktop_host::health_url_from_status_url(&status_url) {
        Ok(url) => url,
        Err(_) => return DaemonState::offline(),
    };
    let Ok(health) = client.get(health_url).send() else {
        return DaemonState::offline();
    };
    if !health.status().is_success() {
        return DaemonState::offline();
    }
    let status = match fetch_status_with_auth(&client, &status_url) {
        Ok(status) => Some(status),
        Err(message) => return DaemonState::session_error(message),
    };
    let virtual_ip = status
        .as_ref()
        .and_then(|value| value.get("virtual_ip"))
        .and_then(serde_json::Value::as_str)
        .filter(|value| !value.trim().is_empty())
        .unwrap_or("—")
        .to_string();
    let online = status
        .as_ref()
        .and_then(verified_online_connection_count);
    let peer_count = status
        .as_ref()
        .and_then(|value| value.get("stats"))
        .and_then(|stats| stats.get("total_peers"))
        .and_then(serde_json::Value::as_u64)
        .unwrap_or(0);
    let latency_ms = status
        .as_ref()
        .and_then(average_verified_latency_ms);
    let total_bytes = status.as_ref().and_then(total_bytes_from_status);
    let devices = status.as_ref().map(tray_device_menu).unwrap_or_default();
    DaemonState {
        running: true,
        busy: false,
        status_label: "已连接".to_string(),
        virtual_ip: virtual_ip.clone(),
        online,
        latency_ms,
        total_bytes,
        speed_bytes_per_second: None,
        devices,
        tooltip: match online {
            Some(count) => format!("p2wlan：已连接 · {virtual_ip} · {count} 台在线"),
            None => format!("p2wlan：已连接 · {peer_count} 台设备"),
        },
    }
}

fn total_bytes_from_status(status: &serde_json::Value) -> Option<u64> {
    let stats = status.get("stats")?;
    let sent = stats
        .get("total_bytes_sent")
        .and_then(serde_json::Value::as_u64)?;
    let received = stats
        .get("total_bytes_received")
        .and_then(serde_json::Value::as_u64)?;
    Some(sent.saturating_add(received))
}

fn average_verified_latency_ms(status: &serde_json::Value) -> Option<u64> {
    let peers = status.get("peers").and_then(serde_json::Value::as_array)?;
    let latencies = peers
        .iter()
        .filter_map(verified_peer_latency_ms)
        .collect::<Vec<_>>();
    if latencies.is_empty() {
        return None;
    }
    let count = latencies.len() as u128;
    let sum = latencies.iter().copied().map(u128::from).sum::<u128>();
    Some(((sum + count / 2) / count) as u64)
}

fn verified_online_connection_count(status: &serde_json::Value) -> Option<u64> {
    let peers = status.get("peers").and_then(serde_json::Value::as_array)?;
    Some(
        peers
            .iter()
            .filter(|peer| verified_active_path_key(peer).is_some())
            .count() as u64,
    )
}

fn verified_peer_latency_ms(peer: &serde_json::Value) -> Option<u64> {
    let path_key = verified_active_path_key(peer)?;
    peer.get(path_key)
        .and_then(|path| path.get("latency_ms"))
        .and_then(serde_json::Value::as_u64)
        .or_else(|| {
            peer.get(path_key)
                .and_then(|path| path.get("rtt_ewma_ms"))
                .and_then(serde_json::Value::as_u64)
        })
}

fn verified_active_path_key(peer: &serde_json::Value) -> Option<&'static str> {
    if peer.get("online").and_then(serde_json::Value::as_bool) != Some(true) {
        return None;
    }
    let active_path = peer.get("active_path").and_then(serde_json::Value::as_str);
    let state = peer.get("state").and_then(serde_json::Value::as_str);
    match (active_path, state) {
        (Some("direct"), Some("direct")) => Some("direct"),
        (Some("relay"), _) => {
            let confirmed = peer
                .get("relay_confirmed_endpoint")
                .and_then(serde_json::Value::as_str)
                .is_some_and(|endpoint| !endpoint.trim().is_empty())
                && peer
                    .get("relay_confirmed_generation")
                    .and_then(serde_json::Value::as_u64)
                    .is_some();
            if !confirmed {
                return None;
            }
            Some("relay")
        }
        _ => None,
    }
}

fn fetch_status_with_auth(
    client: &reqwest::blocking::Client,
    status_url: &str,
) -> Result<serde_json::Value, String> {
    for attempt in 0..2 {
        let token = read_diagnostics_auth_token().ok_or_else(|| {
            "诊断会话 Token 文件不存在，请重新启动 p2wlan-daemon。".to_string()
        })?;
        let response = client
            .get(status_url)
            .bearer_auth(token)
            .send()
            .map_err(|_| "无法读取 p2wlan-daemon 状态。".to_string())?;
        if response.status() == reqwest::StatusCode::UNAUTHORIZED && attempt == 0 {
            continue;
        }
        if response.status() == reqwest::StatusCode::UNAUTHORIZED {
            return Err("诊断会话已变化，请重新启动 p2wlan-daemon。".to_string());
        }
        if !response.status().is_success() {
            return Err(format!("p2wlan-daemon 状态请求返回 HTTP {}。", response.status()));
        }
        return response
            .json::<serde_json::Value>()
            .map_err(|_| "p2wlan-daemon 状态响应无法解析。".to_string());
    }
    Err("诊断会话已变化，请重新启动 p2wlan-daemon。".to_string())
}

fn tray_device_menu(status: &serde_json::Value) -> TrayDeviceMenu {
    let Some(peers) = status.get("peers").and_then(serde_json::Value::as_array) else {
        return TrayDeviceMenu::default();
    };

    let mut devices = peers
        .iter()
        .filter_map(|peer| {
            if peer.get("online").and_then(serde_json::Value::as_bool) != Some(true) {
                return None;
            }
            let virtual_ip = peer.get("virtual_ip").and_then(serde_json::Value::as_str)?;
            virtual_ip.parse::<IpAddr>().ok()?;
            let node_id = peer
                .get("node_id")
                .and_then(serde_json::Value::as_str)
                .unwrap_or_default();
            let device_name = peer
                .get("device_name")
                .and_then(serde_json::Value::as_str)
                .unwrap_or_default();
            Some(TrayDevice {
                name: display_device_name(device_name, node_id),
                virtual_ip: virtual_ip.to_string(),
                path: verified_active_path_key(peer)
                    .unwrap_or("probing")
                    .to_string(),
            })
        })
        .collect::<Vec<_>>();

    devices.sort_by(|left, right| {
        left.name
            .to_lowercase()
            .cmp(&right.name.to_lowercase())
            .then_with(|| left.virtual_ip.cmp(&right.virtual_ip))
    });
    devices.dedup_by(|left, right| left.virtual_ip == right.virtual_ip);

    let total = devices.len();
    TrayDeviceMenu { devices, total }
}

fn display_device_name(device_name: &str, node_id: &str) -> String {
    let normalized = device_name.split_whitespace().collect::<Vec<_>>().join(" ");
    let fallback = if node_id.is_empty() {
        "未知设备".to_string()
    } else {
        node_id.chars().take(12).collect()
    };
    let name = if normalized.is_empty() {
        fallback
    } else {
        normalized
    };

    let mut chars = name.chars();
    let visible = chars.by_ref().take(28).collect::<String>();
    if chars.next().is_some() {
        format!("{visible}...")
    } else {
        visible
    }
}

fn build_tray_menu(state: &DaemonState) -> MenuBuilder<UserEvent> {
    let latency = format_tray_latency(state.latency_ms);
    let speed = format_tray_rate(state.speed_bytes_per_second);
    let network = if state.running {
        match state.online {
            Some(count) => format!(
                "虚拟 IP：{} · 在线设备：{count} · 本端平均 RTT：{latency} · 速度：{speed}",
                state.virtual_ip
            ),
            None => format!(
                "虚拟 IP：{} · 在线设备：— · 本端平均 RTT：{latency} · 速度：{speed}",
                state.virtual_ip
            ),
        }
    } else {
        "虚拟网络未启动".to_string()
    };

    let device_menu = if state.devices.devices.is_empty() {
        MenuBuilder::new().item("暂无在线设备", UserEvent::NoDevices)
    } else {
        state
            .devices
            .devices
            .iter()
            .fold(MenuBuilder::new(), |menu, device| {
                menu.item(
                    &format!(
                        "{} {} · {} · {}",
                        tray_device_marker(&device.path),
                        tray_device_path_label(&device.path),
                        device.name,
                        device.virtual_ip
                    ),
                    UserEvent::CopyPeerIp(device.virtual_ip.clone()),
                )
            })
    };

    MenuBuilder::new()
        .item(
            &format!("状态：{}", state.status_label),
            UserEvent::StatusInfo,
        )
        .item(&network, UserEvent::NetworkInfo)
        .separator()
        .item("打开 P2WLAN", UserEvent::OpenClient)
        .item("启动 Daemon", UserEvent::StartDaemon)
        .item("停止 Daemon", UserEvent::StopDaemon)
        .submenu(
            &format!("设备（{}）", state.devices.total),
            device_menu,
        )
        .separator()
        .item("打开日志", UserEvent::OpenLogs)
        .separator()
        .item("退出 P2WLAN", UserEvent::Quit)
}

fn tray_device_marker(path: &str) -> &'static str {
    match path {
        "direct" => "🟢",
        "relay" => "🟠",
        _ => "🟡",
    }
}

fn tray_device_path_label(path: &str) -> &'static str {
    match path {
        "direct" => "直连",
        "relay" => "中继",
        _ => "探测中",
    }
}
