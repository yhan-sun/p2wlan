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
    let online = status.as_ref().and_then(|value| {
        let stats = value.get("stats")?;
        Some(
            stats
                .get("direct_connections")
                .and_then(serde_json::Value::as_u64)
                .unwrap_or_default()
                + stats
                    .get("relay_connections")
                    .and_then(serde_json::Value::as_u64)
                    .unwrap_or_default(),
        )
    });
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

fn verified_peer_latency_ms(peer: &serde_json::Value) -> Option<u64> {
    if peer.get("online").and_then(serde_json::Value::as_bool) == Some(false) {
        return None;
    }

    let active_path = peer.get("active_path").and_then(serde_json::Value::as_str);
    let state = peer.get("state").and_then(serde_json::Value::as_str);
    let path_key = match (active_path, state) {
        (Some("direct"), Some("direct")) => "direct",
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
            "relay"
        }
        _ => return None,
    };

    peer.get(path_key)
        .and_then(|path| path.get("rtt_ewma_ms"))
        .and_then(serde_json::Value::as_u64)
        .or_else(|| {
            peer.get(path_key)
                .and_then(|path| path.get("latency_ms"))
                .and_then(serde_json::Value::as_u64)
        })
        .or_else(|| {
            (path_key == "relay")
                .then(|| peer.get("remote_relay_latency_ms"))
                .flatten()
                .and_then(serde_json::Value::as_u64)
        })
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
    devices.truncate(MAX_TRAY_DEVICES);
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

fn rebuild_device_menu(submenu: &Submenu, device_menu: &TrayDeviceMenu) {
    while !submenu.items().is_empty() {
        let _ = submenu.remove_at(0);
    }

    submenu.set_text(format!("设备（{}）", device_menu.total));
    if device_menu.devices.is_empty() {
        let empty = MenuItem::with_id("no-devices", "暂无在线设备", false, None);
        let _ = submenu.append(&empty);
        return;
    }

    for device in &device_menu.devices {
        let item = MenuItem::with_id(
            format!("{COPY_PEER_IP_PREFIX}{}", device.virtual_ip),
            format!("{} · {}", device.name, device.virtual_ip),
            true,
            None,
        );
        let _ = submenu.append(&item);
    }

    if device_menu.total > device_menu.devices.len() {
        let remaining = device_menu.total - device_menu.devices.len();
        let overflow = MenuItem::with_id(
            "more-devices",
            format!("另有 {remaining} 台设备，请在控制台查看"),
            false,
            None,
        );
        let _ = submenu.append(&overflow);
    }
}

fn copy_ip_from_menu_id(id: &str) -> Option<&str> {
    let ip = id.strip_prefix(COPY_PEER_IP_PREFIX)?;
    ip.parse::<IpAddr>().ok().map(|_| ip)
}
