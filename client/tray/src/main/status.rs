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
    let status = client
        .get(status_url)
        .send()
        .ok()
        .and_then(|response| response.json::<serde_json::Value>().ok());
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
    let devices = status.as_ref().map(tray_device_menu).unwrap_or_default();
    DaemonState {
        running: true,
        busy: false,
        status_label: "已连接".to_string(),
        virtual_ip: virtual_ip.clone(),
        online,
        devices,
        tooltip: match online {
            Some(count) => format!("p2wlan：已连接 · {virtual_ip} · {count} 台在线"),
            None => format!("p2wlan：已连接 · {peer_count} 台设备"),
        },
    }
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
