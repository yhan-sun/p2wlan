#[cfg(target_os = "macos")]
fn user_owner_for_paths() -> Option<String> {
    for key in ["SUDO_USER", "USER", "LOGNAME"] {
        let value = env::var(key).ok()?;
        if !value.trim().is_empty() && value != "root" {
            return Some(value);
        }
    }
    None
}

#[cfg(target_os = "macos")]
fn shell_quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', "'\\''"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn latency_uses_verified_active_paths_only() {
        let status = serde_json::json!({
            "peers": [
                {
                    "online": true,
                    "active_path": "direct",
                    "state": "direct",
                    "direct": {"latency_ms": 24, "rtt_ewma_ms": 99}
                },
                {
                    "online": true,
                    "active_path": "relay",
                    "state": "direct",
                    "relay_confirmed_endpoint": "relay.example:18081",
                    "relay_confirmed_generation": 0,
                    "relay": {"latency_ms": 43}
                },
                {
                    "online": false,
                    "active_path": "direct",
                    "state": "direct",
                    "direct": {"latency_ms": 1}
                },
                {
                    "online": true,
                    "active_path": "relay",
                    "state": "relay",
                    "relay_confirmed_endpoint": "relay.example:18081",
                    "relay_confirmed_generation": 0,
                    "remote_relay_latency_ms": 2,
                    "relay": {}
                },
                {
                    "online": true,
                    "active_path": "direct",
                    "state": "hole_punching",
                    "direct": {"latency_ms": 3}
                }
            ]
        });

        assert_eq!(average_verified_latency_ms(&status), Some(34));
        assert_eq!(verified_online_connection_count(&status), Some(3));
    }

    #[test]
    fn device_menu_contains_online_roster_only() {
        let status = serde_json::json!({
            "peers": [
                {
                    "node_id": "online",
                    "device_name": "Online",
                    "virtual_ip": "10.20.0.2",
                    "online": true
                },
                {
                    "node_id": "offline",
                    "device_name": "Offline",
                    "virtual_ip": "10.20.0.3",
                    "online": false
                }
            ]
        });

        let menu = tray_device_menu(&status);
        assert_eq!(menu.total, 1);
        assert_eq!(menu.devices[0].name, "Online");
        assert_eq!(menu.devices[0].path, "probing");
    }

    #[test]
    fn tray_device_labels_keep_direct_and_relay_legible() {
        assert_eq!(tray_device_marker("direct"), "🟢");
        assert_eq!(tray_device_path_label("direct"), "直连");
        assert_eq!(tray_device_marker("relay"), "🟠");
        assert_eq!(tray_device_path_label("relay"), "中继");
    }

    #[test]
    fn total_bytes_combines_sent_and_received_counters() {
        let status = serde_json::json!({
            "stats": {
                "total_bytes_sent": 16248,
                "total_bytes_received": 27428
            }
        });

        assert_eq!(total_bytes_from_status(&status), Some(43676));
    }
}
