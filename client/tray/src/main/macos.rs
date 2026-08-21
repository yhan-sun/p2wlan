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
                    "direct": {"latency_ms": 24}
                },
                {
                    "online": true,
                    "active_path": "relay",
                    "state": "relay",
                    "relay_confirmed_endpoint": "relay.example:18081",
                    "relay_confirmed_generation": 0,
                    "relay": {"latency_ms": 43}
                },
                {
                    "online": true,
                    "active_path": "direct",
                    "state": "hole_punching",
                    "direct": {"latency_ms": 1}
                },
                {
                    "online": true,
                    "active_path": "relay",
                    "state": "relay",
                    "relay": {"latency_ms": 2}
                }
            ]
        });

        assert_eq!(average_verified_latency_ms(&status), Some(34));
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
