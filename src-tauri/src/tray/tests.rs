#[cfg(test)]
mod tests {
    use super::*;
    use crate::daemon_manager::DaemonOperationStatus;

    fn snapshot(
        phase: DaemonOperationPhase,
        diagnostics: Option<serde_json::Value>,
    ) -> DesktopStatus {
        let diagnostics_alive = diagnostics.is_some();
        DesktopStatus {
            operation: DaemonOperationStatus {
                phase,
                message: "test".to_string(),
                started_at_ms: 1,
                last_error: None,
            },
            diagnostics,
            diagnostics_url: "http://127.0.0.1:39277/status".to_string(),
            diagnostics_alive,
            diagnostics_stale: false,
            diagnostics_error: None,
        }
    }

    #[test]
    fn running_tray_presentation_includes_network_state() {
        let presentation = tray_presentation(&snapshot(
            DaemonOperationPhase::Running,
            Some(serde_json::json!({
                "virtual_ip": "10.20.0.5",
                "stats": {
                    "direct_connections": 2,
                    "relay_connections": 1
                }
            })),
        ));

        assert_eq!(presentation.status_label, "已连接");
        assert_eq!(presentation.virtual_ip, "10.20.0.5");
        assert_eq!(presentation.online, Some(3));
        assert!(presentation.running);
        assert!(!presentation.busy);
    }

    #[test]
    fn transitional_tray_presentation_disables_conflicting_actions() {
        let presentation = tray_presentation(&snapshot(DaemonOperationPhase::Authorizing, None));

        assert_eq!(presentation.status_label, "等待系统授权");
        assert_eq!(presentation.online, None);
        assert!(!presentation.running);
        assert!(presentation.busy);
    }

    #[test]
    fn tray_device_menu_uses_device_name_and_falls_back_to_node_id() {
        let menu = tray_device_menu(&snapshot(
            DaemonOperationPhase::Running,
            Some(serde_json::json!({
                "peers": [
                    {
                        "node_id": "node-b-123456789",
                        "device_name": "Office Mac",
                        "virtual_ip": "10.20.0.5"
                    },
                    {
                        "node_id": "node-a-123456789",
                        "virtual_ip": "10.20.0.3"
                    }
                ]
            })),
        ));

        assert_eq!(menu.total, 2);
        assert_eq!(menu.devices[0].name, "node-a-12345");
        assert_eq!(menu.devices[1].name, "Office Mac");
    }

    #[test]
    fn copy_menu_id_only_accepts_ip_addresses() {
        assert_eq!(
            copy_ip_from_menu_id("copy_peer_ip:10.20.0.5"),
            Some("10.20.0.5")
        );
        assert_eq!(copy_ip_from_menu_id("copy_peer_ip:not-an-ip"), None);
        assert_eq!(copy_ip_from_menu_id("quit"), None);
    }
}
