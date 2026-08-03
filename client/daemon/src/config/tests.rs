// ============================================================
// Tests
// ============================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config_generation() {
        let config = Config::generate_default("https://control.example.com", "net123").unwrap();
        assert!(!config.node.node_id.is_empty());
        assert!(!config.node.public_key.is_empty());
        assert_eq!(config.network.network_id, "net123");
        assert_eq!(config.network.mtu, 1420);
        assert!(config.relay.servers.is_empty());
        assert!(config.relay.prefer_direct);
        assert!(config.relay.preferred_regions.is_empty());
        assert_eq!(config.relay.selection_timeout_ms, 3000);
        assert!(!config.diagnostics.enabled);
        assert_eq!(config.diagnostics.bind, "127.0.0.1:39277");
        assert!(config.port_mappings.is_empty());
    }

    #[test]
    fn test_config_serialization_roundtrip() {
        let config = Config::generate_default("https://ctrl.test", "net1").unwrap();
        let json = serde_json::to_string_pretty(&config).unwrap();
        let decoded: Config = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded.node.node_id, config.node.node_id);
        assert_eq!(decoded.network.virtual_ip, config.network.virtual_ip);
        assert_eq!(decoded.network.udp_bind, config.network.udp_bind);
        assert_eq!(decoded.network.udp_advertise, config.network.udp_advertise);
        assert_eq!(decoded.network.stun_servers, config.network.stun_servers);
        assert_eq!(decoded.network.udp_observers, config.network.udp_observers);
        assert_eq!(
            decoded.network.stun_timeout_ms,
            config.network.stun_timeout_ms
        );
        assert_eq!(
            decoded.network.punch_interval_ms,
            config.network.punch_interval_ms
        );
        assert_eq!(
            decoded.network.punch_attempts,
            config.network.punch_attempts
        );
        assert_eq!(
            decoded.network.keepalive_interval_secs,
            config.network.keepalive_interval_secs
        );
        assert_eq!(decoded.network.upnp_enabled, config.network.upnp_enabled);
        assert_eq!(
            decoded.network.birthday_probing_enabled,
            config.network.birthday_probing_enabled
        );
        assert_eq!(
            decoded.network.socket_pool_enabled,
            config.network.socket_pool_enabled
        );
        assert_eq!(
            decoded.network.socket_pool_size,
            config.network.socket_pool_size
        );
        assert_eq!(decoded.diagnostics.enabled, config.diagnostics.enabled);
        assert_eq!(decoded.diagnostics.bind, config.diagnostics.bind);
        assert_eq!(
            decoded.relay.preferred_regions,
            config.relay.preferred_regions
        );
        assert_eq!(
            decoded.relay.selection_timeout_ms,
            config.relay.selection_timeout_ms
        );
    }

    #[test]
    fn test_config_debug_redacts_sensitive_values() {
        let mut config = Config::generate_default("https://ctrl.test", "net1").unwrap();
        config.control.auth_token = "jwt-secret-token".to_string();
        config.control.device_credential = "dc-secret-token".to_string();

        let debug = format!("{config:?}");
        assert!(debug.contains("[redacted]"));
        assert!(debug.contains("node_id"));
        assert!(debug.contains("server_url"));
        assert!(!debug.contains(&config.node.private_key));
        assert!(!debug.contains(&config.node.ed25519_private_key));
        assert!(!debug.contains(&config.control.auth_token));
        assert!(!debug.contains(&config.control.device_credential));
    }

    #[test]
    fn test_config_backward_compatible_udp_endpoint_defaults() {
        // Old config without ed25519 keys should still deserialize
        let json = r#"{
            "node": {
                "node_id": "node1",
                "public_key": "pub",
                "private_key": "priv",
                "device_name": "dev",
                "platform": "linux"
            },
            "network": {
                "network_id": "net1",
                "virtual_ip": "10.20.0.1",
                "cidr": "10.20.0.0/16",
                "ipv6_cidr": null,
                "mtu": 1420,
                "netmask": "255.255.0.0",
                "interface": "p2wlan0"
            },
            "control": {
                "server_url": "http://ctrl",
                "auth_token": "",
                "reconnect_interval_secs": 5,
                "heartbeat_interval_secs": 5
            },
            "relay": {
                "servers": [],
                "prefer_direct": true,
                "fallback_timeout_ms": 5000
            }
        }"#;

        let decoded: Config = serde_json::from_str(json).unwrap();
        assert_eq!(decoded.network.udp_bind, "0.0.0.0:0");
        assert_eq!(decoded.network.udp_advertise, None);
        assert!(decoded.network.stun_servers.is_empty());
        assert!(decoded.network.udp_observers.is_empty());
        assert_eq!(decoded.network.stun_timeout_ms, 1500);
        assert_eq!(decoded.network.punch_interval_ms, 200);
        assert_eq!(decoded.network.punch_attempts, 10);
        assert_eq!(decoded.network.keepalive_interval_secs, 25);
        assert!(decoded.network.upnp_enabled);
        assert!(decoded.network.birthday_probing_enabled);
        assert!(!decoded.network.socket_pool_enabled);
        assert_eq!(decoded.network.socket_pool_size, 1);
        assert!(decoded.relay.preferred_regions.is_empty());
        assert_eq!(decoded.relay.selection_timeout_ms, 3000);
        assert!(!decoded.diagnostics.enabled);
        assert_eq!(decoded.diagnostics.bind, "127.0.0.1:39277");
    }

    #[test]
    fn test_config_save_load_roundtrip() {
        let suffix = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let dir = std::env::temp_dir().join(format!(
            "p2wlan_config_test_{}_{}",
            std::process::id(),
            suffix
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("test_config.json");

        let config = Config::generate_default("https://ctrl.test", "net1").unwrap();
        config.save_to_file(&path).unwrap();
        let loaded = Config::load_from_file(&path).unwrap();

        assert_eq!(loaded.node.node_id, config.node.node_id);
        assert_eq!(loaded.network.network_id, config.network.network_id);

        // Cleanup
        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_dir(&dir);
    }

    #[test]
    fn test_port_mapping_config() {
        let mapping = PortMappingConfig {
            id: "map1".to_string(),
            protocol: "tcp".to_string(),
            local_address: "127.0.0.1".to_string(),
            local_port: 8080,
            remote_port: 30000,
            active: true,
        };
        assert_eq!(mapping.protocol, "tcp");
        assert!(mapping.active);
    }

    #[test]
    fn test_acl_default_allows_all() {
        let acl = AclConfig::default();
        assert!(!acl.enabled);
        assert_eq!(acl.rules.len(), 1);
        assert_eq!(acl.rules[0].action, "allow");
        assert_eq!(acl.rules[0].src, "*");
    }

    #[test]
    fn test_dns_default() {
        let dns = DnsConfig::default();
        assert!(!dns.enabled);
        assert_eq!(dns.suffix, "p2wlan.local");
        assert!(dns.mappings.is_empty());
    }

    #[test]
    fn test_network_config_defaults() {
        let config = Config::generate_default("https://ctrl", "net1").unwrap();
        assert_eq!(config.network.cidr, "10.20.0.0/16");
        assert_eq!(config.network.mtu, 1420);
        assert_eq!(config.network.netmask, "255.255.0.0");
        #[cfg(target_os = "windows")]
        assert_eq!(config.network.interface, "p2wlan");
        #[cfg(not(target_os = "windows"))]
        assert_eq!(config.network.interface, "p2wlan0");
        assert_eq!(config.network.udp_bind, "0.0.0.0:0");
        assert_eq!(config.network.udp_advertise, None);
        assert!(config.network.stun_servers.is_empty());
        assert!(config.network.udp_observers.is_empty());
        assert_eq!(config.network.stun_timeout_ms, 1500);
        assert_eq!(config.network.punch_interval_ms, 200);
        assert_eq!(config.network.punch_attempts, 10);
        assert_eq!(config.network.keepalive_interval_secs, 25);
        assert!(config.network.upnp_enabled);
        assert!(config.network.birthday_probing_enabled);
        assert!(!config.network.socket_pool_enabled);
        assert_eq!(config.network.socket_pool_size, 1);
    }
}
