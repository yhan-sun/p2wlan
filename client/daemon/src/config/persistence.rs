// ============================================================
// Config loading / saving
// ============================================================

impl Config {
    /// Load configuration from a JSON file.
    pub fn load_from_file(path: &Path) -> Result<Self> {
        let content = std::fs::read_to_string(path)
            .map_err(|e| DaemonError::Config(format!("failed to read config: {e}")))?;
        let config: Config = serde_json::from_str(&content)
            .map_err(|e| DaemonError::Config(format!("failed to parse config: {e}")))?;
        Ok(config)
    }

    /// Save configuration to a JSON file using atomic write (temp + rename)
    /// and sets 0600 permissions on Unix. An elevated daemon inherits the
    /// owner of the pinned config directory, including on first creation.
    pub fn save_to_file(&self, path: &Path) -> Result<()> {
        let content = serde_json::to_string_pretty(self)
            .map_err(|e| DaemonError::Config(format!("failed to serialize config: {e}")))?;

        #[cfg(unix)]
        {
            private_file::save(path, content.as_bytes())
                .map_err(|e| DaemonError::Config(format!("failed to save private config: {e}")))
        }
        #[cfg(not(unix))]
        {
            let tmp_path = path.with_extension("tmp");
            let mut file = std::fs::File::create(&tmp_path)
                .map_err(|e| DaemonError::Config(format!("failed to create temp config: {e}")))?;
            file.write_all(content.as_bytes())
                .map_err(|e| DaemonError::Config(format!("failed to write temp config: {e}")))?;
            file.sync_all()
                .map_err(|e| DaemonError::Config(format!("failed to sync temp config: {e}")))?;
            drop(file);
            std::fs::rename(&tmp_path, path)
                .map_err(|e| DaemonError::Config(format!("failed to rename config: {e}")))?;
            Ok(())
        }
    }

    /// Generate a default config with a new identity (X25519 + Ed25519).
    pub fn generate_default(control_url: &str, network_id: &str) -> Result<Self> {
        let identity = p2pnet_crypto::NodeIdentity::generate();
        let ed25519 = p2pnet_crypto::Ed25519KeyPair::generate();

        Ok(Self {
            config_path: None,
            node: NodeConfig {
                node_id: identity.node_id().to_string(),
                public_key: hex::encode(identity.public_key()),
                private_key: hex::encode(identity.private_key()),
                device_name: default_device_name(),
                platform: default_platform(),
                ed25519_public_key: hex::encode(ed25519.public_key()),
                ed25519_private_key: hex::encode(ed25519.private_key()),
            },
            network: NetworkConfig {
                network_id: network_id.to_string(),
                manual: false,
                virtual_ip: "10.20.0.1".to_string(),
                cidr: default_cidr(),
                ipv6_cidr: None,
                mtu: default_mtu(),
                netmask: default_netmask(),
                interface: default_interface(),
                udp_bind: default_udp_bind(),
                udp_advertise: None,
                stun_servers: Vec::new(),
                udp_observers: Vec::new(),
                stun_timeout_ms: default_stun_timeout_ms(),
                udp_liveness_enabled: true,
                udp_liveness_targets: default_udp_liveness_targets(),
                udp_liveness_timeout_ms: default_udp_liveness_timeout_ms(),
                udp_liveness_ttl_ms: default_udp_liveness_ttl_ms(),
                udp_liveness_retries: default_udp_liveness_retries(),
                udp_liveness_pre_flight: false,
                punch_interval_ms: default_punch_interval_ms(),
                punch_attempts: default_punch_attempts(),
                keepalive_interval_secs: default_keepalive_interval_secs(),
                upnp_enabled: true,
                birthday_probing_enabled: true,
                socket_pool_enabled: false,
                socket_pool_size: default_socket_pool_size(),
                fresh_mapping_punch_enabled: true,
                predicted_candidates_enabled: true,
                fresh_mapping_harness_loopback: false,
                hard_hard_experiment_only: false,
                accelerated_consent: false,
                early_candidate_signaling: false,
                gather_host_candidates: true,
                validate_overlay: false,
                overlay_start_gate_file: None,
                overlay_any_path: false,
                overlay_burst: 0,
            },
            control: ControlConfig {
                server_url: control_url.to_string(),
                auth_token: String::new(),
                device_credential: String::new(),
                credential_issued: false,
                registration_seq: None,
                reconnect_interval_secs: default_reconnect_interval(),
                heartbeat_interval_secs: default_heartbeat_interval(),
                proxy_mode: ControlProxyMode::default(),
            },
            relay: RelayConfig {
                servers: Vec::new(),
                preferred_regions: Vec::new(),
                selection_timeout_ms: default_relay_selection_timeout(),
                prefer_direct: true,
                path_policy: PathPolicy::default(),
                relay_startup_timeout_ms: default_relay_timeout(),
                warm_failover: false,
                allow_insecure_plaintext: false,
                ca_cert_path: None,
            },
            diagnostics: DiagnosticsConfig::default(),
            port_mappings: Vec::new(),
            dns: DnsConfig::default(),
            acl: AclConfig::default(),
        })
    }
}
