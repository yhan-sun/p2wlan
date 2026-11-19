// ============================================================
// Config loading / saving
// ============================================================

impl Config {
    /// Load configuration from a JSON file.
    pub fn load_from_file(path: &Path) -> Result<Self> {
        let content = zeroize::Zeroizing::new(
            std::fs::read_to_string(path)
                .map_err(|e| DaemonError::Config(format!("failed to read config: {e}")))?,
        );
        let mut config: Config = serde_json::from_str(&content)
            .map_err(|e| DaemonError::Config(format!("failed to parse config: {e}")))?;
        if let Some(protection) = &config.identity_protection {
            protection.open(&mut config.node)?;
        } else if identity_protection::contains_wrapped_key(&config.node) {
            return Err(DaemonError::Config(
                "protected device identity is missing its protection settings".into(),
            ));
        }
        Ok(config)
    }

    /// Save configuration to a JSON file using atomic write (temp + rename)
    /// and sets 0600 permissions on Unix. An elevated daemon inherits the
    /// owner of the pinned config directory, including on first creation.
    pub fn save_to_file(&self, path: &Path) -> Result<()> {
        self.save_with_expected_protection(path, self.identity_protection.as_ref())
    }

    fn save_with_expected_protection(
        &self,
        path: &Path,
        expected: Option<&IdentityProtection>,
    ) -> Result<()> {
        let protected;
        let persisted = if let Some(protection) = &self.identity_protection {
            protected = Config {
                config_path: None,
                node: protection.seal(&self.node)?,
                identity_protection: Some(protection.clone()),
                network: self.network.clone(),
                control: self.control.clone(),
                relay: self.relay.clone(),
                diagnostics: self.diagnostics.clone(),
                port_mappings: self.port_mappings.clone(),
                dns: self.dns.clone(),
                acl: self.acl.clone(),
            };
            &protected
        } else {
            self
        };
        let content = serde_json::to_string_pretty(persisted)
            .map_err(|e| DaemonError::Config(format!("failed to serialize config: {e}")))?;
        let content = zeroize::Zeroizing::new(content);
        #[cfg(unix)]
        {
            private_file::save(path, content.as_bytes(), expected)
                .map_err(|e| DaemonError::Config(format!("failed to save private config: {e}")))
        }
        #[cfg(not(unix))]
        {
            let _write_lock = DaemonInstanceLock::acquire_for_save(path)?;
            match std::fs::File::open(path) {
                Ok(file) => check_identity_protection_before_save(file, expected)?,
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(error) => return Err(error.into()),
            }
            let tmp_path = path.with_file_name(format!(
                ".p2wlan-config-{:032x}.tmp",
                rand::random::<u128>()
            ));
            let mut file = std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&tmp_path)
                .map_err(|e| DaemonError::Config(format!("failed to create temp config: {e}")))?;
            let written = file
                .write_all(content.as_bytes())
                .and_then(|_| file.sync_all());
            drop(file);
            let published = written.and_then(|_| std::fs::rename(&tmp_path, path));
            if published.is_err() {
                let _ = std::fs::remove_file(&tmp_path);
            }
            published
                .map_err(|e| DaemonError::Config(format!("failed to save private config: {e}")))
        }
    }

    /// Wrap an existing profile's device keys in a single atomic replacement.
    /// The profile must be stopped to prevent a live daemon from saving an old config.
    pub fn protect_identity_file(path: &Path, protection: IdentityProtection) -> Result<()> {
        let _lock = DaemonInstanceLock::acquire_for_edit(path)?;
        let mut config = Self::load_from_file(path)?;
        let previous = config.identity_protection.replace(protection);
        config.save_with_expected_protection(path, previous.as_ref())
    }

    pub fn identity_is_protected(&self) -> bool {
        self.identity_protection.is_some()
    }

    /// Generate a default config with a new identity (X25519 + Ed25519).
    pub fn generate_default(control_url: &str, network_id: &str) -> Result<Self> {
        let identity = p2pnet_crypto::NodeIdentity::generate();
        let ed25519 = p2pnet_crypto::Ed25519KeyPair::generate();

        Ok(Self {
            config_path: None,
            identity_protection: None,
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
                peer_trust: PeerTrustConfig::default(),
                manual: false,
                virtual_ip: "10.20.0.1".to_string(),
                cidr: default_cidr(),
                ipv6_cidr: None,
                mtu: default_mtu(),
                business_padding_16: false,
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

/// Reject a stale save after an identity migration or a change of backend.
/// The caller holds the publication lock and owns the current file descriptor.
fn check_identity_protection_before_save(
    file: std::fs::File,
    expected: Option<&IdentityProtection>,
) -> std::io::Result<()> {
    use std::io::{Error, ErrorKind, Read};
    const MAX_CONFIG_BYTES: u64 = 4 * 1024 * 1024;

    #[derive(Deserialize)]
    struct NodeEnvelope<'a> {
        #[serde(default, borrow)]
        private_key: std::borrow::Cow<'a, str>,
    }
    #[derive(Deserialize)]
    struct Envelope<'a> {
        identity_protection: Option<IdentityProtection>,
        #[serde(borrow)]
        node: Option<NodeEnvelope<'a>>,
    }

    if !file.metadata()?.is_file() {
        return Err(Error::new(
            ErrorKind::InvalidData,
            "config target must be a regular file",
        ));
    }
    let mut bytes = zeroize::Zeroizing::new(Vec::new());
    file.take(MAX_CONFIG_BYTES + 1).read_to_end(&mut bytes)?;
    if bytes.len() as u64 > MAX_CONFIG_BYTES {
        return Err(Error::new(
            ErrorKind::InvalidData,
            "existing config exceeds the save verification limit",
        ));
    }
    let current: Envelope<'_> = serde_json::from_slice(&bytes).map_err(|_| {
        Error::new(
            ErrorKind::InvalidData,
            "cannot verify identity protection on the existing config",
        )
    })?;
    if current.identity_protection.as_ref() != expected
        || (current.identity_protection.is_none()
            && current
                .node
                .as_ref()
                .is_some_and(|node| identity_protection::is_wrapped_key(&node.private_key)))
    {
        return Err(Error::new(
            ErrorKind::InvalidData,
            "device identity protection changed on disk; reload the profile before saving",
        ));
    }
    Ok(())
}
