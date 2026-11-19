/// How remote device keys become trusted. Existing configurations retain the
/// managed Control identity directory unless strict verification is selected.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum PeerTrustMode {
    #[default]
    Control,
    Strict,
}

/// An identity confirmed through an independent channel before startup.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PeerIdentityPin {
    pub node_id: String,
    /// Full 32-byte X25519 public key encoded as hexadecimal.
    pub public_key: String,
    pub virtual_ip: String,
}

/// Immutable for the daemon lifetime. Rotation requires stopping the daemon,
/// independently verifying the replacement, editing the config and restarting.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct PeerTrustConfig {
    pub mode: PeerTrustMode,
    /// Explicit binding prevents a copied profile silently reusing another
    /// network's trusted devices.
    pub network_id: String,
    pub peers: Vec<PeerIdentityPin>,
}

const MAX_PEER_IDENTITY_PINS: usize = 1024;

impl NetworkConfig {
    pub fn validate_peer_trust(&self) -> std::result::Result<(), String> {
        let trust = &self.peer_trust;
        if trust.mode == PeerTrustMode::Control {
            return if trust.network_id.is_empty() && trust.peers.is_empty() {
                Ok(())
            } else {
                Err("peer_trust.mode must be strict when local pins are configured".into())
            };
        }
        if trust.network_id.is_empty() || trust.network_id != self.network_id {
            return Err("peer_trust.network_id must match the current network".into());
        }
        if trust.peers.len() > MAX_PEER_IDENTITY_PINS {
            return Err("peer_trust.peers exceeds the 1024 identity limit".into());
        }
        let mut ids = std::collections::HashSet::new();
        let mut keys = std::collections::HashSet::new();
        let mut addresses = std::collections::HashSet::new();
        for pin in &trust.peers {
            if pin.node_id.is_empty()
                || pin.node_id.len() > 255
                || pin.node_id.chars().any(char::is_whitespace)
                || !ids.insert(pin.node_id.as_str())
            {
                return Err("peer_trust contains an invalid or duplicate node_id".into());
            }
            let key = hex::decode(&pin.public_key)
                .ok()
                .filter(|key| key.len() == 32 && key.iter().any(|byte| *byte != 0))
                .ok_or("peer_trust requires a nonzero full 32-byte public_key")?;
            if !keys.insert(key) {
                return Err("peer_trust contains a duplicate public_key".into());
            }
            let address = pin
                .virtual_ip
                .parse::<std::net::Ipv4Addr>()
                .ok()
                .filter(|address| {
                    !address.is_unspecified() && !address.is_multicast() && !address.is_broadcast()
                })
                .ok_or("peer_trust requires a valid unicast virtual_ip")?;
            if !addresses.insert(address) {
                return Err("peer_trust contains a duplicate virtual_ip".into());
            }
        }
        Ok(())
    }

    pub(crate) fn peer_identity_allowed(
        &self,
        node_id: &str,
        public_key: &str,
        virtual_ip: &str,
    ) -> bool {
        // The immutable policy is fully validated at startup/owner creation.
        // Remote roster size must not multiply that validation work.
        if self.peer_trust.mode == PeerTrustMode::Control {
            return self.peer_trust.network_id.is_empty() && self.peer_trust.peers.is_empty();
        }
        if self.peer_trust.network_id.is_empty()
            || self.peer_trust.network_id != self.network_id
            || self.peer_trust.peers.len() > MAX_PEER_IDENTITY_PINS
        {
            return false;
        }
        let Some(pin) = self
            .peer_trust
            .peers
            .iter()
            .find(|pin| pin.node_id == node_id)
        else {
            return false;
        };
        if public_key.len() != 64 {
            return false;
        }
        let Ok(key) = hex::decode(public_key) else {
            return false;
        };
        let Ok(address) = virtual_ip.parse::<std::net::Ipv4Addr>() else {
            return false;
        };
        hex::decode(&pin.public_key).is_ok_and(|expected| expected == key)
            && pin.virtual_ip.parse::<std::net::Ipv4Addr>().ok() == Some(address)
    }
}

#[cfg(test)]
mod peer_trust_tests {
    use super::*;

    fn strict_network() -> NetworkConfig {
        let mut config = Config::generate_default("https://control.example.com", "net-1").unwrap();
        config.network.peer_trust = PeerTrustConfig {
            mode: PeerTrustMode::Strict,
            network_id: "net-1".into(),
            peers: vec![PeerIdentityPin {
                node_id: "node-a".into(),
                public_key: "42".repeat(32),
                virtual_ip: "10.20.0.2".into(),
            }],
        };
        config.network
    }

    #[test]
    fn strict_peer_trust_binds_every_identity_field_and_network() {
        let mut network = strict_network();
        assert!(network.peer_identity_allowed("node-a", &"42".repeat(32), "10.20.0.2"));
        assert!(!network.peer_identity_allowed("renamed-node", &"42".repeat(32), "10.20.0.2"));
        assert!(!network.peer_identity_allowed("node-a", &"73".repeat(32), "10.20.0.2"));
        assert!(!network.peer_identity_allowed("node-a", &"42".repeat(32), "10.20.0.3"));
        network.network_id = "other-network".into();
        assert!(network.validate_peer_trust().is_err());
        assert!(!network.peer_identity_allowed("node-a", &"42".repeat(32), "10.20.0.2"));
    }

    #[test]
    fn peer_trust_rejects_invalid_ambiguous_or_unbounded_policy() {
        for mutate in [
            |n: &mut NetworkConfig| n.peer_trust.network_id.clear(),
            |n: &mut NetworkConfig| n.peer_trust.peers[0].public_key = "42".into(),
            |n: &mut NetworkConfig| n.peer_trust.peers[0].virtual_ip = "not-an-ip".into(),
            |n: &mut NetworkConfig| n.peer_trust.peers.push(n.peer_trust.peers[0].clone()),
            |n: &mut NetworkConfig| n.peer_trust.mode = PeerTrustMode::Control,
            |n: &mut NetworkConfig| {
                n.peer_trust.peers = vec![n.peer_trust.peers[0].clone(); MAX_PEER_IDENTITY_PINS + 1]
            },
        ] {
            let mut network = strict_network();
            mutate(&mut network);
            assert!(network.validate_peer_trust().is_err());
        }
    }

    #[test]
    fn absent_peer_trust_preserves_control_mode_but_empty_strict_denies_all() {
        let network = Config::generate_default("https://control.example.com", "net-1")
            .unwrap()
            .network;
        let mut json = serde_json::to_value(&network).unwrap();
        json.as_object_mut().unwrap().remove("peer_trust");
        let mut restored: NetworkConfig = serde_json::from_value(json).unwrap();
        assert_eq!(restored.peer_trust.mode, PeerTrustMode::Control);
        assert!(restored.peer_identity_allowed("legacy-peer", "legacy-key", "10.20.0.2"));
        restored.peer_trust = PeerTrustConfig {
            mode: PeerTrustMode::Strict,
            network_id: "net-1".into(),
            peers: vec![],
        };
        assert!(restored.validate_peer_trust().is_ok());
        assert!(!restored.peer_identity_allowed("legacy-peer", "legacy-key", "10.20.0.2"));
    }
}
