//! Configuration for creating a virtual network interface.

use std::net::Ipv4Addr;

use crate::error::{Error, Result};

/// Configuration parameters for a TUN/Wintun/utun virtual interface.
#[derive(Debug, Clone)]
pub struct InterfaceConfig {
    /// Interface name (e.g. "p2pnet0"). On Windows this is the adapter name.
    /// Max length depends on platform (15 chars on Linux, 256 on Windows/macOS).
    pub name: String,

    /// Virtual IPv4 address assigned to this interface (e.g. 10.20.0.1).
    pub address: Ipv4Addr,

    /// Subnet mask (e.g. 255.255.255.0).
    pub netmask: Ipv4Addr,

    /// Optional gateway address. If None, the first host address is used.
    pub gateway: Option<Ipv4Addr>,

    /// Maximum Transmission Unit. WireGuard typically uses 1420.
    pub mtu: u32,

    /// Optional IPv6 address (future use).
    pub ipv6_address: Option<String>,
}

impl InterfaceConfig {
    /// Create a new config from string parameters.
    ///
    /// # Arguments
    ///
    /// * `name` - Interface name (e.g. "p2pnet0")
    /// * `address` - IPv4 address (e.g. "10.20.0.1")
    /// * `netmask` - Subnet mask (e.g. "255.255.255.0")
    /// * `mtu` - MTU value (e.g. 1420)
    pub fn new(name: &str, address: &str, netmask: &str, mtu: u32) -> Result<Self> {
        // Validate interface name
        if name.is_empty() {
            return Err(Error::InvalidInterfaceName("name is empty".into()));
        }

        // Linux limits interface names to 15 characters (IFNAMSIZ - 1)
        #[cfg(target_os = "linux")]
        if name.len() > 15 {
            return Err(Error::InvalidInterfaceName(format!(
                "name '{name}' exceeds 15 characters (Linux IFNAMSIZ limit)"
            )));
        }

        // Check for illegal characters
        for c in name.chars() {
            if !c.is_alphanumeric() && c != '-' && c != '_' {
                return Err(Error::InvalidInterfaceName(format!(
                    "name '{name}' contains illegal character '{c}'"
                )));
            }
        }

        let address: Ipv4Addr = address
            .parse()
            .map_err(|_| Error::InvalidIpAddress(address.to_string()))?;

        let netmask: Ipv4Addr = netmask
            .parse()
            .map_err(|_| Error::InvalidIpAddress(netmask.to_string()))?;

        // Validate MTU
        if mtu < 576 {
            return Err(Error::Platform(format!(
                "MTU {mtu} is too small (minimum 576 for IPv4)"
            )));
        }
        if mtu > 65535 {
            return Err(Error::Platform(format!(
                "MTU {mtu} exceeds maximum (65535)"
            )));
        }

        Ok(Self {
            name: name.to_string(),
            address,
            netmask,
            gateway: None,
            mtu,
            ipv6_address: None,
        })
    }

    /// Set the gateway address.
    pub fn with_gateway(mut self, gateway: &str) -> Result<Self> {
        self.gateway = Some(
            gateway
                .parse()
                .map_err(|_| Error::InvalidIpAddress(gateway.to_string()))?,
        );
        Ok(self)
    }

    /// Set the IPv6 address.
    pub fn with_ipv6(mut self, addr: &str) -> Self {
        self.ipv6_address = Some(addr.to_string());
        self
    }

    /// Calculate the CIDR prefix length from the netmask.
    pub fn prefix_len(&self) -> u8 {
        let bits = u32::from(self.netmask);
        bits.count_ones() as u8
    }

    /// Get the network address (address & netmask).
    pub fn network_address(&self) -> Ipv4Addr {
        let addr = u32::from(self.address);
        let mask = u32::from(self.netmask);
        Ipv4Addr::from(addr & mask)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_config_creation() {
        let config = InterfaceConfig::new("p2pnet0", "10.20.0.1", "255.255.255.0", 1420).unwrap();
        assert_eq!(config.name, "p2pnet0");
        assert_eq!(config.address, Ipv4Addr::new(10, 20, 0, 1));
        assert_eq!(config.netmask, Ipv4Addr::new(255, 255, 255, 0));
        assert_eq!(config.mtu, 1420);
    }

    #[test]
    fn test_prefix_len() {
        let config = InterfaceConfig::new("p2pnet0", "10.20.0.1", "255.255.255.0", 1420).unwrap();
        assert_eq!(config.prefix_len(), 24);
    }

    #[test]
    fn test_network_address() {
        let config = InterfaceConfig::new("p2pnet0", "10.20.0.5", "255.255.255.0", 1420).unwrap();
        assert_eq!(config.network_address(), Ipv4Addr::new(10, 20, 0, 0));
    }

    #[test]
    fn test_invalid_name_empty() {
        assert!(InterfaceConfig::new("", "10.20.0.1", "255.255.255.0", 1420).is_err());
    }

    #[test]
    fn test_invalid_name_chars() {
        assert!(InterfaceConfig::new("p2p net", "10.20.0.1", "255.255.255.0", 1420).is_err());
        assert!(InterfaceConfig::new("p2p@net", "10.20.0.1", "255.255.255.0", 1420).is_err());
    }

    #[test]
    fn test_invalid_ip() {
        assert!(InterfaceConfig::new("p2pnet0", "invalid", "255.255.255.0", 1420).is_err());
        assert!(InterfaceConfig::new("p2pnet0", "10.20.0.1", "invalid", 1420).is_err());
    }

    #[test]
    fn test_invalid_mtu() {
        assert!(InterfaceConfig::new("p2pnet0", "10.20.0.1", "255.255.255.0", 100).is_err());
        assert!(InterfaceConfig::new("p2pnet0", "10.20.0.1", "255.255.255.0", 99999).is_err());
    }

    #[test]
    fn test_with_gateway() {
        let config = InterfaceConfig::new("p2pnet0", "10.20.0.1", "255.255.255.0", 1420)
            .unwrap()
            .with_gateway("10.20.0.254")
            .unwrap();
        assert_eq!(config.gateway, Some(Ipv4Addr::new(10, 20, 0, 254)));
    }
}
