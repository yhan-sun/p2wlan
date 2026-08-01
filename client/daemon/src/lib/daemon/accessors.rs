impl Daemon {
    /// Get a reference to the peer manager.
    pub fn peers(&self) -> &PeerManager {
        &self.peers
    }

    /// Get a reference to the port mapping manager.
    pub fn port_mappings(&self) -> &PortMappingManager {
        &self.port_mappings
    }

    /// Get a reference to the DNS resolver.
    pub fn dns(&self) -> &DnsResolver {
        &self.dns
    }

    /// Get the configuration.
    pub fn config(&self) -> &Config {
        &self.config
    }

    /// Check whether traffic is allowed by ACL.
    pub async fn check_acl(&self, src: &str, dst: &str, proto: &str, port: u16) -> bool {
        self.acl.read().await.check(src, dst, proto, port)
    }
}
