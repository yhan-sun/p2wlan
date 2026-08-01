/// Identity key for the relay peer table: `(network_id, node_id)`.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct NetworkNodeKey {
    pub network_id: String,
    pub node_id: String,
}

impl NetworkNodeKey {
    pub fn new(network_id: String, node_id: String) -> Self {
        Self {
            network_id,
            node_id,
        }
    }
}

impl std::fmt::Display for NetworkNodeKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}/{}", self.network_id, self.node_id)
    }
}

/// Authenticated peer context stored alongside each connection.
#[derive(Debug, Clone)]
pub struct AuthenticatedPeer {
    pub network_id: String,
    pub device_id: String,
    pub node_id: String,
    pub audience: String,
    pub region: String,
    pub ticket_expiry: Option<i64>,
    pub kid: String,
}

// ============================================================
// Tests
// ============================================================
