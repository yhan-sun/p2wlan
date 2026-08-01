/// Claims extracted from a verified relay ticket.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RelayTicketClaims {
    /// Must equal `sub`.
    #[serde(rename = "device_id")]
    pub device_id: String,
    /// Network the device belongs to.
    #[serde(rename = "network_id")]
    pub network_id: String,
    /// Node ID (usually equals device_id).
    #[serde(rename = "node_id")]
    pub node_id: String,
    /// Target relay region.
    #[serde(rename = "relay_region")]
    pub relay_region: String,
    /// Relay protocol version.
    #[serde(rename = "relay_protocol")]
    pub relay_protocol: u64,

    // Standard JWT fields
    #[serde(rename = "iss")]
    pub iss: String,
    #[serde(rename = "sub")]
    pub sub: String,
    #[serde(rename = "aud")]
    pub aud: serde_json::Value, // Can be string or array
    #[serde(rename = "iat")]
    pub iat: Option<i64>,
    #[serde(rename = "nbf")]
    pub nbf: Option<i64>,
    #[serde(rename = "exp")]
    pub exp: Option<i64>,
    #[serde(rename = "jti")]
    pub jti: Option<String>,
}

impl Zeroize for RelayTicketClaims {
    fn zeroize(&mut self) {
        self.device_id.zeroize();
        self.network_id.zeroize();
        self.node_id.zeroize();
    }
}

impl Drop for RelayTicketClaims {
    fn drop(&mut self) {
        self.zeroize();
    }
}

/// Secure wrapper that zeroizes claims on drop.
#[derive(Debug)]
pub struct VerifiedTicket {
    pub claims: RelayTicketClaims,
    pub kid: String,
}

impl Drop for VerifiedTicket {
    fn drop(&mut self) {
        self.claims.zeroize();
    }
}

// ============================================================
// Ticket verifier
// ============================================================
