//! # p2pnet-relay
//!
//! DERP-like relay system for P2PNet.
//!
//! ## Overview
//!
//! When direct P2P connection fails (symmetric NAT, restrictive firewall),
//! the relay server acts as a fallback. The relay only forwards encrypted
//! data and cannot decrypt it.
//!
//! ## Architecture
//!
//! ```text
//! ┌──────────────┐     ┌───────────────────┐     ┌──────────────┐
//! │   Node A     │────▶│   Relay Server    │◀────│   Node B     │
//! │ (node-id-A)  │     │  (TCP, frame-based)│     │ (node-id-B)  │
//! └──────────────┘     └───────────────────┘     └──────────────┘
//! ```
//!
//! ## Protocol
//!
//! See [`protocol`] module for the wire format.
//!
//! ## Usage
//!
//! ```no_run
//! use p2pnet_relay::client::RelayClient;
//! use p2pnet_relay::server::RelayServer;
//!
//! # async fn example() -> Result<(), Box<dyn std::error::Error>> {
//! // Start a relay server (for testing)
//! let server = RelayServer::start("0.0.0.0:8080").await?;
//!
//! // Clients connect and register
//! let (mut alice, mut rx_a) = RelayClient::connect("127.0.0.1:8080", "alice").await?;
//! let (mut bob, mut rx_b) = RelayClient::connect("127.0.0.1:8080", "bob").await?;
//!
//! // Alice sends encrypted data to Bob via relay
//! alice.send_data("bob", &[0x01, 0x02, 0x03]).await?;
//!
//! // Bob receives it
//! let msg = rx_b.recv().await.unwrap();
//! assert_eq!(msg.from_node, "alice");
//! # Ok(())
//! # }
//! ```

pub mod client;
pub mod error;
pub mod protocol;
pub mod server;

// Re-export key types for convenience
pub use client::{RelayClient, RelayMessage};
pub use error::{RelayError, Result as RelayResult};
pub use protocol::{Frame, MAX_PAYLOAD, VERSION as PROTOCOL_VERSION};
pub use server::RelayServer;

// ============================================================
// Legacy types (kept for backward compatibility with Phase 1-3 code)
// ============================================================

/// Relay server configuration.
#[derive(Debug, Clone)]
pub struct RelayConfig {
    /// Relay server address (e.g. "127.0.0.1:8080").
    pub url: String,
    /// Optional authentication token.
    pub auth_token: Option<String>,
    /// Maximum relay data rate (bytes/sec, 0 = unlimited).
    pub max_rate: u64,
}

impl RelayConfig {
    /// Create a new relay config.
    pub fn new(url: &str) -> Self {
        Self {
            url: url.to_string(),
            auth_token: None,
            max_rate: 0,
        }
    }
}

/// A relay connection to a specific peer.
#[derive(Debug)]
pub struct RelayConnection {
    /// The peer's node ID.
    pub peer_id: String,
    /// The relay server endpoint.
    pub relay_endpoint: String,
    /// Whether the connection is active.
    pub active: bool,
}

impl RelayConnection {
    /// Create a new relay connection.
    pub fn new(peer_id: &str, relay_endpoint: &str) -> Self {
        Self {
            peer_id: peer_id.to_string(),
            relay_endpoint: relay_endpoint.to_string(),
            active: false,
        }
    }

    /// Activate the connection.
    pub fn activate(&mut self) {
        self.active = true;
    }

    /// Close the connection.
    pub fn close(&mut self) {
        self.active = false;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_relay_config() {
        let config = RelayConfig::new("https://relay.example.com:443");
        assert_eq!(config.url, "https://relay.example.com:443");
        assert!(config.auth_token.is_none());
    }

    #[test]
    fn test_relay_connection_lifecycle() {
        let mut conn = RelayConnection::new("peer123", "relay:443");
        assert!(!conn.active);

        conn.activate();
        assert!(conn.active);

        conn.close();
        assert!(!conn.active);
    }
}
