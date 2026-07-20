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
//! if let p2pnet_relay::RelayMessage::Data { from_node, .. } = msg {
//!     assert_eq!(from_node, "alice");
//! }
//! # Ok(())
//! # }
//! ```

pub mod auth;
pub mod client;
pub mod error;
pub mod protocol;
pub mod server;
pub mod tls;

// Re-export key types for convenience
pub use auth::{
    decode_auth_register, encode_auth_register, AuthenticatedPeer, NetworkNodeKey, TicketVerifier,
    VerifiedTicket, MAX_TICKET_LEN, MSG_AUTH_REGISTER, RELAY_PROTOCOL_VERSION,
};
pub use client::{RelayClient, RelayMessage};
pub use error::{RelayError, RelayErrorCode, Result as RelayResult};
pub use protocol::{Frame, MAX_PAYLOAD, VERSION as PROTOCOL_VERSION};
pub use server::RelayServer;

use std::path::PathBuf;
use std::time::Duration;

/// Relay server limits configuration.
#[derive(Debug, Clone)]
pub struct RelayServerConfig {
    pub outbound_queue_capacity: usize,
    pub register_timeout: Duration,
    pub idle_timeout: Duration,
    pub max_connections: usize,
    pub max_frame_payload: usize,
    /// Whether to require authenticated registration (default: true for security mode).
    pub require_authentication: bool,
    /// Whether to allow legacy unauthenticated MSG_REGISTER (default: false).
    pub allow_legacy_unauthenticated: bool,
    /// Path to TLS certificate chain PEM file (empty = no TLS).
    pub tls_cert_chain_path: Option<PathBuf>,
    /// Path to TLS private key PEM file (empty = no TLS).
    pub tls_private_key_path: Option<PathBuf>,
    /// Whether to allow plaintext TCP (default: false).
    pub allow_insecure_plaintext: bool,
    /// JSON map of kid -> hex Ed25519 public key for ticket verification.
    pub ticket_keyring_json: Option<String>,
    /// Expected audience in relay tickets (required when auth is enabled).
    pub ticket_audience: Option<String>,
    /// Expected region in relay tickets (required when auth is enabled).
    pub ticket_region: Option<String>,
}

impl Default for RelayServerConfig {
    fn default() -> Self {
        Self {
            outbound_queue_capacity: 128,
            register_timeout: Duration::from_secs(5),
            idle_timeout: Duration::from_secs(30),
            max_connections: 1000,
            max_frame_payload: 65535,
            require_authentication: true,
            allow_legacy_unauthenticated: false,
            tls_cert_chain_path: None,
            tls_private_key_path: None,
            allow_insecure_plaintext: false,
            ticket_keyring_json: None,
            ticket_audience: None,
            ticket_region: None,
        }
    }
}

impl RelayServerConfig {
    /// Build a TicketVerifier from config fields.
    pub fn build_verifier(&self) -> std::result::Result<TicketVerifier, String> {
        let keys: std::collections::HashMap<String, String> = match &self.ticket_keyring_json {
            Some(json) => {
                serde_json::from_str(json).map_err(|e| format!("ticket_keyring_json: {e}"))?
            }
            None => {
                // Try env var as fallback
                let env_raw = std::env::var("RELAY_TICKET_KEYRING_JSON").unwrap_or_default();
                if env_raw.is_empty() {
                    return Err(
                        "ticket_keyring_json is required when authentication is enabled".into(),
                    );
                }
                serde_json::from_str(&env_raw)
                    .map_err(|e| format!("RELAY_TICKET_KEYRING_JSON env: {e}"))?
            }
        };
        let audience = self.ticket_audience.as_deref().unwrap_or("").to_string();
        let region = self.ticket_region.as_deref().unwrap_or("").to_string();
        if audience.is_empty() {
            return Err("ticket_audience is required when authentication is enabled".into());
        }
        if region.is_empty() {
            return Err("ticket_region is required when authentication is enabled".into());
        }
        crate::auth::TicketVerifier::new(keys, crate::auth::DEFAULT_CLOCK_SKEW, audience, region)
    }

    pub fn validate(&self) -> std::result::Result<(), error::RelayError> {
        if self.outbound_queue_capacity == 0 {
            return Err(error::RelayError::Protocol(
                "outbound_queue_capacity must be > 0".into(),
            ));
        }
        if self.register_timeout.is_zero() {
            return Err(error::RelayError::Protocol(
                "register_timeout must be > 0".into(),
            ));
        }
        if self.idle_timeout.is_zero() {
            return Err(error::RelayError::Protocol(
                "idle_timeout must be > 0".into(),
            ));
        }
        if self.max_connections == 0 {
            return Err(error::RelayError::Protocol(
                "max_connections must be > 0".into(),
            ));
        }
        if self.max_frame_payload == 0 || self.max_frame_payload > 65535 {
            return Err(error::RelayError::Protocol(
                "max_frame_payload must be between 1 and 65535".into(),
            ));
        }
        // TLS checks
        let has_tls = self.tls_cert_chain_path.is_some() || self.tls_private_key_path.is_some();
        if has_tls {
            if self.tls_cert_chain_path.is_none() {
                return Err(error::RelayError::Protocol(
                    "tls_cert_chain_path is required when TLS is configured".into(),
                ));
            }
            if self.tls_private_key_path.is_none() {
                return Err(error::RelayError::Protocol(
                    "tls_private_key_path is required when TLS is configured".into(),
                ));
            }
        }
        if !has_tls && !self.allow_insecure_plaintext {
            return Err(error::RelayError::Protocol(
                "TLS must be configured or allow_insecure_plaintext must be set (development only)"
                    .into(),
            ));
        }
        Ok(())
    }
}

/// Relay client limits configuration.
#[derive(Debug, Clone)]
pub struct RelayClientConfig {
    pub cmd_queue_capacity: usize,
    pub inbound_queue_capacity: usize,
    pub register_timeout: Duration,
    pub idle_timeout: Duration,
    pub keepalive_interval: Duration,
    pub max_frame_payload: usize,
    /// TLS server name for certificate verification (required for tls:// endpoints).
    pub tls_server_name: Option<String>,
    /// Path to additional CA certificate bundle for self-hosted relays.
    pub tls_ca_cert_path: Option<PathBuf>,
    /// Whether to allow plaintext TCP (default: false).
    pub allow_insecure_plaintext: bool,
    /// Relay ticket JWT for authenticated registration.
    pub relay_ticket: Option<String>,
}

impl Default for RelayClientConfig {
    fn default() -> Self {
        Self {
            cmd_queue_capacity: 128,
            inbound_queue_capacity: 128,
            register_timeout: Duration::from_secs(5),
            idle_timeout: Duration::from_secs(30),
            keepalive_interval: Duration::from_secs(10),
            max_frame_payload: 65535,
            tls_server_name: None,
            tls_ca_cert_path: None,
            allow_insecure_plaintext: false,
            relay_ticket: None,
        }
    }
}

impl RelayClientConfig {
    pub fn validate(&self) -> std::result::Result<(), error::RelayError> {
        if self.cmd_queue_capacity == 0 {
            return Err(error::RelayError::Protocol(
                "cmd_queue_capacity must be > 0".into(),
            ));
        }
        if self.inbound_queue_capacity == 0 {
            return Err(error::RelayError::Protocol(
                "inbound_queue_capacity must be > 0".into(),
            ));
        }
        if self.register_timeout.is_zero() {
            return Err(error::RelayError::Protocol(
                "register_timeout must be > 0".into(),
            ));
        }
        if self.idle_timeout.is_zero() {
            return Err(error::RelayError::Protocol(
                "idle_timeout must be > 0".into(),
            ));
        }
        if self.keepalive_interval.is_zero() {
            return Err(error::RelayError::Protocol(
                "keepalive_interval must be > 0".into(),
            ));
        }
        if self.keepalive_interval >= self.idle_timeout {
            return Err(error::RelayError::Protocol(
                "keepalive_interval must be strictly less than idle_timeout".into(),
            ));
        }
        if self.max_frame_payload == 0 || self.max_frame_payload > 65535 {
            return Err(error::RelayError::Protocol(
                "max_frame_payload must be between 1 and 65535".into(),
            ));
        }
        Ok(())
    }
}

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
