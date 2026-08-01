//! Relay ticket verification and authenticated register frame.
//!
//! ## Auth Register Frame (MSG_AUTH_REGISTER = 0x09)
//!
//! Payload layout (strict binary):
//!
//! ```text
//! u8   node_id_len         (1..255)
//! byte node_id[node_id_len] (valid UTF-8)
//! u16  ticket_len          (big-endian, 1..8192)
//! byte ticket[ticket_len]  (compact JWT)
//! ```
//!
//! ## Network binding
//!
//! The relay peer table uses `(network_id, node_id)` as the identity key.
//! Different networks never see each other. Same node_id in different
//! networks can coexist independently.

use std::collections::HashMap;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use ed25519_dalek::VerifyingKey;
use jsonwebtoken::{decode_header, Algorithm, DecodingKey, TokenData, Validation};
use serde::{Deserialize, Serialize};
use tracing::warn;
use zeroize::Zeroize;

use crate::error::{RelayError, RelayErrorCode};

// ============================================================
// Constants
// ============================================================

/// New Auth Register message type.
pub const MSG_AUTH_REGISTER: u8 = 0x09;

/// Maximum ticket length (compact JWT, conservative 8 KiB upper bound).
pub const MAX_TICKET_LEN: usize = 8192;

/// Default clock skew for ticket validation.
pub const DEFAULT_CLOCK_SKEW: Duration = Duration::from_secs(30);

/// Required JWT typ header value.
const JWT_TYP: &str = "p2wlan-relay+jwt";

/// Required issuer.
const JWT_ISSUER: &str = "p2wlan-control";

/// Relay protocol version embedded in tickets.
pub const RELAY_PROTOCOL_VERSION: u64 = 1;

// ============================================================
// Auth error codes (extend RelayErrorCode)
// ============================================================

/// Stable wire error codes for A2 authentication.
impl RelayErrorCode {
    pub const AUTH_REQUIRED: u16 = 4011;
    pub const INVALID_TICKET: u16 = 4012;
    pub const TICKET_EXPIRED: u16 = 4013;
    pub const AUDIENCE_MISMATCH: u16 = 4014;
    pub const IDENTITY_MISMATCH: u16 = 4015;
    pub const NETWORK_MISMATCH: u16 = 4016;
    pub const TICKET_NOT_YET_VALID: u16 = 4017;
    pub const UNKNOWN_TICKET_KEY: u16 = 4018;
}

// ============================================================
// Relay ticket claims (matching Go schema)
// ============================================================

include!("auth/claims.rs");
include!("auth/verifier.rs");
include!("auth/frame.rs");
include!("auth/identity.rs");

#[cfg(test)]
mod tests {
    include!("auth/tests.rs");
}
