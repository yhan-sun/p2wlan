//! STUN protocol implementation (RFC 5389).
//!
//! ## Overview
//!
//! - **Message types**: Binding Request (0x0001), Binding Response (0x0101),
//!   Binding Error Response (0x0111)
//! - **Attributes**: XOR-MAPPED-ADDRESS, MAPPED-ADDRESS, CHANGE-REQUEST,
//!   ERROR-CODE, SOFTWARE, FINGERPRINT
//! - **Encode/decode**: Full wire format with 4-byte attribute padding
//! - **FINGERPRINT**: CRC-32 based message integrity
//! - **XOR-MAPPED-ADDRESS**: XOR'd with magic cookie to prevent translation
//!   by NATs that rewrite IP addresses

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use crate::error::{NatError, Result};

// ============================================================
// Constants
// ============================================================

/// STUN magic cookie (RFC 5389 Section 6).
pub const MAGIC_COOKIE: u32 = 0x2112A442;

/// Transaction ID length in bytes (96 bits).
pub const TRANSACTION_ID_LEN: usize = 12;

/// STUN header size in bytes (20 bytes).
pub const STUN_HEADER_SIZE: usize = 20;

/// Magic cookie as bytes (big-endian).
pub const MAGIC_COOKIE_BYTES: [u8; 4] = 0x2112A442u32.to_be_bytes();

// Message types
pub const BINDING_REQUEST: u16 = 0x0001;
pub const BINDING_RESPONSE: u16 = 0x0101;
pub const BINDING_ERROR_RESPONSE: u16 = 0x0111;

// Attribute types
pub const ATTR_MAPPED_ADDRESS: u16 = 0x0001;
pub const ATTR_CHANGE_REQUEST: u16 = 0x0003;
pub const ATTR_ERROR_CODE: u16 = 0x0009;
pub const ATTR_REALM: u16 = 0x0014;
pub const ATTR_NONCE: u16 = 0x0015;
pub const ATTR_XOR_MAPPED_ADDRESS: u16 = 0x0020;
pub const ATTR_SOFTWARE: u16 = 0x8022;
pub const ATTR_ALTERNATE_SERVER: u16 = 0x8023;
pub const ATTR_FINGERPRINT: u16 = 0x8028;

/// Address family for IPv4.
const FAMILY_IPV4: u8 = 0x01;
/// Address family for IPv6.
const FAMILY_IPV6: u8 = 0x02;

/// XOR mask used in FINGERPRINT computation.
const FINGERPRINT_XOR: u32 = 0x5354554E;

// ============================================================
// CRC-32
// ============================================================

include!("stun/address.rs");
include!("stun/attribute.rs");
include!("stun/message.rs");

#[cfg(test)]
mod tests {
    include!("stun/tests.rs");
}
