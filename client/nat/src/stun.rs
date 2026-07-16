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

/// Compute standard CRC-32 (same polynomial as Ethernet/PNG/zlib).
///
/// Test vector: `crc32(b"123456789") == 0xCBF43926`
pub fn crc32(data: &[u8]) -> u32 {
    let mut crc: u32 = 0xFFFFFFFF;
    for &byte in data {
        crc ^= byte as u32;
        for _ in 0..8 {
            if crc & 1 != 0 {
                crc = (crc >> 1) ^ 0xEDB88320;
            } else {
                crc >>= 1;
            }
        }
    }
    !crc
}

/// Compute the STUN FINGERPRINT value for the given message bytes.
///
/// FINGERPRINT = CRC-32(message) XOR 0x5354554E
pub fn compute_fingerprint(data: &[u8]) -> u32 {
    crc32(data) ^ FINGERPRINT_XOR
}

// ============================================================
// Attribute Encoding/Decoding Helpers
// ============================================================

/// Encode a SocketAddr as XOR-MAPPED-ADDRESS attribute value.
pub fn encode_xor_mapped_address(addr: SocketAddr, transaction_id: &[u8; 12]) -> Vec<u8> {
    let port = addr.port();
    let x_port = port ^ ((MAGIC_COOKIE >> 16) as u16);

    let mut buf = Vec::new();
    buf.push(0x00); // Reserved

    match addr.ip() {
        IpAddr::V4(ipv4) => {
            buf.push(FAMILY_IPV4);
            buf.extend_from_slice(&x_port.to_be_bytes());
            let octets = ipv4.octets();
            let cookie = MAGIC_COOKIE.to_be_bytes();
            for i in 0..4 {
                buf.push(octets[i] ^ cookie[i]);
            }
        }
        IpAddr::V6(ipv6) => {
            buf.push(FAMILY_IPV6);
            buf.extend_from_slice(&x_port.to_be_bytes());
            let octets = ipv6.octets();
            let mut key = [0u8; 16];
            key[..4].copy_from_slice(&MAGIC_COOKIE_BYTES);
            key[4..].copy_from_slice(transaction_id);
            for i in 0..16 {
                buf.push(octets[i] ^ key[i]);
            }
        }
    }
    buf
}

/// Decode an XOR-MAPPED-ADDRESS attribute value.
pub fn decode_xor_mapped_address(data: &[u8], transaction_id: &[u8; 12]) -> Result<SocketAddr> {
    if data.len() < 8 {
        return Err(NatError::InvalidAttribute(format!(
            "XOR-MAPPED-ADDRESS too short: {} bytes",
            data.len()
        )));
    }

    let family = data[1];
    let x_port = u16::from_be_bytes([data[2], data[3]]);
    let port = x_port ^ ((MAGIC_COOKIE >> 16) as u16);

    match family {
        FAMILY_IPV4 => {
            if data.len() < 8 {
                return Err(NatError::InvalidAttribute(
                    "XOR-MAPPED-ADDRESS IPv4 too short".into(),
                ));
            }
            let cookie = MAGIC_COOKIE.to_be_bytes();
            let octets = [
                data[4] ^ cookie[0],
                data[5] ^ cookie[1],
                data[6] ^ cookie[2],
                data[7] ^ cookie[3],
            ];
            Ok(SocketAddr::new(IpAddr::V4(Ipv4Addr::from(octets)), port))
        }
        FAMILY_IPV6 => {
            if data.len() < 20 {
                return Err(NatError::InvalidAttribute(
                    "XOR-MAPPED-ADDRESS IPv6 too short".into(),
                ));
            }
            let mut key = [0u8; 16];
            key[..4].copy_from_slice(&MAGIC_COOKIE_BYTES);
            key[4..].copy_from_slice(transaction_id);
            let mut octets = [0u8; 16];
            for i in 0..16 {
                octets[i] = data[4 + i] ^ key[i];
            }
            Ok(SocketAddr::new(IpAddr::V6(Ipv6Addr::from(octets)), port))
        }
        _ => Err(NatError::InvalidAttribute(format!(
            "unknown family: {family}"
        ))),
    }
}

/// Encode a SocketAddr as MAPPED-ADDRESS attribute value.
pub fn encode_mapped_address(addr: SocketAddr) -> Vec<u8> {
    let mut buf = Vec::new();
    buf.push(0x00); // Reserved

    match addr.ip() {
        IpAddr::V4(ipv4) => {
            buf.push(FAMILY_IPV4);
            buf.extend_from_slice(&addr.port().to_be_bytes());
            buf.extend_from_slice(&ipv4.octets());
        }
        IpAddr::V6(ipv6) => {
            buf.push(FAMILY_IPV6);
            buf.extend_from_slice(&addr.port().to_be_bytes());
            buf.extend_from_slice(&ipv6.octets());
        }
    }
    buf
}

/// Decode a MAPPED-ADDRESS attribute value.
pub fn decode_mapped_address(data: &[u8]) -> Result<SocketAddr> {
    if data.len() < 8 {
        return Err(NatError::InvalidAttribute(format!(
            "MAPPED-ADDRESS too short: {} bytes",
            data.len()
        )));
    }

    let family = data[1];
    let port = u16::from_be_bytes([data[2], data[3]]);

    match family {
        FAMILY_IPV4 => {
            if data.len() < 8 {
                return Err(NatError::InvalidAttribute(
                    "MAPPED-ADDRESS IPv4 too short".into(),
                ));
            }
            let ip = Ipv4Addr::new(data[4], data[5], data[6], data[7]);
            Ok(SocketAddr::new(IpAddr::V4(ip), port))
        }
        FAMILY_IPV6 => {
            if data.len() < 20 {
                return Err(NatError::InvalidAttribute(
                    "MAPPED-ADDRESS IPv6 too short".into(),
                ));
            }
            let mut octets = [0u8; 16];
            octets.copy_from_slice(&data[4..20]);
            Ok(SocketAddr::new(IpAddr::V6(Ipv6Addr::from(octets)), port))
        }
        _ => Err(NatError::InvalidAttribute(format!(
            "unknown family: {family}"
        ))),
    }
}

// ============================================================
// StunAttribute
// ============================================================

/// A STUN attribute (parsed).
#[derive(Debug, Clone)]
pub enum StunAttribute {
    /// MAPPED-ADDRESS (0x0001): the reflexive address.
    MappedAddress(SocketAddr),
    /// XOR-MAPPED-ADDRESS (0x0020): the reflexive address (XOR'd).
    XorMappedAddress(SocketAddr),
    /// CHANGE-REQUEST (0x0003): ask server to change IP/port in response.
    ChangeRequest { change_ip: bool, change_port: bool },
    /// ERROR-CODE (0x0009): error response code and reason.
    ErrorCode { code: u16, reason: String },
    /// SOFTWARE (0x8022): software description.
    Software(String),
    /// FINGERPRINT (0x8028): CRC-32 integrity check.
    Fingerprint(u32),
    /// Any other attribute we don't specifically parse.
    Other { attr_type: u16, value: Vec<u8> },
}

impl StunAttribute {
    /// Encode this attribute into (type, value) bytes.
    /// `transaction_id` is needed for XOR-MAPPED-ADDRESS encoding.
    pub fn encode(&self, transaction_id: &[u8; 12]) -> (u16, Vec<u8>) {
        match self {
            StunAttribute::MappedAddress(addr) => {
                (ATTR_MAPPED_ADDRESS, encode_mapped_address(*addr))
            }
            StunAttribute::XorMappedAddress(addr) => (
                ATTR_XOR_MAPPED_ADDRESS,
                encode_xor_mapped_address(*addr, transaction_id),
            ),
            StunAttribute::ChangeRequest {
                change_ip,
                change_port,
            } => {
                let mut flags: u32 = 0;
                if *change_ip {
                    flags |= 0x04;
                }
                if *change_port {
                    flags |= 0x02;
                }
                (ATTR_CHANGE_REQUEST, flags.to_be_bytes().to_vec())
            }
            StunAttribute::ErrorCode { code, reason } => {
                let class = (*code / 100) as u8;
                let number = (*code % 100) as u8;
                let mut buf = vec![0x00, 0x00, 0x00, class, number];
                buf.extend_from_slice(reason.as_bytes());
                (ATTR_ERROR_CODE, buf)
            }
            StunAttribute::Software(s) => (ATTR_SOFTWARE, s.as_bytes().to_vec()),
            StunAttribute::Fingerprint(val) => (ATTR_FINGERPRINT, val.to_be_bytes().to_vec()),
            StunAttribute::Other { attr_type, value } => (*attr_type, value.clone()),
        }
    }

    /// Decode an attribute from wire format.
    pub fn decode(attr_type: u16, data: &[u8], transaction_id: &[u8; 12]) -> Result<Self> {
        match attr_type {
            ATTR_MAPPED_ADDRESS => Ok(StunAttribute::MappedAddress(decode_mapped_address(data)?)),
            ATTR_XOR_MAPPED_ADDRESS => Ok(StunAttribute::XorMappedAddress(
                decode_xor_mapped_address(data, transaction_id)?,
            )),
            ATTR_CHANGE_REQUEST => {
                if data.len() < 4 {
                    return Err(NatError::InvalidAttribute(
                        "CHANGE-REQUEST too short".into(),
                    ));
                }
                let flags = u32::from_be_bytes([data[0], data[1], data[2], data[3]]);
                Ok(StunAttribute::ChangeRequest {
                    change_ip: flags & 0x04 != 0,
                    change_port: flags & 0x02 != 0,
                })
            }
            ATTR_ERROR_CODE => {
                if data.len() < 5 {
                    return Err(NatError::InvalidAttribute("ERROR-CODE too short".into()));
                }
                let class = data[3] as u16;
                let number = data[4] as u16;
                let code = class * 100 + number;
                let reason = if data.len() > 5 {
                    String::from_utf8_lossy(&data[5..]).to_string()
                } else {
                    String::new()
                };
                Ok(StunAttribute::ErrorCode { code, reason })
            }
            ATTR_SOFTWARE => Ok(StunAttribute::Software(
                String::from_utf8_lossy(data).to_string(),
            )),
            ATTR_FINGERPRINT => {
                if data.len() < 4 {
                    return Err(NatError::InvalidAttribute("FINGERPRINT too short".into()));
                }
                let val = u32::from_be_bytes([data[0], data[1], data[2], data[3]]);
                Ok(StunAttribute::Fingerprint(val))
            }
            _ => Ok(StunAttribute::Other {
                attr_type,
                value: data.to_vec(),
            }),
        }
    }
}

// ============================================================
// StunMessage
// ============================================================

/// A complete STUN message (header + attributes).
#[derive(Debug, Clone)]
pub struct StunMessage {
    /// Message type (e.g. BINDING_REQUEST, BINDING_RESPONSE).
    pub msg_type: u16,
    /// 12-byte transaction ID.
    pub transaction_id: [u8; 12],
    /// Parsed attributes.
    pub attributes: Vec<StunAttribute>,
    /// Raw bytes of the entire message (set after decode or encode).
    pub raw: Vec<u8>,
}

impl StunMessage {
    /// Create a new STUN message with a random transaction ID.
    pub fn new(msg_type: u16) -> Self {
        let mut transaction_id = [0u8; 12];
        rand::thread_rng().fill_bytes(&mut transaction_id);

        Self {
            msg_type,
            transaction_id,
            attributes: Vec::new(),
            raw: Vec::new(),
        }
    }

    /// Create a new STUN message with a specific transaction ID.
    pub fn with_transaction_id(msg_type: u16, transaction_id: [u8; 12]) -> Self {
        Self {
            msg_type,
            transaction_id,
            attributes: Vec::new(),
            raw: Vec::new(),
        }
    }

    /// Create a Binding Request message.
    pub fn binding_request() -> Self {
        Self::new(BINDING_REQUEST)
    }

    /// Add an attribute.
    pub fn add_attribute(&mut self, attr: StunAttribute) {
        self.attributes.push(attr);
    }

    /// Encode this message to wire format.
    pub fn encode(&mut self) -> Vec<u8> {
        // Encode all attributes into a buffer
        let mut attr_buf = Vec::new();
        for attr in &self.attributes {
            let (attr_type, value) = attr.encode(&self.transaction_id);
            attr_buf.extend_from_slice(&attr_type.to_be_bytes());
            attr_buf.extend_from_slice(&(value.len() as u16).to_be_bytes());
            attr_buf.extend_from_slice(&value);
            // Pad to 4-byte boundary
            let padding = (4 - (value.len() % 4)) % 4;
            for _ in 0..padding {
                attr_buf.push(0);
            }
        }

        // Build header
        let mut buf = Vec::with_capacity(STUN_HEADER_SIZE + attr_buf.len());
        buf.extend_from_slice(&self.msg_type.to_be_bytes());
        buf.extend_from_slice(&(attr_buf.len() as u16).to_be_bytes());
        buf.extend_from_slice(&MAGIC_COOKIE_BYTES);
        buf.extend_from_slice(&self.transaction_id);
        buf.extend_from_slice(&attr_buf);

        self.raw = buf.clone();
        buf
    }

    /// Encode with FINGERPRINT attribute appended.
    pub fn encode_with_fingerprint(&mut self) -> Vec<u8> {
        // First encode without fingerprint
        let buf_no_fp = self.encode();

        // Compute fingerprint over the message (header + attributes, without FP)
        let fp = compute_fingerprint(&buf_no_fp);

        // Append FINGERPRINT attribute
        let mut buf = buf_no_fp;
        buf.extend_from_slice(&ATTR_FINGERPRINT.to_be_bytes());
        buf.extend_from_slice(&4u16.to_be_bytes()); // length = 4
        buf.extend_from_slice(&fp.to_be_bytes());

        // Update message length in header (original length + 8 bytes for FP attribute)
        let new_len = (u16::from_be_bytes([buf[2], buf[3]]) + 8).to_be_bytes();
        buf[2] = new_len[0];
        buf[3] = new_len[1];

        self.raw = buf.clone();
        buf
    }

    /// Decode a STUN message from wire format.
    pub fn decode(data: &[u8]) -> Result<Self> {
        if data.len() < STUN_HEADER_SIZE {
            return Err(NatError::InvalidStunMessage(format!(
                "message too short: {} bytes (need at least {})",
                data.len(),
                STUN_HEADER_SIZE
            )));
        }

        // Check first two bits are 0 (STUN message indicator)
        if data[0] & 0xC0 != 0 {
            return Err(NatError::InvalidStunMessage(
                "first two bits are not zero (not a STUN message)".into(),
            ));
        }

        let msg_type = u16::from_be_bytes([data[0], data[1]]);
        let msg_len = u16::from_be_bytes([data[2], data[3]]) as usize;
        let cookie = u32::from_be_bytes([data[4], data[5], data[6], data[7]]);

        if cookie != MAGIC_COOKIE {
            return Err(NatError::InvalidStunMessage(format!(
                "invalid magic cookie: 0x{:08X} (expected 0x{:08X})",
                cookie, MAGIC_COOKIE
            )));
        }

        let mut transaction_id = [0u8; 12];
        transaction_id.copy_from_slice(&data[8..20]);

        if data.len() < STUN_HEADER_SIZE + msg_len {
            return Err(NatError::InvalidStunMessage(format!(
                "message truncated: have {} bytes, header says {}",
                data.len(),
                STUN_HEADER_SIZE + msg_len
            )));
        }

        // Parse attributes
        let mut attributes = Vec::new();
        let mut offset = STUN_HEADER_SIZE;
        let end = STUN_HEADER_SIZE + msg_len;

        while offset + 4 <= end {
            let attr_type = u16::from_be_bytes([data[offset], data[offset + 1]]);
            let attr_len = u16::from_be_bytes([data[offset + 2], data[offset + 3]]) as usize;
            offset += 4;

            if offset + attr_len > end {
                return Err(NatError::InvalidStunMessage(format!(
                    "attribute 0x{:04X} length {} exceeds message boundary",
                    attr_type, attr_len
                )));
            }

            let attr_data = &data[offset..offset + attr_len];
            let attr = StunAttribute::decode(attr_type, attr_data, &transaction_id)?;
            attributes.push(attr);

            // Advance past padding
            offset += attr_len;
            let padding = (4 - (attr_len % 4)) % 4;
            offset += padding;
        }

        Ok(Self {
            msg_type,
            transaction_id,
            attributes,
            raw: data.to_vec(),
        })
    }

    /// Get the XOR-MAPPED-ADDRESS attribute (preferred reflexive address method).
    pub fn get_xor_mapped_address(&self) -> Option<SocketAddr> {
        for attr in &self.attributes {
            if let StunAttribute::XorMappedAddress(addr) = attr {
                return Some(*addr);
            }
        }
        None
    }

    /// Get the MAPPED-ADDRESS attribute (fallback reflexive address method).
    pub fn get_mapped_address(&self) -> Option<SocketAddr> {
        for attr in &self.attributes {
            if let StunAttribute::MappedAddress(addr) = attr {
                return Some(*addr);
            }
        }
        None
    }

    /// Get the reflexive address (XOR-MAPPED-ADDRESS preferred, MAPPED-ADDRESS fallback).
    pub fn get_reflexive_address(&self) -> Option<SocketAddr> {
        self.get_xor_mapped_address()
            .or_else(|| self.get_mapped_address())
    }

    /// Get the ERROR-CODE attribute if present.
    pub fn get_error_code(&self) -> Option<(u16, &str)> {
        for attr in &self.attributes {
            if let StunAttribute::ErrorCode { code, reason } = attr {
                return Some((*code, reason.as_str()));
            }
        }
        None
    }

    /// Verify the FINGERPRINT attribute (if present).
    pub fn verify_fingerprint(&self) -> bool {
        // Find the FINGERPRINT attribute position in raw bytes
        let fp_attr_size = 8; // 2 (type) + 2 (length) + 4 (value)
        if self.raw.len() < fp_attr_size {
            return false;
        }

        // Check if last 8 bytes are a FINGERPRINT attribute
        let fp_start = self.raw.len() - fp_attr_size;
        let attr_type = u16::from_be_bytes([self.raw[fp_start], self.raw[fp_start + 1]]);
        if attr_type != ATTR_FINGERPRINT {
            return false;
        }

        let stored_fp = u32::from_be_bytes([
            self.raw[fp_start + 4],
            self.raw[fp_start + 5],
            self.raw[fp_start + 6],
            self.raw[fp_start + 7],
        ]);

        // The FINGERPRINT was computed over the message with msg_len NOT including
        // the FINGERPRINT attribute (8 bytes: 2 type + 2 length + 4 value).
        // We must temporarily revert the header's msg_len before computing CRC.
        let mut buf = self.raw[..fp_start].to_vec();
        let msg_len = u16::from_be_bytes([buf[2], buf[3]]);
        if msg_len < 8 {
            return false;
        }
        let original_len = (msg_len - 8).to_be_bytes();
        buf[2] = original_len[0];
        buf[3] = original_len[1];

        let computed_fp = compute_fingerprint(&buf);
        stored_fp == computed_fp
    }

    /// Check if this is a Binding Response.
    pub fn is_binding_response(&self) -> bool {
        self.msg_type == BINDING_RESPONSE
    }

    /// Check if this is a Binding Error Response.
    pub fn is_error_response(&self) -> bool {
        self.msg_type == BINDING_ERROR_RESPONSE
    }
}

// Bring rand::RngCore into scope for fill_bytes
use rand::RngCore;

// ============================================================
// Tests
// ============================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_crc32_known_vector() {
        // Standard CRC-32 test vector
        assert_eq!(crc32(b"123456789"), 0xCBF43926);
    }

    #[test]
    fn test_crc32_empty() {
        assert_eq!(crc32(b""), 0x00000000);
    }

    #[test]
    fn test_fingerprint_xor() {
        // FINGERPRINT = CRC-32 XOR 0x5354554E
        let data = b"test message";
        let expected = crc32(data) ^ 0x5354554E;
        assert_eq!(compute_fingerprint(data), expected);
    }

    #[test]
    fn test_xor_mapped_address_ipv4_roundtrip() {
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)), 5678);
        let txn_id = [0xAA; 12];

        let encoded = encode_xor_mapped_address(addr, &txn_id);
        let decoded = decode_xor_mapped_address(&encoded, &txn_id).unwrap();

        assert_eq!(decoded, addr);
    }

    #[test]
    fn test_xor_mapped_address_ipv6_roundtrip() {
        let addr = SocketAddr::new(IpAddr::V6("2001:db8::1".parse().unwrap()), 9999);
        let txn_id = [0xBB; 12];

        let encoded = encode_xor_mapped_address(addr, &txn_id);
        let decoded = decode_xor_mapped_address(&encoded, &txn_id).unwrap();

        assert_eq!(decoded, addr);
    }

    #[test]
    fn test_mapped_address_ipv4_roundtrip() {
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 3478);
        let encoded = encode_mapped_address(addr);
        let decoded = decode_mapped_address(&encoded).unwrap();
        assert_eq!(decoded, addr);
    }

    #[test]
    fn test_mapped_address_ipv6_roundtrip() {
        let addr = SocketAddr::new(IpAddr::V6("fe80::1".parse().unwrap()), 12345);
        let encoded = encode_mapped_address(addr);
        let decoded = decode_mapped_address(&encoded).unwrap();
        assert_eq!(decoded, addr);
    }

    #[test]
    fn test_change_request_attribute() {
        let attr = StunAttribute::ChangeRequest {
            change_ip: true,
            change_port: true,
        };
        let txn_id = [0; 12];
        let (attr_type, value) = attr.encode(&txn_id);
        assert_eq!(attr_type, ATTR_CHANGE_REQUEST);
        assert_eq!(value, vec![0x00, 0x00, 0x00, 0x06]); // 0x04 | 0x02

        let decoded = StunAttribute::decode(attr_type, &value, &txn_id).unwrap();
        if let StunAttribute::ChangeRequest {
            change_ip,
            change_port,
        } = decoded
        {
            assert!(change_ip);
            assert!(change_port);
        } else {
            panic!("expected ChangeRequest");
        }
    }

    #[test]
    fn test_error_code_attribute() {
        let attr = StunAttribute::ErrorCode {
            code: 401,
            reason: "Unauthorized".to_string(),
        };
        let txn_id = [0; 12];
        let (attr_type, value) = attr.encode(&txn_id);
        assert_eq!(attr_type, ATTR_ERROR_CODE);
        assert_eq!(value[3], 4); // class
        assert_eq!(value[4], 1); // number

        let decoded = StunAttribute::decode(attr_type, &value, &txn_id).unwrap();
        if let StunAttribute::ErrorCode { code, reason } = decoded {
            assert_eq!(code, 401);
            assert_eq!(reason, "Unauthorized");
        } else {
            panic!("expected ErrorCode");
        }
    }

    #[test]
    fn test_software_attribute() {
        let attr = StunAttribute::Software("P2PNet STUN 1.0".to_string());
        let txn_id = [0; 12];
        let (attr_type, value) = attr.encode(&txn_id);
        assert_eq!(attr_type, ATTR_SOFTWARE);

        let decoded = StunAttribute::decode(attr_type, &value, &txn_id).unwrap();
        if let StunAttribute::Software(s) = decoded {
            assert_eq!(s, "P2PNet STUN 1.0");
        } else {
            panic!("expected Software");
        }
    }

    #[test]
    fn test_message_encode_decode_roundtrip() {
        let mut msg = StunMessage::binding_request();
        msg.add_attribute(StunAttribute::Software("TestClient/1.0".to_string()));
        msg.add_attribute(StunAttribute::ChangeRequest {
            change_ip: false,
            change_port: true,
        });

        let encoded = msg.encode();
        assert_eq!(encoded.len() % 4, 0); // STUN messages are 4-byte aligned

        let decoded = StunMessage::decode(&encoded).unwrap();
        assert_eq!(decoded.msg_type, BINDING_REQUEST);
        assert_eq!(decoded.transaction_id, msg.transaction_id);
        assert_eq!(decoded.attributes.len(), 2);

        // Check attribute order
        assert!(matches!(decoded.attributes[0], StunAttribute::Software(_)));
        assert!(matches!(
            decoded.attributes[1],
            StunAttribute::ChangeRequest { .. }
        ));
    }

    #[test]
    fn test_message_with_xor_mapped_address() {
        let mut msg = StunMessage::with_transaction_id(BINDING_RESPONSE, [0x42; 12]);
        let reflexive = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 5)), 43210);
        msg.add_attribute(StunAttribute::XorMappedAddress(reflexive));

        let encoded = msg.encode();
        let decoded = StunMessage::decode(&encoded).unwrap();

        assert_eq!(decoded.get_reflexive_address(), Some(reflexive));
        assert!(decoded.is_binding_response());
    }

    #[test]
    fn test_message_with_fingerprint() {
        let mut msg = StunMessage::binding_request();
        msg.add_attribute(StunAttribute::Software("FingerprintTest".to_string()));

        let encoded = msg.encode_with_fingerprint();

        // The encoded message should have FINGERPRINT as the last attribute
        let last_attr_type =
            u16::from_be_bytes([encoded[encoded.len() - 8], encoded[encoded.len() - 7]]);
        assert_eq!(last_attr_type, ATTR_FINGERPRINT);

        // Decode and verify fingerprint
        let decoded = StunMessage::decode(&encoded).unwrap();
        assert!(decoded.verify_fingerprint());
    }

    #[test]
    fn test_message_with_tampered_fingerprint() {
        let mut msg = StunMessage::binding_request();
        msg.add_attribute(StunAttribute::Software("TamperTest".to_string()));

        let mut encoded = msg.encode_with_fingerprint();

        // Tamper with a byte in the middle
        encoded[25] ^= 0xFF;

        let decoded = StunMessage::decode(&encoded).unwrap();
        assert!(!decoded.verify_fingerprint());
    }

    #[test]
    fn test_invalid_magic_cookie() {
        let mut buf = vec![0x00, 0x01, 0x00, 0x00]; // type + length
        buf.extend_from_slice(&0xDEADBEEFu32.to_be_bytes()); // wrong cookie
        buf.extend_from_slice(&[0u8; 12]); // transaction ID

        let result = StunMessage::decode(&buf);
        assert!(result.is_err());
    }

    #[test]
    fn test_message_too_short() {
        let buf = vec![0x00, 0x01, 0x00];
        let result = StunMessage::decode(&buf);
        assert!(result.is_err());
    }

    #[test]
    fn test_get_reflexive_address_fallback() {
        // Test that MAPPED-ADDRESS is used when XOR-MAPPED-ADDRESS is absent
        let mut msg = StunMessage::new(BINDING_RESPONSE);
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)), 1111);
        msg.add_attribute(StunAttribute::MappedAddress(addr));

        assert_eq!(msg.get_reflexive_address(), Some(addr));
        assert_eq!(msg.get_xor_mapped_address(), None);
    }

    #[test]
    fn test_get_error_code() {
        let mut msg = StunMessage::new(BINDING_ERROR_RESPONSE);
        msg.add_attribute(StunAttribute::ErrorCode {
            code: 300,
            reason: "Try Alternate".to_string(),
        });

        let (code, reason) = msg.get_error_code().unwrap();
        assert_eq!(code, 300);
        assert_eq!(reason, "Try Alternate");
        assert!(msg.is_error_response());
    }

    #[test]
    fn test_attribute_padding() {
        // Attribute with value length not multiple of 4
        let mut msg = StunMessage::binding_request();
        msg.add_attribute(StunAttribute::Software("abc".to_string())); // 3 bytes, needs 1 byte padding

        let encoded = msg.encode();
        let decoded = StunMessage::decode(&encoded).unwrap();

        assert_eq!(decoded.attributes.len(), 1);
        if let StunAttribute::Software(s) = &decoded.attributes[0] {
            assert_eq!(s, "abc");
        } else {
            panic!("expected Software attribute");
        }
    }

    #[test]
    fn test_other_attribute_roundtrip() {
        let raw_value = vec![0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x00, 0x00, 0x01];
        let attr = StunAttribute::Other {
            attr_type: 0x8000,
            value: raw_value.clone(),
        };

        let txn_id = [0; 12];
        let (attr_type, value) = attr.encode(&txn_id);
        let decoded = StunAttribute::decode(attr_type, &value, &txn_id).unwrap();

        if let StunAttribute::Other { attr_type, value } = decoded {
            assert_eq!(attr_type, 0x8000);
            assert_eq!(value, raw_value);
        } else {
            panic!("expected Other attribute");
        }
    }
}
