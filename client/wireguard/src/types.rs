//! WireGuard message types and wire format.
//!
//! WireGuard uses 4 message types:
//! - Type 1: Handshake Initiation (148 bytes)
//! - Type 2: Handshake Response (92 bytes)
//! - Type 3: Cookie Reply (64 bytes)
//! - Type 4: Transport Data (variable, min 32 bytes)

use crate::error::{Result, WireGuardError};

/// Message type for handshake initiation.
pub const TYPE_INITIALIZATION: u8 = 1;
/// Message type for handshake response.
pub const TYPE_RESPONSE: u8 = 2;
/// Message type for cookie reply.
pub const TYPE_COOKIE_REPLY: u8 = 3;
/// Message type for transport data.
pub const TYPE_TRANSPORT: u8 = 4;

/// Size of the sender/receiver index field (4 bytes).
pub const INDEX_SIZE: usize = 4;
/// Size of an X25519 public key (32 bytes).
pub const PUBLIC_KEY_SIZE: usize = 32;
/// Size of ChaCha20-Poly1305 authentication tag (16 bytes).
pub const AEAD_TAG_SIZE: usize = 16;
/// Size of MAC1/MAC2 fields (16 bytes each).
pub const MAC_SIZE: usize = 16;
/// Size of a WireGuard timestamp (12 bytes = TAI64N).
pub const TIMESTAMP_SIZE: usize = 12;

/// Total size of a handshake initiation message (148 bytes).
pub const INITIALIZATION_MSG_SIZE: usize = 4 + INDEX_SIZE + PUBLIC_KEY_SIZE
    + (PUBLIC_KEY_SIZE + AEAD_TAG_SIZE)   // encrypted static
    + (TIMESTAMP_SIZE + AEAD_TAG_SIZE)     // encrypted timestamp
    + MAC_SIZE + MAC_SIZE;

/// Total size of a handshake response message (92 bytes).
pub const RESPONSE_MSG_SIZE: usize = 4 + INDEX_SIZE + INDEX_SIZE + PUBLIC_KEY_SIZE
    + AEAD_TAG_SIZE  // encrypted empty
    + MAC_SIZE + MAC_SIZE;

/// Minimum size of a transport data message (32 bytes = header + tag).
pub const TRANSPORT_MSG_MIN_SIZE: usize = 4 + INDEX_SIZE + 8 + AEAD_TAG_SIZE;

/// A handshake initiation message (Type 1, 148 bytes).
#[derive(Debug, Clone)]
pub struct MessageInitiation {
    /// Sender's session index (chosen by initiator).
    pub sender_index: u32,
    /// Initiator's ephemeral public key (E_i).
    pub ephemeral: [u8; 32],
    /// Encrypted initiator static public key (S_i) + 16-byte tag.
    pub encrypted_static: [u8; 32 + AEAD_TAG_SIZE],
    /// Encrypted timestamp + 16-byte tag.
    pub encrypted_timestamp: [u8; TIMESTAMP_SIZE + AEAD_TAG_SIZE],
    /// MAC1: authentication of the message.
    pub mac1: [u8; MAC_SIZE],
    /// MAC2: cookie-based DoS protection (zeros if no cookie).
    pub mac2: [u8; MAC_SIZE],
}

impl MessageInitiation {
    /// Serialize to wire format (148 bytes).
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(INITIALIZATION_MSG_SIZE);
        buf.push(TYPE_INITIALIZATION);
        buf.push(0); // reserved
        buf.push(0);
        buf.push(0);
        buf.extend_from_slice(&self.sender_index.to_le_bytes());
        buf.extend_from_slice(&self.ephemeral);
        buf.extend_from_slice(&self.encrypted_static);
        buf.extend_from_slice(&self.encrypted_timestamp);
        buf.extend_from_slice(&self.mac1);
        buf.extend_from_slice(&self.mac2);
        debug_assert_eq!(buf.len(), INITIALIZATION_MSG_SIZE);
        buf
    }

    /// Deserialize from wire format.
    pub fn from_bytes(data: &[u8]) -> Result<Self> {
        if data.len() < INITIALIZATION_MSG_SIZE {
            return Err(WireGuardError::InvalidPacket(format!(
                "initiation message too short: {} < {}",
                data.len(),
                INITIALIZATION_MSG_SIZE
            )));
        }
        if data[0] != TYPE_INITIALIZATION {
            return Err(WireGuardError::InvalidMessageType(data[0]));
        }

        let mut msg = Self {
            sender_index: u32::from_le_bytes([data[4], data[5], data[6], data[7]]),
            ephemeral: [0u8; 32],
            encrypted_static: [0u8; 32 + AEAD_TAG_SIZE],
            encrypted_timestamp: [0u8; TIMESTAMP_SIZE + AEAD_TAG_SIZE],
            mac1: [0u8; MAC_SIZE],
            mac2: [0u8; MAC_SIZE],
        };

        let off = 8;
        msg.ephemeral.copy_from_slice(&data[off..off + 32]);
        let off = off + 32;
        msg.encrypted_static.copy_from_slice(&data[off..off + 48]);
        let off = off + 48;
        msg.encrypted_timestamp
            .copy_from_slice(&data[off..off + 28]);
        let off = off + 28;
        msg.mac1.copy_from_slice(&data[off..off + 16]);
        let off = off + 16;
        msg.mac2.copy_from_slice(&data[off..off + 16]);

        Ok(msg)
    }

    /// Get the message bytes without MAC1 and MAC2 (for MAC1 computation).
    pub fn bytes_for_mac1(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(INITIALIZATION_MSG_SIZE - 32);
        buf.push(TYPE_INITIALIZATION);
        buf.push(0);
        buf.push(0);
        buf.push(0);
        buf.extend_from_slice(&self.sender_index.to_le_bytes());
        buf.extend_from_slice(&self.ephemeral);
        buf.extend_from_slice(&self.encrypted_static);
        buf.extend_from_slice(&self.encrypted_timestamp);
        buf
    }
}

/// A handshake response message (Type 2, 92 bytes).
#[derive(Debug, Clone)]
pub struct MessageResponse {
    /// Responder's session index (chosen by responder).
    pub sender_index: u32,
    /// Initiator's session index (echoed back).
    pub receiver_index: u32,
    /// Responder's ephemeral public key (E_r).
    pub ephemeral: [u8; 32],
    /// Encrypted empty payload (just 16-byte tag).
    pub encrypted_empty: [u8; AEAD_TAG_SIZE],
    /// MAC1.
    pub mac1: [u8; MAC_SIZE],
    /// MAC2.
    pub mac2: [u8; MAC_SIZE],
}

impl MessageResponse {
    /// Serialize to wire format (92 bytes).
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(RESPONSE_MSG_SIZE);
        buf.push(TYPE_RESPONSE);
        buf.push(0); // reserved
        buf.push(0);
        buf.push(0);
        buf.extend_from_slice(&self.sender_index.to_le_bytes());
        buf.extend_from_slice(&self.receiver_index.to_le_bytes());
        buf.extend_from_slice(&self.ephemeral);
        buf.extend_from_slice(&self.encrypted_empty);
        buf.extend_from_slice(&self.mac1);
        buf.extend_from_slice(&self.mac2);
        debug_assert_eq!(buf.len(), RESPONSE_MSG_SIZE);
        buf
    }

    /// Deserialize from wire format.
    pub fn from_bytes(data: &[u8]) -> Result<Self> {
        if data.len() < RESPONSE_MSG_SIZE {
            return Err(WireGuardError::InvalidPacket(format!(
                "response message too short: {} < {}",
                data.len(),
                RESPONSE_MSG_SIZE
            )));
        }
        if data[0] != TYPE_RESPONSE {
            return Err(WireGuardError::InvalidMessageType(data[0]));
        }

        let mut msg = Self {
            sender_index: u32::from_le_bytes([data[4], data[5], data[6], data[7]]),
            receiver_index: u32::from_le_bytes([data[8], data[9], data[10], data[11]]),
            ephemeral: [0u8; 32],
            encrypted_empty: [0u8; AEAD_TAG_SIZE],
            mac1: [0u8; MAC_SIZE],
            mac2: [0u8; MAC_SIZE],
        };

        let off = 12;
        msg.ephemeral.copy_from_slice(&data[off..off + 32]);
        let off = off + 32;
        msg.encrypted_empty.copy_from_slice(&data[off..off + 16]);
        let off = off + 16;
        msg.mac1.copy_from_slice(&data[off..off + 16]);
        let off = off + 16;
        msg.mac2.copy_from_slice(&data[off..off + 16]);

        Ok(msg)
    }

    /// Get the message bytes without MAC1 and MAC2.
    pub fn bytes_for_mac1(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(RESPONSE_MSG_SIZE - 32);
        buf.push(TYPE_RESPONSE);
        buf.push(0);
        buf.push(0);
        buf.push(0);
        buf.extend_from_slice(&self.sender_index.to_le_bytes());
        buf.extend_from_slice(&self.receiver_index.to_le_bytes());
        buf.extend_from_slice(&self.ephemeral);
        buf.extend_from_slice(&self.encrypted_empty);
        buf
    }
}

/// A transport data message (Type 4, variable length).
#[derive(Debug, Clone)]
pub struct MessageTransport {
    /// Responder's session index (identifies the session).
    pub receiver_index: u32,
    /// Counter (used as nonce).
    pub counter: u64,
    /// Encrypted payload (includes 16-byte AEAD tag).
    pub encrypted_payload: Vec<u8>,
}

impl MessageTransport {
    /// Serialize to wire format.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(4 + INDEX_SIZE + 8 + self.encrypted_payload.len());
        buf.push(TYPE_TRANSPORT);
        buf.push(0); // reserved
        buf.push(0);
        buf.push(0);
        buf.extend_from_slice(&self.receiver_index.to_le_bytes());
        buf.extend_from_slice(&self.counter.to_le_bytes());
        buf.extend_from_slice(&self.encrypted_payload);
        buf
    }

    /// Deserialize from wire format.
    pub fn from_bytes(data: &[u8]) -> Result<Self> {
        if data.len() < TRANSPORT_MSG_MIN_SIZE {
            return Err(WireGuardError::InvalidPacket(format!(
                "transport message too short: {} < {}",
                data.len(),
                TRANSPORT_MSG_MIN_SIZE
            )));
        }
        if data[0] != TYPE_TRANSPORT {
            return Err(WireGuardError::InvalidMessageType(data[0]));
        }

        let receiver_index = u32::from_le_bytes([data[4], data[5], data[6], data[7]]);
        let counter = u64::from_le_bytes([
            data[8], data[9], data[10], data[11], data[12], data[13], data[14], data[15],
        ]);
        let encrypted_payload = data[16..].to_vec();

        Ok(Self {
            receiver_index,
            counter,
            encrypted_payload,
        })
    }
}

/// Determine the message type from the first byte of a WireGuard message.
pub fn message_type(data: &[u8]) -> Option<u8> {
    if data.is_empty() {
        None
    } else {
        Some(data[0])
    }
}

/// Configuration for a WireGuard peer.
#[derive(Debug, Clone)]
pub struct PeerConfig {
    /// Peer's public key (32 bytes).
    pub public_key: [u8; 32],
    /// Peer's endpoint address (ip:port).
    pub endpoint: Option<String>,
    /// Optional preshared key (32 bytes).
    pub preshared_key: Option<[u8; 32]>,
    /// Keepalive interval in seconds (0 = disabled).
    pub persistent_keepalive: u16,
    /// Allowed IPs for this peer (CIDR notation).
    pub allowed_ips: Vec<String>,
}

impl PeerConfig {
    /// Create a new peer config from a public key.
    pub fn new(public_key: [u8; 32]) -> Self {
        Self {
            public_key,
            endpoint: None,
            preshared_key: None,
            persistent_keepalive: 0,
            allowed_ips: Vec::new(),
        }
    }
}

/// Session keys established after a successful handshake.
#[derive(Clone)]
pub struct SessionKeys {
    /// Key for sending (our direction).
    pub send_key: [u8; 32],
    /// Key for receiving (peer's direction).
    pub recv_key: [u8; 32],
    /// Current send counter.
    pub send_counter: u64,
    /// Highest received counter (for replay protection).
    pub recv_counter: u64,
}

impl SessionKeys {
    /// Create a new session with the given keys.
    pub fn new(send_key: [u8; 32], recv_key: [u8; 32]) -> Self {
        Self {
            send_key,
            recv_key,
            send_counter: 0,
            recv_counter: u64::MAX, // First valid counter (0) should always be accepted
        }
    }

    /// Get the next send nonce (counter).
    pub fn next_nonce(&mut self) -> Result<u64> {
        let nonce = self.send_counter;
        if nonce == u64::MAX {
            return Err(WireGuardError::NonceOverflow);
        }
        self.send_counter += 1;
        Ok(nonce)
    }
}

impl std::fmt::Debug for SessionKeys {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SessionKeys")
            .field("send_key", &hex::encode(self.send_key))
            .field("recv_key", &hex::encode(self.recv_key))
            .field("send_counter", &self.send_counter)
            .field("recv_counter", &self.recv_counter)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_initiation_roundtrip() {
        let msg = MessageInitiation {
            sender_index: 0x12345678,
            ephemeral: [0xAB; 32],
            encrypted_static: [0xCD; 48],
            encrypted_timestamp: [0xEF; 28],
            mac1: [0x11; 16],
            mac2: [0x22; 16],
        };

        let bytes = msg.to_bytes();
        assert_eq!(bytes.len(), INITIALIZATION_MSG_SIZE);

        let decoded = MessageInitiation::from_bytes(&bytes).unwrap();
        assert_eq!(decoded.sender_index, 0x12345678);
        assert_eq!(decoded.ephemeral, [0xAB; 32]);
        assert_eq!(decoded.mac1, [0x11; 16]);
        assert_eq!(decoded.mac2, [0x22; 16]);
    }

    #[test]
    fn test_response_roundtrip() {
        let msg = MessageResponse {
            sender_index: 0xAAAAAAAA,
            receiver_index: 0xBBBBBBBB,
            ephemeral: [0x42; 32],
            encrypted_empty: [0x99; 16],
            mac1: [0x33; 16],
            mac2: [0x44; 16],
        };

        let bytes = msg.to_bytes();
        assert_eq!(bytes.len(), RESPONSE_MSG_SIZE);

        let decoded = MessageResponse::from_bytes(&bytes).unwrap();
        assert_eq!(decoded.sender_index, 0xAAAAAAAA);
        assert_eq!(decoded.receiver_index, 0xBBBBBBBB);
        assert_eq!(decoded.ephemeral, [0x42; 32]);
    }

    #[test]
    fn test_transport_roundtrip() {
        let payload = vec![
            0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE, 0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE,
            0xBA, 0xBE,
        ];
        let msg = MessageTransport {
            receiver_index: 0xCAFEBABE,
            counter: 42,
            encrypted_payload: payload.clone(),
        };

        let bytes = msg.to_bytes();
        let decoded = MessageTransport::from_bytes(&bytes).unwrap();
        assert_eq!(decoded.receiver_index, 0xCAFEBABE);
        assert_eq!(decoded.counter, 42);
        assert_eq!(decoded.encrypted_payload, payload);
    }

    #[test]
    fn test_message_type_detection() {
        let init = MessageInitiation {
            sender_index: 0,
            ephemeral: [0; 32],
            encrypted_static: [0; 48],
            encrypted_timestamp: [0; 28],
            mac1: [0; 16],
            mac2: [0; 16],
        };
        assert_eq!(message_type(&init.to_bytes()), Some(TYPE_INITIALIZATION));

        let resp = MessageResponse {
            sender_index: 0,
            receiver_index: 0,
            ephemeral: [0; 32],
            encrypted_empty: [0; 16],
            mac1: [0; 16],
            mac2: [0; 16],
        };
        assert_eq!(message_type(&resp.to_bytes()), Some(TYPE_RESPONSE));
    }
}
