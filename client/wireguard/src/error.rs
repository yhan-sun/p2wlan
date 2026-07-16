//! Error types for the WireGuard module.

use thiserror::Error;

#[derive(Debug, Error)]
pub enum WireGuardError {
    #[error("handshake failed: {0}")]
    HandshakeFailed(String),

    #[error("invalid message type: {0}")]
    InvalidMessageType(u8),

    #[error("invalid packet: {0}")]
    InvalidPacket(String),

    #[error("invalid mac: {0}")]
    InvalidMac(String),

    #[error("session not established")]
    NoSession,

    #[error("decryption failed")]
    DecryptionFailed,

    #[error("nonce overflow: counter exceeded 2^64-1")]
    NonceOverflow,

    #[error("replay detected: counter {0} is below the current window")]
    ReplayDetected(u64),

    #[error("rekey required")]
    RekeyRequired,

    #[error("handshake timeout")]
    HandshakeTimeout,

    #[error("peer not found")]
    PeerNotFound,

    #[error("crypto error: {0}")]
    Crypto(String),
}

impl From<p2pnet_crypto::CryptoError> for WireGuardError {
    fn from(e: p2pnet_crypto::CryptoError) -> Self {
        WireGuardError::Crypto(e.to_string())
    }
}

pub type Result<T> = std::result::Result<T, WireGuardError>;
