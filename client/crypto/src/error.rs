//! Error types for the crypto module.

use thiserror::Error;

/// Errors that can occur in cryptographic operations.
#[derive(Debug, Error)]
pub enum CryptoError {
    /// Key generation or derivation failed.
    #[error("key error: {0}")]
    KeyError(String),

    /// Encryption or decryption failed.
    #[error("cipher error: {0}")]
    CipherError(String),

    /// Signature verification failed.
    #[error("signature verification failed")]
    SignatureFailed,

    /// Handshake failed.
    #[error("handshake error: {0}")]
    HandshakeError(String),

    /// Invalid input data.
    #[error("invalid input: {0}")]
    InvalidInput(String),
}

/// Convenience type alias.
pub type Result<T> = std::result::Result<T, CryptoError>;
