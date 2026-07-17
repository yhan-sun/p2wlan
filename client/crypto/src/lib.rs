//! # p2pnet-crypto
//!
//! Cryptographic primitives for P2PNet, implementing the exact same
//! cryptographic algorithms used by WireGuard.
//!
//! ## Overview
//!
//! - **Key Exchange**: X25519 (Curve25519 ECDH) for session key agreement
//! - **Symmetric**: ChaCha20-Poly1305 AEAD for data encryption
//! - **Hashing**: BLAKE2s-256 for Noise protocol
//! - **KDF**: HKDF-BLAKE2s for key derivation
//! - **Noise**: Noise Protocol Framework (IK pattern) state machine
//! - **Identity**: X25519-based node identity
//!
//! ## Modules
//!
//! - [`dh`]: X25519 Diffie-Hellman key exchange
//! - [`aead`]: ChaCha20-Poly1305 authenticated encryption
//! - [`hash`]: BLAKE2s-256 hashing and HMAC
//! - [`hkdf`]: HKDF key derivation
//! - [`noise`]: Noise Protocol Framework symmetric state

pub mod aead;
pub mod dh;
pub mod error;
pub mod hash;
pub mod hkdf;
pub mod noise;
pub mod sign;

// Re-export primary types
pub use aead::{decrypt, encrypt, nonce_from_counter, AeadKey, AeadNonce, TAG_SIZE, ZERO_NONCE};
pub use dh::{DhKeyPair, PrivateKey, PublicKeyBytes, SharedSecret};
pub use error::{CryptoError, Result};
pub use hash::{hash, hash2, hmac, keyed_hash, Hash};
pub use hkdf::{expand, extract, hkdf2, hkdf3};
pub use noise::{
    SymmetricState, CONSTRUCTION, IDENTIFIER, REJECT_AFTER_MESSAGES, REJECT_AFTER_TIME,
    REKEY_AFTER_MESSAGES, REKEY_AFTER_TIME,
};
pub use sign::Ed25519KeyPair;

/// A node identity, consisting of an X25519 key pair.
///
/// This is used as the node's static (long-term) key pair in the
/// Noise IK handshake. The public key serves as the node's identity.
#[derive(Clone)]
pub struct NodeIdentity {
    /// X25519 key pair (static key).
    keypair: DhKeyPair,
    /// Hex-encoded node ID (first 8 bytes of public key).
    node_id: String,
}

impl NodeIdentity {
    /// Generate a new random identity.
    pub fn generate() -> Self {
        let keypair = DhKeyPair::generate();
        let pub_key = keypair.public_key();
        let node_id = hex::encode(&pub_key[..8]);
        Self { keypair, node_id }
    }

    /// Create an identity from an existing private key.
    pub fn from_private_key(private_key: PrivateKey) -> Self {
        let keypair = DhKeyPair::from_private_key(private_key);
        let pub_key = keypair.public_key();
        let node_id = hex::encode(&pub_key[..8]);
        Self { keypair, node_id }
    }

    /// Get the public key (32 bytes).
    pub fn public_key(&self) -> PublicKeyBytes {
        self.keypair.public_key()
    }

    /// Get the private key (32 bytes).
    pub fn private_key(&self) -> PrivateKey {
        self.keypair.private_key()
    }

    /// Get a reference to the underlying DH key pair.
    pub fn keypair(&self) -> &DhKeyPair {
        &self.keypair
    }

    /// Get the node ID (hex string, first 8 bytes of public key).
    pub fn node_id(&self) -> &str {
        &self.node_id
    }

    /// Compute a shared secret with a peer's public key.
    pub fn diffie_hellman(&self, peer_public: &PublicKeyBytes) -> Result<SharedSecret> {
        self.keypair.diffie_hellman(peer_public)
    }
}

impl std::fmt::Debug for NodeIdentity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NodeIdentity")
            .field("public_key", &hex::encode(self.keypair.public_key()))
            .field("node_id", &self.node_id)
            .finish_non_exhaustive()
    }
}

/// Encode bytes as a lowercase hex string.
pub fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_identity_generation() {
        let id1 = NodeIdentity::generate();
        let id2 = NodeIdentity::generate();

        assert_ne!(id1.public_key(), id2.public_key());
        assert_ne!(id1.node_id(), id2.node_id());
    }

    #[test]
    fn test_node_id_is_hex() {
        let id = NodeIdentity::generate();
        let node_id = id.node_id();

        assert_eq!(node_id.len(), 16); // 8 bytes * 2 hex chars
        assert!(node_id.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn test_identity_from_private_key() {
        let id1 = NodeIdentity::generate();
        let private = id1.private_key();
        let id2 = NodeIdentity::from_private_key(private);

        assert_eq!(id1.public_key(), id2.public_key());
        assert_eq!(id1.node_id(), id2.node_id());
    }

    #[test]
    fn test_identity_ecdh() {
        let alice = NodeIdentity::generate();
        let bob = NodeIdentity::generate();

        let shared_ab = alice.diffie_hellman(&bob.public_key()).unwrap();
        let shared_ba = bob.diffie_hellman(&alice.public_key()).unwrap();

        assert_eq!(shared_ab, shared_ba);
    }

    #[test]
    fn test_hex_encode() {
        assert_eq!(hex_encode(&[0x00, 0xFF, 0xAB]), "00ffab");
        assert_eq!(hex_encode(&[]), "");
    }
}
