//! Ed25519 device identity and signing.
//!
//! Used for device authentication with the control plane:
//! the daemon signs a server-provided challenge to prove
//! possession of the Ed25519 private key, and the server
//! verifies with the corresponding public key.

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use rand::RngCore;

use crate::error::{CryptoError, Result};

/// An Ed25519 signing key pair for device identity.
///
/// This is **distinct** from the X25519 key pair used for
/// WireGuard / Noise protocol key exchange. Ed25519 is
/// used only for device authentication / challenge signing.
#[derive(Clone)]
pub struct Ed25519KeyPair {
    signing_key: SigningKey,
}

impl Ed25519KeyPair {
    /// Generate a new random Ed25519 key pair.
    pub fn generate() -> Self {
        let mut seed = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut seed);
        let signing_key = SigningKey::from_bytes(&seed);
        Self { signing_key }
    }

    /// Create a key pair from an existing 32-byte seed/private key.
    pub fn from_private_key(private_key: &[u8; 32]) -> Self {
        let signing_key = SigningKey::from_bytes(private_key);
        Self { signing_key }
    }

    /// Get the verifying (public) key as 32 bytes.
    pub fn public_key(&self) -> [u8; 32] {
        self.signing_key.verifying_key().to_bytes()
    }

    /// Get the signing key as 32 bytes.
    pub fn private_key(&self) -> [u8; 32] {
        self.signing_key.to_bytes()
    }

    /// Sign a message with the Ed25519 private key.
    pub fn sign(&self, message: &[u8]) -> [u8; 64] {
        let signature: Signature = self.signing_key.sign(message);
        signature.to_bytes()
    }

    /// Verify an Ed25519 signature against a public key and message.
    pub fn verify(public_key: &[u8; 32], message: &[u8], signature: &[u8; 64]) -> Result<()> {
        let vk = VerifyingKey::from_bytes(public_key)
            .map_err(|_| CryptoError::InvalidKey("invalid ed25519 public key".into()))?;
        let sig = Signature::from_bytes(signature);
        vk.verify(message, &sig)
            .map_err(|_| CryptoError::SignatureVerification("ed25519 signature mismatch".into()))
    }
}

impl std::fmt::Debug for Ed25519KeyPair {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Ed25519KeyPair")
            .field("public_key", &hex::encode(self.public_key()))
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_and_sign_verify() {
        let keypair = Ed25519KeyPair::generate();
        let message = b"test message for signing";

        let signature = keypair.sign(message);
        let pub_key = keypair.public_key();

        assert!(Ed25519KeyPair::verify(&pub_key, message, &signature).is_ok());
    }

    #[test]
    fn test_verify_rejects_tampered_message() {
        let keypair = Ed25519KeyPair::generate();
        let message = b"original message";
        let signature = keypair.sign(message);

        let pub_key = keypair.public_key();
        let result = Ed25519KeyPair::verify(&pub_key, b"tampered message", &signature);
        assert!(result.is_err());
    }

    #[test]
    fn test_from_private_key_deterministic() {
        let keypair1 = Ed25519KeyPair::generate();
        let priv_key = keypair1.private_key();

        let keypair2 = Ed25519KeyPair::from_private_key(&priv_key);
        assert_eq!(keypair1.public_key(), keypair2.public_key());
        assert_eq!(keypair1.private_key(), keypair2.private_key());
    }

    #[test]
    fn test_different_keys_different_signatures() {
        let kp1 = Ed25519KeyPair::generate();
        let kp2 = Ed25519KeyPair::generate();
        let msg = b"same message";

        let sig1 = kp1.sign(msg);
        let sig2 = kp2.sign(msg);
        assert_ne!(sig1, sig2);
    }
}
