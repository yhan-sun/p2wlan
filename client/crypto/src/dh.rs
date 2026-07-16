//! X25519 Diffie-Hellman key exchange (Curve25519 ECDH).
//!
//! Used by WireGuard's Noise protocol for session key agreement.
//! Each party has a static (long-term) key pair and generates an ephemeral
//! key pair per handshake.

use rand::rngs::OsRng;
use rand::RngCore;
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::Zeroize;

use crate::error::{CryptoError, Result};

/// A 32-byte X25519 private key.
pub type PrivateKey = [u8; 32];

/// A 32-byte X25519 public key.
pub type PublicKeyBytes = [u8; 32];

/// A 32-byte shared secret from ECDH.
pub type SharedSecret = [u8; 32];

/// An X25519 key pair used for Diffie-Hellman key exchange.
///
/// Wraps `x25519_dalek::StaticSecret` which provides automatic
/// zeroization when dropped.
#[derive(Clone)]
pub struct DhKeyPair {
    secret: StaticSecret,
    public: PublicKey,
}

impl DhKeyPair {
    /// Generate a new random X25519 key pair.
    pub fn generate() -> Self {
        let secret = StaticSecret::random_from_rng(&mut OsRng);
        let public = PublicKey::from(&secret);
        Self { secret, public }
    }

    /// Create a key pair from an existing 32-byte private key.
    pub fn from_private_key(private_key: PrivateKey) -> Self {
        let secret = StaticSecret::from(private_key);
        let public = PublicKey::from(&secret);
        Self { secret, public }
    }

    /// Get the public key as 32 bytes.
    pub fn public_key(&self) -> PublicKeyBytes {
        self.public.to_bytes()
    }

    /// Get the private key as 32 bytes.
    ///
    /// The caller is responsible for zeroizing the returned bytes
    /// when no longer needed.
    pub fn private_key(&self) -> PrivateKey {
        self.secret.to_bytes()
    }

    /// Compute the shared secret via ECDH with the given peer public key.
    ///
    /// `DH(our_private, peer_public) -> shared_secret`
    pub fn diffie_hellman(&self, peer_public: &PublicKeyBytes) -> Result<SharedSecret> {
        let peer_pub = PublicKey::from(*peer_public);

        // Check for all-zeros public key (invalid point)
        if peer_public == &[0u8; 32] {
            return Err(CryptoError::InvalidInput(
                "peer public key is all zeros".to_string(),
            ));
        }

        let shared = self.secret.diffie_hellman(&peer_pub);
        Ok(*shared.as_bytes())
    }

    /// Generate a random 32-byte private key.
    pub fn random_private_key() -> PrivateKey {
        let mut key = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut key);
        // Clamp the key per RFC 7748
        key[0] &= 248;
        key[31] &= 127;
        key[31] |= 64;
        key
    }
}

impl std::fmt::Debug for DhKeyPair {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DhKeyPair")
            .field("public_key", &hex::encode(self.public_key()))
            .finish_non_exhaustive()
    }
}

impl Drop for DhKeyPair {
    fn drop(&mut self) {
        // StaticSecret handles zeroization internally,
        // but we also zeroize the public key bytes for completeness.
        let mut pk = self.public.to_bytes();
        pk.zeroize();
    }
}

/// Compute X25519 ECDH from raw private and public key bytes.
///
/// Convenience function for one-off DH computations.
pub fn diffie_hellman(
    our_private: &PrivateKey,
    peer_public: &PublicKeyBytes,
) -> Result<SharedSecret> {
    let keypair = DhKeyPair::from_private_key(*our_private);
    keypair.diffie_hellman(peer_public)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_key_generation() {
        let kp1 = DhKeyPair::generate();
        let kp2 = DhKeyPair::generate();

        // Two random key pairs should have different keys
        assert_ne!(kp1.public_key(), kp2.public_key());
        assert_ne!(kp1.private_key(), kp2.private_key());
    }

    #[test]
    fn test_ecdh_symmetric() {
        // DH(a_priv, b_pub) == DH(b_priv, a_pub)
        let alice = DhKeyPair::generate();
        let bob = DhKeyPair::generate();

        let shared_ab = alice.diffie_hellman(&bob.public_key()).unwrap();
        let shared_ba = bob.diffie_hellman(&alice.public_key()).unwrap();

        assert_eq!(shared_ab, shared_ba);
    }

    #[test]
    fn test_ecdh_deterministic() {
        // Same private keys always produce same shared secret
        let alice_key = DhKeyPair::random_private_key();
        let bob_key = DhKeyPair::random_private_key();

        let alice = DhKeyPair::from_private_key(alice_key);
        let bob = DhKeyPair::from_private_key(bob_key);

        let shared1 = alice.diffie_hellman(&bob.public_key()).unwrap();
        let shared2 = bob.diffie_hellman(&alice.public_key()).unwrap();

        assert_eq!(shared1, shared2);

        // Recreate from same keys and verify same result
        let alice2 = DhKeyPair::from_private_key(alice_key);
        let bob2 = DhKeyPair::from_private_key(bob_key);
        let shared3 = alice2.diffie_hellman(&bob2.public_key()).unwrap();
        assert_eq!(shared1, shared3);
    }

    #[test]
    fn test_from_private_key_deterministic() {
        let key = DhKeyPair::random_private_key();
        let kp1 = DhKeyPair::from_private_key(key);
        let kp2 = DhKeyPair::from_private_key(key);

        assert_eq!(kp1.public_key(), kp2.public_key());
        assert_eq!(kp1.private_key(), kp2.private_key());
    }

    #[test]
    fn test_zero_public_key_rejected() {
        let kp = DhKeyPair::generate();
        let zero_pub = [0u8; 32];
        assert!(kp.diffie_hellman(&zero_pub).is_err());
    }

    #[test]
    fn test_raw_diffie_hellman() {
        let alice = DhKeyPair::generate();
        let bob = DhKeyPair::generate();

        let shared1 = alice.diffie_hellman(&bob.public_key()).unwrap();
        let shared2 = diffie_hellman(&alice.private_key(), &bob.public_key()).unwrap();

        assert_eq!(shared1, shared2);
    }
}
