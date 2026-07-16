//! Noise Protocol Framework state machine helpers.
//!
//! Implements the cryptographic operations used by the Noise IK pattern
//! (as used by WireGuard): `MixHash`, `MixKey`, `EncryptAndHash`,
//! `DecryptAndHash`, and `HKDF` key derivation.
//!
//! References:
//! - Noise Protocol Framework specification: http://noiseprotocol.org/
//! - WireGuard whitepaper: https://www.wireguard.com/papers/wireguard.pdf

use crate::aead;
use crate::hash::{self, Hash};
use crate::hkdf;

/// The Noise protocol construction name for WireGuard.
///
/// `Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s`
pub const CONSTRUCTION: &[u8] = b"Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s";

/// The WireGuard protocol identifier string.
pub const IDENTIFIER: &[u8] = b"WireGuard v1 zx2c4 Jason@zx2c4.com";

/// Maximum Noise handshake messages before rekey is required.
pub const REKEY_AFTER_MESSAGES: u64 = 2u64.pow(60);

/// Reject-after-messages: hard limit before session is destroyed.
pub const REJECT_AFTER_MESSAGES: u64 = u64::MAX;

/// Rekey-after-time in seconds (120 seconds = 2 minutes).
pub const REKEY_AFTER_TIME: u64 = 120;

/// Reject-after-time in seconds (180 seconds = 3 minutes).
pub const REJECT_AFTER_TIME: u64 = 180;

/// The Noise symmetric state, containing the chaining key (ck),
/// the hash (h), and a temporary encryption key (temp_k).
///
/// This struct implements the core Noise operations used during
/// the handshake phase.
#[derive(Clone)]
pub struct SymmetricState {
    /// The chaining key (32 bytes). Updated by MixKey operations.
    pub ck: Hash,
    /// The running hash (32 bytes). Updated by MixHash operations.
    pub h: Hash,
    /// The temporary encryption key from the last MixKey call.
    /// Used by EncryptAndHash / DecryptAndHash.
    pub temp_k: Hash,
}

impl SymmetricState {
    /// Initialize the Noise symmetric state.
    ///
    /// ```text
    /// ck = HASH(Construction)
    /// h  = HASH(ck || Identifier)
    /// ```
    pub fn new() -> Self {
        let ck = hash::hash(CONSTRUCTION);
        let h = hash::hash2(&ck, IDENTIFIER);
        Self {
            ck,
            h,
            temp_k: [0u8; 32],
        }
    }

    /// Mix data into the hash.
    ///
    /// ```text
    /// h = HASH(h || data)
    /// ```
    pub fn mix_hash(&mut self, data: &[u8]) {
        self.h = hash::hash2(&self.h, data);
    }

    /// Mix a DH result into the chaining key and derive a temp key.
    ///
    /// ```text
    /// (ck, temp_k) = HKDF(ck, dh_output, 2)
    /// ```
    ///
    /// In WireGuard, the DH output is the 32-byte X25519 shared secret.
    pub fn mix_key(&mut self, dh_output: &[u8]) {
        let (new_ck, new_temp_k) = hkdf::hkdf2(&self.ck, dh_output);
        self.ck = new_ck;
        self.temp_k = new_temp_k;
    }

    /// Mix a preshared key (PSK) into the chaining key.
    ///
    /// Used at the psk2 position in Noise_IKpsk2.
    /// If no PSK is used, a 32-byte all-zero value is mixed in.
    ///
    /// ```text
    /// (ck, temp_k) = HKDF(ck, psk, 2)
    /// ```
    pub fn mix_psk(&mut self, psk: &[u8; 32]) {
        let (new_ck, new_temp_k) = hkdf::hkdf2(&self.ck, psk);
        self.ck = new_ck;
        self.temp_k = new_temp_k;
    }

    /// Encrypt plaintext and mix the ciphertext into the hash.
    ///
    /// Uses the current temp_k as the AEAD key and the current hash h
    /// as the associated data (AD). The nonce is all zeros (each temp_k
    /// is used for exactly one encryption).
    ///
    /// ```text
    /// ciphertext = AEAD_Encrypt(temp_k, nonce=0, ad=h, plaintext)
    /// h = HASH(h || ciphertext)
    /// ```
    pub fn encrypt_and_hash(&mut self, plaintext: &[u8]) -> Vec<u8> {
        let ciphertext = aead::encrypt_with_zero_nonce(&self.temp_k, &self.h, plaintext)
            .expect("AEAD encryption failed in Noise state");
        self.mix_hash(&ciphertext);
        ciphertext
    }

    /// Decrypt ciphertext and mix the ciphertext into the hash.
    ///
    /// ```text
    /// plaintext = AEAD_Decrypt(temp_k, nonce=0, ad=h, ciphertext)
    /// h = HASH(h || ciphertext)
    /// ```
    pub fn decrypt_and_hash(&mut self, ciphertext: &[u8]) -> Result<Vec<u8>, String> {
        let plaintext = aead::decrypt_with_zero_nonce(&self.temp_k, &self.h, ciphertext)
            .map_err(|e| format!("Noise AEAD decrypt failed: {e}"))?;
        self.mix_hash(ciphertext);
        Ok(plaintext)
    }

    /// Derive transport keys after handshake completion.
    ///
    /// ```text
    /// (send_key, recv_key) = HKDF(ck, "", 2)
    /// ```
    ///
    /// For the initiator: send_key = first output, recv_key = second output.
    /// For the responder: send_key = second output, recv_key = first output.
    pub fn derive_transport_keys(&self) -> (Hash, Hash) {
        hkdf::hkdf2(&self.ck, b"")
    }

    /// Mix in the responder's static public key as prologue.
    ///
    /// Called at the beginning of the IK handshake:
    /// ```text
    /// h = HASH(h || responder_static_public_key)
    /// ```
    pub fn mix_responder_static(&mut self, responder_pub: &[u8; 32]) {
        self.mix_hash(responder_pub);
    }
}

impl Default for SymmetricState {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Debug for SymmetricState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SymmetricState")
            .field("ck", &hex::encode(self.ck))
            .field("h", &hex::encode(self.h))
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_symmetric_state_init() {
        let state = SymmetricState::new();

        // ck should be non-zero (hash of construction name)
        assert_ne!(state.ck, [0u8; 32]);

        // h should be non-zero and different from ck
        assert_ne!(state.h, [0u8; 32]);
        assert_ne!(state.ck, state.h);

        // temp_k should be all zeros initially
        assert_eq!(state.temp_k, [0u8; 32]);
    }

    #[test]
    fn test_mix_hash() {
        let mut state = SymmetricState::new();
        let original_h = state.h;

        state.mix_hash(b"test data");

        assert_ne!(state.h, original_h);

        // Should be deterministic
        let mut state2 = SymmetricState::new();
        state2.mix_hash(b"test data");
        assert_eq!(state.h, state2.h);
    }

    #[test]
    fn test_mix_key() {
        let mut state = SymmetricState::new();
        let original_ck = state.ck;

        state.mix_key(&[0xAB; 32]);

        assert_ne!(state.ck, original_ck);
        assert_ne!(state.temp_k, [0u8; 32]);
    }

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let mut state = SymmetricState::new();

        // Mix in a DH result to set temp_k
        state.mix_key(&[0x42; 32]);

        let plaintext = b"hello noise";
        let ciphertext = state.encrypt_and_hash(plaintext);

        // The ciphertext should be plaintext + 16 byte tag
        assert_eq!(ciphertext.len(), plaintext.len() + 16);

        // Decrypt with a fresh state that has the same ck and temp_k
        let mut decrypt_state = SymmetricState::new();
        decrypt_state.mix_key(&[0x42; 32]);

        let decrypted = decrypt_state.decrypt_and_hash(&ciphertext).unwrap();
        assert_eq!(&decrypted, plaintext);

        // Both states should have the same hash after the operation
        assert_eq!(state.h, decrypt_state.h);
    }

    #[test]
    fn test_derive_transport_keys() {
        let mut state = SymmetricState::new();
        state.mix_key(&[0x42; 32]);
        state.mix_key(&[0x43; 32]);

        let (send_key, recv_key) = state.derive_transport_keys();

        assert_ne!(send_key, recv_key);
        assert_ne!(send_key, [0u8; 32]);
        assert_ne!(recv_key, [0u8; 32]);
    }

    #[test]
    fn test_mix_psk() {
        let mut state = SymmetricState::new();
        state.mix_key(&[0x42; 32]);

        let ck_before = state.ck;
        state.mix_psk(&[0xFF; 32]);

        assert_ne!(state.ck, ck_before);

        // With zero PSK (no PSK)
        let mut state2 = SymmetricState::new();
        state2.mix_key(&[0x42; 32]);
        state2.mix_psk(&[0u8; 32]);

        assert_ne!(state2.ck, ck_before);
        assert_ne!(state.ck, state2.ck); // Different PSKs produce different keys
    }

    #[test]
    fn test_construction_string() {
        assert_eq!(
            std::str::from_utf8(CONSTRUCTION).unwrap(),
            "Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s"
        );
    }

    #[test]
    fn test_identifier_string() {
        assert_eq!(
            std::str::from_utf8(IDENTIFIER).unwrap(),
            "WireGuard v1 zx2c4 Jason@zx2c4.com"
        );
    }
}
