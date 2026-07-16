//! ChaCha20-Poly1305 AEAD (Authenticated Encryption with Associated Data).
//!
//! WireGuard uses RFC 7539 ChaCha20-Poly1305 for all encrypted messages.
//! - Handshake messages: 12-byte nonce (all zeros)
//! - Transport messages: 12-byte nonce (4 zero bytes + 8-byte little-endian counter)

use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    ChaCha20Poly1305, Key, Nonce,
};

use crate::error::{CryptoError, Result};

/// Size of the AEAD key in bytes (32 bytes = 256 bits).
pub const KEY_SIZE: usize = 32;

/// Size of the AEAD nonce in bytes (12 bytes = 96 bits).
pub const NONCE_SIZE: usize = 12;

/// Size of the Poly1305 authentication tag in bytes.
pub const TAG_SIZE: usize = 16;

/// A 32-byte AEAD key.
pub type AeadKey = [u8; KEY_SIZE];

/// A 12-byte AEAD nonce.
pub type AeadNonce = [u8; NONCE_SIZE];

/// Construct a 12-byte nonce from a 64-bit counter.
///
/// The nonce is: `[0x00, 0x00, 0x00, 0x00, counter_le_8]`
///
/// This is the WireGuard nonce construction for transport messages.
pub fn nonce_from_counter(counter: u64) -> AeadNonce {
    let mut nonce = [0u8; NONCE_SIZE];
    nonce[4..12].copy_from_slice(&counter.to_le_bytes());
    nonce
}

/// The all-zeros nonce (used for Noise handshake messages).
pub const ZERO_NONCE: AeadNonce = [0u8; NONCE_SIZE];

/// Encrypt plaintext with ChaCha20-Poly1305 AEAD.
///
/// # Arguments
///
/// * `key` - 32-byte encryption key
/// * `nonce` - 12-byte nonce
/// * `aad` - associated data (authenticated but not encrypted)
/// * `plaintext` - data to encrypt
///
/// # Returns
///
/// Ciphertext with appended 16-byte authentication tag.
pub fn encrypt(key: &AeadKey, nonce: &AeadNonce, aad: &[u8], plaintext: &[u8]) -> Result<Vec<u8>> {
    let cipher = ChaCha20Poly1305::new(Key::from_slice(key));
    cipher
        .encrypt(
            Nonce::from_slice(nonce),
            Payload {
                msg: plaintext,
                aad,
            },
        )
        .map_err(|e| CryptoError::CipherError(format!("AEAD encrypt failed: {e}")))
}

/// Decrypt ciphertext with ChaCha20-Poly1305 AEAD.
///
/// # Arguments
///
/// * `key` - 32-byte decryption key
/// * `nonce` - 12-byte nonce
/// * `aad` - associated data (must match encryption)
/// * `ciphertext` - data to decrypt (includes 16-byte tag)
///
/// # Returns
///
/// The decrypted plaintext.
pub fn decrypt(key: &AeadKey, nonce: &AeadNonce, aad: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>> {
    let cipher = ChaCha20Poly1305::new(Key::from_slice(key));
    cipher
        .decrypt(
            Nonce::from_slice(nonce),
            Payload {
                msg: ciphertext,
                aad,
            },
        )
        .map_err(|e| CryptoError::CipherError(format!("AEAD decrypt failed: {e}")))
}

/// Encrypt with a zero nonce (for Noise handshake messages).
///
/// Each Noise handshake message uses a unique key (derived via HKDF),
/// so the nonce can safely be all zeros.
pub fn encrypt_with_zero_nonce(key: &AeadKey, aad: &[u8], plaintext: &[u8]) -> Result<Vec<u8>> {
    encrypt(key, &ZERO_NONCE, aad, plaintext)
}

/// Decrypt with a zero nonce (for Noise handshake messages).
pub fn decrypt_with_zero_nonce(key: &AeadKey, aad: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>> {
    decrypt(key, &ZERO_NONCE, aad, ciphertext)
}

/// Encrypt with a counter-based nonce (for WireGuard transport messages).
pub fn encrypt_with_counter(
    key: &AeadKey,
    counter: u64,
    aad: &[u8],
    plaintext: &[u8],
) -> Result<Vec<u8>> {
    let nonce = nonce_from_counter(counter);
    encrypt(key, &nonce, aad, plaintext)
}

/// Decrypt with a counter-based nonce (for WireGuard transport messages).
pub fn decrypt_with_counter(
    key: &AeadKey,
    counter: u64,
    aad: &[u8],
    ciphertext: &[u8],
) -> Result<Vec<u8>> {
    let nonce = nonce_from_counter(counter);
    decrypt(key, &nonce, aad, ciphertext)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let key = [0x42u8; 32];
        let plaintext = b"Hello, WireGuard!";
        let aad = b"associated data";

        let ciphertext = encrypt_with_zero_nonce(&key, aad, plaintext).unwrap();
        assert_ne!(&ciphertext[..], plaintext);

        let decrypted = decrypt_with_zero_nonce(&key, aad, &ciphertext).unwrap();
        assert_eq!(&decrypted, plaintext);
    }

    #[test]
    fn test_ciphertext_size() {
        let key = [0x42u8; 32];
        let plaintext = b"test";
        let ciphertext = encrypt_with_zero_nonce(&key, b"", plaintext).unwrap();

        // Ciphertext = plaintext + 16-byte tag
        assert_eq!(ciphertext.len(), plaintext.len() + TAG_SIZE);
    }

    #[test]
    fn test_empty_plaintext() {
        let key = [0x42u8; 32];
        let ciphertext = encrypt_with_zero_nonce(&key, b"", b"").unwrap();

        // Just the tag
        assert_eq!(ciphertext.len(), TAG_SIZE);

        let decrypted = decrypt_with_zero_nonce(&key, b"", &ciphertext).unwrap();
        assert!(decrypted.is_empty());
    }

    #[test]
    fn test_wrong_key_fails() {
        let key1 = [0x42u8; 32];
        let key2 = [0x43u8; 32];
        let plaintext = b"secret message";

        let ciphertext = encrypt_with_zero_nonce(&key1, b"", plaintext).unwrap();
        assert!(decrypt_with_zero_nonce(&key2, b"", &ciphertext).is_err());
    }

    #[test]
    fn test_wrong_aad_fails() {
        let key = [0x42u8; 32];
        let plaintext = b"secret message";

        let ciphertext = encrypt_with_zero_nonce(&key, b"aad1", plaintext).unwrap();
        assert!(decrypt_with_zero_nonce(&key, b"aad2", &ciphertext).is_err());
    }

    #[test]
    fn test_tampered_ciphertext_fails() {
        let key = [0x42u8; 32];
        let plaintext = b"secret message";

        let mut ciphertext = encrypt_with_zero_nonce(&key, b"", plaintext).unwrap();
        ciphertext[0] ^= 0xFF;

        assert!(decrypt_with_zero_nonce(&key, b"", &ciphertext).is_err());
    }

    #[test]
    fn test_counter_nonce() {
        let key = [0x42u8; 32];
        let plaintext = b"transport data";

        let ct1 = encrypt_with_counter(&key, 0, b"", plaintext).unwrap();
        let ct2 = encrypt_with_counter(&key, 1, b"", plaintext).unwrap();

        // Same plaintext with different counters should produce different ciphertexts
        assert_ne!(ct1, ct2);

        // Decrypt with correct counter
        let pt1 = decrypt_with_counter(&key, 0, b"", &ct1).unwrap();
        assert_eq!(&pt1, plaintext);

        let pt2 = decrypt_with_counter(&key, 1, b"", &ct2).unwrap();
        assert_eq!(&pt2, plaintext);

        // Decrypt with wrong counter should fail
        assert!(decrypt_with_counter(&key, 0, b"", &ct2).is_err());
    }

    #[test]
    fn test_nonce_from_counter() {
        let nonce = nonce_from_counter(0);
        assert_eq!(nonce, [0u8; 12]);

        let nonce = nonce_from_counter(1);
        assert_eq!(nonce[0..4], [0, 0, 0, 0]);
        assert_eq!(nonce[4..12], 1u64.to_le_bytes());

        let nonce = nonce_from_counter(0x0102030405060708);
        assert_eq!(nonce[4..12], 0x0102030405060708u64.to_le_bytes());
    }

    #[test]
    fn test_large_plaintext_roundtrip() {
        let key = [0x42u8; 32];
        let nonce = [0xABu8; 12];
        let aad = b"associated data";
        let plaintext = b"Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.";

        let ciphertext = encrypt(&key, &nonce, aad, plaintext).unwrap();

        // Ciphertext = plaintext + 16-byte tag
        assert_eq!(ciphertext.len(), plaintext.len() + TAG_SIZE);

        // Verify round-trip decryption
        let decrypted = decrypt(&key, &nonce, aad, &ciphertext).unwrap();
        assert_eq!(&decrypted, plaintext);
    }
}
