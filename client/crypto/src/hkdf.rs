//! HKDF (HMAC-based Key Derivation Function) using BLAKE2s-256.
//!
//! WireGuard's Noise protocol uses HKDF with BLAKE2s as the hash function.
//! This implements the exact same HKDF as specified in RFC 5869, but with
//! BLAKE2s-256 replacing SHA-256.

use crate::hash::{hmac, Hash};

/// HKDF extract step: derive a pseudo-random key from input key material.
///
/// `PRK = HMAC(salt, IKM)`
pub fn extract(salt: &[u8], ikm: &[u8]) -> Hash {
    hmac(salt, ikm)
}

/// HKDF expand step: derive output keying material from a PRK.
///
/// Produces `n` blocks of 32 bytes each (max 255 blocks).
///
/// ```text
/// T(0) = empty
/// T(i) = HMAC(PRK, T(i-1) || info || i)
/// OKM = T(1) || T(2) || ... || T(n)
/// ```
pub fn expand(prk: &Hash, info: &[u8], n: u8) -> Vec<Hash> {
    assert!(n > 0, "HKDF expand requires at least 1 output");

    let mut outputs = Vec::with_capacity(n as usize);
    let mut t_prev: Vec<u8> = Vec::new();

    for i in 1..=n {
        // T(i) = HMAC(PRK, T(i-1) || info || i)
        let mut input = Vec::with_capacity(t_prev.len() + info.len() + 1);
        input.extend_from_slice(&t_prev);
        input.extend_from_slice(info);
        input.push(i);

        let t_i = hmac(prk, &input);
        t_prev = t_i.to_vec();
        outputs.push(t_i);
    }

    outputs
}

/// HKDF: extract + expand, producing 2 output keys (most common in Noise).
///
/// This is the exact operation used by WireGuard's `MixKey`:
/// ```text
/// prk = HMAC(ck, input_key_material)
/// k1 = HMAC(prk, 0x01)
/// k2 = HMAC(prk, k1 || 0x02)
/// (ck, temp_k) = (k1, k2)
/// ```
///
/// Returns `(k1, k2)` where `k1` becomes the new chaining key and
/// `k2` becomes the temporary encryption key.
pub fn hkdf2(chaining_key: &Hash, input_key_material: &[u8]) -> (Hash, Hash) {
    let prk = extract(chaining_key, input_key_material);
    let outputs = expand(&prk, &[], 2);
    (outputs[0], outputs[1])
}

/// HKDF: extract + expand, producing 3 output keys.
///
/// Used for deriving transport keys with preshared key.
pub fn hkdf3(chaining_key: &Hash, input_key_material: &[u8]) -> (Hash, Hash, Hash) {
    let prk = extract(chaining_key, input_key_material);
    let outputs = expand(&prk, &[], 3);
    (outputs[0], outputs[1], outputs[2])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hkdf2_deterministic() {
        let ck = [0x42u8; 32];
        let ikm = b"input key material";

        let (k1a, k2a) = hkdf2(&ck, ikm);
        let (k1b, k2b) = hkdf2(&ck, ikm);

        assert_eq!(k1a, k1b);
        assert_eq!(k2a, k2b);
    }

    #[test]
    fn test_hkdf2_different_inputs() {
        let ck = [0x42u8; 32];

        let (k1a, k2a) = hkdf2(&ck, b"input1");
        let (k1b, k2b) = hkdf2(&ck, b"input2");

        assert_ne!(k1a, k1b);
        assert_ne!(k2a, k2b);
    }

    #[test]
    fn test_hkdf2_different_chaining_keys() {
        let ck1 = [0x42u8; 32];
        let ck2 = [0x43u8; 32];

        let (k1a, _) = hkdf2(&ck1, b"input");
        let (k1b, _) = hkdf2(&ck2, b"input");

        assert_ne!(k1a, k1b);
    }

    #[test]
    fn test_hkdf2_empty_ikm() {
        let ck = [0x42u8; 32];
        let (k1, k2) = hkdf2(&ck, b"");
        assert_ne!(k1, ck); // Should be different from the chaining key
        assert_ne!(k2, [0u8; 32]); // Should not be all zeros
    }

    #[test]
    fn test_hkdf3() {
        let ck = [0x42u8; 32];
        let ikm = b"test ikm";
        let (k1, k2, k3) = hkdf3(&ck, ikm);

        // All three should be different
        assert_ne!(k1, k2);
        assert_ne!(k2, k3);
        assert_ne!(k1, k3);

        // k1 and k2 should match hkdf2 output
        let (k1_2, k2_2) = hkdf2(&ck, ikm);
        assert_eq!(k1, k1_2);
        assert_eq!(k2, k2_2);
    }

    #[test]
    fn test_expand_max_outputs() {
        let prk = [0x42u8; 32];
        let outputs = expand(&prk, b"info", 10);
        assert_eq!(outputs.len(), 10);

        // All outputs should be different
        for i in 0..10 {
            for j in (i + 1)..10 {
                assert_ne!(outputs[i], outputs[j]);
            }
        }
    }
}
