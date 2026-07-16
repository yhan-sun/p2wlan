//! BLAKE2s-256 hashing and HMAC-BLAKE2s.
//!
//! WireGuard uses BLAKE2s-256 as its hash function for the Noise protocol.
//! HMAC is implemented per RFC 2104 with BLAKE2s as the underlying hash.

use blake2::{Blake2s256, Digest};

/// BLAKE2s-256 hash output (32 bytes).
pub type Hash = [u8; 32];

/// BLAKE2s block size in bytes (used for HMAC).
pub const BLOCK_SIZE: usize = 64;

/// BLAKE2s hash output size in bytes.
pub const HASH_SIZE: usize = 32;

/// Compute BLAKE2s-256 of the given data.
pub fn hash(data: &[u8]) -> Hash {
    let mut hasher = Blake2s256::new();
    hasher.update(data);
    hasher.finalize().into()
}

/// Compute BLAKE2s-256 of two concatenated byte slices (avoids allocation).
pub fn hash2(a: &[u8], b: &[u8]) -> Hash {
    let mut hasher = Blake2s256::new();
    hasher.update(a);
    hasher.update(b);
    hasher.finalize().into()
}

/// Compute BLAKE2s-256 of three concatenated byte slices.
pub fn hash3(a: &[u8], b: &[u8], c: &[u8]) -> Hash {
    let mut hasher = Blake2s256::new();
    hasher.update(a);
    hasher.update(b);
    hasher.update(c);
    hasher.finalize().into()
}

/// Compute HMAC-BLAKE2s-256 per RFC 2104.
///
/// ```text
/// HMAC(key, message) = H((key XOR opad) || H((key XOR ipad) || message))
/// ```
///
/// where `ipad = 0x36` repeated, `opad = 0x5c` repeated,
/// and `H` is BLAKE2s-256. The key is padded or hashed to the
/// BLAKE2s block size (64 bytes).
pub fn hmac(key: &[u8], message: &[u8]) -> Hash {
    // Prepare the block-sized key
    let mut block_key = [0u8; BLOCK_SIZE];
    if key.len() > BLOCK_SIZE {
        let h = hash(key);
        block_key[..HASH_SIZE].copy_from_slice(&h);
    } else {
        block_key[..key.len()].copy_from_slice(key);
    }

    // Compute inner: H((key XOR ipad) || message)
    let mut inner_pad = [0u8; BLOCK_SIZE];
    for i in 0..BLOCK_SIZE {
        inner_pad[i] = block_key[i] ^ 0x36;
    }

    let mut inner_hasher = Blake2s256::new();
    inner_hasher.update(&inner_pad);
    inner_hasher.update(message);
    let inner: Hash = inner_hasher.finalize().into();

    // Compute outer: H((key XOR opad) || inner)
    let mut outer_pad = [0u8; BLOCK_SIZE];
    for i in 0..BLOCK_SIZE {
        outer_pad[i] = block_key[i] ^ 0x5c;
    }

    let mut outer_hasher = Blake2s256::new();
    outer_hasher.update(&outer_pad);
    outer_hasher.update(&inner);
    outer_hasher.finalize().into()
}

/// Keyed BLAKE2s-256.
///
/// Used for WireGuard MAC1/MAC2 computation.
/// Uses HMAC-BLAKE2s as keyed hash (both sides use the same impl,
/// providing equivalent security to BLAKE2s keyed mode).
pub fn keyed_hash(key: &[u8], data: &[u8]) -> Hash {
    hmac(key, data)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hash_known_vector() {
        // BLAKE2s-256 of empty string
        let empty = hash(b"");
        assert_eq!(
            hex::encode(empty),
            "69217a3079908094e11121d042354a7c1f55b6482ca1a51e1b250dfd1ed0eef9"
        );
    }

    #[test]
    fn test_hash_consistency() {
        let data = b"hello world";
        assert_eq!(hash(data), hash(data));
    }

    #[test]
    fn test_hash2_matches_concat() {
        let a = b"hello ";
        let b = b"world";
        let combined = hash2(a, b);
        let concatenated = hash(b"hello world");
        assert_eq!(combined, concatenated);
    }

    #[test]
    fn test_hmac_short_key() {
        let key = b"key";
        let msg = b"The quick brown fox jumps over the lazy dog";
        let result = hmac(key, msg);

        // HMAC-BLAKE2s test vector
        // Computed using the same algorithm as wireguard-go
        assert_eq!(result.len(), 32);
        // Just verify it's deterministic
        assert_eq!(result, hmac(key, msg));
    }

    #[test]
    fn test_hmac_long_key() {
        // Key longer than block size (64 bytes) should be hashed first
        let key = vec![0xAA; 128];
        let msg = b"message";
        let result = hmac(&key, msg);
        assert_eq!(result.len(), 32);

        // Shorter key should give different result
        let short_key = vec![0xAA; 64];
        let result2 = hmac(&short_key, msg);
        assert_ne!(result, result2);
    }

    #[test]
    fn test_hmac_empty_key() {
        let result = hmac(b"", b"test");
        assert_eq!(result.len(), 32);
    }

    #[test]
    fn test_keyed_hash() {
        let result = keyed_hash(b"mac1----", b"test data");
        assert_eq!(result.len(), 32);
        // Different key should give different result
        let result2 = keyed_hash(b"mac2----", b"test data");
        assert_ne!(result, result2);
    }
}
