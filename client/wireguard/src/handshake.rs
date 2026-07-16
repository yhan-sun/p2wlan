//! Noise IK handshake state machine.
//!
//! Implements the WireGuard Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s handshake:
//!
//! ```text
//! Initiator                          Responder
//! ─────────                          ─────────
//! ← S_r (pre-message: know responder's static public key)
//!
//! → e_i, DH(e_i, S_r), enc(S_i), DH(S_i, S_r), enc(T_i)
//!                                   ← e_r, DH(e_r, e_i), DH(e_r, S_i), psk, enc(∅)
//! ```
//!
//! After the handshake, both parties derive transport keys via HKDF.

use p2pnet_crypto::{
    dh::DhKeyPair,
    hash::{hash2, keyed_hash, Hash},
    noise::SymmetricState,
    NodeIdentity, PublicKeyBytes,
};
use rand::RngCore;

use crate::error::{Result, WireGuardError};
use crate::types::{MessageInitiation, MessageResponse, MAC_SIZE, TIMESTAMP_SIZE};
use zeroize::Zeroize;

/// Compute MAC1 for a handshake message.
///
/// MAC1 = keyed_hash(HASH("mac1----" || responder_public), msg_without_mac1_and_mac2)
fn compute_mac1(responder_public: &PublicKeyBytes, msg_for_mac1: &[u8]) -> [u8; MAC_SIZE] {
    let mac_key = hash2(b"mac1----", responder_public);
    let mac = keyed_hash(&mac_key, msg_for_mac1);
    let mut result = [0u8; MAC_SIZE];
    result.copy_from_slice(&mac[..MAC_SIZE]);
    result
}

/// Generate a random sender index.
fn random_index() -> u32 {
    let mut rng = rand::thread_rng();
    let mut buf = [0u8; 4];
    rng.fill_bytes(&mut buf);
    u32::from_le_bytes(buf) | 1 // Never zero (0 is reserved)
}

/// Build a TAI64N timestamp (12 bytes).
///
/// Format: 4 bytes TAI64 seconds (big-endian, offset from epoch) +
///          8 bytes nanoseconds (big-endian).
fn build_timestamp() -> [u8; TIMESTAMP_SIZE] {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default();

    let mut ts = [0u8; TIMESTAMP_SIZE];
    // TAI64 = UTC + 10 seconds (leap seconds adjustment)
    let tai_seconds = now.as_secs() + 10;
    ts[0..4].copy_from_slice(&(tai_seconds as u32).to_be_bytes());
    let nanos = now.subsec_nanos() as u64;
    ts[4..12].copy_from_slice(&nanos.to_be_bytes());
    ts
}

// =============================================================================
// Handshake Initiator
// =============================================================================

/// State for the initiator side of a Noise IK handshake.
pub struct HandshakeInitiator {
    /// The initiator's node identity (static key pair).
    identity: NodeIdentity,
    /// The responder's static public key.
    responder_public: PublicKeyBytes,
    /// Optional preshared key.
    preshared_key: Option<[u8; 32]>,
    /// The initiator's ephemeral key pair (generated for this handshake).
    ephemeral: Option<DhKeyPair>,
    /// The Noise symmetric state.
    noise: SymmetricState,
    /// Our chosen sender index.
    pub sender_index: u32,
}

impl HandshakeInitiator {
    /// Create a new initiator.
    ///
    /// # Arguments
    ///
    /// * `identity` - Our node identity (static key pair)
    /// * `responder_public` - The responder's static public key (32 bytes)
    /// * `preshared_key` - Optional preshared key for extra security
    pub fn new(
        identity: NodeIdentity,
        responder_public: PublicKeyBytes,
        preshared_key: Option<[u8; 32]>,
    ) -> Self {
        let mut noise = SymmetricState::new();
        // Mix in the responder's static public key as prologue
        noise.mix_responder_static(&responder_public);

        Self {
            identity,
            responder_public,
            preshared_key,
            ephemeral: None,
            noise,
            sender_index: random_index(),
        }
    }

    /// Create the handshake initiation message (Type 1).
    ///
    /// This is message 1 of the Noise IK handshake.
    /// After calling this, the initiator waits for the response.
    pub fn create_initiation(&mut self) -> Result<MessageInitiation> {
        // 1. Generate ephemeral key pair
        let ephemeral = DhKeyPair::generate();
        let e_pub = ephemeral.public_key();
        self.ephemeral = Some(ephemeral);

        // 2. mix_hash(E_i) — mix ephemeral public key into hash
        self.noise.mix_hash(&e_pub);

        // 3. mix_key(DH(e_i, S_r)) — ephemeral × responder static
        let dh1 = self
            .ephemeral
            .as_ref()
            .unwrap()
            .diffie_hellman(&self.responder_public)?;
        self.noise.mix_key(&dh1);

        // 4. encrypt_and_hash(S_i) — encrypt our static public key
        let our_static_pub = self.identity.public_key();
        let enc_static = self.noise.encrypt_and_hash(&our_static_pub);

        // 5. mix_key(DH(S_i, S_r)) — static × static
        let dh2 = self.identity.diffie_hellman(&self.responder_public)?;
        self.noise.mix_key(&dh2);

        // 6. encrypt_and_hash(timestamp)
        let timestamp = build_timestamp();
        let enc_timestamp = self.noise.encrypt_and_hash(&timestamp);

        // Build the message
        let mut msg = MessageInitiation {
            sender_index: self.sender_index,
            ephemeral: e_pub,
            encrypted_static: [0u8; 48],
            encrypted_timestamp: [0u8; 28],
            mac1: [0u8; MAC_SIZE],
            mac2: [0u8; MAC_SIZE],
        };
        msg.encrypted_static.copy_from_slice(&enc_static);
        msg.encrypted_timestamp.copy_from_slice(&enc_timestamp);

        // Compute MAC1
        let mac1_data = msg.bytes_for_mac1();
        msg.mac1 = compute_mac1(&self.responder_public, &mac1_data);
        // MAC2 is all zeros (no cookie)

        Ok(msg)
    }

    /// Process the handshake response message (Type 2).
    ///
    /// This is message 2 of the Noise IK handshake.
    /// After calling this, transport keys are derived and the session is established.
    ///
    /// Returns the transport session keys.
    pub fn consume_response(&mut self, msg: &MessageResponse) -> Result<TransportKeyPair> {
        // Verify receiver_index matches our sender_index
        if msg.receiver_index != self.sender_index {
            return Err(WireGuardError::HandshakeFailed(format!(
                "receiver_index mismatch: got {}, expected {}",
                msg.receiver_index, self.sender_index
            )));
        }

        // 1. mix_hash(E_r) — mix responder's ephemeral public key
        self.noise.mix_hash(&msg.ephemeral);

        // 2. mix_key(DH(e_i, E_r)) — our ephemeral × responder ephemeral
        let dh3 = self
            .ephemeral
            .as_ref()
            .unwrap()
            .diffie_hellman(&msg.ephemeral)?;
        self.noise.mix_key(&dh3);

        // 3. mix_key(DH(S_i, E_r)) — our static × responder ephemeral
        let dh4 = self.identity.diffie_hellman(&msg.ephemeral)?;
        self.noise.mix_key(&dh4);

        // 4. mix_psk(psk_or_zero)
        let psk = self.preshared_key.unwrap_or([0u8; 32]);
        self.noise.mix_psk(&psk);

        // 5. decrypt_and_hash(enc_empty) — should be empty
        let _empty = self
            .noise
            .decrypt_and_hash(&msg.encrypted_empty)
            .map_err(|e| WireGuardError::HandshakeFailed(format!("decrypt empty failed: {e}")))?;

        // 6. Derive transport keys
        let (k1, k2) = self.noise.derive_transport_keys();
        // Initiator: send = k1, recv = k2
        Ok(TransportKeyPair {
            send_key: k1,
            recv_key: k2,
            our_index: self.sender_index,
            peer_index: msg.sender_index,
        })
    }
}

// =============================================================================
// Handshake Responder
// =============================================================================

/// State for the responder side of a Noise IK handshake.
pub struct HandshakeResponder {
    /// The responder's node identity (static key pair).
    identity: NodeIdentity,
    /// Optional preshared key.
    preshared_key: Option<[u8; 32]>,
    /// The responder's ephemeral key pair (generated for this handshake).
    ephemeral: Option<DhKeyPair>,
    /// The initiator's static public key (learned during handshake).
    initiator_public: Option<PublicKeyBytes>,
    /// The initiator's ephemeral public key (from message 1).
    initiator_ephemeral: Option<PublicKeyBytes>,
    /// The Noise symmetric state.
    noise: SymmetricState,
    /// Our chosen sender index.
    pub sender_index: u32,
    /// The initiator's sender index (used as receiver_index in our response).
    initiator_index: u32,
}

impl HandshakeResponder {
    /// Create a new responder.
    ///
    /// # Arguments
    ///
    /// * `identity` - Our node identity (static key pair)
    /// * `preshared_key` - Optional preshared key
    pub fn new(identity: NodeIdentity, preshared_key: Option<[u8; 32]>) -> Self {
        let mut noise = SymmetricState::new();
        // Mix our own static public key as prologue
        noise.mix_responder_static(&identity.public_key());

        Self {
            identity,
            preshared_key,
            ephemeral: None,
            initiator_public: None,
            initiator_ephemeral: None,
            noise,
            sender_index: random_index(),
            initiator_index: 0,
        }
    }

    /// Process the handshake initiation message (Type 1) and create a response (Type 2).
    ///
    /// This processes message 1 and produces message 2 of the Noise IK handshake.
    /// After calling this, transport keys are derived and the session is established.
    ///
    /// Returns the response message and transport session keys.
    pub fn consume_initiation_and_respond(
        &mut self,
        msg: &MessageInitiation,
    ) -> Result<(MessageResponse, TransportKeyPair)> {
        self.initiator_index = msg.sender_index;

        // 1. mix_hash(E_i) — mix initiator's ephemeral public key
        self.initiator_ephemeral = Some(msg.ephemeral);
        self.noise.mix_hash(&msg.ephemeral);

        // 2. mix_key(DH(S_r, E_i)) — our static × initiator ephemeral
        let dh1 = self.identity.diffie_hellman(&msg.ephemeral)?;
        self.noise.mix_key(&dh1);

        // 3. decrypt_and_hash(enc_static) → S_i
        let initiator_static = self
            .noise
            .decrypt_and_hash(&msg.encrypted_static)
            .map_err(|e| WireGuardError::HandshakeFailed(format!("decrypt static failed: {e}")))?;
        let mut init_pub = [0u8; 32];
        init_pub.copy_from_slice(&initiator_static);
        self.initiator_public = Some(init_pub);

        // 4. mix_key(DH(S_r, S_i)) — our static × initiator static
        let dh2 = self.identity.diffie_hellman(&init_pub)?;
        self.noise.mix_key(&dh2);

        // 5. decrypt_and_hash(enc_timestamp) → timestamp (verified but not used)
        let _timestamp = self
            .noise
            .decrypt_and_hash(&msg.encrypted_timestamp)
            .map_err(|e| {
                WireGuardError::HandshakeFailed(format!("decrypt timestamp failed: {e}"))
            })?;

        // === Now create the response message ===

        // 6. Generate ephemeral key pair
        let ephemeral = DhKeyPair::generate();
        let e_pub = ephemeral.public_key();
        self.ephemeral = Some(ephemeral);

        // 7. mix_hash(E_r)
        self.noise.mix_hash(&e_pub);

        // 8. mix_key(DH(e_r, E_i)) — ephemeral × initiator ephemeral
        let dh3 = self
            .ephemeral
            .as_ref()
            .unwrap()
            .diffie_hellman(&msg.ephemeral)?;
        self.noise.mix_key(&dh3);

        // 9. mix_key(DH(e_r, S_i)) — ephemeral × initiator static
        let dh4 = self.ephemeral.as_ref().unwrap().diffie_hellman(&init_pub)?;
        self.noise.mix_key(&dh4);

        // 10. mix_psk(psk_or_zero)
        let psk = self.preshared_key.unwrap_or([0u8; 32]);
        self.noise.mix_psk(&psk);

        // 11. encrypt_and_hash(empty) → just a 16-byte tag
        let enc_empty = self.noise.encrypt_and_hash(&[]);

        // Build the response message
        let mut response = MessageResponse {
            sender_index: self.sender_index,
            receiver_index: self.initiator_index,
            ephemeral: e_pub,
            encrypted_empty: [0u8; 16],
            mac1: [0u8; MAC_SIZE],
            mac2: [0u8; MAC_SIZE],
        };
        response.encrypted_empty.copy_from_slice(&enc_empty);

        // Compute MAC1 (keyed with our public key since we're the responder)
        let mac1_data = response.bytes_for_mac1();
        response.mac1 = compute_mac1(&self.identity.public_key(), &mac1_data);

        // 12. Derive transport keys
        let (k1, k2) = self.noise.derive_transport_keys();
        // Responder: send = k2, recv = k1
        let keys = TransportKeyPair {
            send_key: k2,
            recv_key: k1,
            our_index: self.sender_index,
            peer_index: self.initiator_index,
        };

        Ok((response, keys))
    }

    /// Get the initiator's public key (learned during handshake).
    pub fn initiator_public_key(&self) -> Option<&PublicKeyBytes> {
        self.initiator_public.as_ref()
    }
}

// =============================================================================
// Transport Keys
// =============================================================================

/// Transport key pair derived after a successful handshake.
#[derive(Clone, Zeroize)]
pub struct TransportKeyPair {
    /// Key for sending data.
    pub send_key: Hash,
    /// Key for receiving data.
    pub recv_key: Hash,
    /// Our session index (sender_index).
    pub our_index: u32,
    /// Peer's session index (used as receiver_index in transport messages).
    pub peer_index: u32,
}

impl TransportKeyPair {
    /// Check that both sides derived matching keys (initiator's send = responder's recv).
    pub fn keys_match(&self, other: &TransportKeyPair) -> bool {
        self.send_key == other.recv_key && self.recv_key == other.send_key
    }
}

impl std::fmt::Debug for TransportKeyPair {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TransportKeyPair")
            .field("send_key", &hex::encode(self.send_key))
            .field("recv_key", &hex::encode(self.recv_key))
            .field("our_index", &self.our_index)
            .field("peer_index", &self.peer_index)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_full_handshake() {
        // Generate identities
        let initiator_identity = NodeIdentity::generate();
        let initiator_identity_clone = initiator_identity.clone();
        let responder_identity = NodeIdentity::generate();

        // Create initiator (knows responder's public key)
        let mut initiator =
            HandshakeInitiator::new(initiator_identity, responder_identity.public_key(), None);

        // Create responder (doesn't know initiator yet)
        let mut responder = HandshakeResponder::new(responder_identity, None);

        // Message 1: Initiator → Responder
        let init_msg = initiator.create_initiation().unwrap();

        // Responder processes message 1 and creates response
        let (response, responder_keys) =
            responder.consume_initiation_and_respond(&init_msg).unwrap();

        // Verify responder learned the initiator's public key
        assert_eq!(
            responder.initiator_public_key().unwrap(),
            &initiator_identity_clone.public_key()
        );

        // Message 2: Responder → Initiator
        let initiator_keys = initiator.consume_response(&response).unwrap();

        // Verify keys match: initiator's send = responder's recv and vice versa
        assert_eq!(initiator_keys.send_key, responder_keys.recv_key);
        assert_eq!(initiator_keys.recv_key, responder_keys.send_key);

        // Verify indices
        assert_eq!(initiator_keys.our_index, responder_keys.peer_index);
        assert_eq!(initiator_keys.peer_index, responder_keys.our_index);
    }

    #[test]
    fn test_handshake_with_psk() {
        let initiator_identity = NodeIdentity::generate();
        let responder_identity = NodeIdentity::generate();
        let psk = [0x42u8; 32];

        let mut initiator = HandshakeInitiator::new(
            initiator_identity,
            responder_identity.public_key(),
            Some(psk),
        );
        let mut responder = HandshakeResponder::new(responder_identity, Some(psk));

        let init_msg = initiator.create_initiation().unwrap();
        let (response, responder_keys) =
            responder.consume_initiation_and_respond(&init_msg).unwrap();
        let initiator_keys = initiator.consume_response(&response).unwrap();

        // Keys should match
        assert!(initiator_keys.keys_match(&responder_keys));
    }

    #[test]
    fn test_handshake_none_psk_works() {
        // Verify that a handshake with None PSK completes successfully
        // (internally treated as all-zeros PSK)
        let init_id = NodeIdentity::generate();
        let resp_id = NodeIdentity::generate();

        let mut init = HandshakeInitiator::new(init_id, resp_id.public_key(), None);
        let mut resp = HandshakeResponder::new(resp_id, None);

        let msg = init.create_initiation().unwrap();
        let (resp_msg, resp_keys) = resp.consume_initiation_and_respond(&msg).unwrap();
        let init_keys = init.consume_response(&resp_msg).unwrap();

        // Keys must match across both sides
        assert!(init_keys.keys_match(&resp_keys));
    }

    #[test]
    fn test_wrong_responder_key_fails() {
        let initiator_identity = NodeIdentity::generate();
        let wrong_responder = NodeIdentity::generate();
        let actual_responder = NodeIdentity::generate();

        // Initiator thinks the responder has the wrong key
        let mut initiator =
            HandshakeInitiator::new(initiator_identity, wrong_responder.public_key(), None);
        let mut responder = HandshakeResponder::new(actual_responder, None);

        let init_msg = initiator.create_initiation().unwrap();

        // Responder should fail to decrypt (wrong key)
        let result = responder.consume_initiation_and_respond(&init_msg);
        assert!(result.is_err());
    }

    #[test]
    fn test_random_index_nonzero() {
        let indices: Vec<u32> = (0..10).map(|_| random_index()).collect();
        for idx in &indices {
            assert_ne!(*idx, 0);
        }
    }

    #[test]
    fn test_timestamp_size() {
        let ts = build_timestamp();
        assert_eq!(ts.len(), TIMESTAMP_SIZE);
    }

    #[test]
    fn test_mac1_computation() {
        let responder_pub = NodeIdentity::generate().public_key();
        let data = b"test message for mac1";
        let mac1 = compute_mac1(&responder_pub, data);

        // Same inputs should produce same MAC
        let mac1_2 = compute_mac1(&responder_pub, data);
        assert_eq!(mac1, mac1_2);

        // Different responder should produce different MAC
        let other_pub = NodeIdentity::generate().public_key();
        let mac1_3 = compute_mac1(&other_pub, data);
        assert_ne!(mac1, mac1_3);
    }
}
