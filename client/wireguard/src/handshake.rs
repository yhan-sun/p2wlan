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
use subtle::ConstantTimeEq;

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

fn mac1_matches(
    recipient_public: &PublicKeyBytes,
    msg_for_mac1: &[u8],
    received: &[u8; MAC_SIZE],
) -> bool {
    let expected = compute_mac1(recipient_public, msg_for_mac1);
    bool::from(expected.ct_eq(received))
}

/// Generate a random sender index.
fn random_index() -> u32 {
    let mut rng = rand::thread_rng();
    let mut buf = [0u8; 4];
    rng.fill_bytes(&mut buf);
    u32::from_le_bytes(buf) | 1 // Never zero (0 is reserved)
}

/// WireGuard's TAI64N epoch bias: 2^62 plus the 10-second TAI offset at the
/// Unix epoch. The wire format is 8-byte seconds followed by 4-byte nanos.
const TAI64N_BASE: u64 = 0x4000_0000_0000_000a;

/// Build a canonical WireGuard TAI64N timestamp (12 bytes).
fn build_timestamp() -> [u8; TIMESTAMP_SIZE] {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default();

    let mut ts = [0u8; TIMESTAMP_SIZE];
    let tai_seconds = TAI64N_BASE.saturating_add(now.as_secs());
    ts[0..8].copy_from_slice(&tai_seconds.to_be_bytes());
    ts[8..12].copy_from_slice(&now.subsec_nanos().to_be_bytes());
    ts
}

/// Normalize a timestamp for monotonic replay comparison. New messages use
/// canonical TAI64N. The previous p2wlan encoding accidentally used 4-byte
/// `(unix + 10)` seconds followed by 8-byte nanos; accepting and normalizing
/// that layout keeps rolling upgrades interoperable while new senders emit
/// the standard layout.
fn normalize_timestamp(timestamp: &[u8]) -> Result<[u8; TIMESTAMP_SIZE]> {
    if timestamp.len() != TIMESTAMP_SIZE {
        return Err(WireGuardError::HandshakeFailed(format!(
            "invalid timestamp length: {}",
            timestamp.len()
        )));
    }

    let mut canonical = [0u8; TIMESTAMP_SIZE];
    if timestamp[0] == 0x40 {
        let seconds = u64::from_be_bytes(timestamp[0..8].try_into().unwrap());
        let nanos = u32::from_be_bytes(timestamp[8..12].try_into().unwrap());
        if seconds < TAI64N_BASE || nanos >= 1_000_000_000 {
            return Err(WireGuardError::HandshakeFailed(
                "invalid TAI64N timestamp".into(),
            ));
        }
        canonical.copy_from_slice(timestamp);
        return Ok(canonical);
    }

    let legacy_seconds = u32::from_be_bytes(timestamp[0..4].try_into().unwrap()) as u64;
    let legacy_nanos = u64::from_be_bytes(timestamp[4..12].try_into().unwrap());
    if legacy_seconds < 10 || legacy_nanos >= 1_000_000_000 {
        return Err(WireGuardError::HandshakeFailed(
            "invalid legacy handshake timestamp".into(),
        ));
    }
    let seconds = TAI64N_BASE.saturating_add(legacy_seconds - 10);
    canonical[0..8].copy_from_slice(&seconds.to_be_bytes());
    canonical[8..12].copy_from_slice(&(legacy_nanos as u32).to_be_bytes());
    Ok(canonical)
}

// =============================================================================
// Handshake Initiator
// =============================================================================

/// State for the initiator side of a Noise IK handshake.
#[derive(Clone)]
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
        if self.ephemeral.is_some() {
            return Err(WireGuardError::HandshakeFailed(
                "handshake initiation already created".into(),
            ));
        }

        // 1. Generate ephemeral key pair
        let ephemeral = DhKeyPair::generate();
        let e_pub = ephemeral.public_key();

        // Compute all fallible DH operations before mutating the Noise state.
        // This keeps a failed call retryable and avoids leaving a half-built
        // handshake that would otherwise panic or silently diverge later.
        let dh1 = ephemeral.diffie_hellman(&self.responder_public)?;
        let dh2 = self.identity.diffie_hellman(&self.responder_public)?;
        self.ephemeral = Some(ephemeral);

        // 2. mix_hash(E_i) — mix ephemeral public key into hash
        self.noise.mix_hash(&e_pub);

        // 3. mix_key(DH(e_i, S_r)) — ephemeral × responder static
        self.noise.mix_key(&dh1);

        // 4. encrypt_and_hash(S_i) — encrypt our static public key
        let our_static_pub = self.identity.public_key();
        let enc_static = self.noise.encrypt_and_hash(&our_static_pub);

        // 5. mix_key(DH(S_i, S_r)) — static × static
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
        // Authentication is the final operation in a Noise response.  Work on
        // a clone so a response with the right receiver index but an invalid
        // tag cannot mutate the pending initiator and poison a later valid
        // response.
        let mut staged = self.clone();
        let keys = staged.consume_response_inner(msg)?;
        *self = staged;
        Ok(keys)
    }

    fn consume_response_inner(&mut self, msg: &MessageResponse) -> Result<TransportKeyPair> {
        let ephemeral = self.ephemeral.clone().ok_or_else(|| {
            WireGuardError::HandshakeFailed(
                "cannot consume a response before creating an initiation".into(),
            )
        })?;
        if msg.sender_index == 0 {
            return Err(WireGuardError::HandshakeFailed(
                "response sender_index must not be zero".into(),
            ));
        }
        if msg.mac2 != [0u8; MAC_SIZE] {
            return Err(WireGuardError::InvalidMac(
                "unsupported non-zero response MAC2".into(),
            ));
        }
        // A response is addressed to the initiator, so its MAC1 is keyed by
        // the initiator's static public key. Accept the historical p2wlan key
        // (responder static) during rolling upgrades, but emit only the
        // recipient-keyed form below.
        let mac1_data = msg.bytes_for_mac1();
        let recipient_mac_valid = mac1_matches(&self.identity.public_key(), &mac1_data, &msg.mac1);
        let legacy_mac_valid = mac1_matches(&self.responder_public, &mac1_data, &msg.mac1);
        if !recipient_mac_valid && !legacy_mac_valid {
            return Err(WireGuardError::InvalidMac(
                "response MAC1 verification failed".into(),
            ));
        }

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
        let dh3 = ephemeral.diffie_hellman(&msg.ephemeral)?;
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
#[derive(Clone)]
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
    /// Most recent authenticated, canonical TAI64N timestamp. A caller that
    /// reuses this responder (or seeds a new responder with the floor) rejects
    /// replayed and out-of-order initiations.
    latest_timestamp: Option<[u8; TIMESTAMP_SIZE]>,
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
            latest_timestamp: None,
        }
    }

    /// Create a responder with a previously authenticated timestamp floor.
    /// This is used when responder objects are short-lived but replay state is
    /// retained per peer by the owning daemon.
    pub fn new_with_timestamp_floor(
        identity: NodeIdentity,
        preshared_key: Option<[u8; 32]>,
        timestamp_floor: Option<[u8; TIMESTAMP_SIZE]>,
    ) -> Self {
        let mut responder = Self::new(identity, preshared_key);
        responder.latest_timestamp = timestamp_floor;
        responder
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
        // The final timestamp authentication and response construction mutate
        // Noise state. Stage all work so a bad initiation cannot poison a
        // reusable responder and make the next legitimate initiation fail.
        let mut staged = self.clone();
        let result = staged.consume_initiation_and_respond_inner(msg)?;
        *self = staged;
        Ok(result)
    }

    fn consume_initiation_and_respond_inner(
        &mut self,
        msg: &MessageInitiation,
    ) -> Result<(MessageResponse, TransportKeyPair)> {
        if msg.sender_index == 0 {
            return Err(WireGuardError::HandshakeFailed(
                "initiation sender_index must not be zero".into(),
            ));
        }
        if msg.mac2 != [0u8; MAC_SIZE] {
            return Err(WireGuardError::InvalidMac(
                "unsupported non-zero initiation MAC2".into(),
            ));
        }
        if !mac1_matches(
            &self.identity.public_key(),
            &msg.bytes_for_mac1(),
            &msg.mac1,
        ) {
            return Err(WireGuardError::InvalidMac(
                "initiation MAC1 verification failed".into(),
            ));
        }

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

        // 5. decrypt_and_hash(enc_timestamp) and enforce the per-peer
        // monotonic replay floor.
        let timestamp = self
            .noise
            .decrypt_and_hash(&msg.encrypted_timestamp)
            .map_err(|e| {
                WireGuardError::HandshakeFailed(format!("decrypt timestamp failed: {e}"))
            })?;
        let timestamp = normalize_timestamp(&timestamp)?;
        if self
            .latest_timestamp
            .is_some_and(|latest| timestamp <= latest)
        {
            return Err(WireGuardError::HandshakeFailed(
                "replayed or out-of-order initiation timestamp".into(),
            ));
        }
        self.latest_timestamp = Some(timestamp);

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

        // The response is addressed to the initiator, so MAC1 is keyed with
        // the initiator's authenticated static public key.
        let mac1_data = response.bytes_for_mac1();
        response.mac1 = compute_mac1(&init_pub, &mac1_data);

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

    /// Canonical timestamp authenticated by the latest successful initiation.
    pub fn latest_timestamp(&self) -> Option<[u8; TIMESTAMP_SIZE]> {
        self.latest_timestamp
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
            .field("send_key", &"[redacted]")
            .field("recv_key", &"[redacted]")
            .field("our_index", &self.our_index)
            .field("peer_index", &self.peer_index)
            .finish()
    }
}

include!("handshake/tests.rs");
