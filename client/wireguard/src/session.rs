//! Transport session: encrypt and decrypt IP packets after handshake.
//!
//! Uses ChaCha20-Poly1305 AEAD with counter-based nonces.
//! Implements replay protection via a sliding window.

use std::time::{Duration, Instant};

use p2pnet_crypto::aead::{decrypt_with_counter, encrypt_with_counter};
use p2pnet_crypto::{
    Hash, REJECT_AFTER_MESSAGES, REJECT_AFTER_TIME, REKEY_AFTER_MESSAGES, REKEY_AFTER_TIME,
};

use crate::error::{Result, WireGuardError};
use crate::handshake::TransportKeyPair;
use crate::types::MessageTransport;

/// Sliding window size for replay protection (64 packets).
const REPLAY_WINDOW_SIZE: u64 = 64;

/// An established transport session for a single peer.
///
/// Handles encryption and decryption of IP packets using the
/// transport keys derived from the Noise IK handshake.
pub struct TransportSession {
    /// Key for sending data.
    send_key: Hash,
    /// Key for receiving data.
    recv_key: Hash,
    /// Our session index (used in the receiver_index field of outgoing messages).
    our_index: u32,
    /// Peer's session index (used to identify incoming messages).
    peer_index: u32,
    /// Current send counter (incremented per packet).
    send_counter: u64,
    /// Highest received counter (for replay protection).
    recv_highest: u64,
    /// Bitmap for the replay window (tracks which counters have been seen).
    replay_bitmap: u64,
    /// Whether we've received at least one packet.
    replay_initialized: bool,
    /// When this session was created (for time-based rekey / reject).
    created_at: Instant,
    /// Optional overrides used by tests to exercise rekey without waiting 2 minutes.
    rekey_after_messages: u64,
    rekey_after_time: Duration,
    reject_after_messages: u64,
    reject_after_time: Duration,
}

impl TransportSession {
    /// Create a new transport session from handshake-derived keys.
    pub fn new(keys: TransportKeyPair) -> Self {
        Self {
            send_key: keys.send_key,
            recv_key: keys.recv_key,
            our_index: keys.our_index,
            peer_index: keys.peer_index,
            send_counter: 0,
            recv_highest: 0,
            replay_bitmap: 0,
            replay_initialized: false,
            created_at: Instant::now(),
            rekey_after_messages: REKEY_AFTER_MESSAGES,
            rekey_after_time: Duration::from_secs(REKEY_AFTER_TIME),
            reject_after_messages: REJECT_AFTER_MESSAGES,
            reject_after_time: Duration::from_secs(REJECT_AFTER_TIME),
        }
    }

    /// Override rekey/reject thresholds (tests and controlled environments).
    pub fn with_thresholds(
        mut self,
        rekey_after_messages: u64,
        rekey_after_time: Duration,
        reject_after_messages: u64,
        reject_after_time: Duration,
    ) -> Self {
        self.rekey_after_messages = rekey_after_messages;
        self.rekey_after_time = rekey_after_time;
        self.reject_after_messages = reject_after_messages;
        self.reject_after_time = reject_after_time;
        self
    }

    /// Age of this session.
    pub fn age(&self) -> Duration {
        self.created_at.elapsed()
    }

    /// Instant when this session was created.
    pub fn created_at(&self) -> Instant {
        self.created_at
    }

    /// Get our session index.
    pub fn our_index(&self) -> u32 {
        self.our_index
    }

    /// Get the peer's session index.
    pub fn peer_index(&self) -> u32 {
        self.peer_index
    }

    /// Get the current send counter.
    pub fn send_counter(&self) -> u64 {
        self.send_counter
    }

    /// Encrypt an IP packet into a WireGuard transport message.
    ///
    /// # Arguments
    ///
    /// * `packet` - The raw IP packet to encrypt
    ///
    /// # Returns
    ///
    /// A WireGuard transport data message (Type 4).
    pub fn encrypt(&mut self, packet: &[u8]) -> Result<MessageTransport> {
        if self.is_expired() {
            return Err(WireGuardError::InvalidPacket(
                "session expired; rekey required".into(),
            ));
        }
        if self.send_counter == u64::MAX {
            return Err(WireGuardError::NonceOverflow);
        }

        let counter = self.send_counter;

        // The associated data for transport messages is empty in WireGuard.
        // But the nonce encodes the counter, and the receiver_index identifies the session.
        // Actually, WireGuard transport messages use empty AAD.
        let encrypted = encrypt_with_counter(&self.send_key, counter, b"", packet)?;

        self.send_counter += 1;

        Ok(MessageTransport {
            receiver_index: self.peer_index,
            counter,
            encrypted_payload: encrypted,
        })
    }

    /// Encrypt a packet and serialize to wire format in one call.
    pub fn encrypt_to_bytes(&mut self, packet: &[u8]) -> Result<Vec<u8>> {
        let msg = self.encrypt(packet)?;
        Ok(msg.to_bytes())
    }

    /// Decrypt a WireGuard transport message into an IP packet.
    ///
    /// # Arguments
    ///
    /// * `msg` - The received transport data message
    ///
    /// # Returns
    ///
    /// The decrypted IP packet, or an error if decryption fails or replay is detected.
    pub fn decrypt(&mut self, msg: &MessageTransport) -> Result<Vec<u8>> {
        if self.is_expired() {
            return Err(WireGuardError::InvalidPacket(
                "session expired; rekey required".into(),
            ));
        }
        // Verify the message is addressed to us
        if msg.receiver_index != self.our_index {
            return Err(WireGuardError::InvalidPacket(format!(
                "receiver_index mismatch: got {}, expected {}",
                msg.receiver_index, self.our_index
            )));
        }

        // Replay protection
        if !self.check_replay(msg.counter) {
            return Err(WireGuardError::ReplayDetected(msg.counter));
        }

        // Decrypt
        let plaintext =
            decrypt_with_counter(&self.recv_key, msg.counter, b"", &msg.encrypted_payload)
                .map_err(|_| WireGuardError::DecryptionFailed)?;

        // Mark this counter as received
        self.update_replay(msg.counter);

        Ok(plaintext)
    }

    /// Decrypt from raw wire-format bytes.
    pub fn decrypt_from_bytes(&mut self, data: &[u8]) -> Result<Vec<u8>> {
        let msg = MessageTransport::from_bytes(data)?;
        self.decrypt(&msg)
    }

    /// Check if a counter is within the replay window (not a replay).
    ///
    /// Uses a sliding window of `REPLAY_WINDOW_SIZE` packets.
    fn check_replay(&self, counter: u64) -> bool {
        // First packet is always accepted
        if !self.replay_initialized {
            return true;
        }

        // Counter is above the highest seen → valid (new)
        if counter > self.recv_highest {
            return true;
        }

        // Counter is below the window → replay
        if counter + REPLAY_WINDOW_SIZE <= self.recv_highest {
            return false;
        }

        // Counter is within the window → check bitmap
        let offset = self.recv_highest - counter;
        if offset >= 64 {
            return false;
        }
        let bit = 1u64 << offset;
        (self.replay_bitmap & bit) == 0
    }

    /// Update the replay window after receiving a valid packet.
    fn update_replay(&mut self, counter: u64) {
        if !self.replay_initialized {
            self.replay_initialized = true;
            self.recv_highest = counter;
            self.replay_bitmap = 1; // Set bit 0 for the current highest
            return;
        }

        if counter > self.recv_highest {
            // Shift bitmap: old bits move up, new bit 0 for new highest
            let shift = counter - self.recv_highest;
            if shift >= 64 {
                self.replay_bitmap = 1; // All old counters are out of window
            } else {
                self.replay_bitmap = (self.replay_bitmap << shift) | 1;
            }
            self.recv_highest = counter;
        } else if counter < self.recv_highest {
            // Mark this counter as seen within the window
            let offset = self.recv_highest - counter;
            if offset < 64 {
                self.replay_bitmap |= 1u64 << offset;
            }
        } else {
            // counter == recv_highest: mark bit 0
            self.replay_bitmap |= 1;
        }
    }

    /// Check if rekeying is needed (message counter or time threshold).
    pub fn needs_rekey(&self) -> bool {
        self.send_counter >= self.rekey_after_messages || self.age() >= self.rekey_after_time
    }

    /// Check if the session has exceeded its hard lifetime and must be rejected.
    pub fn is_expired(&self) -> bool {
        self.send_counter >= self.reject_after_messages || self.age() >= self.reject_after_time
    }
}

impl std::fmt::Debug for TransportSession {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TransportSession")
            .field("our_index", &self.our_index)
            .field("peer_index", &self.peer_index)
            .field("send_counter", &self.send_counter)
            .field("recv_highest", &self.recv_highest)
            .field("age_secs", &self.age().as_secs())
            .field("needs_rekey", &self.needs_rekey())
            .field("is_expired", &self.is_expired())
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
include!("session/tests.rs");
