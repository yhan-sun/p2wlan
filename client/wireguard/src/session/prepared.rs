//! Output storage without keys, counters or session authority.

use super::{Result, TransportSession, WireGuardError};
use crate::types::{AEAD_TAG_SIZE, TRANSPORT_MSG_MIN_SIZE, TYPE_TRANSPORT};
use p2pnet_crypto::aead::encrypt_in_place_with_counter;

const HEADER_SIZE: usize = TRANSPORT_MSG_MIN_SIZE - AEAD_TAG_SIZE;

/// One zeroed wire buffer that may be allocated before acquiring session locks.
/// Preparing it neither encrypts plaintext nor consumes a session counter.
pub struct PreparedTransportBuffer {
    wire: Vec<u8>,
    plaintext_len: usize,
    padded_plaintext_len: usize,
}

impl PreparedTransportBuffer {
    pub fn new(plaintext_len: usize) -> Result<Self> {
        Self::with_length(plaintext_len, plaintext_len)
    }

    /// Opt in to sixteen-byte length buckets only for one complete IPv4 or
    /// IPv6 packet. Invalid, already-trailed or non-IP inputs stay unpadded.
    /// This reads the IP length without copying plaintext or allocating a nonce.
    pub fn new_with_ip_padding(packet: &[u8]) -> Result<Self> {
        if super::padding::complete_ip_len(packet) != Some(packet.len()) {
            return Self::new(packet.len());
        }
        let bucket = super::padding::IP_PADDING_BUCKET;
        let padded =
            packet.len().checked_add(bucket - 1).ok_or_else(|| {
                WireGuardError::InvalidPacket("IP padding length overflow".into())
            })? / bucket
                * bucket;
        Self::with_length(packet.len(), padded)
    }

    /// Padding never displaces an otherwise admissible original packet. If
    /// its next bucket exceeds the current path budget, send the original size.
    pub fn limit_ip_padding(&mut self, max_plaintext_len: usize) {
        if self.padded_plaintext_len > max_plaintext_len {
            self.padded_plaintext_len = self.plaintext_len;
        }
    }

    fn with_length(plaintext_len: usize, padded_plaintext_len: usize) -> Result<Self> {
        let wire_len = padded_plaintext_len
            .checked_add(TRANSPORT_MSG_MIN_SIZE)
            .ok_or_else(|| {
                WireGuardError::InvalidPacket("transport buffer length overflow".into())
            })?;
        let mut wire = Vec::new();
        wire.try_reserve_exact(wire_len).map_err(|error| {
            WireGuardError::InvalidPacket(format!("transport buffer allocation failed: {error}"))
        })?;
        wire.resize(wire_len, 0);
        Ok(Self {
            wire,
            plaintext_len,
            padded_plaintext_len,
        })
    }

    /// Read-only access for observing the concrete allocation's length/capacity.
    pub fn buffer(&self) -> &Vec<u8> {
        &self.wire
    }
}

impl TransportSession {
    /// Use prepared storage with this session's current key, index and counter.
    /// Plaintext is copied only here, at the original encryption boundary.
    pub fn encrypt_into_prepared(
        &mut self,
        packet: &[u8],
        mut prepared: PreparedTransportBuffer,
    ) -> Result<Vec<u8>> {
        let ((), counter) = self.encrypt_payload(|key, counter| {
            if prepared.plaintext_len != packet.len() {
                return Err(WireGuardError::InvalidPacket(
                    "prepared transport buffer length mismatch".into(),
                ));
            }
            // Revalidate the actual encryption input rather than trusting the
            // earlier preparation snapshot. No allocation occurs under crypto.
            let payload_len = if prepared.padded_plaintext_len > prepared.plaintext_len
                && super::padding::complete_ip_len(packet) == Some(packet.len())
            {
                prepared.padded_plaintext_len
            } else {
                packet.len()
            };
            prepared.wire.truncate(payload_len + TRANSPORT_MSG_MIN_SIZE);
            let payload_end = HEADER_SIZE + payload_len;
            let payload = &mut prepared.wire[HEADER_SIZE..payload_end];
            payload[..packet.len()].copy_from_slice(packet);
            payload[packet.len()..].fill(0);
            let tag = encrypt_in_place_with_counter(key, counter, b"", payload)?;
            prepared.wire[payload_end..].copy_from_slice(&tag);
            Ok(())
        })?;
        prepared.wire[..4].copy_from_slice(&u32::from(TYPE_TRANSPORT).to_le_bytes());
        prepared.wire[4..8].copy_from_slice(&self.peer_index.to_le_bytes());
        prepared.wire[8..HEADER_SIZE].copy_from_slice(&counter.to_le_bytes());
        Ok(prepared.wire)
    }
}
