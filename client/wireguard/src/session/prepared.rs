//! Output storage without keys, counters or session authority.

use super::{Result, TransportSession, WireGuardError};
use crate::types::{AEAD_TAG_SIZE, TRANSPORT_MSG_MIN_SIZE, TYPE_TRANSPORT};
use p2pnet_crypto::aead::{decrypt_in_place_with_counter, encrypt_in_place_with_counter};
use p2pnet_crypto::packet_buf::PacketBuf;

const HEADER_SIZE: usize = TRANSPORT_MSG_MIN_SIZE - AEAD_TAG_SIZE;

/// One zeroed wire buffer that may be allocated before acquiring session locks.
/// Preparing it neither encrypts plaintext nor consumes a session counter.
pub struct PreparedTransportBuffer {
    wire: Vec<u8>,
}

impl PreparedTransportBuffer {
    pub fn new(plaintext_len: usize) -> Result<Self> {
        let wire_len = plaintext_len
            .checked_add(TRANSPORT_MSG_MIN_SIZE)
            .ok_or_else(|| {
                WireGuardError::InvalidPacket("transport buffer length overflow".into())
            })?;
        let mut wire = Vec::new();
        wire.try_reserve_exact(wire_len).map_err(|error| {
            WireGuardError::InvalidPacket(format!("transport buffer allocation failed: {error}"))
        })?;
        wire.resize(wire_len, 0);
        Ok(Self { wire })
    }

    /// Read-only access for observing the concrete allocation's length/capacity.
    pub fn buffer(&self) -> &Vec<u8> {
        &self.wire
    }
}

impl TransportSession {
    pub fn seal_packet(&mut self, packet: &mut PacketBuf) -> Result<()> {
        if !packet.can_frame(HEADER_SIZE, AEAD_TAG_SIZE) {
            return Err(WireGuardError::InvalidPacket(
                "insufficient packet headroom or tailroom".into(),
            ));
        }
        let (tag, counter) = self.encrypt_payload(|key, counter| {
            Ok(encrypt_in_place_with_counter(
                key,
                counter,
                b"",
                packet.bytes_mut(),
            )?)
        })?;
        let mut header = [0; HEADER_SIZE];
        header[..4].copy_from_slice(&u32::from(TYPE_TRANSPORT).to_le_bytes());
        header[4..8].copy_from_slice(&self.peer_index.to_le_bytes());
        header[8..].copy_from_slice(&counter.to_le_bytes());
        let _ = packet.prepend(&header);
        let _ = packet.append(&tag);
        Ok(())
    }

    pub fn open_packet(&mut self, packet: &mut PacketBuf) -> Result<()> {
        let (index, counter, tag) = frame_header(packet.bytes())?;
        self.authorize_receive(index, counter)?;
        open_payload(&self.recv_key, counter, packet, &tag)?;
        self.update_replay(counter);
        Ok(())
    }
    /// Undo a locally sealed packet after the kernel declined the complete
    /// datagram. Its counter remains consumed, even when retried.
    pub fn restore_unsent_packet(&self, packet: &mut PacketBuf) -> Result<()> {
        let (index, counter, tag) = frame_header(packet.bytes())?;
        if index != self.peer_index || counter >= self.send_counter {
            return Err(WireGuardError::InvalidPacket(
                "not a locally sealed counter".into(),
            ));
        }
        open_payload(&self.send_key, counter, packet, &tag)
    }

    /// Use prepared storage with this session's current key, index and counter.
    /// Plaintext is copied only here, at the original encryption boundary.
    pub fn encrypt_into_prepared(
        &mut self,
        packet: &[u8],
        mut prepared: PreparedTransportBuffer,
    ) -> Result<Vec<u8>> {
        let ((), counter) = self.encrypt_payload(|key, counter| {
            if prepared.wire.len().checked_sub(TRANSPORT_MSG_MIN_SIZE) != Some(packet.len()) {
                return Err(WireGuardError::InvalidPacket(
                    "prepared transport buffer length mismatch".into(),
                ));
            }
            let payload_end = HEADER_SIZE + packet.len();
            let payload = &mut prepared.wire[HEADER_SIZE..payload_end];
            payload.copy_from_slice(packet);
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

fn open_payload(
    key: &[u8; 32],
    counter: u64,
    packet: &mut PacketBuf,
    tag: &[u8; AEAD_TAG_SIZE],
) -> Result<()> {
    let end = packet.len() - AEAD_TAG_SIZE;
    decrypt_in_place_with_counter(
        key,
        counter,
        b"",
        &mut packet.bytes_mut()[HEADER_SIZE..end],
        tag,
    )
    .map_err(|_| WireGuardError::DecryptionFailed)?;
    let _ = packet.trim(HEADER_SIZE, AEAD_TAG_SIZE);
    Ok(())
}

pub(super) fn frame_header(wire: &[u8]) -> Result<(u32, u64, [u8; AEAD_TAG_SIZE])> {
    if wire.len() < TRANSPORT_MSG_MIN_SIZE {
        return Err(WireGuardError::InvalidPacket(format!(
            "transport message too short: {} < {}",
            wire.len(),
            TRANSPORT_MSG_MIN_SIZE
        )));
    }
    if wire[0] != TYPE_TRANSPORT {
        return Err(WireGuardError::InvalidMessageType(wire[0]));
    }
    if wire[1..4] != [0, 0, 0] {
        return Err(WireGuardError::InvalidPacket(
            "transport message reserved bytes must be zero".into(),
        ));
    }
    let mut index = [0u8; 4];
    let mut counter = [0u8; 8];
    let mut tag = [0u8; AEAD_TAG_SIZE];
    index.copy_from_slice(&wire[4..8]);
    counter.copy_from_slice(&wire[8..HEADER_SIZE]);
    tag.copy_from_slice(&wire[wire.len() - AEAD_TAG_SIZE..]);
    Ok((u32::from_le_bytes(index), u64::from_le_bytes(counter), tag))
}
