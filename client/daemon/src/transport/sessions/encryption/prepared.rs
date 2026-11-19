//! Move-only output storage, owned by the bounded original preparation future.

use std::sync::Arc;

use p2pnet_wireguard::{PreparedTransportBuffer, TransportSession, WireGuardError};

use super::{EncryptedOutboundWithSource, OriginalEncryptionSource};
use crate::dataplane::OutboundPacket;
use crate::dataplane_resources::{
    BufferStage, OwnedBufferLease, ResidencyLease, ResidencyStage, ResourceCapture,
};
use crate::error::{DaemonError, Result};
use crate::transport::EncryptedPeerPacket;

pub(crate) struct PreparedEncryptionBuffer(Box<PreparedStorage>);

struct PreparedStorage {
    wire: Option<PreparedTransportBuffer>,
    residency: Option<ResidencyLease>,
    _buffer_lease: Option<OwnedBufferLease>,
}

impl PreparedEncryptionBuffer {
    pub(crate) fn new(
        plaintext_len: usize,
        capture: Option<&Arc<ResourceCapture>>,
    ) -> Result<Self> {
        let wire = PreparedTransportBuffer::new(plaintext_len).map_err(|error| {
            DaemonError::Peer(format!("WireGuard buffer preparation failed: {error}"))
        })?;
        Ok(Self::observe(wire, capture))
    }

    pub(crate) fn new_for_business(
        packet: &[u8],
        padding_16: bool,
        capture: Option<&Arc<ResourceCapture>>,
    ) -> Result<Self> {
        if !padding_16 || crate::transport::wire::is_internal_control_packet(packet) {
            return Self::new(packet.len(), capture);
        }
        let wire = PreparedTransportBuffer::new_with_ip_padding(packet).map_err(|error| {
            DaemonError::Peer(format!("WireGuard buffer preparation failed: {error}"))
        })?;
        Ok(Self::observe(wire, capture))
    }

    pub(crate) fn limit_ip_padding(&mut self, max_plaintext_len: usize) {
        if let Some(wire) = self.0.wire.as_mut() {
            wire.limit_ip_padding(max_plaintext_len);
        }
    }

    fn observe(wire: PreparedTransportBuffer, capture: Option<&Arc<ResourceCapture>>) -> Self {
        // Storage is not ciphertext yet and grants no successful-encryption source.
        let residency = capture.and_then(|capture| {
            ResidencyLease::observe(capture, ResidencyStage::PreparationPlaintext, wire.buffer())
        });
        let buffer_lease =
            OwnedBufferLease::observe(capture, BufferStage::PreparationPlaintext, wire.buffer());
        Self(Box::new(PreparedStorage {
            wire: Some(wire),
            residency,
            _buffer_lease: buffer_lease,
        }))
    }

    pub(super) fn encrypt(
        &mut self,
        session: &mut TransportSession,
        packet: &[u8],
    ) -> p2pnet_wireguard::Result<Vec<u8>> {
        let wire = self.0.wire.take().ok_or_else(|| {
            WireGuardError::InvalidPacket("prepared transport buffer already consumed".into())
        })?;
        session.encrypt_into_prepared(packet, wire)
    }

    #[allow(clippy::ptr_arg)] // Compare the actual allocation, including capacity.
    fn into_residency(mut self, wire: &Vec<u8>) -> Option<ResidencyLease> {
        if let Some(lease) = self.0.residency.as_mut() {
            lease.relocate(ResidencyStage::SerializedWire, wire);
        }
        self.0.residency.take()
    }
}

pub(super) struct EncryptionInput {
    pub(super) packet: OutboundPacket,
    pub(super) prepared: Option<PreparedEncryptionBuffer>,
}

impl From<OutboundPacket> for EncryptionInput {
    fn from(packet: OutboundPacket) -> Self {
        Self {
            packet,
            prepared: None,
        }
    }
}

pub(super) fn finish_encryption(
    prepared: Option<PreparedEncryptionBuffer>,
    packet: EncryptedPeerPacket,
    source: Option<OriginalEncryptionSource>,
    capture: Option<&Arc<ResourceCapture>>,
) -> EncryptedOutboundWithSource {
    match prepared {
        Some(prepared) => {
            let residency = prepared.into_residency(&packet.wire_bytes);
            EncryptedOutboundWithSource::with_residency(packet, source, residency)
        }
        None => EncryptedOutboundWithSource::new(packet, source, capture),
    }
}
