//! RX values retain their concrete Vec and its optional observation together.
//! This carrier contains no packet permission, network owner or routing state.
use super::{ResidencyLease, ResidencyStage, ResourceCapture};
use p2pnet_crypto::packet_buf::PacketBuf;
use std::{ops::Deref, sync::Arc};

pub(crate) trait RxPayload {
    fn payload(&self) -> &Vec<u8>;
    fn payload_mut(&mut self) -> &mut Vec<u8>;
}

impl RxPayload for Vec<u8> {
    fn payload(&self) -> &Vec<u8> {
        self
    }
    fn payload_mut(&mut self) -> &mut Vec<u8> {
        self
    }
}
impl RxPayload for crate::transport::ReceivedEncryptedPacket {
    fn payload(&self) -> &Vec<u8> {
        &self.wire_bytes
    }
    fn payload_mut(&mut self) -> &mut Vec<u8> {
        &mut self.wire_bytes
    }
}
impl RxPayload for crate::dataplane::InboundPacket {
    fn payload(&self) -> &Vec<u8> {
        &self.packet
    }
    fn payload_mut(&mut self) -> &mut Vec<u8> {
        &mut self.packet
    }
}
impl RxPayload for p2pnet_wireguard::MessageTransport {
    fn payload(&self) -> &Vec<u8> {
        &self.encrypted_payload
    }
    fn payload_mut(&mut self) -> &mut Vec<u8> {
        &mut self.encrypted_payload
    }
}

pub(crate) struct RxOwned<T: RxPayload> {
    // Declaration order frees the value before retiring its observation.
    value: T,
    pooled: Option<PacketBuf>,
    lease: Option<ResidencyLease>,
}

impl<T: RxPayload> RxOwned<T> {
    pub(crate) fn observe(
        value: T,
        capture: Option<&Arc<ResourceCapture>>,
        stage: ResidencyStage,
    ) -> Self {
        let lease = capture.and_then(|c| ResidencyLease::observe(c, stage, value.payload()));
        Self {
            value,
            pooled: None,
            lease,
        }
    }

    pub(crate) fn from_parts(value: T, mut lease: Option<ResidencyLease>) -> Self {
        if let Some(lease) = lease.as_mut() {
            lease.refresh(value.payload());
        }
        Self {
            value,
            pooled: None,
            lease,
        }
    }

    pub(crate) fn bytes(&self) -> &[u8] {
        self.pooled
            .as_ref()
            .map_or(self.value.payload().as_slice(), |buffer| buffer.bytes())
    }

    pub(crate) fn with_pool(mut self, buffer: Option<PacketBuf>) -> Self {
        debug_assert!(
            buffer.is_none() || (self.lease.is_none() && self.value.payload().is_empty())
        );
        self.pooled = buffer;
        self
    }

    fn materialize(&mut self) {
        if let Some(buffer) = self.pooled.take() {
            *self.value.payload_mut() = buffer.into_vec();
        }
    }

    pub(crate) fn into_parts_with_pool(self) -> (Option<ResidencyLease>, T, Option<PacketBuf>) {
        (self.lease, self.value, self.pooled)
    }

    /// Callers unpack the lease into a local BEFORE the raw value so the value
    /// drops first, including when an enclosing async future is cancelled.
    pub(crate) fn into_parts(mut self) -> (Option<ResidencyLease>, T) {
        self.materialize();
        (self.lease, self.value)
    }

    pub(crate) fn map<U: RxPayload>(mut self, convert: impl FnOnce(T) -> U) -> RxOwned<U> {
        self.materialize();
        let mut lease = self.lease;
        let value = convert(self.value);
        if let Some(lease) = lease.as_mut() {
            lease.refresh(value.payload());
        }
        RxOwned {
            value,
            pooled: None,
            lease,
        }
    }

    pub(crate) fn align(
        &mut self,
        expected: Option<&Arc<ResourceCapture>>,
        stage: ResidencyStage,
        missing_is_gap: bool,
    ) {
        if expected.is_some() {
            self.materialize();
        }
        match (self.lease.as_mut(), expected) {
            (Some(lease), Some(capture)) => {
                if !Arc::ptr_eq(lease.capture(), capture) {
                    lease.unobserved_exit();
                    capture.unobserved_residency_exit();
                }
                lease.relocate(stage, self.value.payload());
            }
            (Some(lease), None) => {
                lease.unobserved_exit();
                lease.relocate(stage, self.value.payload());
            }
            (None, Some(capture)) if !capture.is_finished() => {
                if missing_is_gap {
                    capture.unobserved_residency_exit();
                }
                self.lease = ResidencyLease::observe(capture, stage, self.value.payload());
            }
            _ => {}
        }
    }

    pub(crate) fn into_unobserved(mut self) -> T {
        self.materialize();
        if let Some(lease) = self.lease.as_ref() {
            lease.unobserved_exit();
        }
        // The public compatibility value cannot retain private metadata. This
        // is an explicit observation boundary, not a claim that its Vec freed.
        self.value
    }
}

impl<T: RxPayload> From<T> for RxOwned<T> {
    fn from(value: T) -> Self {
        Self {
            value,
            pooled: None,
            lease: None,
        }
    }
}
impl<T: RxPayload> Deref for RxOwned<T> {
    type Target = T;
    fn deref(&self) -> &T {
        &self.value
    }
}

#[cfg(test)]
#[path = "rx_owned_tests.rs"]
mod tests;
