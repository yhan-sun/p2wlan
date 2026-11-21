// Sole original emit owner OUTSIDE the cancellable bounded send future.
// The inner future borrows storage; its epoch/slot/session guards end first.
use crate::overlay_requests::{PhysicalRequestPublisher, PreparedPhysicalPublication};
use crate::relay::{RelayCaptureOutcome, RelaySendCapture};
use crate::transport::EncryptedPeerPacket;
use crate::udp::UdpSendCapture;
use std::sync::Arc;

pub(super) struct PhysicalSendCapture {
    udp: UdpSendCapture,
    relay: Option<Arc<RelaySendCapture>>,
    metadata_failed: bool,
    relay_admitted: bool,
}
impl PhysicalSendCapture {
    fn new() -> Self {
        Self {
            udp: UdpSendCapture::new(),
            relay: None,
            metadata_failed: false,
            relay_admitted: false,
        }
    }
    pub(super) fn udp(&mut self) -> &mut UdpSendCapture {
        &mut self.udp
    }
    #[cfg(test)]
    pub(super) fn relay_for_test(&mut self, packet: &EncryptedPeerPacket) -> Arc<RelaySendCapture> {
        // Test-only hook preparation before borrowing storage into original
        // bounded future. The first real branch still admits/configures once.
        if self.relay.is_none() {
            self.relay = RelaySendCapture::new(packet);
        }
        self.relay.as_ref().unwrap().clone()
    }
    pub(super) fn relay(&mut self, packet: &EncryptedPeerPacket) -> Option<Arc<RelaySendCapture>> {
        if self.relay_admitted {
            // A second original Relay admission cannot relabel the first cell.
            self.metadata_failed = true;
            return self.relay.clone();
        }
        self.relay_admitted = true;
        if self.relay.is_none() {
            self.relay = RelaySendCapture::new(packet);
        }
        if self.relay.is_none() {
            self.metadata_failed = true;
        }
        self.relay.clone()
    }
}

pub(super) struct PhysicalAttempt<G> {
    emit: Option<G>,
    publisher: Option<PhysicalRequestPublisher>,
    capture: PhysicalSendCapture,
}
impl<G> PhysicalAttempt<G> {
    pub(super) fn new(emit: G, prepared: Option<PreparedPhysicalPublication>) -> Self {
        Self {
            emit: Some(emit),
            publisher: prepared.and_then(|prepared| prepared.open().ok()),
            capture: PhysicalSendCapture::new(),
        }
    }
    pub(super) fn arm(&mut self, prepared: Option<PreparedPhysicalPublication>) {
        // The sole existing fast caller arms once. Fence any future re-arm:
        // old observers retain only their sealed old cell, never new B/storage.
        if let Some(relay) = self.capture.relay.take() {
            let _ = relay.finish();
        }
        if let Some(old) = self.publisher.as_mut() {
            old.fail_metadata();
        }
        self.capture = PhysicalSendCapture::new();
        self.publisher = prepared.and_then(|prepared| prepared.open().ok());
    }
    // Existing fast UDP callers retain their original borrowed capture API.
    pub(super) fn capture(&mut self) -> Option<&mut UdpSendCapture> {
        self.publisher.as_ref()?;
        Some(&mut self.capture.udp)
    }
    pub(super) fn slow_capture(&mut self) -> Option<&mut PhysicalSendCapture> {
        self.publisher.as_ref()?;
        Some(&mut self.capture)
    }
    pub(super) fn finish(&mut self, definitely_not_handed: bool) {
        // Take once: Drop cannot seal a second time or publish a second fact.
        let relay = self.capture.relay.take().map(|capture| capture.finish());
        let udp = self.capture.udp.take();
        // Seal after destroying inner, then release original emit before publish.
        drop(self.emit.take());
        if let Some(publisher) = self.publisher.as_mut() {
            if self.capture.metadata_failed || (udp.is_some() && relay.is_some()) {
                publisher.fail_metadata();
            } else {
                match (udp, relay) {
                    (Some(fact), None) => {
                        let _ = publisher.publish(fact);
                    }
                    (None, Some(RelayCaptureOutcome::Full(fact))) => {
                        let _ = publisher.publish_relay(fact);
                    }
                    (None, Some(RelayCaptureOutcome::MetadataFailed)) => publisher.fail_metadata(),
                    (None, Some(RelayCaptureOutcome::DefinitelyNotHanded)) => {
                        publisher.finish(true)
                    }
                    (None, Some(RelayCaptureOutcome::Uncertain)) => publisher.finish(false),
                    (None, None) => publisher.finish(definitely_not_handed),
                    (Some(_), Some(_)) => publisher.fail_metadata(),
                }
            }
            // Full consumes preparation before this idempotent matching finish.
            publisher.finish(false);
        }
        self.publisher.take();
    }
}
impl<G> Drop for PhysicalAttempt<G> {
    fn drop(&mut self) {
        self.finish(false);
    }
}
