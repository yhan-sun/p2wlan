//! Frozen diagnostics for one original control attempt. Subscriber callbacks
//! run after its actual emit guard, including error, no-session and cancellation.
use super::{DeferredEncryptionLog, TARGET};
use crate::transport::{wire_counter, wire_fingerprint};
struct Wire {
    counter: Option<u64>,
    bytes: usize,
    fingerprint: u64,
}
pub(in crate::transport) struct DeferredControlLog {
    peer: String,
    plaintext_bytes: usize,
    wait_ms: Option<u64>,
    wire: Option<Wire>,
    completed: bool,
    crypto: DeferredEncryptionLog,
}
impl DeferredControlLog {
    pub(in crate::transport) fn new(peer: String, plaintext_bytes: usize) -> Self {
        Self {
            crypto: DeferredEncryptionLog::new(peer.clone()),
            peer,
            plaintext_bytes,
            wait_ms: None,
            wire: None,
            completed: false,
        }
    }
    pub(in crate::transport) fn acquired(&mut self, wait_ms: u64) {
        self.wait_ms = Some(wait_ms);
    }
    pub(in crate::transport) fn crypto(&mut self) -> &mut DeferredEncryptionLog {
        &mut self.crypto
    }
    pub(in crate::transport) fn started(&mut self, wire: &[u8]) {
        // This static/global level query does not invoke subscriber filters.
        if tracing::level_enabled!(tracing::Level::DEBUG) {
            self.wire = Some(Wire {
                counter: wire_counter(wire),
                bytes: wire.len(),
                fingerprint: wire_fingerprint(wire),
            });
        }
    }
    pub(in crate::transport) fn completed(&mut self, success: bool) {
        self.completed = success;
    }
}
impl Drop for DeferredControlLog {
    fn drop(&mut self) {
        if let Some(wait_ms) = self.wait_ms {
            tracing::debug!(target: TARGET, event = "control_emit_lock_acquired", peer_id = %self.peer, lock_wait_ms = wait_ms, bytes = self.plaintext_bytes, "control/probe packet acquired the same per-peer counter-ordering lock as business traffic");
        }
        self.crypto.emit();
        if let Some(wire) = &self.wire {
            tracing::debug!(target: TARGET, event = "control_transport_handoff_started", peer_id = %self.peer, counter = ?wire.counter, bytes = wire.bytes, plaintext_bytes = self.plaintext_bytes, wire_fp = format_args!("{:016x}",wire.fingerprint), "encrypted control packet entered its caller-provided transport handoff");
            if self.completed {
                tracing::debug!(target: TARGET, event = "control_transport_handoff_completed", peer_id = %self.peer, counter = ?wire.counter, bytes = wire.bytes, wire_fp = format_args!("{:016x}",wire.fingerprint), "control packet handoff completed locally; peer delivery still requires its matching ACK");
            }
        }
    }
}
