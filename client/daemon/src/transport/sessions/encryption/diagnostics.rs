//! One attempt's frozen crypto log fields. No packet, guard or worker is kept.
use crate::transport::{wire_counter, wire_fingerprint};

mod control;
pub(super) use control::DeferredControlLog;

const TARGET: &str = "p2pnet_daemon::transport::sessions::encryption";

pub(super) enum Unavailable {
    Missing,
    Inactive,
    Expired,
}

enum Event {
    Counter {
        session_instance: u64,
        counter: Option<u64>,
        bytes: usize,
        is_business: bool,
        wire_fp: u64,
        fast: bool,
    },
    Unavailable(Unavailable, usize),
}

/// Construct before the actual emit/epoch/session guards. The outer attempt
/// owns this through its original handoff or cancellation, then publishes once.
pub(crate) struct DeferredEncryptionLog {
    peer: String,
    event: Option<Event>,
}

// The level macro reads only static/global limits. Event filtering and
// subscriber callbacks run in Drop, outside the actual transaction.
impl DeferredEncryptionLog {
    pub(crate) fn new(peer: String) -> Self {
        Self { peer, event: None }
    }

    pub(super) fn counter(
        &mut self,
        session_instance: u64,
        wire: &[u8],
        is_business: bool,
        fast: bool,
    ) {
        if tracing::level_enabled!(tracing::Level::DEBUG) && self.event.is_none() {
            self.event = Some(Event::Counter {
                session_instance,
                counter: wire_counter(wire),
                bytes: wire.len(),
                is_business,
                wire_fp: wire_fingerprint(wire),
                fast,
            });
        }
    }

    pub(super) fn unavailable(&mut self, reason: Unavailable, bytes: usize) {
        if tracing::level_enabled!(tracing::Level::DEBUG) && self.event.is_none() {
            self.event = Some(Event::Unavailable(reason, bytes));
        }
    }
}

impl DeferredEncryptionLog {
    pub(super) fn emit(&mut self) {
        let event = self.event.take();
        match event.as_ref() {
            Some(Event::Counter {
                session_instance,
                counter,
                bytes,
                is_business,
                wire_fp,
                fast,
            }) => {
                if *fast {
                    tracing::debug!(
                        target: TARGET,
                        event = "wireguard_outbound_counter_allocated",
                        peer_id = %self.peer,
                        session_instance,
                        counter = ?counter,
                        bytes,
                        is_business,
                        wire_fp = format_args!("{wire_fp:016x}"),
                        "WireGuard counter allocated under the LAN Direct fast-path ordering lock"
                    );
                } else {
                    tracing::debug!(
                        target: TARGET,
                        event = "wireguard_outbound_counter_allocated",
                        peer_id = %self.peer,
                        session_instance,
                        counter = ?counter,
                        bytes,
                        is_business,
                        wire_fp = format_args!("{wire_fp:016x}"),
                        "WireGuard counter allocated under the per-peer emit ordering lock"
                    );
                }
            }
            Some(Event::Unavailable(Unavailable::Missing, bytes)) => tracing::debug!(
                target: TARGET,
                "No WireGuard session for peer {}; dropping {} byte packet",
                self.peer,
                bytes
            ),
            Some(Event::Unavailable(Unavailable::Inactive, bytes)) => tracing::debug!(
                target: TARGET,
                "No usable WireGuard session for peer {}; dropping {} byte packet until rekey completes",
                self.peer,
                bytes
            ),
            Some(Event::Unavailable(Unavailable::Expired, bytes)) => tracing::debug!(
                target: TARGET,
                "WireGuard session for peer {} expired; dropping {} byte packet until authenticated rekey confirmation",
                self.peer,
                bytes
            ),
            None => {}
        }
    }
}

impl Drop for DeferredEncryptionLog {
    fn drop(&mut self) {
        self.emit();
    }
}
