//! Authoritative active-path telemetry module.
//!
//! Provides the daemon sidecar for authoritative active-path telemetry:
//! - [`wire`]: DTO serialization with strict privacy guarantees (no IPs, keys, or endpoints).
//! - [`hub`]: Non-blocking commit hook, bounded coalesced queue, and snapshot storage.
//! - [`sender`]: Background HTTP fallback delivery worker.

pub mod hub;
pub mod sender;
pub mod wire;

pub use hub::{
    PathTelemetryHub, PathTelemetryMetrics, DEFAULT_BATCH_OBSERVATIONS, MAX_DIRTY_PEERS,
};
pub use sender::PathTelemetrySender;
pub use wire::{
    observation_from_snapshot, opt_path_to_wire, path_to_wire, PathTelemetryAckFrame,
    PathTelemetryFrame, PathTelemetryObservation, PathTelemetryPayload, PathTransitionTeleItem,
};

#[cfg(test)]
mod tests;
