//! Per-process connection timeline: a bounded, serializable record of the
//! observable milestones of one daemon connection/round.
//!
//! Every event carries the same stable `correlation_id` and a `t_ms` relative
//! to daemon start, so the dual-end harness can correlate the two daemons'
//! logs and diagnostics into one round without wall-clock reconciliation.
//!
//! Definitions (strict):
//! - `relay_transport_connected` means only that a relay transport is
//!   registered in the shared slot;
//! - `relay_peer_confirmed` means a verifiably decrypted encrypted relay path
//!   to a peer;
//! - `first_usable_*` requires a bidirectional decrypted overlay business
//!   loopback (produced by the validation harness's real encrypted payload),
//!   never a single UDP send or TCP connect;
//! - `direct_promoted` still requires the existing encrypted validation chain.

use std::collections::{HashSet, VecDeque};
use std::sync::{Arc, Mutex};
use std::time::Instant;

use serde::{Deserialize, Serialize};
use tracing::info;

/// Bound on the diagnostics ring so `/status` stays small.
pub const TIMELINE_MAX_EVENTS: usize = 64;

/// One recorded timeline event (serializable, bounded).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConnectionTimelineEvent {
    pub event: String,
    pub at_ms: u64,
    pub path: Option<String>,
    pub reason_code: Option<String>,
    pub detail: Option<String>,
}

/// Bounded, serializable snapshot exposed by diagnostics `/status`.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ConnectionTimelineDiagnostics {
    pub correlation_id: String,
    pub events: Vec<ConnectionTimelineEvent>,
}

/// Structured INFO timeline emitter shared across daemon subsystems.
pub struct ConnectionTimeline {
    correlation_id: String,
    started_at: Instant,
    events: Mutex<VecDeque<ConnectionTimelineEvent>>,
    /// Events that must be emitted at most once per scope.  The scope is a
    /// stable string (`""` for process-level milestones, `peer:<id>:<generation>`
    /// for per-peer + generation milestones), so a first-milestone can never be
    /// deduplicated across different peers or generations of the same peer.
    first_events: Mutex<HashSet<(String, String)>>,
}

impl ConnectionTimeline {
    /// Create a timeline for one daemon process.  The correlation id is derived
    /// from the local node id and the persistent monotonic boot epoch, so it is
    /// stable across restarts of the same node and unique between nodes.
    pub fn new(node_id: &str, boot_epoch_ms: u64) -> Arc<Self> {
        let short_node = node_id.get(..8).unwrap_or(node_id).to_string();
        let correlation_id = if boot_epoch_ms == 0 {
            format!("{short_node}-boot0")
        } else {
            format!("{short_node}-{boot_epoch_ms:x}")
        };
        Arc::new(Self {
            correlation_id,
            started_at: Instant::now(),
            events: Mutex::new(VecDeque::new()),
            first_events: Mutex::new(HashSet::new()),
        })
    }

    pub fn correlation_id(&self) -> &str {
        &self.correlation_id
    }

    /// Monotonic milliseconds since this daemon process started (the same
    /// clock used for every event's `at_ms`).  Exposed at `/status` top level
    /// so a single snapshot can be placed on the daemon's own timeline without
    /// wall-clock reconciliation.
    pub fn uptime_ms(&self) -> u64 {
        self.started_at.elapsed().as_millis().min(u64::MAX as u128) as u64
    }

    /// Record and log one timeline event with the shared correlation id and the
    /// relative startup time (`t_ms`).
    #[allow(clippy::too_many_arguments)]
    pub fn emit(
        &self,
        event: &'static str,
        path: Option<&str>,
        reason_code: Option<&str>,
        detail: Option<String>,
    ) {
        let at_ms = self.started_at.elapsed().as_millis().min(u64::MAX as u128) as u64;
        {
            let mut events = self
                .events
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            events.push_back(ConnectionTimelineEvent {
                event: event.to_string(),
                at_ms,
                path: path.map(str::to_string),
                reason_code: reason_code.map(str::to_string),
                detail: detail.clone(),
            });
            while events.len() > TIMELINE_MAX_EVENTS {
                events.pop_front();
            }
        }
        info!(
            event = event,
            corr_id = %self.correlation_id,
            t_ms = at_ms,
            path = path,
            reason_code = reason_code,
            detail = detail,
            "{event} corr_id={} t_ms={} path={:?} reason_code={:?} detail={:?}",
            self.correlation_id,
            at_ms,
            path,
            reason_code,
            detail,
        );
    }

    /// Emit an event at most once per scope.  `scope` is a stable per-peer +
    /// generation key (e.g. `peer:node-b:3`) or `""` for a process-level
    /// milestone.  Returns `true` when it emitted (the first occurrence);
    /// subsequent calls for the SAME scope are no-ops, while the same event for
    /// a DIFFERENT peer or generation still emits.  Used for first-milestone
    /// events such as `first_usable_path`, which must be reported per peer +
    /// generation, never deduplicated process-globally.
    pub fn emit_first_scoped(
        &self,
        scope: &str,
        event: &'static str,
        path: Option<&str>,
        reason_code: Option<&str>,
        detail: Option<String>,
    ) -> bool {
        let mut firsts = self
            .first_events
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if !firsts.insert((scope.to_string(), event.to_string())) {
            return false;
        }
        drop(firsts);
        self.emit(event, path, reason_code, detail);
        true
    }

    /// Emit an event at most once per process.  Returns `true` when it emitted
    /// (the first occurrence); subsequent calls are no-ops.  Used for
    /// first-milestone events such as `first_direct_probe_sent`.
    pub fn emit_first(
        &self,
        event: &'static str,
        path: Option<&str>,
        reason_code: Option<&str>,
        detail: Option<String>,
    ) -> bool {
        self.emit_first_scoped("", event, path, reason_code, detail)
    }

    /// Serialize the bounded event ring for diagnostics.
    pub fn snapshot(&self) -> ConnectionTimelineDiagnostics {
        let events = self
            .events
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .iter()
            .cloned()
            .collect();
        ConnectionTimelineDiagnostics {
            correlation_id: self.correlation_id.clone(),
            events,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn timeline_events_are_bounded_and_serde_round_trip() {
        let timeline = ConnectionTimeline::new("node-a", 0x1234);
        assert_eq!(timeline.correlation_id(), "node-a-1234");
        timeline.emit("daemon_started", None, None, None);
        timeline.emit(
            "relay_transport_connected",
            Some("relay"),
            None,
            Some("endpoint=tcp://relay.test:18081".to_string()),
        );
        timeline.emit(
            "relay_unavailable_or_first_packet_expired",
            None,
            Some("path_unavailable"),
            None,
        );
        let snapshot = timeline.snapshot();
        assert_eq!(snapshot.correlation_id, "node-a-1234");
        assert_eq!(snapshot.events.len(), 3);
        // Serde round-trips and preserves every field.
        let json = serde_json::to_string(&snapshot).unwrap();
        let decoded: ConnectionTimelineDiagnostics = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded.correlation_id, "node-a-1234");
        assert_eq!(decoded.events.len(), 3);
        assert_eq!(decoded.events[0].event, "daemon_started");
        // at_ms is a relative startup time: later events are never earlier.
        assert!(decoded.events[1].at_ms >= decoded.events[0].at_ms);
        assert_eq!(decoded.events[1].path.as_deref(), Some("relay"));
        assert_eq!(
            decoded.events[2].reason_code.as_deref(),
            Some("path_unavailable")
        );
        // New/old JSON both deserialize: a legacy empty snapshot still parses.
        let empty: ConnectionTimelineDiagnostics =
            serde_json::from_str(r#"{"correlation_id":"x","events":[]}"#).unwrap();
        assert!(empty.events.is_empty());
    }

    #[test]
    fn timeline_emit_first_fires_only_once() {
        let timeline = ConnectionTimeline::new("node-a", 0);
        assert!(timeline.emit_first("first_direct_probe_sent", Some("direct"), None, None));
        assert!(!timeline.emit_first("first_direct_probe_sent", Some("direct"), None, None));
        // A DIFFERENT event is still a first occurrence.
        assert!(timeline.emit_first("first_usable_path", Some("relay"), None, None));
        let snapshot = timeline.snapshot();
        let direct_count = snapshot
            .events
            .iter()
            .filter(|event| event.event == "first_direct_probe_sent")
            .count();
        assert_eq!(direct_count, 1);
    }

    #[test]
    fn timeline_emit_first_scoped_dedupes_per_peer_and_generation() {
        let timeline = ConnectionTimeline::new("node-a", 0);
        // The same milestone for the same peer + generation fires exactly once.
        assert!(timeline.emit_first_scoped(
            "peer:node-b:3",
            "first_usable_path",
            Some("relay"),
            None,
            None
        ));
        assert!(!timeline.emit_first_scoped(
            "peer:node-b:3",
            "first_usable_path",
            Some("relay"),
            None,
            None
        ));
        // A NEW generation of the SAME peer still emits (never process-global).
        assert!(timeline.emit_first_scoped(
            "peer:node-b:4",
            "first_usable_path",
            Some("relay"),
            None,
            None
        ));
        // A DIFFERENT peer emits too.
        assert!(timeline.emit_first_scoped(
            "peer:node-c:3",
            "first_usable_path",
            Some("direct"),
            None,
            None
        ));
        let snapshot = timeline.snapshot();
        let usable = snapshot
            .events
            .iter()
            .filter(|event| event.event == "first_usable_path")
            .count();
        assert_eq!(
            usable, 3,
            "three distinct peer+generation scopes must each emit once"
        );
    }
}
