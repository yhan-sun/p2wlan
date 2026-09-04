//! Per-process connection timeline: a bounded, serializable record of the
//! observable milestones of one daemon connection/round.
//!
//! Every event carries the same stable `correlation_id`, the optional bounded
//! harness `run_id`, and a `t_ms` relative to daemon start, so the dual-end
//! harness can correlate the two daemons' logs and diagnostics into one round
//! without wall-clock reconciliation.
//!
//! Definitions (strict):
//! - `relay_transport_connected` means only that a relay transport is
//!   registered in the shared slot;
//! - `relay_peer_confirmed` means a verifiably decrypted encrypted relay path
//!   to a peer;
//! - `first_real_business_ingress` is production evidence: the first normal,
//!   authenticated, decrypted overlay business packet received by the real
//!   dataplane, with its direct/relay ingress known from the packet envelope;
//! - `first_usable_confirmed` and `first_usable_bidirectional_overlay_ms` are
//!   stronger validation-harness milestones that additionally require a
//!   nonce-matched bidirectional echo; neither local send, queue acceptance,
//!   TCP connect, writer completion, nor metrics is business evidence;
//! - `direct_promoted` still requires the existing encrypted validation chain.

use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Instant;

use serde::{Deserialize, Serialize};
use tracing::{debug, info};

/// Bound on the diagnostics ring so `/status` stays bounded while retaining
/// a complete burst/failure window. 64 events was too small for a 256-packet
/// acceptance burst: the timeline evicted its own queue-overflow records even
/// though the structured counters still retained them. Keep the ring bounded,
/// but large enough to correlate a burst, handshake, retries, and teardown.
pub const TIMELINE_MAX_EVENTS: usize = 512;

/// Additive schema for the durable first-usable evidence ledger. The ordinary
/// timeline is intentionally a bounded ring and may evict the transition that
/// proved usability; this summary remains available to `/status` after that
/// eviction and carries the status revision fence used by the NAT harness.
pub const FIRST_USABLE_SUMMARY_SCHEMA_VERSION: u32 = 1;
pub const FIRST_USABLE_SUMMARY_MAX_ENTRIES: usize = 1024;

/// One recorded timeline event (serializable, bounded).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConnectionTimelineEvent {
    /// The explicit run identity supplied by the acceptance harness. It is
    /// accepted only from `P2WLAN_TEST_RUN_ID` after strict character/length
    /// validation; credentials and arbitrary environment values never enter
    /// the diagnostics payload.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub run_id: Option<String>,
    pub event: String,
    pub at_ms: u64,
    pub path: Option<String>,
    pub reason_code: Option<String>,
    pub detail: Option<String>,
    /// Structured copies of the audit dimensions when an event detail carries
    /// the conventional `key=value` fields. The original bounded detail is
    /// retained for backwards-compatible human diagnostics.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub peer_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub connection_generation: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub relay_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub relay_region: Option<String>,
    /// The monotonic status-event sequence assigned at the same commit. A
    /// missing value means this timeline is running without a status event bus
    /// (standalone/unit mode), never that a production transition has an
    /// unknown revision.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub transition_revision: Option<u64>,
}

/// Persistent, per-peer/per-network-generation first-usable commit summary.
///
/// This is written only after the authoritative peer state has accepted a
/// real authenticated business ingress. Relay confirmation, socket readiness,
/// queue acceptance, and writer completion are represented separately and
/// cannot create one of these records.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FirstUsableEvidenceSummary {
    pub schema_version: u32,
    pub peer_id: String,
    pub path: String,
    pub network_generation: u64,
    pub first_usable_at_ms: u64,
    /// Status-event revision assigned to the `first_usable_path` commit. Zero
    /// means the timeline is used without an attached status event bus (unit
    /// tests and standalone diagnostics fixtures).
    #[serde(default)]
    pub transition_revision: u64,
    /// The closest same-peer/same-generation relay-ready commit known to the
    /// process-local timeline. It is optional because a long-running daemon
    /// may have evicted the ready event before the first-usable commit.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub relay_ready_at_ms: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub first_usable_delta_ms: Option<u64>,
    /// Business evidence dimensions are explicit so a collector cannot treat
    /// `relay_connected` or `relay_peer_confirmed` as first usability.
    #[serde(default)]
    pub business_sent: bool,
    #[serde(default)]
    pub business_received: bool,
    #[serde(default)]
    pub business_exchange: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub relay_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub relay_connection_id: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason_code: Option<String>,
    /// Stable producer label; kept additive for machine evidence audits.
    pub source: String,
}

/// Bounded, serializable snapshot exposed by diagnostics `/status`.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ConnectionTimelineDiagnostics {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub run_id: Option<String>,
    pub correlation_id: String,
    pub events: Vec<ConnectionTimelineEvent>,
    /// Persistent first-usable summaries are not subject to the event-ring
    /// eviction window.
    #[serde(default)]
    pub first_usable_summaries: Vec<FirstUsableEvidenceSummary>,
}

/// Structured INFO timeline emitter shared across daemon subsystems.
pub struct ConnectionTimeline {
    run_id: Option<String>,
    correlation_id: String,
    started_at: Instant,
    events: Mutex<VecDeque<ConnectionTimelineEvent>>,
    first_usable_summaries: Mutex<VecDeque<FirstUsableEvidenceSummary>>,
    /// Same-peer/same-generation relay-ready times used to compute a local
    /// delta even when the ready event later leaves the bounded event ring.
    relay_ready_at_ms: Mutex<HashMap<(String, u64), u64>>,
    /// Events that must be emitted at most once per scope.  The scope is a
    /// stable string (`""` for process-level milestones, `peer:<id>:<generation>`
    /// for per-peer + generation milestones), so a first-milestone can never be
    /// deduplicated across different peers or generations of the same peer.
    first_events: Mutex<HashSet<(String, String)>>,
    /// Optional forwarder to the diagnostics status event bus. When present,
    /// every recorded timeline event is also mirrored to `/events`, giving a
    /// single choke point that covers all timeline emits without touching each
    /// call site. Absent in tests that do not need the diagnostics surface.
    status_events: Mutex<Option<Arc<crate::diagnostics::StatusEventBus>>>,
    /// Monotonic control-plane registration count. This deliberately lives
    /// outside the bounded event ring so reconnects remain observable after
    /// older timeline entries have been evicted.
    control_registration_count: AtomicU64,
}

impl ConnectionTimeline {
    /// Create a timeline for one daemon process.  The correlation id is derived
    /// from the local node id and the persistent monotonic boot epoch, so it is
    /// stable across restarts of the same node and unique between nodes.
    pub fn new(node_id: &str, boot_epoch_ms: u64) -> Arc<Self> {
        Self::new_with_run_id(node_id, boot_epoch_ms, safe_test_run_id())
    }

    fn new_with_run_id(node_id: &str, boot_epoch_ms: u64, run_id: Option<String>) -> Arc<Self> {
        let short_node = node_id.get(..8).unwrap_or(node_id).to_string();
        let correlation_id = if boot_epoch_ms == 0 {
            format!("{short_node}-boot0")
        } else {
            format!("{short_node}-{boot_epoch_ms:x}")
        };
        Arc::new(Self {
            run_id,
            correlation_id,
            started_at: Instant::now(),
            events: Mutex::new(VecDeque::new()),
            first_usable_summaries: Mutex::new(VecDeque::new()),
            relay_ready_at_ms: Mutex::new(HashMap::new()),
            first_events: Mutex::new(HashSet::new()),
            status_events: Mutex::new(None),
            control_registration_count: AtomicU64::new(0),
        })
    }

    /// Attach the diagnostics status event bus so every timeline record is
    /// mirrored to `/events`. Called once by the daemon after constructing the
    /// shared timeline (construction precedes run(), so before any emit).
    pub fn set_status_event_bus(&self, bus: Arc<crate::diagnostics::StatusEventBus>) {
        let mut guard = self.status_events.lock().unwrap_or_else(|p| p.into_inner());
        *guard = Some(bus);
    }

    pub fn run_id(&self) -> Option<&str> {
        self.run_id.as_deref()
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

    fn record_event(
        &self,
        event: &'static str,
        path: Option<&str>,
        reason_code: Option<&str>,
        detail: Option<String>,
    ) -> (u64, u64) {
        let at_ms = self.started_at.elapsed().as_millis().min(u64::MAX as u128) as u64;
        if event == "control_registered" {
            self.control_registration_count
                .fetch_add(1, Ordering::Relaxed);
        }
        let fields = detail
            .as_deref()
            .map(parse_detail_fields)
            .unwrap_or_default();
        if event == "relay_transport_ready_peer" {
            if let (Some(peer_id), Some(generation)) =
                (fields.peer_id.as_ref(), fields.connection_generation)
            {
                let mut ready_times = self
                    .relay_ready_at_ms
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner());
                ready_times.insert((peer_id.clone(), generation), at_ms);
                while ready_times.len() > FIRST_USABLE_SUMMARY_MAX_ENTRIES {
                    let Some(oldest_key) = ready_times
                        .iter()
                        .min_by_key(|(_, timestamp)| **timestamp)
                        .map(|(key, _)| key.clone())
                    else {
                        break;
                    };
                    ready_times.remove(&oldest_key);
                }
            }
        }
        // Hold the event-ring lock while assigning the status sequence so
        // concurrent producers cannot make the ring order disagree with the
        // `/events` cursor order.
        let mirror_peer_id = fields.peer_id.clone();
        let mut events = self
            .events
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let revision = if let Some(bus) = self
            .status_events
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .as_ref()
        {
            bus.record(event, at_ms, path, reason_code, mirror_peer_id.as_deref())
        } else {
            0
        };
        events.push_back(ConnectionTimelineEvent {
            run_id: self.run_id.clone(),
            event: event.to_string(),
            at_ms,
            path: path.map(str::to_string),
            reason_code: reason_code.map(str::to_string),
            detail: detail.clone(),
            peer_id: fields.peer_id,
            connection_generation: fields.connection_generation,
            path_id: fields.path_id.or_else(|| path.map(str::to_string)),
            relay_id: fields.relay_id,
            relay_region: fields.relay_region,
            transition_revision: (revision != 0).then_some(revision),
        });
        while events.len() > TIMELINE_MAX_EVENTS {
            events.pop_front();
        }
        drop(events);
        // A detached timeline (no bus) intentionally returns revision zero;
        // that value is omitted from the serialized event in standalone/unit
        // mode rather than being mistaken for a production cursor.
        (at_ms, revision)
    }

    /// Number of control-plane reconnects observed after the initial
    /// registration. Unlike the event timeline, this counter is not bounded
    /// by `TIMELINE_MAX_EVENTS` and therefore survives ring eviction.
    pub fn control_reconnects(&self) -> u64 {
        self.control_registration_count
            .load(Ordering::Relaxed)
            .saturating_sub(1)
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
        let (at_ms, _) = self.record_event(event, path, reason_code, detail.clone());
        info!(
            event = event,
            run_id = ?self.run_id,
            corr_id = %self.correlation_id,
            t_ms = at_ms,
            path = path,
            reason_code = reason_code,
            detail = detail,
            "{event} run_id={:?} corr_id={} t_ms={} path={:?} reason_code={:?} detail={:?}",
            self.run_id,
            self.correlation_id,
            at_ms,
            path,
            reason_code,
            detail,
        );
    }

    /// Emit a correlation-aware DEBUG line without retaining another event in
    /// the bounded process timeline.  High-volume Direct request attempts use
    /// this path: `/status` keeps its own protected direct-validation ring,
    /// while the process-level milestone ring remains useful after a burst.
    #[allow(clippy::too_many_arguments)]
    pub fn log_debug(
        &self,
        event: &'static str,
        path: Option<&str>,
        reason_code: Option<&str>,
        detail: Option<String>,
    ) {
        let at_ms = self.started_at.elapsed().as_millis().min(u64::MAX as u128) as u64;
        debug!(
            event = event,
            run_id = ?self.run_id,
            corr_id = %self.correlation_id,
            t_ms = at_ms,
            path = path,
            reason_code = reason_code,
            detail = detail,
            "{event} run_id={:?} corr_id={} t_ms={} path={:?} reason_code={:?} detail={:?}",
            self.run_id,
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
        self.emit_first_scoped_with_key(scope, event, event, path, reason_code, detail)
    }

    /// Emit a bounded diagnostic milestone once for a caller-defined identity
    /// within a peer+generation scope.  This is useful for a state transition
    /// that is not process-global: for example, record the first business
    /// ingress observed on Direct and the first one observed on the current
    /// Relay connection, while suppressing the remaining packets in a burst.
    ///
    /// `key` is diagnostic-only and must not contain secrets.  The event ring
    /// still has the same global bound, and the identity is kept in the same
    /// bounded-lifetime timeline object as the existing first-milestone set.
    pub fn emit_first_scoped_with_key(
        &self,
        scope: &str,
        key: &str,
        event: &'static str,
        path: Option<&str>,
        reason_code: Option<&str>,
        detail: Option<String>,
    ) -> bool {
        let mut firsts = self
            .first_events
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let identity = format!("{event}:{key}");
        if !firsts.insert((scope.to_string(), identity)) {
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

    /// Record the durable first-usable summary and its event-ring milestone as
    /// one deduplicated commit. Callers must invoke this only after the
    /// authoritative PeerConnection state transition returned `true`.
    #[allow(clippy::too_many_arguments)]
    pub fn emit_first_usable(
        &self,
        peer_id: &str,
        generation: u64,
        path: &str,
        reason_code: Option<&str>,
        detail: Option<String>,
        business_sent: bool,
        business_received: bool,
        business_exchange: bool,
        relay_id: Option<&str>,
        relay_connection_id: Option<u64>,
    ) -> bool {
        let scope = format!("peer:{peer_id}:{generation}");
        let mut firsts = self
            .first_events
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if !firsts.insert((scope, "first_usable_path:first_usable_path".to_string())) {
            return false;
        }
        drop(firsts);

        let fields = detail
            .as_deref()
            .map(parse_detail_fields)
            .unwrap_or_default();
        let (at_ms, transition_revision) =
            self.record_event("first_usable_path", Some(path), reason_code, detail.clone());
        let ready_key = (peer_id.to_string(), generation);
        let relay_ready_at_ms = self
            .relay_ready_at_ms
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .get(&ready_key)
            .copied();
        let first_usable_delta_ms = relay_ready_at_ms
            .filter(|ready_at_ms| at_ms >= *ready_at_ms)
            .map(|ready_at_ms| at_ms.saturating_sub(ready_at_ms));
        let summary = FirstUsableEvidenceSummary {
            schema_version: FIRST_USABLE_SUMMARY_SCHEMA_VERSION,
            peer_id: peer_id.to_string(),
            path: path.to_string(),
            network_generation: generation,
            first_usable_at_ms: at_ms,
            transition_revision,
            relay_ready_at_ms,
            first_usable_delta_ms,
            business_sent,
            business_received,
            business_exchange,
            relay_id: relay_id.map(str::to_string).or(fields.relay_id),
            relay_connection_id,
            reason_code: reason_code.map(str::to_string),
            source: "authoritative_business_ingress_commit".to_string(),
        };
        let mut summaries = self
            .first_usable_summaries
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        summaries.push_back(summary);
        while summaries.len() > FIRST_USABLE_SUMMARY_MAX_ENTRIES {
            summaries.pop_front();
        }
        drop(summaries);
        info!(
            event = "first_usable_path",
            run_id = ?self.run_id,
            corr_id = %self.correlation_id,
            t_ms = at_ms,
            path = path,
            reason_code = reason_code,
            peer_id = peer_id,
            generation,
            transition_revision,
            business_sent,
            business_received,
            business_exchange,
            "first_usable_path run_id={:?} corr_id={} t_ms={} peer_id={} generation={} path={} transition_revision={} business_sent={} business_received={} business_exchange={}",
            self.run_id,
            self.correlation_id,
            at_ms,
            peer_id,
            generation,
            path,
            transition_revision,
            business_sent,
            business_received,
            business_exchange,
        );
        true
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
            run_id: self.run_id.clone(),
            correlation_id: self.correlation_id.clone(),
            events,
            first_usable_summaries: self
                .first_usable_summaries
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .iter()
                .cloned()
                .collect(),
        }
    }
}

#[derive(Default)]
struct TimelineDetailFields {
    peer_id: Option<String>,
    connection_generation: Option<u64>,
    path_id: Option<String>,
    relay_id: Option<String>,
    relay_region: Option<String>,
}

fn safe_test_run_id() -> Option<String> {
    let value = std::env::var("P2WLAN_TEST_RUN_ID").ok()?;
    let value = value.trim();
    if value.is_empty()
        || value.len() > 128
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"_.:-".contains(&byte))
    {
        return None;
    }
    Some(value.to_string())
}

fn detail_value(detail: &str, keys: &[&str]) -> Option<String> {
    detail.split_whitespace().find_map(|part| {
        let (key, value) = part.split_once('=')?;
        if !keys.contains(&key) {
            return None;
        }
        let value = value.trim_matches(|ch: char| matches!(ch, ',' | ';' | ')' | ']' | '"' | '\''));
        (!value.is_empty()).then(|| value.to_string())
    })
}

fn parse_detail_fields(detail: &str) -> TimelineDetailFields {
    TimelineDetailFields {
        peer_id: detail_value(detail, &["peer_id", "peer"]),
        connection_generation: detail_value(detail, &["connection_generation", "generation"])
            .and_then(|value| value.parse().ok()),
        path_id: detail_value(detail, &["path_id"]),
        relay_id: detail_value(detail, &["relay_id", "relay_endpoint", "endpoint"]),
        relay_region: detail_value(detail, &["relay_region", "region"]),
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
            decoded.events[1].relay_id.as_deref(),
            Some("tcp://relay.test:18081")
        );
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

    #[test]
    fn timeline_emit_first_scoped_with_key_keeps_path_race_evidence() {
        let timeline = ConnectionTimeline::new("node-a", 0);
        let scope = "peer:node-b:7";

        assert!(timeline.emit_first_scoped_with_key(
            scope,
            "path=direct relay_connection_id=none usable=false",
            "business_ingress_observed",
            Some("direct"),
            Some("first_usable_not_recorded"),
            Some("peer=node-b generation=7".to_string()),
        ));
        assert!(!timeline.emit_first_scoped_with_key(
            scope,
            "path=direct relay_connection_id=none usable=false",
            "business_ingress_observed",
            Some("direct"),
            Some("first_usable_not_recorded"),
            None,
        ));
        // A later Relay ingress is a distinct, useful transition even though
        // the scope is unchanged.  This is the exact Direct-first/Relay-later
        // race that must remain diagnosable after a WireGuard replay rejection.
        assert!(timeline.emit_first_scoped_with_key(
            scope,
            "path=relay relay_connection_id=12 usable=true",
            "business_ingress_observed",
            Some("relay"),
            Some("first_usable_recorded"),
            Some("peer=node-b generation=7 relay_id=relay.test".to_string()),
        ));

        let events = timeline.snapshot().events;
        let observed: Vec<_> = events
            .iter()
            .filter(|event| event.event == "business_ingress_observed")
            .collect();
        assert_eq!(observed.len(), 2);
        assert_eq!(observed[0].path.as_deref(), Some("direct"));
        assert_eq!(observed[1].path.as_deref(), Some("relay"));
        assert_eq!(observed[1].relay_id.as_deref(), Some("relay.test"));
    }

    #[test]
    fn first_usable_summary_is_revision_fenced_and_deduplicated() {
        let timeline = ConnectionTimeline::new("node-a", 0);
        timeline.set_status_event_bus(crate::diagnostics::StatusEventBus::new());
        timeline.emit(
            "relay_transport_ready_peer",
            Some("relay"),
            None,
            Some(
                "peer=node-b generation=7 relay_endpoint=relay.test relay_connection_id=12"
                    .to_string(),
            ),
        );
        assert!(timeline.emit_first_usable(
            "node-b",
            7,
            "relay",
            None,
            Some("peer=node-b generation=7 ingress=relay:relay.test".to_string()),
            true,
            true,
            true,
            Some("relay.test"),
            Some(12),
        ));
        assert!(!timeline.emit_first_usable(
            "node-b",
            7,
            "relay",
            None,
            None,
            true,
            true,
            true,
            Some("relay.test"),
            Some(12),
        ));
        let snapshot = timeline.snapshot();
        assert_eq!(snapshot.first_usable_summaries.len(), 1);
        let summary = &snapshot.first_usable_summaries[0];
        assert_eq!(summary.schema_version, FIRST_USABLE_SUMMARY_SCHEMA_VERSION);
        assert_eq!(summary.transition_revision, 2);
        assert_eq!(
            snapshot
                .events
                .iter()
                .find(|event| event.event == "first_usable_path")
                .and_then(|event| event.transition_revision),
            Some(2)
        );
        let relay_ready_at_ms = summary.relay_ready_at_ms.expect("relay ready timestamp");
        assert!(summary.first_usable_at_ms >= relay_ready_at_ms);
        assert_eq!(
            summary.first_usable_delta_ms,
            Some(summary.first_usable_at_ms - relay_ready_at_ms)
        );
        assert!(summary.business_sent && summary.business_received && summary.business_exchange);
    }

    #[test]
    fn first_usable_summary_survives_event_ring_eviction() {
        let timeline = ConnectionTimeline::new("node-a", 0);
        timeline.emit(
            "relay_transport_ready_peer",
            Some("relay"),
            None,
            Some("peer=node-b generation=9 relay_endpoint=relay.test".to_string()),
        );
        assert!(timeline.emit_first_usable(
            "node-b",
            9,
            "relay",
            None,
            Some("peer=node-b generation=9 ingress=relay:relay.test".to_string()),
            false,
            true,
            false,
            Some("relay.test"),
            None,
        ));
        for _ in 0..(TIMELINE_MAX_EVENTS + 8) {
            timeline.emit("diagnostic_noise", None, None, None);
        }
        let snapshot = timeline.snapshot();
        assert!(!snapshot
            .events
            .iter()
            .any(|event| event.event == "first_usable_path"));
        assert_eq!(snapshot.first_usable_summaries.len(), 1);
        assert_eq!(snapshot.first_usable_summaries[0].peer_id, "node-b");
        assert_eq!(snapshot.first_usable_summaries[0].network_generation, 9);
    }

    #[test]
    fn control_reconnect_counter_survives_timeline_eviction() {
        let timeline = ConnectionTimeline::new("node-a", 0);

        // The first registration is the initial connection, not a reconnect.
        timeline.emit("control_registered", None, None, None);
        for _ in 0..TIMELINE_MAX_EVENTS {
            timeline.record_event("diagnostic_noise", None, None, None);
        }
        // The initial registration has been evicted from the bounded ring.
        timeline.emit("control_registered", None, None, None);

        assert_eq!(
            timeline
                .snapshot()
                .events
                .iter()
                .filter(|event| event.event == "control_registered")
                .count(),
            1
        );
        assert_eq!(timeline.control_reconnects(), 1);
    }
}
