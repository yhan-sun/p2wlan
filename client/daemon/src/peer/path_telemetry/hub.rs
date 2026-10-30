//! Authoritative active-path telemetry hub.
//!
//! Owns latest peer path snapshots, dirty state, and bounded coalesced
//! telemetry queueing. Non-blocking at commit time: records snapshots
//! under uncontended synchronization without async awaits, I/O, or locks
//! held across network boundaries.

use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use super::super::path_observability::PathObservabilitySnapshot;
use super::wire::{
    observation_from_snapshot, PathTelemetryFrame, PathTelemetryObservation, PathTelemetryPayload,
    MAX_PATH_TELEMETRY_FRAME_BYTES,
};

pub const MAX_DIRTY_PEERS: usize = 128;
pub const DEFAULT_BATCH_OBSERVATIONS: usize = 32;
/// A failed immutable sample gets at most three requeues. A new authoritative
/// sample or successful delivery starts a new budget; workers own its lifetime.
pub const MAX_TELEMETRY_RETRIES: u8 = 3;

#[derive(Debug, Clone, Copy)]
pub enum PathTelemetrySendFailure {
    Transport,
    Timeout,
    HttpStatus,
    Encoding,
}

#[derive(Debug)]
struct LatestPathObservation {
    observation: PathTelemetryObservation,
    retries: u8,
    // Three requeues still permit the queued final attempt. Exhaustion is
    // reached only if that attempt also fails, and survives reconnects.
    retry_exhausted: bool,
}

fn same_sample(left: &PathTelemetryObservation, right: &PathTelemetryObservation) -> bool {
    // Optional history may have been trimmed to fit a frame; it does not
    // create a new authoritative sample or reset its retry budget.
    left.remote_device_id == right.remote_device_id
        && left.network_id == right.network_id
        && left.observed_at == right.observed_at
        && left.network_generation == right.network_generation
        && left.peer_session_generation == right.peer_session_generation
        && left.remote_candidate_epoch == right.remote_candidate_epoch
        && left.observation_revision == right.observation_revision
        && left.lifecycle == right.lifecycle
        && left.current_path == right.current_path
        && left.transition_reason == right.transition_reason
}

/// Telemetry operational and health metrics counters.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PathTelemetryMetrics {
    pub enqueued_events: u64,
    pub coalesced_events: u64,
    pub dropped_events: u64,
    pub sent_batches: u64,
    pub sent_observations: u64,
    pub ack_received: u64,
    pub send_failures: u64,
    pub oversized_observations: u64,
    pub trimmed_transition_items: u64,
    pub send_transport_failures: u64,
    pub send_timeouts: u64,
    pub send_http_failures: u64,
    pub send_encoding_failures: u64,
    pub requeued_observations: u64,
    pub retry_exhausted_observations: u64,
}

/// The authoritative active-path telemetry hub.
#[derive(Debug)]
pub struct PathTelemetryHub {
    device_id: Mutex<String>,
    network_id: Mutex<String>,
    registration_seq: AtomicU64,
    latest_snapshots: Mutex<HashMap<String, LatestPathObservation>>,
    dirty_peers: Mutex<VecDeque<String>>,
    dirty_set: Mutex<HashSet<String>>,
    metrics: Mutex<PathTelemetryMetrics>,
    notify: Arc<tokio::sync::Notify>,
}

impl PathTelemetryHub {
    /// Create a new hub with the given local device and network identifiers.
    pub fn new(device_id: String, network_id: String) -> Self {
        Self {
            device_id: Mutex::new(device_id),
            network_id: Mutex::new(network_id),
            registration_seq: AtomicU64::new(0),
            latest_snapshots: Mutex::new(HashMap::new()),
            dirty_peers: Mutex::new(VecDeque::with_capacity(MAX_DIRTY_PEERS)),
            dirty_set: Mutex::new(HashSet::new()),
            metrics: Mutex::new(PathTelemetryMetrics::default()),
            notify: Arc::new(tokio::sync::Notify::new()),
        }
    }

    /// Update local identifiers (e.g. following authoritative registration).
    pub fn set_ids(&self, device_id: String, network_id: String) {
        if let Ok(mut id) = self.device_id.lock() {
            *id = device_id;
        }
        if let Ok(mut net) = self.network_id.lock() {
            *net = network_id;
        }
    }

    /// Set server-issued registration sequence fence.
    pub fn set_registration_seq(&self, seq: u64) {
        self.registration_seq.store(seq, Ordering::Release);
    }

    /// Current registration sequence.
    pub fn registration_seq(&self) -> u64 {
        self.registration_seq.load(Ordering::Acquire)
    }

    /// Synchronous, non-blocking telemetry enqueue called from `commit_path_transition`.
    pub fn enqueue(&self, remote_device_id: &str, snapshot: &PathObservabilitySnapshot) {
        let network_id = self
            .network_id
            .lock()
            .map(|g| g.clone())
            .unwrap_or_default();

        let obs = observation_from_snapshot(remote_device_id, &network_id, snapshot);

        // Update latest snapshot
        if let Ok(mut snapshots) = self.latest_snapshots.lock() {
            snapshots.insert(
                remote_device_id.to_string(),
                LatestPathObservation {
                    observation: obs,
                    retries: 0,
                    retry_exhausted: false,
                },
            );
        }

        // Bounded queueing and coalescing
        if let (Ok(mut peers), Ok(mut set), Ok(mut metrics)) = (
            self.dirty_peers.lock(),
            self.dirty_set.lock(),
            self.metrics.lock(),
        ) {
            if set.contains(remote_device_id) {
                metrics.coalesced_events = metrics.coalesced_events.saturating_add(1);
            } else {
                if peers.len() >= MAX_DIRTY_PEERS {
                    if let Some(old) = peers.pop_front() {
                        set.remove(&old);
                    }
                    metrics.dropped_events = metrics.dropped_events.saturating_add(1);
                }
                peers.push_back(remote_device_id.to_string());
                set.insert(remote_device_id.to_string());
                metrics.enqueued_events = metrics.enqueued_events.saturating_add(1);
            }
        }

        self.notify.notify_one();
    }

    /// Drain up to `max_batch` dirty observations for transmission.
    pub fn drain_dirty(&self, max_batch: usize) -> Vec<PathTelemetryObservation> {
        let peer_ids: Vec<String> = {
            if let (Ok(mut peers), Ok(mut set)) = (self.dirty_peers.lock(), self.dirty_set.lock()) {
                let count = max_batch.min(peers.len());
                let mut drained = Vec::with_capacity(count);
                for _ in 0..count {
                    if let Some(peer) = peers.pop_front() {
                        set.remove(&peer);
                        drained.push(peer);
                    }
                }
                drained
            } else {
                Vec::new()
            }
        };

        if peer_ids.is_empty() {
            return Vec::new();
        }

        let mut results = Vec::with_capacity(peer_ids.len());
        if let Ok(snapshots) = self.latest_snapshots.lock() {
            for peer_id in peer_ids {
                if let Some(obs) = snapshots.get(&peer_id) {
                    // A ready/resync can queue this ID while its final HTTP
                    // attempt is in flight. Recheck the sample at dispatch.
                    if !obs.retry_exhausted {
                        results.push(obs.observation.clone());
                    }
                }
            }
        }

        results
    }

    /// Drain a batch bounded by both observation count and complete serialized
    /// WebSocket bytes. Overflow stays dirty and is re-read from the latest
    /// coalesced snapshot on the next flush. This budget also bounds HTTP.
    pub fn drain_bounded_frame(&self, max_batch: usize) -> Option<PathTelemetryFrame> {
        let mut pending = self
            .drain_dirty(max_batch.min(DEFAULT_BATCH_OBSERVATIONS))
            .into_iter();
        let mut frame = self.build_frame(Vec::new());
        while let Some(observation) = pending.next() {
            frame.payload.observations.push(observation);
            loop {
                let fits = serde_json::to_vec(&frame)
                    .map(|bytes| bytes.len() <= MAX_PATH_TELEMETRY_FRAME_BYTES)
                    .unwrap_or(false);
                if fits {
                    break;
                }
                if frame.payload.observations.len() > 1 {
                    // The last observation belongs in a new frame. Never trim
                    // normal history just to fit an already populated batch.
                    if let Some(last) = frame.payload.observations.pop() {
                        self.requeue_dirty_ids(
                            std::iter::once(last)
                                .chain(pending)
                                .map(|observation| observation.remote_device_id),
                        );
                    }
                    return Some(frame);
                }
                // An oversized single observation must never trigger an endless
                // reconnect loop. Retain its authoritative snapshot, dropping
                // oldest optional history first and exposing the loss in metrics.
                let transitions = &mut frame.payload.observations[0].transitions;
                let trimmed = !transitions.is_empty();
                if trimmed {
                    transitions.remove(0);
                }
                if let Ok(mut metrics) = self.metrics.lock() {
                    if trimmed {
                        metrics.trimmed_transition_items =
                            metrics.trimmed_transition_items.saturating_add(1);
                    } else {
                        metrics.oversized_observations =
                            metrics.oversized_observations.saturating_add(1);
                        metrics.dropped_events = metrics.dropped_events.saturating_add(1);
                    }
                }
                if !trimmed {
                    tracing::warn!(
                        reason_code = "path_telemetry_observation_too_large",
                        limit_bytes = MAX_PATH_TELEMETRY_FRAME_BYTES,
                        "Path telemetry observation exceeds message budget"
                    );
                    frame.payload.observations.clear();
                    break;
                }
            }
        }
        (!frame.payload.observations.is_empty()).then_some(frame)
    }

    fn requeue_dirty_ids(&self, peers_to_retry: impl Iterator<Item = String>) -> usize {
        let mut requeued = 0;
        if let (Ok(mut peers), Ok(mut set), Ok(mut metrics)) = (
            self.dirty_peers.lock(),
            self.dirty_set.lock(),
            self.metrics.lock(),
        ) {
            for peer in peers_to_retry {
                if set.contains(&peer) {
                    continue;
                }
                if peers.len() == MAX_DIRTY_PEERS {
                    metrics.dropped_events = metrics.dropped_events.saturating_add(1);
                    continue;
                }
                set.insert(peer.clone());
                peers.push_back(peer);
                requeued += 1;
            }
        }
        requeued
    }

    /// Retry peer IDs, never old cloned data. A concurrent committed generation
    /// is already in latest_snapshots and will be read by the next drain.
    /// No notification is emitted: HTTP retries use the existing five-second
    /// worker tick, and a failed WebSocket leaves its current connection.
    pub fn retry_observations(&self, failed: &[PathTelemetryObservation]) {
        let mut exhausted = 0u64;
        let mut peers = Vec::with_capacity(failed.len());
        if let Ok(mut snapshots) = self.latest_snapshots.lock() {
            for observation in failed {
                let Some(latest) = snapshots.get_mut(&observation.remote_device_id) else {
                    continue;
                };
                // An older in-flight failure cannot revive an exhausted
                // replacement sample merely because its identity differs.
                if latest.retry_exhausted {
                    continue;
                }
                if same_sample(&latest.observation, observation) {
                    if latest.retries == MAX_TELEMETRY_RETRIES {
                        latest.retry_exhausted = true;
                        exhausted = exhausted.saturating_add(1);
                        continue;
                    }
                    latest.retries += 1;
                }
                peers.push(observation.remote_device_id.clone());
            }
        }
        let requeued = self.requeue_dirty_ids(peers.into_iter());
        if let Ok(mut metrics) = self.metrics.lock() {
            metrics.requeued_observations = metrics
                .requeued_observations
                .saturating_add(requeued as u64);
            metrics.retry_exhausted_observations = metrics
                .retry_exhausted_observations
                .saturating_add(exhausted);
            metrics.dropped_events = metrics.dropped_events.saturating_add(exhausted);
        }
        if exhausted > 0 {
            tracing::warn!(
                reason_code = "path_telemetry_retry_exhausted",
                observations = exhausted,
                "Path telemetry delivery exhausted its retry budget"
            );
        }
    }

    /// Check if there are any pending dirty peers.
    pub fn has_dirty(&self) -> bool {
        self.dirty_peers
            .lock()
            .map(|p| !p.is_empty())
            .unwrap_or(false)
    }

    /// Mark all known peers dirty to trigger full resync on reconnect.
    pub fn mark_all_dirty(&self) {
        if let (Ok(snapshots), Ok(mut peers), Ok(mut set)) = (
            self.latest_snapshots.lock(),
            self.dirty_peers.lock(),
            self.dirty_set.lock(),
        ) {
            for (peer_id, latest) in snapshots.iter() {
                if !latest.retry_exhausted
                    && !set.contains(peer_id)
                    && peers.len() < MAX_DIRTY_PEERS
                {
                    peers.push_back(peer_id.clone());
                    set.insert(peer_id.clone());
                }
            }
        }
        self.notify.notify_one();
    }

    /// Snapshot all current observations.
    pub fn snapshot_all(&self) -> Vec<PathTelemetryObservation> {
        self.latest_snapshots
            .lock()
            .map(|m| {
                m.values()
                    .map(|latest| latest.observation.clone())
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Build a wire payload containing the provided observations.
    pub fn build_payload(
        &self,
        observations: Vec<PathTelemetryObservation>,
    ) -> PathTelemetryPayload {
        let device_id = self.device_id.lock().map(|d| d.clone()).unwrap_or_default();
        let network_id = self
            .network_id
            .lock()
            .map(|n| n.clone())
            .unwrap_or_default();
        let sent_at = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_millis() as i64)
            .unwrap_or(0);

        PathTelemetryPayload {
            device_id,
            network_id,
            sent_at,
            observations,
        }
    }

    /// Build a WebSocket signaling frame wrapping observations.
    pub fn build_frame(&self, observations: Vec<PathTelemetryObservation>) -> PathTelemetryFrame {
        PathTelemetryFrame {
            frame_type: "path_telemetry".to_string(),
            payload: self.build_payload(observations),
        }
    }

    /// Record that a batch of observations was transmitted.
    pub fn record_sent_batch(&self, count: usize) {
        if let Ok(mut metrics) = self.metrics.lock() {
            metrics.sent_batches = metrics.sent_batches.saturating_add(1);
            metrics.sent_observations = metrics.sent_observations.saturating_add(count as u64);
        }
    }

    /// Clear only the retry budget belonging to the exact delivered sample.
    /// A newer generation remains untouched if it arrived during network I/O.
    pub fn record_delivery_success(&self, observations: &[PathTelemetryObservation]) {
        if let Ok(mut snapshots) = self.latest_snapshots.lock() {
            for observation in observations {
                if let Some(latest) = snapshots.get_mut(&observation.remote_device_id) {
                    if same_sample(&latest.observation, observation) {
                        latest.retries = 0;
                        latest.retry_exhausted = false;
                    }
                }
            }
        }
        self.record_sent_batch(observations.len());
    }

    /// Record that an ack frame was received from the Control server.
    pub fn record_ack(&self, _sent_at: i64) {
        if let Ok(mut metrics) = self.metrics.lock() {
            metrics.ack_received = metrics.ack_received.saturating_add(1);
        }
    }

    /// Record a failed transmission.
    pub fn record_send_failure(&self) {
        self.record_delivery_failure(PathTelemetrySendFailure::Transport);
    }

    pub fn record_delivery_failure(&self, reason: PathTelemetrySendFailure) {
        if let Ok(mut metrics) = self.metrics.lock() {
            metrics.send_failures = metrics.send_failures.saturating_add(1);
            let counter = match reason {
                PathTelemetrySendFailure::Transport => &mut metrics.send_transport_failures,
                PathTelemetrySendFailure::Timeout => &mut metrics.send_timeouts,
                PathTelemetrySendFailure::HttpStatus => &mut metrics.send_http_failures,
                PathTelemetrySendFailure::Encoding => &mut metrics.send_encoding_failures,
            };
            *counter = counter.saturating_add(1);
        }
    }

    /// Retrieve a snapshot of the current metrics.
    pub fn metrics(&self) -> PathTelemetryMetrics {
        self.metrics.lock().map(|m| m.clone()).unwrap_or_default()
    }

    /// Async notification hook: waits until at least one peer is marked dirty.
    pub async fn wait_for_dirty(&self) {
        self.notify.notified().await;
    }
}
