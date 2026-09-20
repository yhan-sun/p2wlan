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
};

pub const MAX_DIRTY_PEERS: usize = 128;
pub const DEFAULT_BATCH_OBSERVATIONS: usize = 32;

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
}

/// The authoritative active-path telemetry hub.
#[derive(Debug)]
pub struct PathTelemetryHub {
    device_id: Mutex<String>,
    network_id: Mutex<String>,
    registration_seq: AtomicU64,
    latest_snapshots: Mutex<HashMap<String, PathTelemetryObservation>>,
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
            snapshots.insert(remote_device_id.to_string(), obs);
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
                    results.push(obs.clone());
                }
            }
        }

        results
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
            for peer_id in snapshots.keys() {
                if !set.contains(peer_id) && peers.len() < MAX_DIRTY_PEERS {
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
            .map(|m| m.values().cloned().collect())
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

    /// Record that an ack frame was received from the Control server.
    pub fn record_ack(&self, _sent_at: i64) {
        if let Ok(mut metrics) = self.metrics.lock() {
            metrics.ack_received = metrics.ack_received.saturating_add(1);
        }
    }

    /// Record a failed transmission.
    pub fn record_send_failure(&self) {
        if let Ok(mut metrics) = self.metrics.lock() {
            metrics.send_failures = metrics.send_failures.saturating_add(1);
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
