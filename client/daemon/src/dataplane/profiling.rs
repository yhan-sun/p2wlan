use std::collections::{HashMap, VecDeque};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant};

/// One packet out of every fixed-size sample window carries this context
/// through the raw outbound queue. The sample rate is deliberately low so
/// diagnostics cannot become a source of dataplane work themselves.
const PROFILE_SAMPLE_EVERY: u64 = 64;
const MAX_PROFILE_SAMPLES: usize = 512;
const PROFILE_REPORT_EVERY: u64 = 8;
const PROFILE_SUMMARY_INTERVAL: Duration = Duration::from_secs(30);
const TAIL_EVENT_RATE_LIMIT: Duration = Duration::from_millis(100);
#[allow(dead_code)]
const TUN_TURNAROUND_MAX_PENDING: usize = 128;
#[allow(dead_code)]
const TUN_TURNAROUND_TTL: Duration = Duration::from_secs(2);
/// A sampled dataplane packet above this threshold is a warning candidate.
pub(crate) const DATAPLANE_TAIL_WARNING_THRESHOLD: Duration = Duration::from_millis(2);
/// A sampled dataplane packet above this threshold is a severe tail event.
pub(crate) const DATAPLANE_TAIL_SEVERE_THRESHOLD: Duration = Duration::from_millis(5);
/// A diagnostic threshold for the field-observed 30ms+ tail, intentionally
/// far above normal sub-millisecond stage work. It emits an event only when a
/// real packet crosses the threshold; it is not a correctness timeout.
pub(crate) const DATAPLANE_STALL_THRESHOLD: Duration = Duration::from_millis(25);

/// The small amount of correlation state used to measure Android's kernel
/// echo turnaround after a packet has been written to the TUN. It deliberately
/// stores only ICMP echo id/sequence and monotonic timestamps: no payload,
/// packet copy, or routing state is retained.
#[allow(dead_code)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct IcmpEchoKey {
    identifier: u16,
    sequence: u16,
}

#[allow(dead_code)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct PendingTunEcho {
    key: IcmpEchoKey,
    written_at: Instant,
}

#[allow(dead_code)]
pub(crate) struct TunTurnaroundCorrelator {
    pending: Mutex<VecDeque<PendingTunEcho>>,
}

impl Default for TunTurnaroundCorrelator {
    fn default() -> Self {
        Self {
            pending: Mutex::new(VecDeque::with_capacity(TUN_TURNAROUND_MAX_PENDING)),
        }
    }
}

#[allow(dead_code)]
impl TunTurnaroundCorrelator {
    fn icmp_echo_key(packet: &[u8], expected_type: u8) -> Option<IcmpEchoKey> {
        let parsed = p2pnet_tun::Ipv4Packet::new(packet).ok()?;
        if parsed.protocol() != p2pnet_tun::Protocol::Icmp || parsed.is_fragment() {
            return None;
        }
        let payload = parsed.payload();
        if payload.len() < 8 || payload[0] != expected_type || payload[1] != 0 {
            return None;
        }
        Some(IcmpEchoKey {
            identifier: u16::from_be_bytes([payload[4], payload[5]]),
            sequence: u16::from_be_bytes([payload[6], payload[7]]),
        })
    }

    fn prune_expired(pending: &mut VecDeque<PendingTunEcho>, now: Instant) {
        while pending.front().is_some_and(|sample| {
            now.saturating_duration_since(sample.written_at) > TUN_TURNAROUND_TTL
        }) {
            pending.pop_front();
        }
    }

    /// Remember a sampled echo request immediately after it is written to the
    /// Android TUN. This is intentionally a no-op for unsampled packets.
    pub(crate) fn record_request(&self, packet: &[u8], written_at: Instant, sampled: bool) {
        if !sampled {
            return;
        }
        let Some(key) = Self::icmp_echo_key(packet, 8) else {
            return;
        };
        let mut pending = self
            .pending
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        Self::prune_expired(&mut pending, written_at);
        if pending.len() >= TUN_TURNAROUND_MAX_PENDING {
            pending.pop_front();
        }
        pending.push_back(PendingTunEcho { key, written_at });
    }

    /// Match a kernel-generated echo reply against a recent sampled request.
    /// Returns only the monotonic elapsed time for the diagnostic histogram.
    pub(crate) fn observe_reply(&self, packet: &[u8], read_at: Instant) -> Option<Duration> {
        let key = Self::icmp_echo_key(packet, 0)?;
        let mut pending = self
            .pending
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        Self::prune_expired(&mut pending, read_at);
        let index = pending.iter().rposition(|sample| sample.key == key)?;
        let sample = pending.remove(index)?;
        Some(read_at.saturating_duration_since(sample.written_at))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct DataplaneTxTrace {
    pub(crate) sampled: bool,
    pub(crate) tun_read_started: Instant,
    pub(crate) tun_read_completed: Instant,
    pub(crate) route_ready: Option<Instant>,
    /// Timestamp immediately before the bounded outbound send. If the queue
    /// is full this includes the backpressure wait, which is the useful local
    /// scheduler signal for the enqueue-to-dequeue interval.
    pub(crate) dataplane_queue_send_started: Option<Instant>,
    pub(crate) transport_queue_dequeued: Option<Instant>,
    pub(crate) transport_queue_send_started: Option<Instant>,
    pub(crate) network_queue_dequeued: Option<Instant>,
}

/// Diagnostic time accumulated only while one sampled plaintext packet is
/// parked in network-outbound pending queues. Moving a queue between the
/// actor and a flush task does not end an interval. An actual send attempt
/// pauses it; a retry resumes it without counting encryption/send execution
/// twice. This context never participates in a delivery decision.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct PendingQueueResidence {
    queued_at: Option<Instant>,
    accumulated: Duration,
}

impl PendingQueueResidence {
    pub(crate) fn start(sampled: bool) -> Option<Self> {
        if !sampled {
            return None;
        }
        Some(Self::start_at(Instant::now()))
    }

    pub(crate) fn start_at(now: Instant) -> Self {
        Self {
            queued_at: Some(now),
            accumulated: Duration::ZERO,
        }
    }

    pub(crate) fn pause(&mut self) {
        if self.queued_at.is_some() {
            self.pause_at(Instant::now());
        }
    }

    pub(crate) fn pause_at(&mut self, now: Instant) {
        if let Some(queued_at) = self.queued_at.take() {
            self.accumulated = self
                .accumulated
                .saturating_add(now.saturating_duration_since(queued_at));
        }
    }

    pub(crate) fn resume(&mut self) {
        if self.queued_at.is_none() {
            self.resume_at(Instant::now());
        }
    }

    fn resume_at(&mut self, now: Instant) {
        // Queue-to-queue ownership transfers and repeated admission must not
        // discard an interval that is still running.
        self.queued_at.get_or_insert(now);
    }

    pub(crate) fn finish(mut self) -> Duration {
        self.pause();
        self.accumulated
    }
}

/// Exact values available from the network-outbound actor at one sampling
/// point. Task-owned queues and each task's active packet are deliberately
/// outside actor_pending; channel byte depth and a whole-pipeline logical
/// byte total cannot be derived from these owners.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct NetworkOutboundResourceSnapshot {
    pub(crate) channel_packets: usize,
    pub(crate) actor_pending_packets: usize,
    pub(crate) actor_pending_bytes: usize,
    pub(crate) active_flush_tasks: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct DataplaneRxTrace {
    pub(crate) sampled: bool,
    pub(crate) udp_received: Option<Instant>,
    /// Timestamp immediately before the encrypted-ingress queue send.
    pub(crate) transport_queue_send_started: Option<Instant>,
    pub(crate) transport_dequeued: Instant,
    pub(crate) decrypt_started: Instant,
    pub(crate) decrypt_completed: Instant,
    /// Timestamp immediately before the decrypted inbound queue send.
    pub(crate) inbound_queue_send_started: Option<Instant>,
    pub(crate) inbound_queue_dequeued: Option<Instant>,
}

/// Values that are useful on a threshold event but should not be encoded in a
/// per-packet allocation or JSON object. Zero means the stage was not present
/// on the selected path.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct DataplaneTailMetrics {
    pub(crate) queue_wait_us: u64,
    pub(crate) emit_guard_wait_us: u64,
    pub(crate) emit_guard_hold_us: u64,
    pub(crate) epoch_gate_wait_us: u64,
    pub(crate) epoch_gate_hold_us: u64,
    pub(crate) session_lock_wait_us: u64,
    pub(crate) crypto_us: u64,
    pub(crate) udp_socket_lookup_us: u64,
    pub(crate) udp_send_call_us: u64,
    pub(crate) tun_write_us: u64,
}

#[cfg(test)]
#[derive(Debug, Clone, PartialEq, Eq)]
struct TailEventRecord {
    direction: &'static str,
    peer_id: String,
    path: &'static str,
    total_us: u64,
    metrics: DataplaneTailMetrics,
    candidate_gather_active: bool,
    network_generation: u64,
}

/// Cheap process-local counters for the specialized LAN Direct sender. These
/// are atomic on purpose: the fast path must not take the profiler histogram
/// mutex or add an allocation to every packet.
#[allow(dead_code)]
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct FastPathCounters {
    pub(crate) hits: u64,
    pub(crate) misses: u64,
    pub(crate) invalidated: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum ProfileUnit {
    Microseconds,
    Count,
    Bytes,
}

impl ProfileUnit {
    fn as_str(self) -> &'static str {
        match self {
            Self::Microseconds => "microseconds",
            Self::Count => "count",
            Self::Bytes => "bytes",
        }
    }

    fn legacy_duration_value(self, value: u64) -> Option<u64> {
        (self == Self::Microseconds).then_some(value)
    }
}

#[derive(Debug, Clone, Copy)]
struct ProfileSample {
    value: u64,
    observed_at_us: u64,
}

#[derive(Default)]
struct StageSamples {
    values: VecDeque<ProfileSample>,
    total: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct StageSummary {
    unit: ProfileUnit,
    /// Cumulative observations for this stage/unit, including evicted samples.
    sample_count: u64,
    /// Only these retained samples contribute to the percentiles below.
    window_sample_count: u64,
    window_start_elapsed_us: u64,
    window_end_elapsed_us: u64,
    window_span_us: u64,
    p50: u64,
    p95: u64,
    p99: u64,
    max: u64,
}

#[derive(Default)]
struct DataplaneProfilerState {
    stages: HashMap<(&'static str, ProfileUnit), StageSamples>,
}

/// Process-local, low-frequency dataplane profiler. It is intentionally a
/// diagnostic histogram rather than a routing input: no path or candidate
/// decision reads these values.
pub(crate) struct DataplaneProfiler {
    started_at: Instant,
    packet_counter: AtomicU64,
    candidate_gather_active: std::sync::atomic::AtomicBool,
    fast_path_hits: AtomicU64,
    fast_path_misses: AtomicU64,
    fast_path_invalidated: AtomicU64,
    tail_events: AtomicU64,
    tail_events_emitted: AtomicU64,
    tail_events_suppressed: AtomicU64,
    last_tail_event_us: AtomicU64,
    last_summary_us: AtomicU64,
    state: Mutex<DataplaneProfilerState>,
    #[cfg(test)]
    tail_event_records: Mutex<Vec<TailEventRecord>>,
}

impl DataplaneProfiler {
    fn new() -> Self {
        Self {
            started_at: Instant::now(),
            packet_counter: AtomicU64::new(0),
            candidate_gather_active: std::sync::atomic::AtomicBool::new(false),
            fast_path_hits: AtomicU64::new(0),
            fast_path_misses: AtomicU64::new(0),
            fast_path_invalidated: AtomicU64::new(0),
            tail_events: AtomicU64::new(0),
            tail_events_emitted: AtomicU64::new(0),
            tail_events_suppressed: AtomicU64::new(0),
            last_tail_event_us: AtomicU64::new(0),
            last_summary_us: AtomicU64::new(0),
            state: Mutex::new(DataplaneProfilerState::default()),
            #[cfg(test)]
            tail_event_records: Mutex::new(Vec::new()),
        }
    }

    pub(crate) fn sample_next_packet(&self) -> bool {
        self.packet_counter
            .fetch_add(1, Ordering::Relaxed)
            .is_multiple_of(PROFILE_SAMPLE_EVERY)
    }

    pub(crate) fn set_candidate_gather_active(&self, active: bool) {
        self.candidate_gather_active
            .store(active, Ordering::Release);
    }

    pub(crate) fn candidate_gather_active(&self) -> bool {
        self.candidate_gather_active.load(Ordering::Acquire)
    }

    pub(crate) fn record_fast_path_hit(&self) {
        self.fast_path_hits.fetch_add(1, Ordering::Relaxed);
    }

    pub(crate) fn record_fast_path_miss(&self) {
        self.fast_path_misses.fetch_add(1, Ordering::Relaxed);
    }

    pub(crate) fn record_fast_path_invalidation(&self) {
        self.fast_path_invalidated.fetch_add(1, Ordering::Relaxed);
    }

    #[allow(dead_code)]
    pub(crate) fn fast_path_counters(&self) -> FastPathCounters {
        FastPathCounters {
            hits: self.fast_path_hits.load(Ordering::Relaxed),
            misses: self.fast_path_misses.load(Ordering::Relaxed),
            invalidated: self.fast_path_invalidated.load(Ordering::Relaxed),
        }
    }

    pub(crate) fn record(&self, sampled: bool, stage: &'static str, duration: Duration) {
        if !sampled {
            return;
        }
        self.record_with_unit(
            true,
            stage,
            duration_us(duration),
            ProfileUnit::Microseconds,
        );
    }

    /// Record a count (for example, queue depth), rather than a duration.
    pub(crate) fn record_value(&self, sampled: bool, stage: &'static str, value: u64) {
        self.record_with_unit(sampled, stage, value, ProfileUnit::Count);
    }

    #[allow(dead_code)]
    pub(crate) fn record_bytes(&self, sampled: bool, stage: &'static str, bytes: u64) {
        self.record_with_unit(sampled, stage, bytes, ProfileUnit::Bytes);
    }

    pub(crate) fn record_network_outbound_resources(
        &self,
        sampled: bool,
        snapshot: NetworkOutboundResourceSnapshot,
    ) {
        if !sampled {
            return;
        }
        self.record_value(
            true,
            "tx_network_outbound_queue_depth",
            snapshot.channel_packets as u64,
        );
        self.record_value(
            true,
            "tx_network_outbound_actor_pending_packets",
            snapshot.actor_pending_packets as u64,
        );
        self.record_bytes(
            true,
            "tx_network_outbound_actor_pending_bytes",
            snapshot.actor_pending_bytes as u64,
        );
        self.record_value(
            true,
            "tx_network_outbound_active_flush_tasks",
            snapshot.active_flush_tasks as u64,
        );
    }

    fn record_with_unit(&self, sampled: bool, stage: &'static str, value: u64, unit: ProfileUnit) {
        if !sampled {
            return;
        }
        self.record_value_at(stage, value, unit, duration_us(self.started_at.elapsed()));
    }

    fn record_value_at(
        &self,
        stage: &'static str,
        value: u64,
        unit: ProfileUnit,
        observed_at_us: u64,
    ) {
        let report = {
            let mut state = self
                .state
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            // Unit is part of the key so an accidental mixed-unit caller
            // cannot combine durations and resource counts in one histogram.
            let samples = state.stages.entry((stage, unit)).or_default();
            samples.total = samples.total.saturating_add(1);
            if samples.values.len() >= MAX_PROFILE_SAMPLES {
                samples.values.pop_front();
            }
            samples.values.push_back(ProfileSample {
                value,
                observed_at_us,
            });
            samples
                .total
                .is_multiple_of(PROFILE_REPORT_EVERY)
                .then(|| summarize_samples(samples, unit))
        };

        if let Some(summary) = report {
            let reported_at_elapsed_us = duration_us(self.started_at.elapsed());
            tracing::debug!(
                target: "p2wlan_daemon::dataplane",
                event = "dataplane_profile",
                profile_schema_version = 2,
                stage,
                unit = summary.unit.as_str(),
                resource_scope = network_outbound_resource_scope(stage),
                total_logical_bytes_measured = network_outbound_resource_scope(stage).map(|_| false),
                sample_count = summary.sample_count,
                window_sample_count = summary.window_sample_count,
                window_kind = "latest_samples",
                window_capacity = MAX_PROFILE_SAMPLES as u64,
                sample_every_packets = PROFILE_SAMPLE_EVERY,
                window_start_elapsed_us = summary.window_start_elapsed_us,
                window_end_elapsed_us = summary.window_end_elapsed_us,
                window_span_us = summary.window_span_us,
                reported_at_elapsed_us,
                window_last_sample_age_us = reported_at_elapsed_us
                    .saturating_sub(summary.window_end_elapsed_us),
                p50 = summary.p50,
                p95 = summary.p95,
                p99 = summary.p99,
                max = summary.max,
                p50_us = summary.unit.legacy_duration_value(summary.p50),
                p95_us = summary.unit.legacy_duration_value(summary.p95),
                p99_us = summary.unit.legacy_duration_value(summary.p99),
                max_us = summary.unit.legacy_duration_value(summary.max),
                "sampled userspace dataplane stage histogram"
            );
        }
        self.maybe_report_summary();
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn record_tail_event(
        &self,
        direction: &'static str,
        peer_id: &str,
        path: &'static str,
        total: Duration,
        metrics: DataplaneTailMetrics,
        candidate_gather_active: bool,
        network_generation: u64,
    ) {
        if total < DATAPLANE_TAIL_WARNING_THRESHOLD {
            return;
        }
        self.record_tail_event_at(
            direction,
            peer_id,
            path,
            total,
            metrics,
            candidate_gather_active,
            network_generation,
            duration_us(self.started_at.elapsed()),
        );
    }

    #[allow(clippy::too_many_arguments)]
    fn record_tail_event_at(
        &self,
        direction: &'static str,
        peer_id: &str,
        path: &'static str,
        total: Duration,
        metrics: DataplaneTailMetrics,
        candidate_gather_active: bool,
        network_generation: u64,
        now_us: u64,
    ) {
        if total < DATAPLANE_TAIL_WARNING_THRESHOLD {
            return;
        }
        self.tail_events.fetch_add(1, Ordering::Relaxed);

        if !self.claim_tail_event(now_us) {
            self.tail_events_suppressed.fetch_add(1, Ordering::Relaxed);
            return;
        }
        self.tail_events_emitted.fetch_add(1, Ordering::Relaxed);

        #[cfg(test)]
        self.tail_event_records
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .push(TailEventRecord {
                direction,
                peer_id: peer_id.to_owned(),
                path,
                total_us: duration_us(total),
                metrics,
                candidate_gather_active,
                network_generation,
            });

        let severity = if total >= DATAPLANE_TAIL_SEVERE_THRESHOLD {
            "severe"
        } else {
            "warning"
        };
        tracing::debug!(
            target: "p2wlan_daemon::dataplane",
            event = "dataplane_tail_event",
            profile_schema_version = 2,
            severity,
            direction,
            peer_id,
            path,
            total_us = duration_us(total),
            queue_wait_us = metrics.queue_wait_us,
            emit_guard_wait_us = metrics.emit_guard_wait_us,
            emit_guard_hold_us = metrics.emit_guard_hold_us,
            epoch_gate_wait_us = metrics.epoch_gate_wait_us,
            epoch_gate_hold_us = metrics.epoch_gate_hold_us,
            session_lock_wait_us = metrics.session_lock_wait_us,
            crypto_us = metrics.crypto_us,
            udp_socket_lookup_us = metrics.udp_socket_lookup_us,
            udp_send_call_us = metrics.udp_send_call_us,
            tun_write_us = metrics.tun_write_us,
            candidate_gather_active,
            network_generation,
            tail_events = self.tail_events.load(Ordering::Relaxed),
            tail_events_emitted = self.tail_events_emitted.load(Ordering::Relaxed),
            tail_events_suppressed = self.tail_events_suppressed.load(Ordering::Relaxed),
            "sampled dataplane packet crossed the tail-latency diagnostic threshold"
        );
    }

    fn claim_tail_event(&self, now_us: u64) -> bool {
        // Encode zero uptime as one, reserving zero exclusively for "never
        // emitted". This keeps the first microsecond rate limited as well.
        let timestamp = now_us.saturating_add(1);
        let previous = self.last_tail_event_us.load(Ordering::Relaxed);
        (previous == 0 || timestamp.saturating_sub(previous) >= duration_us(TAIL_EVENT_RATE_LIMIT))
            && self
                .last_tail_event_us
                .compare_exchange(previous, timestamp, Ordering::Relaxed, Ordering::Relaxed)
                .is_ok()
    }

    #[cfg(test)]
    pub(crate) fn tail_event_count(&self) -> u64 {
        self.tail_events.load(Ordering::Relaxed)
    }

    #[cfg(test)]
    fn tail_event_records(&self) -> Vec<TailEventRecord> {
        self.tail_event_records
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clone()
    }

    fn maybe_report_summary(&self) {
        let elapsed_us = self
            .started_at
            .elapsed()
            .as_micros()
            .min(u128::from(u64::MAX)) as u64;
        let interval_us = PROFILE_SUMMARY_INTERVAL
            .as_micros()
            .min(u128::from(u64::MAX)) as u64;
        let previous = self.last_summary_us.load(Ordering::Relaxed);
        if elapsed_us < interval_us
            || (previous != 0 && elapsed_us.saturating_sub(previous) < interval_us)
            || self
                .last_summary_us
                .compare_exchange(previous, elapsed_us, Ordering::Relaxed, Ordering::Relaxed)
                .is_err()
        {
            return;
        }

        let summaries = {
            let state = self
                .state
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            state
                .stages
                .iter()
                .map(|((stage, unit), samples)| (*stage, summarize_samples(samples, *unit)))
                .collect::<Vec<_>>()
        };
        let reported_at_elapsed_us = duration_us(self.started_at.elapsed());
        for (stage, summary) in summaries {
            tracing::info!(
                target: "p2wlan_daemon::dataplane",
                event = "dataplane_profile_summary",
                profile_schema_version = 2,
                stage,
                unit = summary.unit.as_str(),
                resource_scope = network_outbound_resource_scope(stage),
                total_logical_bytes_measured = network_outbound_resource_scope(stage).map(|_| false),
                sample_count = summary.sample_count,
                window_sample_count = summary.window_sample_count,
                window_kind = "latest_samples",
                window_capacity = MAX_PROFILE_SAMPLES as u64,
                sample_every_packets = PROFILE_SAMPLE_EVERY,
                window_start_elapsed_us = summary.window_start_elapsed_us,
                window_end_elapsed_us = summary.window_end_elapsed_us,
                window_span_us = summary.window_span_us,
                reported_at_elapsed_us,
                window_last_sample_age_us = reported_at_elapsed_us
                    .saturating_sub(summary.window_end_elapsed_us),
                p50 = summary.p50,
                p95 = summary.p95,
                p99 = summary.p99,
                max = summary.max,
                p50_us = summary.unit.legacy_duration_value(summary.p50),
                p95_us = summary.unit.legacy_duration_value(summary.p95),
                p99_us = summary.unit.legacy_duration_value(summary.p99),
                max_us = summary.unit.legacy_duration_value(summary.max),
                fast_path_hits = self.fast_path_hits.load(Ordering::Relaxed),
                fast_path_misses = self.fast_path_misses.load(Ordering::Relaxed),
                fast_path_invalidated = self.fast_path_invalidated.load(Ordering::Relaxed),
                tail_events = self.tail_events.load(Ordering::Relaxed),
                tail_events_emitted = self.tail_events_emitted.load(Ordering::Relaxed),
                tail_events_suppressed = self.tail_events_suppressed.load(Ordering::Relaxed),
                "low-frequency sampled userspace dataplane summary"
            );
        }
    }
}

fn duration_us(duration: Duration) -> u64 {
    duration.as_micros().min(u128::from(u64::MAX)) as u64
}

fn summarize_samples(samples: &StageSamples, unit: ProfileUnit) -> StageSummary {
    let mut sorted = samples
        .values
        .iter()
        .map(|sample| sample.value)
        .collect::<Vec<_>>();
    sorted.sort_unstable();
    // Producers timestamp before taking the mutex, so insertion order need
    // not be timestamp order. Report the actual retained timestamp range.
    let window_start_elapsed_us = samples
        .values
        .iter()
        .map(|sample| sample.observed_at_us)
        .min()
        .unwrap_or(0);
    let window_end_elapsed_us = samples
        .values
        .iter()
        .map(|sample| sample.observed_at_us)
        .max()
        .unwrap_or(0);
    StageSummary {
        unit,
        sample_count: samples.total,
        window_sample_count: samples.values.len() as u64,
        window_start_elapsed_us,
        window_end_elapsed_us,
        window_span_us: window_end_elapsed_us.saturating_sub(window_start_elapsed_us),
        p50: percentile(&sorted, 50, 100),
        p95: percentile(&sorted, 95, 100),
        p99: percentile(&sorted, 99, 100),
        max: sorted.last().copied().unwrap_or(0),
    }
}

fn percentile(sorted: &[u64], numerator: usize, denominator: usize) -> u64 {
    if sorted.is_empty() {
        return 0;
    }
    let index = ((sorted.len() - 1) * numerator).div_ceil(denominator);
    sorted[index.min(sorted.len() - 1)]
}

fn network_outbound_resource_scope(stage: &str) -> Option<&'static str> {
    match stage {
        "tx_network_outbound_queue_depth" => Some("channel_queued_packets"),
        "tx_network_outbound_actor_pending_packets" | "tx_network_outbound_actor_pending_bytes" => {
            Some("actor_owned_pending_only")
        }
        "tx_network_outbound_active_flush_tasks" => Some("spawned_flush_tasks_including_unjoined"),
        _ => None,
    }
}

pub(crate) fn global_dataplane_profiler() -> &'static DataplaneProfiler {
    static PROFILER: OnceLock<DataplaneProfiler> = OnceLock::new();
    PROFILER.get_or_init(DataplaneProfiler::new)
}

#[cfg(test)]
mod profiling_tests {
    use std::net::Ipv4Addr;

    use p2pnet_tun::Ipv4Packet;

    use super::*;

    fn stage_values(profiler: &DataplaneProfiler, stage: &'static str) -> Vec<u64> {
        profiler
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .stages
            .iter()
            .find(|((name, _), _)| *name == stage)
            .map(|(_, samples)| samples.values.iter().map(|sample| sample.value).collect())
            .unwrap_or_default()
    }

    fn record_tail(
        profiler: &DataplaneProfiler,
        peer_id: &str,
        candidate_gather_active: bool,
        network_generation: u64,
        metrics: DataplaneTailMetrics,
    ) {
        profiler.record_tail_event(
            "tx",
            peer_id,
            "lan_direct",
            Duration::from_millis(6),
            metrics,
            candidate_gather_active,
            network_generation,
        );
    }

    fn allow_next_tail_event(profiler: &DataplaneProfiler) {
        profiler.last_tail_event_us.store(0, Ordering::Relaxed);
    }

    #[test]
    fn b03_pending_residence_accumulates_retry_wait_without_send_execution() {
        let start = Instant::now();
        let mut residence = PendingQueueResidence::start_at(start);
        residence.pause_at(start + Duration::from_micros(10));
        // Encryption and the failed send take 40us, outside pending queues.
        residence.resume_at(start + Duration::from_micros(50));
        residence.pause_at(start + Duration::from_micros(80));
        // Repeated pause cannot double-count a completed interval.
        residence.pause_at(start + Duration::from_micros(100));
        assert_eq!(residence.finish(), Duration::from_micros(40));
    }

    #[test]
    fn b03_pending_residence_ownership_moves_do_not_restart_queue_wait() {
        let start = Instant::now();
        let actor_owned = PendingQueueResidence::start_at(start);
        let mut task_owned = actor_owned;
        task_owned.resume_at(start + Duration::from_micros(20));
        let mut merged_actor_owned = task_owned;
        merged_actor_owned.resume_at(start + Duration::from_micros(30));
        merged_actor_owned.pause_at(start + Duration::from_micros(50));
        assert_eq!(merged_actor_owned.finish(), Duration::from_micros(50));
    }

    #[test]
    fn b03_pending_residence_drop_and_unsampled_paths_are_bounded() {
        assert!(PendingQueueResidence::start(false).is_none());
        let start = Instant::now();
        let mut residence = PendingQueueResidence::start_at(start + Duration::from_micros(1));
        // A reversed diagnostic clock never underflows or changes routing.
        residence.pause_at(start);
        residence.resume_at(start + Duration::from_micros(10));
        residence.pause_at(start + Duration::from_micros(35));
        assert_eq!(residence.finish(), Duration::from_micros(25));
    }

    #[test]
    fn b03_resource_snapshot_keeps_actor_counts_bytes_and_task_count_scoped() {
        let profiler = DataplaneProfiler::new();
        let snapshot = NetworkOutboundResourceSnapshot {
            channel_packets: 7,
            actor_pending_packets: 11,
            actor_pending_bytes: 1200,
            active_flush_tasks: 2,
        };
        profiler.record_network_outbound_resources(false, snapshot);
        assert!(profiler.state.lock().unwrap().stages.is_empty());
        profiler.record_network_outbound_resources(true, snapshot);
        let state = profiler.state.lock().unwrap();
        assert_eq!(state.stages.len(), 4);
        for (stage, unit, expected) in [
            ("tx_network_outbound_queue_depth", ProfileUnit::Count, 7),
            (
                "tx_network_outbound_actor_pending_packets",
                ProfileUnit::Count,
                11,
            ),
            (
                "tx_network_outbound_actor_pending_bytes",
                ProfileUnit::Bytes,
                1200,
            ),
            (
                "tx_network_outbound_active_flush_tasks",
                ProfileUnit::Count,
                2,
            ),
        ] {
            let summary = summarize_samples(&state.stages[&(stage, unit)], unit);
            assert_eq!(summary.p99, expected);
            assert_eq!(summary.sample_count, 1);
            assert!(network_outbound_resource_scope(stage).is_some());
        }
        assert_eq!(
            network_outbound_resource_scope("tx_pending_residence_sent_us"),
            None
        );
    }

    #[test]
    fn p1_queue_histogram_records_enqueue_to_dequeue_wait() {
        let profiler = DataplaneProfiler::new();
        let enqueue = Instant::now();
        let dequeue = enqueue + Duration::from_micros(42);
        profiler.record(
            true,
            "tx_outbound_queue_wait_us",
            dequeue.saturating_duration_since(enqueue),
        );

        assert_eq!(
            stage_values(&profiler, "tx_outbound_queue_wait_us"),
            vec![42]
        );
    }

    #[test]
    fn p2_fast_and_slow_path_histograms_are_separate() {
        let profiler = DataplaneProfiler::new();
        profiler.record_fast_path_hit();
        profiler.record(true, "tx_fast_path_lookup_us", Duration::from_micros(3));
        profiler.record(
            true,
            "tx_slow_path_total_userspace_us",
            Duration::from_micros(9),
        );

        assert_eq!(profiler.fast_path_counters().hits, 1);
        assert_eq!(stage_values(&profiler, "tx_fast_path_lookup_us"), vec![3]);
        assert_eq!(
            stage_values(&profiler, "tx_slow_path_total_userspace_us"),
            vec![9]
        );
        assert!(stage_values(&profiler, "tx_fast_path_lookup_us")
            .iter()
            .all(|value| *value != 9));
    }

    #[test]
    fn p3_emit_guard_wait_and_hold_are_distinct() {
        let profiler = DataplaneProfiler::new();
        record_tail(
            &profiler,
            "peer-a",
            false,
            1,
            DataplaneTailMetrics {
                emit_guard_wait_us: 12,
                emit_guard_hold_us: 34,
                ..DataplaneTailMetrics::default()
            },
        );

        let event = &profiler.tail_event_records()[0];
        assert_eq!(event.metrics.emit_guard_wait_us, 12);
        assert_eq!(event.metrics.emit_guard_hold_us, 34);
    }

    #[test]
    fn p4_epoch_gate_wait_and_hold_are_distinct() {
        let profiler = DataplaneProfiler::new();
        record_tail(
            &profiler,
            "peer-a",
            false,
            7,
            DataplaneTailMetrics {
                epoch_gate_wait_us: 23,
                epoch_gate_hold_us: 45,
                ..DataplaneTailMetrics::default()
            },
        );

        let event = &profiler.tail_event_records()[0];
        assert_eq!(event.metrics.epoch_gate_wait_us, 23);
        assert_eq!(event.metrics.epoch_gate_hold_us, 45);
        assert_eq!(event.network_generation, 7);
    }

    #[test]
    fn p5_session_wait_and_crypto_exec_are_separate() {
        let profiler = DataplaneProfiler::new();
        record_tail(
            &profiler,
            "peer-a",
            false,
            1,
            DataplaneTailMetrics {
                session_lock_wait_us: 17,
                crypto_us: 61,
                ..DataplaneTailMetrics::default()
            },
        );

        let event = &profiler.tail_event_records()[0];
        assert_eq!(event.metrics.session_lock_wait_us, 17);
        assert_eq!(event.metrics.crypto_us, 61);
        assert_ne!(event.metrics.session_lock_wait_us, event.metrics.crypto_us);
    }

    #[test]
    fn p6_udp_socket_lookup_and_send_are_separate() {
        let profiler = DataplaneProfiler::new();
        record_tail(
            &profiler,
            "peer-a",
            false,
            1,
            DataplaneTailMetrics {
                udp_socket_lookup_us: 29,
                udp_send_call_us: 47,
                ..DataplaneTailMetrics::default()
            },
        );

        let event = &profiler.tail_event_records()[0];
        assert_eq!(event.metrics.udp_socket_lookup_us, 29);
        assert_eq!(event.metrics.udp_send_call_us, 47);
    }

    #[test]
    fn p7_rx_queue_histogram_records_enqueue_to_dequeue_wait() {
        let profiler = DataplaneProfiler::new();
        profiler.record(true, "rx_decrypt_queue_wait_us", Duration::from_micros(31));
        profiler.record(
            true,
            "rx_dataplane_inbound_queue_wait_us",
            Duration::from_micros(53),
        );

        assert_eq!(
            stage_values(&profiler, "rx_decrypt_queue_wait_us"),
            vec![31]
        );
        assert_eq!(
            stage_values(&profiler, "rx_dataplane_inbound_queue_wait_us"),
            vec![53]
        );
    }

    #[test]
    fn p8_tun_write_metric_is_recorded_without_being_folded_into_queue_wait() {
        let profiler = DataplaneProfiler::new();
        profiler.record(true, "rx_tun_write_us", Duration::from_micros(71));
        profiler.record(
            true,
            "rx_dataplane_inbound_queue_wait_us",
            Duration::from_micros(19),
        );

        assert_eq!(stage_values(&profiler, "rx_tun_write_us"), vec![71]);
        assert_eq!(
            stage_values(&profiler, "rx_dataplane_inbound_queue_wait_us"),
            vec![19]
        );
    }

    #[test]
    fn p9_tail_event_threshold_only_counts_packets_at_or_above_warning() {
        let profiler = DataplaneProfiler::new();
        profiler.record_tail_event(
            "tx",
            "peer-a",
            "lan_direct",
            DATAPLANE_TAIL_WARNING_THRESHOLD.saturating_sub(Duration::from_nanos(1)),
            DataplaneTailMetrics::default(),
            false,
            1,
        );
        record_tail(
            &profiler,
            "peer-a",
            false,
            1,
            DataplaneTailMetrics::default(),
        );

        assert_eq!(profiler.tail_event_count(), 1);
        assert_eq!(profiler.tail_event_records().len(), 1);
    }

    #[test]
    fn p10_tail_event_logging_is_rate_limited_but_counted() {
        let profiler = DataplaneProfiler::new();
        record_tail(
            &profiler,
            "peer-a",
            false,
            1,
            DataplaneTailMetrics::default(),
        );
        profiler.last_tail_event_us.store(
            profiler.started_at.elapsed().as_micros() as u64,
            Ordering::Relaxed,
        );
        record_tail(
            &profiler,
            "peer-b",
            false,
            1,
            DataplaneTailMetrics::default(),
        );

        assert_eq!(profiler.tail_event_count(), 2);
        assert_eq!(profiler.tail_event_records().len(), 1);
    }

    #[test]
    fn p11_sampling_does_not_disable_fast_path_counters() {
        let profiler = DataplaneProfiler::new();
        profiler.record(false, "tx_fast_path_lookup_us", Duration::from_micros(3));
        profiler.record_fast_path_hit();

        assert_eq!(profiler.fast_path_counters().hits, 1);
        assert!(stage_values(&profiler, "tx_fast_path_lookup_us").is_empty());
    }

    #[test]
    fn p12_tail_context_keeps_network_generations_separate() {
        let profiler = DataplaneProfiler::new();
        record_tail(
            &profiler,
            "peer-a",
            false,
            11,
            DataplaneTailMetrics::default(),
        );
        allow_next_tail_event(&profiler);
        record_tail(
            &profiler,
            "peer-a",
            false,
            12,
            DataplaneTailMetrics::default(),
        );

        let records = profiler.tail_event_records();
        assert_eq!(records.len(), 2);
        assert_eq!(records[0].network_generation, 11);
        assert_eq!(records[1].network_generation, 12);
    }

    #[test]
    fn p13_tail_context_keeps_multiple_peers_separate() {
        let profiler = DataplaneProfiler::new();
        record_tail(
            &profiler,
            "peer-a",
            false,
            1,
            DataplaneTailMetrics::default(),
        );
        allow_next_tail_event(&profiler);
        record_tail(
            &profiler,
            "peer-b",
            false,
            1,
            DataplaneTailMetrics::default(),
        );

        let records = profiler.tail_event_records();
        assert_eq!(records.len(), 2);
        assert_eq!(records[0].peer_id, "peer-a");
        assert_eq!(records[1].peer_id, "peer-b");
    }

    #[test]
    fn p14_candidate_refresh_context_is_observed_without_mutating_gather_state() {
        let profiler = DataplaneProfiler::new();
        profiler.set_candidate_gather_active(true);
        assert!(profiler.candidate_gather_active());
        record_tail(
            &profiler,
            "peer-a",
            profiler.candidate_gather_active(),
            1,
            DataplaneTailMetrics::default(),
        );

        assert!(profiler.candidate_gather_active());
        assert!(profiler.tail_event_records()[0].candidate_gather_active);
    }

    #[test]
    fn p15_unsampled_metrics_are_a_noop_for_business_counters_and_histograms() {
        let profiler = DataplaneProfiler::new();
        profiler.record(false, "tx_total_userspace_us", Duration::from_micros(99));

        assert_eq!(profiler.fast_path_counters(), FastPathCounters::default());
        assert!(profiler.state.lock().unwrap().stages.is_empty());
    }

    #[test]
    fn fast_path_counters_are_independent_of_histogram_sampling() {
        let profiler = DataplaneProfiler::new();
        profiler.record_fast_path_hit();
        profiler.record_fast_path_hit();
        profiler.record_fast_path_miss();
        profiler.record_fast_path_invalidation();

        assert_eq!(
            profiler.fast_path_counters(),
            FastPathCounters {
                hits: 2,
                misses: 1,
                invalidated: 1,
            }
        );
    }

    #[test]
    fn packet_sampling_is_one_in_each_fixed_window() {
        let profiler = DataplaneProfiler::new();
        let sampled = (0..(PROFILE_SAMPLE_EVERY * 2))
            .filter(|_| profiler.sample_next_packet())
            .count();
        assert_eq!(sampled, 2);
    }

    #[test]
    fn unsampled_values_do_not_create_histogram_entries() {
        let profiler = DataplaneProfiler::new();
        profiler.record(false, "queue_wait_us", Duration::from_micros(7));
        let state = profiler.state.lock().unwrap();
        assert!(state.stages.is_empty());
    }

    #[test]
    fn sampled_values_are_bounded_and_keep_the_newest_tail() {
        let profiler = DataplaneProfiler::new();
        for value in 0..(MAX_PROFILE_SAMPLES as u64 + 3) {
            profiler.record_value(true, "queue_depth", value);
        }
        let state = profiler.state.lock().unwrap();
        let samples = state
            .stages
            .get(&("queue_depth", ProfileUnit::Count))
            .expect("stage recorded");
        assert_eq!(samples.values.len(), MAX_PROFILE_SAMPLES);
        assert_eq!(samples.values.front().map(|sample| sample.value), Some(3));
        assert_eq!(
            samples.values.back().map(|sample| sample.value),
            Some(MAX_PROFILE_SAMPLES as u64 + 2)
        );
    }

    #[test]
    fn tail_event_counter_ignores_sub_threshold_packets() {
        let profiler = DataplaneProfiler::new();
        profiler.record_tail_event(
            "tx",
            "peer-a",
            "lan_direct",
            Duration::from_micros(1_999),
            DataplaneTailMetrics::default(),
            false,
            1,
        );
        assert_eq!(profiler.tail_event_count(), 0);
    }

    #[test]
    fn tail_event_counter_keeps_rate_limited_events_for_diagnostics() {
        let profiler = DataplaneProfiler::new();
        for total in [Duration::from_millis(2), Duration::from_millis(5)] {
            profiler.record_tail_event(
                "tx",
                "peer-a",
                "lan_direct",
                total,
                DataplaneTailMetrics::default(),
                false,
                1,
            );
        }
        assert_eq!(profiler.tail_event_count(), 2);
    }

    #[test]
    fn percentile_is_monotonic_for_tail_samples() {
        let values = [10, 20, 30, 40, 50];
        assert!(percentile(&values, 99, 100) >= percentile(&values, 95, 100));
        assert!(percentile(&values, 95, 100) >= percentile(&values, 50, 100));
    }

    #[test]
    fn b03_profile_window_excludes_evicted_outlier_and_tracks_retained_time_range() {
        let profiler = DataplaneProfiler::new();
        let unit = ProfileUnit::Microseconds;
        profiler.record_value_at("rolling_window", 99_999, unit, 0);
        for index in 1..=MAX_PROFILE_SAMPLES as u64 {
            profiler.record_value_at("rolling_window", 7, unit, index * 10);
        }

        let state = profiler.state.lock().unwrap();
        let summary = summarize_samples(state.stages.get(&("rolling_window", unit)).unwrap(), unit);
        assert_eq!(summary.sample_count, MAX_PROFILE_SAMPLES as u64 + 1);
        assert_eq!(summary.window_sample_count, MAX_PROFILE_SAMPLES as u64);
        assert_eq!(summary.window_start_elapsed_us, 10);
        assert_eq!(
            summary.window_end_elapsed_us,
            MAX_PROFILE_SAMPLES as u64 * 10
        );
        assert_eq!(
            summary.window_span_us,
            (MAX_PROFILE_SAMPLES as u64 - 1) * 10
        );
        assert_eq!(
            (summary.p50, summary.p95, summary.p99, summary.max),
            (7, 7, 7, 7)
        );
    }

    #[test]
    fn b03_profile_window_handles_empty_single_and_reordered_sample_timestamps() {
        let unit = ProfileUnit::Count;
        let mut samples = StageSamples::default();
        let empty = summarize_samples(&samples, unit);
        assert_eq!(empty.window_sample_count, 0);
        assert_eq!(
            (
                empty.window_start_elapsed_us,
                empty.window_end_elapsed_us,
                empty.window_span_us
            ),
            (0, 0, 0)
        );
        samples.values.push_back(ProfileSample {
            value: 1,
            observed_at_us: 30,
        });
        samples.total = 1;
        let single = summarize_samples(&samples, unit);
        assert_eq!(single.window_span_us, 0);
        assert_eq!(single.window_start_elapsed_us, 30);
        samples.values.push_back(ProfileSample {
            value: 2,
            observed_at_us: 10,
        });
        samples.values.push_back(ProfileSample {
            value: 3,
            observed_at_us: 20,
        });
        samples.total = 3;
        let reordered = summarize_samples(&samples, unit);
        assert_eq!(
            (
                reordered.window_start_elapsed_us,
                reordered.window_end_elapsed_us,
                reordered.window_span_us
            ),
            (10, 30, 20)
        );
        assert_eq!(reordered.window_sample_count, 3);
    }

    #[test]
    fn b03_profile_schema_keeps_duration_aliases_and_separates_resource_units() {
        use std::collections::BTreeMap;
        use std::sync::Arc;
        use tracing::{
            field::{Field, Visit},
            Event, Subscriber,
        };
        use tracing_subscriber::{layer::Context, prelude::*, Layer};

        #[derive(Default)]
        struct Fields(BTreeMap<String, serde_json::Value>);
        impl Visit for Fields {
            fn record_bool(&mut self, field: &Field, value: bool) {
                self.0.insert(field.name().to_owned(), value.into());
            }
            fn record_i64(&mut self, field: &Field, value: i64) {
                self.0.insert(field.name().to_owned(), value.into());
            }
            fn record_u64(&mut self, field: &Field, value: u64) {
                self.0.insert(field.name().to_owned(), value.into());
            }
            fn record_str(&mut self, field: &Field, value: &str) {
                self.0.insert(field.name().to_owned(), value.into());
            }
            fn record_debug(&mut self, field: &Field, value: &dyn std::fmt::Debug) {
                self.0
                    .insert(field.name().to_owned(), format!("{value:?}").into());
            }
        }
        struct Capture(Arc<Mutex<Vec<Fields>>>);
        impl<S: Subscriber> Layer<S> for Capture {
            fn on_event(&self, event: &Event<'_>, _context: Context<'_, S>) {
                let mut fields = Fields::default();
                event.record(&mut fields);
                self.0.lock().unwrap().push(fields);
            }
        }

        let records = Arc::new(Mutex::new(Vec::new()));
        let subscriber = tracing_subscriber::registry().with(Capture(records.clone()));
        let profiler = DataplaneProfiler::new();
        tracing::subscriber::with_default(subscriber, || {
            for _ in 0..PROFILE_REPORT_EVERY {
                profiler.record(true, "duration_stage", Duration::from_micros(19));
                profiler.record_value(true, "count_stage", 3);
                profiler.record_bytes(true, "bytes_stage", 4096);
                profiler.record_network_outbound_resources(
                    true,
                    NetworkOutboundResourceSnapshot {
                        channel_packets: 2,
                        actor_pending_packets: 5,
                        actor_pending_bytes: 1500,
                        active_flush_tasks: 1,
                    },
                );
            }
        });
        let records = records.lock().unwrap();
        assert_eq!(records.len(), 7);
        for (stage, unit, value) in [
            ("duration_stage", "microseconds", 19),
            ("count_stage", "count", 3),
            ("bytes_stage", "bytes", 4096),
            ("tx_network_outbound_queue_depth", "count", 2),
            ("tx_network_outbound_actor_pending_packets", "count", 5),
            ("tx_network_outbound_actor_pending_bytes", "bytes", 1500),
            ("tx_network_outbound_active_flush_tasks", "count", 1),
        ] {
            let fields = &records
                .iter()
                .find(|fields| fields.0.get("stage") == Some(&stage.into()))
                .unwrap()
                .0;
            assert_eq!(fields.get("event"), Some(&"dataplane_profile".into()));
            assert_eq!(fields.get("profile_schema_version"), Some(&2.into()));
            if let Some(scope) = network_outbound_resource_scope(stage) {
                assert_eq!(fields.get("resource_scope"), Some(&scope.into()));
                assert_eq!(
                    fields.get("total_logical_bytes_measured"),
                    Some(&false.into())
                );
            } else {
                assert!(!fields.contains_key("resource_scope"));
                assert!(!fields.contains_key("total_logical_bytes_measured"));
            }
            assert_eq!(fields.get("unit"), Some(&unit.into()));
            assert_eq!(
                fields.get("sample_count"),
                Some(&PROFILE_REPORT_EVERY.into())
            );
            assert_eq!(
                fields.get("window_sample_count"),
                Some(&PROFILE_REPORT_EVERY.into())
            );
            assert_eq!(
                fields.get("window_capacity"),
                Some(&(MAX_PROFILE_SAMPLES as u64).into())
            );
            assert_eq!(
                fields.get("sample_every_packets"),
                Some(&PROFILE_SAMPLE_EVERY.into())
            );
            for field in ["p50", "p95", "p99", "max"] {
                assert_eq!(fields.get(field), Some(&serde_json::Value::from(value)));
            }
            for field in ["p50_us", "p95_us", "p99_us", "max_us"] {
                if unit == "microseconds" {
                    assert_eq!(fields.get(field), Some(&serde_json::Value::from(value)));
                } else {
                    assert!(!fields.contains_key(field));
                }
            }
        }
    }

    #[test]
    fn b03_tail_rate_limit_counts_suppression_and_accepts_interval_boundary() {
        let profiler = DataplaneProfiler::new();
        let interval_us = duration_us(TAIL_EVENT_RATE_LIMIT);
        for now_us in [0, interval_us - 1, interval_us] {
            profiler.record_tail_event_at(
                "tx",
                "peer-a",
                "lan_direct",
                Duration::from_millis(6),
                DataplaneTailMetrics::default(),
                false,
                1,
                now_us,
            );
        }
        assert_eq!(profiler.tail_event_count(), 3);
        assert_eq!(profiler.tail_events_emitted.load(Ordering::Relaxed), 2);
        assert_eq!(profiler.tail_events_suppressed.load(Ordering::Relaxed), 1);
        assert_eq!(profiler.tail_event_records().len(), 2);
    }

    #[test]
    fn b03_tail_rate_limit_accounts_for_concurrent_candidates() {
        use std::sync::{Arc, Barrier};

        let profiler = Arc::new(DataplaneProfiler::new());
        let barrier = Arc::new(Barrier::new(8));
        std::thread::scope(|scope| {
            for _ in 0..8 {
                let profiler = profiler.clone();
                let barrier = barrier.clone();
                scope.spawn(move || {
                    barrier.wait();
                    profiler.record_tail_event_at(
                        "tx",
                        "peer-a",
                        "lan_direct",
                        Duration::from_millis(6),
                        DataplaneTailMetrics::default(),
                        false,
                        1,
                        10,
                    );
                });
            }
        });
        assert_eq!(profiler.tail_event_count(), 8);
        assert_eq!(profiler.tail_events_emitted.load(Ordering::Relaxed), 1);
        assert_eq!(profiler.tail_events_suppressed.load(Ordering::Relaxed), 7);
        assert_eq!(profiler.tail_event_records().len(), 1);
    }

    #[test]
    fn b03_unsampled_duration_counts_and_bytes_do_not_create_windows() {
        let profiler = DataplaneProfiler::new();
        profiler.record(false, "duration_stage", Duration::from_micros(19));
        profiler.record_value(false, "count_stage", 3);
        profiler.record_bytes(false, "bytes_stage", 4096);
        assert!(profiler.state.lock().unwrap().stages.is_empty());
        assert_eq!(profiler.last_summary_us.load(Ordering::Relaxed), 0);
        assert_eq!(profiler.tail_event_count(), 0);
        assert_eq!(profiler.tail_events_emitted.load(Ordering::Relaxed), 0);
        assert_eq!(profiler.tail_events_suppressed.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn android_tun_turnaround_uses_only_icmp_echo_id_and_sequence() {
        let correlator = TunTurnaroundCorrelator::default();
        let request = Ipv4Packet::build_icmp_echo_request(
            Ipv4Addr::new(10, 20, 0, 2),
            Ipv4Addr::new(10, 20, 0, 1),
            0x1234,
            7,
            b"payload-is-not-retained",
        );
        let mut reply = request.clone();
        reply[20] = 0; // ICMP Echo Reply; the checksum is not correlation state.
        let written_at = Instant::now();

        correlator.record_request(&request, written_at, true);
        assert_eq!(
            correlator.observe_reply(&reply, written_at + Duration::from_millis(7)),
            Some(Duration::from_millis(7))
        );
        assert!(correlator
            .observe_reply(&reply, written_at + Duration::from_millis(8))
            .is_none());
    }

    #[test]
    fn android_tun_turnaround_is_bounded_and_expires() {
        let correlator = TunTurnaroundCorrelator::default();
        let start = Instant::now();
        for sequence in 0..=TUN_TURNAROUND_MAX_PENDING as u16 {
            let request = Ipv4Packet::build_icmp_echo_request(
                Ipv4Addr::new(10, 20, 0, 2),
                Ipv4Addr::new(10, 20, 0, 1),
                0x4321,
                sequence,
                &[],
            );
            correlator.record_request(
                &request,
                start + Duration::from_micros(sequence as u64),
                true,
            );
        }

        let first_request = Ipv4Packet::build_icmp_echo_request(
            Ipv4Addr::new(10, 20, 0, 2),
            Ipv4Addr::new(10, 20, 0, 1),
            0x4321,
            0,
            &[],
        );
        let mut first_reply = first_request.clone();
        first_reply[20] = 0;
        assert!(correlator
            .observe_reply(&first_reply, start + Duration::from_millis(1))
            .is_none());

        let retained_request = Ipv4Packet::build_icmp_echo_request(
            Ipv4Addr::new(10, 20, 0, 2),
            Ipv4Addr::new(10, 20, 0, 1),
            0x4321,
            1,
            &[],
        );
        let mut retained_reply = retained_request.clone();
        retained_reply[20] = 0;
        assert!(correlator
            .observe_reply(&retained_reply, start + Duration::from_millis(1))
            .is_some());

        let expired_request = Ipv4Packet::build_icmp_echo_request(
            Ipv4Addr::new(10, 20, 0, 2),
            Ipv4Addr::new(10, 20, 0, 1),
            0x4321,
            129,
            &[],
        );
        let mut expired_reply = expired_request.clone();
        expired_reply[20] = 0;
        assert!(correlator
            .observe_reply(&expired_reply, start + Duration::from_secs(3))
            .is_none());
    }
}
