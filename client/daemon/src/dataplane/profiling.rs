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
/// A sampled dataplane packet above this threshold is a warning candidate.
pub(crate) const DATAPLANE_TAIL_WARNING_THRESHOLD: Duration = Duration::from_millis(2);
/// A sampled dataplane packet above this threshold is a severe tail event.
pub(crate) const DATAPLANE_TAIL_SEVERE_THRESHOLD: Duration = Duration::from_millis(5);
/// A diagnostic threshold for the field-observed 30ms+ tail, intentionally
/// far above normal sub-millisecond stage work. It emits an event only when a
/// real packet crosses the threshold; it is not a correctness timeout.
pub(crate) const DATAPLANE_STALL_THRESHOLD: Duration = Duration::from_millis(25);

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

#[derive(Default)]
struct StageSamples {
    values: VecDeque<u64>,
    total: u64,
}

#[derive(Default)]
struct DataplaneProfilerState {
    stages: HashMap<&'static str, StageSamples>,
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
    last_tail_event_us: AtomicU64,
    last_summary_us: AtomicU64,
    state: Mutex<DataplaneProfilerState>,
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
            last_tail_event_us: AtomicU64::new(0),
            last_summary_us: AtomicU64::new(0),
            state: Mutex::new(DataplaneProfilerState::default()),
        }
    }

    pub(crate) fn sample_next_packet(&self) -> bool {
        self.packet_counter
            .fetch_add(1, Ordering::Relaxed)
            .is_multiple_of(PROFILE_SAMPLE_EVERY)
    }

    pub(crate) fn set_candidate_gather_active(&self, active: bool) {
        self.candidate_gather_active.store(active, Ordering::Release);
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
        self.record_value(sampled, stage, duration.as_micros().min(u128::from(u64::MAX)) as u64);
    }

    pub(crate) fn record_value(&self, sampled: bool, stage: &'static str, value: u64) {
        if !sampled {
            return;
        }
        let report = {
            let mut state = self.state.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
            let samples = state.stages.entry(stage).or_default();
            samples.total = samples.total.saturating_add(1);
            if samples.values.len() >= MAX_PROFILE_SAMPLES {
                samples.values.pop_front();
            }
            samples.values.push_back(value);
            samples.total.is_multiple_of(PROFILE_REPORT_EVERY).then(|| {
                summarize_samples(samples)
            })
        };

        if let Some((sample_count, p50_us, p95_us, p99_us, max_us)) = report {
            tracing::debug!(
                target: "p2wlan_daemon::dataplane",
                event = "dataplane_profile",
                stage,
                sample_count,
                p50_us,
                p95_us,
                p99_us,
                max_us,
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
        self.tail_events.fetch_add(1, Ordering::Relaxed);

        let now_us = self.started_at.elapsed().as_micros().min(u128::from(u64::MAX)) as u64;
        let previous = self.last_tail_event_us.load(Ordering::Relaxed);
        if previous != 0
            && now_us.saturating_sub(previous)
                < TAIL_EVENT_RATE_LIMIT.as_micros().min(u128::from(u64::MAX)) as u64
        {
            return;
        }
        if self
            .last_tail_event_us
            .compare_exchange(previous, now_us, Ordering::Relaxed, Ordering::Relaxed)
            .is_err()
        {
            return;
        }

        let severity = if total >= DATAPLANE_TAIL_SEVERE_THRESHOLD {
            "severe"
        } else {
            "warning"
        };
        tracing::debug!(
            target: "p2wlan_daemon::dataplane",
            event = "dataplane_tail_event",
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
            "sampled dataplane packet crossed the tail-latency diagnostic threshold"
        );
    }

    #[cfg(test)]
    pub(crate) fn tail_event_count(&self) -> u64 {
        self.tail_events.load(Ordering::Relaxed)
    }

    fn maybe_report_summary(&self) {
        let elapsed_us = self.started_at.elapsed().as_micros().min(u128::from(u64::MAX)) as u64;
        let interval_us = PROFILE_SUMMARY_INTERVAL.as_micros().min(u128::from(u64::MAX)) as u64;
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
            let state = self.state.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
            state
                .stages
                .iter()
                .map(|(stage, samples)| (*stage, summarize_samples(samples)))
                .collect::<Vec<_>>()
        };
        for (stage, (sample_count, p50_us, p95_us, p99_us, max_us)) in summaries {
            tracing::info!(
                target: "p2wlan_daemon::dataplane",
                event = "dataplane_profile_summary",
                stage,
                sample_count,
                p50_us,
                p95_us,
                p99_us,
                max_us,
                fast_path_hits = self.fast_path_hits.load(Ordering::Relaxed),
                fast_path_misses = self.fast_path_misses.load(Ordering::Relaxed),
                fast_path_invalidated = self.fast_path_invalidated.load(Ordering::Relaxed),
                tail_events = self.tail_events.load(Ordering::Relaxed),
                "low-frequency sampled userspace dataplane summary"
            );
        }
    }
}

fn duration_us(duration: Duration) -> u64 {
    duration.as_micros().min(u128::from(u64::MAX)) as u64
}

fn summarize_samples(samples: &StageSamples) -> (u64, u64, u64, u64, u64) {
    let mut sorted = samples.values.iter().copied().collect::<Vec<_>>();
    sorted.sort_unstable();
    (
        samples.total,
        percentile(&sorted, 50, 100),
        percentile(&sorted, 95, 100),
        percentile(&sorted, 99, 100),
        sorted.last().copied().unwrap_or(0),
    )
}

fn percentile(sorted: &[u64], numerator: usize, denominator: usize) -> u64 {
    if sorted.is_empty() {
        return 0;
    }
    let index = ((sorted.len() - 1) * numerator).div_ceil(denominator);
    sorted[index.min(sorted.len() - 1)]
}

pub(crate) fn global_dataplane_profiler() -> &'static DataplaneProfiler {
    static PROFILER: OnceLock<DataplaneProfiler> = OnceLock::new();
    PROFILER.get_or_init(DataplaneProfiler::new)
}

#[cfg(test)]
mod profiling_tests {
    use super::*;

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
        let samples = state.stages.get("queue_depth").expect("stage recorded");
        assert_eq!(samples.values.len(), MAX_PROFILE_SAMPLES);
        assert_eq!(samples.values.front(), Some(&3));
        assert_eq!(samples.values.back(), Some(&(MAX_PROFILE_SAMPLES as u64 + 2)));
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
}
