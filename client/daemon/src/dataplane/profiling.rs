use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant};

/// One packet out of every fixed-size sample window carries this context
/// through the raw outbound queue. The sample rate is deliberately low so
/// diagnostics cannot become a source of dataplane work themselves.
const PROFILE_SAMPLE_EVERY: u64 = 64;
const MAX_PROFILE_SAMPLES: usize = 512;
const PROFILE_REPORT_EVERY: u64 = 64;
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
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct DataplaneRxTrace {
    pub(crate) sampled: bool,
    pub(crate) transport_dequeued: Instant,
    pub(crate) decrypt_completed: Instant,
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
    values: Vec<u64>,
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
    packet_counter: AtomicU64,
    candidate_gather_active: std::sync::atomic::AtomicBool,
    fast_path_hits: AtomicU64,
    fast_path_misses: AtomicU64,
    fast_path_invalidated: AtomicU64,
    state: Mutex<DataplaneProfilerState>,
}

impl DataplaneProfiler {
    fn new() -> Self {
        Self {
            packet_counter: AtomicU64::new(0),
            candidate_gather_active: std::sync::atomic::AtomicBool::new(false),
            fast_path_hits: AtomicU64::new(0),
            fast_path_misses: AtomicU64::new(0),
            fast_path_invalidated: AtomicU64::new(0),
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
        let micros = duration.as_micros().min(u128::from(u64::MAX)) as u64;
        let mut state = self.state.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        let samples = state.stages.entry(stage).or_default();
        samples.total = samples.total.saturating_add(1);
        if samples.values.len() >= MAX_PROFILE_SAMPLES {
            samples.values.remove(0);
        }
        samples.values.push(micros);

        if !samples.total.is_multiple_of(PROFILE_REPORT_EVERY) {
            return;
        }
        let mut sorted = samples.values.clone();
        sorted.sort_unstable();
        let p50_us = percentile(&sorted, 50, 100);
        let p95_us = percentile(&sorted, 95, 100);
        let p99_us = percentile(&sorted, 99, 100);
        let max_us = sorted.last().copied().unwrap_or(0);
        tracing::debug!(
            target: "p2wlan_daemon::dataplane",
            event = "dataplane_profile",
            stage,
            sample_count = samples.total,
            p50_us,
            p95_us,
            p99_us,
            max_us,
            "sampled userspace dataplane stage histogram"
        );
    }
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
}
