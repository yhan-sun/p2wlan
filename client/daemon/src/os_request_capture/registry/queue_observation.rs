//! First observation of this packet's two existing bounded channel intervals.
//! These process-local differences grant no read, Full, path or current-owner
//! authority. Pending queues, locks, crypto and kernel time are not covered.
use super::*;
use crate::dataplane::DataplaneTxTrace;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg_attr(not(unix), allow(dead_code))] // Descriptor snapshots are Unix-only.
#[cfg_attr(unix, derive(Serialize))]
#[cfg_attr(unix, serde(tag = "availability", rename_all = "snake_case"))]
pub(super) enum QueueInterval {
    Available { nanoseconds: u64 },
    Unavailable { reason: &'static str },
}

fn interval(start: Option<Instant>, end: Option<Instant>) -> QueueInterval {
    let (Some(start), Some(end)) = (start, end) else {
        return QueueInterval::Unavailable {
            reason: "boundary_missing",
        };
    };
    // Windows may tolerate a reversed Instant within the QPC error margin.
    // Observations require strict boundary order rather than a zero duration.
    if end < start {
        return QueueInterval::Unavailable {
            reason: "clock_order_invalid",
        };
    }
    let Some(elapsed) = end.checked_duration_since(start) else {
        return QueueInterval::Unavailable {
            reason: "clock_order_invalid",
        };
    };
    match u64::try_from(elapsed.as_nanos()) {
        Ok(nanoseconds) => QueueInterval::Available { nanoseconds },
        Err(_) => QueueInterval::Unavailable {
            reason: "duration_out_of_range",
        },
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg_attr(not(unix), allow(dead_code))] // Keep the same packet carrier on Windows.
#[cfg_attr(unix, derive(Serialize))]
pub(super) struct QueueIntervals {
    schema_version: u8,
    scope: &'static str,
    clock: &'static str,
    dataplane_queue: QueueInterval,
    network_outbound_queue: QueueInterval,
    pending_queue: QueueInterval,
}

impl QueueIntervals {
    fn from_trace(trace: Option<&DataplaneTxTrace>) -> Self {
        Self {
            schema_version: 1,
            scope: "same_packet_initial_bounded_queue_intervals",
            clock: "process_local_std_instant_differences_only",
            dataplane_queue: interval(
                trace.and_then(|t| t.dataplane_queue_send_started),
                trace.and_then(|t| t.transport_queue_dequeued),
            ),
            network_outbound_queue: interval(
                trace.and_then(|t| t.transport_queue_send_started),
                trace.and_then(|t| t.network_queue_dequeued),
            ),
            pending_queue: QueueInterval::Unavailable {
                reason: "not_observed_by_this_scope",
            },
        }
    }
}

impl KernelReadBinding {
    pub(crate) fn observe_initial_queue_intervals(&self, trace: Option<&DataplaneTxTrace>) {
        // The same sealed read binding travels with this exact packet owner.
        // One set only: a later requeue cannot refill a missing first boundary.
        let _ = self
            .initial_queue_intervals
            .set(QueueIntervals::from_trace(trace));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn two_channel_intervals_keep_backpressure_in_separate_process_local_differences() {
        let start = Instant::now();
        let end = start + std::time::Duration::from_nanos(23);
        assert_eq!(
            interval(Some(start), Some(end)),
            QueueInterval::Available { nanoseconds: 23 }
        );
        assert_eq!(
            interval(Some(start), Some(start)),
            QueueInterval::Available { nanoseconds: 0 }
        );
    }

    #[test]
    fn missing_or_reversed_boundaries_are_unavailable_without_saturation_to_zero() {
        let start = Instant::now();
        let end = start + std::time::Duration::from_nanos(1);
        assert_eq!(
            interval(None, Some(end)),
            QueueInterval::Unavailable {
                reason: "boundary_missing"
            }
        );
        assert_eq!(
            interval(Some(end), Some(start)),
            QueueInterval::Unavailable {
                reason: "clock_order_invalid"
            }
        );
    }

    #[test]
    fn actual_trace_mapping_keeps_both_channel_boundaries_distinct_and_pending_unavailable() {
        let start = Instant::now();
        let trace = DataplaneTxTrace {
            sampled: false,
            tun_read_started: start,
            tun_read_completed: start + std::time::Duration::from_nanos(1),
            route_ready: Some(start + std::time::Duration::from_nanos(5)),
            dataplane_queue_send_started: Some(start + std::time::Duration::from_nanos(7)),
            transport_queue_dequeued: Some(start + std::time::Duration::from_nanos(31)),
            transport_queue_send_started: Some(start + std::time::Duration::from_nanos(40)),
            network_queue_dequeued: Some(start + std::time::Duration::from_nanos(88)),
        };
        let observed = QueueIntervals::from_trace(Some(&trace));
        assert_eq!(
            observed.dataplane_queue,
            QueueInterval::Available { nanoseconds: 24 }
        );
        assert_eq!(
            observed.network_outbound_queue,
            QueueInterval::Available { nanoseconds: 48 }
        );
        assert_eq!(
            observed.pending_queue,
            QueueInterval::Unavailable {
                reason: "not_observed_by_this_scope"
            }
        );
        let mut missing = trace;
        missing.transport_queue_send_started = None;
        let partial = QueueIntervals::from_trace(Some(&missing));
        assert_eq!(partial.dataplane_queue, observed.dataplane_queue);
        assert_eq!(
            partial.network_outbound_queue,
            QueueInterval::Unavailable {
                reason: "boundary_missing"
            }
        );
    }
}
