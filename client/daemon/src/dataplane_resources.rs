//! Private, opt-in software-buffer observations, without packet authority.
//!
//! Vec operations and observed capacities are not allocator calls or RSS.
//! Counters cover fixed sites; leases cover only their two plaintext FIFOs.
//! The private opt-in readout is retained without wiring a default capture or
//! status export. Its currently unused readout items are marked individually.

use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Instant;

#[cfg(test)]
mod tests;

const CAS_ATTEMPTS: usize = 8;
const MAX_CAPTURE_BYTES: usize = 16 * 1024;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum VecSite {
    UdpReaderBuffer,
    UdpWireCopy,
    RxParsedPayloadCopy,
    RxAuthenticatedPlaintext,
    RxTunPacketCopy,
    RxNormalizedPacketCopy,
    TxTunReadCopy,
    TxRoutedPacketCopy,
    TxNormalizedPacketCopy,
    TxRetryCopy,
    TxPreparationCopy,
    TxSerializedWire,
}

impl VecSite {
    pub(crate) const COUNT: usize = 12;

    #[allow(dead_code)] // Used by the private snapshot readout.
    const ALL: [Self; Self::COUNT] = [
        Self::UdpReaderBuffer,
        Self::UdpWireCopy,
        Self::RxParsedPayloadCopy,
        Self::RxAuthenticatedPlaintext,
        Self::RxTunPacketCopy,
        Self::RxNormalizedPacketCopy,
        Self::TxTunReadCopy,
        Self::TxRoutedPacketCopy,
        Self::TxNormalizedPacketCopy,
        Self::TxRetryCopy,
        Self::TxPreparationCopy,
        Self::TxSerializedWire,
    ];

    fn index(self) -> usize {
        self as usize
    }

    #[allow(dead_code)] // Used by the private snapshot readout.
    fn copies_are_known(self) -> bool {
        !matches!(
            self,
            Self::UdpReaderBuffer | Self::RxAuthenticatedPlaintext | Self::TxSerializedWire
        )
    }

    fn accepts(self, operation: VecOperation) -> bool {
        match self {
            Self::UdpReaderBuffer => operation == VecOperation::FixedReadBuffer,
            Self::RxAuthenticatedPlaintext => operation == VecOperation::CryptoOutput,
            Self::TxSerializedWire => operation == VecOperation::SerializedOutput,
            _ => operation.is_copy(),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum VecOperation {
    SliceCopy,
    DeepClone,
    CryptoOutput,
    SerializedOutput,
    FixedReadBuffer,
}

impl VecOperation {
    fn is_copy(self) -> bool {
        matches!(self, Self::SliceCopy | Self::DeepClone)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum QueueStage {
    ActorFifo,
    TaskOrUnjoinedFifo,
}

impl QueueStage {
    const COUNT: usize = 2;

    fn index(self) -> usize {
        self as usize
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum RecordDisposition {
    Recorded,
    Disabled,
    InvalidObservation,
    CounterOverflow,
    GaugeUnderflow,
    Contended,
}

impl RecordDisposition {
    fn gap_bit(self) -> u32 {
        match self {
            Self::InvalidObservation => 1,
            Self::CounterOverflow => 2,
            Self::GaugeUnderflow => 4,
            Self::Contended => 8,
            Self::Recorded | Self::Disabled => 0,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum EnableError {
    AlreadyEnabled,
    CaptureFinished,
}

#[derive(Default)]
struct VecCounters {
    materialization_ops: AtomicU64,
    copy_ops: AtomicU64,
    known_copied_bytes: AtomicU64,
    destination_len_observed_sum: AtomicU64,
    destination_capacity_observed_sum: AtomicU64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[allow(dead_code)] // Private opt-in readout; no default status export.
pub(crate) struct VecSiteSnapshot {
    pub(crate) materialization_ops: u64,
    pub(crate) copy_ops: u64,
    pub(crate) known_copied_bytes: u64,
    pub(crate) destination_len_observed_sum: u64,
    pub(crate) destination_capacity_observed_sum: u64,
    pub(crate) copied_bytes_known: bool,
}

#[derive(Default)]
struct FifoCounters {
    lease_scope_observed: AtomicBool,
    live_packets: AtomicU64,
    plaintext_len: AtomicU64,
    vec_capacity: AtomicU64,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
#[allow(dead_code)] // Private opt-in readout; no default status export.
pub(crate) struct FifoSnapshot {
    pub(crate) live_packets: u64,
    pub(crate) plaintext_len: u64,
    pub(crate) vec_capacity: u64,
}

/// All snapshots are bounded reads, not a multi-atomic transaction.
#[allow(dead_code)] // Private opt-in readout; no default status export.
pub(crate) struct ResourceSnapshot {
    pub(crate) scope: [u8; 16],
    pub(crate) read_started: Instant,
    pub(crate) read_completed: Instant,
    pub(crate) enabled: bool,
    pub(crate) ended: bool,
    pub(crate) coherent: bool,
    pub(crate) valid: bool,
    pub(crate) gap_bits: u32,
    pub(crate) allocator_alloc_calls_measured: bool,
    pub(crate) allocator_free_calls_measured: bool,
    pub(crate) channel_bytes_measured: bool,
    pub(crate) session_backlog_measured: bool,
    pub(crate) active_attempt_bytes_measured: bool,
    pub(crate) overflow_report_bytes_measured: bool,
    pub(crate) relay_writer_bytes_measured: bool,
    pub(crate) crypto_temporaries_measured: bool,
    pub(crate) kernel_bytes_measured: bool,
    pub(crate) queue_metadata_bytes_measured: bool,
    pub(crate) total_pipeline_bytes_measured: bool,
    sites: [VecSiteSnapshot; VecSite::COUNT],
    fifo: [FifoSnapshot; QueueStage::COUNT],
    fifo_lease_scope_observed: [bool; QueueStage::COUNT],
}

#[allow(dead_code)] // Private opt-in readout; no default status export.
impl ResourceSnapshot {
    pub(crate) fn vec_site(&self, site: VecSite) -> VecSiteSnapshot {
        self.sites[site.index()]
    }

    pub(crate) fn fifo(&self, stage: QueueStage) -> FifoSnapshot {
        self.fifo[stage.index()]
    }

    /// Zero without an observed lease is missing coverage, not measured zero.
    /// Observed means covered lease owners, never every FIFO in the pipeline.
    pub(crate) fn fifo_scope_observed(&self, stage: QueueStage) -> bool {
        self.fifo_lease_scope_observed[stage.index()]
    }
}

/// A fixed footprint, explicit-finish capture. Existing leases survive finish.
/// The scope is a caller's run label, never a networking/fencing authority.
pub(crate) struct ResourceCapture {
    #[allow(dead_code)] // Run label is consumed by the private snapshot readout.
    scope: [u8; 16],
    ended: AtomicBool,
    gaps: AtomicU32,
    sites: [VecCounters; VecSite::COUNT],
    fifo: [FifoCounters; QueueStage::COUNT],
}

const _: () = assert!(std::mem::size_of::<ResourceCapture>() <= MAX_CAPTURE_BYTES);

impl ResourceCapture {
    #[allow(dead_code)] // No production capture is armed by default.
    pub(crate) fn new(scope: [u8; 16]) -> Arc<Self> {
        Arc::new(Self {
            scope,
            ended: AtomicBool::new(false),
            gaps: AtomicU32::new(0),
            sites: std::array::from_fn(|_| VecCounters::default()),
            fifo: std::array::from_fn(|_| FifoCounters::default()),
        })
    }

    pub(crate) fn is_finished(&self) -> bool {
        self.ended.load(Ordering::Acquire)
    }

    #[allow(dead_code)] // Private capture lifecycle, without a default caller.
    pub(crate) fn finish(&self) {
        // Do not reset counters: an existing FIFO still owns its stored bytes.
        self.ended.store(true, Ordering::Release);
    }

    fn gap(&self, disposition: RecordDisposition) -> RecordDisposition {
        self.gaps.fetch_or(disposition.gap_bit(), Ordering::Relaxed);
        disposition
    }

    fn adjust(&self, counter: &AtomicU64, amount: u64, increase: bool) -> RecordDisposition {
        if amount == 0 {
            return RecordDisposition::Recorded;
        }
        let mut previous = counter.load(Ordering::Relaxed);
        for _ in 0..CAS_ATTEMPTS {
            let next = if increase {
                previous.checked_add(amount)
            } else {
                previous.checked_sub(amount)
            };
            let Some(next) = next else {
                return self.gap(if increase {
                    RecordDisposition::CounterOverflow
                } else {
                    RecordDisposition::GaugeUnderflow
                });
            };
            match counter.compare_exchange(previous, next, Ordering::Relaxed, Ordering::Relaxed) {
                Ok(_) => return RecordDisposition::Recorded,
                Err(current) => previous = current,
            }
        }
        self.gap(RecordDisposition::Contended)
    }

    // Vec is intentional: capacity is an observed property of this destination.
    #[allow(clippy::ptr_arg)]
    pub(crate) fn observe_vec(
        &self,
        site: VecSite,
        operation: VecOperation,
        copied_bytes: Option<usize>,
        destination: &Vec<u8>,
    ) -> RecordDisposition {
        if self.is_finished() {
            return RecordDisposition::Disabled;
        }
        if !site.accepts(operation)
            || operation.is_copy() != copied_bytes.is_some()
            || copied_bytes.is_some_and(|bytes| bytes != destination.len())
        {
            return self.gap(RecordDisposition::InvalidObservation);
        }
        let (Ok(len), Ok(capacity), Ok(copied)) = (
            u64::try_from(destination.len()),
            u64::try_from(destination.capacity()),
            u64::try_from(copied_bytes.unwrap_or(0)),
        ) else {
            return self.gap(RecordDisposition::InvalidObservation);
        };
        let counters = &self.sites[site.index()];
        let updates = [
            (&counters.materialization_ops, 1),
            (&counters.copy_ops, u64::from(operation.is_copy())),
            (&counters.known_copied_bytes, copied),
            (&counters.destination_len_observed_sum, len),
            (&counters.destination_capacity_observed_sum, capacity),
        ];
        for (counter, amount) in updates {
            let outcome = self.adjust(counter, amount, true);
            if outcome != RecordDisposition::Recorded {
                return outcome;
            }
        }
        RecordDisposition::Recorded
    }

    #[allow(dead_code)] // Private opt-in readout; no default status export.
    pub(crate) fn snapshot(&self) -> ResourceSnapshot {
        let read_started = Instant::now();
        let ended = self.is_finished();
        let mut sites = std::array::from_fn(|i| {
            let counters = &self.sites[i];
            let materialization_ops = counters.materialization_ops.load(Ordering::Relaxed);
            VecSiteSnapshot {
                materialization_ops,
                copy_ops: counters.copy_ops.load(Ordering::Relaxed),
                known_copied_bytes: counters.known_copied_bytes.load(Ordering::Relaxed),
                destination_len_observed_sum: counters
                    .destination_len_observed_sum
                    .load(Ordering::Relaxed),
                destination_capacity_observed_sum: counters
                    .destination_capacity_observed_sum
                    .load(Ordering::Relaxed),
                // The unit's known/unknown classification is fixed per site.
                // A partial concurrent read must never label crypto/serialized
                // output as measured copy bytes before another atomic updates.
                copied_bytes_known: materialization_ops != 0 && VecSite::ALL[i].copies_are_known(),
            }
        });
        let fifo = std::array::from_fn(|i| FifoSnapshot {
            live_packets: self.fifo[i].live_packets.load(Ordering::Relaxed),
            plaintext_len: self.fifo[i].plaintext_len.load(Ordering::Relaxed),
            vec_capacity: self.fifo[i].vec_capacity.load(Ordering::Relaxed),
        });
        let fifo_lease_scope_observed =
            std::array::from_fn(|i| self.fifo[i].lease_scope_observed.load(Ordering::Relaxed));
        let gap_bits = self.gaps.load(Ordering::Relaxed);
        if gap_bits != 0 {
            for site in &mut sites {
                site.copied_bytes_known = false;
            }
        }
        ResourceSnapshot {
            scope: self.scope,
            read_started,
            read_completed: Instant::now(),
            enabled: !ended,
            ended,
            coherent: false,
            valid: gap_bits == 0,
            gap_bits,
            allocator_alloc_calls_measured: false,
            allocator_free_calls_measured: false,
            channel_bytes_measured: false,
            session_backlog_measured: false,
            active_attempt_bytes_measured: false,
            overflow_report_bytes_measured: false,
            relay_writer_bytes_measured: false,
            crypto_temporaries_measured: false,
            kernel_bytes_measured: false,
            queue_metadata_bytes_measured: false,
            total_pipeline_bytes_measured: false,
            sites,
            fifo,
            fifo_lease_scope_observed,
        }
    }

    fn change_fifo(
        &self,
        stage: QueueStage,
        previous: QueueTotals,
        next: QueueTotals,
    ) -> RecordDisposition {
        let counters = &self.fifo[stage.index()];
        let changes = [
            (&counters.live_packets, previous.packets, next.packets),
            (
                &counters.plaintext_len,
                previous.plaintext_len,
                next.plaintext_len,
            ),
            (
                &counters.vec_capacity,
                previous.vec_capacity,
                next.vec_capacity,
            ),
        ];
        let mut result = RecordDisposition::Recorded;
        for (counter, old, new) in changes {
            let Ok(amount) = u64::try_from(new.abs_diff(old)) else {
                result = self.gap(RecordDisposition::InvalidObservation);
                continue;
            };
            let outcome = self.adjust(counter, amount, new >= old);
            if result == RecordDisposition::Recorded && outcome != RecordDisposition::Recorded {
                result = outcome;
            }
        }
        result
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) struct QueueTotals {
    pub(crate) packets: usize,
    pub(crate) plaintext_len: usize,
    pub(crate) vec_capacity: usize,
}

/// Move-only aggregate ownership of one FIFO; no packet IDs or new queue.
pub(crate) struct QueueAggregateLease {
    capture: Arc<ResourceCapture>,
    stage: QueueStage,
    totals: QueueTotals,
}

impl QueueAggregateLease {
    pub(crate) fn new(capture: Arc<ResourceCapture>, stage: QueueStage) -> Option<Self> {
        if capture.is_finished() {
            return None;
        }
        capture.fifo[stage.index()]
            .lease_scope_observed
            .store(true, Ordering::Relaxed);
        Some(Self {
            capture,
            stage,
            totals: QueueTotals::default(),
        })
    }

    pub(crate) fn set_totals(&mut self, next: QueueTotals) -> RecordDisposition {
        if next.plaintext_len > next.vec_capacity
            || (next.packets == 0 && (next.plaintext_len != 0 || next.vec_capacity != 0))
        {
            return self.capture.gap(RecordDisposition::InvalidObservation);
        }
        let outcome = self.capture.change_fifo(self.stage, self.totals, next);
        // Even if diagnostics failed, remember this owner's actual local total.
        // No diagnostic error changes its business storage/lifecycle decision.
        self.totals = next;
        outcome
    }

    pub(crate) fn relocate(&mut self, stage: QueueStage) -> RecordDisposition {
        if stage == self.stage {
            return RecordDisposition::Recorded;
        }
        self.capture.fifo[stage.index()]
            .lease_scope_observed
            .store(true, Ordering::Relaxed);
        let removed = self
            .capture
            .change_fifo(self.stage, self.totals, QueueTotals::default());
        let added = self
            .capture
            .change_fifo(stage, QueueTotals::default(), self.totals);
        self.stage = stage;
        if removed != RecordDisposition::Recorded {
            removed
        } else {
            added
        }
    }
}

impl Drop for QueueAggregateLease {
    fn drop(&mut self) {
        self.capture
            .change_fifo(self.stage, self.totals, QueueTotals::default());
    }
}
