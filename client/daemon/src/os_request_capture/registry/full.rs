//! Historical Fulls from the existing original physical-attempt producer.
//! No current connection state or final once permission is owned here.
use super::{CaptureSession, FullRetentionLossReason, KernelReadBinding, RegisteredFlowPlan};
use crate::os_request_capture::clock::monotonic_ns;
use crate::os_request_capture::plan::{CaptureFailure, Protocol};
use crate::peer::PeerManager;
#[cfg(unix)]
use serde::Serialize;
use std::sync::atomic::Ordering;
use std::sync::{Arc, Weak};
use std::time::Instant;

// One scope, at most 1000 registered requests, and an independent packet-fact
// capacity. Fragmentation/retransmission cannot grow retained metadata forever.
pub(super) const MAX_FULL_PACKETS: usize = 1024;
const MAX_FRAME_WIRE_BYTES: usize = 1204;

/// A negative observation guard, never a Full or current-owner permission.
/// Only an actual KernelRead supplies its weak scope. Preparation alone does
/// not arm it; the original physical-attempt owner arms it before opening.
pub(crate) struct OriginalFullObservation {
    scope: Weak<CaptureSession>,
    armed: bool,
}

impl OriginalFullObservation {
    pub(crate) fn arm(&mut self) {
        self.armed = true;
    }

    /// Called only after the original Full callback or a definitely-not-handed
    /// terminal. Disarming this observer cannot restore a previously lost one.
    pub(crate) fn complete(&mut self) {
        self.armed = false;
    }
}

impl Drop for OriginalFullObservation {
    fn drop(&mut self) {
        if self.armed {
            if let Some(scope) = self.scope.upgrade() {
                scope.original_full_retention_lost(FullRetentionLossReason::ObservationDropped);
            }
        }
    }
}

impl CaptureSession {
    pub(super) fn original_full_retention_lost(&self, reason: FullRetentionLossReason) {
        // No lock or retry: loss must remain observable even when the history
        // mutex itself caused the miss. Later duplicates never rearm a scope.
        self.full_loss.record(reason);
        self.original_observation_lost(&self.full_complete);
    }
}

#[derive(Clone, Copy)]
#[cfg_attr(unix, derive(Serialize))]
pub(super) struct ReadFrameSpan {
    slot: usize,
    start: u16,
    end: u16,
}

impl ReadFrameSpan {
    pub(super) fn new(slot: usize, start: u16, end: u16) -> Self {
        Self { slot, start, end }
    }

    pub(super) fn slot(&self) -> usize {
        self.slot
    }

    fn fits(&self, plan: &RegisteredFlowPlan) -> bool {
        let length = match plan.protocol {
            Protocol::Udp => 1,
            Protocol::Tcp => 4 + 63 + usize::from(plan.payload_bytes),
        };
        self.slot < plan.requests.len()
            && self.start < self.end
            && usize::from(self.end) <= length
            && length <= MAX_FRAME_WIRE_BYTES
    }
}

#[derive(Clone)]
pub(super) struct FrameSpanCoverage {
    slot: usize,
    length: usize,
    seen: [u64; MAX_FRAME_WIRE_BYTES.div_ceil(64)],
    covered: usize,
}

impl FrameSpanCoverage {
    pub(super) fn new(plan: &RegisteredFlowPlan, slot: usize) -> Option<Self> {
        let length = match plan.protocol {
            Protocol::Udp => 1,
            Protocol::Tcp => 4 + 63 + usize::from(plan.payload_bytes),
        };
        (slot < plan.requests.len() && length <= MAX_FRAME_WIRE_BYTES).then_some(Self {
            slot,
            length,
            seen: [0; MAX_FRAME_WIRE_BYTES.div_ceil(64)],
            covered: 0,
        })
    }

    /// True only when this original span contributes previously missing bytes.
    pub(super) fn add(&mut self, span: &ReadFrameSpan) -> Result<bool, CaptureFailure> {
        if span.slot != self.slot {
            return Ok(false);
        }
        let (start, end) = (usize::from(span.start), usize::from(span.end));
        if start >= end || end > self.length {
            return Err(CaptureFailure::InvalidPlan);
        }
        let before = self.covered;
        let first_word = start / 64;
        let last_word = (end - 1) / 64;
        for word in first_word..=last_word {
            let low = if word == first_word { start % 64 } else { 0 };
            let high = if word == last_word {
                (end - 1) % 64 + 1
            } else {
                64
            };
            let mask = (u64::MAX << low) & (u64::MAX >> (64 - high));
            let fresh = mask & !self.seen[word];
            self.seen[word] |= mask;
            self.covered += fresh.count_ones() as usize;
        }
        Ok(self.covered != before)
    }

    pub(super) fn is_complete(&self) -> bool {
        self.covered == self.length
    }
}

#[cfg(unix)]
pub(super) fn spans_complete<'a>(
    spans: impl Iterator<Item = &'a ReadFrameSpan>,
    slot: usize,
    plan: &RegisteredFlowPlan,
) -> bool {
    #[cfg(all(unix, test))]
    snapshot_coverage_probe_for_test();
    let Some(mut coverage) = FrameSpanCoverage::new(plan, slot) else {
        return false;
    };
    for span in spans {
        if coverage.add(span).is_err() {
            return false;
        }
    }
    coverage.is_complete()
}

#[cfg(unix)]
#[derive(Serialize)]
pub(super) struct FullPacketSnapshot {
    flow: usize,
    read_ordinal: u64,
    read_monotonic_ns: u64,
    full_observed_monotonic_ns: u64,
    publication_observed_monotonic_ns: Option<u64>,
    packet_len: usize,
    #[serde(serialize_with = "super::snapshot_hex::serialize")]
    packet_sha256: [u8; 32],
    spans: Vec<ReadFrameSpan>,
    attempt_id: u64,
    encryption_generation: u64,
    encryption_session_instance: u64,
    encryption_peer_lifecycle: Option<u64>,
    physical_path: &'static str,
    initial_queue_intervals: Option<super::queue_observation::QueueIntervals>,
}

// The bounded original-read index is installed by the actual read producer.
// An indexed read is not a Full: only its sole physical producer can seal the
// nonzero observation. Snapshots serialize that fact without completing it.
#[cfg(any(target_os = "linux", all(unix, test)))]
pub(super) fn frame_complete(
    reads: &super::Published<Arc<KernelReadBinding>>,
    flow: usize,
    slot: usize,
    plan: &RegisteredFlowPlan,
) -> bool {
    spans_complete(
        reads
            .iter()
            .filter(|read| read.flow == flow && read.full_observed_ns().is_some())
            .flat_map(|read| &read.spans),
        slot,
        plan,
    )
}

#[cfg(unix)]
pub(super) fn snapshot(
    reads: &super::Published<Arc<KernelReadBinding>>,
    mut output: Vec<FullPacketSnapshot>,
) -> Vec<FullPacketSnapshot> {
    output.extend(reads.iter().filter_map(|read| {
        let observed_monotonic_ns = read.full_observed_ns()?;
        let record = read.physical_publication.record()?;
        Some(FullPacketSnapshot {
            flow: read.flow,
            read_ordinal: read.read.ordinal(),
            read_monotonic_ns: read.read.monotonic_ns(),
            full_observed_monotonic_ns: observed_monotonic_ns,
            publication_observed_monotonic_ns: read.original_publication_ns.get().copied(),
            packet_len: read.packet_len,
            packet_sha256: read.packet_sha256,
            spans: read.spans.clone(),
            initial_queue_intervals: read.initial_queue_intervals.get().copied(),
            attempt_id: record.attempt_id(),
            encryption_generation: record.encryption_generation(),
            encryption_session_instance: record.encryption().session_instance(),
            encryption_peer_lifecycle: record
                .encryption()
                .authorized_peer_lifecycle()
                .map(|life| life.value()),
            physical_path: if record.udp().is_some() {
                "udp"
            } else {
                "relay"
            },
        })
    }));
    output
}

impl KernelReadBinding {
    #[cfg(unix)]
    pub(super) fn full_observed_ns(&self) -> Option<u64> {
        let at = self.full_retained_ns.load(Ordering::Acquire);
        (at != 0).then_some(at)
    }
    /// The sole actual Full producer calls this just before publishing its
    /// Instant observation. This clock precedes that boundary; later retention
    /// time is a different upper bound and must not stand in for publication.
    pub(crate) fn observe_original_publication_clock(&self) {
        let Some(at) = monotonic_ns().filter(|at| *at != 0) else {
            self.full_retention_lost(FullRetentionLossReason::PublicationClockUnavailable);
            return;
        };
        if self.original_publication_ns.set(at).is_err() {
            self.full_retention_lost(FullRetentionLossReason::PublicationClockAlreadyRecorded);
        }
    }

    pub(crate) fn original_full_observation(&self) -> OriginalFullObservation {
        OriginalFullObservation {
            scope: self.scope.clone(),
            armed: false,
        }
    }

    pub(crate) fn original_full_retention_lost(&self, reason: FullRetentionLossReason) {
        self.full_retention_lost(reason);
    }

    fn full_retention_lost(&self, reason: FullRetentionLossReason) {
        if let Some(scope) = self.scope.upgrade() {
            scope.original_full_retention_lost(reason);
        }
    }

    pub(crate) fn physical_publication(&self) -> &crate::overlay_requests::PhysicalSendPublication {
        &self.physical_publication
    }

    pub(crate) fn peer_id(&self) -> &str {
        &self.plan.peer
    }

    pub(crate) fn read_at(&self) -> Instant {
        self.read.at()
    }

    pub(crate) fn original_peer_owner(&self, peers: &PeerManager) -> Option<Weak<PeerManager>> {
        let scope = self.scope.upgrade()?;
        std::ptr::eq(scope.peers.as_ptr(), peers).then(|| scope.peers.clone())
    }

    pub(crate) fn original_peer_owner_ptr_matches(&self, peers: &Weak<PeerManager>) -> bool {
        self.scope
            .upgrade()
            .is_some_and(|scope| scope.peers.ptr_eq(peers))
    }

    pub(crate) fn retain_original_full(self: &Arc<Self>) {
        let Some(scope) = self.scope.upgrade() else {
            return;
        };
        let retain = || -> Result<(), FullRetentionLossReason> {
            let record = self
                .physical_publication
                .record()
                .ok_or(FullRetentionLossReason::PublicationMissing)?;
            if !record.matches_original_kernel_read(self) {
                return Err(FullRetentionLossReason::PublicationIdentityMismatch);
            }
            if self.physical_publication.recorded_observed_at().is_none() {
                return Err(FullRetentionLossReason::PublicationObservationMissing);
            }
            // A native observation AFTER the actual original Full is an upper
            // bound, never a reconstructed syscall timestamp. The original
            // application deadline is compared separately, without rearming.
            let observed = monotonic_ns()
                .filter(|at| *at != 0)
                .ok_or(FullRetentionLossReason::RetentionClockUnavailable)?;
            if observed < self.read.monotonic_ns()
                || self.spans.is_empty()
                || !self.spans.iter().all(|span| span.fits(&self.plan))
            {
                return Err(FullRetentionLossReason::history(
                    CaptureFailure::InvalidPlan,
                ));
            }
            // No metadata lock, allocation or wait at the actual producer.
            // The original read index is already bounded to MAX_FULL_PACKETS.
            // Duplicates keep the first observation and cannot rearm a scope.
            if self
                .full_retained_ns
                .compare_exchange(0, observed, Ordering::Release, Ordering::Relaxed)
                .is_err()
            {
                return Ok(());
            }
            #[cfg(any(target_os = "linux", all(unix, test)))]
            self.complete_original_full_or_notify(&scope);
            Ok(())
        };
        if let Err(reason) = retain() {
            scope.original_full_retention_lost(reason);
        }
    }
}

#[cfg(all(unix, test))]
pub(super) mod tests;

// Only deterministic metadata controls install this one-shot thread-local hook.
// It observes the real mutex during the original coverage operation, with no
// native read/write, positive owner, retry, timer or production callback.
#[cfg(all(unix, test))]
thread_local! {
    static SNAPSHOT_COVERAGE_PROBE: std::cell::RefCell<Option<Box<dyn FnOnce()>>> =
        const { std::cell::RefCell::new(None) };
}

#[cfg(all(unix, test))]
pub(super) fn on_next_snapshot_coverage_for_test(probe: impl FnOnce() + 'static) {
    SNAPSHOT_COVERAGE_PROBE.with(|slot| {
        assert!(slot.borrow_mut().replace(Box::new(probe)).is_none());
    });
}

#[cfg(all(unix, test))]
fn snapshot_coverage_probe_for_test() {
    let probe = SNAPSHOT_COVERAGE_PROBE.with(|slot| slot.borrow_mut().take());
    if let Some(probe) = probe {
        probe();
    }
}
