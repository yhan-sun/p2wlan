//! Metadata only: sixteen writer observations and one original refused read.
//! A polled writer intent never establishes an exclusive holder or native fact.
use serde::Serialize;
use std::panic::Location;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, OnceLock, Weak};
use std::time::Instant;
const MAX_WRITERS: usize = 16;
pub(super) fn now_ns() -> Option<u64> {
    #[cfg(any(target_os = "linux", all(unix, test)))]
    {
        crate::os_request_capture::original_kernel_monotonic_ns()
    }
    #[cfg(not(any(target_os = "linux", all(unix, test))))]
    {
        None
    }
}
#[derive(Clone, Copy)]
pub(crate) struct Site {
    source: &'static str,
    line: u32,
}
impl Site {
    #[track_caller]
    pub(crate) fn caller() -> Self {
        let location = Location::caller();
        let file = location.file();
        let tail = file.rsplit_once("/src/").map_or(file, |(_, tail)| tail);
        let source = if tail.len() <= 128
            && ["peer/", "network_outbound/", "udp/", "lib/"]
                .iter()
                .any(|p| tail.starts_with(p))
        {
            tail
        } else {
            "unclassified"
        };
        Self {
            source,
            line: location.line(),
        }
    }
}
struct Writer {
    token: u64,
    site: Site,
    polled: Option<u64>,
    acquired: AtomicU64,
    granted: AtomicBool,
    ending: AtomicU64,
    released: AtomicBool,
    dropped: AtomicU64,
    finished: AtomicBool,
}
pub(super) struct WriteObservation {
    writer: Arc<Writer>,
}
impl WriteObservation {
    pub(super) fn acquired(&self) {
        if let Some(t) = now_ns() {
            self.writer.acquired.store(t, Ordering::Release);
        }
        self.writer.granted.store(true, Ordering::Release);
    }
    pub(super) fn ending(&self) {
        if let Some(t) = now_ns() {
            self.writer.ending.store(t, Ordering::Release);
        }
    }
    pub(super) fn released(&self) {
        self.writer.released.store(true, Ordering::Release);
    }
}
impl Drop for WriteObservation {
    fn drop(&mut self) {
        if let Some(t) = now_ns() {
            self.writer.dropped.store(t, Ordering::Release);
        }
        self.writer.finished.store(true, Ordering::Release);
    }
}
#[derive(Clone, Copy)]
struct Labels {
    capture_owner: u64,
    capture_id: [u8; 16],
    run: [u8; 16],
    round: [u8; 16],
    request_nonce: [u8; 16],
    sequence: u32,
    protocol: &'static str,
    kind: &'static str,
    read_peer_input_ordinal: Option<u64>,
}
struct Refusal {
    context: Labels,
    started: Option<u64>,
    returned: Option<u64>,
    writers: Vec<Arc<Writer>>,
    metadata_complete: bool,
    unobserved: u64,
}
pub(super) struct Trace {
    owner: u64,
    id: [u8; 16],
    expires: Instant,
    active: AtomicBool,
    next: AtomicU64,
    writers: Mutex<Vec<Arc<Writer>>>,
    unobserved: AtomicU64,
    first_claimed: AtomicBool,
    first: OnceLock<Refusal>,
}
impl Trace {
    pub(super) fn new(owner: u64, id: [u8; 16], expires: Instant) -> Self {
        Self {
            owner,
            id,
            expires,
            active: AtomicBool::new(true),
            next: AtomicU64::new(1),
            writers: Mutex::new(Vec::with_capacity(MAX_WRITERS)),
            unobserved: AtomicU64::new(0),
            first_claimed: AtomicBool::new(false),
            first: OnceLock::new(),
        }
    }
    fn live(&self) -> bool {
        self.active.load(Ordering::Acquire) && Instant::now() < self.expires
    }
    pub(super) fn begin(&self, site: Site) -> Option<WriteObservation> {
        if !self.live() {
            return None;
        }
        let record = || {
            let mut writers = self.writers.try_lock().ok()?;
            // Keep completed intervals until a later writer needs their slot.
            if writers.len() == MAX_WRITERS {
                let i = writers
                    .iter()
                    .position(|w| w.finished.load(Ordering::Acquire))?;
                writers.remove(i);
            }
            let token = self
                .next
                .try_update(Ordering::Relaxed, Ordering::Relaxed, |n| n.checked_add(1))
                .ok()?;
            let writer = Arc::new(Writer {
                token,
                site,
                polled: now_ns(),
                acquired: AtomicU64::new(0),
                granted: AtomicBool::new(false),
                ending: AtomicU64::new(0),
                released: AtomicBool::new(false),
                dropped: AtomicU64::new(0),
                finished: AtomicBool::new(false),
            });
            writers.push(writer.clone());
            Some(WriteObservation { writer })
        };
        let observation = record();
        if observation.is_none() {
            let _ = self
                .unobserved
                .try_update(Ordering::Relaxed, Ordering::Relaxed, |n| n.checked_add(1));
        }
        observation
    }
    #[cfg(any(target_os = "linux", all(unix, test)))]
    pub(super) fn accepts(&self, c: &crate::peer::EpochTryContext) -> bool {
        self.live()
            && c.capture_owner == self.owner
            && c.capture_id == self.id
            && c.first_read_ordinal == 0
            && c.read_peer_input_ordinal.is_some_and(|n| n != 0)
    }
    #[cfg(any(target_os = "linux", all(unix, test)))]
    pub(super) fn refused(
        &self,
        c: crate::peer::EpochTryContext,
        started: Option<u64>,
        returned: Option<u64>,
    ) {
        if !self.accepts(&c)
            || self
                .first_claimed
                .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
                .is_err()
        {
            return;
        }
        let (writers, metadata_complete) = match self.writers.try_lock() {
            Ok(ws) => (ws.iter().cloned().collect(), true),
            Err(_) => (Vec::new(), false),
        };
        let _ = self.first.set(Refusal {
            context: Labels {
                capture_owner: c.capture_owner,
                capture_id: c.capture_id,
                run: c.run,
                round: c.round,
                request_nonce: c.request_nonce,
                sequence: c.sequence,
                protocol: c.protocol,
                kind: c.kind,
                read_peer_input_ordinal: c.read_peer_input_ordinal,
            },
            started,
            returned,
            writers,
            metadata_complete,
            unobserved: self.unobserved.load(Ordering::Relaxed),
        });
    }
    fn snapshot(&self, owner: u64) -> Option<ConnectionsRefusalSnapshot> {
        if owner != self.owner {
            return None;
        }
        let r = self.first.get()?;
        let c = r.context;
        let writers=r.writers.iter().map(|w|{
            let acquired=nonzero(w.acquired.load(Ordering::Acquire));let ended=nonzero(w.ending.load(Ordering::Acquire));let released=w.released.load(Ordering::Acquire);let dropped=nonzero(w.dropped.load(Ordering::Acquire));
            let covers=matches!((acquired,r.started,r.returned,ended),(Some(a),Some(s),Some(t),Some(e))if a<=s&&s<=t&&t<=e)&&released;
            WriterSnapshot{token:w.token,source:w.site.source,source_line:w.site.line,writer_future_polled_observed_ns:w.polled,exclusive_grant_observed:w.granted.load(Ordering::Acquire),writer_acquired_observed_ns:acquired,ended_before_unlock_ns:ended,actual_guard_release_completion_observed:released,observer_drop_observed_ns:dropped,held_interval_covers_failed_try:covers}
        }).collect();
        Some(ConnectionsRefusalSnapshot {
            scope: "actual_original_peer_connections_read_try_refusal_metadata_only",
            capture_owner: c.capture_owner,
            capture_id: hex::encode(c.capture_id),
            run_nonce: hex::encode(c.run),
            round_nonce: hex::encode(c.round),
            request_nonce: hex::encode(c.request_nonce),
            sequence: c.sequence,
            protocol: c.protocol,
            kind: c.kind,
            original_input_read_ordinal: c.read_peer_input_ordinal,
            failed_try_started_ns: r.started,
            failed_try_returned_ns: r.returned,
            writer_observations: writers,
            writer_observation_cap: MAX_WRITERS,
            writer_metadata_copy_complete: r.metadata_complete,
            unobserved_writer_count_at_refusal: r.unobserved,
            queued_intent_is_not_exclusive_holder: true,
            observations_sequential_not_atomic: true,
            native_os_write_verified: false,
            physical_send_verified: false,
            canonical_current_owner_verified: false,
        })
    }
}
fn nonzero(v: u64) -> Option<u64> {
    (v != 0).then_some(v)
}
#[derive(Serialize)]
struct WriterSnapshot {
    token: u64,
    source: &'static str,
    source_line: u32,
    writer_future_polled_observed_ns: Option<u64>,
    exclusive_grant_observed: bool,
    writer_acquired_observed_ns: Option<u64>,
    ended_before_unlock_ns: Option<u64>,
    actual_guard_release_completion_observed: bool,
    observer_drop_observed_ns: Option<u64>,
    held_interval_covers_failed_try: bool,
}
#[derive(Serialize)]
pub(crate) struct ConnectionsRefusalSnapshot {
    scope: &'static str,
    capture_owner: u64,
    capture_id: String,
    run_nonce: String,
    round_nonce: String,
    request_nonce: String,
    sequence: u32,
    protocol: &'static str,
    kind: &'static str,
    original_input_read_ordinal: Option<u64>,
    failed_try_started_ns: Option<u64>,
    failed_try_returned_ns: Option<u64>,
    writer_observations: Vec<WriterSnapshot>,
    writer_observation_cap: usize,
    writer_metadata_copy_complete: bool,
    unobserved_writer_count_at_refusal: u64,
    queued_intent_is_not_exclusive_holder: bool,
    observations_sequential_not_atomic: bool,
    native_os_write_verified: bool,
    physical_send_verified: bool,
    canonical_current_owner_verified: bool,
}
pub(crate) struct ConnectionsTraceLease {
    trace: Weak<Trace>,
    owner: u64,
}
impl ConnectionsTraceLease {
    pub(super) fn new(trace: &Arc<Trace>, owner: u64) -> Self {
        Self {
            trace: Arc::downgrade(trace),
            owner,
        }
    }
    pub(super) fn disabled() -> Self {
        Self {
            trace: Weak::new(),
            owner: 0,
        }
    }
    pub(crate) fn snapshot(&self) -> Option<ConnectionsRefusalSnapshot> {
        self.trace.upgrade()?.snapshot(self.owner)
    }
    pub(crate) fn deactivate(&self) {
        if let Some(t) = self.trace.upgrade() {
            if t.owner == self.owner {
                t.active.store(false, Ordering::Release);
            }
        }
    }
}
impl Drop for ConnectionsTraceLease {
    fn drop(&mut self) {
        self.deactivate();
    }
}
