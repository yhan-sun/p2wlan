// Bounded, monotonic status event log backing the `/events?since=N` long-poll
// endpoint and the `/status` `revision` counter.
//
// Design notes:
// - The producer side (`record`) is **synchronous** so it can be called from
//   `ConnectionTimeline::record_event` (which is sync and runs from many
//   subsystems). It stores a bounded `VecDeque` behind a `std::sync::Mutex`.
// - `seq` is a per-process monotonic counter that is never reset; the bounded
//   ring may evict old *events* once past `STATUS_EVENT_MAX_EVENTS`, but the
//   counter keeps advancing so `/events?since=N` stays monotonic. A client that
//   falls behind the ring beyond `N - evicted` must re-fetch a full `/status`
//   snapshot (the revision in that snapshot is authoritative).
// - The consumer side exposes an async long-poll (`wait_or_poll`) that waits on
//   a `tokio::sync::Notify` until a new event arrives or the timeout elapses.
//
// This file is `include!`-spliced into the `diagnostics` module scope, so it
// relies on that scope's imports (`Arc`, `Serialize`, `Duration`) and
// fully-qualifies the rest.

/// Bound on retained events so `/events` responses stay bounded. The `seq`
/// counter is unbounded; only the ring evicts.
pub const STATUS_EVENT_MAX_EVENTS: usize = 1024;

/// One status event exposed over `/events`. Kept intentionally small and
/// credential-free: it mirrors the timeline event identity but never carries
/// tickets, tokens, keys, or endpoint credentials.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StatusEvent {
    pub seq: u64,
    pub event: String,
    pub at_ms: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason_code: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub peer_id: Option<String>,
}

struct StatusEventInner {
    seq: u64,
    ring: std::collections::VecDeque<StatusEvent>,
}

/// One atomic view of the bounded event ring. `revision`, `oldest_seq`, and
/// `events` are captured under the same mutex so a client can never receive a
/// newer cursor while the corresponding event is absent from the response.
#[derive(Debug, Clone)]
pub struct StatusEventPoll {
    /// Daemon process incarnation. Sequence numbers restart at zero, so this
    /// disambiguates two processes that happen to have the same revision.
    pub process_id: u32,
    pub revision: u64,
    pub oldest_seq: u64,
    pub reset_required: bool,
    pub events: Vec<StatusEvent>,
}

/// A process-wide bounded status event log. Cheap to clone (`Arc`).
pub struct StatusEventBus {
    process_id: u32,
    inner: std::sync::Mutex<StatusEventInner>,
    notify: tokio::sync::Notify,
}

impl StatusEventBus {
    pub fn new() -> Arc<Self> {
        Self::with_process_id(std::process::id())
    }

    fn with_process_id(process_id: u32) -> Arc<Self> {
        Arc::new(Self {
            process_id,
            inner: std::sync::Mutex::new(StatusEventInner {
                seq: 0,
                ring: std::collections::VecDeque::new(),
            }),
            notify: tokio::sync::Notify::new(),
        })
    }

    /// Record an event, assigning it the next monotonic `seq`. Synchronous.
    /// Returns the assigned `seq`.
    pub fn record(
        &self,
        event: &str,
        at_ms: u64,
        path: Option<&str>,
        reason_code: Option<&str>,
        peer_id: Option<&str>,
    ) -> u64 {
        let seq = {
            let mut guard = self.inner.lock().unwrap_or_else(|p| p.into_inner());
            guard.seq += 1;
            let ev = StatusEvent {
                seq: guard.seq,
                event: event.to_string(),
                at_ms,
                path: path.map(str::to_string),
                reason_code: reason_code.map(str::to_string),
                peer_id: peer_id.map(str::to_string),
            };
            guard.ring.push_back(ev);
            while guard.ring.len() > STATUS_EVENT_MAX_EVENTS {
                guard.ring.pop_front();
            }
            guard.seq
        };
        self.notify.notify_waiters();
        seq
    }

    /// Current monotonic revision (same value used as `/status.revision`).
    pub fn current_seq(&self) -> u64 {
        let guard = self.inner.lock().unwrap_or_else(|p| p.into_inner());
        guard.seq
    }

    /// Capture the ring and its cursor metadata atomically.
    pub fn poll(&self, since: u64) -> StatusEventPoll {
        self.poll_for_process(since, None)
    }

    /// Capture the ring for a client cursor bound to an optional daemon
    /// process incarnation. A mismatched process requires an immediate full
    /// reset even when the old and new processes have the same revision.
    pub fn poll_for_process(
        &self,
        since: u64,
        expected_process_id: Option<u32>,
    ) -> StatusEventPoll {
        let guard = self.inner.lock().unwrap_or_else(|p| p.into_inner());
        let oldest_seq = guard.ring.front().map(|event| event.seq).unwrap_or(0);
        // A cursor above the current per-process revision belongs to an older
        // daemon process. A cursor below the retained ring has an eviction gap.
        // In either case deltas alone cannot reconstruct current state.
        let reset_required = expected_process_id.is_some_and(|id| id != self.process_id)
            || since > guard.seq
            || (oldest_seq != 0 && since.saturating_add(1) < oldest_seq);
        let events = guard
            .ring
            .iter()
            .filter(|event| event.seq > since)
            .cloned()
            .collect();
        StatusEventPoll {
            process_id: self.process_id,
            revision: guard.seq,
            oldest_seq,
            reset_required,
            events,
        }
    }

    /// All retained events with `seq > since`, in ascending order. Bounded by
    /// the ring. Does not wait.
    pub fn since(&self, since: u64) -> Vec<StatusEvent> {
        self.poll(since).events
    }

    /// Long-poll: if there are events after `since`, return them immediately;
    /// otherwise wait up to `timeout` for a new event and then return whatever
    /// has arrived (possibly empty).
    pub async fn wait_or_poll(&self, since: u64, timeout: Duration) -> StatusEventPoll {
        self.wait_or_poll_for_process(since, None, timeout).await
    }

    /// Process-bound long-poll. A process mismatch never waits: callers must
    /// discard their cursor and fetch a fresh `/status` snapshot immediately.
    pub async fn wait_or_poll_for_process(
        &self,
        since: u64,
        expected_process_id: Option<u32>,
        timeout: Duration,
    ) -> StatusEventPoll {
        // Register and enable the waiter BEFORE checking the ring. If a record
        // lands before registration, the following poll sees it; if it lands
        // after registration, Notify wakes us. This closes the old check-then-
        // register lost-wakeup window that could add the full 25s HTTP timeout.
        let notified = self.notify.notified();
        tokio::pin!(notified);
        notified.as_mut().enable();
        let initial = self.poll_for_process(since, expected_process_id);
        if initial.reset_required || !initial.events.is_empty() {
            return initial;
        }
        if timeout == Duration::ZERO {
            return initial;
        }
        let _ = tokio::time::timeout(timeout, notified).await;
        self.poll_for_process(since, expected_process_id)
    }
}

#[cfg(test)]
mod status_event_bus_tests {
    use super::*;

    #[test]
    fn seq_is_monotonic_and_since_filters() {
        let bus = StatusEventBus::new();
        let s1 = bus.record("a", 100, Some("direct"), None, None);
        let s2 = bus.record("b", 200, None, Some("ok"), Some("node-b"));
        let s3 = bus.record("c", 300, None, None, None);
        assert_eq!((s1, s2, s3), (1, 2, 3));
        assert_eq!(bus.current_seq(), 3);

        let since1 = bus.since(1);
        assert_eq!(since1.len(), 2);
        assert_eq!(since1[0].event, "b");
        assert_eq!(since1[0].peer_id.as_deref(), Some("node-b"));
        assert_eq!(since1[1].event, "c");

        assert!(bus.since(3).is_empty());
        assert_eq!(bus.since(0).len(), 3);
    }

    #[test]
    fn ring_is_bounded_and_seq_keeps_advancing() {
        let bus = StatusEventBus::new();
        let total = STATUS_EVENT_MAX_EVENTS + 50;
        for i in 0..total {
            bus.record("e", i as u64, None, None, None);
        }
        assert_eq!(bus.current_seq(), total as u64);
        // Ring holds only the most recent STATUS_EVENT_MAX_EVENTS.
        let all = bus.since(0);
        assert_eq!(all.len(), STATUS_EVENT_MAX_EVENTS);
        assert_eq!(
            all[0].seq,
            (total - STATUS_EVENT_MAX_EVENTS + 1) as u64,
            "oldest retained event must be the first beyond the evicted window"
        );
    }

    #[tokio::test]
    async fn wait_or_poll_returns_immediately_when_events_present() {
        let bus = StatusEventBus::new();
        bus.record("a", 1, None, None, None);
        let got = bus.wait_or_poll(0, Duration::from_millis(10)).await;
        assert_eq!(got.events.len(), 1);
        assert_eq!(got.revision, 1);
        assert_eq!(got.oldest_seq, 1);
        assert!(!got.reset_required);
    }

    #[tokio::test]
    async fn wait_or_poll_times_out_when_idle() {
        let bus = StatusEventBus::new();
        let start = std::time::Instant::now();
        let got = bus.wait_or_poll(0, Duration::from_millis(30)).await;
        assert!(got.events.is_empty());
        assert_eq!(got.revision, 0);
        assert!(!got.reset_required);
        assert!(start.elapsed() >= Duration::from_millis(25));
    }

    #[test]
    fn poll_requires_reset_for_evicted_or_previous_process_cursor() {
        let bus = StatusEventBus::new();
        for i in 0..(STATUS_EVENT_MAX_EVENTS + 3) {
            bus.record("e", i as u64, None, None, None);
        }

        let evicted = bus.poll(0);
        assert_eq!(evicted.oldest_seq, 4);
        assert!(evicted.reset_required);
        assert_eq!(evicted.revision, (STATUS_EVENT_MAX_EVENTS + 3) as u64);
        assert_eq!(evicted.events.len(), STATUS_EVENT_MAX_EVENTS);

        let current = bus.poll(evicted.revision);
        assert!(!current.reset_required);
        assert!(current.events.is_empty());

        let previous_process = bus.poll(evicted.revision + 1);
        assert!(previous_process.reset_required);
        assert!(previous_process.events.is_empty());
    }

    #[test]
    fn process_id_disambiguates_restart_at_the_same_revision() {
        let old = StatusEventBus::with_process_id(1001);
        old.record("old", 1, None, None, None);
        let old_cursor = old.poll(0);

        let restarted = StatusEventBus::with_process_id(2002);
        restarted.record("new", 1, None, None, None);
        let same_revision = restarted.poll(old_cursor.revision);

        assert_eq!(same_revision.revision, old_cursor.revision);
        assert!(same_revision.events.is_empty());
        assert_ne!(same_revision.process_id, old_cursor.process_id);

        let process_bound = restarted.poll_for_process(old_cursor.revision, Some(1001));
        assert!(process_bound.reset_required);
    }

    #[tokio::test]
    async fn process_mismatch_returns_reset_without_long_poll_delay() {
        let bus = StatusEventBus::with_process_id(2002);
        bus.record("new", 1, None, None, None);
        let start = std::time::Instant::now();

        let poll = bus
            .wait_or_poll_for_process(1, Some(1001), Duration::from_secs(30))
            .await;

        assert!(poll.reset_required);
        assert_eq!(poll.process_id, 2002);
        assert!(start.elapsed() < Duration::from_millis(100));
    }

    #[test]
    fn events_response_serializes_cursor_gap_metadata() {
        let bus = StatusEventBus::with_process_id(4242);
        bus.record("changed", 7, None, None, Some("peer-a"));

        let json = serde_json::to_value(EventsResponse::from_poll(bus.poll(0))).unwrap();
        assert_eq!(json["process_id"], 4242);
        assert_eq!(json["revision"], 1);
        assert_eq!(json["oldest_seq"], 1);
        assert_eq!(json["reset_required"], false);
        assert_eq!(json["events"][0]["seq"], 1);
    }

    #[tokio::test]
    async fn wait_or_poll_observes_event_recorded_after_waiter_registration() {
        let bus = StatusEventBus::new();
        let waiter = {
            let bus = bus.clone();
            tokio::spawn(async move { bus.wait_or_poll(0, Duration::from_secs(1)).await })
        };
        tokio::task::yield_now().await;
        bus.record("wake", 1, None, None, None);

        let poll = tokio::time::timeout(Duration::from_millis(100), waiter)
            .await
            .expect("event waiter must not lose the wakeup")
            .unwrap();
        assert_eq!(poll.revision, 1);
        assert_eq!(poll.events.len(), 1);
    }
}
