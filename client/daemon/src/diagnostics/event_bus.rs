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

/// A process-wide bounded status event log. Cheap to clone (`Arc`).
pub struct StatusEventBus {
    inner: std::sync::Mutex<StatusEventInner>,
    notify: tokio::sync::Notify,
}

impl StatusEventBus {
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
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

    /// All retained events with `seq > since`, in ascending order. Bounded by
    /// the ring. Does not wait.
    pub fn since(&self, since: u64) -> Vec<StatusEvent> {
        let guard = self.inner.lock().unwrap_or_else(|p| p.into_inner());
        guard
            .ring
            .iter()
            .filter(|e| e.seq > since)
            .cloned()
            .collect()
    }

    /// Long-poll: if there are events after `since`, return them immediately;
    /// otherwise wait up to `timeout` for a new event and then return whatever
    /// has arrived (possibly empty).
    pub async fn wait_or_poll(&self, since: u64, timeout: Duration) -> Vec<StatusEvent> {
        if !self.since(since).is_empty() {
            return self.since(since);
        }
        let notified = self.notify.notified();
        tokio::pin!(notified);
        notified.as_mut().enable();
        if timeout == Duration::ZERO {
            return Vec::new();
        }
        let _ = tokio::time::timeout(timeout, notified).await;
        self.since(since)
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
        assert_eq!(got.len(), 1);
    }

    #[tokio::test]
    async fn wait_or_poll_times_out_when_idle() {
        let bus = StatusEventBus::new();
        let start = std::time::Instant::now();
        let got = bus.wait_or_poll(0, Duration::from_millis(30)).await;
        assert!(got.is_empty());
        assert!(start.elapsed() >= Duration::from_millis(25));
    }
}
