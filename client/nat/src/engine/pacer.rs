use std::collections::{HashSet, VecDeque};
use std::net::SocketAddr;
use std::sync::{
    atomic::{AtomicU64, Ordering},
    Mutex, MutexGuard,
};
use std::time::Duration;
use tokio::time::Instant;

const QUEUE_CAPACITY: usize = 512;

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct PunchTarget {
    pub address: SocketAddr,
    pub socket: usize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Lane {
    Regular,
    Predicted,
}

#[derive(Clone, Debug, Default, serde::Serialize, serde::Deserialize)]
#[serde(default)]
pub struct PunchMetrics {
    pub punch_epoch: u64,
    pub queue_a_len: usize,
    pub queue_b_len: usize,
    pub actual_pps: usize,
    pub active_punch_sockets: usize,
}

#[derive(Debug, Default)]
struct Queues {
    regular: VecDeque<PunchTarget>,
    predicted: VecDeque<PunchTarget>,
    seen: HashSet<PunchTarget>,
    sends: VecDeque<Instant>,
    issued: usize,
    prefer_predicted: bool,
}

impl Queues {
    fn expire(&mut self, now: Instant) {
        while self
            .sends
            .front()
            .is_some_and(|t| now.duration_since(*t) >= Duration::from_secs(1))
        {
            self.sends.pop_front();
        }
    }
}

/// Every dequeued item retains the epoch used for admission. The kernel send
/// commits under the same short guard as cancellation and budget consumption.
#[derive(Debug)]
pub struct PunchPacer {
    punch_epoch: AtomicU64,
    pps: usize,
    queues: Mutex<Queues>,
}

impl PunchPacer {
    pub fn new(epoch: u64, pps: u16) -> Self {
        Self {
            punch_epoch: AtomicU64::new(epoch),
            pps: usize::from(pps.min(200)),
            queues: Mutex::default(),
        }
    }
    fn queues(&self) -> MutexGuard<'_, Queues> {
        self.queues.lock().unwrap_or_else(|err| err.into_inner())
    }
    pub fn epoch(&self) -> u64 {
        self.punch_epoch.load(Ordering::Acquire)
    }

    pub fn interval(&self) -> Duration {
        Duration::from_nanos(2_000_000_000u64.div_ceil(self.pps.max(1) as u64))
    }

    pub fn enqueue(&self, epoch: u64, lane: Lane, target: PunchTarget) -> bool {
        let mut q = self.queues();
        if self.epoch() != epoch
            || self.pps == 0
            || q.issued >= QUEUE_CAPACITY
            || !q.seen.insert(target)
        {
            return false;
        }
        q.issued += 1;
        match lane {
            Lane::Regular => q.regular.push_back(target),
            Lane::Predicted => q.predicted.push_back(target),
        }
        true
    }

    pub fn tick(&self, epoch: u64, now: Instant) -> [Option<PunchTarget>; 2] {
        let mut q = self.queues();
        q.expire(now);
        if self.epoch() != epoch || self.pps <= q.sends.len() {
            return [None, None];
        }
        let available = self.pps - q.sends.len();
        let prefer_predicted = q.prefer_predicted;
        q.prefer_predicted = !prefer_predicted;
        let a = if available > 1 || !prefer_predicted || q.predicted.is_empty() {
            q.regular.pop_front()
        } else {
            None
        };
        let b = if available > usize::from(a.is_some()) {
            q.predicted.pop_front()
        } else {
            None
        };
        for t in [a, b].into_iter().flatten() {
            q.seen.remove(&t);
        }
        [a, b]
    }

    /// The closure performs a single non-blocking datagram send.
    pub fn try_send<T>(
        &self,
        epoch: u64,
        send: impl FnOnce() -> std::io::Result<T>,
    ) -> std::io::Result<T> {
        let mut q = self.queues();
        let now = Instant::now();
        q.expire(now);
        if self.epoch() != epoch {
            return Err(std::io::ErrorKind::Interrupted.into());
        }
        if self.pps <= q.sends.len() {
            return Err(std::io::ErrorKind::WouldBlock.into());
        }
        let result = send()?;
        q.sends.push_back(now);
        Ok(result)
    }

    pub fn clear_punch_state(&self) -> Option<u64> {
        let mut q = self.queues();
        q.regular.clear();
        q.predicted.clear();
        q.seen.clear();
        q.issued = 0;
        // Keep the sliding window across rounds; a restart cannot buy more packets.
        super::reserve_sequence(&self.punch_epoch, 1, u64::MAX).map(|previous| previous + 1)
    }

    pub fn metrics(&self, active_punch_sockets: usize) -> PunchMetrics {
        let mut q = self.queues();
        q.expire(Instant::now());
        PunchMetrics {
            punch_epoch: self.epoch(),
            queue_a_len: q.regular.len(),
            queue_b_len: q.predicted.len(),
            actual_pps: q.sends.len(),
            active_punch_sockets,
        }
    }
}
