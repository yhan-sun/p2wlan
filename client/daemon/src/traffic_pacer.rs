use std::{num::NonZeroU32, time::Duration};
use tokio::time::Instant;

pub(crate) struct TrafficPacer {
    rate: u64,
    burst: u64,
    available: u64,
    updated: Instant,
    fractional: u64,
}

impl TrafficPacer {
    pub(crate) fn new(mbps: NonZeroU32, maximum_packet: u32) -> Self {
        let rate = u64::from(mbps.get()) * 125_000;
        let burst = (rate / 250).clamp(u64::from(maximum_packet) + 256, 256 * 1024);
        Self {
            rate,
            burst,
            available: burst,
            updated: Instant::now(),
            fractional: 0,
        }
    }

    pub(crate) fn reserve(&mut self, bytes: usize, now: Instant) -> Option<Duration> {
        let elapsed = now.saturating_duration_since(self.updated).as_nanos();
        self.updated = now;
        let credit = elapsed * u128::from(self.rate) + u128::from(self.fractional);
        let available = u128::from(self.available) + credit / 1_000_000_000;
        self.available = available.min(u128::from(self.burst)) as u64;
        self.fractional = (credit % 1_000_000_000) as u64;
        let needed = (bytes as u64).min(self.burst);
        if needed <= self.available {
            self.available -= needed;
            return None;
        }
        let missing = (needed - self.available) * 1_000_000_000 - self.fractional;
        Some(Duration::from_nanos(missing.div_ceil(self.rate)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test(start_paused = true)]
    async fn pacing_stays_within_the_configured_rate_after_the_initial_burst() {
        let mut pacer = TrafficPacer::new(NonZeroU32::new(4).unwrap(), 1400);
        let start = Instant::now();
        let mut sent = 0;
        const WIRE_LEN: usize = 1432;
        while start.elapsed() < Duration::from_secs(2) {
            if let Some(wait) = pacer.reserve(WIRE_LEN, Instant::now()) {
                tokio::time::advance(wait).await;
            } else {
                sent += WIRE_LEN;
            }
        }
        assert!((996_000..=1_002_000).contains(&sent));
    }
}
