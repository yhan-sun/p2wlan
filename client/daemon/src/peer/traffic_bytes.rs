//! One advisory byte counter per live connection; clones freeze their value.
//! These values grant no authorization, liveness, path or native-read credit.
use std::sync::atomic::{AtomicU64, Ordering};

#[derive(Debug, Default)]
pub struct TrafficBytes(AtomicU64);

impl TrafficBytes {
    pub const fn new(value: u64) -> Self {
        Self(AtomicU64::new(value))
    }

    pub fn get(&self) -> u64 {
        self.0.load(Ordering::Relaxed)
    }

    pub(crate) fn add(&self, bytes: u64) {
        // Same wrapping arithmetic as the former release-build u64 counter.
        // A diagnostic overflow cannot panic a production packet worker.
        self.0.fetch_add(bytes, Ordering::Relaxed);
    }
}

impl Clone for TrafficBytes {
    fn clone(&self) -> Self {
        Self::new(self.get())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn one_live_counter_has_u64_size_and_frozen_snapshot_clones() {
        let live = TrafficBytes::new(17);
        let snapshot = live.clone();
        live.add(5);
        assert_eq!(live.get(), 22);
        assert_eq!(snapshot.get(), 17);
        assert_eq!(
            std::mem::size_of::<TrafficBytes>(),
            std::mem::size_of::<u64>()
        );
    }

    #[test]
    fn full_u64_range_and_release_wrap_remain_diagnostic_without_panic() {
        let counter = TrafficBytes::new(u64::MAX);
        counter.add(2);
        assert_eq!(counter.get(), 1);
    }

    #[test]
    fn shared_counter_updates_accumulate_without_a_connection_writer() {
        let counter = std::sync::Arc::new(TrafficBytes::default());
        let workers = (0..4)
            .map(|_| {
                let counter = counter.clone();
                std::thread::spawn(move || {
                    for _ in 0..256 {
                        counter.add(3);
                    }
                })
            })
            .collect::<Vec<_>>();
        for worker in workers {
            worker.join().unwrap();
        }
        assert_eq!(counter.get(), 4 * 256 * 3);
    }
}
