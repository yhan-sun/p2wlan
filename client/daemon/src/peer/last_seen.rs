//! The live connection's advisory timestamp; it grants no lifecycle authority.
use std::sync::atomic::{AtomicU64, Ordering};

#[derive(Debug, Default)]
pub struct LastSeen(AtomicU64);

impl LastSeen {
    pub const fn new(value: u64) -> Self {
        Self(AtomicU64::new(value))
    }

    pub fn get(&self) -> u64 {
        self.0.load(Ordering::Relaxed)
    }

    pub(crate) fn set(&self, value: u64) {
        // This display value neither orders nor fences network state. The
        // caller still owns the original connection read/write guard.
        self.0.store(value, Ordering::Relaxed);
    }

    pub(crate) fn try_advance(&self, observed: u64, value: u64) -> bool {
        value > observed
            && self
                .0
                .compare_exchange(observed, value, Ordering::Relaxed, Ordering::Relaxed)
                .is_ok()
    }
}

impl Clone for LastSeen {
    fn clone(&self) -> Self {
        // PeerConnection snapshots freeze the observed value; they do not
        // retain a live mutable timestamp or become another state owner.
        Self::new(self.get())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn snapshot_clone_keeps_original_value_after_live_refresh() {
        let live = LastSeen::new(10);
        let snapshot = live.clone();
        live.set(11);
        assert_eq!(live.get(), 11);
        assert_eq!(snapshot.get(), 10);
        assert_eq!(live.clone().get(), 11);
    }

    #[test]
    fn timestamp_preserves_full_u64_range_without_an_extra_owner() {
        let timestamp = LastSeen::default();
        assert_eq!(timestamp.get(), 0);
        timestamp.set(u64::MAX);
        assert_eq!(timestamp.get(), u64::MAX);
        timestamp.set(0);
        assert_eq!(timestamp.get(), 0);
        assert_eq!(std::mem::size_of::<LastSeen>(), std::mem::size_of::<u64>());
    }

    #[test]
    fn one_conditional_refresh_cannot_overwrite_a_concurrent_or_newer_timestamp() {
        let live = LastSeen::new(10);
        assert!(live.try_advance(10, 11));
        assert!(!live.try_advance(10, 12));
        assert!(!live.try_advance(11, 10));
        assert_eq!(live.get(), 11);
        assert!(live.try_advance(11, u64::MAX));
    }
}
