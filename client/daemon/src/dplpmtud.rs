//! Path MTU discovery — bounded probing / fallback decision logic (audit §16).
//!
//! The live probe (an authenticated padded datagram plus a timeout over the
//! selected path) must be driven by something that decides *which* size to try
//! next and *how far* to fall back when a probe fails.  That decision is pure
//! state — it takes the set of sizes tried so far and their success/failure and
//! returns the next size — so it is unit-tested here without any network.
//!
//! Strategy (mirrors audit §16.3):
//!   - Start at a conservative floor (1200).
//!   - Probe upward through a ladder of candidate sizes.
//!   - A failed probe does NOT mean the path is dead: it means the current size
//!     is too big, so collapse to the largest size that already succeeded (fast
//!     fallback).  This is O(1) — no re-probing from scratch — which keeps the
//!     cost bounded and the convergence quick.
//!
//! The path is intentionally split per (peer, path_type, generation) by the
//! caller ([`MtuState`]); this module owns no path identity.

/// The minimum probe size we always start from.
pub const MTU_FLOOR: u32 = 1200;
/// IPv6-safe minimum (RFC 8200): the largest size guaranteed to pass if any
/// IPv6 size passes.
pub const IPV6_SAFE_MIN_MTU: u32 = 1280;

/// Candidate sizes probed in ascending order (audit §16.3 ladder).
pub const MTU_LADDER: &[u32] = &[1280, 1360, 1380, 1420];

/// A per-path MTU decision state.
///
/// The caller resets this whenever the `(peer, path_type, generation)` changes
/// (audit §16.2), so this struct is intentionally stateless across those axes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MtuState {
    /// The largest size that has succeeded so far.  Always `>= MTU_FLOOR`.
    confirmed: u32,
    /// The largest size probed so far.  Never exceeds the ladder top.
    probed: u32,
    /// Index of the next ladder entry to try; `None` when the ladder is
    /// exhausted (we have climbed to the largest that succeeded).
    next_index: Option<usize>,
}

impl Default for MtuState {
    fn default() -> Self {
        Self::new()
    }
}

impl MtuState {
    /// A fresh state: floor confirmed, nothing probed above it.
    pub fn new() -> Self {
        Self {
            confirmed: MTU_FLOOR,
            probed: MTU_FLOOR,
            next_index: Some(0),
        }
    }

    /// The next size the caller should probe, or `None` when probing is done
    /// (the largest ladder size that succeeded is the effective MTU).
    pub fn next_probe(&self) -> Option<u32> {
        self.next_index.and_then(|i| MTU_LADDER.get(i).copied())
    }

    /// The effective path MTU: the largest size confirmed possible.  For a
    /// path that never probed above the floor this is `MTU_FLOOR`.
    pub fn effective_mtu(&self) -> u32 {
        self.confirmed
    }

    /// Fold one probe result.
    ///
    /// - `Ok(size)`: the given size carried traffic successfully; it becomes
    ///   the confirmed size and probing continues upward.
    /// - `Err(_)`: the given size was too large; probing stops immediately and
    ///   the effective MTU collapses to the last confirmed size (fast fallback,
    ///   no re-probing from scratch).
    pub fn record(&mut self, size: u32, succeeded: bool) {
        if succeeded {
            if size > self.confirmed {
                self.confirmed = size;
            }
            self.probed = size;
            match self.next_index {
                Some(i) if MTU_LADDER.get(i).copied() == Some(size) => {
                    self.next_index = Some(i + 1);
                }
                _ => {
                    // A size outside the ladder (e.g. a fallback floor) was
                    // confirmed; keep probing the next unconfirmed ladder entry.
                    if let Some(next) = MTU_LADDER.iter().position(|s| *s > size) {
                        self.next_index = Some(next);
                    } else {
                        self.next_index = None;
                    }
                }
            }
        } else {
            // Failure: collapse immediately and stop climbing.  The confirmed
            // size is already the largest that succeeded.
            self.probed = size;
            self.next_index = None;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn starts_at_floor_and_climbs_ladder() {
        let mut s = MtuState::new();
        assert_eq!(s.effective_mtu(), MTU_FLOOR);
        assert_eq!(s.next_probe(), Some(1280));

        // Climb the whole ladder successfully.
        for size in MTU_LADDER {
            s.record(*size, true);
        }
        assert_eq!(s.effective_mtu(), 1420);
        assert_eq!(s.next_probe(), None, "ladder exhausted -> probing done");
    }

    #[test]
    fn failure_collapses_to_last_confirmed_and_stops() {
        let mut s = MtuState::new();
        s.record(1280, true); // confirmed 1280
        assert_eq!(s.effective_mtu(), 1280);
        assert_eq!(s.next_probe(), Some(1360));

        s.record(1360, false); // 1360 too big
        assert_eq!(
            s.effective_mtu(),
            1280,
            "must fall back to the last confirmed size, not the floor"
        );
        assert_eq!(s.next_probe(), None, "no further probing after a failure");
    }

    #[test]
    fn floor_failure_keeps_floor_as_effective() {
        let mut s = MtuState::new();
        s.record(1280, false);
        assert_eq!(
            s.effective_mtu(),
            MTU_FLOOR,
            "a floor-adjacent failure still yields a usable conservative floor"
        );
        assert_eq!(s.next_probe(), None);
    }

    #[test]
    fn partial_climb_stops_at_max_confirmed() {
        let mut s = MtuState::new();
        s.record(1280, true);
        s.record(1360, false);
        assert_eq!(s.effective_mtu(), 1280);
        assert_eq!(s.next_probe(), None);

        let mut s2 = MtuState::new();
        s2.record(1280, true);
        s2.record(1360, true);
        s2.record(1380, false);
        assert_eq!(s2.effective_mtu(), 1360);
        assert_eq!(s2.next_probe(), None);
    }

    #[test]
    fn ipv6_safe_min_is_at_least_floor() {
        const {
            assert!(IPV6_SAFE_MIN_MTU >= MTU_FLOOR);
        }
    }
}
