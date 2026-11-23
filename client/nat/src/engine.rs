//! Negotiated traversal parameters for authenticated peers.

mod profile;
pub use profile::{select_best_candidate_group_pair, GroupPair, NatKind, PunchProfile};

use serde::{Deserialize, Serialize};
use std::sync::atomic::{AtomicU64, Ordering};

/// Reserve consecutive IDs without reusing an ID after the sequence is exhausted.
pub fn reserve_sequence(counter: &AtomicU64, count: u64, limit: u64) -> Option<u64> {
    if count == 0 {
        return None;
    }
    let mut current = counter.load(Ordering::Acquire);
    loop {
        let next = current.checked_add(count).filter(|&n| n <= limit)?;
        match counter.compare_exchange_weak(current, next, Ordering::AcqRel, Ordering::Acquire) {
            Ok(previous) => return Some(previous),
            Err(observed) => current = observed,
        }
    }
}

/// Budgets apply to one live peer attempt. A zero budget disables that resource.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(default)]
pub struct PunchSettings {
    pub disable_sym_hole_punching: bool,
    pub lazy_p2p: bool,
    pub max_punch_pps: u16,
    pub max_punch_sockets: u8,
    pub linear_scan_count: u16,
    pub firewall_probe_addresses: Vec<std::net::SocketAddr>,
}

impl Default for PunchSettings {
    fn default() -> Self {
        Self {
            disable_sym_hole_punching: false,
            lazy_p2p: false,
            max_punch_pps: 200,
            max_punch_sockets: 24,
            linear_scan_count: 50,
            firewall_probe_addresses: Vec::new(),
        }
    }
}

mod frame;
pub use frame::{
    CompactFrame, CompactSession, EndpointReceipt, FrameKind, ENDPOINT_RECEIPT_SIZE, FRAME_SIZE,
};

mod pacer;
pub use pacer::{Lane, PunchMetrics, PunchPacer, PunchTarget};

mod firewall;
pub use firewall::{check_udp_reachability, UdpReachability};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sequence_reservations_are_disjoint_and_bounded() {
        let counter = AtomicU64::new(u64::MAX - 16);
        let mut starts = std::thread::scope(|scope| {
            let left = scope.spawn(|| reserve_sequence(&counter, 8, u64::MAX));
            let right = reserve_sequence(&counter, 8, u64::MAX);
            [left.join().unwrap(), right]
        });
        starts.sort();
        assert_eq!(starts, [Some(u64::MAX - 16), Some(u64::MAX - 8)]);
        assert_eq!(reserve_sequence(&counter, 1, u64::MAX), None);
        assert_eq!(reserve_sequence(&AtomicU64::new(1), 8, 8), None);
        assert_eq!(reserve_sequence(&counter, 0, u64::MAX), None);
    }
}
