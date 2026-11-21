//! Negotiated traversal parameters for authenticated peers.

mod profile;
pub use profile::{select_best_candidate_group_pair, GroupPair, NatKind, PunchProfile};

use serde::{Deserialize, Serialize};

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
pub use frame::{CompactFrame, CompactSession, FrameKind, FRAME_SIZE};

mod pacer;
pub use pacer::{Lane, PunchMetrics, PunchPacer, PunchTarget};

mod firewall;
pub use firewall::{check_udp_reachability, UdpReachability};
