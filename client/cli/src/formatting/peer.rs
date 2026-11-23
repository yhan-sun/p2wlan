//! Peer doctor/diagnostics formatting helpers.
//!
//! Renders peer connection health, path/direct event timelines, candidate
//! pairs, and traversal history for the `p2wlan doctor` output. Split out of
//! `formatting.rs`.

use std::net::{IpAddr, SocketAddr};

use serde_json::Value;

use super::relay::relay_path_reason;

include!("peer/diagnostics.rs");
include!("peer/suggestions.rs");
include!("peer/path.rs");
include!("peer/direct.rs");
include!("peer/candidates.rs");
include!("peer/traversal.rs");
include!("peer/utils.rs");

#[cfg(test)]
mod negotiated_diagnostics_tests {
    use super::*;
    #[test]
    fn doctor_displays_negotiated_profile_and_observed_path() {
        let profile =
            serde_json::json!({"nat_type":"RandomSymmetric","port_step":0,"port_hint":47001});
        let peer = serde_json::json!({"remote_nat_profile":profile,"punch_mode":9,"punch_epoch":17,
            "queue_a_len":5,"queue_b_len":2,"actual_pps":7,"active_punch_sockets":0,"udp_firewall_status":"blocked",
            "active_path":"Relay","active_path_type":"tls_relay","path_cost":10,"reason_code":"UDP_BLOCKED"});
        let summary = negotiated_punch_summary(&peer).unwrap();
        for (name, value) in peer.as_object().unwrap() {
            assert!(summary.contains(&format!("{name}={value}")), "{name}");
        }
        assert!(negotiated_punch_summary(&serde_json::json!({"active_path":"Direct"})).is_none());
    }
}
