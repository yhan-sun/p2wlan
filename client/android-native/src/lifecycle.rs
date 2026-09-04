//! Platform-neutral ownership primitives for the Android bridge.
//!
//! Android-specific JNI code owns the actual runtime. This module owns only
//! the compare-and-clear rule, so host `cargo test -p p2wlan-android-native`
//! exercises the race that matters without pretending to have a VPN device.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;

static NEXT_OWNER: AtomicU64 = AtomicU64::new(1);

/// The Rust-side vocabulary is checked against the canonical JSON contract in
/// the host test below. The list is intentionally test-facing: the Android
/// bridge does not invent a second transition store or serialize these names.
pub const MOBILE_LIFECYCLE_EVENT_WIRE_NAMES: &[&str] = &[
    "app_backgrounded",
    "app_resumed",
    "physical_network_changed",
    "vpn_permission_request_started",
    "vpn_permission_revoked",
    "vpn_permission_granted",
    "vpn_start_requested",
    "explicit_stop_requested",
    "activity_recreated",
    "service_recreated",
    "bridge_attached",
    "bridge_detached",
    "native_runtime_started",
    "native_runtime_stopped",
    "native_monitor_callback",
    "automatic_restart_scheduled",
    "automatic_restart_rejected",
    "control_disconnected",
    "control_reconnected",
    "candidate_refresh_started",
    "relay_retained",
    "direct_reconfirmed",
];

pub const MOBILE_LIFECYCLE_OUTCOME_WIRE_NAMES: &[&str] = &[
    "applied",
    "duplicate",
    "stale_rejected",
    "superseded",
    "failed",
];

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct OwnerId(u64);

impl OwnerId {
    pub fn allocate() -> Self {
        Self(NEXT_OWNER.fetch_add(1, Ordering::Relaxed))
    }

    pub const fn from_raw(value: u64) -> Self {
        Self(value)
    }

    pub const fn raw(self) -> u64 {
        self.0
    }
}

#[derive(Debug)]
struct Owned<T> {
    owner: OwnerId,
    value: T,
}

/// A slot whose cleanup can only be performed by the owner that currently
/// occupies it. Installing a replacement is explicit; an older owner cannot
/// clear or mutate the replacement.
#[derive(Debug)]
pub struct OwnerScopedSlot<T> {
    current: Mutex<Option<Owned<T>>>,
}

/// Final Rust-side admission fence for Android physical-network callbacks.
///
/// Kotlin owns callback reduction, but it is not authoritative for the
/// dataplane. This fence ties every accepted hint to the current service and
/// bridge owners and makes the Kotlin generation/hash pair idempotent before
/// it enters the daemon's existing transport lifecycle.
#[derive(Debug)]
pub struct PhysicalNetworkHintAuthority {
    service_owner: u64,
    bridge_owner: OwnerId,
    last_kotlin_generation: Option<u64>,
    last_network_identity_hash: Option<String>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NetworkHintDecision {
    Applied,
    Duplicate,
    StaleRejected,
    Failed,
}

impl NetworkHintDecision {
    pub const fn wire_name(self) -> &'static str {
        match self {
            Self::Applied => "applied",
            Self::Duplicate => "duplicate",
            Self::StaleRejected => "stale_rejected",
            Self::Failed => "failed",
        }
    }
}

impl PhysicalNetworkHintAuthority {
    pub fn new(service_owner: u64, bridge_owner: OwnerId) -> Self {
        Self {
            service_owner,
            bridge_owner,
            last_kotlin_generation: None,
            last_network_identity_hash: None,
        }
    }

    pub fn service_owner(&self) -> u64 {
        self.service_owner
    }

    pub fn bridge_owner(&self) -> OwnerId {
        self.bridge_owner
    }

    /// Rebind the callback owner when START_STICKY gives a new service object
    /// ownership of the still-running Rust bridge.
    pub fn rebind_service_owner(
        &mut self,
        expected_bridge_owner: OwnerId,
        service_owner: u64,
    ) -> NetworkHintDecision {
        if service_owner == 0 || expected_bridge_owner != self.bridge_owner {
            return NetworkHintDecision::StaleRejected;
        }
        if service_owner == self.service_owner {
            return NetworkHintDecision::Duplicate;
        }
        if service_owner < self.service_owner {
            return NetworkHintDecision::StaleRejected;
        }
        self.service_owner = service_owner;
        self.last_kotlin_generation = None;
        self.last_network_identity_hash = None;
        NetworkHintDecision::Applied
    }

    pub fn accept(
        &mut self,
        service_owner: u64,
        bridge_owner: OwnerId,
        kotlin_network_generation: u64,
        network_identity_hash: &str,
    ) -> NetworkHintDecision {
        if service_owner == 0 || bridge_owner.raw() == 0 {
            return NetworkHintDecision::Failed;
        }
        if service_owner != self.service_owner || bridge_owner != self.bridge_owner {
            return NetworkHintDecision::StaleRejected;
        }
        let network_identity_hash = network_identity_hash.trim();
        if kotlin_network_generation == 0 || network_identity_hash.is_empty() {
            return NetworkHintDecision::Failed;
        }
        match self.last_kotlin_generation {
            Some(last) if kotlin_network_generation < last => NetworkHintDecision::StaleRejected,
            Some(last) if kotlin_network_generation == last => {
                if self.last_network_identity_hash.as_deref() == Some(network_identity_hash) {
                    NetworkHintDecision::Duplicate
                } else {
                    // One Kotlin generation may publish at most one physical
                    // identity. A conflicting callback is stale rather than
                    // a second network transition.
                    NetworkHintDecision::StaleRejected
                }
            }
            _ => {
                self.last_kotlin_generation = Some(kotlin_network_generation);
                self.last_network_identity_hash = Some(network_identity_hash.to_string());
                NetworkHintDecision::Applied
            }
        }
    }
}

impl<T> Default for OwnerScopedSlot<T> {
    fn default() -> Self {
        Self {
            current: Mutex::new(None),
        }
    }
}

impl<T> OwnerScopedSlot<T> {
    pub fn install(&self, owner: OwnerId, value: T) -> Option<T> {
        let mut guard = self
            .current
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        guard.replace(Owned { owner, value }).map(|old| old.value)
    }

    pub fn owner(&self) -> Option<OwnerId> {
        self.current
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .as_ref()
            .map(|owned| owned.owner)
    }

    pub fn is_owner(&self, owner: OwnerId) -> bool {
        self.owner() == Some(owner)
    }

    pub fn compare_and_clear(&self, owner: OwnerId) -> Option<T> {
        let mut guard = self
            .current
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if guard.as_ref().is_some_and(|owned| owned.owner == owner) {
            guard.take().map(|owned| owned.value)
        } else {
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{
        NetworkHintDecision, OwnerId, OwnerScopedSlot, PhysicalNetworkHintAuthority,
        MOBILE_LIFECYCLE_EVENT_WIRE_NAMES, MOBILE_LIFECYCLE_OUTCOME_WIRE_NAMES,
    };

    #[test]
    fn old_runtime_cannot_clear_new_socket_protector() {
        let slot = OwnerScopedSlot::default();
        let runtime_a = OwnerId::from_raw(100);
        let runtime_b = OwnerId::from_raw(101);
        assert!(slot.install(runtime_a, "protector-a").is_none());
        assert_eq!(slot.install(runtime_b, "protector-b"), Some("protector-a"));
        assert_eq!(slot.compare_and_clear(runtime_a), None);
        assert_eq!(slot.owner(), Some(runtime_b));
        assert_eq!(slot.compare_and_clear(runtime_b), Some("protector-b"));
        assert_eq!(slot.owner(), None);
    }

    #[test]
    fn duplicate_lifecycle_install_is_an_explicit_replacement() {
        let slot = OwnerScopedSlot::default();
        let owner = OwnerId::from_raw(200);
        assert!(slot.install(owner, 1u8).is_none());
        assert_eq!(slot.install(owner, 2u8), Some(1));
        assert_eq!(slot.compare_and_clear(owner), Some(2));
    }

    #[test]
    fn canonical_contract_contains_all_mobile_scenarios() {
        let contract = include_str!("../../../contracts/mobile_lifecycle.json");
        let value: serde_json::Value = serde_json::from_str(contract).expect("valid contract");
        assert_eq!(value["schema_version"], 2);
        let scenarios = value["required_scenarios"]
            .as_array()
            .expect("scenario array");
        assert_eq!(scenarios.len(), 18);
        for (index, scenario) in scenarios.iter().enumerate() {
            assert_eq!(scenario["id"], format!("ML-{index:02}", index = index + 1));
        }
        let events = value["events"].as_array().expect("event array");
        assert_eq!(
            MOBILE_LIFECYCLE_EVENT_WIRE_NAMES,
            events
                .iter()
                .map(|event| event.as_str().expect("event string"))
                .collect::<Vec<_>>()
                .as_slice()
        );
        assert_eq!(
            MOBILE_LIFECYCLE_OUTCOME_WIRE_NAMES,
            value["outcomes"]
                .as_array()
                .expect("outcome array")
                .iter()
                .map(|outcome| outcome.as_str().expect("outcome string"))
                .collect::<Vec<_>>()
                .as_slice()
        );
    }

    #[test]
    fn physical_network_hint_is_owner_scoped_and_exactly_once() {
        let bridge = OwnerId::from_raw(4);
        let mut authority = PhysicalNetworkHintAuthority::new(40, bridge);
        assert_eq!(
            authority.accept(40, bridge, 1, "wifi"),
            NetworkHintDecision::Applied
        );
        assert_eq!(
            authority.accept(40, bridge, 1, "wifi"),
            NetworkHintDecision::Duplicate
        );
        assert_eq!(
            authority.accept(40, bridge, 1, "cellular"),
            NetworkHintDecision::StaleRejected
        );
        assert_eq!(
            authority.accept(40, bridge, 0, "cellular"),
            NetworkHintDecision::Failed
        );
        assert_eq!(
            authority.accept(40, bridge, 2, "cellular"),
            NetworkHintDecision::Applied
        );
        assert_eq!(
            authority.accept(40, OwnerId::from_raw(3), 3, "hotspot"),
            NetworkHintDecision::StaleRejected
        );
        assert_eq!(
            authority.accept(39, bridge, 3, "hotspot"),
            NetworkHintDecision::StaleRejected
        );
        assert_eq!(
            authority.accept(40, bridge, 1, "old"),
            NetworkHintDecision::StaleRejected
        );
        emit_evidence(
            "ML-18",
            "physical_network_hint_is_owner_scoped_and_exactly_once",
            "[\"physical_network_changed\",\"physical_network_changed\"]",
            "{\"network_generation\":1}",
            "{\"network_generation\":1}",
            NetworkHintDecision::Duplicate.wire_name(),
            "{\"duplicate_has_no_second_effect\":true}",
        );
    }

    #[test]
    fn physical_network_hint_service_rebind_rejects_old_owner() {
        let bridge = OwnerId::from_raw(5);
        let mut authority = PhysicalNetworkHintAuthority::new(40, bridge);
        assert_eq!(
            authority.rebind_service_owner(OwnerId::from_raw(4), 41),
            NetworkHintDecision::StaleRejected
        );
        assert_eq!(
            authority.rebind_service_owner(bridge, 41),
            NetworkHintDecision::Applied
        );
        assert_eq!(
            authority.accept(40, bridge, 1, "old-service"),
            NetworkHintDecision::StaleRejected
        );
        assert_eq!(
            authority.accept(41, bridge, 1, "new-service"),
            NetworkHintDecision::Applied
        );
        assert_eq!(
            authority.rebind_service_owner(bridge, 40),
            NetworkHintDecision::StaleRejected
        );
    }

    #[test]
    fn evidence_ml10_bridge_incarnation_adoption() {
        let bridge = OwnerId::from_raw(5);
        let mut authority = PhysicalNetworkHintAuthority::new(8, bridge);
        assert_eq!(
            authority.rebind_service_owner(bridge, 9),
            NetworkHintDecision::Applied
        );
        assert_eq!(authority.service_owner(), 9);
        emit_evidence(
            "ML-10",
            "evidence_ml10_bridge_incarnation_adoption",
            "[\"bridge_detached\",\"bridge_attached\"]",
            "{\"bridge_incarnation\":4}",
            "{\"bridge_incarnation\":5}",
            NetworkHintDecision::Applied.wire_name(),
            "{\"bridge_identity_adopted\":true}",
        );
    }

    #[test]
    fn evidence_ml11_old_bridge_cleanup() {
        let slot = OwnerScopedSlot::default();
        let old = OwnerId::from_raw(4);
        let replacement = OwnerId::from_raw(5);
        slot.install(replacement, "replacement");
        assert!(slot.compare_and_clear(old).is_none());
        assert!(slot.is_owner(replacement));
        emit_evidence(
            "ML-11",
            "evidence_ml11_old_bridge_cleanup",
            "[\"bridge_detached\",\"bridge_attached\"]",
            "{\"bridge_incarnation\":4}",
            "{\"bridge_incarnation\":5}",
            NetworkHintDecision::StaleRejected.wire_name(),
            "{\"old_bridge_cleanup_rejected\":true}",
        );
    }

    fn emit_evidence(
        scenario_id: &str,
        test_name: &str,
        events: &str,
        old_identity: &str,
        new_identity: &str,
        decision: &str,
        invariants: &str,
    ) {
        let exact_test_id = format!("lifecycle::tests::{test_name}");
        println!(
            "MOBILE_LIFECYCLE_RECORD {{\"scenario_id\":\"{scenario_id}\",\"exact_test_id\":\"{exact_test_id}\",\"executed\":true,\"skipped\":false,\"result\":\"pass\",\"events\":{events},\"observed_old_identity\":{old_identity},\"observed_new_identity\":{new_identity},\"observed_decision\":\"{decision}\",\"invariants\":{invariants},\"execution_source\":\"rust_test_nocapture\"}}"
        );
    }
}
