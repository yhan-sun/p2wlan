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
        OwnerId, OwnerScopedSlot, MOBILE_LIFECYCLE_EVENT_WIRE_NAMES,
        MOBILE_LIFECYCLE_OUTCOME_WIRE_NAMES,
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
}
