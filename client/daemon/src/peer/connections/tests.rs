//! Actual Tokio lock grants, fair queueing and cancellation; metadata grants
//! no KernelRead, Full, SystemTun or native/current-owner/once permission.
use super::*;
use crate::peer::EpochTryContext;
use serde_json::Value;
use std::time::Duration;
fn labels(sequence: u32) -> EpochTryContext {
    EpochTryContext {
        capture_owner: 7,
        capture_id: [1; 16],
        run: [2; 16],
        round: [3; 16],
        request_nonce: [4; 16],
        sequence,
        protocol: "tcp",
        kind: "response",
        first_read_ordinal: 0,
        read_peer_input_ordinal: Some(33),
    }
}
fn capture(table: &ConnectionsTable) -> ConnectionsTraceLease {
    table.capture(7, [1; 16], Instant::now() + Duration::from_secs(30))
}
fn snapshot(lease: &ConnectionsTraceLease) -> Value {
    let v = serde_json::to_value(lease.snapshot().unwrap()).unwrap();
    for key in [
        "native_os_write_verified",
        "physical_send_verified",
        "canonical_current_owner_verified",
    ] {
        assert_eq!(v[key], false);
    }
    v
}
#[tokio::test]
async fn actual_writer_and_first_original_refusal_retain_only_bounded_metadata() {
    let table = ConnectionsTable::new(HashMap::new());
    let lease = capture(&table);
    let held = table.write().await;
    assert!(table.try_read_original(Some(labels(1))).is_err());
    let before = snapshot(&lease);
    let w = &before["writer_observations"][0];
    assert_eq!(w["exclusive_grant_observed"], true);
    assert_eq!(w["actual_guard_release_completion_observed"], false);
    assert_eq!(w["held_interval_covers_failed_try"], false);
    assert!(w["source"]
        .as_str()
        .unwrap()
        .ends_with("peer/connections/tests.rs"));
    drop(held);
    let completed = snapshot(&lease);
    let w = &completed["writer_observations"][0];
    assert_eq!(w["actual_guard_release_completion_observed"], true);
    assert_eq!(
        w["held_interval_covers_failed_try"],
        cfg!(target_os = "linux")
    );
    let later = table.try_write().unwrap();
    assert!(table.try_read_original(Some(labels(2))).is_err());
    drop(later);
    assert_eq!(snapshot(&lease), completed); // First refusal is never backfilled.
    assert!(table.try_read().is_ok());
}
#[tokio::test]
async fn actual_queued_writer_is_not_an_exclusive_holder_and_cancellation_releases_queue() {
    let table = ConnectionsTable::new(HashMap::new());
    let lease = capture(&table);
    let reader = table.read().await;
    let mut pending = Box::pin(table.write());
    assert!(futures_util::poll!(pending.as_mut()).is_pending());
    assert!(table.try_read_original(Some(labels(3))).is_err());
    let value = snapshot(&lease);
    let w = &value["writer_observations"][0];
    assert_eq!(w["exclusive_grant_observed"], false);
    assert_eq!(w["held_interval_covers_failed_try"], false);
    assert_eq!(value["queued_intent_is_not_exclusive_holder"], true);
    drop(pending);
    // The existing read still lives, but the original fair queue is released.
    assert!(table.try_read().is_ok());
    assert_eq!(
        snapshot(&lease)["writer_observations"][0]["actual_guard_release_completion_observed"],
        false
    );
    drop(reader);
    assert!(table.try_write().is_ok());
}
#[tokio::test]
async fn default_off_owner_expiry_retirement_and_capacity_never_change_original_grants() {
    let table = ConnectionsTable::new(HashMap::new());
    let original = table.try_write().unwrap();
    assert!(original.observation.is_none());
    drop(original);
    assert!(table.trace.get().is_none());
    let lease = capture(&table);
    assert!(capture(&table).snapshot().is_none());
    let reader = table.read().await;
    let mut writers = Vec::new();
    for _ in 0..17 {
        let mut f = Box::pin(table.write());
        assert!(futures_util::poll!(f.as_mut()).is_pending());
        writers.push(f);
    }
    let mut wrong = labels(4);
    wrong.capture_owner = 8;
    assert!(table.try_read_original(Some(wrong)).is_err());
    assert!(lease.snapshot().is_none());
    let mut wrong = labels(4);
    wrong.capture_id = [9; 16];
    assert!(table.try_read_original(Some(wrong)).is_err());
    assert!(lease.snapshot().is_none());
    let mut wrong = labels(4);
    wrong.first_read_ordinal = 1;
    assert!(table.try_read_original(Some(wrong)).is_err());
    assert!(lease.snapshot().is_none());
    assert!(table.try_read_original(Some(labels(4))).is_err());
    let value = snapshot(&lease);
    assert_eq!(value["writer_observations"].as_array().unwrap().len(), 16);
    assert_eq!(value["unobserved_writer_count_at_refusal"], 1);
    assert!(value["writer_observations"]
        .as_array()
        .unwrap()
        .iter()
        .all(|w| w["exclusive_grant_observed"] == false));
    drop(writers);
    drop(reader);
    assert!(table.try_write().is_ok());
    lease.deactivate();
    let held = table.write().await;
    assert!(held.observation.is_none());
    drop(held);
    let expired = ConnectionsTable::new(HashMap::new());
    let disabled = expired.capture(7, [1; 16], Instant::now() - Duration::from_secs(1));
    let held = expired.write().await;
    assert!(held.observation.is_none());
    assert!(expired.try_read_original(Some(labels(5))).is_err());
    assert!(disabled.snapshot().is_none());
    drop(held);
    assert!(expired.try_read().is_ok());
}
#[tokio::test]
async fn owned_read_guards_and_raw_test_alias_keep_the_same_original_connection_lock() {
    let table = Arc::new(ConnectionsTable::new(HashMap::new()));
    let lease = capture(&table);
    let raw = table.raw_for_test();
    assert!(Arc::ptr_eq(&raw, &table.raw_for_test()));
    let held = raw.write().await;
    assert!(table.clone().try_read_owned().is_err());
    drop(held);
    let reader = table.clone().read_owned().await;
    assert!(raw.try_write().is_err());
    drop(reader);
    let held = table.try_write().unwrap();
    assert!(raw.try_read().is_err());
    drop(held);
    assert!(raw.try_read().is_ok());
    let weak = Arc::downgrade(&table);
    drop(table);
    assert!(weak.upgrade().is_none());
    assert!(lease.snapshot().is_none());
}
