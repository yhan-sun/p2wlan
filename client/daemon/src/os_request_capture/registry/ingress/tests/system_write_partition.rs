//! Actual lock interleavings and authenticated UDP input. These controls never
//! construct KernelWrite, claim a concrete system-TUN Full or grant credit.
use super::*;

#[tokio::test]
async fn actual_authenticated_input_does_not_wait_for_system_write_history() {
    let mut harness = Harness::new(false, true).await;
    let scope = harness.setup.session.clone();
    let before = scope.try_source_metadata_versions().unwrap();
    let writer = scope.system_write_state.try_lock().unwrap();
    assert!(scope.try_source_metadata_versions().is_err());
    let binding = harness.receive(&packet(true)).await;
    assert!(binding.source.original_udp_read().is_some());
    assert!(scope.inbound_complete.load(Ordering::Acquire));
    assert!(scope.state.try_lock().is_ok());
    drop(writer);
    let after = scope.try_source_metadata_versions().unwrap();
    assert_eq!(after.1, before.1);
    assert_eq!(after.2, before.2 + 2);
    harness.close().await;
    let snapshot = serde_json::to_value(scope.snapshot().unwrap()).unwrap();
    assert_eq!(snapshot["system_tun_full_writes"], json!([]));
    assert_eq!(snapshot["physical_send_verified"], false);
    assert_eq!(snapshot["canonical_current_owner_verified"], false);
}

#[tokio::test]
async fn actual_system_history_lock_is_disjoint_and_versions_cannot_alias() {
    let (setup, _parent) = super::super::super::snapshot_projection_tests::scope().await;
    let scope = setup.session;
    let before = scope.try_source_metadata_versions().unwrap();
    let input = scope.state.try_lock().unwrap();
    // This ordinal only labels the actual mutex observation; it is no write.
    let writer = scope.system_write_state.try_system_write_lock(1).unwrap();
    assert!(scope.try_source_metadata_versions().is_err());
    drop(input);
    // Releasing one partition cannot make the other writer's fence even.
    assert!(scope.try_source_metadata_versions().is_err());
    assert!(scope.state.try_lock().is_ok());
    drop(writer);
    let after = scope.try_source_metadata_versions().unwrap();
    assert_eq!(after.1, before.1);
    assert_eq!(after.2, before.2 + 2);
    assert!(scope.inbound_complete.load(Ordering::Acquire));
    let snapshot = serde_json::to_value(scope.snapshot().unwrap()).unwrap();
    assert_eq!(snapshot["system_tun_full_writes"], json!([]));
    assert_eq!(snapshot["daemon_registration_verified"], false);
    assert_eq!(snapshot["canonical_current_owner_verified"], false);
}
