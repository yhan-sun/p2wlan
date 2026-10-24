//! Real registry contention and canonical cells; no fabricated KernelRead.
use super::*;
use serde_json::json;

async fn setup() -> (
    crate::os_request_capture::control::CaptureSetup,
    std::os::unix::net::UnixStream,
) {
    let (setup, parent) = full::tests::descriptor_scope().await;
    let value = json!({"schema_version":1,"capture_id":"11".repeat(16),
        "producer_scope":"22".repeat(16),"flows":[{
        "protocol":"udp","kind":"request","peer_id":"retention-input-peer",
        "run_nonce":"33".repeat(16),"round_nonce":"44".repeat(16),
        "bind_ip":"10.21.1.2","bind_port":32123,"target_ip":"10.21.1.3","target_port":43210,
        "payload_bytes":128,"request_nonces":["55".repeat(16)]}]});
    setup
        .session
        .register(RegistrationPlan::decode(&serde_json::to_vec(&value).unwrap()).unwrap())
        .unwrap();
    (setup, parent)
}
fn prepared(scope: &CaptureSession) -> PreparedInput {
    let state = scope.state.try_lock().unwrap();
    let prepared = PreparedInput::capture(scope, 0, &state.flows[0].plan).unwrap();
    assert!(Arc::ptr_eq(&prepared.0.invalid, &state.flows[0].invalid));
    prepared
}
fn actual_try(scope: &CaptureSession, ordinal: u64) -> Option<FullRetentionLossReason> {
    match scope.state.try_input_lock(ordinal) {
        Ok(_) => None,
        Err(std::sync::TryLockError::WouldBlock) => {
            Some(FullRetentionLossReason::InputRegistryContended)
        }
        Err(std::sync::TryLockError::Poisoned(_)) => {
            Some(FullRetentionLossReason::InputRegistryPoisoned)
        }
    }
}
fn no_facts(scope: &CaptureSession) {
    let value = serde_json::to_value(scope.snapshot().unwrap()).unwrap();
    assert_eq!(value["requests"][0]["read_events"], 0);
    assert_eq!(
        value["requests"][0]["native_credit"],
        serde_json::Value::Null
    );
    assert_eq!(value["historical_full_packets"], json!([]));
    assert_eq!(value["system_tun_full_writes"], json!([]));
    assert_eq!(value["physical_send_verified"], false);
    assert_eq!(value["canonical_current_owner_verified"], false);
}

#[tokio::test]
async fn retained_input_metadata_keeps_original_busy_try_and_grants_no_native_facts() {
    let (setup, _parent) = setup().await;
    let prepared = prepared(&setup.session);
    let held = setup.session.state.try_lock().unwrap();
    let original = actual_try(&setup.session, 7);
    assert_eq!(
        original,
        Some(FullRetentionLossReason::InputRegistryContended)
    );
    assert_eq!(prepared.after_original(original), None);
    assert!(setup.session.state.input_refusal_snapshot().is_some());
    assert_eq!(actual_try(&setup.session, 8), original); // The strict caller stays refused.
    drop(held);
    no_facts(&setup.session);
}

#[tokio::test]
async fn retained_input_observes_same_canonical_invalidation_during_original_try() {
    let (setup, _parent) = setup().await;
    let prepared = prepared(&setup.session);
    let held = setup.session.state.try_lock().unwrap();
    held.flows[0].invalid.store(true, Ordering::Release);
    let original = actual_try(&setup.session, 7);
    assert_eq!(
        prepared.after_original(original),
        Some(FullRetentionLossReason::InputFlowInvalid)
    );
    drop(held);
    no_facts(&setup.session);
}

#[tokio::test]
async fn retained_input_rejects_missing_foreign_and_equal_but_distinct_registration_handles() {
    let (setup, _parent) = setup().await;
    let (foreign, _foreign_parent) = self::setup().await;
    let state = setup.session.state.try_lock().unwrap();
    assert!(PreparedInput::capture(&setup.session, 1, &state.flows[0].plan).is_none());
    let foreign_state = foreign.session.state.try_lock().unwrap();
    let equal = foreign_state.flows[0].plan.clone();
    assert!(PreparedInput::capture(&setup.session, 0, &equal).is_none());
    assert!(PreparedInput::capture(&foreign.session, 0, &state.flows[0].plan).is_none());
    drop(foreign_state);
    drop(state);
    no_facts(&setup.session);
    no_facts(&foreign.session);
}

#[tokio::test]
async fn retained_input_never_overrides_another_original_refusal_or_success() {
    let (setup, _parent) = setup().await;
    let prepared = prepared(&setup.session);
    for reason in [
        None,
        Some(FullRetentionLossReason::InputScopeUnavailable),
        Some(FullRetentionLossReason::InputScopeNotLive),
        Some(FullRetentionLossReason::InputReadObservationIncomplete),
        Some(FullRetentionLossReason::InputDeviceRetired),
        Some(FullRetentionLossReason::InputClockBeforeRead),
        Some(FullRetentionLossReason::InputRegistryPoisoned),
        Some(FullRetentionLossReason::InputFlowInvalid),
    ] {
        assert_eq!(prepared.after_original(reason), reason);
    }
    no_facts(&setup.session);
}

#[tokio::test]
async fn retained_input_keeps_original_scope_expiry_retirement_and_read_loss() {
    let (setup, _parent) = setup().await;
    assert_eq!(
        PreparedInput::scope_rejection(&setup.session, Instant::now()),
        None
    );
    assert_eq!(
        PreparedInput::scope_rejection(&setup.session, setup.session.expires),
        Some(FullRetentionLossReason::InputScopeNotLive)
    );
    setup.session.read_complete.store(false, Ordering::Release);
    assert_eq!(
        PreparedInput::scope_rejection(&setup.session, Instant::now()),
        Some(FullRetentionLossReason::InputReadObservationIncomplete)
    );
    setup.session.retire();
    assert_eq!(
        PreparedInput::scope_rejection(&setup.session, Instant::now()),
        Some(FullRetentionLossReason::InputScopeNotLive)
    );
    no_facts(&setup.session);
}

#[tokio::test]
async fn retained_input_handle_does_not_keep_scope_or_descriptor_alive() {
    let (setup, parent) = setup().await;
    let prepared = prepared(&setup.session);
    let weak = Arc::downgrade(&setup.session);
    drop(setup);
    drop(parent);
    assert!(weak.upgrade().is_none());
    assert!(!prepared.0.invalid.load(Ordering::Acquire));
}

#[tokio::test]
async fn retained_input_preserves_poison_from_actual_original_registry() {
    let (setup, _parent) = setup().await;
    let prepared = prepared(&setup.session);
    let scope = setup.session.clone();
    assert!(std::thread::spawn(move || {
        let _held = scope.state.try_lock().unwrap();
        panic!("intentional original registry poison control");
    })
    .join()
    .is_err());
    assert_eq!(
        prepared.after_original(actual_try(&setup.session, 7)),
        Some(FullRetentionLossReason::InputRegistryPoisoned)
    );
}
