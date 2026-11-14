//! Descriptor/scheduler and negative metadata only. No KernelRead, Full,
//! SystemTun write, current-owner permit or positive credit is constructed.
use super::super::FullRetentionLossReason;
use super::*;
use crate::os_request_capture::plan::RegistrationPlan;
use serde_json::json;
use std::time::Duration;

const PRODUCER: [u8; 16] = [0x33; 16];

fn flow(protocol: &str, count: u16, bind_port: u16) -> serde_json::Value {
    json!({
        "protocol":protocol,"kind":"request","peer_id":"terminal-metadata-peer",
        "run_nonce":"44".repeat(16),"round_nonce":"55".repeat(16),
        "bind_ip":"10.21.1.2","bind_port":bind_port,"target_ip":"10.21.1.3","target_port":43210,
        "payload_bytes":128,"request_nonces":(1..=count)
            .map(|i|format!("{:032x}",u32::from(bind_port)*16+u32::from(i)))
            .collect::<Vec<_>>()
    })
}

fn register(session: &CaptureSession, producer: [u8; 16], flows: Vec<serde_json::Value>) {
    let document = json!({"schema_version":1,"capture_id":"11".repeat(16),
        "producer_scope":hex::encode(producer),"flows":flows});
    session
        .register(RegistrationPlan::decode(&serde_json::to_vec(&document).unwrap()).unwrap())
        .unwrap();
}

async fn scope() -> (
    crate::os_request_capture::control::CaptureSetup,
    std::os::unix::net::UnixStream,
) {
    let (setup, parent) = super::super::full::tests::descriptor_scope().await;
    register(&setup.session, PRODUCER, vec![flow("tcp", 8, 32123)]);
    (setup, parent)
}

fn refuse_all(session: &Arc<CaptureSession>) {
    let mut state = session.state.lock().unwrap();
    for request in &mut state.flows[0].requests {
        request.native_credit.get_or_insert_with(|| {
            NativeFrameOutcome::failure(Outcome::Unknown(Unknown::OriginalSource))
        });
    }
    session.record_native_terminal_progress();
}

fn no_credit(session: &CaptureSession) {
    let value = serde_json::to_value(session.snapshot().unwrap()).unwrap();
    assert_eq!(value["historical_full_packets"], json!([]));
    assert_eq!(value["system_tun_full_writes"], json!([]));
    assert_eq!(value["physical_send_verified"], false);
    assert_eq!(value["canonical_current_owner_verified"], false);
}

#[tokio::test]
async fn terminal_handoff_irrevocable_loss_before_wait_keeps_original_negative_and_finishes_missing_rows(
) {
    let (setup, _parent) = scope().await;
    {
        let mut state = setup.session.state.lock().unwrap();
        state.flows[0].requests[0]
            .native_credit
            .get_or_insert_with(|| {
                NativeFrameOutcome::failure(Outcome::Unknown(Unknown::OriginalSource))
            });
    }
    setup
        .session
        .original_full_retention_lost(FullRetentionLossReason::InputRegistryContended);
    let end = tokio::time::Instant::now() + Duration::from_secs(1);
    let receipt = setup
        .session
        .wait_original_outcomes(PRODUCER, end)
        .await
        .unwrap();
    assert_eq!(
        serde_json::to_value(receipt).unwrap()["completed_requests"],
        8
    );
    let value = serde_json::to_value(setup.session.snapshot().unwrap()).unwrap();
    for (i, row) in value["requests"].as_array().unwrap().iter().enumerate() {
        assert_eq!(row["native_credit"]["status"], "unknown");
        assert_eq!(
            row["native_credit"]["outcome"],
            if i == 0 {
                "Unknown(OriginalSource)"
            } else {
                "Unknown(OriginalPublication)"
            }
        );
        assert_eq!(row["native_credit"]["once_committed"], false);
        assert_eq!(row["native_credit"]["commit_monotonic_ns"], json!(null));
        assert_eq!(row["native_credit"]["owner_check"], "not_entered");
        assert_eq!(row["first_read_ordinal"], json!(null));
    }
    assert_eq!(value["original_full_retention_complete"], false);
    no_credit(&setup.session);
}

#[tokio::test(flavor = "current_thread")]
async fn terminal_handoff_irrevocable_loss_wakes_existing_wait_without_a_full_marker() {
    let (setup, _parent) = scope().await;
    let session = setup.session.clone();
    let end = tokio::time::Instant::now() + Duration::from_secs(1);
    let child = tokio::spawn(async move { session.wait_original_outcomes(PRODUCER, end).await });
    tokio::task::yield_now().await;
    assert!(!child.is_finished());
    assert!(!setup.session.full_completion_pending());
    setup
        .session
        .original_full_retention_lost(FullRetentionLossReason::InputRegistryContended);
    let receipt = tokio::time::timeout_at(end, child)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    let value = serde_json::to_value(receipt).unwrap();
    assert_eq!(value["completed_requests"], 8);
    for key in [
        "native_os_write_verified",
        "physical_send_verified",
        "canonical_current_owner_verified",
    ] {
        assert_eq!(value[key], false);
    }
    assert!(!setup.session.full_completion_pending());
    setup
        .session
        .original_full_retention_lost(FullRetentionLossReason::HistoryInvalid);
    assert_eq!(
        setup.session.full_loss.snapshot(),
        Some(FullRetentionLossReason::InputRegistryContended)
    );
    no_credit(&setup.session);
}

#[tokio::test(flavor = "current_thread")]
async fn terminal_handoff_irrevocable_read_and_inbound_loss_wake_without_native_facts() {
    for lose_read in [true, false] {
        let (setup, _parent) = scope().await;
        let session = setup.session.clone();
        let end = tokio::time::Instant::now() + Duration::from_secs(1);
        let child =
            tokio::spawn(async move { session.wait_original_outcomes(PRODUCER, end).await });
        tokio::task::yield_now().await;
        assert!(!child.is_finished());
        let flag = if lose_read {
            &setup.session.read_complete
        } else {
            &setup.session.inbound_complete
        };
        setup.session.original_observation_lost(flag);
        let receipt = tokio::time::timeout_at(end, child)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        assert_eq!(
            serde_json::to_value(receipt).unwrap()["completed_requests"],
            8
        );
        assert!(setup.session.full_complete.load(Ordering::Acquire));
        assert!(!setup.session.full_completion_pending());
        let value = serde_json::to_value(setup.session.snapshot().unwrap()).unwrap();
        for row in value["requests"].as_array().unwrap() {
            assert_eq!(
                row["native_credit"]["outcome"],
                "Unknown(OriginalPublication)"
            );
            assert_eq!(row["native_credit"]["owner_check"], "not_entered");
            assert_eq!(row["native_credit"]["once_committed"], false);
        }
        no_credit(&setup.session);
    }
}

#[tokio::test]
async fn terminal_handoff_irrevocable_loss_cannot_refill_an_expired_end_or_complete_unread_rows() {
    let (setup, _parent) = scope().await;
    let end = tokio::time::Instant::now();
    setup
        .session
        .original_full_retention_lost(FullRetentionLossReason::InputRegistryContended);
    assert!(matches!(
        setup.session.wait_original_outcomes(PRODUCER, end).await,
        Err(CaptureFailure::ControlNotReady)
    ));
    assert!(setup.session.state.lock().unwrap().flows[0]
        .requests
        .iter()
        .all(|r| r.native_credit.is_none()));
    no_credit(&setup.session);
}

#[tokio::test(flavor = "current_thread")]
async fn terminal_handoff_waits_for_first_negative_rows_and_yields_without_credit() {
    let (setup, _parent) = scope().await;
    let session = setup.session.clone();
    let end = tokio::time::Instant::now() + Duration::from_secs(1);
    let child = tokio::spawn(async move { session.wait_original_outcomes(PRODUCER, end).await });
    tokio::task::yield_now().await;
    assert!(!child.is_finished());
    refuse_all(&setup.session);
    let receipt = tokio::time::timeout_at(end, child)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    let value = serde_json::to_value(receipt).unwrap();
    assert_eq!(value["completed_requests"], 8);
    for key in [
        "physical_send_verified",
        "native_os_write_verified",
        "canonical_current_owner_verified",
    ] {
        assert_eq!(value[key], false);
    }
    no_credit(&setup.session);
}

#[tokio::test(flavor = "current_thread")]
async fn terminal_handoff_progress_labels_cannot_refill_original_end_or_make_rows() {
    let (setup, _parent) = scope().await;
    setup.session.record_native_terminal_progress();
    let end = tokio::time::Instant::now() + Duration::from_millis(20);
    assert!(matches!(
        setup.session.wait_original_outcomes(PRODUCER, end).await,
        Err(CaptureFailure::ControlNotReady)
    ));
    refuse_all(&setup.session);
    assert!(matches!(
        setup.session.wait_original_outcomes(PRODUCER, end).await,
        Err(CaptureFailure::ControlNotReady)
    ));
    no_credit(&setup.session);
}

#[tokio::test]
async fn terminal_handoff_keeps_recorded_failure_and_once_false_across_later_metadata() {
    let (setup, _parent) = scope().await;
    refuse_all(&setup.session);
    let before = serde_json::to_value(setup.session.snapshot().unwrap()).unwrap();
    let end = tokio::time::Instant::now() + Duration::from_secs(1);
    setup
        .session
        .wait_original_outcomes(PRODUCER, end)
        .await
        .unwrap();
    {
        let mut completion = completion::NativeCompletionBatch::new();
        setup
            .session
            .prepare_original_frames(0, &[0, 1, 2, 3, 4, 5, 6, 7], &mut completion);
        completion.finish(&setup.session);
    }
    setup
        .session
        .wait_original_outcomes(PRODUCER, end)
        .await
        .unwrap();
    let after = serde_json::to_value(setup.session.snapshot().unwrap()).unwrap();
    assert_eq!(before["requests"], after["requests"]);
    for row in after["requests"].as_array().unwrap() {
        assert_eq!(row["native_credit"]["status"], "unknown");
        assert_eq!(row["native_credit"]["once_committed"], false);
    }
    no_credit(&setup.session);
}

#[tokio::test]
async fn terminal_handoff_validates_published_plans_without_locking_capture_input() {
    use std::future::Future;
    use std::task::{Context, Poll, Waker};

    let (setup, _parent) = scope().await;
    let wrong_count = [0x45; 16];
    let wrong_protocol = [0x46; 16];
    let ambiguous = [0x47; 16];
    register(&setup.session, wrong_count, vec![flow("tcp", 7, 32124)]);
    register(&setup.session, wrong_protocol, vec![flow("udp", 8, 32125)]);
    register(
        &setup.session,
        ambiguous,
        vec![flow("tcp", 8, 32126), flow("tcp", 8, 32127)],
    );
    refuse_all(&setup.session);
    let end = tokio::time::Instant::now() + Duration::from_secs(1);
    {
        let _input = setup.session.state.lock().unwrap();
        let poll = |producer| {
            let mut waiter = std::pin::pin!(setup.session.wait_original_outcomes(producer, end));
            waiter
                .as_mut()
                .poll(&mut Context::from_waker(Waker::noop()))
        };
        let Poll::Ready(Ok(receipt)) = poll(PRODUCER) else {
            panic!("registered terminal outcomes must be readable with capture input locked");
        };
        assert_eq!(
            serde_json::to_value(receipt).unwrap()["completed_requests"],
            8
        );
        for invalid in [[0x44; 16], wrong_count, wrong_protocol, ambiguous] {
            assert!(matches!(
                poll(invalid),
                Poll::Ready(Err(CaptureFailure::InvalidPlan))
            ));
        }
    }
    setup.session.retire();
    assert!(matches!(
        setup.session.wait_original_outcomes(PRODUCER, end).await,
        Err(CaptureFailure::Expired)
    ));
    no_credit(&setup.session);
}
