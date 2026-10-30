//! Published expected inputs stay metadata; the actual command must still
//! acquire the sole window metadata owner within its deadline and fence the Arc.
use super::super::{expected, selection};
use super::*;

#[cfg(target_os = "linux")]
pub(super) fn current_wire(scope: &CaptureSession, duration: u64) -> WireWriteWindow {
    let now = monotonic_ns().unwrap();
    let clock = serde_json::to_value(scope.clock_scope.as_ref().unwrap()).unwrap();
    let mut wire = labels();
    wire.producer_scope = hex::encode([0x22; 16]);
    wire.request_nonce = hex::encode(registered("udp", "response").requests[0].request_nonce);
    wire.boot_id = clock["boot_id"].as_str().unwrap().to_owned();
    wire.frame_sha256 = UDP_REQUESTS[0].to_owned();
    wire.original_started_ns = now;
    wire.original_sent_ns = now;
    wire.complete_returned_ns = now;
    wire.original_deadline_ns = now.checked_add(duration).unwrap();
    wire
}

#[tokio::test]
async fn published_window_expectation_never_acquires_held_registry_or_grants_credit() {
    let (setup, _parent) = digest_scope().await;
    {
        let state = setup.session.state.try_lock().unwrap();
        let prepared = expected::prepare(&setup.session, [0x22; 16]).unwrap();
        assert!(Arc::ptr_eq(&prepared.plan, &state.flows[0].plan));
        assert_eq!(selection::current_original_index(&prepared, &state), Ok(0));
        assert!(matches!(
            setup.session.state.try_lock(),
            Err(std::sync::TryLockError::WouldBlock)
        ));
        assert!(matches!(
            expected::prepare(&setup.session, [0x23; 16]),
            Err(CaptureFailure::InvalidPlan)
        ));
    }
    digest_no_credit(&setup.session);
}

#[tokio::test]
async fn published_window_expectation_keeps_actual_producer_shape_and_exact_arc_fences() {
    let (setup, _parent) = digest_scope().await;
    let prepared = expected::prepare(&setup.session, [0x22; 16]).unwrap();
    {
        let mut state = setup.session.state.try_lock().unwrap();
        state.flows[0].producer_scope = [0x23; 16];
        assert_eq!(
            selection::current_original_index(&prepared, &state),
            Err(CaptureFailure::InvalidPlan)
        );
        state.flows[0].producer_scope = [0x22; 16];
        state.flows[0].requests.pop();
        assert_eq!(
            selection::current_original_index(&prepared, &state),
            Err(CaptureFailure::InvalidPlan)
        );
    }
    let (other, _other_parent) = digest_scope().await;
    let prepared = expected::prepare(&other.session, [0x22; 16]).unwrap();
    {
        let mut state = other.session.state.try_lock().unwrap();
        state.flows[0].plan = Arc::new(registered("udp", "response"));
        assert_eq!(
            selection::current_original_index(&prepared, &state),
            Err(CaptureFailure::InvalidPlan)
        );
    }
    digest_no_credit(&setup.session);
    digest_no_credit(&other.session);
}

#[cfg(target_os = "linux")]
#[tokio::test]
async fn actual_window_command_uses_one_real_guard_and_rejects_duplicate_without_io_credit() {
    let (setup, _parent) = digest_scope().await;
    let wire = current_wire(&setup.session, 1_000_000_000);
    let version = setup
        .session
        .window_commands
        .try_metadata_version()
        .unwrap();
    setup
        .session
        .observe_original_write_window(wire)
        .await
        .unwrap();
    assert_eq!(
        setup
            .session
            .window_commands
            .try_metadata_version()
            .unwrap(),
        version + 2
    );
    {
        let state = setup.session.state.try_lock().unwrap();
        let window = state.flows[0].requests[0]
            .original_write_window
            .as_ref()
            .unwrap();
        assert!(!window.native_os_write_verified && !window.canonical_current_owner_verified);
    }
    let mut duplicate = current_wire(&setup.session, 1_000_000_000);
    {
        let state = setup.session.state.try_lock().unwrap();
        let first = state.flows[0].requests[0]
            .original_write_window
            .as_ref()
            .unwrap();
        duplicate.original_started_ns = first.original_started_ns;
        duplicate.original_sent_ns = first.original_sent_ns;
        duplicate.original_deadline_ns = first.original_deadline_ns;
    }
    assert!(matches!(
        setup.session.observe_original_write_window(duplicate).await,
        Err(CaptureFailure::DuplicateWrite)
    ));
    digest_no_credit(&setup.session);
}

#[cfg(target_os = "linux")]
#[tokio::test(flavor = "current_thread")]
async fn actual_window_command_busy_registry_keeps_original_deadline_and_empty_window() {
    let (setup, _parent) = digest_scope().await;
    let session = setup.session.clone();
    let (acquired_tx, acquired_rx) = std::sync::mpsc::sync_channel(0);
    let (release_tx, release_rx) = std::sync::mpsc::sync_channel(1);
    let owner = std::thread::spawn(move || {
        let _guard = session.window_commands.lock().unwrap();
        acquired_tx.send(()).unwrap();
        release_rx
            .recv_timeout(std::time::Duration::from_secs(3))
            .unwrap();
    });
    acquired_rx
        .recv_timeout(std::time::Duration::from_secs(1))
        .unwrap();
    // The original protocol uses exactly sent+1s as its request deadline.
    let wire = current_wire(&setup.session, 1_000_000_000);
    let result = setup.session.observe_original_write_window(wire).await;
    release_tx.send(()).unwrap();
    owner.join().unwrap();
    assert!(matches!(result, Err(CaptureFailure::ControlNotReady)));
    {
        let state = setup.session.state.try_lock().unwrap();
        assert!(state.flows[0]
            .requests
            .iter()
            .all(|request| request.original_write_window.is_none()));
    }
    digest_no_credit(&setup.session);
}
