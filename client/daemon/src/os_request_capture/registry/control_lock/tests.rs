//! Actual mutex/scheduler controls only; no kernel, packet or owner is minted.
use super::*;
use std::sync::Arc;
use std::time::Duration;

#[tokio::test(flavor = "current_thread")]
async fn control_metadata_wait_yields_while_packet_admission_stays_try_only() {
    let state = Arc::new(ControlState::new(7usize));
    let held = state.try_lock().unwrap();
    let other = state.clone();
    let end = tokio::time::Instant::now() + Duration::from_secs(1);
    let child = tokio::spawn(async move { *other.lock_until(end).await.unwrap() });
    tokio::task::yield_now().await;
    assert!(!child.is_finished());
    assert!(matches!(state.try_lock(), Err(TryLockError::WouldBlock)));
    drop(held);
    assert_eq!(
        tokio::time::timeout_at(end, child).await.unwrap().unwrap(),
        7
    );
}

#[tokio::test(flavor = "current_thread")]
async fn original_metadata_deadline_is_not_refilled_after_contention() {
    let state = Arc::new(ControlState::new(7usize));
    let held = state.try_lock().unwrap();
    let other = state.clone();
    let end = tokio::time::Instant::now() + Duration::from_millis(30);
    let child = tokio::spawn(async move {
        matches!(
            other.lock_until(end).await,
            Err(CaptureFailure::ControlNotReady)
        )
    });
    assert!(child.await.unwrap());
    drop(held);
    assert!(matches!(
        state.lock_until(end).await,
        Err(CaptureFailure::ControlNotReady)
    ));
    assert_eq!(*state.try_lock().unwrap(), 7);
}

#[tokio::test(flavor = "current_thread")]
async fn control_metadata_has_one_waiter_and_cancellation_releases_only_its_slot() {
    let state = Arc::new(ControlState::new(7usize));
    let held = state.try_lock().unwrap();
    let other = state.clone();
    let end = tokio::time::Instant::now() + Duration::from_secs(1);
    let child = tokio::spawn(async move { *other.lock_until(end).await.unwrap() });
    tokio::task::yield_now().await;
    assert!(state.waiting.load(Ordering::Acquire));
    assert!(matches!(
        state.lock_until(end).await,
        Err(CaptureFailure::Contended)
    ));
    child.abort();
    assert!(child.await.unwrap_err().is_cancelled());
    assert!(!state.waiting.load(Ordering::Acquire));
    drop(held);
    assert_eq!(*state.lock_until(end).await.unwrap(), 7);
}

#[tokio::test]
async fn poisoned_metadata_remains_terminal_without_waiting_for_a_new_owner() {
    let state = ControlState::new(7usize);
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _held = state.try_lock().unwrap();
        panic!("intentional metadata poison control");
    }));
    assert!(result.is_err());
    let end = tokio::time::Instant::now() + Duration::from_secs(1);
    assert!(matches!(
        state.lock_until(end).await,
        Err(CaptureFailure::Contended)
    ));
    assert!(!state.waiting.load(Ordering::Acquire));
}

#[tokio::test(flavor = "current_thread")]
async fn full_metadata_release_listener_cannot_steal_original_command_wakeup() {
    let state = Arc::new(ControlState::new(7usize));
    let held = state.try_lock().unwrap();
    let other = state.clone();
    let end = tokio::time::Instant::now() + Duration::from_secs(1);
    let child = tokio::spawn(async move { *other.lock_until(end).await.unwrap() });
    tokio::task::yield_now().await;
    let released = state.completion_released();
    tokio::pin!(released);
    assert!(
        std::future::poll_fn(|cx| {
            use std::future::Future;
            assert!(released.as_mut().poll(cx).is_pending());
            std::task::Poll::Ready(true)
        })
        .await
    );
    drop(held);
    tokio::time::timeout_at(end, released).await.unwrap();
    assert_eq!(
        tokio::time::timeout_at(end, child).await.unwrap().unwrap(),
        7
    );
}

#[tokio::test(flavor = "current_thread")]
async fn full_metadata_release_does_not_refill_expired_command_deadline() {
    let state = ControlState::new(7usize);
    let end = tokio::time::Instant::now();
    drop(state.try_lock().unwrap());
    state.completion_released().await;
    assert!(matches!(
        state.lock_until(end).await,
        Err(CaptureFailure::ControlNotReady)
    ));
    assert!(!state.waiting.load(Ordering::Acquire));
}

#[test]
fn metadata_source_version_observes_real_writer_and_never_locks_it() {
    let state = ControlState::new(1u8);
    let first = state.try_metadata_version().unwrap();
    let mut actual = state.try_lock().unwrap();
    assert!(matches!(
        state.try_metadata_version(),
        Err(TryLockError::WouldBlock)
    ));
    *actual = 2;
    drop(actual);
    let next = state.try_metadata_version().unwrap();
    assert!(next > first && next.is_multiple_of(2));
    assert!(state.try_lock().is_ok());
    assert!(state.try_metadata_version().unwrap() > next);
}

#[test]
fn metadata_source_version_exhaustion_never_wraps_or_reopens_sampling() {
    let state = ControlState::new(0u8);
    state
        .metadata_version
        .store(u64::MAX - 1, Ordering::Release);
    let actual = state.try_lock().unwrap();
    assert!(matches!(
        state.try_metadata_version(),
        Err(TryLockError::WouldBlock)
    ));
    drop(actual);
    assert_eq!(state.metadata_version.load(Ordering::Acquire), u64::MAX);
    let actual = state.try_lock().unwrap();
    drop(actual);
    assert!(matches!(
        state.try_metadata_version(),
        Err(TryLockError::WouldBlock)
    ));
    assert_eq!(state.metadata_version.load(Ordering::Acquire), u64::MAX);
}

#[tokio::test]
async fn sibling_partitions_share_one_waiter_and_cancellation_releases_that_same_slot() {
    let input = ControlState::new(());
    let window = input.sibling(());
    let input_held = input.try_lock().unwrap();
    let window_held = window.try_lock().unwrap();
    let end = tokio::time::Instant::now() + std::time::Duration::from_secs(1);
    let mut first = Box::pin(input.lock_until(end));
    assert!(futures_util::poll!(first.as_mut()).is_pending());
    assert!(matches!(
        window.lock_until(end).await,
        Err(CaptureFailure::Contended)
    ));
    drop(first);
    let mut second = Box::pin(window.lock_until(end));
    assert!(futures_util::poll!(second.as_mut()).is_pending());
    drop(window_held);
    let _window = second.await.unwrap();
    drop(input_held);
}
