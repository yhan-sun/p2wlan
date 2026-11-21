use super::*;

#[tokio::test]
async fn n01_original_absolute_deadline_already_reached_beats_ready_body() {
    let dedup = PunchAttemptDeduplicator::default();
    let session = dedup.claim("deadline-peer").await.unwrap();
    let outcome = run_owned_punch_session_until(
        &session,
        tokio::time::Instant::now() - Duration::from_millis(1),
        async {},
    )
    .await;
    assert_eq!(outcome, PunchSessionOutcome::DeadlineExceeded);
}

#[tokio::test]
async fn n01_original_cancel_wins_when_deadline_and_body_are_ready() {
    let dedup = PunchAttemptDeduplicator::default();
    let session = dedup.claim("cancel-peer").await.unwrap();
    session.cancellation_handle().cancel();
    let outcome = run_owned_punch_session_until(
        &session,
        tokio::time::Instant::now() - Duration::from_millis(1),
        async {},
    )
    .await;
    assert_eq!(outcome, PunchSessionOutcome::Cancelled);
}

#[tokio::test]
async fn n01_original_cancel_during_body_poll_is_observed_without_reclocking() {
    let dedup = PunchAttemptDeduplicator::default();
    let session = dedup.claim("poll-peer").await.unwrap();
    let cancellation = session.cancellation_handle();
    let deadline = tokio::time::Instant::now() + Duration::from_secs(1);
    let outcome = run_owned_punch_session_until(&session, deadline, async {
        cancellation.cancel();
        std::future::pending::<()>().await;
    })
    .await;
    assert_eq!(outcome, PunchSessionOutcome::Cancelled);
}

#[tokio::test]
async fn n01_original_duration_helper_and_absolute_helper_complete_normally() {
    let dedup = PunchAttemptDeduplicator::default();
    let session = dedup.claim("complete-peer").await.unwrap();
    let deadline = tokio::time::Instant::now() + Duration::from_secs(1);
    let absolute = run_owned_punch_session_until(&session, deadline, async {}).await;
    let relative =
        run_owned_punch_session_with_deadline(&session, Duration::from_secs(1), async {}).await;
    assert_eq!(absolute, PunchSessionOutcome::Completed);
    assert_eq!(relative, PunchSessionOutcome::Completed);
    // Original sleep(Duration) handles overflow without panicking. The
    // delegated absolute helper must preserve that conversion as well.
    session.cancellation_handle().cancel();
    let overflowing =
        run_owned_punch_session_with_deadline(&session, Duration::MAX, async {}).await;
    assert_eq!(overflowing, PunchSessionOutcome::Cancelled);
}
