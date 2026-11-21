use super::*;

fn owner() -> OrdinaryProbeCost {
    OrdinaryProbeCost::new(super::super::ordinary_probe_cost::OrdinaryProbeIdentity {
        transport_instance: 1,
        session_id: 2,
        network_generation: 3,
        peer_session_generation: crate::peer::PeerSessionGeneration::for_test(4),
        recovery_epoch: 5,
    })
}

struct DropSignal(Option<tokio::sync::oneshot::Sender<()>>);

impl Drop for DropSignal {
    fn drop(&mut self) {
        if let Some(tx) = self.0.take() {
            let _ = tx.send(());
        }
    }
}

#[tokio::test]
async fn n01_original_child_normal_completion_is_really_joined() {
    let cost = owner();
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(1);
    let mut task = OrdinaryProbeTask::spawn(cost.clone(), deadline, async {});
    let error = task.finish(false).await;
    let snapshot = cost.snapshot();
    let handle_removed = task.child.is_none();
    drop(task);
    assert!(error.is_none());
    assert!(handle_removed);
    assert_eq!(
        snapshot.producer_settlement,
        OrdinaryProducerSettlement::Joined
    );
    assert!(!snapshot.producer_active);
}

#[tokio::test]
async fn n01_original_child_deadline_exhaustion_is_not_a_join() {
    let cost = owner();
    let fixture_deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(1);
    let already_expired = tokio::time::Instant::now() - std::time::Duration::from_millis(1);
    let (tx, rx) = tokio::sync::oneshot::channel();
    let marker = DropSignal(Some(tx));
    let mut task = OrdinaryProbeTask::spawn(cost.clone(), already_expired, async move {
        let _marker = marker;
        std::future::pending::<()>().await;
    });
    let error = task.finish(false).await;
    let at_return = cost.snapshot();
    // Test fixture cleanup retains and actually reaps the aborted handle under
    // its original one-second bound. It must not rewrite the production
    // exhausted-deadline observation as a successful invocation join.
    let mut handle = task.child.take().unwrap();
    let joined = tokio::time::timeout_at(fixture_deadline, &mut handle).await;
    let dropped = tokio::time::timeout_at(fixture_deadline, rx).await;
    let after_cleanup = cost.snapshot();
    drop(task);
    assert!(error.is_none());
    assert_eq!(
        at_return.producer_settlement,
        OrdinaryProducerSettlement::OriginalProducerNotJoined
    );
    assert!(joined.unwrap().unwrap_err().is_cancelled());
    assert!(dropped.unwrap().is_ok());
    assert_eq!(
        after_cleanup.producer_settlement,
        OrdinaryProducerSettlement::OriginalProducerNotJoined
    );
    assert!(!after_cleanup.producer_active);
}

#[tokio::test]
async fn n01_parent_abort_drops_the_guard_and_aborts_its_original_child() {
    let cost = owner();
    let started = tokio::time::Instant::now();
    let deadline = started + std::time::Duration::from_secs(1);
    // Observation consumes at most half the original fixture bound, retaining
    // its remaining time for actual failure cleanup. No production timeout changes.
    let observation_deadline = started + std::time::Duration::from_millis(500);
    let (drop_tx, mut drop_rx) = tokio::sync::oneshot::channel();
    let (ready_tx, ready_rx) = tokio::sync::oneshot::channel();
    let marker = DropSignal(Some(drop_tx));
    let mut parent = tokio::spawn({
        let cost = cost.clone();
        async move {
            let owned = OrdinaryProbeTask::spawn(cost, deadline, async move {
                let _marker = marker;
                std::future::pending::<()>().await;
            });
            // This cleanup-only handle cannot join or credit the child. It
            // protects the fixture if a negative removes the original Drop abort.
            let backup_abort = owned.child.as_ref().unwrap().abort_handle();
            let _ = ready_tx.send(backup_abort);
            std::future::pending::<()>().await;
        }
    });
    let ready = tokio::time::timeout_at(observation_deadline, ready_rx).await;
    let ready_succeeded = matches!(&ready, Ok(Ok(_)));
    let backup_abort = ready.ok().and_then(std::result::Result::ok);
    parent.abort();
    let first_parent_join = tokio::time::timeout_at(observation_deadline, &mut parent).await;
    let observed = tokio::time::timeout_at(observation_deadline, &mut drop_rx).await;
    let original_guard_dropped_child = matches!(&observed, Ok(Ok(())));
    if let Some(abort) = backup_abort {
        abort.abort();
    }
    let child_cleanup = match observed {
        Ok(result) => Ok(result),
        Err(_) => tokio::time::timeout_at(deadline, &mut drop_rx).await,
    };
    let parent_join = match first_parent_join {
        Ok(result) => Ok(result),
        Err(_) => tokio::time::timeout_at(deadline, &mut parent).await,
    };
    let snapshot = cost.snapshot();
    // Assert saved original behavior only after the real parent join and
    // backup-protected child future destruction, including a negative path.
    assert!(ready_succeeded);
    assert!(parent_join.unwrap().unwrap_err().is_cancelled());
    assert!(child_cleanup.unwrap().is_ok());
    assert!(
        original_guard_dropped_child,
        "original guard left its child pending until fixture backup abort"
    );
    // Future-drop proof is stronger than abort() alone, but still not a
    // recovered original child JoinHandle. Do not call it a joined total.
    assert_eq!(
        snapshot.producer_settlement,
        OrdinaryProducerSettlement::OriginalProducerNotJoined
    );
    assert!(!snapshot.producer_active);
}

#[tokio::test]
async fn n01_original_child_panic_is_collected_after_join() {
    let cost = owner();
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(1);
    let mut task = OrdinaryProbeTask::spawn(cost.clone(), deadline, async {
        panic!("test-only original child failure");
    });
    let error = task.finish(false).await;
    let snapshot = cost.snapshot();
    let handle_removed = task.child.is_none();
    drop(task);
    assert!(error.is_some_and(|e| e.is_panic()));
    assert!(handle_removed);
    assert_eq!(
        snapshot.producer_settlement,
        OrdinaryProducerSettlement::FailedJoined
    );
    assert!(!snapshot.producer_active);
}
