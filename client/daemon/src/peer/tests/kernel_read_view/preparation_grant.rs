//! Real original grants, not KernelRead/Full/current-owner/once proof.
use super::*;

#[tokio::test]
async fn original_grant_publishes_before_generation_and_caller_profiling() {
    let (peers, _active) = fixture().await;
    let prepared = peers
        .prepare_original_kernel_read_view(PEER, TARGET)
        .unwrap();
    let grant = peers
        .lock_original_identity_preparation(Some(prepared))
        .await;
    assert!(grant.acquired_at() <= Instant::now());
    assert_eq!(
        grant.current_generation(),
        peers.current_network_generation_sync()
    );
    assert!(peers.connections.try_read().is_err());
    // This happens before any caller profiling or generation predicate.
    let original = peers
        .try_capture_original_kernel_read_peer(PEER, TARGET.parse().unwrap(), None)
        .unwrap();
    assert_eq!(
        original.try_identity_at(&peers, Instant::now()),
        Err(OverlayCreditOutcome::Contended(CreditLock::Epoch))
    );
    let (scope, _) = grant.select(
        PEER,
        false,
        true,
        None,
        peers.current_network_generation_sync(),
        false,
        Some(&mut DeferredPathSelectionLog::default()),
    );
    for phase in [
        OutboundEpochPhase::DirectBudget,
        OutboundEpochPhase::OriginalEcho,
        OutboundEpochPhase::Encryption,
        OutboundEpochPhase::PhysicalMetadata,
        OutboundEpochPhase::DirectFirst,
    ] {
        scope.note_outbound_phase(phase);
        let retained = peers
            .try_capture_original_kernel_read_peer(PEER, TARGET.parse().unwrap(), None)
            .unwrap();
        assert_eq!(
            retained.try_identity_at(&peers, Instant::now()),
            Err(OverlayCreditOutcome::Contended(CreditLock::Epoch))
        );
    }
    drop(scope.finish());
    assert!(original.try_identity_at(&peers, Instant::now()).is_ok());
}

#[tokio::test]
async fn original_grant_rejection_or_cancel_retires_before_exposing_later_epoch() {
    let (peers, _active) = fixture().await;
    let prepared = peers
        .prepare_original_kernel_read_view(PEER, TARGET)
        .unwrap();
    let grant = peers
        .lock_original_identity_preparation(Some(prepared.clone()))
        .await;
    let rejected_expected_generation = grant.current_generation() + 1;
    assert_ne!(grant.current_generation(), rejected_expected_generation);
    drop(grant);
    assert!(peers.connections.try_write().is_ok());
    let gate = peers.network_epoch_gate();
    let mut later = gate.try_lock().unwrap();
    assert!(peers
        .publish_original_kernel_read_view(&mut later, &prepared)
        .is_none());
    assert!(peers
        .try_capture_original_kernel_read_peer(PEER, TARGET.parse().unwrap(), None)
        .is_err());
}

#[tokio::test]
async fn original_grant_keeps_writer_fairness_cancel_and_observer_retirement() {
    let (peers, active) = fixture().await;
    let prepared = peers
        .prepare_original_kernel_read_view(PEER, TARGET)
        .unwrap();
    let reader = peers.connections.read().await;
    let mut waiting = Box::pin(peers.lock_original_identity_preparation(Some(prepared)));
    assert!(futures_util::poll!(waiting.as_mut()).is_pending());
    // The original helper releases epoch while the real writer is queued.
    assert!(peers.network_epoch_gate().try_lock().is_ok());
    drop(waiting);
    drop(reader);
    let prepared = peers
        .prepare_original_kernel_read_view(PEER, TARGET)
        .unwrap();
    active.store(false, Ordering::Release);
    let grant = peers
        .lock_original_identity_preparation(Some(prepared))
        .await;
    assert!(peers
        .try_capture_original_kernel_read_peer(PEER, TARGET.parse().unwrap(), None)
        .is_err());
    drop(grant);
    assert!(peers.network_epoch_gate().try_lock().is_ok());
    assert!(peers.connections.try_write().is_ok());
}
