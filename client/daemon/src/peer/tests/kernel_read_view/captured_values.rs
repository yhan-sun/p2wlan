//! Copies from the real original grant; never a native/Full/current-owner fact.
use super::*;
#[tokio::test]
async fn original_grant_values_survive_real_queued_writer_without_relocking_connections() {
    let (peers, _active) = fixture().await;
    let prepared = peers
        .prepare_original_kernel_read_view(PEER, TARGET)
        .unwrap();
    let (mut epoch, connections) = peers.lock_epoch_and_connections_write().await;
    assert!(peers.capture_original_kernel_read_view_values(&mut epoch, &connections, &prepared));
    let mut queued = Box::pin(peers.hold_connections_writer_for_test());
    assert!(futures_util::poll!(queued.as_mut()).is_pending());
    // The same original writer is still held and another actual writer queued.
    // Publishing an already copied expectation must not request another read.
    let phase = peers
        .publish_original_kernel_read_view(&mut epoch, &prepared)
        .unwrap();
    let expected = peers
        .try_capture_original_kernel_read_peer(PEER, TARGET.parse().unwrap(), None)
        .unwrap();
    assert_eq!(
        expected.try_identity_at(&peers, Instant::now()),
        Err(OverlayCreditOutcome::Contended(CreditLock::Epoch))
    );
    drop(phase);
    assert!(peers
        .publish_original_kernel_read_view(&mut epoch, &prepared)
        .is_none());
    drop(queued);
    drop(connections);
    drop(epoch);
    assert!(expected.try_identity_at(&peers, Instant::now()).is_ok());
}
#[tokio::test]
async fn original_grant_values_reject_foreign_connection_and_later_epoch_guards() {
    let (peers, _active) = fixture().await;
    let (other, _other_active) = fixture().await;
    let prepared = peers
        .prepare_original_kernel_read_view(PEER, TARGET)
        .unwrap();
    let (mut epoch, connections) = peers.lock_epoch_and_connections_write().await;
    let (_foreign_epoch, foreign_connections) = other.lock_epoch_and_connections_write().await;
    assert!(!peers.capture_original_kernel_read_view_values(
        &mut epoch,
        &foreign_connections,
        &prepared
    ));
    assert!(peers.capture_original_kernel_read_view_values(&mut epoch, &connections, &prepared));
    drop(connections);
    drop(epoch);
    let gate = peers.network_epoch_gate();
    let mut later = gate.lock().await;
    assert!(peers
        .publish_original_kernel_read_view(&mut later, &prepared)
        .is_none());
    assert!(!peers.capture_original_kernel_read_view_values(
        &mut later,
        &foreign_connections,
        &prepared
    ));
}
#[tokio::test]
async fn original_grant_values_keep_canonical_rejection_and_observer_retirement() {
    for mode in 0..3 {
        let (peers, active) = fixture().await;
        let target = if mode == 0 { "10.20.0.99" } else { TARGET };
        let prepared = peers
            .prepare_original_kernel_read_view(PEER, target)
            .unwrap();
        let (mut epoch, mut connections) = peers.lock_epoch_and_connections_write().await;
        if mode == 1 {
            connections.get_mut(PEER).unwrap().state = ConnectionState::Closed;
        }
        let copied =
            peers.capture_original_kernel_read_view_values(&mut epoch, &connections, &prepared);
        if mode == 2 {
            assert!(copied);
            active.store(false, Ordering::Release);
        } else {
            assert!(!copied);
        }
        assert!(peers
            .publish_original_kernel_read_view(&mut epoch, &prepared)
            .is_none());
        drop(connections);
        drop(epoch);
    }
}
