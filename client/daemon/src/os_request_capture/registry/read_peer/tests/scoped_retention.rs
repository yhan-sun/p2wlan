use super::*;

#[tokio::test]
async fn scoped_retention_metadata_without_original_bytes_grants_no_full_or_native_credit() {
    let (setup, _parent, peers) = setup().await;
    let first = collect(&setup.session);
    assert!(first.is_known());
    let prepared = peers
        .prepare_original_kernel_read_view(PEER, TARGET)
        .unwrap();
    let gate = peers.network_epoch_gate();
    let mut epoch = gate.lock().await;
    let phase = peers
        .publish_original_kernel_read_view(&mut epoch, &prepared)
        .unwrap();
    assert!(first
        .current_rejection_observed(&peers, Instant::now(), None)
        .is_none());
    assert!(first
        .original()
        .unwrap()
        .try_identity_at_observed(&peers, Instant::now(), None)
        .is_err());
    no_kernel_credit(&setup.session);
    drop(phase);
    assert!(first
        .current_rejection_observed(&peers, Instant::now(), None)
        .is_some());
    no_kernel_credit(&setup.session);
}

#[tokio::test]
async fn first_read_refusal_cannot_be_refilled_by_retention_metadata() {
    let (setup, _parent, peers) = setup().await;
    let prepared = peers
        .prepare_original_kernel_read_view(PEER, TARGET)
        .unwrap();
    let gate = peers.network_epoch_gate();
    let mut epoch = gate.lock().await;
    let first = collect(&setup.session);
    assert!(!first.is_known());
    let phase = peers
        .publish_original_kernel_read_view(&mut epoch, &prepared)
        .unwrap();
    let cached = collect(&setup.session);
    assert!(Arc::ptr_eq(&first, &cached));
    assert!(cached
        .current_rejection_observed(&peers, Instant::now(), None)
        .is_some());
    no_kernel_credit(&setup.session);
    drop(phase);
}
