//! Actual epoch/lifecycle owners; metadata cannot mint a native IO receipt.
use super::*;
use std::sync::atomic::{AtomicBool, Ordering};

const PEER: &str = "retention-view-peer";
const TARGET: &str = "10.24.0.2";

async fn fixture() -> (Arc<PeerManager>, Arc<AtomicBool>) {
    let peers = Arc::new(PeerManager::new(test_config()));
    let mut info = test_peer(PEER, "127.0.0.1:41000".parse().unwrap());
    info.virtual_ip = TARGET.into();
    peers.add_peer(&info).await;
    let active = Arc::new(AtomicBool::new(true));
    peers.register_original_kernel_read_observer(
        Arc::downgrade(&active),
        Instant::now() + Duration::from_secs(30),
    );
    (peers, active)
}

#[tokio::test]
async fn live_read_retention_view_never_replaces_strict_final_identity() {
    let (peers, _active) = fixture().await;
    let original = peers
        .try_capture_original_kernel_read_peer(PEER, TARGET.parse().unwrap(), None)
        .unwrap();
    let prepared = peers
        .prepare_original_kernel_read_view(PEER, TARGET)
        .unwrap();
    let gate = peers.network_epoch_gate();
    let trace = gate.capture_diagnostics(79, [5; 16], Instant::now() + Duration::from_secs(30));
    let context = EpochTryContext {
        capture_owner: 79,
        capture_id: [5; 16],
        run: [6; 16],
        round: [7; 16],
        request_nonce: [8; 16],
        sequence: 0,
        protocol: "tcp",
        kind: "response",
        first_read_ordinal: 0,
        read_peer_input_ordinal: Some(14),
    };
    let mut epoch = gate.lock().await;
    let phase = peers
        .publish_original_kernel_read_view(&mut epoch, &prepared)
        .unwrap();
    assert!(original
        .try_read_retention_identity_at_observed(&peers, Instant::now(), Some(context))
        .is_ok());
    let refusal = serde_json::to_value(trace.read_peer_snapshot().unwrap()).unwrap();
    assert_eq!(
        refusal["scope"],
        "actual_original_read_peer_epoch_try_refusal_only"
    );
    for field in [
        "native_os_write_verified",
        "physical_send_verified",
        "canonical_current_owner_verified",
    ] {
        assert_eq!(refusal[field], false);
    }
    assert_eq!(
        original.try_identity_at(&peers, Instant::now()),
        Err(OverlayCreditOutcome::Contended(CreditLock::Epoch))
    );
    drop(phase);
    assert!(original
        .try_read_retention_identity_at_observed(&peers, Instant::now(), None)
        .is_err());
    drop(epoch);
    assert!(original.try_identity_at(&peers, Instant::now()).is_ok());
}

#[tokio::test]
async fn retention_rejects_retired_expired_and_dropped_canonical_observers() {
    for mode in 0..3 {
        let (peers, active) = fixture().await;
        let original = peers
            .try_capture_original_kernel_read_peer(PEER, TARGET.parse().unwrap(), None)
            .unwrap();
        let prepared = peers
            .prepare_original_kernel_read_view(PEER, TARGET)
            .unwrap();
        let gate = peers.network_epoch_gate();
        let mut epoch = gate.lock().await;
        let phase = peers
            .publish_original_kernel_read_view(&mut epoch, &prepared)
            .unwrap();
        match mode {
            0 => active.store(false, Ordering::Release),
            1 => drop(active),
            _ => peers
                .register_original_kernel_read_observer(Arc::downgrade(&active), Instant::now()),
        }
        assert!(original
            .try_read_retention_identity_at_observed(&peers, Instant::now(), None)
            .is_err());
        drop(phase);
    }
}

#[tokio::test]
async fn retention_cannot_refill_an_old_generation_or_peer_lifecycle() {
    for lifecycle in [false, true] {
        let (peers, _active) = fixture().await;
        let original = peers
            .try_capture_original_kernel_read_peer(PEER, TARGET.parse().unwrap(), None)
            .unwrap();
        if lifecycle {
            peers.remove_peer(PEER).await;
            let mut info = test_peer(PEER, "127.0.0.1:41000".parse().unwrap());
            info.virtual_ip = TARGET.into();
            peers.add_peer(&info).await;
        } else {
            peers
                .advance_network_generation("retention identity fence")
                .await;
        }
        let prepared = peers
            .prepare_original_kernel_read_view(PEER, TARGET)
            .unwrap();
        let gate = peers.network_epoch_gate();
        let mut epoch = gate.lock().await;
        let phase = peers
            .publish_original_kernel_read_view(&mut epoch, &prepared)
            .unwrap();
        assert!(original
            .try_read_retention_identity_at_observed(&peers, Instant::now(), None)
            .is_err());
        drop(phase);
    }
}

#[tokio::test]
async fn foreign_peer_target_and_owner_views_do_not_cover_retention() {
    let (peers, _active) = fixture().await;
    let (other, _other_active) = fixture().await;
    let original = peers
        .try_capture_original_kernel_read_peer(PEER, TARGET.parse().unwrap(), None)
        .unwrap();
    let prepared = other
        .prepare_original_kernel_read_view(PEER, TARGET)
        .unwrap();
    let other_gate = other.network_epoch_gate();
    let mut other_epoch = other_gate.lock().await;
    let phase = other
        .publish_original_kernel_read_view(&mut other_epoch, &prepared)
        .unwrap();
    assert!(matches!(
        original.try_read_retention_identity_at_observed(&other, Instant::now(), None),
        Err(OverlayCreditOutcome::Stale(CreditStale::Identity))
    ));
    drop(phase);
    drop(other_epoch);
    let mut second = test_peer("retention-other-peer", "127.0.0.1:41001".parse().unwrap());
    second.virtual_ip = "10.24.0.3".into();
    peers.add_peer(&second).await;
    let prepared = peers
        .prepare_original_kernel_read_view("retention-other-peer", "10.24.0.3")
        .unwrap();
    let gate = peers.network_epoch_gate();
    let mut epoch = gate.lock().await;
    let phase = peers
        .publish_original_kernel_read_view(&mut epoch, &prepared)
        .unwrap();
    assert!(original
        .try_read_retention_identity_at_observed(&peers, Instant::now(), None)
        .is_err());
    drop(phase);
}
