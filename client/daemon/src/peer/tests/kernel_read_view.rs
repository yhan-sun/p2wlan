//! Real epoch and canonical peer owners. These metadata observations cannot
//! mint KernelRead, Full, SystemTun, current-owner or once credit.
use super::*;
use std::sync::atomic::{AtomicBool, Ordering};

const PEER: &str = "read-view-peer";
const TARGET: &str = "10.20.0.2";

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
async fn expectation_preserves_original_epoch_refusal_and_final_fresh_identity() {
    let (peers, _active) = fixture().await;
    let gate = peers.network_epoch_gate();
    let trace = gate.capture_diagnostics(17, [1; 16], Instant::now() + Duration::from_secs(30));
    let prepared = peers
        .prepare_original_kernel_read_view(PEER, TARGET)
        .unwrap();
    let mut epoch = gate.lock().await;
    let phase = peers
        .publish_original_kernel_read_view(&mut epoch, &prepared)
        .unwrap();
    let context = EpochTryContext {
        capture_owner: 17,
        capture_id: [1; 16],
        run: [2; 16],
        round: [3; 16],
        request_nonce: [4; 16],
        sequence: 0,
        protocol: "tcp",
        kind: "request",
        first_read_ordinal: 0,
        read_peer_input_ordinal: Some(4),
    };
    let first = peers
        .try_capture_original_kernel_read_peer(PEER, TARGET.parse().unwrap(), Some(context))
        .unwrap();
    let refusal = serde_json::to_value(trace.read_peer_snapshot().unwrap()).unwrap();
    for field in [
        "native_os_write_verified",
        "physical_send_verified",
        "canonical_current_owner_verified",
    ] {
        assert_eq!(refusal[field], false);
    }
    assert_eq!(
        first.try_identity_at(&peers, Instant::now()),
        Err(OverlayCreditOutcome::Contended(CreditLock::Epoch))
    );
    drop(phase);
    assert!(peers
        .try_capture_original_kernel_read_peer(PEER, TARGET.parse().unwrap(), None)
        .is_err());
    drop(epoch);
    assert!(first.try_identity_at(&peers, Instant::now()).is_ok());
}

#[tokio::test]
async fn phase_and_canonical_observer_end_disable_the_same_weak_view() {
    for mode in 0..4 {
        let (peers, active) = fixture().await;
        let prepared = peers
            .prepare_original_kernel_read_view(PEER, TARGET)
            .unwrap();
        let gate = peers.network_epoch_gate();
        let mut epoch = gate.lock().await;
        let phase = peers
            .publish_original_kernel_read_view(&mut epoch, &prepared)
            .unwrap();
        match mode {
            0 => drop(phase),
            1 => {
                active.store(false, Ordering::Release);
                drop(phase);
            }
            2 => {
                drop(active);
                drop(phase);
            }
            _ => {
                drop(phase);
                peers.register_original_kernel_read_observer(
                    Arc::downgrade(&active),
                    Instant::now(),
                );
            }
        }
        assert!(peers
            .try_capture_original_kernel_read_peer(PEER, TARGET.parse().unwrap(), None)
            .is_err());
        if mode != 0 {
            assert!(peers
                .prepare_original_kernel_read_view(PEER, TARGET)
                .is_none());
        }
    }
}

#[tokio::test]
async fn foreign_registry_guard_peer_and_target_cannot_publish() {
    let (peers, _active) = fixture().await;
    let (other, _other_active) = fixture().await;
    let prepared = peers
        .prepare_original_kernel_read_view(PEER, TARGET)
        .unwrap();
    let gate = peers.network_epoch_gate();
    let other_gate = other.network_epoch_gate();
    let mut foreign = other_gate.lock().await;
    assert!(peers
        .publish_original_kernel_read_view(&mut foreign, &prepared)
        .is_none());
    drop(foreign);
    let mut epoch = gate.lock().await;
    assert!(other
        .publish_original_kernel_read_view(&mut epoch, &prepared)
        .is_none());
    // Sharing an actual gate still cannot substitute another manager's view.
    let mut shared = PeerManager::new(test_config());
    shared.network_epoch_gate = gate.clone();
    assert!(shared
        .publish_original_kernel_read_view(&mut epoch, &prepared)
        .is_none());
    for (peer, target) in [("absent-peer", TARGET), (PEER, "10.20.0.99")] {
        let wrong = peers
            .prepare_original_kernel_read_view(peer, target)
            .unwrap();
        assert!(peers
            .publish_original_kernel_read_view(&mut epoch, &wrong)
            .is_none());
    }
    assert!(peers
        .prepare_original_kernel_read_view(PEER, "::1")
        .is_none());
}

#[tokio::test]
async fn old_expectations_reject_real_generation_and_lifecycle_changes() {
    for lifecycle in [false, true] {
        let (peers, _active) = fixture().await;
        let prepared = peers
            .prepare_original_kernel_read_view(PEER, TARGET)
            .unwrap();
        let gate = peers.network_epoch_gate();
        let mut epoch = gate.lock().await;
        let phase = peers
            .publish_original_kernel_read_view(&mut epoch, &prepared)
            .unwrap();
        let first = peers
            .try_capture_original_kernel_read_peer(PEER, TARGET.parse().unwrap(), None)
            .unwrap();
        drop(phase);
        drop(epoch);
        if lifecycle {
            peers.remove_peer(PEER).await;
            let mut info = test_peer(PEER, "127.0.0.1:41000".parse().unwrap());
            info.virtual_ip = TARGET.into();
            peers.add_peer(&info).await;
        } else {
            peers
                .advance_network_generation("read-view identity fence")
                .await;
        }
        let expected = if lifecycle {
            CreditStale::Lifecycle
        } else {
            CreditStale::Generation
        };
        assert_eq!(
            first.try_identity_at(&peers, Instant::now()),
            Err(OverlayCreditOutcome::Stale(expected))
        );
    }
}

#[tokio::test]
async fn busy_or_inactive_canonical_owners_publish_nothing() {
    let (peers, _active) = fixture().await;
    let gate = peers.network_epoch_gate();
    let mut epoch = gate.lock().await;
    let prepared = peers
        .prepare_original_kernel_read_view(PEER, TARGET)
        .unwrap();
    {
        let _connections = peers.connections.write().await;
        assert!(peers
            .publish_original_kernel_read_view(&mut epoch, &prepared)
            .is_none());
    }
    {
        let _membership = peers.peer_membership.lock().unwrap();
        assert!(peers
            .publish_original_kernel_read_view(&mut epoch, &prepared)
            .is_none());
    }
    for closed in [false, true] {
        {
            let mut connections = peers.connections.write().await;
            let peer = connections.get_mut(PEER).unwrap();
            peer.online = closed;
            if closed {
                peer.state = ConnectionState::Closed;
            }
        }
        assert!(peers
            .publish_original_kernel_read_view(&mut epoch, &prepared)
            .is_none());
    }
}

#[tokio::test]
async fn actual_guard_invalidates_latch_before_unlock_even_without_phase_drop() {
    let gate = NetworkEpochGate::new(());
    let active = Arc::new(AtomicBool::new(true));
    let replacement = Arc::new(AtomicBool::new(true));
    let mut epoch = gate.lock().await;
    assert!(epoch.bind_read_view(&active));
    assert!(!epoch.bind_read_view(&replacement));
    drop(epoch);
    assert!(!active.load(Ordering::Acquire));
    assert!(gate.try_lock().is_ok());
}

#[tokio::test]
async fn actual_view_metadata_readers_share_the_same_live_guard_without_final_native_permission() {
    let (peers, _active) = fixture().await;
    let gate = peers.network_epoch_gate();
    let prepared = peers
        .prepare_original_kernel_read_view(PEER, TARGET)
        .unwrap();
    let mut epoch = gate.lock().await;
    let phase = peers
        .publish_original_kernel_read_view(&mut epoch, &prepared)
        .unwrap();
    let first = peers.with_original_kernel_view_read_held_for_test(|| {
        peers
            .try_capture_original_kernel_read_peer(PEER, TARGET.parse().unwrap(), None)
            .unwrap()
    });
    assert_eq!(
        first.try_identity_at(&peers, Instant::now()),
        Err(OverlayCreditOutcome::Contended(CreditLock::Epoch))
    );
    drop(phase);
    assert!(peers
        .with_original_kernel_view_read_held_for_test(|| {
            peers.try_capture_original_kernel_read_peer(PEER, TARGET.parse().unwrap(), None)
        })
        .is_err());
    drop(epoch);
    assert!(first.try_identity_at(&peers, Instant::now()).is_ok());
}

#[tokio::test]
async fn actual_view_metadata_writer_contention_still_fails_closed_without_replacing_the_original_try(
) {
    let (peers, _active) = fixture().await;
    let gate = peers.network_epoch_gate();
    let prepared = peers
        .prepare_original_kernel_read_view(PEER, TARGET)
        .unwrap();
    let mut epoch = gate.lock().await;
    let phase = peers
        .publish_original_kernel_read_view(&mut epoch, &prepared)
        .unwrap();
    assert!(peers
        .with_original_kernel_view_write_held_for_test(|| {
            peers.try_capture_original_kernel_read_peer(PEER, TARGET.parse().unwrap(), None)
        })
        .is_err());
    drop(phase);
    drop(epoch);
}

#[path = "kernel_read_view/captured_values.rs"]
mod captured_values;
