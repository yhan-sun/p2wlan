//! Actual canonical selector and actual guards; metadata cannot create IO proof.
use super::*;
use std::sync::atomic::AtomicUsize;
use tracing_subscriber::prelude::*;

struct DuringSelection {
    peers: Arc<PeerManager>,
    observed: Arc<AtomicUsize>,
}
impl<S: tracing::Subscriber> tracing_subscriber::Layer<S> for DuringSelection {
    fn on_event(&self, event: &tracing::Event<'_>, _: tracing_subscriber::layer::Context<'_, S>) {
        #[derive(Default)]
        struct Name(bool);
        impl tracing::field::Visit for Name {
            fn record_str(&mut self, field: &tracing::field::Field, value: &str) {
                if field.name() == "event" && value == "path_state_snapshot" {
                    self.0 = true;
                }
            }
            fn record_debug(&mut self, _: &tracing::field::Field, _: &dyn std::fmt::Debug) {}
        }
        let mut name = Name::default();
        event.record(&mut name);
        if !name.0 {
            return;
        }
        assert!(self.peers.connections.try_read().is_err());
        let expected = self
            .peers
            .try_capture_original_kernel_read_peer(PEER, TARGET.parse().unwrap(), None)
            .unwrap();
        assert_eq!(
            expected.try_identity_at(&self.peers, Instant::now()),
            Err(OverlayCreditOutcome::Contended(CreditLock::Epoch))
        );
        self.observed.fetch_add(1, Ordering::Relaxed);
    }
}

#[tokio::test]
async fn identity_preparation_covers_actual_selector_without_granting_final_identity() {
    use crate::config::PathPolicy;
    let observed = Arc::new(AtomicUsize::new(0));
    for policy in [
        PathPolicy::Auto,
        PathPolicy::RelayOnly,
        PathPolicy::DirectFirst,
        PathPolicy::DirectSticky,
        PathPolicy::Score,
    ] {
        for (prefer, relay, force) in [
            (false, false, false),
            (true, true, false),
            (false, true, true),
        ] {
            let mut config = test_config();
            config.relay.path_policy = policy;
            let peers = Arc::new(PeerManager::new(config));
            let mut info = test_peer(PEER, "127.0.0.1:41000".parse().unwrap());
            info.virtual_ip = TARGET.into();
            peers.add_peer(&info).await;
            let active = Arc::new(AtomicBool::new(true));
            peers.register_original_kernel_read_observer(
                Arc::downgrade(&active),
                Instant::now() + Duration::from_secs(30),
            );
            let prepared = peers
                .prepare_original_kernel_read_view(PEER, TARGET)
                .unwrap();
            let (epoch, connections) = peers.lock_epoch_and_connections_write().await;
            let before = peers
                .try_kernel_read_peer_values_from_connections(
                    &connections,
                    PEER,
                    TARGET.parse().unwrap(),
                )
                .unwrap();
            let online = connections[PEER].online;
            let vip = connections[PEER].virtual_ip.clone();
            let subscriber = tracing_subscriber::registry().with(DuringSelection {
                peers: peers.clone(),
                observed: observed.clone(),
            });
            let (mut scope, _) = tracing::subscriber::with_default(subscriber, || {
                peers
                    .select_path_with_original_identity_epoch(
                        epoch,
                        connections,
                        Some(prepared),
                        PEER,
                        prefer,
                        relay,
                        None,
                        before.0,
                        force,
                        None,
                    )
                    .unwrap()
            });
            let read = peers.connections.try_read().unwrap();
            assert_eq!(
                peers
                    .try_kernel_read_peer_values_from_connections(
                        &read,
                        PEER,
                        TARGET.parse().unwrap()
                    )
                    .unwrap(),
                before
            );
            assert_eq!(read[PEER].online, online);
            assert_eq!(read[PEER].virtual_ip, vip);
            drop(read);
            scope.note_outbound_phase(OutboundEpochPhase::DirectBudget);
            scope.begin_encryption();
            let expected = peers
                .try_capture_original_kernel_read_peer(PEER, TARGET.parse().unwrap(), None)
                .unwrap();
            assert_eq!(
                expected.try_identity_at(&peers, Instant::now()),
                Err(OverlayCreditOutcome::Contended(CreditLock::Epoch))
            );
            drop(scope);
            assert!(expected.try_identity_at(&peers, Instant::now()).is_ok());
        }
    }
    assert!(observed.load(Ordering::Relaxed) > 0);
}

#[tokio::test]
async fn identity_preparation_finish_and_cancel_retire_before_actual_unlock() {
    for finish in [false, true] {
        let (peers, _active) = fixture().await;
        let prepared = peers
            .prepare_original_kernel_read_view(PEER, TARGET)
            .unwrap();
        let (epoch, connections) = peers.lock_epoch_and_connections_write().await;
        let (scope, _) = peers
            .select_path_with_original_identity_epoch(
                epoch,
                connections,
                Some(prepared.clone()),
                PEER,
                false,
                true,
                None,
                peers.current_network_generation_sync(),
                false,
                Some(&mut DeferredPathSelectionLog::default()),
            )
            .unwrap();
        let expected = peers
            .try_capture_original_kernel_read_peer(PEER, TARGET.parse().unwrap(), None)
            .unwrap();
        if finish {
            let mut epoch = scope.finish();
            assert!(peers
                .try_capture_original_kernel_read_peer(PEER, TARGET.parse().unwrap(), None)
                .is_err());
            assert!(peers
                .publish_original_kernel_read_view(&mut epoch, &prepared)
                .is_none());
            assert_eq!(
                expected.try_identity_at(&peers, Instant::now()),
                Err(OverlayCreditOutcome::Contended(CreditLock::Epoch))
            );
            drop(epoch);
        } else {
            drop(scope);
        }
        assert!(peers.network_epoch_gate().try_lock().is_ok());
        assert!(expected.try_identity_at(&peers, Instant::now()).is_ok());
    }
}

#[tokio::test]
async fn identity_preparation_rejects_foreign_retired_and_later_grants() {
    for mode in 0..5 {
        let (peers, active) = fixture().await;
        let (other, _other_active) = fixture().await;
        let prepared = peers
            .prepare_original_kernel_read_view(PEER, TARGET)
            .unwrap();
        let (mut epoch, mut connections) = peers.lock_epoch_and_connections_write().await;
        if mode == 0 {
            let (_foreign_epoch, foreign_connections) =
                other.lock_epoch_and_connections_write().await;
            drop(connections);
            assert!(peers
                .select_path_with_original_identity_epoch(
                    epoch,
                    foreign_connections,
                    Some(prepared),
                    PEER,
                    false,
                    true,
                    None,
                    peers.current_network_generation_sync(),
                    false,
                    None
                )
                .is_none());
            continue;
        }
        if mode == 4 {
            let (foreign_epoch, foreign_connections) =
                other.lock_epoch_and_connections_write().await;
            drop(foreign_connections);
            drop(epoch);
            assert!(peers
                .select_path_with_original_identity_epoch(
                    foreign_epoch,
                    connections,
                    Some(prepared),
                    PEER,
                    false,
                    true,
                    None,
                    peers.current_network_generation_sync(),
                    false,
                    None
                )
                .is_none());
            continue;
        }
        if mode == 1 {
            active.store(false, Ordering::Release);
        }
        if mode == 2 {
            connections.get_mut(PEER).unwrap().online = false;
        }
        if mode == 3 {
            assert!(peers.capture_original_kernel_read_view_values(
                &mut epoch,
                &connections,
                &prepared
            ));
            drop(connections);
            drop(epoch);
            (epoch, connections) = peers.lock_epoch_and_connections_write().await;
        }
        let (mut scope, _) = peers
            .select_path_with_original_identity_epoch(
                epoch,
                connections,
                Some(prepared),
                PEER,
                false,
                true,
                None,
                peers.current_network_generation_sync(),
                false,
                None,
            )
            .unwrap();
        scope.begin_encryption();
        assert!(peers
            .try_capture_original_kernel_read_peer(PEER, TARGET.parse().unwrap(), None)
            .is_err());
        drop(scope);
    }
}
