//! Real grants/reducer fixtures; no Full, KernelRead or native evidence.
use super::*;
use std::sync::atomic::{AtomicUsize, Ordering};
use tracing::instrument::WithSubscriber;
use tracing_subscriber::prelude::*;
const PEER: &str = "relay-log-peer";
const RELAY: &str = "tcp://relay.test:18083";
const CONNECTION: u64 = 7;
async fn fixture() -> Arc<PeerManager> {
    let manager = Arc::new(PeerManager::new(test_config()));
    manager
        .add_peer(&test_peer(PEER, "127.0.0.1:41002".parse().unwrap()))
        .await;
    let generation = manager.current_network_generation_sync();
    manager
        .mark_relay_transport_ready_with_transport(PEER, RELAY, generation, Some(CONNECTION))
        .await;
    assert!(
        manager
            .confirm_relay_peer_with_transport(PEER, RELAY, generation, Some(CONNECTION))
            .await
    );
    manager
}
#[tokio::test]
async fn already_recorded_relay_first_sent_uses_actual_reader_without_epoch_or_writer_wait() {
    let manager = fixture().await;
    let generation = manager.current_network_generation_sync();
    assert!(
        manager
            .mark_relay_first_business_sent_for_generation_with_transport(
                PEER,
                generation,
                RELAY,
                Some(CONNECTION)
            )
            .await
    );
    let before = manager
        .get_connection(PEER)
        .await
        .unwrap()
        .path_state_snapshot();
    let gate = manager.network_epoch_gate();
    let epoch = gate.lock().await;
    let reader = manager.connections.read().await;
    let mut repeated = Box::pin(
        manager.mark_relay_first_business_sent_for_generation_with_transport(
            PEER,
            generation,
            RELAY,
            Some(CONNECTION),
        ),
    );
    assert!(matches!(
        futures_util::poll!(repeated.as_mut()),
        std::task::Poll::Ready(false)
    ));
    drop(repeated);
    assert_eq!(reader.get(PEER).unwrap().path_state_snapshot(), before);
    drop(reader);
    drop(epoch);
}
#[tokio::test]
async fn first_relay_sent_keeps_original_writer_cancellation_and_transport_fences() {
    let manager = fixture().await;
    let generation = manager.current_network_generation_sync();
    assert!(
        !manager
            .mark_relay_first_business_sent_for_generation_with_transport(
                PEER,
                generation,
                RELAY,
                Some(CONNECTION + 1)
            )
            .await
    );
    assert!(manager
        .get_connection(PEER)
        .await
        .unwrap()
        .relay_first
        .business_sent_generation
        .is_none());
    let gate = manager.network_epoch_gate();
    let epoch = gate.lock().await;
    let mut original = Box::pin(
        manager.mark_relay_first_business_sent_for_generation_with_transport(
            PEER,
            generation,
            RELAY,
            Some(CONNECTION),
        ),
    );
    assert!(futures_util::poll!(original.as_mut()).is_pending());
    drop(original);
    assert!(manager
        .connections
        .try_read()
        .unwrap()
        .get(PEER)
        .unwrap()
        .relay_first
        .business_sent_generation
        .is_none());
    drop(epoch);
    assert!(
        manager
            .mark_relay_first_business_sent_for_generation_with_transport(
                PEER,
                generation,
                RELAY,
                Some(CONNECTION)
            )
            .await
    );
}
struct PathLogProbe {
    manager: Arc<PeerManager>,
    events: Arc<AtomicUsize>,
    released: Arc<AtomicUsize>,
}
impl<S: tracing::Subscriber> tracing_subscriber::Layer<S> for PathLogProbe {
    fn on_event(&self, event: &tracing::Event<'_>, _: tracing_subscriber::layer::Context<'_, S>) {
        if event.metadata().target() == "p2pnet_daemon::peer::connection" {
            self.events.fetch_add(1, Ordering::SeqCst);
            let gate = self.manager.network_epoch_gate();
            if gate.try_lock().is_ok() && self.manager.connections.try_write().is_ok() {
                self.released.fetch_add(1, Ordering::SeqCst);
            }
        }
    }
}
#[tokio::test]
async fn original_reducer_state_change_log_callbacks_reenter_only_after_both_grants_release() {
    let manager = fixture().await;
    let events = Arc::new(AtomicUsize::new(0));
    let released = Arc::new(AtomicUsize::new(0));
    let subscriber = tracing_subscriber::registry().with(PathLogProbe {
        manager: manager.clone(),
        events: events.clone(),
        released: released.clone(),
    });
    async {
        let mut log = DeferredPathTransitionLog::new(PEER);
        let (epoch, mut connections) = manager.lock_epoch_and_connections_write().await;
        let conn = connections.get_mut(PEER).unwrap();
        let path_epoch = conn.path_state_snapshot().state.epoch.unwrap();
        let result = conn.commit_path_transition_deferred(
            PathEvent::PeerLeft { epoch: path_epoch },
            |conn| {
                conn.online = false;
            },
            &mut log,
        );
        assert!(result.accepted());
        assert_eq!(events.load(Ordering::SeqCst), 0);
        drop(connections);
        drop(epoch);
        drop(log);
    }
    .with_subscriber(subscriber)
    .await;
    assert_eq!(events.load(Ordering::SeqCst), 1);
    assert_eq!(released.load(Ordering::SeqCst), 1);
    assert_eq!(
        manager.get_connection(PEER).await.unwrap().state,
        ConnectionState::Closed
    );
}
