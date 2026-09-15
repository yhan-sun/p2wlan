use super::*;
use std::future::{poll_fn, Future};
use std::task::Poll;

async fn assert_history_wait_releases_connections<F>(manager: &PeerManager, operation: F)
where
    F: Future<Output = bool>,
{
    let history = manager.traversal_history.write().await;
    tokio::pin!(operation);
    poll_fn(|cx| {
        assert!(operation.as_mut().poll(cx).is_pending());
        Poll::Ready(())
    })
    .await;
    assert!(manager.network_epoch_gate.try_lock().is_ok());
    assert!(
        manager.connections.try_write().is_ok(),
        "traversal-history contention must not retain the all-peer connection writer"
    );
    drop(history);
    assert!(operation.await);
}

async fn history_contention_peer() -> (PeerManager, SocketAddr, u64) {
    let manager = PeerManager::new_with_history(test_config(), None, TraversalHistory::default());
    let endpoint: SocketAddr = "203.0.113.10:41000".parse().unwrap();
    manager
        .add_peer(&test_peer(
            "history-peer",
            "203.0.113.10:41001".parse().unwrap(),
        ))
        .await;
    let generation = manager.current_network_generation().await;
    {
        let mut connections = manager.connections.write().await;
        let connection = connections.get_mut("history-peer").unwrap();
        connection.ensure_candidate_pair_with_source(
            endpoint,
            generation,
            CandidatePairSource::Birthday,
        );
        connection
            .candidate_sources
            .insert(endpoint.to_string(), CandidatePairSource::Birthday);
    }
    assert!(
        manager
            .record_direct_probe_sent("history-peer", endpoint)
            .await
    );
    (manager, endpoint, generation)
}

#[tokio::test]
async fn direct_failure_releases_connection_writer_before_history_wait() {
    let (manager, _, generation) = history_contention_peer().await;
    assert_history_wait_releases_connections(
        &manager,
        manager.record_direct_failure_for_generation(
            "history-peer",
            generation,
            REASON_DIRECT_PROBE_FAILED,
            "probe failed",
        ),
    )
    .await;
}

#[tokio::test]
async fn birthday_miss_releases_connection_writer_before_history_wait() {
    let (manager, endpoint, generation) = history_contention_peer().await;
    assert_history_wait_releases_connections(
        &manager,
        manager.record_expected_birthday_window_miss_for_generation(
            "history-peer",
            generation,
            &[endpoint],
            false,
            "window exhausted",
        ),
    )
    .await;
}

#[tokio::test]
async fn keepalive_timeout_releases_connection_writer_before_history_wait() {
    let (manager, endpoint, generation) = history_contention_peer().await;
    manager
        .record_direct_success("history-peer", Some(endpoint))
        .await;
    assert_history_wait_releases_connections(
        &manager,
        manager.record_direct_keepalive_timeout_for_generation(
            "history-peer",
            endpoint,
            generation,
        ),
    )
    .await;
}
