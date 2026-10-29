//! A failed old-network attempt must not hold a restored network behind the
//! Relay backoff. This only wakes the existing supervisor; it owns no sockets.

use super::connection::{wait_for_android_network_change, RelayRouteMonitor};
use super::*;

pub(super) async fn wait_for_retry(
    delay: Duration,
    receiver: Option<crate::AndroidNetworkChangeReceiver>,
    baseline: Vec<String>,
    allow_network_wake: bool,
) -> bool {
    if !allow_network_wake {
        sleep(delay).await;
        return false;
    }
    let mut routes = RelayRouteMonitor::new(baseline);
    wait_for_retry_with_route_change(delay, receiver, routes.wait_for_change()).await
}

async fn wait_for_retry_with_route_change(
    delay: Duration,
    receiver: Option<crate::AndroidNetworkChangeReceiver>,
    route_change: impl std::future::Future<Output = Vec<String>>,
) -> bool {
    tokio::select! {
        biased;
        _ = async {
            if wait_for_android_network_change(receiver).await.is_none() {
                // Desktop has no Android channel. A closed producer must not
                // turn a failed connection into a tight retry loop either.
                std::future::pending::<()>().await;
            }
        } => true,
        _ = route_change => true,
        _ = sleep(delay) => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::sync::{broadcast, Mutex};

    #[tokio::test(start_paused = true)]
    async fn android_edge_wakes_long_retry_and_coalesces_old_service_edges() {
        let (sender, receiver) = broadcast::channel(8);
        let receiver = Arc::new(Mutex::new(receiver));
        let mut retry = Box::pin(wait_for_retry_with_route_change(
            Duration::from_secs(60),
            Some(receiver.clone()),
            std::future::pending(),
        ));
        assert!(futures_util::poll!(retry.as_mut()).is_pending());
        for generation in [40, 1, 2] {
            sender
                .send(crate::AndroidNetworkChangeHint {
                    kotlin_network_generation: generation,
                    network_identity_hash: format!("network-{generation}"),
                })
                .unwrap();
        }
        assert!(retry.await);
        assert!(crate::android_network_change::take_latest(&receiver)
            .await
            .is_none());
    }

    #[tokio::test(start_paused = true)]
    async fn desktop_route_change_wakes_long_retry_without_an_android_receiver() {
        let (sender, changed) = oneshot::channel();
        let mut retry = Box::pin(wait_for_retry_with_route_change(
            Duration::from_secs(60),
            None,
            async { changed.await.unwrap() },
        ));
        assert!(futures_util::poll!(retry.as_mut()).is_pending());
        sender.send(vec!["replacement-route".into()]).unwrap();
        assert!(retry.await);
    }

    #[tokio::test(start_paused = true)]
    async fn unchanged_network_and_closed_hint_channel_keep_original_deadline() {
        let (sender, receiver) = broadcast::channel(8);
        drop(sender);
        let mut retry = Box::pin(wait_for_retry_with_route_change(
            Duration::from_secs(60),
            Some(Arc::new(Mutex::new(receiver))),
            std::future::pending(),
        ));
        assert!(futures_util::poll!(retry.as_mut()).is_pending());
        tokio::time::advance(Duration::from_secs(59)).await;
        assert!(futures_util::poll!(retry.as_mut()).is_pending());
        tokio::time::advance(Duration::from_secs(1)).await;
        assert!(!retry.await);
    }

    #[tokio::test(start_paused = true)]
    async fn network_edge_does_not_bypass_permanent_auth_backoff() {
        let (sender, receiver) = broadcast::channel(8);
        let receiver = Arc::new(Mutex::new(receiver));
        sender
            .send(crate::AndroidNetworkChangeHint {
                kotlin_network_generation: 1,
                network_identity_hash: "new-network".into(),
            })
            .unwrap();
        let mut retry = Box::pin(wait_for_retry(
            Duration::from_secs(60),
            Some(receiver.clone()),
            Vec::new(),
            false,
        ));
        assert!(futures_util::poll!(retry.as_mut()).is_pending());
        tokio::time::advance(Duration::from_secs(60)).await;
        assert!(!retry.await);
        assert!(crate::android_network_change::take_latest(&receiver)
            .await
            .is_some());
    }
}
