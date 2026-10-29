//! A failed old-network attempt must not hold a restored network behind the
//! Relay backoff. This only wakes the existing supervisor; it owns no sockets.

use super::connection::{wait_for_android_network_change, RelayRouteMonitor};
use super::*;

pub(super) async fn wait_for_retry(
    delay: Duration,
    receiver: Option<crate::AndroidNetworkChangeReceiver>,
    routes: &mut RelayRouteMonitor,
    allow_network_wake: bool,
) -> bool {
    wait_for_retry_with_inspector(delay, receiver, routes, allow_network_wake, || async {
        tokio::task::spawn_blocking(|| crate::netenv::network_route_signature(&[]))
            .await
            .unwrap_or_default()
    })
    .await
}

async fn wait_for_retry_with_inspector<F, Fut>(
    delay: Duration,
    receiver: Option<crate::AndroidNetworkChangeReceiver>,
    routes: &mut RelayRouteMonitor,
    allow_network_wake: bool,
    inspect: F,
) -> bool
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = Vec<String>>,
{
    if !allow_network_wake {
        // Authentication failures retain their original deadline. Do not
        // consume a pending network edge until this wait has completed.
        sleep(delay).await;
        return false;
    }
    wait_for_retry_with_route_change(delay, receiver, routes.wait_for_change_with(inspect)).await
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
    async fn subsecond_retries_preserve_route_confirmation_and_accept_new_baseline() {
        use std::sync::atomic::{AtomicUsize, Ordering};

        let mut routes = RelayRouteMonitor::new(vec!["old-route".into()]);
        let samples = AtomicUsize::new(0);
        // Every retry is shorter than one route poll. The first observation
        // must survive nine expired waits until the second poll confirms it.
        for attempt in 0..10 {
            let mut retry = Box::pin(wait_for_retry_with_inspector(
                Duration::from_millis(100),
                None,
                &mut routes,
                true,
                || {
                    samples.fetch_add(1, Ordering::Relaxed);
                    std::future::ready(vec!["new-route".into()])
                },
            ));
            assert!(futures_util::poll!(retry.as_mut()).is_pending());
            tokio::time::advance(Duration::from_millis(100)).await;
            assert_eq!(retry.await, attempt == 9);
        }
        assert_eq!(samples.load(Ordering::Relaxed), 2);
        assert!(
            !wait_for_retry_with_inspector(Duration::from_secs(3), None, &mut routes, true, || {
                std::future::ready(vec!["new-route".into()])
            },)
            .await,
            "an accepted route must not repeatedly reset the retry backoff"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn cancelled_retry_retains_route_confirmation_without_an_extra_monitor() {
        let mut routes = RelayRouteMonitor::new(vec!["old-route".into()]);
        let mut retry = Box::pin(wait_for_retry_with_inspector(
            Duration::from_secs(60),
            None,
            &mut routes,
            true,
            || std::future::ready(vec!["new-route".into()]),
        ));
        assert!(futures_util::poll!(retry.as_mut()).is_pending());
        drop(retry);
        let mut retry = Box::pin(wait_for_retry_with_inspector(
            Duration::from_secs(60),
            None,
            &mut routes,
            true,
            || std::future::ready(vec!["new-route".into()]),
        ));
        assert!(futures_util::poll!(retry.as_mut()).is_pending());
        tokio::time::advance(Duration::from_millis(999)).await;
        assert!(futures_util::poll!(retry.as_mut()).is_pending());
        tokio::time::advance(Duration::from_millis(1)).await;
        assert!(retry.await);
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
        let mut routes = RelayRouteMonitor::new(Vec::new());
        let mut retry = Box::pin(wait_for_retry(
            Duration::from_secs(60),
            Some(receiver.clone()),
            &mut routes,
            false,
        ));
        assert!(futures_util::poll!(retry.as_mut()).is_pending());
        tokio::time::advance(Duration::from_secs(59)).await;
        assert!(futures_util::poll!(retry.as_mut()).is_pending());
        tokio::time::advance(Duration::from_secs(1)).await;
        assert!(!retry.await);
        assert!(crate::android_network_change::take_latest(&receiver)
            .await
            .is_some());
    }
}
