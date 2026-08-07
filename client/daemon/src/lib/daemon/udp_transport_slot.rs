/// The daemon's authoritative publication point for the currently usable UDP
/// transport.
///
/// Most older daemon consumers intentionally keep using `legacy`: they only
/// need a best-effort snapshot before an outbound operation.  WireGuard
/// inbound, however, subscribes to `updates` and resolves the transport at
/// packet handling time, so it can recover from a delayed bind or a later
/// replacement instead of retaining a startup-time `None` forever.
///
/// Publication and withdrawal are serialized by `state`.  A worker receives
/// an owner token with its lease; `clear_if_owner` refuses a late worker's
/// cleanup once a newer worker has published.  This prevents an old socket
/// reader failure from unpublishing a replacement transport.
#[derive(Clone)]
struct UdpTransportPublication {
    inner: Arc<UdpTransportPublicationInner>,
}

struct UdpTransportPublicationInner {
    legacy: Arc<RwLock<Option<UdpTransport>>>,
    updates: tokio::sync::watch::Sender<Option<UdpTransport>>,
    state: Mutex<UdpTransportPublicationState>,
}

struct UdpTransportPublicationState {
    next_owner: u64,
    current_owner: Option<UdpTransportOwner>,
    current_stop: Option<tokio::sync::watch::Sender<bool>>,
}

/// Identity of one published UDP task instance.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct UdpTransportOwner(u64);

/// A lease held by the UDP task instance that published a transport.
///
/// The receiver is also the ownership-scoped cancellation signal for detached
/// workers associated with that transport (currently the peer-reflexive
/// signal loop).  A new publication cancels the prior lease before exposing
/// the replacement.
struct UdpTransportLease {
    owner: UdpTransportOwner,
    shutdown_rx: tokio::sync::watch::Receiver<bool>,
}

impl UdpTransportLease {
    fn owner(&self) -> UdpTransportOwner {
        self.owner
    }

    fn shutdown_receiver(&self) -> tokio::sync::watch::Receiver<bool> {
        self.shutdown_rx.clone()
    }
}

impl UdpTransportPublication {
    fn new(legacy: Arc<RwLock<Option<UdpTransport>>>) -> Self {
        let (updates, _initial_receiver) = tokio::sync::watch::channel(None);
        Self {
            inner: Arc::new(UdpTransportPublicationInner {
                legacy,
                updates,
                state: Mutex::new(UdpTransportPublicationState {
                    next_owner: 0,
                    current_owner: None,
                    current_stop: None,
                }),
            }),
        }
    }

    /// Subscribe to every current/future transport value.  Consumers must
    /// clone a value out of the receiver before awaiting on it.
    fn subscribe(&self) -> tokio::sync::watch::Receiver<Option<UdpTransport>> {
        self.inner.updates.subscribe()
    }

    /// Publish a new transport and atomically supersede the prior owner with
    /// respect to future owner-checked cleanup.
    async fn publish(&self, transport: UdpTransport) -> UdpTransportLease {
        let mut state = self.inner.state.lock().await;
        let previous_owner = state.current_owner;
        if let Some(stop) = state.current_stop.take() {
            let _ = stop.send(true);
        }
        if let (Some(previous_owner), Some(previous_transport)) = (
            previous_owner,
            self.inner.legacy.read().await.clone(),
        ) {
            previous_transport
                .clear_inbound_publication_owner_if_matches(previous_owner.0);
        }

        state.next_owner = state.next_owner.wrapping_add(1);
        if state.next_owner == 0 {
            // Zero is reserved only as an implementation sentinel.  Wrapping
            // must never make a genuinely old owner look current again.
            state.next_owner = 1;
        }
        let owner = UdpTransportOwner(state.next_owner);
        let (stop_tx, stop_rx) = tokio::sync::watch::channel(false);

        // `state` stays locked through both stores.  An old worker can either
        // clear before this begins, or observes the new owner and is refused;
        // it can never clear the legacy slot/watch value after this commit.
        transport.set_inbound_publication_owner(owner.0);
        *self.inner.legacy.write().await = Some(transport.clone());
        self.inner.updates.send_replace(Some(transport));
        state.current_owner = Some(owner);
        state.current_stop = Some(stop_tx);

        UdpTransportLease {
            owner,
            shutdown_rx: stop_rx,
        }
    }

    /// Withdraw the currently published value only when the caller still owns
    /// it.  Returns false when the lease was already superseded.
    async fn clear_if_owner(&self, owner: UdpTransportOwner) -> bool {
        let mut state = self.inner.state.lock().await;
        if state.current_owner != Some(owner) {
            return false;
        }

        if let Some(stop) = state.current_stop.take() {
            let _ = stop.send(true);
        }
        if let Some(transport) = self.inner.legacy.read().await.clone() {
            transport.clear_inbound_publication_owner_if_matches(owner.0);
        }
        *self.inner.legacy.write().await = None;
        self.inner.updates.send_replace(None);
        state.current_owner = None;
        true
    }

    /// Withdraw whichever instance is current, used during daemon shutdown.
    async fn clear_current(&self) {
        let mut state = self.inner.state.lock().await;
        let owner = state.current_owner;
        if let Some(stop) = state.current_stop.take() {
            let _ = stop.send(true);
        }
        if let (Some(owner), Some(transport)) = (owner, self.inner.legacy.read().await.clone()) {
            transport.clear_inbound_publication_owner_if_matches(owner.0);
        }
        *self.inner.legacy.write().await = None;
        self.inner.updates.send_replace(None);
        state.current_owner = None;
    }

    #[cfg(test)]
    async fn current_owner(&self) -> Option<UdpTransportOwner> {
        self.inner.state.lock().await.current_owner
    }
}

// This file is included at the crate root, where `lib.rs` already owns the
// aggregate `tests` module.  Give its focused publication tests a distinct
// module name so they can coexist with that suite.
#[cfg(test)]
mod udp_transport_slot_tests {
    use std::sync::Arc;
    use std::time::Duration;

    use tokio::sync::RwLock;
    use tokio::time::timeout;

    use super::*;

    fn peers() -> Arc<PeerManager> {
        Arc::new(PeerManager::new(
            Config::generate_default("https://ctrl.test", "net1").unwrap(),
        ))
    }

    #[tokio::test]
    async fn udp_transport_publication_notifies_delayed_subscriber() {
        let legacy = Arc::new(RwLock::new(None));
        let publication = UdpTransportPublication::new(legacy.clone());
        let mut updates = publication.subscribe();
        assert!(updates.borrow().is_none());

        let udp = UdpTransport::bind("127.0.0.1:0".parse().unwrap(), peers())
            .await
            .unwrap();
        let expected_addr = udp.local_addr().unwrap();
        let _lease = publication.publish(udp).await;

        timeout(Duration::from_secs(1), updates.changed())
            .await
            .expect("a delayed UDP publication must wake inbound subscribers")
            .expect("UDP publication sender must remain alive");
        assert_eq!(
            updates.borrow().as_ref().unwrap().local_addr().unwrap(),
            expected_addr
        );
        assert_eq!(
            legacy
                .read()
                .await
                .as_ref()
                .unwrap()
                .local_addr()
                .unwrap(),
            expected_addr
        );
    }

    #[tokio::test]
    async fn stale_udp_owner_cannot_unpublish_replacement() {
        let legacy = Arc::new(RwLock::new(None));
        let publication = UdpTransportPublication::new(legacy.clone());
        let mut updates = publication.subscribe();

        let old_udp = UdpTransport::bind("127.0.0.1:0".parse().unwrap(), peers())
            .await
            .unwrap();
        let old_lease = publication.publish(old_udp).await;
        updates.changed().await.unwrap();
        let mut old_shutdown = old_lease.shutdown_receiver();

        let replacement = UdpTransport::bind("127.0.0.1:0".parse().unwrap(), peers())
            .await
            .unwrap();
        let replacement_addr = replacement.local_addr().unwrap();
        let replacement_lease = publication.publish(replacement).await;

        timeout(Duration::from_secs(1), old_shutdown.changed())
            .await
            .expect("replacement must cancel the old transport worker")
            .unwrap();
        assert!(*old_shutdown.borrow());
        assert!(
            !publication.clear_if_owner(old_lease.owner()).await,
            "a late old worker must not clear the replacement"
        );
        assert_eq!(publication.current_owner().await, Some(replacement_lease.owner()));
        assert_eq!(
            legacy
                .read()
                .await
                .as_ref()
                .unwrap()
                .local_addr()
                .unwrap(),
            replacement_addr
        );
        assert_eq!(
            updates.borrow().as_ref().unwrap().local_addr().unwrap(),
            replacement_addr
        );
    }
}
