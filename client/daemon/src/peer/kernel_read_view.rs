//! A bounded immutable first-read expectation, live only while its actual
//! epoch guard is borrowed for encryption. It never authorizes native credit.
use super::{NetworkEpochGuard, PeerManager, PeerSessionGeneration};
use std::net::Ipv4Addr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, OnceLock, RwLock, Weak};
use std::time::Instant;

#[derive(Clone)]
struct Observer {
    active: Weak<AtomicBool>,
    expires: Instant,
}

impl Observer {
    fn live(&self, at: Instant) -> bool {
        at < self.expires
            && self
                .active
                .upgrade()
                .is_some_and(|active| active.load(Ordering::Acquire))
    }
}

#[derive(Default)]
struct State {
    observer: Option<Observer>,
    view: Weak<PreparedReadView>,
}

#[derive(Default)]
pub(super) struct ReadViewRegistry {
    identity: Arc<()>,
    state: RwLock<State>,
}

pub(crate) struct PreparedReadView {
    registry: Weak<()>,
    observer: Observer,
    peer: String,
    target: Ipv4Addr,
    values: OnceLock<(u64, PeerSessionGeneration)>,
    active: Arc<AtomicBool>,
}

impl PreparedReadView {
    pub(super) fn is_live(&self, at: Instant) -> bool {
        self.active.load(Ordering::Acquire)
            && self.observer.live(at)
            && Instant::now() < self.observer.expires
    }
}

type ObservedView = (Arc<PreparedReadView>, u64, PeerSessionGeneration);

impl ReadViewRegistry {
    pub(super) fn observe(&self, peer: &str, target: Ipv4Addr) -> Option<ObservedView> {
        let view = self.state.try_read().ok()?.view.upgrade()?;
        if !view.registry.ptr_eq(&Arc::downgrade(&self.identity))
            || view.peer != peer
            || view.target != target
            || !view.is_live(Instant::now())
        {
            return None;
        }
        let (generation, lifecycle) = *view.values.get()?;
        Some((view, generation, lifecycle))
    }
}

pub(crate) struct ReadViewPhase<'a, 'g> {
    _epoch: &'a mut NetworkEpochGuard<'g>,
    view: Arc<PreparedReadView>,
}

impl Drop for ReadViewPhase<'_, '_> {
    fn drop(&mut self) {
        self.view.active.store(false, Ordering::Release);
    }
}

impl PeerManager {
    #[cfg(any(target_os = "linux", all(unix, test)))]
    pub(crate) fn register_original_kernel_read_observer(
        &self,
        active: Weak<AtomicBool>,
        expires: Instant,
    ) {
        if let Ok(mut state) = self.kernel_read_views.state.try_write() {
            state.observer = Some(Observer { active, expires });
            state.view = Weak::new();
        }
    }

    /// Allocation and owned strings stay outside the original epoch scope.
    /// Only the actual capture session's weak canonical active flag enables it.
    pub(crate) fn prepare_original_kernel_read_view(
        &self,
        peer: &str,
        target: &str,
    ) -> Option<Arc<PreparedReadView>> {
        let observer = self
            .kernel_read_views
            .state
            .try_read()
            .ok()?
            .observer
            .clone()?;
        if !observer.live(Instant::now()) {
            return None;
        }
        Some(Arc::new(PreparedReadView {
            registry: Arc::downgrade(&self.kernel_read_views.identity),
            observer,
            peer: peer.to_owned(),
            target: target.parse().ok()?,
            values: OnceLock::new(),
            active: Arc::new(AtomicBool::new(false)),
        }))
    }

    /// The mutable borrow excludes other epoch-fenced caller mutations while
    /// this expectation is live. Guard Drop also invalidates before unlocking.
    pub(crate) fn publish_original_kernel_read_view<'a, 'g>(
        &self,
        epoch: &'a mut NetworkEpochGuard<'g>,
        prepared: &Arc<PreparedReadView>,
    ) -> Option<ReadViewPhase<'a, 'g>> {
        if !epoch.protects(&self.network_epoch_gate)
            || !prepared
                .registry
                .ptr_eq(&Arc::downgrade(&self.kernel_read_views.identity))
            || !prepared.observer.live(Instant::now())
        {
            return None;
        }
        let values = self
            .try_kernel_read_peer_values_in_epoch(
                epoch,
                &prepared.peer,
                prepared.target,
                #[cfg(any(target_os = "linux", all(unix, test)))]
                None,
            )
            .ok()?;
        let mut state = self.kernel_read_views.state.try_write().ok()?;
        prepared.values.set(values).ok()?;
        if !epoch.bind_read_view(&prepared.active) {
            return None;
        }
        prepared.active.store(true, Ordering::Release);
        state.view = Arc::downgrade(prepared);
        Some(ReadViewPhase {
            _epoch: epoch,
            view: prepared.clone(),
        })
    }
}

#[cfg(all(unix, test))]
impl PeerManager {
    pub(crate) fn with_original_kernel_view_read_held_for_test<T>(
        &self,
        operation: impl FnOnce() -> T,
    ) -> T {
        let _held = self.kernel_read_views.state.read().unwrap();
        operation()
    }
    pub(crate) fn with_original_kernel_view_write_held_for_test<T>(
        &self,
        operation: impl FnOnce() -> T,
    ) -> T {
        let _held = self.kernel_read_views.state.write().unwrap();
        operation()
    }
}
