//! The same exclusive epoch mutex, with optional first-refusal metadata.
//! No diagnostic can authorize a read, Full, current owner or once commit.
use std::future::Future;
use std::ops::{Deref, DerefMut};
use std::sync::atomic::{AtomicBool, Ordering};
#[cfg(any(target_os = "linux", all(unix, test)))]
use std::sync::OnceLock;
use std::sync::{Arc, Weak};
#[cfg(any(target_os = "linux", all(unix, test)))]
use std::time::Instant;
use tokio::sync::{Mutex, MutexGuard, OwnedMutexGuard, TryLockError};

#[cfg(any(target_os = "linux", all(unix, test)))]
mod trace;
#[cfg(any(target_os = "linux", all(unix, test)))]
use trace::Site;
#[cfg(any(target_os = "linux", all(unix, test)))]
pub(crate) use trace::{EpochRefusalSnapshot, EpochTryContext};
#[cfg(not(any(target_os = "linux", all(unix, test))))]
#[derive(Clone, Copy)]
struct Site;

// An observation label captured by a synchronous entry before constructing
// its lock future. It never grants access to the mutex or network state.
#[derive(Clone, Copy)]
pub(super) struct EpochLockCaller(Site);

impl EpochLockCaller {
    #[track_caller]
    pub(super) fn capture() -> Self {
        Self(caller_site())
    }
}

// Bounded observation labels only; never an epoch fence or send permit.
#[derive(Clone, Copy)]
pub(crate) enum OutboundEpochPhase {
    Generation = 1,
    Path,
    DirectBudget,
    OriginalEcho,
    Encryption,
    PhysicalMetadata,
    DirectFirst,
}

pub(crate) struct NetworkEpochGate {
    inner: Arc<Mutex<()>>,
    #[cfg(any(target_os = "linux", all(unix, test)))]
    trace_claimed: AtomicBool,
    #[cfg(any(target_os = "linux", all(unix, test)))]
    trace: OnceLock<trace::Trace>,
}

pub(crate) struct NetworkEpochGuard<'a> {
    inner: Option<MutexGuard<'a, ()>>,
    owner: &'a NetworkEpochGate,
    token: Option<u64>,
    read_view_active: Option<Weak<AtomicBool>>,
}

pub(crate) struct OwnedNetworkEpochGuard {
    inner: Option<OwnedMutexGuard<()>>,
    owner: Arc<NetworkEpochGate>,
    token: Option<u64>,
}

#[cfg(any(target_os = "linux", all(unix, test)))]
pub(crate) struct EpochTraceLease {
    gate: Weak<NetworkEpochGate>,
    owner: u64,
}

impl NetworkEpochGate {
    pub(crate) fn new(_: ()) -> Self {
        Self {
            inner: Arc::new(Mutex::new(())),
            #[cfg(any(target_os = "linux", all(unix, test)))]
            trace_claimed: AtomicBool::new(false),
            #[cfg(any(target_os = "linux", all(unix, test)))]
            trace: OnceLock::new(),
        }
    }

    // A synchronous entry captures the real caller before constructing the
    // original lock future; track_caller on an async fn would lose this site.
    #[track_caller]
    pub(crate) fn lock(&self) -> impl Future<Output = NetworkEpochGuard<'_>> {
        self.lock_for(EpochLockCaller::capture())
    }

    pub(super) async fn lock_for(&self, caller: EpochLockCaller) -> NetworkEpochGuard<'_> {
        self.wrap(self.inner.lock().await, caller.0)
    }

    #[track_caller]
    pub(crate) fn try_lock(&self) -> Result<NetworkEpochGuard<'_>, TryLockError> {
        self.try_lock_for(EpochLockCaller::capture())
    }

    pub(super) fn try_lock_for(
        &self,
        caller: EpochLockCaller,
    ) -> Result<NetworkEpochGuard<'_>, TryLockError> {
        self.inner
            .try_lock()
            .map(|guard| self.wrap(guard, caller.0))
    }

    #[track_caller]
    pub(crate) fn try_lock_owned(self: Arc<Self>) -> Result<OwnedNetworkEpochGuard, TryLockError> {
        let site = caller_site();
        let inner = self.inner.clone().try_lock_owned()?;
        Ok(self.wrap_owned(inner, site))
    }

    #[cfg(any(target_os = "linux", all(unix, test)))]
    #[track_caller]
    pub(crate) fn try_lock_original(
        &self,
        context: Option<EpochTryContext>,
    ) -> Result<NetworkEpochGuard<'_>, TryLockError> {
        let site = caller_site();
        let observed = context.and_then(|context| {
            self.trace
                .get()
                .filter(|trace| trace.accepts(&context))
                .map(|trace| (trace, context))
        });
        let started = observed.and_then(|_| trace::now_ns());
        let result = self.inner.try_lock(); // The one original actual try.
        let returned = observed.and_then(|_| trace::now_ns());
        match result {
            Ok(guard) => Ok(self.wrap(guard, site)),
            Err(error) => {
                if let Some((trace, context)) = observed {
                    trace.refused(context, started, returned);
                }
                Err(error)
            }
        }
    }

    fn wrap<'a>(&'a self, inner: MutexGuard<'a, ()>, site: Site) -> NetworkEpochGuard<'a> {
        NetworkEpochGuard {
            inner: Some(inner),
            owner: self,
            token: self.acquired(site),
            read_view_active: None,
        }
    }

    fn wrap_owned(
        self: Arc<Self>,
        inner: OwnedMutexGuard<()>,
        site: Site,
    ) -> OwnedNetworkEpochGuard {
        let token = self.acquired(site);
        OwnedNetworkEpochGuard {
            inner: Some(inner),
            owner: self,
            token,
        }
    }

    #[cfg(any(target_os = "linux", all(unix, test)))]
    pub(crate) fn capture_diagnostics(
        self: &Arc<Self>,
        owner: u64,
        capture_id: [u8; 16],
        expires: Instant,
    ) -> EpochTraceLease {
        let enabled = owner != 0
            && Instant::now() < expires
            && self
                .trace_claimed
                .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
                .is_ok();
        if enabled {
            // Only the single claimant can set: no competing initializer can
            // make a packet or control actor wait on diagnostic initialization.
            let _ = self
                .trace
                .set(trace::Trace::new(owner, capture_id, expires));
        }
        EpochTraceLease {
            gate: if enabled {
                Arc::downgrade(self)
            } else {
                Weak::new()
            },
            owner,
        }
    }

    fn acquired(&self, site: Site) -> Option<u64> {
        #[cfg(any(target_os = "linux", all(unix, test)))]
        {
            self.trace.get().and_then(|trace| trace.acquired(site))
        }
        #[cfg(not(any(target_os = "linux", all(unix, test))))]
        {
            let _ = site;
            None
        }
    }

    fn ending(&self, token: Option<u64>, ended: Option<u64>) {
        #[cfg(any(target_os = "linux", all(unix, test)))]
        if let (Some(token), Some(trace)) = (token, self.trace.get()) {
            trace.ending(token, ended);
        }
        #[cfg(not(any(target_os = "linux", all(unix, test))))]
        let _ = (token, ended);
    }

    fn released(&self, token: Option<u64>, ended: Option<u64>) {
        #[cfg(any(target_os = "linux", all(unix, test)))]
        if let (Some(token), Some(trace)) = (token, self.trace.get()) {
            trace.released(token, ended);
        }
        #[cfg(not(any(target_os = "linux", all(unix, test))))]
        let _ = (token, ended);
    }

    #[cfg(all(unix, test))]
    pub(crate) fn exhaust_diagnostic_tokens(&self) {
        if let Some(trace) = self.trace.get() {
            trace.exhaust_tokens();
        }
    }
}

#[cfg(any(target_os = "linux", all(unix, test)))]
impl EpochTraceLease {
    pub(crate) fn snapshot(&self) -> Option<EpochRefusalSnapshot> {
        self.gate.upgrade()?.trace.get()?.snapshot(self.owner)
    }
    pub(crate) fn read_peer_snapshot(&self) -> Option<EpochRefusalSnapshot> {
        self.gate
            .upgrade()?
            .trace
            .get()?
            .read_peer_snapshot(self.owner)
    }
    pub(crate) fn deactivate(&self) {
        if let Some(gate) = self.gate.upgrade() {
            if let Some(trace) = gate.trace.get() {
                trace.deactivate(self.owner);
            }
        }
    }
}
#[cfg(any(target_os = "linux", all(unix, test)))]
impl Drop for EpochTraceLease {
    fn drop(&mut self) {
        self.deactivate();
    }
}

impl NetworkEpochGuard<'_> {
    pub(super) fn protects(&self, gate: &NetworkEpochGate) -> bool {
        std::ptr::eq(self.owner, gate)
    }

    pub(super) fn bind_read_view(&mut self, active: &Arc<AtomicBool>) -> bool {
        if self
            .read_view_active
            .as_ref()
            .and_then(Weak::upgrade)
            .is_some_and(|previous| previous.load(Ordering::Acquire))
        {
            return false;
        }
        self.read_view_active = Some(Arc::downgrade(active));
        true
    }

    pub(super) fn read_view_is_bound(&self, active: &Arc<AtomicBool>) -> bool {
        self.read_view_active
            .as_ref()
            .is_some_and(|bound| bound.ptr_eq(&Arc::downgrade(active)))
    }

    pub(crate) fn note_outbound_phase(&self, phase: OutboundEpochPhase) {
        #[cfg(any(target_os = "linux", all(unix, test)))]
        if let (Some(token), Some(trace)) = (self.token, self.owner.trace.get()) {
            trace.phase(token, phase);
        }
        #[cfg(not(any(target_os = "linux", all(unix, test))))]
        let _ = phase;
    }
}

// Borrow the same actual guard for existing epoch-fenced APIs. Ownership
// and real unlock stay in this wrapper, including every returned guard.
impl<'a> Deref for NetworkEpochGuard<'a> {
    type Target = MutexGuard<'a, ()>;
    fn deref(&self) -> &Self::Target {
        self.inner.as_ref().expect("epoch guard exists until drop")
    }
}
impl Deref for OwnedNetworkEpochGuard {
    type Target = ();
    fn deref(&self) -> &() {
        self.inner
            .as_deref()
            .expect("owned epoch guard exists until drop")
    }
}
impl DerefMut for OwnedNetworkEpochGuard {
    fn deref_mut(&mut self) -> &mut () {
        self.inner
            .as_deref_mut()
            .expect("owned epoch guard exists until drop")
    }
}

impl Drop for NetworkEpochGuard<'_> {
    fn drop(&mut self) {
        let ended = observed_end(self.token);
        self.owner.ending(self.token, ended);
        if let Some(active) = self.read_view_active.as_ref().and_then(Weak::upgrade) {
            active.store(false, Ordering::Release);
        }
        drop(self.inner.take());
        self.owner.released(self.token, ended);
    }
}
impl Drop for OwnedNetworkEpochGuard {
    fn drop(&mut self) {
        let ended = observed_end(self.token);
        self.owner.ending(self.token, ended);
        drop(self.inner.take());
        self.owner.released(self.token, ended);
    }
}

#[track_caller]
fn caller_site() -> Site {
    #[cfg(any(target_os = "linux", all(unix, test)))]
    {
        Site::caller()
    }
    #[cfg(not(any(target_os = "linux", all(unix, test))))]
    {
        Site
    }
}
fn observed_end(token: Option<u64>) -> Option<u64> {
    #[cfg(any(target_os = "linux", all(unix, test)))]
    {
        token.and_then(|_| trace::now_ns())
    }
    #[cfg(not(any(target_os = "linux", all(unix, test))))]
    {
        let _ = token;
        None
    }
}
