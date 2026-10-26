//! One metadata owner. Packet callbacks only try; the single control actor may
//! yield within its caller's existing deadline. No guard crosses an IO await.
use crate::os_request_capture::plan::CaptureFailure;
use std::ops::{Deref, DerefMut};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
#[cfg(test)]
use std::sync::LockResult;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError, TryLockError, TryLockResult};
use tokio::sync::Notify;

mod refusal;
pub(super) use refusal::{
    AuthenticatedRefusalSnapshot, InputRefusalSnapshot, OriginalReadRefusalSnapshot,
    SystemWriteRefusalSnapshot,
};

enum ObservedTry {
    OriginalRead(u64),
    KernelInput(u64),
    AuthenticatedInput,
    SystemWrite(u64),
}

pub(super) struct ControlState<T> {
    inner: Mutex<T>,
    metadata_version: AtomicU64,
    changed: Notify,
    completion_released: Notify,
    waiting: Arc<AtomicBool>,
    refusals: refusal::RefusalDiagnostics,
}

pub(super) struct StateGuard<'a, T> {
    inner: Option<MutexGuard<'a, T>>,
    metadata_version: &'a AtomicU64,
    refusals: &'a refusal::RefusalDiagnostics,
    holder_token: u64,
    changed: &'a Notify,
    completion_released: &'a Notify,
}

struct Waiter<'a>(&'a AtomicBool);
impl Drop for Waiter<'_> {
    fn drop(&mut self) {
        self.0.store(false, Ordering::Release);
    }
}

impl<T> ControlState<T> {
    #[cfg(any(target_os = "linux", test))]
    pub(super) fn new(value: T) -> Self {
        Self {
            inner: Mutex::new(value),
            metadata_version: AtomicU64::new(0),
            changed: Notify::new(),
            completion_released: Notify::new(),
            waiting: Arc::new(AtomicBool::new(false)),
            refusals: refusal::RefusalDiagnostics::new(),
        }
    }

    /// A disjoint metadata partition shares the original one-waiter budget.
    /// Its state and write version remain independent, never a second fact.
    #[cfg(any(target_os = "linux", test))]
    pub(super) fn sibling<U>(&self, value: U) -> ControlState<U> {
        let mut state = ControlState::new(value);
        state.waiting = self.waiting.clone();
        state
    }

    fn wrap<'a>(&'a self, inner: MutexGuard<'a, T>, site: refusal::Site) -> StateGuard<'a, T> {
        let _ = self
            .metadata_version
            .try_update(Ordering::AcqRel, Ordering::Acquire, |v| v.checked_add(1));
        StateGuard {
            inner: Some(inner),
            metadata_version: &self.metadata_version,
            refusals: &self.refusals,
            holder_token: self.refusals.acquired(site),
            changed: &self.changed,
            completion_released: &self.completion_released,
        }
    }

    #[track_caller]
    pub(super) fn try_lock(&self) -> TryLockResult<StateGuard<'_, T>> {
        self.try_lock_at(refusal::Site::caller(), None)
    }

    #[track_caller]
    pub(super) fn try_input_lock(&self, read_ordinal: u64) -> TryLockResult<StateGuard<'_, T>> {
        self.try_lock_at(
            refusal::Site::caller(),
            Some(ObservedTry::KernelInput(read_ordinal)),
        )
    }

    #[track_caller]
    pub(super) fn try_original_read_lock(
        &self,
        read_ordinal: u64,
    ) -> TryLockResult<StateGuard<'_, T>> {
        self.try_lock_at(
            refusal::Site::caller(),
            Some(ObservedTry::OriginalRead(read_ordinal)),
        )
    }

    #[track_caller]
    pub(super) fn try_authenticated_lock(&self) -> TryLockResult<StateGuard<'_, T>> {
        self.try_lock_at(
            refusal::Site::caller(),
            Some(ObservedTry::AuthenticatedInput),
        )
    }

    #[track_caller]
    pub(super) fn try_system_write_lock(
        &self,
        write_ordinal: u64,
    ) -> TryLockResult<StateGuard<'_, T>> {
        self.try_lock_at(
            refusal::Site::caller(),
            Some(ObservedTry::SystemWrite(write_ordinal)),
        )
    }

    fn try_lock_at(
        &self,
        site: refusal::Site,
        input: Option<ObservedTry>,
    ) -> TryLockResult<StateGuard<'_, T>> {
        let started = input
            .as_ref()
            .and_then(|_| crate::os_request_capture::clock::monotonic_ns());
        let result = self.inner.try_lock();
        let returned = input
            .as_ref()
            .and_then(|_| crate::os_request_capture::clock::monotonic_ns());
        match result {
            Ok(guard) => Ok(self.wrap(guard, site)),
            Err(TryLockError::WouldBlock) => {
                match input {
                    Some(ObservedTry::OriginalRead(read)) => self.refusals.original_read_refused(
                        read,
                        started,
                        returned,
                        refusal::OriginalReadMutexFailure::WouldBlock,
                    ),
                    Some(ObservedTry::KernelInput(read)) => {
                        self.refusals.refused(read, started, returned)
                    }
                    Some(ObservedTry::AuthenticatedInput) => {
                        self.refusals.authenticated_refused(started, returned)
                    }
                    Some(ObservedTry::SystemWrite(write)) => {
                        self.refusals.system_write_refused(write, started, returned)
                    }
                    None => {}
                }
                Err(TryLockError::WouldBlock)
            }
            Err(TryLockError::Poisoned(error)) => {
                if let Some(ObservedTry::OriginalRead(read)) = input {
                    self.refusals.original_read_refused(
                        read,
                        started,
                        returned,
                        refusal::OriginalReadMutexFailure::Poisoned,
                    );
                }
                Err(TryLockError::Poisoned(PoisonError::new(
                    self.wrap(error.into_inner(), site),
                )))
            }
        }
    }

    #[cfg(any(target_os = "linux", all(unix, test)))]
    pub(super) fn try_metadata_version(&self) -> Result<u64, TryLockError<()>> {
        if self.inner.is_poisoned() {
            return Err(TryLockError::Poisoned(PoisonError::new(())));
        }
        std::sync::atomic::fence(Ordering::Acquire);
        let version = self.metadata_version.load(Ordering::Acquire);
        if !version.is_multiple_of(2) {
            return Err(TryLockError::WouldBlock);
        }
        Ok(version)
    }

    #[cfg(all(unix, test))]
    pub(super) fn actual_mutex_is_available_for_test(&self) -> bool {
        // The same real mutex, without manufacturing a source-write version.
        self.inner.try_lock().is_ok()
    }

    pub(super) fn input_refusal_snapshot(&self) -> Option<InputRefusalSnapshot> {
        self.refusals.snapshot()
    }

    pub(super) fn original_read_refusal_snapshot(&self) -> Option<OriginalReadRefusalSnapshot> {
        self.refusals.original_read_snapshot()
    }

    pub(super) fn authenticated_refusal_snapshot(&self) -> Option<AuthenticatedRefusalSnapshot> {
        self.refusals.authenticated_snapshot()
    }

    pub(super) fn system_write_refusal_snapshot(&self) -> Option<SystemWriteRefusalSnapshot> {
        self.refusals.system_write_snapshot()
    }

    #[cfg(any(target_os = "linux", all(unix, test)))]
    pub(super) async fn completion_released(&self) {
        self.completion_released.notified().await;
    }

    #[cfg(test)]
    #[track_caller]
    pub(super) fn lock(&self) -> LockResult<StateGuard<'_, T>> {
        let site = refusal::Site::caller();
        self.inner
            .lock()
            .map(|guard| self.wrap(guard, site))
            .map_err(|error| PoisonError::new(self.wrap(error.into_inner(), site)))
    }

    /// At most one control waiter; no packet worker enters this path. The
    /// deadline belongs to the original command/window, never a new timeout.
    /// Capture its actual call site synchronously, before polling the unchanged
    /// wait future; tracking a caller on an async fn would lose that site.
    #[track_caller]
    pub(super) fn lock_until(
        &self,
        end: tokio::time::Instant,
    ) -> impl std::future::Future<Output = Result<StateGuard<'_, T>, CaptureFailure>> {
        let site = refusal::Site::caller();
        async move {
            self.waiting
                .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
                .map_err(|_| CaptureFailure::Contended)?;
            let _waiter = Waiter(&self.waiting);
            loop {
                if tokio::time::Instant::now() >= end {
                    return Err(CaptureFailure::ControlNotReady);
                }
                let changed = self.changed.notified();
                tokio::pin!(changed);
                // Subscribe before trying, so release between try and await is
                // retained. Poison remains terminal instead of being waited out.
                changed.as_mut().enable();
                match self.try_lock_at(site, None) {
                    Ok(guard) => {
                        if tokio::time::Instant::now() >= end {
                            return Err(CaptureFailure::ControlNotReady);
                        }
                        return Ok(guard);
                    }
                    Err(TryLockError::Poisoned(_)) => return Err(CaptureFailure::Contended),
                    Err(TryLockError::WouldBlock) => {}
                }
                tokio::time::timeout_at(end, changed)
                    .await
                    .map_err(|_| CaptureFailure::ControlNotReady)?;
            }
        }
    }
}

impl<T> Deref for StateGuard<'_, T> {
    type Target = T;
    fn deref(&self) -> &T {
        self.inner
            .as_deref()
            .expect("state guard exists until drop")
    }
}
impl<T> DerefMut for StateGuard<'_, T> {
    fn deref_mut(&mut self) -> &mut T {
        self.inner
            .as_deref_mut()
            .expect("state guard exists until drop")
    }
}
impl<T> Drop for StateGuard<'_, T> {
    fn drop(&mut self) {
        let ended = crate::os_request_capture::clock::monotonic_ns();
        if !std::thread::panicking() {
            // All sole source writes are complete before marking this prefix
            // stable. The next writer cannot enter until actual mutex unlock.
            let _ = self
                .metadata_version
                .try_update(Ordering::Release, Ordering::Relaxed, |v| v.checked_add(1));
        }
        drop(self.inner.take());
        // Fixed first-refusal metadata only, after releasing the actual guard.
        self.refusals.released(self.holder_token, ended);
        // Waking can call an executor's waker; release the metadata first.
        self.changed.notify_one();
        // A distinct listener cannot consume the original command waiter's
        // release notification. Neither wake grants any native permission.
        self.completion_released.notify_one();
    }
}

#[cfg(test)]
mod tests;
