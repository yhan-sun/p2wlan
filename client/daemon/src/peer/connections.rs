//! The original connection-table lock with optional bounded writer metadata.
//! Read grants, fair writer admission and every actual try remain Tokio's.
#![cfg_attr(not(any(target_os = "linux", all(unix, test))), allow(dead_code))]
use super::{PeerConnection, PeerManager};
use std::collections::HashMap;
use std::future::Future;
use std::ops::{Deref, DerefMut};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, OnceLock};
use std::time::Instant;
use tokio::sync::{OwnedRwLockReadGuard, RwLock, RwLockReadGuard, RwLockWriteGuard, TryLockError};
mod trace;
#[cfg(any(target_os = "linux", all(unix, test)))]
pub(crate) use trace::ConnectionsRefusalSnapshot;
pub(crate) use trace::ConnectionsTraceLease;
pub(super) use trace::Site as ConnectionsLockCaller;
use trace::{Site, Trace, WriteObservation};
type Table = HashMap<String, PeerConnection>;

pub(crate) struct ConnectionsTable {
    inner: Arc<RwLock<Table>>,
    trace: OnceLock<Arc<Trace>>,
    capture_claimed: AtomicBool,
}
pub(crate) struct ConnectionsWriteGuard<'a> {
    inner: Option<RwLockWriteGuard<'a, Table>>,
    observation: Option<WriteObservation>,
}
impl ConnectionsTable {
    pub(super) fn new(value: Table) -> Self {
        Self {
            inner: Arc::new(RwLock::new(value)),
            trace: OnceLock::new(),
            capture_claimed: AtomicBool::new(false),
        }
    }
    pub(super) async fn read(&self) -> RwLockReadGuard<'_, Table> {
        self.inner.read().await
    }
    pub(super) fn try_read(&self) -> Result<RwLockReadGuard<'_, Table>, TryLockError> {
        self.inner.try_read()
    }
    #[cfg(test)]
    pub(super) async fn read_owned(self: Arc<Self>) -> OwnedRwLockReadGuard<Table> {
        self.inner.clone().read_owned().await
    }
    pub(super) fn try_read_owned(
        self: Arc<Self>,
    ) -> Result<OwnedRwLockReadGuard<Table>, TryLockError> {
        self.inner.clone().try_read_owned()
    }
    #[track_caller]
    pub(super) fn write(&self) -> impl Future<Output = ConnectionsWriteGuard<'_>> {
        self.write_for(Site::caller())
    }
    pub(super) async fn write_for(&self, site: Site) -> ConnectionsWriteGuard<'_> {
        // Metadata records first polling, not an exact queue admission time.
        let observation = self.trace.get().and_then(|t| t.begin(site));
        let inner = self.inner.write().await;
        if let Some(value) = &observation {
            value.acquired();
        }
        ConnectionsWriteGuard {
            inner: Some(inner),
            observation,
        }
    }
    #[track_caller]
    pub(super) fn try_write(&self) -> Result<ConnectionsWriteGuard<'_>, TryLockError> {
        self.try_write_for(Site::caller())
    }
    pub(super) fn try_write_for(
        &self,
        site: Site,
    ) -> Result<ConnectionsWriteGuard<'_>, TryLockError> {
        let inner = self.inner.try_write()?; // Exactly the original actual try.
        let observation = self.trace.get().and_then(|t| t.begin(site));
        if let Some(value) = &observation {
            value.acquired();
        }
        Ok(ConnectionsWriteGuard {
            inner: Some(inner),
            observation,
        })
    }
    #[cfg(any(target_os = "linux", all(unix, test)))]
    pub(super) fn try_read_original(
        &self,
        context: Option<super::EpochTryContext>,
    ) -> Result<RwLockReadGuard<'_, Table>, TryLockError> {
        let observed =
            context.and_then(|c| self.trace.get().filter(|t| t.accepts(&c)).map(|t| (t, c)));
        let started = observed.and_then(|_| trace::now_ns());
        let result = self.inner.try_read(); // One original read try; no probe or retry.
        let returned = observed.and_then(|_| trace::now_ns());
        if result.is_err() {
            if let Some((t, c)) = observed {
                t.refused(c, started, returned);
            }
        }
        result
    }
    #[cfg(test)]
    pub(super) fn raw_for_test(&self) -> Arc<RwLock<Table>> {
        self.inner.clone()
    }
    fn capture(&self, owner: u64, id: [u8; 16], expires: Instant) -> ConnectionsTraceLease {
        // Only the first valid capture allocates, before original packet use.
        if owner == 0
            || Instant::now() >= expires
            || self
                .capture_claimed
                .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
                .is_err()
        {
            return ConnectionsTraceLease::disabled();
        }
        let trace = Arc::new(Trace::new(owner, id, expires));
        if self.trace.set(trace.clone()).is_err() {
            return ConnectionsTraceLease::disabled();
        }
        ConnectionsTraceLease::new(&trace, owner)
    }
}
impl Deref for ConnectionsWriteGuard<'_> {
    type Target = Table;
    fn deref(&self) -> &Self::Target {
        self.inner
            .as_deref()
            .expect("connection guard exists until drop")
    }
}
impl DerefMut for ConnectionsWriteGuard<'_> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        self.inner
            .as_deref_mut()
            .expect("connection guard exists until drop")
    }
}
impl Drop for ConnectionsWriteGuard<'_> {
    fn drop(&mut self) {
        if let Some(v) = &self.observation {
            v.ending();
        }
        drop(self.inner.take());
        if let Some(v) = &self.observation {
            v.released();
        }
    }
}
impl PeerManager {
    #[cfg(any(target_os = "linux", all(unix, test)))]
    pub(crate) fn capture_connections_diagnostics(
        &self,
        owner: u64,
        id: [u8; 16],
        expires: Instant,
    ) -> ConnectionsTraceLease {
        self.connections.capture(owner, id, expires)
    }
}
#[cfg(all(unix, test))]
mod tests;
