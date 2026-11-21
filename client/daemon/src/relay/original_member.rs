//! Borrowed qualification against original Relay membership/lifecycle owners.
//! The final credit caller must additionally freeze the outer slot,
//! authenticated peer/session, generation and canonical request through commit.
use super::{
    send_origin::RelayBranchDisposition, RelayFullSendFact, RelayTransport, RendezvousRoutes,
};
use p2pnet_relay::{
    OriginalRelayFrameRead, RelayClient, RelayClientOpenError, RelayClientOpenGuard,
};
use std::sync::{atomic::Ordering, Arc, Mutex, MutexGuard, TryLockError};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum RelayMemberFailure {
    UnknownWrite,
    StalePublication,
    Stopped,
    StaleMember,
    UnknownReader,
    Retired,
    Closed,
    ContendedRoutes,
    ContendedLive,
    ContendedClose,
}

pub(crate) struct RelayMemberGuard<'a> {
    transport: &'a RelayTransport,
    endpoint: &'a str,
    routes: Option<MutexGuard<'a, RendezvousRoutes>>,
    _live: Option<MutexGuard<'a, bool>>,
}

fn try_guard<T>(
    lock: &Mutex<T>,
    conflict: RelayMemberFailure,
) -> Result<MutexGuard<'_, T>, RelayMemberFailure> {
    match lock.try_lock() {
        Ok(guard) => Ok(guard),
        Err(TryLockError::Poisoned(error)) => Ok(error.into_inner()),
        Err(TryLockError::WouldBlock) => Err(conflict),
    }
}

impl RelayMemberGuard<'_> {
    fn client(&self) -> Result<&Arc<RelayClient>, RelayMemberFailure> {
        match &self.routes {
            Some(routes) => routes
                .clients
                .get(self.endpoint)
                .ok_or(RelayMemberFailure::StaleMember),
            None => Ok(&self.transport.client),
        }
    }

    /// Borrow from this stable member guard instead of building a self-referential
    /// routes+client guard or retaining a strong client after membership removal.
    pub(crate) fn try_open_guard(&self) -> Result<RelayClientOpenGuard<'_>, RelayMemberFailure> {
        self.client()?
            .try_open_guard()
            .map_err(|error| match error {
                RelayClientOpenError::Closed => RelayMemberFailure::Closed,
                RelayClientOpenError::Contended => RelayMemberFailure::ContendedClose,
            })
    }
}

impl RelayTransport {
    #[cfg(test)]
    pub(crate) fn with_original_live_held_for_test<R>(&self, operation: impl FnOnce() -> R) -> R {
        let _guard = self.write_boundaries_live.lock().unwrap();
        operation()
    }

    #[cfg(test)]
    pub(crate) fn with_original_client_open_held_for_test<R>(
        &self,
        operation: impl FnOnce() -> R,
    ) -> R {
        let _guard = self.client.try_open_guard().unwrap();
        operation()
    }

    pub(crate) fn try_original_reader_member_guard<'a>(
        &'a self,
        rx: &OriginalRelayFrameRead,
        endpoint: &'a str,
        id: u64,
    ) -> Result<RelayMemberGuard<'a>, RelayMemberFailure> {
        if id != self.connection_id() {
            return Err(RelayMemberFailure::StalePublication);
        }
        let routes = match &self.rendezvous {
            Some(pool) => {
                let routes = try_guard(&pool.routes, RelayMemberFailure::ContendedRoutes)?;
                if pool.stopped.load(Ordering::Acquire) {
                    return Err(RelayMemberFailure::Stopped);
                }
                Some(routes)
            }
            None if endpoint == self.endpoint() => None,
            None => return Err(RelayMemberFailure::StaleMember),
        };
        let live = try_guard(
            &self.write_boundaries_live,
            RelayMemberFailure::ContendedLive,
        )?;
        if !*live {
            return Err(RelayMemberFailure::Retired);
        }
        let guard = RelayMemberGuard {
            transport: self,
            endpoint,
            routes,
            _live: Some(live),
        };
        if !rx.belongs_to_client(guard.client()?) {
            return Err(RelayMemberFailure::UnknownReader);
        }
        Ok(guard)
    }

    /// Original writer already owns this exact outer-live mutex. Retain the
    /// original routes, then borrow its close guard through the final prewrite
    /// test. No guard is carried into the later TCP await/Full completion.
    pub(crate) fn try_original_echo_reader_member_guard_under_live<'a>(
        &'a self,
        rx: &OriginalRelayFrameRead,
        endpoint: &'a str,
        original_id: u64,
        writer: &Arc<RelayClient>,
        actual_id: u64,
        actual_live: &Arc<Mutex<bool>>,
    ) -> Result<RelayMemberGuard<'a>, RelayMemberFailure> {
        if original_id != self.connection_id()
            || actual_id != original_id
            || !Arc::ptr_eq(actual_live, &self.write_boundaries_live)
        {
            return Err(RelayMemberFailure::StalePublication);
        }
        let routes = match &self.rendezvous {
            Some(pool) => {
                let routes = try_guard(&pool.routes, RelayMemberFailure::ContendedRoutes)?;
                if pool.stopped.load(Ordering::Acquire) {
                    return Err(RelayMemberFailure::Stopped);
                }
                Some(routes)
            }
            None if endpoint == self.endpoint() => None,
            None => return Err(RelayMemberFailure::StaleMember),
        };
        // None means the real writer callback holds the exact live guard.
        let guard = RelayMemberGuard {
            transport: self,
            endpoint,
            routes,
            _live: None,
        };
        let client = guard.client()?;
        if !Arc::ptr_eq(client, writer) || !rx.belongs_to_client(client) {
            return Err(RelayMemberFailure::UnknownReader);
        }
        Ok(guard)
    }
    /// Caller must hold the original current Relay slot read guard through use.
    /// The RX id must come from its original envelope, never a current snapshot.
    /// Acquire routes -> live here, then close via the returned member guard.
    /// All acquisition is try-only; no IO/await/callback may occur while held.
    pub(crate) fn try_original_member_guard<'a>(
        &'a self,
        tx: &'a RelayFullSendFact,
        rx: &OriginalRelayFrameRead,
        original_rx_connection_id: u64,
    ) -> Result<RelayMemberGuard<'a>, RelayMemberFailure> {
        if tx.disposition() != RelayBranchDisposition::FullWrite || tx.original().is_none() {
            return Err(RelayMemberFailure::UnknownWrite);
        }
        if original_rx_connection_id != self.connection_id()
            || !tx.matches_publication(self.connection_id(), &self.write_boundaries_live)
        {
            return Err(RelayMemberFailure::StalePublication);
        }
        let routes = match &self.rendezvous {
            Some(pool) => {
                let routes = try_guard(&pool.routes, RelayMemberFailure::ContendedRoutes)?;
                if pool.stopped.load(Ordering::Acquire) {
                    return Err(RelayMemberFailure::Stopped);
                }
                Some(routes)
            }
            None if tx.endpoint() == self.endpoint() => None,
            None => return Err(RelayMemberFailure::StaleMember),
        };
        let live = try_guard(
            &self.write_boundaries_live,
            RelayMemberFailure::ContendedLive,
        )?;
        if !*live {
            return Err(RelayMemberFailure::Retired);
        }
        let guard = RelayMemberGuard {
            transport: self,
            endpoint: tx.endpoint(),
            routes,
            _live: Some(live),
        };
        let client = guard.client()?;
        if !tx.matches_client(client) {
            return Err(RelayMemberFailure::StaleMember);
        }
        if !rx.belongs_to_client(client) {
            return Err(RelayMemberFailure::UnknownReader);
        }
        Ok(guard)
    }
}
