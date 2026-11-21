//! Synchronization around the original per-client close watch, not a second
//! lifecycle state. A borrowed open guard freezes only close publication.
use std::sync::{Arc, Mutex, MutexGuard, TryLockError};
use tokio::sync::watch;

#[derive(Clone, Copy)]
pub(super) enum ClosePublisher {
    Abort,
    GeneralWriter,
    GeneralReader,
    LegacyWriter,
    LegacyReader,
}

#[derive(Debug)]
pub(super) struct RelayCloseSignal {
    gate: Mutex<()>,
    sender: watch::Sender<bool>,
    #[cfg(test)]
    attempted: std::sync::atomic::AtomicU8,
    #[cfg(test)]
    published: std::sync::atomic::AtomicU8,
    #[cfg(test)]
    changed: tokio::sync::Notify,
}

/// Holds the original close publication gate for a short synchronous operation.
/// This is neither route membership nor peer/session/ACK authority. Do not call
/// close/abort, perform IO, await, or invoke a callback while holding this guard.
/// Do not drop any clone of this RelayClient while the guard is held: every
/// clone's Drop closes the shared connection and would wait on this same gate.
pub struct RelayClientOpenGuard<'a> {
    _gate: MutexGuard<'a, ()>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RelayClientOpenError {
    Closed,
    Contended,
}

impl RelayCloseSignal {
    pub(super) fn new() -> (Arc<Self>, watch::Receiver<bool>) {
        let (sender, receiver) = watch::channel(false);
        (
            Arc::new(Self {
                gate: Mutex::new(()),
                sender,
                #[cfg(test)]
                attempted: std::sync::atomic::AtomicU8::new(0),
                #[cfg(test)]
                published: std::sync::atomic::AtomicU8::new(0),
                #[cfg(test)]
                changed: tokio::sync::Notify::new(),
            }),
            receiver,
        )
    }

    pub(super) fn publish_closed(&self, _publisher: ClosePublisher) {
        #[cfg(test)]
        {
            self.attempted
                .fetch_or(1 << _publisher as u8, std::sync::atomic::Ordering::Release);
            self.changed.notify_waiters();
        }
        let _gate = self.gate.lock().unwrap_or_else(|p| p.into_inner());
        // Retain the original terminal truth even after both receivers retire.
        self.sender.send_replace(true);
        #[cfg(test)]
        {
            self.published
                .fetch_or(1 << _publisher as u8, std::sync::atomic::Ordering::Release);
            self.changed.notify_waiters();
        }
    }

    pub(super) fn try_open(&self) -> Result<RelayClientOpenGuard<'_>, RelayClientOpenError> {
        let gate = match self.gate.try_lock() {
            Ok(guard) => guard,
            Err(TryLockError::Poisoned(error)) => error.into_inner(),
            Err(TryLockError::WouldBlock) => return Err(RelayClientOpenError::Contended),
        };
        // Every writer of this dedicated watch holds this same gate. No watch
        // writer can be outstanding after acquisition; readers cannot close it.
        if *self.sender.borrow() {
            return Err(RelayClientOpenError::Closed);
        }
        Ok(RelayClientOpenGuard { _gate: gate })
    }

    #[cfg(test)]
    pub(super) async fn wait_site(&self, site: ClosePublisher, published: bool) {
        let flags = if published {
            &self.published
        } else {
            &self.attempted
        };
        loop {
            let changed = self.changed.notified();
            if flags.load(std::sync::atomic::Ordering::Acquire) & (1 << site as u8) != 0 {
                return;
            }
            changed.await;
        }
    }

    #[cfg(test)]
    pub(super) fn attempted_at(&self, site: ClosePublisher) -> bool {
        self.attempted.load(std::sync::atomic::Ordering::Acquire) & (1 << site as u8) != 0
    }

    #[cfg(test)]
    pub(super) fn published_at(&self, site: ClosePublisher) -> bool {
        self.published.load(std::sync::atomic::Ordering::Acquire) & (1 << site as u8) != 0
    }
}
