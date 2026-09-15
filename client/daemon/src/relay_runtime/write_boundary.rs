use super::*;

/// Per-command deadline ownership shared by the timeout branch and the relay
/// writer callback. The mutex deliberately spans expectation registration:
/// if the writer wins, timeout waits for registration and can then remove it;
/// if timeout wins, the late-dequeued hook observes `live == false` and cannot
/// register or write. A bare AtomicBool has a Claiming→register race here.
#[derive(Clone, Debug)]
pub(super) struct RelayWriteBoundaryPermit {
    live: Arc<std::sync::Mutex<bool>>,
}

impl RelayWriteBoundaryPermit {
    pub(super) fn new() -> Self {
        Self {
            live: Arc::new(std::sync::Mutex::new(true)),
        }
    }

    pub(super) fn commit(&self, register: impl FnOnce() -> bool) -> bool {
        let mut live = self
            .live
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if !*live {
            return false;
        }
        let accepted = register();
        *live = false;
        accepted
    }

    pub(super) fn revoke(&self) {
        *self
            .live
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = false;
    }
}

#[cfg(test)]
#[path = "tests/write_boundary.rs"]
mod tests;
