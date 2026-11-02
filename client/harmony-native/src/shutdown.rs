use std::sync::{Arc, Mutex, MutexGuard};

type ShutdownCallback = Arc<dyn Fn() + Send + Sync>;

#[derive(Default)]
struct ShutdownState {
    requested: bool,
    callback: Option<ShutdownCallback>,
}

/// Latches a stop request and delivers it to the daemon shutdown channel.
/// The request bit and callback share one mutex so installation and stop have
/// a single ordering point; a stop cannot slip between a pre-lock check and
/// the callback publication.
pub(crate) struct ShutdownGate {
    state: Mutex<ShutdownState>,
}

impl ShutdownGate {
    pub(crate) fn new() -> Self {
        Self {
            state: Mutex::new(ShutdownState::default()),
        }
    }

    #[cfg(target_env = "ohos")]
    pub(crate) fn is_requested(&self) -> bool {
        self.lock_state().requested
    }

    pub(crate) fn install(&self, callback: ShutdownCallback) {
        let callback_now = {
            let mut state = self.lock_state();
            if state.requested {
                Some(callback)
            } else {
                state.callback = Some(callback);
                None
            }
        };
        if let Some(callback) = callback_now {
            callback();
        }
    }

    pub(crate) fn request(&self) {
        let sender = {
            let mut state = self.lock_state();
            state.requested = true;
            state.callback.clone()
        };
        if let Some(callback) = sender {
            callback();
        }
    }

    fn lock_state(&self) -> MutexGuard<'_, ShutdownState> {
        self.state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }
}

#[cfg(test)]
mod tests {
    use super::ShutdownGate;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::{Arc, Barrier};

    fn callback(signaled: Arc<AtomicBool>) -> super::ShutdownCallback {
        Arc::new(move || signaled.store(true, Ordering::Release))
    }

    #[test]
    fn stop_before_sender_install_is_latched_and_delivered() {
        let gate = ShutdownGate::new();
        let signaled = Arc::new(AtomicBool::new(false));

        gate.request();
        gate.install(callback(Arc::clone(&signaled)));

        assert!(signaled.load(Ordering::Acquire));
    }

    #[test]
    fn stop_after_sender_install_is_delivered() {
        let gate = ShutdownGate::new();
        let signaled = Arc::new(AtomicBool::new(false));

        gate.install(callback(Arc::clone(&signaled)));
        gate.request();

        assert!(signaled.load(Ordering::Acquire));
    }

    #[test]
    fn concurrent_stop_and_sender_install_never_loses_shutdown() {
        for _ in 0..64 {
            let gate = Arc::new(ShutdownGate::new());
            let barrier = Arc::new(Barrier::new(3));
            let signaled = Arc::new(AtomicBool::new(false));

            let install_gate = Arc::clone(&gate);
            let install_barrier = Arc::clone(&barrier);
            let install_signaled = Arc::clone(&signaled);
            let install = std::thread::spawn(move || {
                install_barrier.wait();
                install_gate.install(callback(install_signaled));
            });

            let stop_gate = Arc::clone(&gate);
            let stop_barrier = Arc::clone(&barrier);
            let stop = std::thread::spawn(move || {
                stop_barrier.wait();
                stop_gate.request();
            });

            barrier.wait();
            install.join().unwrap();
            stop.join().unwrap();
            assert!(signaled.load(Ordering::Acquire));
        }
    }
}
