#[derive(Clone, Default)]
struct PunchAttemptDeduplicator {
    state: Arc<std::sync::Mutex<PunchAttemptState>>,
}

#[derive(Default)]
struct PunchAttemptState {
    next_session_id: u64,
    active: HashMap<String, PunchAttemptRecord>,
}

struct PunchAttemptRecord {
    session_id: u64,
    priority: u8,
    cancellation: Arc<PunchSessionCancellation>,
}

#[derive(Default)]
struct PunchSessionCancellation {
    cancelled: std::sync::atomic::AtomicBool,
    notify: tokio::sync::Notify,
}

struct PunchSessionPermit {
    owner: PunchAttemptDeduplicator,
    peer_id: String,
    session_id: u64,
    cancellation: Arc<PunchSessionCancellation>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PunchSessionOutcome {
    Completed,
    Cancelled,
    DeadlineExceeded,
}

impl PunchSessionCancellation {
    fn cancel(&self) {
        self.cancelled
            .store(true, std::sync::atomic::Ordering::Release);
        self.notify.notify_waiters();
    }

    async fn cancelled(&self) {
        loop {
            let notified = self.notify.notified();
            if self
                .cancelled
                .load(std::sync::atomic::Ordering::Acquire)
            {
                return;
            }
            notified.await;
        }
    }

    #[cfg(test)]
    fn is_cancelled(&self) -> bool {
        self.cancelled
            .load(std::sync::atomic::Ordering::Acquire)
    }
}

impl PunchSessionPermit {
    async fn cancelled(&self) {
        self.cancellation.cancelled().await;
    }

    #[cfg(test)]
    fn is_cancelled(&self) -> bool {
        self.cancellation.is_cancelled()
    }
}

impl Drop for PunchSessionPermit {
    fn drop(&mut self) {
        self.owner.release(&self.peer_id, self.session_id);
    }
}

impl PunchAttemptDeduplicator {
    async fn claim(&self, peer_id: &str) -> Option<PunchSessionPermit> {
        self.claim_with_priority(peer_id, 1)
    }

    async fn claim_with_window(
        &self,
        peer_id: &str,
        _window: Duration,
    ) -> Option<PunchSessionPermit> {
        self.claim_with_priority(peer_id, 0)
    }

    fn claim_with_priority(&self, peer_id: &str, priority: u8) -> Option<PunchSessionPermit> {
        let mut state = self.state.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        if let Some(active) = state.active.get(peer_id) {
            if active.priority >= priority {
                return None;
            }
            active.cancellation.cancel();
        }

        state.next_session_id = state.next_session_id.wrapping_add(1).max(1);
        let session_id = state.next_session_id;
        let cancellation = Arc::new(PunchSessionCancellation::default());
        state.active.insert(
            peer_id.to_string(),
            PunchAttemptRecord {
                session_id,
                priority,
                cancellation: cancellation.clone(),
            },
        );
        Some(PunchSessionPermit {
            owner: self.clone(),
            peer_id: peer_id.to_string(),
            session_id,
            cancellation,
        })
    }

    fn release(&self, peer_id: &str, session_id: u64) {
        let mut state = self.state.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        if state
            .active
            .get(peer_id)
            .is_some_and(|active| active.session_id == session_id)
        {
            state.active.remove(peer_id);
        }
    }

    #[cfg(test)]
    fn active_session_count(&self) -> usize {
        self.state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .active
            .len()
    }
}

/// Run a punch session with a caller-chosen hard deadline.
///
/// Wide remote-scatter sweeps plan hundreds of ports across multiple sockets
/// and need a deadline derived from the actual probe schedule instead of the
/// fixed 24s bound, which kills them mid-scan before the tail of the birthday
/// window has been covered.
async fn run_owned_punch_session_with_deadline<F>(
    session: &PunchSessionPermit,
    deadline: Duration,
    work: F,
) -> PunchSessionOutcome
where
    F: std::future::Future<Output = ()>,
{
    tokio::select! {
        biased;
        _ = session.cancelled() => PunchSessionOutcome::Cancelled,
        _ = sleep(deadline) => PunchSessionOutcome::DeadlineExceeded,
        _ = work => PunchSessionOutcome::Completed,
    }
}

fn should_cancel_maintenance_offer(
    is_rekey: bool,
    has_session: bool,
    needs_rekey: bool,
    expired: bool,
    has_pending_responder: bool,
) -> bool {
    if has_pending_responder {
        return true;
    }
    if is_rekey {
        has_session && !needs_rekey && !expired
    } else {
        has_session
    }
}
