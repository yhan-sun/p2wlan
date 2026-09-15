/// Optional signaling context for a synchronized hole punch.
///
/// When present, the punch task can run a fresh-mapping generation and
/// immediately advertise the predicted port window to the peer so the stable
/// side probes the model's top-1 + successor window first.
#[derive(Clone)]
struct HolePunchSignalContext {
    control: ControlClient,
    candidate_snapshot: Arc<RwLock<Option<CandidateSnapshotLease>>>,
    stun_servers: Vec<SocketAddr>,
    stun_timeout: Duration,
    /// Daemon incarnation epoch embedded in the fresh-prediction label.
    boot_epoch_ms: u64,
}

/// Whether the UDP transport incarnation that admitted a punch has already
/// been withdrawn.  A closed sender is cancellation too: no detached worker
/// may keep an unpublished socket alive merely because its final `true` value
/// could not be observed.
fn punch_invocation_is_cancelled(shutdown_rx: Option<&tokio::sync::watch::Receiver<bool>>) -> bool {
    shutdown_rx
        .is_some_and(|shutdown_rx| *shutdown_rx.borrow() || shutdown_rx.has_changed().is_err())
}

async fn wait_and_cancel_punch_invocation(
    mut shutdown_rx: tokio::sync::watch::Receiver<bool>,
    cancellation: Arc<crate::PunchSessionCancellation>,
) {
    loop {
        if *shutdown_rx.borrow_and_update() {
            break;
        }
        if shutdown_rx.changed().await.is_err() {
            break;
        }
    }
    // This handle belongs to exactly one claimed punch/session.  Cancelling it
    // cannot revoke a replacement transport's newer per-peer owner.
    cancellation.cancel_for_hard_hard_cleanup();
}

/// Hard↔Hard releases its short-lived dedup permit after installing the
/// durable session ledger, so its transport-incarnation fence must outlive the
/// initiating worker.  Bind the old lease to that session's own cancellation
/// handle instead of calling the peer-wide deduplicator cancellation API.
fn bind_hard_hard_session_to_punch_invocation(
    shutdown_rx: Option<tokio::sync::watch::Receiver<bool>>,
    cancellation: Arc<crate::PunchSessionCancellation>,
) {
    if let Some(shutdown_rx) = shutdown_rx {
        tokio::spawn(async move {
            let cancellation_on_shutdown = cancellation.clone();
            tokio::select! {
                biased;
                _ = cancellation.cancelled() => {}
                _ = wait_and_cancel_punch_invocation(
                    shutdown_rx,
                    cancellation_on_shutdown,
                ) => {}
            }
        });
    }
}
