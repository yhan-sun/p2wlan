/// Until an initiator record is installed in the manager ledger, no other
/// owner will cancel its shared handle when the short-lived punch permit is
/// dropped.  Make every pre-ledger return (including cancellation/panic
/// unwinding) cancel the exact handle so the UDP-lease watcher cannot outlive
/// a failed measurement until the whole transport is replaced.
struct PendingHardHardSessionCancellation {
    cancellation: Option<Arc<crate::PunchSessionCancellation>>,
}

impl PendingHardHardSessionCancellation {
    fn new(cancellation: Arc<crate::PunchSessionCancellation>) -> Self {
        Self {
            cancellation: Some(cancellation),
        }
    }

    fn disarm(&mut self) {
        self.cancellation = None;
    }
}

impl Drop for PendingHardHardSessionCancellation {
    fn drop(&mut self) {
        if let Some(cancellation) = self.cancellation.take() {
            cancellation.cancel_for_hard_hard_cleanup();
        }
    }
}

#[derive(Clone)]
struct HardHardCleanupDescriptor {
    peer_id: String,
    session_id: String,
    session_token: String,
    fresh_socket: crate::peer::HardHardFreshSocketIdentity,
    expires_at_ms: u64,
    cancellation: Arc<crate::PunchSessionCancellation>,
}

impl HardHardCleanupDescriptor {
    fn from_record(record: &HardHardSessionRecord) -> Self {
        Self {
            peer_id: record.peer_id.clone(),
            session_id: record.session_id.clone(),
            session_token: record.session_token.clone(),
            fresh_socket: record.fresh_socket.clone(),
            expires_at_ms: record.expires_at_ms,
            cancellation: record.cancellation.clone(),
        }
    }
}

#[derive(Clone)]
struct HardHardCleanupCompletion {
    completed: Arc<std::sync::atomic::AtomicBool>,
    notify: Arc<tokio::sync::Notify>,
}

impl HardHardCleanupCompletion {
    fn new() -> Self {
        Self {
            completed: Arc::new(std::sync::atomic::AtomicBool::new(false)),
            notify: Arc::new(tokio::sync::Notify::new()),
        }
    }

    fn finish(&self) {
        self.completed
            .store(true, std::sync::atomic::Ordering::Release);
        self.notify.notify_waiters();
    }

    #[cfg(test)]
    async fn wait(&self) {
        loop {
            if self.completed.load(std::sync::atomic::Ordering::Acquire) {
                return;
            }
            let notified = self.notify.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            if self.completed.load(std::sync::atomic::Ordering::Acquire) {
                return;
            }
            notified.await;
        }
    }
}

struct HardHardCleanupCompletionGuard(HardHardCleanupCompletion);

impl Drop for HardHardCleanupCompletionGuard {
    fn drop(&mut self) {
        self.0.finish();
    }
}

/// Cleanup may run after the short rendezvous session has expired.  It still
/// retains a socket only when the current Direct candidate pair and the exact
/// socket's authenticated evidence agree; the expired session token itself is
/// intentionally not required for this post-success retention decision.
async fn hard_hard_exact_direct_socket_is_current_for_cleanup(
    udp: &UdpTransport,
    peers: &PeerManager,
    identity: &crate::peer::HardHardFreshSocketIdentity,
) -> bool {
    peers.hard_hard_direct_pair_is_current(identity).await
        && udp
            .hard_hard_socket_identity_has_authenticated_evidence(identity)
            .await
}

/// An authenticated Hard↔Hard winner may reach the encrypted validation
/// worker just after the short rendezvous sweep expires. Keep that exact
/// socket alive until the normal bounded session cleanup gets a chance to see
/// the Direct commit; a winner with no socket-local authenticated evidence is
/// still cleaned immediately by the caller.
async fn hard_hard_authenticated_winner_for_cleanup(
    udp: &UdpTransport,
    peers: &PeerManager,
    peer_id: &str,
    session_token: &str,
) -> Option<crate::peer::HardHardFreshSocketIdentity> {
    let winner = peers
        .hard_hard_winner_for_token(peer_id, session_token)
        .await?;
    let identity = peers
        .hard_hard_fresh_socket_for_token(peer_id, session_token)
        .await?;
    if identity.socket_index != winner
        || !peers.hard_hard_session_identity_is_current(&identity).await
        || !udp
            .hard_hard_socket_identity_has_authenticated_evidence(&identity)
            .await
    {
        return None;
    }
    Some(identity)
}

async fn hard_hard_authenticated_socket_for_cleanup(
    udp: &UdpTransport,
    peers: &PeerManager,
    identity: &crate::peer::HardHardFreshSocketIdentity,
) -> bool {
    peers.hard_hard_session_identity_is_current(identity).await
        && udp
            .hard_hard_socket_identity_has_authenticated_evidence(identity)
            .await
}

fn spawn_hard_hard_session_cleanup(
    udp: UdpTransport,
    peers: Arc<PeerManager>,
    descriptor: HardHardCleanupDescriptor,
) -> HardHardCleanupCompletion {
    spawn_hard_hard_session_cleanup_with_owner(udp, peers, descriptor, None)
}

fn spawn_hard_hard_session_cleanup_with_owner(
    udp: UdpTransport,
    peers: Arc<PeerManager>,
    descriptor: HardHardCleanupDescriptor,
    cleanup_owner: Option<PunchSessionPermit>,
) -> HardHardCleanupCompletion {
    let completion = HardHardCleanupCompletion::new();
    let watcher_completion = completion.clone();
    tokio::spawn(async move {
        // Keep the exact punch-dedup record occupied until this cleanup task
        // has completed both the token-scoped UDP cleanup and the ledger
        // removal. This closes the window in which a peer-reflexive worker
        // could otherwise claim a lower-priority ordinary punch after the
        // Hard↔Hard worker released its short-lived permit.
        let _completion_guard = HardHardCleanupCompletionGuard(watcher_completion);
        let _cleanup_owner = cleanup_owner;
        if !peers
            .hard_hard_claim_cleanup_owner(
                &descriptor.peer_id,
                &descriptor.session_id,
                &descriptor.session_token,
            )
            .await
        {
            return;
        }

        let expiry_woke = if descriptor.cancellation.is_cancelled() {
            false
        } else {
            let delay = descriptor.expires_at_ms.saturating_sub(hard_hard_now_ms());
            tokio::select! {
                biased;
                _ = descriptor.cancellation.cancelled() => false,
                _ = sleep(Duration::from_millis(delay)) => true,
            }
        };
        let snapshot = peers
            .hard_hard_session_snapshot_for_cleanup(
                &descriptor.peer_id,
                &descriptor.session_id,
                &descriptor.session_token,
            )
            .await;
        let current_socket = snapshot
            .as_ref()
            .map(|record| record.fresh_socket.clone())
            .unwrap_or_else(|| descriptor.fresh_socket.clone());
        let retain_fresh_socket = expiry_woke
            && snapshot.as_ref().is_some_and(|record| {
                record.state != crate::peer::HardHardSessionState::Retiring
                    && !record.cancellation.is_cancelled()
            })
            && !descriptor.cancellation.is_cancelled()
            && hard_hard_exact_direct_socket_is_current_for_cleanup(&udp, &peers, &current_socket)
                .await;

        // The ledger is retired before any UDP cleanup await. This is the
        // completion-fence boundary: no admission/fence query can revive the
        // session, while the descriptor and token still own cleanup.
        let _ = peers
            .hard_hard_retire_session(
                &descriptor.peer_id,
                &descriptor.session_id,
                &descriptor.session_token,
            )
            .await;
        #[cfg(test)]
        peers
            .pause_hard_hard_cleanup_for_test(
                &descriptor.peer_id,
                &descriptor.session_id,
                &descriptor.session_token,
            )
            .await;

        if retain_fresh_socket {
            udp.detach_hard_hard_sockets_for_token(
                &descriptor.peer_id,
                &descriptor.session_token,
                Some(current_socket.socket_index),
                "hard_hard_session_expired_losers",
            )
            .await;
        } else {
            udp.detach_hard_hard_sockets_for_token(
                &descriptor.peer_id,
                &descriptor.session_token,
                None,
                "hard_hard_session_expired",
            )
            .await;
            udp.detach_hard_hard_socket_if_identity(&current_socket, "hard_hard_session_expired")
                .await;
            if current_socket != descriptor.fresh_socket {
                udp.detach_hard_hard_socket_if_identity(
                    &descriptor.fresh_socket,
                    "hard_hard_session_expired",
                )
                .await;
            }
        }
        udp.clear_hard_hard_pending_probes_for_token(
            &descriptor.peer_id,
            &descriptor.session_token,
            retain_fresh_socket.then_some(current_socket.socket_index),
        )
        .await;
        let _ = peers
            .hard_hard_complete_session_cleanup(
                &descriptor.peer_id,
                &descriptor.session_id,
                &descriptor.session_token,
            )
            .await;
        #[cfg(test)]
        peers.signal_hard_hard_cleanup_completed_for_test(
            &descriptor.peer_id,
            &descriptor.session_id,
            &descriptor.session_token,
        );
    });
    completion
}
