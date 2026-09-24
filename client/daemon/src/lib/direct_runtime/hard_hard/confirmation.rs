/// The single Hard↔Hard success proof. Peer-global Direct is only one input:
/// the current generation/profile candidate pair must select the expected
/// local endpoint, and the exact token-tagged dynamic socket must be the
/// affinity pin with authenticated evidence of its own. The live punch owner
/// is deliberately not required after this proof: committing Direct ends the
/// recovery epoch and cancels that owner as part of the same transaction.
async fn hard_hard_exact_direct_confirmation_is_current(
    udp: &UdpTransport,
    peers: &PeerManager,
    identity: &crate::peer::HardHardFreshSocketIdentity,
) -> bool {
    peers
        .hard_hard_direct_confirmation_is_current(identity)
        .await
        && udp
            .hard_hard_socket_identity_has_authenticated_evidence(identity)
            .await
}

/// Wait for the existing Direct commit sequence, then require the exact
/// Hard↔Hard socket proof.  A Direct transition on another socket terminates
/// immediately; a matching manager commit gets a short bounded opportunity for
/// the ACK transaction to finish its affinity adoption under the same epoch
/// fence.
async fn hard_hard_wait_for_exact_direct_confirmation(
    udp: &UdpTransport,
    peers: &PeerManager,
    session: &PunchSessionPermit,
    identity: &crate::peer::HardHardFreshSocketIdentity,
    from_commit_seq: Option<u64>,
) -> bool {
    let deadline = Instant::now() + HARD_HARD_DIRECT_CONFIRMATION_GRACE;
    loop {
        let commit_advanced = peers.direct_commit_seq_sync(&identity.peer_id) != from_commit_seq;
        let manager_pair_matches = peers.direct_commit_pair_matches_sync(identity);
        if commit_advanced
            && manager_pair_matches
            && udp
                .hard_hard_socket_identity_has_authenticated_evidence(identity)
                .await
        {
            return true;
        }

        let session_current = peers
            .hard_hard_session_identity_is_current_for_confirmation(identity)
            .await;
        if session.is_cancelled() || !session_current {
            return false;
        }

        // A peer-global Direct commit that selected another local endpoint is
        // the competing ordinary-Direct case.  Do not wait for a misleading
        // success on the Hard↔Hard socket.
        if peers.is_direct_sync(&identity.peer_id) && !manager_pair_matches {
            return false;
        }

        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return false;
        }
        // Wait on the commit sequence notification rather than polling at a
        // fixed cadence.  The sequence is re-checked after every wake, and
        // `enable` closes the check-to-wait race because `notify_waiters`
        // itself does not retain a permit for a not-yet-enabled waiter.
        let notify = peers.direct_commit_notify();
        let notified = notify.notified();
        tokio::pin!(notified);
        notified.as_mut().enable();
        tokio::select! {
            // Direct commit itself ends the recovery epoch and cancels this
            // owner. Re-enter the loop once so the exact commit/socket proof
            // wins that expected completion race; every other cancellation
            // still fails the checks above and returns false.
            _ = session.cancelled() => {}
            _ = notified => {}
            _ = sleep(remaining) => return false,
        }
    }
}
