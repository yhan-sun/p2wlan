use super::{
    mpsc, oneshot, sleep, Arc, DaemonError, Duration, PeerManager, RelayInboundEnd, RelayMessage,
    RelayTicketCache, RelayTransport, RELAY_TICKET_RENEWAL_MARGIN_SECS, RELAY_TICKET_RENEWAL_RETRY,
};

/// Time until the renewal deadline: `expiry - margin` (clamped to at least
/// 1s so the renewal task always has a bounded wait and never spins).
pub(crate) fn relay_renewal_deadline(expires_at_unix: i64, now_unix: i64) -> Duration {
    let remaining = expires_at_unix.saturating_sub(now_unix);
    Duration::from_secs(
        remaining
            .saturating_sub(RELAY_TICKET_RENEWAL_MARGIN_SECS)
            .max(1) as u64,
    )
}

/// Result of a renewal attempt: the replacement transport (with its new
/// ticket metadata attached) plus its inbound receiver.
pub(super) type RelayRenewalResult = Option<(RelayTransport, mpsc::Receiver<RelayMessage>)>;

/// An armed make-before-break renewal.
pub(super) struct ArmedRelayRenewal {
    /// Result of the renewal task (awaited BY REFERENCE when the select branch
    /// polls it, so an un-selected branch future never consumes the receiver).
    pub(super) result: Option<oneshot::Receiver<RelayRenewalResult>>,
    /// Set by the renewal task immediately BEFORE it connects the replacement
    /// transport.  The supervisor uses it to tell a genuine connection end
    /// apart from the hub's newest-wins close of the superseded connection:
    /// an EOF that arrives while the renewal is already connecting is held
    /// until the renewal resolves instead of aborting a successful handoff.
    pub(super) connecting: Arc<std::sync::atomic::AtomicBool>,
    /// Abort the detached ticket-fetch/connect task when the supervisor moves
    /// to a new network generation or drops the renewal for any other reason.
    /// Without this handle a route change could leave a stale task running
    /// long enough to register an orphaned newest-wins relay connection.
    pub(super) abort_handle: Option<tokio::task::AbortHandle>,
}

impl Drop for ArmedRelayRenewal {
    fn drop(&mut self) {
        if let Some(abort_handle) = self.abort_handle.take() {
            abort_handle.abort();
        }
    }
}

/// Await an optional inbound-end oneshot receiver (used inside `tokio::select!`
/// where the branch must be a future): `None` when no receiver is armed.
pub(super) async fn relay_oneshot_wait(
    rx: &mut Option<oneshot::Receiver<RelayInboundEnd>>,
) -> Option<std::result::Result<RelayInboundEnd, oneshot::error::RecvError>> {
    match rx {
        Some(receiver) => Some(receiver.await),
        None => None,
    }
}

/// Extract the close-reason label from a transport-close error produced by
/// [`RelayTransport::run_inbound`] for `RelayMessage::Closed` (the message
/// format is `relay {endpoint} connection closed; reason={label}`), or `None`
/// for any other failure.  The supervisor uses this to attribute the deferred
/// close diagnostics only to GENUINE ends of the current connection.
pub(super) fn relay_close_reason_label_from_error(error: &DaemonError) -> Option<String> {
    let message = error.to_string();
    let marker = "closed; reason=";
    let label = message
        .rfind(marker)
        .map(|idx| message[idx + marker.len()..].trim())
        .filter(|label| !label.is_empty())?;
    Some(label.to_string())
}

/// Await the armed renewal result (see [`ArmedRelayRenewal`]) by reference,
/// without taking the receiver out of the armed struct.  `tokio::select!` may
/// poll this branch future and then drop it un-selected when another branch
/// (e.g. an inbound EOF) wins the same round; taking the receiver at poll time
/// would drop the pending renewal result and leave `armed.result` consumed,
/// tripping the caller's next round.  Awaiting by reference means a dropped
/// branch future loses nothing and the receiver stays re-pollable.
pub(super) async fn relay_renewal_wait(
    renewal: &mut Option<ArmedRelayRenewal>,
) -> Option<std::result::Result<RelayRenewalResult, oneshot::error::RecvError>> {
    match renewal {
        Some(armed) => {
            let receiver = armed.result.as_mut().expect("renewal result missing");
            Some(receiver.await)
        }
        None => None,
    }
}

/// Implementation of the make-before-break renewal task.  A free function so
/// the supervisor can hand a `'static`-captured closure (cloned configuration,
/// no `&self` borrow) to the generation-tagged connection supervisor.
///
/// The task sleeps until `expiry - margin`, then — after verifying that its
/// connection generation is still the current one — fetches a fresh ticket and
/// connects the replacement transport CONCURRENTLY with the current
/// connection's inbound drain, so the swap (which the caller performs
/// atomically) never produces a data-path gap.  A fetch or connect failure
/// sends `None` and leaves the current connection untouched; the supervisor
/// then falls back to its existing reconnect path at expiry.
///
/// The replacement transport carries the NEW ticket metadata (audience,
/// region, expires-at) attached before it is returned, so the next renewal is
/// scheduled from the replacement's own deadline instead of being lost after
/// the first swap.
///
/// Returns `None` when the connection has no ticket (legacy relay).
#[allow(clippy::too_many_arguments)]
pub(super) async fn spawn_relay_renewal_task_impl(
    ticket_cache: Option<Arc<RelayTicketCache>>,
    node_id: String,
    peers: Arc<PeerManager>,
    allow_insecure_plaintext: bool,
    ca_cert_path: Option<String>,
    generation_token: Arc<std::sync::atomic::AtomicU64>,
    expected_generation: u64,
    transport: RelayTransport,
) -> Option<ArmedRelayRenewal> {
    let (audience, region, expires_at_unix) = transport.ticket_expiry()?;
    let ticket_cache = ticket_cache?;
    let endpoint = transport.endpoint().to_string();
    let region = region.clone();
    let (tx, rx) = oneshot::channel();
    let connecting = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let connecting_task = connecting.clone();
    let task = tokio::spawn(async move {
        // Sleep until the renewal deadline (expiry - margin), re-checking
        // in bounded steps so the wait always ends before the server's
        // expiry close.
        loop {
            let now_unix = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs() as i64;
            let step = relay_renewal_deadline(expires_at_unix, now_unix);
            if step <= RELAY_TICKET_RENEWAL_RETRY {
                break;
            }
            sleep(RELAY_TICKET_RENEWAL_RETRY).await;
        }
        // The connection this renewal belongs to may have ended (a real
        // failure or a superseding handoff) while the renewal was sleeping.
        // Abort instead of registering an orphaned replacement that would
        // "newest-wins" over the supervisor's current link.
        if generation_token.load(std::sync::atomic::Ordering::SeqCst) != expected_generation {
            let _ = tx.send(None);
            return;
        }
        connecting_task.store(true, std::sync::atomic::Ordering::SeqCst);
        // Fetch a fresh ticket and connect the replacement; the caller
        // swaps it in only after this succeeded, so the old connection
        // keeps serving until the new one is ready.  The replacement
        // keeps the ticket expiry metadata attached so the NEXT renewal
        // is scheduled from the new deadline.
        let result = async {
            let (ticket, expires_at) =
                ticket_cache.refresh_ticket(&audience, &region).await.ok()?;
            if generation_token.load(std::sync::atomic::Ordering::SeqCst) != expected_generation {
                return None;
            }
            let (transport, relay_rx) = RelayTransport::connect_secure(
                &endpoint,
                &region,
                &node_id,
                peers,
                Some(ticket),
                allow_insecure_plaintext,
                ca_cert_path,
            )
            .await
            .ok()?;
            if generation_token.load(std::sync::atomic::Ordering::SeqCst) != expected_generation {
                transport.abort_writer();
                return None;
            }
            Some((
                transport.with_ticket_metadata(&audience, &region, expires_at),
                relay_rx,
            ))
        }
        .await;
        let _ = tx.send(result);
    });
    Some(ArmedRelayRenewal {
        result: Some(rx),
        connecting,
        abort_handle: Some(task.abort_handle()),
    })
}
