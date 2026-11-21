//! Healthy idle, RTT spike and post-receive adoption queue on one real consent.
//! No application request, native encrypted ACK or new health authority.

use super::*;
use futures_util::FutureExt;
use tokio::sync::{oneshot, OwnedMutexGuard};
use tokio::task::JoinHandle;
use tokio::time::{timeout_at, Instant as TokioInstant};

#[derive(Clone, Copy)]
struct ConsentReply {
    nonce: [u8; 8],
    ack_hold: Duration,
}

struct AdoptionQueueObservation {
    nonce: [u8; 8],
    post_rx_hold: Duration,
    released_at: Instant,
    rx_before: UdpProbeRxSnapshot,
    rx_held: UdpProbeRxSnapshot,
    rx_after: UdpProbeRxSnapshot,
    pending_before: PendingProbe,
    pending_held: PendingProbe,
    current_match: bool,
    pending_consumed: bool,
    connection: crate::peer::PeerConnection,
    selection: crate::peer::PathSelection,
}

#[derive(Default)]
struct IdleOwners {
    remote: Option<Arc<UdpSocket>>,
    udp: Option<UdpTransport>,
    inbound: Option<JoinHandle<crate::error::Result<()>>>,
    responder: Option<JoinHandle<std::result::Result<ConsentReply, String>>>,
    adoption: Option<OwnedMutexGuard<()>>,
}

impl IdleOwners {
    fn abort_workers(&self) {
        if let Some(task) = self.inbound.as_ref() {
            task.abort();
        }
        if let Some(task) = self.responder.as_ref() {
            task.abort();
        }
    }
}

impl Drop for IdleOwners {
    fn drop(&mut self) {
        drop(self.adoption.take());
        // Dropping the whole test is abort protection, never a claimed join.
        self.abort_workers();
    }
}

async fn collect_idle_worker<T>(
    slot: &mut Option<JoinHandle<T>>,
    end: TokioInstant,
) -> (bool, Option<T>, Option<String>) {
    let Some(task) = slot.as_mut() else {
        return (true, None, None); // No task acquired in a partial setup.
    };
    let result = match timeout_at(end, task).await {
        Ok(result) => result,
        Err(_) => return (false, None, Some("original worker join deadline".into())),
    };
    drop(slot.take()); // Consume Ready before handling any JoinError.
    match result {
        Ok(value) => (true, Some(value), None),
        Err(error) if error.is_cancelled() => (true, None, None),
        Err(error) => (true, None, Some(error.to_string())),
    }
}

#[tokio::test]
async fn c02_idle_application_healthy_consent_preserves_actual_selector() {
    assert_healthy_consent_preserves_actual_selector(Duration::ZERO, Duration::ZERO).await;
}

#[tokio::test]
async fn c02_single_consent_rtt_spike_preserves_actual_selector() {
    assert_healthy_consent_preserves_actual_selector(Duration::from_millis(60), Duration::ZERO)
        .await;
}

#[tokio::test]
async fn c02_received_consent_ack_adoption_queue_preserves_actual_selector() {
    assert_healthy_consent_preserves_actual_selector(Duration::ZERO, Duration::from_millis(60))
        .await;
}

async fn observe_original_adoption_queue(
    udp: &UdpTransport,
    peers: &PeerManager,
    endpoint: SocketAddr,
    rx_before: UdpProbeRxSnapshot,
    reply: oneshot::Receiver<ConsentReply>,
    adoption: &mut Option<OwnedMutexGuard<()>>,
    queue_delay: Duration,
) -> std::result::Result<AdoptionQueueObservation, String> {
    let reply = reply
        .await
        .map_err(|_| "original ACK reply channel closed")?;
    // Only one original responder/nonce can advance this fresh transport's
    // aggregate counter. The original reader increments it before adoption.
    let rx_seen = loop {
        let snapshot = udp.probe_rx_snapshot().await;
        if snapshot.legacy_probe_acks_observed > rx_before.legacy_probe_acks_observed {
            break snapshot;
        }
        tokio::task::yield_now().await;
    };
    if adoption.is_none()
        || rx_seen.legacy_probe_acks_observed != rx_before.legacy_probe_acks_observed + 1
        || rx_seen.legacy_probe_acks_unmatched != rx_before.legacy_probe_acks_unmatched
        || rx_seen.probe_acks_received != rx_before.probe_acks_received
    {
        return Err("original single ACK was not waiting before adoption".into());
    }
    let pending_before = udp
        .pending_probes
        .lock()
        .await
        .get(&reply.nonce)
        .cloned()
        .ok_or("received original ACK lost its pending nonce before hold")?;
    let generation = peers.current_network_generation_sync();
    let remote_epoch = peers
        .current_remote_candidate_epoch("peer-b")
        .await
        .ok_or("original peer candidate epoch missing")?;
    let cleanup_epoch = udp.peer_probe_cleanup_epoch("peer-b").await;
    let commit_seq = peers
        .direct_commit_seq_sync("peer-b")
        .ok_or("original peer Direct commit missing")?;
    let current_match = legacy_ack_matches_pending(
        &pending_before,
        endpoint,
        generation,
        remote_epoch,
        0,
        cleanup_epoch,
        commit_seq,
    ) && pending_before.peer_id.as_deref() == Some("peer-b")
        && pending_before.endpoint == endpoint
        && pending_before.purpose == PendingProbePurpose::ConsentCheck
        && !pending_before.is_expired(Instant::now());
    if !current_match {
        return Err("received original ACK does not match its current pending consent".into());
    }
    // Begin the sole configured hold only after actual typed RX and exact
    // pending matching. No new worker, send, deadline or RTT injection.
    let held_at = Instant::now();
    tokio::time::sleep(queue_delay).await;
    let pending_held = udp
        .pending_probes
        .lock()
        .await
        .get(&reply.nonce)
        .cloned()
        .ok_or("received original ACK lost its nonce while adoption was held")?;
    let rx_held = udp.probe_rx_snapshot().await;
    let connection = peers
        .get_connection("peer-b")
        .await
        .ok_or("original queued peer missing")?;
    let selection = peers.select_path_for_data("peer-b", true, false).await;
    let released_at = Instant::now();
    let post_rx_hold = released_at.duration_since(held_at);
    drop(adoption.take());
    Ok(AdoptionQueueObservation {
        nonce: reply.nonce,
        post_rx_hold,
        released_at,
        rx_before,
        rx_held,
        rx_after: UdpProbeRxSnapshot::default(),
        pending_before,
        pending_held,
        current_match,
        pending_consumed: false,
        connection,
        selection,
    })
}

async fn assert_healthy_consent_preserves_actual_selector(
    ack_delay: Duration,
    queue_delay: Duration,
) {
    let end = TokioInstant::now() + Duration::from_secs(2);
    let work_end = end - Duration::from_secs(1);
    let peers = peer_manager();
    let bursts = Arc::new(ProbeBurstCaptureForTest::new());
    let mut owners = IdleOwners::default();
    let mut remote_addr = None;
    let mut local_addr = None;
    let mut remote_weak = None;
    let mut primary = None;
    let mut ipv6 = None;

    let body = std::panic::AssertUnwindSafe(async {
        owners.remote = Some(Arc::new(
            UdpSocket::bind("127.0.0.1:0")
                .await
                .map_err(|e| e.to_string())?,
        ));
        let remote = owners.remote.as_ref().unwrap();
        remote_weak = Some(Arc::downgrade(remote));
        let endpoint = remote.local_addr().map_err(|e| e.to_string())?;
        remote_addr = Some(endpoint);
        peers
            .add_peer(&peer("peer-b", "10.20.0.2", Some(endpoint)))
            .await;
        peers
            .record_direct_probe_success_with_latency(
                "peer-b",
                endpoint,
                Some(Duration::from_millis(5)),
            )
            .await;
        peers.record_direct_success("peer-b", Some(endpoint)).await;
        let before = peers
            .get_connection("peer-b")
            .await
            .ok_or("missing original idle peer")?;
        let selection_before = peers.select_path_for_data("peer-b", true, false).await;
        owners.udp = Some(
            UdpTransport::bind("127.0.0.1:0".parse().unwrap(), peers.clone())
                .await
                .map_err(|e| e.to_string())?,
        );
        let udp = owners.udp.as_mut().unwrap();
        udp.probe_burst_capture_for_test = Some(bursts.clone());
        primary = Some(Arc::downgrade(&udp.socket));
        ipv6 = udp.ipv6_socket.as_ref().map(Arc::downgrade);
        let source_endpoint = udp.local_addr().map_err(|e| e.to_string())?;
        local_addr = Some(source_endpoint);
        let queue_setup = if queue_delay.is_zero() {
            None
        } else {
            owners.adoption = Some(udp.lock_peer_adoption_for_direct_validation("peer-b").await);
            let rx_before = udp.probe_rx_snapshot().await;
            let (reply_tx, reply_rx) = oneshot::channel();
            Some((rx_before, reply_tx, reply_rx))
        };
        let (reply_tx, queue_input) = match queue_setup {
            Some((before, tx, rx)) => (Some(tx), Some((before, rx))),
            None => (None, None),
        };
        let (tx, _rx) = mpsc::channel(1);
        let inbound = udp.clone();
        // Each actual spawn result enters its external owner before an await.
        owners.inbound = Some(tokio::spawn(inbound.run_inbound(tx)));
        let responder_socket = remote.clone();
        owners.responder = Some(tokio::spawn(async move {
            let mut bytes = [0u8; 256];
            let (len, source) = responder_socket
                .recv_from(&mut bytes)
                .await
                .map_err(|e| e.to_string())?;
            let received_at = Instant::now();
            let probe = decode_punch_packet(&bytes[..len]).ok_or("invalid actual idle consent")?;
            if source != source_endpoint || probe.kind != PunchPacketKind::Punch {
                return Err("actual idle consent source/kind mismatch".into());
            }
            // The sole delayed ACK follows an actual receive, never an RTT
            // injection. Reliability copies keep their original scheduling.
            if !ack_delay.is_zero() {
                tokio::time::sleep(ack_delay).await;
            }
            let ack = build_punch_ack(probe.nonce);
            let ack_hold = received_at.elapsed();
            let accepted = responder_socket
                .send_to(&ack, source_endpoint)
                .await
                .map_err(|e| e.to_string())?;
            if accepted != ack.len() {
                return Err("actual idle consent ACK short send".into());
            }
            let reply = ConsentReply {
                nonce: probe.nonce,
                ack_hold,
            };
            if let Some(sender) = reply_tx {
                sender
                    .send(reply)
                    .map_err(|_| "original ACK observer closed")?;
            }
            Ok(reply)
        }));
        // This is the original matching-consent wait. No application traffic
        // or extra idle sleep supplies a synthetic success observation.
        let mut queued = if let Some((rx_before, reply_rx)) = queue_input {
            let (_, queued) = tokio::join!(
                udp.run_keepalive_round(Duration::from_millis(500)),
                observe_original_adoption_queue(
                    udp,
                    &peers,
                    endpoint,
                    rx_before,
                    reply_rx,
                    &mut owners.adoption,
                    queue_delay,
                )
            );
            Some(queued?)
        } else {
            udp.run_keepalive_round(Duration::from_millis(500)).await;
            None
        };
        let _ack_transaction = udp.lock_peer_adoption_for_direct_validation("peer-b").await;
        if let Some(queued) = queued.as_mut() {
            queued.rx_after = udp.probe_rx_snapshot().await;
            queued.pending_consumed = !udp.pending_probes.lock().await.contains_key(&queued.nonce);
        }
        let connection = peers
            .get_connection("peer-b")
            .await
            .ok_or("missing idle peer after original ACK adoption")?;
        let selection = peers.select_path_for_data("peer-b", true, false).await;
        Ok::<_, String>((before, selection_before, connection, selection, queued))
    })
    .catch_unwind();
    let body_result = timeout_at(work_end, body).await;

    // A partial/failed timed body must release the original guard before any
    // worker cancellation or actual join, within the same unchanged end.
    drop(owners.adoption.take());
    let held = usize::from(owners.inbound.is_some()) + usize::from(owners.responder.is_some());
    owners.abort_workers();
    let (burst_count, bursts_joined) = bursts.abort_and_join_until(end).await;
    let (inbound_joined, inbound_result, inbound_error) =
        collect_idle_worker(&mut owners.inbound, end).await;
    let (responder_joined, responder_result, responder_error) =
        collect_idle_worker(&mut owners.responder, end).await;
    let had_udp = owners.udp.is_some();
    let had_remote = owners.remote.is_some();
    drop(owners.udp.take());
    drop(owners.remote.take());
    // run_inbound owns its original reader JoinSet. Its dropped children are
    // not exposed as independent handles; observe their actual socket release
    // within the same end without claiming extra native joins.
    let sockets_released = timeout_at(end, async {
        while primary.as_ref().is_some_and(|w| w.upgrade().is_some())
            || ipv6.as_ref().is_some_and(|w| w.upgrade().is_some())
            || remote_weak.as_ref().is_some_and(|w| w.upgrade().is_some())
        {
            tokio::task::yield_now().await;
        }
    })
    .await
    .is_ok();
    let local_rebound = if let Some(address) = local_addr {
        Some(timeout_at(end, UdpSocket::bind(address)).await)
    } else {
        None
    };
    let remote_rebound = if let Some(address) = remote_addr {
        Some(timeout_at(end, UdpSocket::bind(address)).await)
    } else {
        None
    };
    let ports_reclaimed = (!had_udp || matches!(&local_rebound, Some(Ok(Ok(_)))))
        && (!had_remote || matches!(&remote_rebound, Some(Ok(Ok(_)))));
    drop(local_rebound);
    drop(remote_rebound);

    assert!(inbound_joined && responder_joined && bursts_joined);
    assert!(
        inbound_error.is_none() && responder_error.is_none(),
        "original idle worker errors after cleanup: {inbound_error:?}/{responder_error:?}"
    );
    assert!(sockets_released && ports_reclaimed);
    let (before, selection_before, observed, selection, queued) = match body_result {
        Ok(Ok(Ok(value))) => value,
        Ok(Ok(Err(error))) => panic!("original idle consent body failed after cleanup: {error}"),
        Ok(Err(panic)) => std::panic::resume_unwind(panic),
        Err(_) => panic!("original idle consent body exceeded work end after cleanup"),
    };
    assert_eq!(held, 2);
    assert_eq!(burst_count, 1, "one original legacy consent producer");
    assert!(inbound_result.is_none() || matches!(inbound_result, Some(Ok(()))));
    let Some(Ok(reply)) = responder_result else {
        panic!("original responder must actually receive the probe and fully send its ACK");
    };
    assert!(reply.ack_hold >= ack_delay);
    assert!(reply.ack_hold < Duration::from_millis(500));
    let endpoint = remote_addr.expect("completed body must retain original endpoint");
    let before_pair = before
        .candidate_pairs
        .iter()
        .find(|pair| pair.remote_endpoint == endpoint)
        .expect("original healthy pair before consent");
    let pair = observed
        .candidate_pairs
        .iter()
        .find(|pair| pair.remote_endpoint == endpoint)
        .expect("original pair after ACK adoption");
    assert_eq!(before.state, ConnectionState::Direct);
    assert_eq!(before_pair.state, crate::peer::CandidatePairState::Selected);
    assert_eq!(before.direct_health.latency_ms, Some(5));
    assert_eq!(before_pair.rtt_ms, Some(5));
    assert_eq!(observed.state, ConnectionState::Direct);
    assert_eq!(
        observed.direct_health.success_count,
        before.direct_health.success_count + 1,
        "one original matched health sample"
    );
    assert_eq!(pair.success_count, before_pair.success_count + 1);
    assert_eq!(observed.direct_health.consecutive_failures, 0);
    assert_eq!(pair.consecutive_failures, 0);
    assert_eq!(
        observed.direct_health.failure_count,
        before.direct_health.failure_count
    );
    assert_eq!(pair.failure_count, before_pair.failure_count);
    assert!(observed.direct_health.last_error_code.is_none());
    assert!(pair.last_error_code.is_none());
    assert_eq!(pair.state, crate::peer::CandidatePairState::Selected);
    assert_eq!(pair.local_endpoint, local_addr);
    assert_eq!(
        selection_before.path,
        Some(crate::peer::NetworkPath::Direct)
    );
    assert_eq!(selection_before.direct_endpoint, Some(endpoint));
    assert!(selection_before.direct_confirmed);
    assert_eq!(selection.path, selection_before.path);
    assert_eq!(selection.direct_endpoint, selection_before.direct_endpoint);
    assert!(selection.direct_confirmed);
    let latency_ms = observed
        .direct_health
        .latency_ms
        .expect("original matched consent must publish its real RTT");
    assert_eq!(pair.rtt_ms, Some(latency_ms));
    assert!(u128::from(latency_ms) >= ack_delay.as_millis() && latency_ms < 500);
    if !ack_delay.is_zero() {
        assert!(Some(latency_ms) > before.direct_health.latency_ms);
    }
    if let Some(queued) = queued {
        assert!(!queue_delay.is_zero() && ack_delay.is_zero());
        assert_eq!(queued.nonce, reply.nonce);
        assert!(queued.current_match && queued.pending_consumed);
        assert!(queued.post_rx_hold >= queue_delay);
        assert!(queued.post_rx_hold < Duration::from_millis(500));
        assert_eq!(queued.rx_before.legacy_probe_acks_observed, 0);
        assert_eq!(queued.rx_before.legacy_probe_acks_unmatched, 0);
        assert_eq!(queued.rx_before.probe_acks_received, 0);
        assert_eq!(queued.rx_held.legacy_probe_acks_observed, 1);
        assert_eq!(queued.rx_held.legacy_probe_acks_unmatched, 0);
        assert_eq!(queued.rx_held.probe_acks_received, 0);
        assert_eq!(queued.rx_after.legacy_probe_acks_observed, 1);
        assert_eq!(queued.rx_after.legacy_probe_acks_unmatched, 0);
        assert_eq!(queued.rx_after.probe_acks_received, 1);
        assert_eq!(queued.pending_before.sent_at, queued.pending_held.sent_at);
        assert_eq!(
            queued.pending_before.expires_at,
            queued.pending_held.expires_at
        );
        assert_eq!(
            queued.pending_before.generation,
            queued.pending_held.generation
        );
        assert_eq!(
            queued.pending_before.remote_candidate_epoch,
            queued.pending_held.remote_candidate_epoch
        );
        assert_eq!(
            queued.pending_before.cleanup_epoch,
            queued.pending_held.cleanup_epoch
        );
        assert_eq!(
            queued.pending_before.direct_commit_seq,
            queued.pending_held.direct_commit_seq
        );
        assert_eq!(
            queued.pending_before.socket_index,
            queued.pending_held.socket_index
        );
        assert_eq!(queued.pending_held.local_endpoint, local_addr);
        assert!(!queued.pending_held.is_expired(queued.released_at));
        assert_eq!(queued.connection.state, ConnectionState::Direct);
        assert_eq!(
            queued.connection.direct_health.success_count,
            before.direct_health.success_count
        );
        assert_eq!(
            queued.connection.direct_health.failure_count,
            before.direct_health.failure_count
        );
        assert_eq!(queued.connection.direct_health.consecutive_failures, 0);
        assert_eq!(
            queued.connection.direct_health.latency_ms,
            before.direct_health.latency_ms
        );
        let held_pair = queued
            .connection
            .candidate_pairs
            .iter()
            .find(|pair| pair.remote_endpoint == endpoint)
            .expect("original selected pair while actual ACK waits");
        assert_eq!(held_pair.state, crate::peer::CandidatePairState::Selected);
        assert_eq!(held_pair.success_count, before_pair.success_count);
        assert_eq!(held_pair.failure_count, before_pair.failure_count);
        assert_eq!(held_pair.consecutive_failures, 0);
        assert_eq!(held_pair.rtt_ms, before_pair.rtt_ms);
        assert_eq!(queued.selection.path, selection_before.path);
        assert_eq!(
            queued.selection.direct_endpoint,
            selection_before.direct_endpoint
        );
        assert!(queued.selection.direct_confirmed);
        assert!(u128::from(latency_ms) >= queue_delay.as_millis());
        assert!(u128::from(latency_ms) >= queued.post_rx_hold.as_millis());
    } else {
        assert!(queue_delay.is_zero());
    }
    assert!(observed
        .direct_events
        .iter()
        .any(|event| event.stage == "consent_ack_received"));
    assert!(!observed
        .direct_events
        .iter()
        .any(|event| event.stage == "consent_timeout"));
}
