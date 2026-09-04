// ============================================================
// Encrypted overlay validation loop (independent harness only)
// ============================================================
//
// When `config.network.validate_overlay` is enabled (daemon flag
// `--validate-overlay`, off by default), the daemon runs the REAL production
// dataplane over an in-memory MockTunDevice and this loop injects business
// payloads into that dataplane.  Every injected payload is:
//
//   1. routed by the production DataPlane (record_sent),
//   2. encrypted by the production WireGuardTransport session,
//   3. emitted through the production outbound path selector, which sends
//      the encrypted datagram over the DIRECT UDP socket when the peer is
//      Direct, or over the relay once RelayPeerConfirmed,
//   4. decrypted on the far side by the production WireGuard inbound path,
//   5. delivered to the production DataPlane inbound path (record_received),
//      which writes it to the mock TUN,
//   6. read back by this loop and verified (magic, checksum, nonce/seq).
//
// The reply is echoed back through the same pipeline, so a single round
// proves bidirectional real encrypted overlay traffic.  This is NOT a
// test-only plaintext bypass: there is no path from this loop to the UDP
// socket other than DataPlane -> WireGuard -> outbound selector.
//
// AVAILABILITY EVIDENCE (relay-first):
// - Every inbound overlay payload is forwarded from the WireGuard inbound
//   path WITH its REAL relay/direct ingress metadata (the `OverlayIngressEvent`
//   side channel).  The loop never back-infers the path from `active_path`.
// - An echo is only accepted as `first_usable` evidence when its nonce matches
//   a nonce THIS daemon actually sent to the SAME peer, within the validity
//   window — a bounded outbound nonce registry, never a bare "transport-ready"
//   signal.
// - `first_usable_path` is emitted per peer + generation (scoped timeline
//   first-event), and the relay-ready -> usable delta is computed on the
//   daemon's own monotonic clock and reported in the event detail.  The
//   harness only SUMS the two ends' deltas; it never subtracts wall clocks
//   across machines.

use std::collections::VecDeque;

use p2pnet_tun::mock::MockTunController;
use crate::transport::{OverlayIngress, OverlayIngressEvent};

/// Overlay payload magic ("P2WLOV"), shared with the transport-layer
/// pre-filter so the ingress feed forwards exactly these payloads.
const OVERLAY_MAGIC: &[u8] = crate::OVERLAY_PAYLOAD_MAGIC;
/// Overlay payload marker for the acceptance report.
const OVERLAY_EVIDENCE_PREFIX: &str = "overlay_payload";
/// How often the loop probes every Direct peer.
const OVERLAY_SEND_INTERVAL: Duration = Duration::from_secs(2);
/// Filler size so the IP packet looks like a small user datagram.
const OVERLAY_FILLER_BYTES: usize = 128;
/// Maximum remembered (nonce, seq) pairs for duplicate suppression.
const OVERLAY_SEEN_CAP: usize = 256;
/// Byte offset of the checksum field inside the overlay payload.
const OVERLAY_CHECKSUM_OFFSET: usize = 6 + 1 + 8 + 4;
/// Checksummed region: magic + direction + nonce + sequence (the checksum
/// field itself is excluded so the sender and the verifier compute the same
/// value).
const OVERLAY_CHECKSUM_SPAN: usize = 6 + 1 + 8 + 4;
/// Payload direction marker: `0` is a fresh request, `1` is an echo.  Only
/// fresh requests are echoed, so an echo of an echo can never loop.
const OVERLAY_DIRECTION_REQUEST: u8 = 0;
const OVERLAY_DIRECTION_ECHO: u8 = 1;
/// An echo must match a nonce this daemon actually sent (to the same peer)
/// within this validity window; a stale or never-sent nonce can never confirm
/// first usability.
const OVERLAY_NONCE_TTL: Duration = Duration::from_secs(15);
/// Bound on the outbound nonce registry (oldest evicted first).
const OVERLAY_NONCE_CAP: usize = 256;

struct OverlayStats {
    sent: u64,
    received_valid: u64,
    received_invalid: u64,
    verified_round_trips: u64,
    last_seq: u64,
}

/// One nonce this daemon sent in a fresh overlay request.
struct SentOverlayNonce {
    peer_id: String,
    generation: u64,
    sent_at: Instant,
}

/// Strict-Direct requests can arrive just before this endpoint commits its own
/// Direct state. Preserve the request until that local commit so its echo also
/// traverses Direct instead of falling back to an otherwise healthy Relay.
struct PendingOverlayEcho {
    peer_id: String,
    virtual_ip: String,
    generation: u64,
    nonce: u64,
    seq: u32,
    packet: Vec<u8>,
    queued_at: Instant,
}

/// The pending set is harness-only and bounded independently of the TUN queue.
const OVERLAY_PENDING_ECHO_CAP: usize = 256;

/// Post-first-usable burst verification state for one peer.
struct OverlayBurst {
    /// Armed once first-usable evidence exists for this peer.
    armed: bool,
    /// Nonces of the burst packets actually injected.
    nonces: Vec<u64>,
    /// Packets injected.
    sent: u64,
    /// Verified echoes received for this burst.
    received: u64,
    /// When the burst was injected (None until fired).
    fired_at: Option<Instant>,
}

/// How long a burst may wait for its echoes before being reported incomplete.
const OVERLAY_BURST_TIMEOUT: Duration = Duration::from_secs(20);

/// Fire the armed burst of one peer: inject `burst_size` fresh business
/// payloads and register every nonce (bounded registry + burst state).
#[allow(clippy::too_many_arguments)]
async fn fire_pending_bursts(
    controller: &MockTunController,
    peers: &Arc<PeerManager>,
    local_vip: &str,
    burst_size: usize,
    next_nonce: &mut u64,
    next_seq: &mut u32,
    sent_nonces: &mut HashMap<u64, SentOverlayNonce>,
    nonce_order: &mut VecDeque<u64>,
    bursts: &mut HashMap<String, OverlayBurst>,
) {
    let generation = peers.current_network_generation_sync();
    let virtual_ips: HashMap<String, String> = peers
        .committed_business_path_snapshots_sync()
        .into_iter()
        .filter(|peer| {
            peer.is_online_in_generation(generation) && peer.active_path().is_some()
        })
        .map(|peer| (peer.peer_id, peer.virtual_ip))
        .collect();
    let targets: Vec<(String, String)> = bursts
        .iter()
        .filter(|(_, burst)| burst.armed && burst.fired_at.is_none())
        .filter_map(|(peer_id, _)| {
            virtual_ips
                .get(peer_id)
                .cloned()
                .map(|vip| (peer_id.clone(), vip))
        })
        .collect();
    for (peer_id, virtual_ip) in targets {
        let mut nonces = Vec::with_capacity(burst_size);
        for _ in 0..burst_size {
            *next_nonce = next_nonce.wrapping_add(1);
            *next_seq = next_seq.wrapping_add(1);
            let payload = build_overlay_payload(OVERLAY_DIRECTION_REQUEST, *next_nonce, *next_seq);
            let Some(packet) =
                build_udp_overlay_packet(local_vip, &virtual_ip, 39286, 39287, &payload)
            else {
                continue;
            };
            let nonce = *next_nonce;
            // Register the outbound nonce BEFORE the send so a fast echo
            // cannot race ahead of the registry insert.
            sent_nonces.insert(
                nonce,
                SentOverlayNonce {
                    peer_id: peer_id.clone(),
                    generation,
                    sent_at: Instant::now(),
                },
            );
            nonce_order.push_back(nonce);
            while nonce_order.len() > OVERLAY_NONCE_CAP {
                if let Some(oldest) = nonce_order.pop_front() {
                    sent_nonces.remove(&oldest);
                }
            }
            if controller.inject(packet).await.is_ok() {
                nonces.push(nonce);
            }
        }
        if let Some(burst) = bursts.get_mut(&peer_id) {
            burst.nonces = nonces.clone();
            burst.sent = nonces.len() as u64;
            burst.fired_at = Some(Instant::now());
        }
        info!(
            event = "overlay_burst_sent",
            peer = %peer_id,
            sent = burst_size,
            injected = nonces.len(),
            "overlay_burst_sent peer={peer_id} sent={burst_size} injected={}",
            nonces.len()
        );
    }
}

/// Report bursts whose echoes did not all return within the timeout (a
/// structured failure the harness can gate on) and drop them.
fn settle_overdue_bursts(
    bursts: &mut HashMap<String, OverlayBurst>,
    timeline: &Arc<ConnectionTimeline>,
) {
    let now = Instant::now();
    let overdue: Vec<(String, u64, u64)> = bursts
        .iter()
        .filter(|(_, burst)| {
            burst
                .fired_at
                .is_some_and(|fired| now.saturating_duration_since(fired) > OVERLAY_BURST_TIMEOUT)
        })
        .map(|(peer_id, burst)| (peer_id.clone(), burst.sent, burst.received))
        .collect();
    for (peer_id, sent, received) in overdue {
        warn!(
            event = "overlay_burst_incomplete",
            peer = %peer_id,
            sent = sent,
            received = received,
            "overlay_burst_incomplete peer={peer_id} sent={sent} received={received}"
        );
        timeline.emit(
            "overlay_burst_incomplete",
            None,
            Some("overlay_burst_loss"),
            Some(format!("peer={peer_id} sent={sent} received={received}")),
        );
        bursts.remove(&peer_id);
    }
}

fn build_pending_overlay_echo(
    local_vip: &str,
    peer_id: String,
    virtual_ip: String,
    generation: u64,
    nonce: u64,
    seq: u32,
) -> Option<PendingOverlayEcho> {
    let payload = build_overlay_payload(OVERLAY_DIRECTION_ECHO, nonce, seq);
    let packet = build_udp_overlay_packet(local_vip, &virtual_ip, 39287, 39286, &payload)?;
    Some(PendingOverlayEcho {
        peer_id,
        virtual_ip,
        generation,
        nonce,
        seq,
        packet,
        queued_at: Instant::now(),
    })
}

async fn inject_pending_overlay_echo(
    controller: &MockTunController,
    echo: PendingOverlayEcho,
) {
    let PendingOverlayEcho {
        peer_id,
        virtual_ip,
        nonce,
        seq,
        packet,
        ..
    } = echo;
    let len = packet.len();
    if controller.inject(packet).await.is_ok() {
        info!(
            "{OVERLAY_EVIDENCE_PREFIX}_echo peer={peer_id} dst_ip={virtual_ip} seq={seq} nonce={nonce:#x} len={len}"
        );
    }
}

fn committed_direct_ready_for_echo(
    peers: &PeerManager,
    peer_id: &str,
    generation: u64,
) -> bool {
    peers
        .committed_business_path_snapshots_sync()
        .into_iter()
        .any(|peer| {
            peer.peer_id == peer_id
                && peer.is_online_in_generation(generation)
                && peer.active_path() == Some(crate::peer::NetworkPath::Direct)
        })
}

async fn flush_pending_overlay_echoes(
    controller: &MockTunController,
    peers: &PeerManager,
    pending: &mut VecDeque<PendingOverlayEcho>,
) {
    if pending.is_empty() {
        return;
    }
    let generation = peers.current_network_generation_sync();
    let snapshots: HashMap<_, _> = peers
        .committed_business_path_snapshots_sync()
        .into_iter()
        .map(|peer| (peer.peer_id.clone(), peer))
        .collect();
    let mut ready = Vec::new();
    let mut waiting = VecDeque::new();
    while let Some(echo) = pending.pop_front() {
        if echo.generation != generation || echo.queued_at.elapsed() > OVERLAY_NONCE_TTL {
            debug!(
                event = "overlay_echo_retired",
                peer = %echo.peer_id,
                generation = echo.generation,
                current_generation = generation,
                "retired a stale pending strict-Direct overlay echo"
            );
            continue;
        }
        let Some(snapshot) = snapshots.get(&echo.peer_id) else {
            continue;
        };
        if !snapshot.is_online_in_generation(generation) {
            continue;
        }
        if snapshot.active_path() == Some(crate::peer::NetworkPath::Direct) {
            ready.push(echo);
        } else {
            waiting.push_back(echo);
        }
    }
    *pending = waiting;
    for echo in ready {
        inject_pending_overlay_echo(controller, echo).await;
    }
}

#[allow(clippy::too_many_arguments)]
async fn run_overlay_send_cycle(
    controller: &MockTunController,
    peers: &Arc<PeerManager>,
    local_vip: &str,
    overlay_any_path: bool,
    overlay_burst: usize,
    next_nonce: &mut u64,
    next_seq: &mut u32,
    stats: &mut OverlayStats,
    sent_nonces: &mut HashMap<u64, SentOverlayNonce>,
    nonce_order: &mut VecDeque<u64>,
    bursts: &mut HashMap<String, OverlayBurst>,
    timeline: &Arc<ConnectionTimeline>,
) {
    stats.sent = stats.sent.saturating_add(
        send_overlay_payloads(
            controller,
            peers,
            local_vip,
            overlay_any_path,
            next_nonce,
            next_seq,
            stats,
            sent_nonces,
            nonce_order,
        )
        .await,
    );
    if overlay_burst > 0 {
        fire_pending_bursts(
            controller,
            peers,
            local_vip,
            overlay_burst,
            next_nonce,
            next_seq,
            sent_nonces,
            nonce_order,
            bursts,
        )
        .await;
        settle_overdue_bursts(bursts, timeline);
    }
}

#[allow(clippy::too_many_arguments)]
pub async fn run_overlay_validate_loop(
    controller: MockTunController,
    peers: Arc<PeerManager>,
    local_vip: String,
    local_node_id: String,
    overlay_any_path: bool,
    overlay_burst: usize,
    timeline: Arc<ConnectionTimeline>,
    mut overlay_ingress_rx: mpsc::Receiver<OverlayIngressEvent>,
    mut shutdown_rx: watch::Receiver<bool>,
) {
    info!(
        "overlay_validate loop started local_vip={local_vip} any_path={overlay_any_path} burst={overlay_burst}: sending real encrypted overlay payloads through the production dataplane"
    );
    let mut stats = OverlayStats {
        sent: 0,
        received_valid: 0,
        received_invalid: 0,
        verified_round_trips: 0,
        last_seq: 0,
    };
    let mut seen = VecDeque::<(u64, u32)>::new();
    let mut next_nonce: u64 = rand::random();
    let mut next_seq = 0u32;
    // Bounded outbound nonce registry: nonce -> (peer sent to, generation,
    // sent at).  Echo verification requires an exact match here.
    let mut sent_nonces: HashMap<u64, SentOverlayNonce> = HashMap::new();
    let mut nonce_order: VecDeque<u64> = VecDeque::new();
    // Post-first-usable burst verification: one burst of `overlay_burst`
    // payloads per peer, every echo counted (zero loss / duplicate /
    // reorder through the REAL dataplane + WireGuard pipeline).
    let mut bursts: HashMap<String, OverlayBurst> = HashMap::new();
    let mut pending_echoes = VecDeque::<PendingOverlayEcho>::new();
    // The committed path stream is published by the same atomic entry that
    // changes the active business path. Availability mode uses it immediately
    // so Relay evidence cannot be delayed by diagnostics lock contention.
    // Strict-Direct mode keeps its periodic send: one endpoint can commit
    // Direct slightly before the other, and an immediate request would then be
    // echoed over the other endpoint's still-active Relay path rather than
    // proving a bidirectional Direct business exchange.
    let mut committed_path_changes = peers.subscribe_committed_business_path_changes();
    // First-usable strictness: a bidirectional encrypted overlay business
    // loopback is proven by the FIRST verified echo.  An echo is only ever
    // generated when the peer verified a fresh request of ours (our outbound ->
    // peer inbound -> peer echo -> our inbound decryption), so a single UDP
    // send or TCP connect can never satisfy it.  The loop does NOT require a
    // prior verified inbound request first: the two daemons send on their own
    // intervals, so the first echo can legitimately arrive before the peer's
    // first request.
    let mut send_tick = tokio::time::interval(OVERLAY_SEND_INTERVAL);
    send_tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    // Skip the immediate first tick so the peer can converge before the first
    // payload is injected.
    send_tick.tick().await;

    // Drain the mock TUN's WRITE side continuously: the dataplane writes every
    // decrypted inbound overlay payload into it, and if nothing consumes the
    // (bounded, 256-entry) channel the dataplane's write_inbound blocks
    // forever once a burst fills it — stalling the whole inbound pipeline.
    // Verification happens through the transport's ingress feed, so the
    // written bytes only need to be consumed, not inspected.
    let drain_controller = controller.clone();
    let _drain_task = tokio::spawn(async move {
        let mut written: u64 = 0;
        let drain = drain_controller;
        while let Ok(_packet) = drain.recv_written().await {
            written = written.saturating_add(1);
        }
        written
    });

    loop {
        tokio::select! {
            _ = send_tick.tick() => {
                flush_pending_overlay_echoes(&controller, &peers, &mut pending_echoes).await;
                run_overlay_send_cycle(
                    &controller,
                    &peers,
                    &local_vip,
                    overlay_any_path,
                    overlay_burst,
                    &mut next_nonce,
                    &mut next_seq,
                    &mut stats,
                    &mut sent_nonces,
                    &mut nonce_order,
                    &mut bursts,
                    &timeline,
                ).await;
            }
            changed = committed_path_changes.changed() => {
                if changed.is_err() {
                    warn!("overlay_validate: committed path feed closed; stopping");
                    break;
                }
                flush_pending_overlay_echoes(&controller, &peers, &mut pending_echoes).await;
                if overlay_any_path {
                    run_overlay_send_cycle(
                        &controller,
                        &peers,
                        &local_vip,
                        overlay_any_path,
                        overlay_burst,
                        &mut next_nonce,
                        &mut next_seq,
                        &mut stats,
                        &mut sent_nonces,
                        &mut nonce_order,
                        &mut bursts,
                        &timeline,
                    ).await;
                }
            }
            event = overlay_ingress_rx.recv() => {
                let Some(event) = event else {
                    warn!("overlay_validate: overlay ingress feed closed; stopping");
                    break;
                };
                handle_overlay_ingress(
                    event,
                    &controller,
                    &local_vip,
                    &local_node_id,
                    overlay_any_path,
                    &mut seen,
                    &mut stats,
                    &peers,
                    &timeline,
                    &sent_nonces,
                    &mut bursts,
                    &mut pending_echoes,
                )
                .await;
            }
            changed = shutdown_rx.changed() => {
                if changed.is_err() || *shutdown_rx.borrow_and_update() {
                    break;
                }
            }
        }
    }
    info!(
        "overlay_validate loop stopped: sent={} received_valid={} received_invalid={} verified_round_trips={} last_seq={}",
        stats.sent, stats.received_valid, stats.received_invalid, stats.verified_round_trips, stats.last_seq
    );
}

/// Build one overlay business payload: magic + direction + nonce + sequence +
/// checksum + random filler.
fn build_overlay_payload(direction: u8, nonce: u64, seq: u32) -> Vec<u8> {
    let mut payload = Vec::with_capacity(OVERLAY_CHECKSUM_OFFSET + 4 + OVERLAY_FILLER_BYTES);
    payload.extend_from_slice(OVERLAY_MAGIC);
    payload.push(direction);
    payload.extend_from_slice(&nonce.to_be_bytes());
    payload.extend_from_slice(&seq.to_be_bytes());
    payload.extend_from_slice(&[0u8; 4]);
    let mut filler = vec![0u8; OVERLAY_FILLER_BYTES];
    rand::thread_rng().fill_bytes(&mut filler);
    payload.extend_from_slice(&filler);
    let checksum = crc32_business_payload(&payload[..OVERLAY_CHECKSUM_SPAN]);
    payload[OVERLAY_CHECKSUM_OFFSET..OVERLAY_CHECKSUM_OFFSET + 4]
        .copy_from_slice(&checksum.to_be_bytes());
    payload
}

fn overlay_validation_path_ready(
    online: bool,
    active_path: Option<crate::peer::NetworkPath>,
    overlay_any_path: bool,
) -> bool {
    if !online {
        return false;
    }
    match active_path {
        Some(crate::peer::NetworkPath::Direct) => true,
        Some(crate::peer::NetworkPath::Relay) if overlay_any_path => true,
        _ => false,
    }
}

fn overlay_validation_target_ready(
    peer: &crate::peer::CommittedBusinessPathSnapshot,
    generation: u64,
    overlay_any_path: bool,
) -> bool {
    overlay_validation_path_ready(
        peer.is_online_in_generation(generation),
        peer.active_path(),
        overlay_any_path,
    )
}

/// Inject one payload per target peer into the production dataplane.
///
/// In the default strict-direct mode only peers in `ConnectionState::Direct`
/// are targeted, so the evidence always rides a confirmed Direct path.  In
/// `any_path` mode targets peers only after the production state machine owns
/// a confirmed Relay or Direct active path. This keeps the harness out of the
/// startup queue while still allowing Relay to provide the availability proof
/// before a UDP punch succeeds.
///
/// Every sent nonce is recorded in the bounded registry so a later echo can be
/// matched to THIS daemon's own request (peer + generation + validity).
#[allow(clippy::too_many_arguments)]
async fn send_overlay_payloads(
    controller: &MockTunController,
    peers: &Arc<PeerManager>,
    local_vip: &str,
    overlay_any_path: bool,
    next_nonce: &mut u64,
    next_seq: &mut u32,
    stats: &mut OverlayStats,
    sent_nonces: &mut HashMap<u64, SentOverlayNonce>,
    nonce_order: &mut VecDeque<u64>,
) -> u64 {
    let mut sent = 0u64;
    let generation = peers.current_network_generation_sync();
    let committed_peers = peers.committed_business_path_snapshots_sync();
    for peer in committed_peers {
        // This independent harness must measure loss only after the production
        // path state machine owns a confirmed path. Injecting synthetic traffic
        // while the peer is merely online pushes it into the bounded startup
        // queue and can expire before Relay confirmation; that tests startup
        // timing rather than the zero-loss Direct/Relay dataplane contract.
        if !overlay_validation_target_ready(&peer, generation, overlay_any_path) {
            continue;
        }
        let virtual_ip = peer.virtual_ip.clone();
        let peer_id = peer.peer_id.clone();
        // The strict Direct acceptance profile is a make-before-break proof:
        // its first Direct business packet must not race ahead of the forced
        // encrypted Relay confirmation.  This is an authoritative manager
        // read, not a second path state machine and not a timing sleep.  The
        // Relay-availability profile intentionally allows Relay immediately.
        if !overlay_any_path
            && peer.active_path() == Some(crate::peer::NetworkPath::Direct)
            && !peers
                .is_relay_peer_confirmed_for_generation(&peer_id, generation)
                .await
        {
            continue;
        }
        *next_nonce = next_nonce.wrapping_add(1);
        *next_seq = next_seq.wrapping_add(1);
        let payload = build_overlay_payload(OVERLAY_DIRECTION_REQUEST, *next_nonce, *next_seq);
        let Some(packet) =
            build_udp_overlay_packet(local_vip, &virtual_ip, 39286, 39287, &payload)
        else {
            continue;
        };
        // Register the outbound nonce BEFORE the send so a fast echo cannot
        // race ahead of the registry insert.
        sent_nonces.insert(
            *next_nonce,
            SentOverlayNonce {
                peer_id: peer_id.clone(),
                generation,
                sent_at: Instant::now(),
            },
        );
        nonce_order.push_back(*next_nonce);
        while nonce_order.len() > OVERLAY_NONCE_CAP {
            if let Some(oldest) = nonce_order.pop_front() {
                sent_nonces.remove(&oldest);
            }
        }
        if controller.inject(packet).await.is_ok() {
            sent += 1;
            stats.last_seq = u64::from(*next_seq);
            info!(
                "{OVERLAY_EVIDENCE_PREFIX}_sent peer={peer_id} dst_ip={virtual_ip} seq={} nonce={} len={} generation={generation}",
                *next_seq,
                *next_nonce,
                payload.len() + 28,
            );
        }
    }
    sent
}

enum OverlayVerdict {
    Valid {
        peer_id: String,
        virtual_ip: String,
        nonce: u64,
        seq: u32,
        direction: u8,
        /// Path that actually carried the verified inbound packet (relay or
        /// direct), from the transport-layer ingress metadata — never
        /// back-inferred from `active_path`.
        path: String,
    },
    Invalid {
        reason: String,
    },
    Ignored,
}

/// Handle one decrypted inbound overlay event forwarded by the WireGuard
/// inbound path with its real ingress metadata.
#[allow(clippy::too_many_arguments)]
async fn handle_overlay_ingress(
    event: OverlayIngressEvent,
    controller: &MockTunController,
    local_vip: &str,
    local_node_id: &str,
    overlay_any_path: bool,
    seen: &mut VecDeque<(u64, u32)>,
    stats: &mut OverlayStats,
    peers: &Arc<PeerManager>,
    timeline: &Arc<ConnectionTimeline>,
    sent_nonces: &HashMap<u64, SentOverlayNonce>,
    bursts: &mut HashMap<String, OverlayBurst>,
    pending_echoes: &mut VecDeque<PendingOverlayEcho>,
) {
    let current_generation = peers.current_network_generation_sync();
    if event.connection_generation != current_generation {
        stats.received_invalid = stats.received_invalid.saturating_add(1);
        warn!(
            "{OVERLAY_EVIDENCE_PREFIX}_stale_generation peer={} event_generation={} current_generation={} reason_code=stale_overlay_generation",
            event.peer_id, event.connection_generation, current_generation
        );
        timeline.emit(
            "overlay_stale_generation",
            None,
            Some("stale_overlay_generation"),
            Some(format!(
                "peer={} event_generation={} current_generation={}",
                event.peer_id, event.connection_generation, current_generation
            )),
        );
        return;
    }
    let ingress_label = match &event.ingress {
        OverlayIngress::Direct => "direct".to_string(),
        OverlayIngress::Relay(endpoint) => format!("relay:{endpoint}"),
    };
    match verify_overlay_packet(
        &event.packet,
        local_vip,
        local_node_id,
        seen,
        stats,
        peers,
        &ingress_label,
    )
    .await
    {
        OverlayVerdict::Valid {
            peer_id,
            virtual_ip,
            nonce,
            seq,
            direction,
            path,
        } => {
            if direction == OVERLAY_DIRECTION_REQUEST {
                // Echo the payload back through the real pipeline so
                // one round proves bidirectional encrypted traffic.
                // ONLY a fresh request (direction 0) is echoed; an
                // echo is never echoed again, so (nonce, seq) ping-
                // pong is impossible.
                if let Some(echo) = build_pending_overlay_echo(
                    local_vip,
                    peer_id.clone(),
                    virtual_ip.clone(),
                    event.connection_generation,
                    nonce,
                    seq,
                ) {
                    if overlay_any_path
                        || committed_direct_ready_for_echo(
                            peers,
                            &peer_id,
                            event.connection_generation,
                        )
                    {
                        inject_pending_overlay_echo(controller, echo).await;
                    } else {
                        if pending_echoes.len() >= OVERLAY_PENDING_ECHO_CAP {
                            if let Some(retired) = pending_echoes.pop_front() {
                                warn!(
                                    event = "overlay_echo_capacity_retired",
                                    peer = %retired.peer_id,
                                    generation = retired.generation,
                                    "retired the oldest pending strict-Direct overlay echo at the hard capacity"
                                );
                            }
                        }
                        info!(
                            event = "overlay_echo_deferred_until_direct_commit",
                            peer = %peer_id,
                            generation = event.connection_generation,
                            seq = seq,
                            nonce = nonce,
                            "deferred strict-Direct overlay echo until the local Direct path commits"
                        );
                        pending_echoes.push_back(echo);
                    }
                }
            } else if direction == OVERLAY_DIRECTION_ECHO {
                // First confirmed bidirectional encrypted overlay
                // business loopback: an echo only exists after the
                // peer verified and echoed OUR request.  The echo is
                // accepted as first-usable evidence ONLY when its
                // nonce matches a nonce this daemon actually sent to
                // the SAME peer within the validity window (bounded
                // outbound nonce registry).
                match sent_nonces.get(&nonce) {
                    Some(sent)
                        if sent.peer_id == peer_id
                            && sent.generation == event.connection_generation
                            && sent.sent_at.elapsed() <= OVERLAY_NONCE_TTL =>
                    {
                        let generation = sent.generation;
                        let scope = format!("peer:{peer_id}:{generation}");
                        // The harness-level bidirectional milestone is
                        // recorded here — with real ingress — never by a
                        // relay confirmation, TCP/TLS connect, or queued
                        // registration. Production TUN has its own earlier
                        // decrypted-business ingress milestone.
                        let usable_path = match &event.ingress {
                            OverlayIngress::Direct => crate::peer::NetworkPath::Direct,
                            OverlayIngress::Relay(_) => crate::peer::NetworkPath::Relay,
                        };
                        // Production TUN ingress may already have recorded
                        // first_usable from this decrypted packet. The
                        // harness still requires the stronger nonce-matched
                        // bidirectional echo before emitting its
                        // first_usable_confirmed/SLO evidence; these are two
                        // intentionally separate milestones.
                        let _production_recorded = peers
                            .record_verified_first_usable(
                                &peer_id,
                                generation,
                                usable_path,
                                &ingress_label,
                            )
                            .await;
                        // Per-daemon monotonic relay-ready -> usable delta
                        // (only meaningful when the usable path is relay).
                        let relay_delta_ms = if let OverlayIngress::Relay(_) = &event.ingress {
                            peers
                                .relay_ready_at_for_generation(&peer_id, generation)
                                .await
                                .map(|ready_at| {
                                    Instant::now()
                                        .saturating_duration_since(ready_at)
                                        .as_millis()
                                        .min(u64::MAX as u128)
                                        as u64
                                })
                        } else {
                            None
                        };
                        let newly_confirmed = timeline.emit_first_scoped(
                            &scope,
                            "first_usable_bidirectional_overlay_ms",
                            Some(&path),
                            None,
                            Some(format!(
                                "peer={peer_id} dst_ip={virtual_ip} seq={seq} ingress={ingress_label} generation={generation} relay_ready_to_usable_ms={}",
                                relay_delta_ms
                                    .map(|ms| ms.to_string())
                                    .unwrap_or_else(|| "n/a".to_string())
                            )),
                        );
                        if newly_confirmed {
                            info!(
                                event = "first_usable_confirmed",
                                peer_id = %peer_id,
                                path = %path,
                                ingress = %ingress_label,
                                generation = generation,
                                relay_ready_to_usable_ms = ?relay_delta_ms,
                                seq = seq,
                                "first_usable_confirmed peer_id={peer_id} path={path} ingress={ingress_label} generation={generation} relay_ready_to_usable_ms={relay_delta_ms:?}",
                            );
                            // Arm the post-first-usable burst for this peer (the
                            // fire happens on the next send tick).
                            bursts
                                .entry(peer_id.clone())
                                .or_insert_with(|| OverlayBurst {
                                    armed: true,
                                    nonces: Vec::new(),
                                    sent: 0,
                                    received: 0,
                                    fired_at: None,
                                })
                                .armed = true;
                        }
                    }
                    _ => {
                        // A valid echo of a request originated by the peer is
                        // still encrypted business ingress, but this daemon
                        // must not use it as proof of its own request/echo
                        // round. It is not a malformed or stale packet, so do
                        // not turn simultaneous bidirectional probes into a
                        // false invalid/drop result.
                        warn!(
                            "{OVERLAY_EVIDENCE_PREFIX}_unmatched_echo peer={peer_id} seq={seq} nonce={nonce:#x} ingress={ingress_label} reason_code=remote_echo_not_local_request — not first-usable evidence"
                        );
                    }
                }
            }
            // A verified echo of a burst packet counts toward the burst.
            if direction == OVERLAY_DIRECTION_ECHO {
                if let Some(burst) = bursts.get_mut(&peer_id) {
                    if burst.fired_at.is_some() && burst.nonces.contains(&nonce) {
                        burst.received = burst.received.saturating_add(1);
                        if burst.received >= burst.sent {
                            info!(
                                event = "overlay_burst_complete",
                                peer = %peer_id,
                                sent = burst.sent,
                                received = burst.received,
                                "overlay_burst_complete peer={peer_id} sent={} received={}",
                                burst.sent,
                                burst.received
                            );
                            timeline.emit(
                                "overlay_burst_complete",
                                None,
                                None,
                                Some(format!(
                                    "peer={peer_id} sent={} received={}",
                                    burst.sent, burst.received
                                )),
                            );
                            bursts.remove(&peer_id);
                        }
                    }
                }
            }
        }
        OverlayVerdict::Invalid { reason } => {
            warn!("{OVERLAY_EVIDENCE_PREFIX}_invalid {reason}");
        }
        OverlayVerdict::Ignored => {}
    }
}

/// Verify a decrypted inbound overlay payload that the production dataplane
/// delivered.  Returns the sender peer and the payload identity when the
/// magic, checksum and nonce/seq are all valid.
async fn verify_overlay_packet(
    packet: &[u8],
    local_vip: &str,
    _local_node_id: &str,
    seen: &mut VecDeque<(u64, u32)>,
    stats: &mut OverlayStats,
    peers: &Arc<PeerManager>,
    ingress_label: &str,
) -> OverlayVerdict {
    let parsed = match p2pnet_tun::Ipv4Packet::new(packet) {
        Ok(parsed) => parsed,
        Err(_) => {
            return OverlayVerdict::Invalid {
                reason: format!("not an IPv4 packet ({} bytes)", packet.len()),
            };
        }
    };
    if parsed.protocol() != p2pnet_tun::Protocol::Udp {
        return OverlayVerdict::Ignored;
    }
    let payload = parsed.payload();
    // The IP payload includes the 8-byte UDP header; the overlay business
    // payload starts after it.
    if payload.len() < 8 + OVERLAY_CHECKSUM_OFFSET + 4 {
        return OverlayVerdict::Invalid {
            reason: format!("overlay payload too short: {}", payload.len()),
        };
    }
    let payload = &payload[8..];
    if &payload[..OVERLAY_MAGIC.len()] != OVERLAY_MAGIC {
        return OverlayVerdict::Ignored;
    }
    let direction = payload[OVERLAY_MAGIC.len()];
    if direction > OVERLAY_DIRECTION_ECHO {
        stats.received_invalid += 1;
        return OverlayVerdict::Invalid {
            reason: format!("unknown direction byte {direction}"),
        };
    }
    let mut nonce_bytes = [0u8; 8];
    nonce_bytes.copy_from_slice(&payload[7..15]);
    let nonce = u64::from_be_bytes(nonce_bytes);
    let mut seq_bytes = [0u8; 4];
    seq_bytes.copy_from_slice(&payload[15..19]);
    let seq = u32::from_be_bytes(seq_bytes);
    let expected_checksum = crc32_business_payload(&payload[..OVERLAY_CHECKSUM_SPAN]);
    let actual_checksum = u32::from_be_bytes(
        payload[OVERLAY_CHECKSUM_OFFSET..OVERLAY_CHECKSUM_OFFSET + 4]
            .try_into()
            .unwrap_or([0u8; 4]),
    );
    if actual_checksum != expected_checksum {
        stats.received_invalid += 1;
        return OverlayVerdict::Invalid {
            reason: format!("checksum mismatch: expected {expected_checksum:08x} got {actual_checksum:08x}"),
        };
    }
    if seen.iter().any(|&(seen_nonce, seen_seq)| seen_nonce == nonce && seen_seq == seq) {
        stats.received_invalid += 1;
        return OverlayVerdict::Invalid {
            reason: format!("duplicate nonce/seq ({nonce:#x}/{seq})"),
        };
    }
    seen.push_back((nonce, seq));
    while seen.len() > OVERLAY_SEEN_CAP {
        seen.pop_front();
    }

    let src_ip = parsed.src_addr().to_string();
    let dst_ip = parsed.dst_addr().to_string();
    let Some(peer_id) = peers.resolve_virtual_ip(&src_ip).await else {
        stats.received_invalid += 1;
        return OverlayVerdict::Invalid {
            reason: format!("unknown sender virtual IP {src_ip}"),
        };
    };
    if dst_ip != local_vip {
        stats.received_invalid += 1;
        return OverlayVerdict::Invalid {
            reason: format!("unexpected destination {dst_ip} (local {local_vip})"),
        };
    }
    stats.received_valid += 1;
    stats.verified_round_trips += 1;
    info!(
        "{OVERLAY_EVIDENCE_PREFIX}_verified peer={peer_id} src_ip={src_ip} seq={seq} nonce={nonce:#x} len={} ingress={ingress_label} verified_round_trips={}",
        payload.len(),
        stats.verified_round_trips
    );
    OverlayVerdict::Valid {
        peer_id,
        virtual_ip: src_ip,
        nonce,
        seq,
        direction,
        path: ingress_label.to_string(),
    }
}

/// Build a small UDP/IPv4 packet carrying an overlay business payload.
fn build_udp_overlay_packet(
    src_ip: &str,
    dst_ip: &str,
    sport: u16,
    dport: u16,
    payload: &[u8],
) -> Option<Vec<u8>> {
    use std::net::Ipv4Addr;
    let src: Ipv4Addr = src_ip.parse().ok()?;
    let dst: Ipv4Addr = dst_ip.parse().ok()?;
    let total_len = 20 + 8 + payload.len();
    if total_len > 65_535 {
        return None;
    }
    let mut packet = Vec::with_capacity(total_len);
    packet.push(0x45);
    packet.push(0);
    packet.extend_from_slice(&(total_len as u16).to_be_bytes());
    packet.extend_from_slice(&0x0000u16.to_be_bytes());
    packet.extend_from_slice(&0x0000u16.to_be_bytes());
    packet.push(64);
    packet.push(17);
    packet.extend_from_slice(&0x0000u16.to_be_bytes());
    packet.extend_from_slice(&src.octets());
    packet.extend_from_slice(&dst.octets());
    packet.extend_from_slice(&sport.to_be_bytes());
    packet.extend_from_slice(&dport.to_be_bytes());
    packet.extend_from_slice(&((8 + payload.len()) as u16).to_be_bytes());
    packet.extend_from_slice(&0x0000u16.to_be_bytes());
    packet.extend_from_slice(payload);
    Some(packet)
}

/// CRC-32 (IEEE) over the checksummed overlay region, computed exactly like
/// the sender.
fn crc32_business_payload(data: &[u8]) -> u32 {
    let mut crc = 0xFFFF_FFFFu32;
    for &byte in data {
        crc ^= u32::from(byte);
        for _ in 0..8 {
            let mask = (crc & 1).wrapping_neg();
            crc = (crc >> 1) ^ (0xEDB8_8320 & mask);
        }
    }
    !crc
}

/// Allow tests to build and verify the same payload encoding end-to-end.
#[cfg(test)]
mod overlay_validate_tests {
    use super::*;

    #[test]
    fn overlay_validation_waits_for_a_confirmed_active_path() {
        use crate::peer::NetworkPath;

        assert!(!overlay_validation_path_ready(true, None, true));
        assert!(!overlay_validation_path_ready(true, None, false));
        assert!(overlay_validation_path_ready(
            true,
            Some(NetworkPath::Relay),
            true,
        ));
        assert!(!overlay_validation_path_ready(
            true,
            Some(NetworkPath::Relay),
            false,
        ));
        assert!(overlay_validation_path_ready(
            true,
            Some(NetworkPath::Direct),
            false,
        ));
        assert!(!overlay_validation_path_ready(
            false,
            Some(NetworkPath::Direct),
            false,
        ));
    }

    #[tokio::test]
    async fn committed_path_notification_and_snapshot_bypass_stale_diagnostics() {
        use crate::control::PeerInfo;
        use crate::peer::NetworkPath;

        let manager = PeerManager::new(
            Config::generate_default("http://ctrl.test", "default")
                .expect("test config must build"),
        );
        manager
            .add_peer(&PeerInfo {
                node_id: "peer-overlay-path".to_string(),
                public_key: "pk".to_string(),
                endpoint: "127.0.0.1:45000".to_string(),
                nat_type: "Unknown".to_string(),
                virtual_ip: "10.20.0.2".to_string(),
                online: true,
                ..PeerInfo::default()
            })
            .await;

        // Prime the intentionally non-blocking diagnostics fallback before the
        // path is confirmed. It must not become authority for this harness.
        let stale_before_confirmation = manager.diagnostics().await;
        assert_eq!(stale_before_confirmation[0].active_path, None);

        manager
            .mark_relay_transport_ready("peer-overlay-path", "tcp://relay.test:443", 0)
            .await;
        let mut committed_path_changes = manager.subscribe_committed_business_path_changes();
        assert!(
            manager
                .confirm_relay_peer("peer-overlay-path", "tcp://relay.test:443", 0)
                .await
        );
        tokio::time::timeout(
            Duration::from_secs(1),
            committed_path_changes.changed(),
        )
        .await
        .expect("Relay commit must wake the overlay harness")
        .expect("committed path stream must remain open");

        let _connection_writer = manager.hold_connections_writer_for_test().await;
        let stale_under_contention = manager.diagnostics().await;
        assert_eq!(stale_under_contention[0].active_path, None);

        let generation = manager.current_network_generation_sync();
        let committed = manager.committed_business_path_snapshots_sync();
        let peer = committed
            .iter()
            .find(|peer| peer.peer_id == "peer-overlay-path")
            .expect("committed path projection must contain the peer");
        assert_eq!(peer.active_path(), Some(NetworkPath::Relay));
        assert!(overlay_validation_target_ready(peer, generation, true));
        assert_eq!(peer.virtual_ip, "10.20.0.2");
    }

    #[tokio::test]
    async fn strict_direct_echo_waits_for_local_direct_commit_without_sleep() {
        use crate::control::PeerInfo;
        use crate::peer::NetworkPath;

        let manager = PeerManager::new(
            Config::generate_default("http://ctrl.test", "default")
                .expect("test config must build"),
        );
        manager
            .add_peer(&PeerInfo {
                node_id: "peer-strict-direct-echo".to_string(),
                public_key: "pk".to_string(),
                endpoint: "127.0.0.1:45001".to_string(),
                nat_type: "Unknown".to_string(),
                virtual_ip: "10.20.0.2".to_string(),
                online: true,
                ..PeerInfo::default()
            })
            .await;
        manager
            .mark_relay_transport_ready(
                "peer-strict-direct-echo",
                "tcp://relay.test:443",
                0,
            )
            .await;
        assert!(
            manager
                .confirm_relay_peer(
                    "peer-strict-direct-echo",
                    "tcp://relay.test:443",
                    0,
                )
                .await
        );

        let generation = manager.current_network_generation_sync();
        let (mut tun, controller) =
            p2pnet_tun::mock::MockTunDevice::new_pair("strict-direct-echo", 1420, "10.20.0.1");
        let mut pending = VecDeque::from([
            build_pending_overlay_echo(
                "10.20.0.1",
                "peer-strict-direct-echo".to_string(),
                "10.20.0.2".to_string(),
                generation,
                0x1234_5678_9abc_def0,
                42,
            )
            .expect("valid IPv4 addresses must build a pending echo"),
        ]);

        flush_pending_overlay_echoes(&controller, &manager, &mut pending).await;
        assert_eq!(
            pending.len(),
            1,
            "a healthy Relay must not release a strict-Direct echo"
        );

        manager
            .record_direct_success(
                "peer-strict-direct-echo",
                Some("127.0.0.1:45001".parse().unwrap()),
            )
            .await;
        assert!(committed_direct_ready_for_echo(
            &manager,
            "peer-strict-direct-echo",
            generation,
        ));
        assert_eq!(
            manager
                .committed_business_path_snapshots_sync()
                .into_iter()
                .find(|peer| peer.peer_id == "peer-strict-direct-echo")
                .and_then(|peer| peer.active_path()),
            Some(NetworkPath::Direct),
        );

        flush_pending_overlay_echoes(&controller, &manager, &mut pending).await;
        assert!(pending.is_empty(), "the Direct commit must release the echo");

        let mut packet = [0u8; 512];
        let received = tokio::time::timeout(Duration::from_secs(1), tun.read(&mut packet))
            .await
            .expect("the Direct commit must inject the queued echo")
            .expect("the mock TUN must stay open");
        let parsed = p2pnet_tun::Ipv4Packet::new(&packet[..received])
            .expect("the released echo must remain a valid IPv4 packet");
        assert_eq!(parsed.src_addr().to_string(), "10.20.0.1");
        assert_eq!(parsed.dst_addr().to_string(), "10.20.0.2");
        let payload = &parsed.payload()[8..];
        assert_eq!(&payload[..OVERLAY_MAGIC.len()], OVERLAY_MAGIC);
        assert_eq!(payload[OVERLAY_MAGIC.len()], OVERLAY_DIRECTION_ECHO);
    }

    #[test]
    fn overlay_payload_checksum_round_trip() {
        let payload = build_overlay_payload(OVERLAY_DIRECTION_REQUEST, 0x1234_5678_9abc_def0u64, 42);
        let actual_checksum = u32::from_be_bytes(
            payload[OVERLAY_CHECKSUM_OFFSET..OVERLAY_CHECKSUM_OFFSET + 4]
                .try_into()
                .unwrap(),
        );
        assert_eq!(
            crc32_business_payload(&payload[..OVERLAY_CHECKSUM_SPAN]),
            actual_checksum,
            "the checksum field must match the CRC over magic+nonce+seq"
        );
    }

    #[test]
    fn overlay_packet_build_and_parse() {
        let packet = build_udp_overlay_packet("10.20.0.1", "10.20.0.2", 39286, 39287, b"P2WLOV")
            .expect("packet must build");
        let parsed = p2pnet_tun::Ipv4Packet::new(&packet).expect("packet must parse");
        assert_eq!(parsed.protocol(), p2pnet_tun::Protocol::Udp);
        assert_eq!(parsed.src_addr().to_string(), "10.20.0.1");
        assert_eq!(parsed.dst_addr().to_string(), "10.20.0.2");
        assert_eq!(&parsed.payload()[8..], b"P2WLOV");
    }
}
