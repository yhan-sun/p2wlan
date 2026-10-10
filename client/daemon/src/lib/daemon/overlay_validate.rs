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
use std::path::PathBuf;

use crate::transport::{OverlayIngress, OverlayIngressEvent};
use p2pnet_tun::mock::MockTunController;

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
    seq: u32,
    sent_at: Instant,
}

/// One successfully injected burst request. The existing burst container keeps
/// these exact identities after the smaller periodic nonce registry evicts them.
#[derive(Clone, Copy)]
struct InjectedOverlayBurstRequest {
    nonce: u64,
    seq: u32,
    generation: u64,
    sent_at: Instant,
}

/// Strict-Direct requests can arrive just before this endpoint commits its own
/// Direct state or publishes the DPLPMTUD business budget. Preserve the request
/// until both production Direct business admission conditions hold so its echo
/// also traverses Direct instead of falling back to an otherwise healthy Relay.
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
    /// Exact successful requests awaiting one matching echo. Bounded by the
    /// configured burst size; removing a match prevents duplicate credit after
    /// the smaller ingress seen ring forgets an older echo.
    nonces: Vec<InjectedOverlayBurstRequest>,
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
    overlay_any_path: bool,
    udp_transport: Option<&Arc<RwLock<Option<UdpTransport>>>>,
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
            peer.is_online_in_generation(generation)
                && peer.active_path().is_some()
                && (overlay_any_path
                    || peer.active_path() == Some(crate::peer::NetworkPath::Direct))
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
        if !overlay_any_path && !overlay_direct_business_budget_ready(udp_transport, &peer_id).await
        {
            continue;
        }
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
            let seq = *next_seq;
            let sent_at = Instant::now();
            if controller.inject(packet).await.is_ok() {
                // This loop awaits its send cycle before polling ingress again.
                // Register only an actual successful injection; a fast echo can
                // queue meanwhile, but cannot be handled before this insertion.
                sent_nonces.insert(
                    nonce,
                    SentOverlayNonce {
                        peer_id: peer_id.clone(),
                        generation,
                        seq,
                        sent_at,
                    },
                );
                nonce_order.push_back(nonce);
                while nonce_order.len() > OVERLAY_NONCE_CAP {
                    if let Some(oldest) = nonce_order.pop_front() {
                        sent_nonces.remove(&oldest);
                    }
                }
                nonces.push(InjectedOverlayBurstRequest {
                    nonce,
                    seq,
                    generation,
                    sent_at,
                });
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

async fn inject_pending_overlay_echo(controller: &MockTunController, echo: PendingOverlayEcho) {
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

fn committed_direct_ready_for_echo(peers: &PeerManager, peer_id: &str, generation: u64) -> bool {
    peers
        .committed_business_path_snapshots_sync()
        .into_iter()
        .any(|peer| {
            peer.peer_id == peer_id
                && peer.is_online_in_generation(generation)
                && peer.active_path() == Some(crate::peer::NetworkPath::Direct)
        })
}

/// Read the same authoritative Direct business admission bit used by the
/// production outbound selector. `None` is used only by unit tests that focus
/// on the committed-path transition; the production validation loop always
/// supplies the live UDP transport slot.
async fn overlay_direct_business_budget_ready(
    udp_transport: Option<&Arc<RwLock<Option<UdpTransport>>>>,
    peer_id: &str,
) -> bool {
    let Some(udp_transport) = udp_transport else {
        return true;
    };
    udp_transport
        .read()
        .await
        .as_ref()
        .is_some_and(|udp| udp.direct_business_budget_ready_for_peer(peer_id))
}

async fn flush_pending_overlay_echoes(
    controller: &MockTunController,
    peers: &PeerManager,
    overlay_any_path: bool,
    udp_transport: Option<&Arc<RwLock<Option<UdpTransport>>>>,
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
        let direct_ready = snapshot.active_path() == Some(crate::peer::NetworkPath::Direct)
            && overlay_direct_business_budget_ready(udp_transport, &echo.peer_id).await;
        if overlay_any_path || direct_ready {
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
    udp_transport: Option<&Arc<RwLock<Option<UdpTransport>>>>,
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
            udp_transport,
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
            overlay_any_path,
            udp_transport,
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
    overlay_start_gate_file: Option<PathBuf>,
    overlay_any_path: bool,
    udp_transport: Arc<RwLock<Option<UdpTransport>>>,
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
    // Bounded successful-injection registry: nonce -> (peer, generation, seq,
    // request creation time). Echo verification requires an exact match here.
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
    let mut direct_budget_changes = peers.subscribe_direct_business_budget_changes();
    let mut start_gate_released = overlay_start_gate_file.is_none();
    let mut start_gate_poll = tokio::time::interval(Duration::from_millis(20));
    start_gate_poll.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    // Avoid an immediate filesystem check; the first poll happens after 20ms.
    start_gate_poll.tick().await;
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
                if !start_gate_released {
                    continue;
                }
                flush_pending_overlay_echoes(
                    &controller,
                    &peers,
                    overlay_any_path,
                    Some(&udp_transport),
                    &mut pending_echoes,
                )
                .await;
                run_overlay_send_cycle(
                    &controller,
                    &peers,
                    &local_vip,
                    overlay_any_path,
                    Some(&udp_transport),
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
                if !start_gate_released {
                    continue;
                }
                flush_pending_overlay_echoes(
                    &controller,
                    &peers,
                    overlay_any_path,
                    Some(&udp_transport),
                    &mut pending_echoes,
                )
                .await;
                if overlay_any_path {
                    run_overlay_send_cycle(
                        &controller,
                        &peers,
                        &local_vip,
                        overlay_any_path,
                        Some(&udp_transport),
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
            changed = direct_budget_changes.changed(), if !overlay_any_path => {
                if changed.is_err() {
                    warn!("overlay_validate: direct business budget feed closed; stopping");
                    break;
                }
                if !start_gate_released {
                    continue;
                }
                flush_pending_overlay_echoes(
                    &controller,
                    &peers,
                    overlay_any_path,
                    Some(&udp_transport),
                    &mut pending_echoes,
                )
                .await;
                run_overlay_send_cycle(
                    &controller,
                    &peers,
                    &local_vip,
                    overlay_any_path,
                    Some(&udp_transport),
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
            _ = start_gate_poll.tick(), if !start_gate_released => {
                let Some(gate_path) = overlay_start_gate_file.as_ref() else {
                    start_gate_released = true;
                    continue;
                };
                match std::fs::metadata(gate_path) {
                    Ok(metadata) if metadata.is_file() => {
                        start_gate_released = true;
                        info!(
                            event = "overlay_start_gate_released",
                            gate_path = %gate_path.display(),
                            "overlay_start_gate_released"
                        );
                        // Do not make the test wait for the next periodic
                        // tick after the external barrier has released.
                        send_tick.reset_immediately();
                    }
                    Ok(_) => {
                        error!(
                            gate_path = %gate_path.display(),
                            "overlay validation start gate exists but is not a regular file"
                        );
                        break;
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                    Err(error) => {
                        error!(
                            gate_path = %gate_path.display(),
                            %error,
                            "could not inspect overlay validation start gate"
                        );
                        break;
                    }
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
                    start_gate_released,
                    &mut seen,
                    &mut stats,
                    &peers,
                    &timeline,
                    &sent_nonces,
                    &mut bursts,
                    &mut pending_echoes,
                    Some(&udp_transport),
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
    udp_transport: Option<&Arc<RwLock<Option<UdpTransport>>>>,
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
        if !overlay_any_path
            && peer.active_path() == Some(crate::peer::NetworkPath::Direct)
            && !overlay_direct_business_budget_ready(udp_transport, &peer_id).await
        {
            continue;
        }
        *next_nonce = next_nonce.wrapping_add(1);
        *next_seq = next_seq.wrapping_add(1);
        let payload = build_overlay_payload(OVERLAY_DIRECTION_REQUEST, *next_nonce, *next_seq);
        let Some(packet) = build_udp_overlay_packet(local_vip, &virtual_ip, 39286, 39287, &payload)
        else {
            continue;
        };
        let sent_at = Instant::now();
        if controller.inject(packet).await.is_ok() {
            // The same task handles ingress only after this awaited send cycle.
            // Failed injections leave no matchable entry or eviction side effect.
            sent_nonces.insert(
                *next_nonce,
                SentOverlayNonce {
                    peer_id: peer_id.clone(),
                    generation,
                    seq: *next_seq,
                    sent_at,
                },
            );
            nonce_order.push_back(*next_nonce);
            while nonce_order.len() > OVERLAY_NONCE_CAP {
                if let Some(oldest) = nonce_order.pop_front() {
                    sent_nonces.remove(&oldest);
                }
            }
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
    start_gate_released: bool,
    seen: &mut VecDeque<(u64, u32)>,
    stats: &mut OverlayStats,
    peers: &Arc<PeerManager>,
    timeline: &Arc<ConnectionTimeline>,
    sent_nonces: &HashMap<u64, SentOverlayNonce>,
    bursts: &mut HashMap<String, OverlayBurst>,
    pending_echoes: &mut VecDeque<PendingOverlayEcho>,
    udp_transport: Option<&Arc<RwLock<Option<UdpTransport>>>>,
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
                    let direct_committed = committed_direct_ready_for_echo(
                        peers,
                        &peer_id,
                        event.connection_generation,
                    );
                    let direct_business_ready = direct_committed
                        && overlay_direct_business_budget_ready(udp_transport, &peer_id).await;
                    if start_gate_released && (overlay_any_path || direct_business_ready) {
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
                        if !start_gate_released {
                            info!(
                                event = "overlay_echo_deferred_until_start_gate",
                                peer = %peer_id,
                                generation = event.connection_generation,
                                seq = seq,
                                nonce = nonce,
                                "deferred overlay echo until the external validation start gate releases"
                            );
                        } else if !direct_committed {
                            info!(
                                event = "overlay_echo_deferred_until_direct_commit",
                                peer = %peer_id,
                                generation = event.connection_generation,
                                seq = seq,
                                nonce = nonce,
                                "deferred strict-Direct overlay echo until the local Direct path commits"
                            );
                        } else {
                            info!(
                                event = "overlay_echo_deferred_until_direct_business_budget",
                                peer = %peer_id,
                                generation = event.connection_generation,
                                seq = seq,
                                nonce = nonce,
                                "deferred strict-Direct overlay echo until the local Direct business budget is ready"
                            );
                        }
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
                            && sent.seq == seq
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
            // Burst tracking retains exact successful requests independently of
            // the 256-entry periodic registry, so larger bursts remain verifiable.
            if direction == OVERLAY_DIRECTION_ECHO {
                if let Some(burst) = bursts.get_mut(&peer_id) {
                    if let Some(index) = burst.nonces.iter().position(|sent| {
                        burst.fired_at.is_some()
                            && sent.nonce == nonce
                            && sent.seq == seq
                            && sent.generation == event.connection_generation
                            && sent.sent_at.elapsed() <= OVERLAY_NONCE_TTL
                    }) {
                        burst.nonces.swap_remove(index);
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
            reason: format!(
                "checksum mismatch: expected {expected_checksum:08x} got {actual_checksum:08x}"
            ),
        };
    }
    if seen
        .iter()
        .any(|&(seen_nonce, seen_seq)| seen_nonce == nonce && seen_seq == seq)
    {
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

        let manager = PeerManager::new({
            // This regression exercises the explicit legacy Auto policy.
            let mut config = Config::generate_default("http://ctrl.test", "default")
                .expect("test config must build");
            config.relay.path_policy = crate::config::PathPolicy::Auto;
            config
        });
        manager
            .add_peer(&PeerInfo {
                capabilities: crate::control::PeerCapabilities::default(),
                registration_seq: 0,
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
        tokio::time::timeout(Duration::from_secs(1), committed_path_changes.changed())
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
                capabilities: crate::control::PeerCapabilities::default(),
                registration_seq: 0,
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
            .mark_relay_transport_ready("peer-strict-direct-echo", "tcp://relay.test:443", 0)
            .await;
        assert!(
            manager
                .confirm_relay_peer("peer-strict-direct-echo", "tcp://relay.test:443", 0,)
                .await
        );

        let generation = manager.current_network_generation_sync();
        let (mut tun, controller) =
            p2pnet_tun::mock::MockTunDevice::new_pair("strict-direct-echo", 1420, "10.20.0.1");
        let mut pending = VecDeque::from([build_pending_overlay_echo(
            "10.20.0.1",
            "peer-strict-direct-echo".to_string(),
            "10.20.0.2".to_string(),
            generation,
            0x1234_5678_9abc_def0,
            42,
        )
        .expect("valid IPv4 addresses must build a pending echo")]);

        flush_pending_overlay_echoes(&controller, &manager, false, None, &mut pending).await;
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

        flush_pending_overlay_echoes(&controller, &manager, false, None, &mut pending).await;
        assert!(
            pending.is_empty(),
            "the Direct commit must release the echo"
        );

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
        let payload =
            build_overlay_payload(OVERLAY_DIRECTION_REQUEST, 0x1234_5678_9abc_def0u64, 42);
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

/// B01-ACK-01 local controls. These exercise actual MockTun send results and
/// the existing payload verifier/ingress handler, not WireGuard or Relay I/O.
#[cfg(test)]
mod ack01_exact_injection_tests {
    use super::*;
    use p2pnet_tun::VirtualInterface;

    const PEER: &str = "peer-ack01";
    const LOCAL_VIP: &str = "10.20.0.1";
    const PEER_VIP: &str = "10.20.0.2";
    const RELAY: &str = "tcp://relay.test:443";

    struct Fixture {
        peers: Arc<PeerManager>,
        tun: Option<p2pnet_tun::mock::MockTunDevice>,
        controller: MockTunController,
        timeline: Arc<ConnectionTimeline>,
        stats: OverlayStats,
        seen: VecDeque<(u64, u32)>,
        sent_nonces: HashMap<u64, SentOverlayNonce>,
        nonce_order: VecDeque<u64>,
        bursts: HashMap<String, OverlayBurst>,
        pending: VecDeque<PendingOverlayEcho>,
        next_nonce: u64,
        next_seq: u32,
    }

    impl Fixture {
        async fn new() -> Self {
            let mut config = Config::generate_default("http://ctrl.test", "default")
                .expect("test config must build");
            config.relay.path_policy = crate::config::PathPolicy::Auto;
            let peers = Arc::new(PeerManager::new(config));
            peers
                .add_peer(&crate::control::PeerInfo {
                    node_id: PEER.to_string(),
                    public_key: "pk".to_string(),
                    endpoint: "127.0.0.1:45003".to_string(),
                    nat_type: "Unknown".to_string(),
                    virtual_ip: PEER_VIP.to_string(),
                    online: true,
                    ..crate::control::PeerInfo::default()
                })
                .await;
            let generation = peers.current_network_generation_sync();
            peers
                .mark_relay_transport_ready(PEER, RELAY, generation)
                .await;
            assert!(peers.confirm_relay_peer(PEER, RELAY, generation).await);
            let (tun, controller) =
                p2pnet_tun::mock::MockTunDevice::new_pair("ack01", 1420, LOCAL_VIP);
            Self {
                peers,
                tun: Some(tun),
                controller,
                timeline: ConnectionTimeline::new("local-ack01", 1),
                stats: OverlayStats {
                    sent: 0,
                    received_valid: 0,
                    received_invalid: 0,
                    verified_round_trips: 0,
                    last_seq: 0,
                },
                seen: VecDeque::new(),
                sent_nonces: HashMap::new(),
                nonce_order: VecDeque::new(),
                bursts: HashMap::new(),
                pending: VecDeque::new(),
                next_nonce: 0x1000,
                next_seq: 10,
            }
        }

        fn event_count(&self, name: &str) -> usize {
            self.timeline
                .snapshot()
                .events
                .iter()
                .filter(|event| event.event == name)
                .count()
        }

        async fn inject_periodic(&mut self) -> u64 {
            send_overlay_payloads(
                &self.controller,
                &self.peers,
                LOCAL_VIP,
                true,
                None,
                &mut self.next_nonce,
                &mut self.next_seq,
                &mut self.stats,
                &mut self.sent_nonces,
                &mut self.nonce_order,
            )
            .await
        }

        fn arm_burst(&mut self) {
            // Existing isolated burst boundary; no first-usable claim is made.
            self.bursts.insert(
                PEER.to_string(),
                OverlayBurst {
                    armed: true,
                    nonces: Vec::new(),
                    sent: 0,
                    received: 0,
                    fired_at: None,
                },
            );
        }

        async fn inject_burst_attempts(&mut self, count: usize) {
            fire_pending_bursts(
                &self.controller,
                &self.peers,
                LOCAL_VIP,
                true,
                None,
                count,
                &mut self.next_nonce,
                &mut self.next_seq,
                &mut self.sent_nonces,
                &mut self.nonce_order,
                &mut self.bursts,
            )
            .await;
        }

        async fn read_requests(
            tun: &mut p2pnet_tun::mock::MockTunDevice,
            count: usize,
        ) -> Vec<(u64, u32)> {
            let mut requests = Vec::new();
            for _ in 0..count {
                let mut bytes = [0u8; 512];
                let size = tun.read(&mut bytes).await.expect("mock TUN stays open");
                let packet = p2pnet_tun::Ipv4Packet::new(&bytes[..size])
                    .expect("actual injected request remains IPv4");
                assert_eq!(packet.src_addr().to_string(), LOCAL_VIP);
                assert_eq!(packet.dst_addr().to_string(), PEER_VIP);
                let payload = &packet.payload()[8..];
                assert_eq!(&payload[..OVERLAY_MAGIC.len()], OVERLAY_MAGIC);
                assert_eq!(payload[6], OVERLAY_DIRECTION_REQUEST);
                let nonce = u64::from_be_bytes(payload[7..15].try_into().unwrap());
                let seq = u32::from_be_bytes(payload[15..19].try_into().unwrap());
                let checksum = u32::from_be_bytes(
                    payload[OVERLAY_CHECKSUM_OFFSET..OVERLAY_CHECKSUM_OFFSET + 4]
                        .try_into()
                        .unwrap(),
                );
                assert_eq!(
                    checksum,
                    crc32_business_payload(&payload[..OVERLAY_CHECKSUM_SPAN])
                );
                requests.push((nonce, seq));
            }
            requests
        }

        async fn take_one_request(&mut self) -> (u64, u32) {
            tokio::time::timeout(
                Duration::from_secs(1),
                Self::read_requests(self.tun.as_mut().expect("mock TUN stays open"), 1),
            )
            .await
            .expect("actual successful request must be readable")[0]
        }

        async fn inject_and_read_burst(&mut self, count: usize) -> Vec<(u64, u32)> {
            self.arm_burst();
            let mut tun = self.tun.take().expect("mock TUN stays open");
            // The real MockTun has only 256 slots. Drain concurrently for the
            // 257-packet control rather than pretending the queue is larger.
            let (_, requests) = tokio::time::timeout(Duration::from_secs(1), async {
                tokio::join!(
                    self.inject_burst_attempts(count),
                    Self::read_requests(&mut tun, count),
                )
            })
            .await
            .expect("bounded real burst injection/read must complete");
            self.tun = Some(tun);
            assert_eq!(self.bursts[PEER].sent, count as u64);
            requests
        }

        async fn echo(&mut self, nonce: u64, seq: u32) {
            let payload = build_overlay_payload(OVERLAY_DIRECTION_ECHO, nonce, seq);
            let packet = build_udp_overlay_packet(PEER_VIP, LOCAL_VIP, 39287, 39286, &payload)
                .expect("valid addresses must build an echo");
            // This is an explicit post-decrypt unit input. It proves no native
            // crypto/current-session/current-Relay/fault or system-TUN claim.
            handle_overlay_ingress(
                OverlayIngressEvent {
                    peer_id: PEER.to_string(),
                    packet,
                    ingress: OverlayIngress::Relay(RELAY.to_string()),
                    connection_generation: self.peers.current_network_generation_sync(),
                },
                &self.controller,
                LOCAL_VIP,
                "local-ack01",
                true,
                true,
                &mut self.seen,
                &mut self.stats,
                &self.peers,
                &self.timeline,
                &self.sent_nonces,
                &mut self.bursts,
                &mut self.pending,
                None,
            )
            .await;
        }
    }

    #[tokio::test]
    async fn periodic_wrong_sequence_cannot_confirm_then_exact_echo_can() {
        let mut fixture = Fixture::new().await;
        assert_eq!(fixture.inject_periodic().await, 1);
        let (nonce, seq) = fixture.take_one_request().await;
        fixture.echo(nonce, seq.wrapping_add(1)).await;
        assert_eq!(
            fixture.stats.received_valid, 1,
            "valid CRC/payload reached matching"
        );
        assert_eq!(
            fixture.event_count("first_usable_bidirectional_overlay_ms"),
            0,
            "B01_ACK_01_PERIODIC_SEQ: wrong seq must not confirm a local request"
        );
        fixture.echo(nonce, seq).await;
        assert_eq!(fixture.stats.received_valid, 2);
        assert_eq!(
            fixture.event_count("first_usable_bidirectional_overlay_ms"),
            1,
            "the same successful request's exact echo still confirms"
        );
    }

    #[tokio::test]
    async fn periodic_failed_injection_cannot_confirm_a_valid_echo() {
        let mut fixture = Fixture::new().await;
        drop(fixture.tun.take());
        assert!(
            fixture.controller.inject(vec![0x45]).await.is_err(),
            "real closed MockTun receiver proves injection failure"
        );
        assert_eq!(fixture.inject_periodic().await, 0);
        fixture.echo(fixture.next_nonce, fixture.next_seq).await;
        assert_eq!(
            fixture.stats.received_valid, 1,
            "valid CRC/payload reached matching"
        );
        assert_eq!(
            fixture.event_count("first_usable_bidirectional_overlay_ms"),
            0,
            "B01_ACK_01_PERIODIC_ERR: attempted but failed injection is not sent"
        );
        assert!(fixture.sent_nonces.is_empty());
        assert!(fixture.nonce_order.is_empty());
    }

    #[tokio::test]
    async fn burst_failed_injection_cannot_confirm_a_valid_echo() {
        let mut fixture = Fixture::new().await;
        fixture.arm_burst();
        drop(fixture.tun.take());
        assert!(fixture.controller.inject(vec![0x45]).await.is_err());
        fixture.inject_burst_attempts(1).await;
        assert_eq!(fixture.bursts[PEER].sent, 0);
        fixture.echo(fixture.next_nonce, fixture.next_seq).await;
        assert_eq!(
            fixture.stats.received_valid, 1,
            "valid CRC/payload reached matching"
        );
        assert_eq!(
            fixture.event_count("first_usable_bidirectional_overlay_ms"),
            0,
            "B01_ACK_01_BURST_ERR: failed burst injection is not sent"
        );
        assert_eq!(fixture.event_count("overlay_burst_complete"), 0);
        assert!(fixture.sent_nonces.is_empty());
        assert!(fixture.nonce_order.is_empty());
    }

    #[tokio::test]
    async fn burst_wrong_sequence_cannot_complete_then_exact_echo_can() {
        let mut fixture = Fixture::new().await;
        let requests = fixture.inject_and_read_burst(1).await;
        let (nonce, seq) = requests[0];
        fixture.echo(nonce, seq.wrapping_add(1)).await;
        assert_eq!(
            fixture.stats.received_valid, 1,
            "valid CRC/payload reached matching"
        );
        assert_eq!(
            fixture.event_count("overlay_burst_complete"),
            0,
            "B01_ACK_01_BURST_SEQ: wrong seq cannot complete the successful burst"
        );
        fixture.echo(nonce, seq).await;
        assert_eq!(fixture.event_count("overlay_burst_complete"), 1);
        assert!(!fixture.bursts.contains_key(PEER));
    }

    #[tokio::test]
    async fn burst_repeat_after_seen_eviction_cannot_replace_missing_echo() {
        let mut fixture = Fixture::new().await;
        let requests = fixture.inject_and_read_burst(2).await;
        let first = requests[0];
        fixture.echo(first.0, first.1).await;
        assert_eq!(fixture.bursts[PEER].received, 1);
        for index in 0..OVERLAY_SEEN_CAP {
            fixture
                .echo(0x9000 + index as u64, 0x9000 + index as u32)
                .await;
        }
        assert!(
            !fixture.seen.contains(&first),
            "real verifier evicted the first pair"
        );
        fixture.echo(first.0, first.1).await;
        assert_eq!(
            fixture.stats.received_valid,
            OVERLAY_SEEN_CAP as u64 + 2,
            "the repeat passed payload verification after actual seen eviction"
        );
        assert_eq!(
            fixture.event_count("overlay_burst_complete"),
            0,
            "B01_ACK_01_BURST_ONCE: one successful request cannot earn two credits"
        );
        assert_eq!(fixture.bursts[PEER].received, 1);
        fixture.echo(requests[1].0, requests[1].1).await;
        assert_eq!(
            fixture.event_count("overlay_burst_complete"),
            1,
            "only the second request's genuine exact echo completes the burst"
        );
    }

    #[tokio::test]
    async fn burst_larger_than_periodic_registry_keeps_exact_successes() {
        let mut fixture = Fixture::new().await;
        let requests = fixture.inject_and_read_burst(OVERLAY_NONCE_CAP + 1).await;
        assert_eq!(fixture.sent_nonces.len(), OVERLAY_NONCE_CAP);
        assert!(
            !fixture.sent_nonces.contains_key(&requests[0].0),
            "actual FIFO eviction occurred before any echo was handled"
        );
        for (nonce, seq) in requests {
            fixture.echo(nonce, seq).await;
        }
        assert_eq!(
            fixture.event_count("overlay_burst_complete"),
            1,
            "all 257 actual injected requests can complete despite registry eviction"
        );
        assert!(!fixture.bursts.contains_key(PEER));
    }

    #[tokio::test]
    async fn successful_request_expired_ttl_cannot_confirm_or_complete_burst() {
        let mut fixture = Fixture::new().await;
        let requests = fixture.inject_and_read_burst(1).await;
        let (nonce, seq) = requests[0];
        // Only the original request's age is controlled. Injection/read/CRC,
        // peer identity, generation and the open 20s burst window stay real.
        let expired = Instant::now()
            .checked_sub(OVERLAY_NONCE_TTL + Duration::from_secs(1))
            .expect("test Instant must support a past request timestamp");
        fixture
            .sent_nonces
            .get_mut(&nonce)
            .expect("actual injection registered")
            .sent_at = expired;
        let burst_request = fixture
            .bursts
            .get_mut(PEER)
            .expect("actual burst fired")
            .nonces
            .iter_mut()
            .find(|request| request.nonce == nonce)
            .expect("actual successful burst request retained");
        burst_request.sent_at = expired;
        assert!(expired.elapsed() > OVERLAY_NONCE_TTL);
        assert!(
            fixture.bursts[PEER]
                .fired_at
                .expect("actual burst fired")
                .elapsed()
                < OVERLAY_BURST_TIMEOUT,
            "20s overall timeout must still be open"
        );

        fixture.echo(nonce, seq).await;
        assert_eq!(
            fixture.stats.received_valid, 1,
            "exact echo still passes original packet/CRC/VIP verification"
        );
        assert_eq!(
            fixture.event_count("first_usable_bidirectional_overlay_ms"),
            0,
            "B01_ACK_01_TTL_FIRST: expired successful request cannot confirm"
        );
        assert_eq!(
            fixture.event_count("overlay_burst_complete"),
            0,
            "B01_ACK_01_TTL_BURST: expired successful request cannot complete burst"
        );
        assert_eq!(fixture.bursts[PEER].received, 0);

        // An independent real fresh injection/read proves that a broken
        // fixture/ingress path did not manufacture the negative result.
        let mut fresh = Fixture::new().await;
        let fresh_requests = fresh.inject_and_read_burst(1).await;
        fresh.echo(fresh_requests[0].0, fresh_requests[0].1).await;
        assert_eq!(
            fresh.event_count("first_usable_bidirectional_overlay_ms"),
            1
        );
        assert_eq!(fresh.event_count("overlay_burst_complete"), 1);
    }

    #[tokio::test]
    async fn advanced_generation_old_burst_cannot_count_current_generation_echo() {
        let mut fixture = Fixture::new().await;
        let requests = fixture.inject_and_read_burst(1).await;
        let (nonce, seq) = requests[0];
        let old_generation = fixture.peers.current_network_generation_sync();
        // Use the existing production transition API, not a test mirror or
        // rewriting the registry/event's stored generation to force a result.
        let generation = fixture
            .peers
            .advance_network_generation("ack01 supplemental old-burst control")
            .await;
        assert!(generation > old_generation);
        assert_eq!(fixture.peers.current_network_generation_sync(), generation);

        // Fixture::echo reads the actual current generation. The event clears
        // the handler's initial current-generation check and reaches matching.
        fixture.echo(nonce, seq).await;
        assert_eq!(
            fixture.stats.received_valid, 1,
            "current-generation old nonce/seq passed the payload verifier"
        );
        assert_eq!(
            fixture.event_count("first_usable_bidirectional_overlay_ms"),
            0,
            "B01_ACK_01_GEN_FIRST: old request cannot confirm in the new generation"
        );
        assert_eq!(
            fixture.event_count("overlay_burst_complete"),
            0,
            "B01_ACK_01_GEN_BURST: old burst cannot count a relabelled current event"
        );
        assert_eq!(fixture.bursts[PEER].received, 0);

        // Restore confirmation using the existing production API, then produce
        // a genuinely new request in that generation as a positive control.
        fixture
            .peers
            .mark_relay_transport_ready(PEER, RELAY, generation)
            .await;
        assert!(
            fixture
                .peers
                .confirm_relay_peer(PEER, RELAY, generation)
                .await
        );
        let fresh = fixture.inject_and_read_burst(1).await;
        assert_ne!(fresh[0], (nonce, seq));
        fixture.echo(fresh[0].0, fresh[0].1).await;
        assert_eq!(fixture.stats.received_valid, 2);
        assert_eq!(
            fixture.event_count("first_usable_bidirectional_overlay_ms"),
            1
        );
        assert_eq!(fixture.event_count("overlay_burst_complete"), 1);
    }

    #[tokio::test]
    async fn failed_periodic_and_burst_injection_preserve_full_successful_fifo() {
        let mut fixture = Fixture::new().await;
        let mut tun = fixture.tun.take().expect("mock TUN stays open");
        // Fill the real 256-entry successful registry, reading every real
        // injection. No fabricated registry entries or larger MockTun queue.
        let (_, requests) = tokio::time::timeout(Duration::from_secs(1), async {
            tokio::join!(
                async {
                    for _ in 0..OVERLAY_NONCE_CAP {
                        assert_eq!(fixture.inject_periodic().await, 1);
                    }
                },
                Fixture::read_requests(&mut tun, OVERLAY_NONCE_CAP),
            )
        })
        .await
        .expect("bounded real successful injection/read must complete");
        fixture.tun = Some(tun);
        assert_eq!(fixture.sent_nonces.len(), OVERLAY_NONCE_CAP);
        assert_eq!(fixture.nonce_order.len(), OVERLAY_NONCE_CAP);
        let fifo_before = fixture.nonce_order.clone();
        let oldest = requests[0];
        let original_request_time = fixture.sent_nonces[&oldest.0].sent_at;

        drop(fixture.tun.take());
        assert!(
            fixture.controller.inject(vec![0x45]).await.is_err(),
            "real closed receiver supplies injection Err"
        );
        assert_eq!(fixture.inject_periodic().await, 0);
        let failed_periodic = (fixture.next_nonce, fixture.next_seq);
        fixture.arm_burst();
        fixture.inject_burst_attempts(1).await;
        let failed_burst = (fixture.next_nonce, fixture.next_seq);
        assert_ne!(failed_periodic, failed_burst);
        assert_eq!(fixture.bursts[PEER].sent, 0);

        // The decisive oracle is external behavior of the oldest successful
        // request, which the old pre-Err registration would have evicted.
        assert!(
            original_request_time.elapsed() <= OVERLAY_NONCE_TTL,
            "retained-success control must remain within its original TTL"
        );
        fixture.echo(oldest.0, oldest.1).await;
        assert_eq!(
            fixture.stats.received_valid, 1,
            "oldest exact successful echo passes payload verification"
        );
        assert_eq!(
            fixture.event_count("first_usable_bidirectional_overlay_ms"),
            1,
            "B01_ACK_01_ERR_RETAIN: actual injection failures cannot evict success"
        );

        // State checks supplement the behavioral oracle: both failure sites
        // left the existing full FIFO unchanged and inserted no failed pair.
        assert_eq!(fixture.nonce_order, fifo_before);
        assert_eq!(fixture.sent_nonces.len(), OVERLAY_NONCE_CAP);
        assert!(!fixture.sent_nonces.contains_key(&failed_periodic.0));
        assert!(!fixture.sent_nonces.contains_key(&failed_burst.0));
        assert!(requests
            .iter()
            .all(|(nonce, _)| fixture.sent_nonces.contains_key(nonce)));
        fixture.echo(failed_periodic.0, failed_periodic.1).await;
        fixture.echo(failed_burst.0, failed_burst.1).await;
        assert_eq!(fixture.stats.received_valid, 3);
        assert_eq!(fixture.event_count("overlay_burst_complete"), 0);
    }
}
