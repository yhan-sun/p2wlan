//! Canonical original overlay requests and their actual MockTun injection.
//!
//! One Arc is retained by the existing periodic and burst views. Target life is
//! an expectation from the original committed path, never actual-key auth-L.
//! The original publication records historical send completion and this owner
//! holds the sole native ACK once; PeerManager qualifies current authority.

use std::collections::{HashMap, VecDeque};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Weak};
use std::time::Instant;

use p2pnet_tun::mock::MockTunController;
use p2pnet_tun::PacketReadContext;
use tokio::sync::RwLock;
use tracing::info;

use crate::peer::{CommittedBusinessPathSnapshot, PeerManager, PeerSessionGeneration};
use crate::udp::UdpTransport;
use crate::{
    build_overlay_payload, build_udp_overlay_packet, overlay_direct_business_budget_ready,
    overlay_validation_target_ready, OverlayBurst, OverlayStats, SentOverlayNonce,
    OVERLAY_DIRECTION_REQUEST, OVERLAY_EVIDENCE_PREFIX, OVERLAY_NONCE_CAP,
};

mod ack_credit;
mod echo_origin;
mod send_publication;
pub(crate) use ack_credit::{
    OriginalOverlayAck, OverlayCreditLockSite, OverlayCreditOutcome, OverlayCreditReceipt,
    OverlayCreditStale, OverlayCreditUnknown,
};
pub(crate) use echo_origin::{OriginalEchoInput, OriginalEchoPrewrite};
#[cfg(test)]
pub(crate) use send_publication::{PhysicalInputQualification, PhysicalPublicationState};
pub(crate) use send_publication::{
    PhysicalRequestPublisher, PhysicalSendPublication, PhysicalSendRecord,
    PreparedPhysicalPublication,
};

#[derive(Clone)]
struct OriginalTargetExpectation {
    owner: Weak<PeerManager>,
    lifecycle: Option<PeerSessionGeneration>,
}

impl OriginalTargetExpectation {
    fn capture(
        peers: &Arc<PeerManager>,
        peer: &CommittedBusinessPathSnapshot,
        generation: u64,
    ) -> Self {
        let lifecycle = peer
            .epoch
            .filter(|epoch| {
                peer.is_online_in_generation(generation)
                    && epoch.peer_session_generation != PeerSessionGeneration::UNBOUND
            })
            .map(|epoch| epoch.peer_session_generation);
        Self {
            owner: Arc::downgrade(peers),
            lifecycle,
        }
    }
}

/// Original request identity. It intentionally does not implement Clone:
/// retained views clone the Arc, never split or relabel the canonical object.
pub(crate) struct CanonicalOverlayRequest {
    pub(super) nonce: u64,
    pub(super) seq: u32,
    pub(super) peer_id: String,
    pub(super) generation: u64,
    /// The sole original creation time; the old diagnostic name is preserved.
    pub(super) sent_at: Instant,
    local_vip: String,
    target_vip: String,
    target: OriginalTargetExpectation,
    original_packet: Box<[u8]>,
    injection_accepted: AtomicBool,
    native_ack_credited: AtomicBool,
    pub(crate) physical_publication: PhysicalSendPublication,
}

// These immutable accessors support carriage and final qualification. They do
// not qualify current ownership, TTL, actual crypto or a physical send.
#[allow(dead_code)]
impl CanonicalOverlayRequest {
    pub(crate) fn expected_target_lifecycle(&self) -> Option<PeerSessionGeneration> {
        self.target.lifecycle
    }

    pub(crate) fn belongs_to(&self, peers: &Arc<PeerManager>) -> bool {
        Weak::ptr_eq(&self.target.owner, &Arc::downgrade(peers))
    }

    pub(crate) fn original_peer_owner(&self, peers: &PeerManager) -> Option<Weak<PeerManager>> {
        std::ptr::eq(self.target.owner.as_ptr(), peers).then(|| self.target.owner.clone())
    }

    pub(crate) fn local_vip(&self) -> &str {
        &self.local_vip
    }

    pub(crate) fn target_vip(&self) -> &str {
        &self.target_vip
    }

    pub(crate) fn original_packet(&self) -> &[u8] {
        &self.original_packet
    }

    pub(crate) fn injection_accepted(&self) -> bool {
        self.injection_accepted.load(Ordering::Acquire)
    }
}

/// Sealed Weak identity carried only by a genuine local request injection.
/// An arbitrary public Any value cannot construct this private field.
#[derive(Clone)]
pub(crate) struct RequestSendToken {
    request: Weak<CanonicalOverlayRequest>,
    echo: Option<Arc<OriginalEchoInput>>,
}

// Decoding only identifies the original record. The carriage consumer checks
// bytes/peer/VIP/owner/TTL separately; this grants no native ACK authority.
#[allow(dead_code)]
impl RequestSendToken {
    pub(crate) fn from_read_context(context: PacketReadContext) -> Option<Self> {
        context.downcast::<Self>().ok().map(|token| *token)
    }

    pub(crate) fn request(&self) -> Option<Arc<CanonicalOverlayRequest>> {
        self.request.upgrade()
    }

    pub(crate) fn echo(&self) -> Option<&Arc<OriginalEchoInput>> {
        self.echo.as_ref()
    }

    pub(crate) fn original_echo(input: OriginalEchoInput) -> Self {
        Self {
            request: Weak::new(),
            echo: Some(Arc::new(input)),
        }
    }
}

#[derive(Clone, Copy)]
enum RequestCreationTime {
    Now,
    #[cfg(test)]
    Fixed(Instant),
}

impl RequestCreationTime {
    fn at_mint(self) -> Instant {
        match self {
            Self::Now => Instant::now(),
            #[cfg(test)]
            Self::Fixed(instant) => instant,
        }
    }
}

#[allow(clippy::too_many_arguments)]
async fn inject_request(
    controller: &MockTunController,
    peer_id: &str,
    generation: u64,
    local_vip: &str,
    target_vip: &str,
    target: &OriginalTargetExpectation,
    nonce: u64,
    seq: u32,
    packet: Vec<u8>,
    creation_time: RequestCreationTime,
    #[cfg(test)] publication_gate: Option<&InjectionPublicationGate>,
) -> p2pnet_tun::Result<Arc<CanonicalOverlayRequest>> {
    let request = Arc::new(CanonicalOverlayRequest {
        nonce,
        seq,
        peer_id: peer_id.to_string(),
        generation,
        sent_at: creation_time.at_mint(),
        local_vip: local_vip.to_string(),
        target_vip: target_vip.to_string(),
        target: target.clone(),
        // The actual random packet is copied once; the original Vec moves to TUN.
        original_packet: packet.clone().into_boxed_slice(),
        injection_accepted: AtomicBool::new(false),
        native_ack_credited: AtomicBool::new(false),
        physical_publication: PhysicalSendPublication::new(),
    });
    let context = Box::new(RequestSendToken {
        request: Arc::downgrade(&request),
        echo: None,
    });
    controller.inject_with_context(packet, context).await?;
    #[cfg(test)]
    if let Some(gate) = publication_gate {
        gate.reached.notify_one();
        gate.release.notified().await;
    }
    request.injection_accepted.store(true, Ordering::Release);
    Ok(request)
}

/// Fire the original burst with production creation time at each real mint.
#[allow(clippy::too_many_arguments)]
pub(super) async fn fire_pending_bursts(
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
    fire_pending_bursts_with_creation_time(
        controller,
        peers,
        local_vip,
        overlay_any_path,
        udp_transport,
        burst_size,
        next_nonce,
        next_seq,
        sent_nonces,
        nonce_order,
        bursts,
        RequestCreationTime::Now,
    )
    .await;
}

/// Immutable negative-age fixture seam, before Arc construction and injection.
#[cfg(test)]
#[allow(clippy::too_many_arguments)]
pub(super) async fn fire_pending_bursts_at_for_test(
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
    created_at: Instant,
) {
    fire_pending_bursts_with_creation_time(
        controller,
        peers,
        local_vip,
        overlay_any_path,
        udp_transport,
        burst_size,
        next_nonce,
        next_seq,
        sent_nonces,
        nonce_order,
        bursts,
        RequestCreationTime::Fixed(created_at),
    )
    .await;
}

/// Fire the armed burst of one peer: inject `burst_size` fresh business
/// payloads and register every nonce (bounded registry + burst state).
#[allow(clippy::too_many_arguments)]
async fn fire_pending_bursts_with_creation_time(
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
    creation_time: RequestCreationTime,
) {
    let generation = peers.current_network_generation_sync();
    let virtual_ips: HashMap<String, (String, OriginalTargetExpectation)> = peers
        .committed_business_path_snapshots_sync()
        .into_iter()
        .filter(|peer| {
            peer.is_online_in_generation(generation)
                && peer.active_path().is_some()
                && (overlay_any_path
                    || peer.active_path() == Some(crate::peer::NetworkPath::Direct))
        })
        .map(|peer| {
            let target = OriginalTargetExpectation::capture(peers, &peer, generation);
            (peer.peer_id, (peer.virtual_ip, target))
        })
        .collect();
    let targets: Vec<(String, String, OriginalTargetExpectation)> = bursts
        .iter()
        .filter(|(_, burst)| burst.armed && burst.fired_at.is_none())
        .filter_map(|(peer_id, _)| {
            virtual_ips
                .get(peer_id)
                .cloned()
                .map(|(vip, target)| (peer_id.clone(), vip, target))
        })
        .collect();
    for (peer_id, virtual_ip, target) in targets {
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
            if let Ok(request) = inject_request(
                controller,
                &peer_id,
                generation,
                local_vip,
                &virtual_ip,
                &target,
                nonce,
                seq,
                packet,
                creation_time,
                #[cfg(test)]
                None,
            )
            .await
            {
                // Register only real inject Ok. Both retained views name the
                // same canonical object, including its original target life.
                sent_nonces.insert(nonce, request.clone());
                nonce_order.push_back(nonce);
                while nonce_order.len() > OVERLAY_NONCE_CAP {
                    if let Some(oldest) = nonce_order.pop_front() {
                        sent_nonces.remove(&oldest);
                    }
                }
                nonces.push(request);
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
pub(super) async fn send_overlay_payloads(
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
    send_overlay_payloads_inner(
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
        #[cfg(test)]
        None,
    )
    .await
}

#[cfg(test)]
pub(crate) struct InjectionPublicationGate {
    pub(crate) reached: tokio::sync::Notify,
    pub(crate) release: tokio::sync::Notify,
}

#[cfg(test)]
impl InjectionPublicationGate {
    pub(crate) fn new() -> Self {
        Self {
            reached: tokio::sync::Notify::new(),
            release: tokio::sync::Notify::new(),
        }
    }
}

/// A bounded test owns this gate; production has no gate or pause mechanism.
#[cfg(test)]
#[allow(clippy::too_many_arguments)]
pub(super) async fn send_overlay_payloads_with_publication_gate_for_test(
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
    publication_gate: &InjectionPublicationGate,
) -> u64 {
    send_overlay_payloads_inner(
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
        Some(publication_gate),
    )
    .await
}

#[allow(clippy::too_many_arguments)]
async fn send_overlay_payloads_inner(
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
    #[cfg(test)] publication_gate: Option<&InjectionPublicationGate>,
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
        // Preserve this original target before either readiness/budget await.
        let target = OriginalTargetExpectation::capture(peers, &peer, generation);
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
        if let Ok(request) = inject_request(
            controller,
            &peer_id,
            generation,
            local_vip,
            &virtual_ip,
            &target,
            *next_nonce,
            *next_seq,
            packet,
            RequestCreationTime::Now,
            #[cfg(test)]
            publication_gate,
        )
        .await
        {
            // A failed real injection still changes no retained success/FIFO.
            sent_nonces.insert(*next_nonce, request);
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
