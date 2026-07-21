//! UDP transport for encrypted peer packets.
//!
//! The WireGuard adapter produces serialized transport messages keyed by peer
//! ID. This module is the direct UDP sink: it resolves each peer endpoint from
//! `PeerManager` and sends the encrypted datagram to that socket address.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use p2pnet_nat::{
    build_authenticated_punch_ack, build_authenticated_punch_packet, build_punch_ack,
    build_punch_packet, candidate_report_from_observations, decode_authenticated_punch_packet,
    decode_punch_packet, gather_candidate_report, peek_authenticated_punch_identity,
    CandidateGatherReport, IceConfig, PunchPacketKind, StunAttribute, StunMessage, StunObservation,
    BINDING_RESPONSE, MAGIC_COOKIE,
};
use tokio::net::UdpSocket;
use tokio::sync::{mpsc, oneshot, Mutex};
use tokio::time::{interval, sleep, timeout};
use tracing::{debug, trace, warn};

use crate::error::{DaemonError, Result};
use crate::peer::{PeerManager, REASON_DIRECT_SEND_FAILED};
use crate::transport::{EncryptedPeerPacket, ReceivedEncryptedPacket};

type ProbeNonce = [u8; 8];
type PendingProbes = Arc<Mutex<HashMap<ProbeNonce, PendingProbe>>>;
type StunTransactionId = [u8; 12];
type StunResponse = (Vec<u8>, SocketAddr);
type StunWaiters = Arc<Mutex<HashMap<StunTransactionId, oneshot::Sender<StunResponse>>>>;
const DIRECT_KEEPALIVE_ACK_TIMEOUT: Duration = Duration::from_secs(2);

#[derive(Debug, Clone)]
struct PendingProbe {
    sent_at: Instant,
    endpoint: SocketAddr,
    generation: u64,
    peer_id: Option<String>,
    authenticated: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ProbeScheduleRound {
    delay_before: Duration,
    endpoints: Vec<SocketAddr>,
}

fn build_probe_schedule(
    candidates: &[SocketAddr],
    probe_interval: Duration,
    attempts: u32,
) -> Vec<ProbeScheduleRound> {
    if candidates.is_empty() || attempts == 0 {
        return Vec::new();
    }

    let mut unique = Vec::new();
    for candidate in candidates {
        if !unique.contains(candidate) {
            unique.push(*candidate);
        }
    }

    (0..attempts)
        .map(|round| {
            let is_final_round = round + 1 == attempts;
            let width = if attempts == 1 || is_final_round {
                unique.len()
            } else if round == 0 {
                unique.len().min(2)
            } else if round == 1 {
                unique.len().min(4)
            } else {
                unique.len()
            };

            ProbeScheduleRound {
                delay_before: probe_round_delay(round, probe_interval),
                endpoints: unique.iter().take(width).copied().collect(),
            }
        })
        .filter(|round| !round.endpoints.is_empty())
        .collect()
}

fn probe_round_delay(round: u32, probe_interval: Duration) -> Duration {
    if round == 0 || probe_interval.is_zero() {
        return Duration::ZERO;
    }

    let burst_delay = match round {
        1 => Duration::from_millis(60),
        2 => Duration::from_millis(140),
        _ => probe_interval,
    };

    burst_delay.min(probe_interval)
}

/// Sends encrypted WireGuard packets over direct UDP endpoints.
#[derive(Clone)]
pub struct UdpTransport {
    socket: Arc<UdpSocket>,
    peers: Arc<PeerManager>,
    pending_probes: PendingProbes,
    stun_waiters: StunWaiters,
    local_node_id: Option<String>,
}

impl UdpTransport {
    /// Bind a UDP socket for direct peer traffic.
    pub async fn bind(bind_addr: SocketAddr, peers: Arc<PeerManager>) -> Result<Self> {
        let socket = UdpSocket::bind(bind_addr).await.map_err(|e| {
            DaemonError::Network(format!("failed to bind UDP socket at {bind_addr}: {e}"))
        })?;

        Ok(Self {
            socket: Arc::new(socket),
            peers,
            pending_probes: Arc::new(Mutex::new(HashMap::new())),
            stun_waiters: Arc::new(Mutex::new(HashMap::new())),
            local_node_id: None,
        })
    }

    /// Attach the local control-plane node ID used by authenticated UDP Probe v2.
    pub fn with_local_node_id(mut self, node_id: impl Into<String>) -> Self {
        self.local_node_id = Some(node_id.into());
        self
    }

    async fn send_probe(&self, peer_id: Option<&str>, peer_addr: SocketAddr) -> Result<ProbeNonce> {
        let generation = self.peers.current_network_generation().await;
        let authenticated_probe = match (peer_id, self.local_node_id.as_deref()) {
            (Some(peer_id), Some(local_node_id))
                if local_node_id.len() <= u8::MAX as usize && peer_id.len() <= u8::MAX as usize =>
            {
                self.peers.probe_key_for_peer(peer_id).await.map(|key| {
                    let (bytes, nonce) =
                        build_authenticated_punch_packet(local_node_id, peer_id, generation, &key);
                    (bytes, nonce)
                })
            }
            _ => None,
        };

        let (bytes, nonce, authenticated) = if let Some((bytes, nonce)) = authenticated_probe {
            (bytes, nonce, true)
        } else {
            let bytes = build_punch_packet();
            let nonce = decode_punch_packet(&bytes)
                .map(|packet| packet.nonce)
                .ok_or_else(|| DaemonError::Network("failed to create UDP probe".to_string()))?;
            (bytes.to_vec(), nonce, false)
        };

        {
            let mut pending = self.pending_probes.lock().await;
            pending.retain(|_, pending| {
                pending.sent_at.elapsed() < Duration::from_secs(60)
                    && pending.generation == generation
            });
            pending.insert(
                nonce,
                PendingProbe {
                    sent_at: Instant::now(),
                    endpoint: peer_addr,
                    generation,
                    peer_id: peer_id.map(str::to_string),
                    authenticated,
                },
            );
        }

        if let Err(error) = self.socket.send_to(&bytes, peer_addr).await {
            self.pending_probes.lock().await.remove(&nonce);
            return Err(DaemonError::Network(format!(
                "UDP probe send to {peer_addr} failed: {error}"
            )));
        }
        Ok(nonce)
    }

    /// Return the local UDP socket address.
    pub fn local_addr(&self) -> Result<SocketAddr> {
        self.socket
            .local_addr()
            .map_err(|e| DaemonError::Network(format!("failed to read UDP local addr: {e}")))
    }

    /// Gather ICE-style candidate endpoints for this UDP socket.
    pub async fn gather_candidates(
        &self,
        stun_servers: Vec<SocketAddr>,
        stun_timeout: Duration,
    ) -> Result<Vec<String>> {
        let report = self
            .gather_candidate_report(stun_servers, stun_timeout)
            .await?;

        Ok(report
            .candidates
            .into_iter()
            .map(|candidate| candidate.endpoint.to_string())
            .collect())
    }

    /// Gather ICE-style candidates plus STUN/NAT behavior diagnostics.
    pub async fn gather_candidate_report(
        &self,
        stun_servers: Vec<SocketAddr>,
        stun_timeout: Duration,
    ) -> Result<CandidateGatherReport> {
        let config = IceConfig {
            stun_servers,
            stun_timeout,
            gather_host: true,
            gather_srflx: true,
        };

        gather_candidate_report(&self.socket, &config)
            .await
            .map_err(|e| DaemonError::Network(format!("ICE candidate gathering failed: {e}")))
    }

    /// Gather candidates while `run_inbound` owns all reads from the UDP socket.
    pub async fn gather_candidate_report_live(
        &self,
        stun_servers: Vec<SocketAddr>,
        stun_timeout: Duration,
    ) -> Result<CandidateGatherReport> {
        let local_addr = self.local_addr()?;
        let mut observations = Vec::with_capacity(stun_servers.len());

        for server in stun_servers {
            if server.is_ipv4() != local_addr.is_ipv4() {
                continue;
            }
            observations.push(self.query_stun_live(server, stun_timeout).await);
        }

        Ok(candidate_report_from_observations(
            local_addr,
            true,
            observations,
        ))
    }

    async fn query_stun_live(&self, server: SocketAddr, stun_timeout: Duration) -> StunObservation {
        let started = Instant::now();
        let mut request = StunMessage::binding_request();
        request.add_attribute(StunAttribute::Software("P2WLAN/0.1".to_string()));
        let transaction_id = request.transaction_id;
        let encoded = request.encode();
        let (response_tx, response_rx) = oneshot::channel();

        self.stun_waiters
            .lock()
            .await
            .insert(transaction_id, response_tx);

        let result = async {
            self.socket
                .send_to(&encoded, server)
                .await
                .map_err(|error| format!("send_to failed: {error}"))?;
            let (data, source) = timeout(stun_timeout, response_rx)
                .await
                .map_err(|_| format!("no response from {server} after {stun_timeout:?}"))?
                .map_err(|_| "STUN response dispatcher closed".to_string())?;
            if source != server {
                return Err(format!(
                    "response source mismatch: expected {server}, received {source}"
                ));
            }
            let response = StunMessage::decode(&data)
                .map_err(|error| format!("invalid STUN response: {error}"))?;
            if response.transaction_id != transaction_id {
                return Err("STUN transaction ID mismatch".to_string());
            }
            if response.msg_type != BINDING_RESPONSE {
                if let Some((code, reason)) = response.get_error_code() {
                    return Err(format!("STUN error response: {code} {reason}"));
                }
                return Err(format!(
                    "unexpected STUN message type: 0x{:04X}",
                    response.msg_type
                ));
            }
            response
                .get_reflexive_address()
                .ok_or_else(|| "STUN response has no mapped address".to_string())
        }
        .await;

        self.stun_waiters.lock().await.remove(&transaction_id);
        match result {
            Ok(mapped_address) => StunObservation {
                server: server.to_string(),
                mapped_address: Some(mapped_address.to_string()),
                rtt_ms: Some(started.elapsed().as_millis().try_into().unwrap_or(u64::MAX)),
                error: None,
            },
            Err(error) => StunObservation {
                server: server.to_string(),
                mapped_address: None,
                rtt_ms: None,
                error: Some(error),
            },
        }
    }

    /// Send active UDP probes to every candidate for a peer.
    pub async fn punch_candidates(
        &self,
        peer_id: &str,
        candidates: Vec<SocketAddr>,
        probe_interval: Duration,
        attempts: u32,
    ) -> Result<u32> {
        if candidates.is_empty() || attempts == 0 {
            return Ok(0);
        }

        let schedule = build_probe_schedule(&candidates, probe_interval, attempts);
        trace!(
            "Built adaptive UDP probe schedule for peer {}: {} rounds across {} candidates",
            peer_id,
            schedule.len(),
            candidates.len()
        );

        let mut packets_sent = 0;
        for (round_index, round) in schedule.iter().enumerate() {
            if !round.delay_before.is_zero() {
                sleep(round.delay_before).await;
            }

            for &candidate in &round.endpoints {
                match self.send_probe(Some(peer_id), candidate).await {
                    Ok(_) => {
                        packets_sent += 1;
                        trace!(
                            "Sent adaptive punch probe round {} to peer {} candidate {}",
                            round_index + 1,
                            peer_id,
                            candidate
                        );
                    }
                    Err(err) => {
                        debug!(
                            "Failed to send punch probe to peer {} candidate {}: {}",
                            peer_id, candidate, err
                        );
                    }
                }
            }
        }

        Ok(packets_sent)
    }

    /// Send a single encrypted packet.
    ///
    /// Returns `Ok(Some(bytes))` when sent, `Ok(None)` when no endpoint is known
    /// for the destination peer, and `Err` for socket-level failures.
    pub async fn send_packet(&self, packet: &EncryptedPeerPacket) -> Result<Option<usize>> {
        let Some(endpoint) = self.peers.direct_endpoint_for_send(&packet.peer_id).await else {
            trace!(
                "No UDP endpoint for {}; dropping {} byte encrypted packet",
                packet.peer_id,
                packet.wire_bytes.len()
            );
            return Ok(None);
        };

        self.send_packet_to(packet, endpoint).await.map(Some)
    }

    /// Send a single encrypted packet to a selector-provided direct endpoint.
    pub async fn send_packet_to(
        &self,
        packet: &EncryptedPeerPacket,
        endpoint: SocketAddr,
    ) -> Result<usize> {
        let sent = self
            .socket
            .send_to(&packet.wire_bytes, endpoint)
            .await
            .map_err(|e| {
                DaemonError::Network(format!(
                    "UDP send to {} for peer {} failed: {}",
                    endpoint, packet.peer_id, e
                ))
            })?;

        if sent != packet.wire_bytes.len() {
            return Err(DaemonError::Network(format!(
                "short UDP send to {} for peer {}: sent {} of {} bytes",
                endpoint,
                packet.peer_id,
                sent,
                packet.wire_bytes.len()
            )));
        }

        debug!(
            "Sent {} encrypted bytes to peer {} at {} (dst={})",
            sent, packet.peer_id, endpoint, packet.dst_ip
        );
        Ok(sent)
    }

    /// Consume encrypted packets until the channel closes.
    pub async fn run_outbound(self, mut encrypted_rx: mpsc::Receiver<EncryptedPeerPacket>) {
        while let Some(packet) = encrypted_rx.recv().await {
            match self.send_packet(&packet).await {
                Ok(Some(_)) => {}
                Ok(None) => {
                    debug!(
                        "Encrypted packet for peer {} has no UDP endpoint yet",
                        packet.peer_id
                    );
                }
                Err(err) => {
                    warn!("UDP transport send failed: {err}");
                }
            }
        }
    }

    /// Periodically refresh direct UDP NAT mappings.
    pub async fn run_keepalives(self, keepalive_interval: Duration) {
        if keepalive_interval.is_zero() {
            return;
        }

        let mut ticker = interval(keepalive_interval);
        loop {
            ticker.tick().await;

            self.run_keepalive_round(DIRECT_KEEPALIVE_ACK_TIMEOUT).await;
        }
    }

    async fn run_keepalive_round(&self, ack_timeout: Duration) {
        let mut sent = Vec::new();

        for (peer_id, endpoint) in self.peers.direct_endpoints().await {
            match self.send_probe(Some(&peer_id), endpoint).await {
                Ok(nonce) => {
                    trace!("Sent direct UDP keepalive to peer {peer_id} at {endpoint}");
                    sent.push((peer_id, endpoint, nonce));
                }
                Err(err) => {
                    self.peers
                        .record_direct_failure_with_code(
                            &peer_id,
                            REASON_DIRECT_SEND_FAILED,
                            format!("direct keepalive to {endpoint} failed: {err}"),
                        )
                        .await;
                    debug!(
                        "Failed to send direct UDP keepalive to peer {peer_id} at {endpoint}: {err}"
                    );
                }
            }
        }

        if sent.is_empty() {
            return;
        }

        sleep(ack_timeout).await;
        for (peer_id, endpoint, nonce) in sent {
            let unanswered = self.pending_probes.lock().await.remove(&nonce);
            let Some(pending) = unanswered else {
                continue;
            };
            if pending.peer_id.as_deref() != Some(peer_id.as_str()) || pending.endpoint != endpoint
            {
                continue;
            }

            if self
                .peers
                .record_direct_keepalive_timeout_for_generation(
                    &peer_id,
                    endpoint,
                    pending.generation,
                )
                .await
            {
                debug!("Direct UDP keepalive ACK timed out for peer {peer_id} at {endpoint}");
            }
        }
    }

    /// Receive encrypted UDP datagrams until the socket or channel closes.
    pub async fn run_inbound(
        self,
        inbound_tx: mpsc::Sender<ReceivedEncryptedPacket>,
    ) -> Result<()> {
        let mut buf = vec![0u8; 65_535];

        loop {
            let (n, source) = match self.socket.recv_from(&mut buf).await {
                Ok(packet) => packet,
                Err(err) if is_ignorable_udp_receive_error(&err) => {
                    debug!("Ignoring transient UDP receive error on direct transport: {err}");
                    continue;
                }
                Err(err) => {
                    return Err(DaemonError::Network(format!(
                        "UDP receive on direct transport failed: {err}"
                    )));
                }
            };

            if n == 0 {
                continue;
            }

            let data = &buf[..n];

            if let Some(transaction_id) = stun_transaction_id(data) {
                let waiter = self.stun_waiters.lock().await.remove(&transaction_id);
                if let Some(waiter) = waiter {
                    let _ = waiter.send((data.to_vec(), source));
                } else {
                    trace!("Ignored unmatched STUN response from {source}");
                }
                continue;
            }

            if is_authenticated_punch_candidate(data) {
                let Some(identity) = peek_authenticated_punch_identity(data) else {
                    trace!("Ignored malformed authenticated UDP probe from {source}");
                    continue;
                };
                let Some(local_node_id) = self.local_node_id.as_deref() else {
                    trace!(
                        "Ignored authenticated UDP probe from {source}; local node ID is unknown"
                    );
                    continue;
                };
                if identity.target_node_id != local_node_id {
                    trace!(
                        "Ignored authenticated UDP probe from {} for target {}",
                        identity.source_node_id,
                        identity.target_node_id
                    );
                    continue;
                }
                let Some(key) = self
                    .peers
                    .probe_key_for_peer(&identity.source_node_id)
                    .await
                else {
                    trace!(
                        "Ignored authenticated UDP probe from {}; no Probe v2 MAC key",
                        identity.source_node_id
                    );
                    continue;
                };
                let Some(packet) = decode_authenticated_punch_packet(data, &key) else {
                    trace!(
                        "Ignored authenticated UDP probe from {}; invalid MAC",
                        identity.source_node_id
                    );
                    continue;
                };

                match packet.kind {
                    PunchPacketKind::Punch => {
                        let learned = self
                            .peers
                            .learn_authenticated_endpoint(&identity.source_node_id, source)
                            .await;
                        if !learned {
                            trace!(
                                "Ignored authenticated UDP punch from {}; peer disappeared before endpoint learning",
                                identity.source_node_id
                            );
                            continue;
                        }
                        self.peers
                            .record_direct_probe_success(&identity.source_node_id, source)
                            .await;

                        let generation = self.peers.current_network_generation().await;
                        let ack = build_authenticated_punch_ack(
                            packet.nonce,
                            local_node_id,
                            &identity.source_node_id,
                            generation,
                            &key,
                        );
                        match self.socket.send_to(&ack, source).await {
                            Ok(_) => {
                                debug!(
                                    "Received authenticated UDP punch from peer {} at {}; sent ACK",
                                    identity.source_node_id, source
                                );
                            }
                            Err(err) => warn!(
                                "Failed to ACK authenticated UDP punch from peer {} at {}: {}",
                                identity.source_node_id, source, err
                            ),
                        }
                    }
                    PunchPacketKind::Ack => {
                        let ack_match = {
                            let generation = self.peers.current_network_generation().await;
                            let mut pending = self.pending_probes.lock().await;
                            pending
                                .remove(&packet.nonce)
                                .filter(|pending| {
                                    pending.generation == generation
                                        && pending.peer_id.as_deref()
                                            == Some(identity.source_node_id.as_str())
                                        && pending.authenticated
                                })
                                .map(|pending| (pending.sent_at.elapsed(), pending.generation))
                        };

                        if let Some((latency, generation)) = ack_match {
                            self.peers
                                .learn_authenticated_endpoint(&identity.source_node_id, source)
                                .await;
                            let accepted = self
                                .peers
                                .record_direct_probe_success_with_latency_for_generation(
                                    &identity.source_node_id,
                                    source,
                                    Some(latency),
                                    generation,
                                )
                                .await;
                            if accepted {
                                debug!(
                                    "Received authenticated UDP punch ACK from peer {} at {} (rtt={latency:?})",
                                    identity.source_node_id, source
                                );
                            } else {
                                trace!(
                                    "Ignored stale authenticated UDP punch ACK from peer {} at {}",
                                    identity.source_node_id,
                                    source
                                );
                            }
                        } else {
                            trace!(
                                "Ignored unmatched authenticated UDP punch ACK from peer {} at {}",
                                identity.source_node_id,
                                source
                            );
                        }
                    }
                }
                continue;
            }

            if let Some(packet) = decode_punch_packet(data) {
                match packet.kind {
                    PunchPacketKind::Punch => {
                        let ack = build_punch_ack(packet.nonce);
                        match self.socket.send_to(&ack, source).await {
                            Ok(_) => {
                                debug!("Received UDP punch from {source}; sent ACK");
                                if let Some(peer_id) =
                                    self.peers.learn_endpoint_from_addr(source).await
                                {
                                    self.peers
                                        .record_direct_probe_success(&peer_id, source)
                                        .await;
                                    debug!(
                                        "Recorded direct UDP probe success from peer {peer_id} at {source}"
                                    );
                                }
                            }
                            Err(err) => warn!("Failed to ACK UDP punch from {source}: {err}"),
                        }
                    }
                    PunchPacketKind::Ack => {
                        let ack_match = {
                            let generation = self.peers.current_network_generation().await;
                            let mut pending = self.pending_probes.lock().await;
                            pending
                                .remove(&packet.nonce)
                                .filter(|pending| {
                                    pending.endpoint == source
                                        && pending.generation == generation
                                        && !pending.authenticated
                                })
                                .map(|pending| (pending.sent_at.elapsed(), pending.generation))
                        };
                        if let Some(peer_id) = self.peers.learn_endpoint_from_addr(source).await {
                            if let Some((latency, generation)) = ack_match {
                                let accepted = self
                                    .peers
                                    .record_direct_probe_success_with_latency_for_generation(
                                        &peer_id,
                                        source,
                                        Some(latency),
                                        generation,
                                    )
                                    .await;
                                if accepted {
                                    debug!(
                                        "Received UDP punch ACK from peer {peer_id} at {source} (rtt={latency:?})"
                                    );
                                } else {
                                    trace!(
                                        "Ignored stale UDP punch ACK from peer {peer_id} at {source}"
                                    );
                                }
                            } else {
                                trace!("Ignored stale or unmatched UDP punch ACK from {source}");
                            }
                        } else {
                            trace!("Received UDP punch ACK from unknown candidate {source}");
                        }
                    }
                }
                continue;
            }

            if let Some(peer_id) = self.peers.learn_endpoint_from_addr(source).await {
                trace!("Learned encrypted UDP source {source} for peer {peer_id}");
            }

            inbound_tx
                .send(ReceivedEncryptedPacket {
                    source: Some(source),
                    relay_endpoint: None,
                    relay_peer_id: None,
                    wire_bytes: data.to_vec(),
                })
                .await
                .map_err(|_| {
                    DaemonError::Network("received encrypted packet channel closed".to_string())
                })?;

            debug!("Received {n} encrypted UDP bytes from {source}");
        }
    }
}

fn is_ignorable_udp_receive_error(error: &std::io::Error) -> bool {
    #[cfg(target_os = "windows")]
    {
        error.raw_os_error() == Some(10054) || error.kind() == std::io::ErrorKind::ConnectionReset
    }

    #[cfg(not(target_os = "windows"))]
    {
        let _ = error;
        false
    }
}

fn is_authenticated_punch_candidate(data: &[u8]) -> bool {
    data.len() >= 5 && data.starts_with(&[0x50, 0x4e, 0x43, 0x48]) && data[4] == 2
}

fn stun_transaction_id(data: &[u8]) -> Option<StunTransactionId> {
    if data.len() < 20 || data[0] & 0xc0 != 0 {
        return None;
    }
    if u32::from_be_bytes(data[4..8].try_into().ok()?) != MAGIC_COOKIE {
        return None;
    }
    let declared_len = u16::from_be_bytes(data[2..4].try_into().ok()?) as usize;
    if data.len() < 20 + declared_len {
        return None;
    }
    data[8..20].try_into().ok()
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;
    use std::time::Duration;

    use p2pnet_crypto::NodeIdentity;
    use p2pnet_tun::{Ipv4Packet, MockTunDevice};
    use p2pnet_wireguard::{HandshakeInitiator, HandshakeResponder, TransportSession};
    use tokio::sync::mpsc;
    use tokio::time::timeout;

    use super::*;
    use crate::config::Config;
    use crate::control::PeerInfo;
    use crate::dataplane::DataPlane;
    use crate::peer::ConnectionState;
    use crate::transport::WireGuardTransport;

    fn peer(node_id: &str, virtual_ip: &str, endpoint: Option<SocketAddr>) -> PeerInfo {
        PeerInfo {
            node_id: node_id.to_string(),
            device_name: String::new(),
            public_key: "pk".to_string(),
            endpoint: endpoint.map(|addr| addr.to_string()).unwrap_or_default(),
            nat_type: "FullCone".to_string(),
            virtual_ip: virtual_ip.to_string(),
            online: true,
            last_seen: 0,
        }
    }

    fn peer_with_public_key(
        node_id: &str,
        virtual_ip: &str,
        public_key: String,
        endpoint: Option<SocketAddr>,
    ) -> PeerInfo {
        PeerInfo {
            node_id: node_id.to_string(),
            device_name: String::new(),
            public_key,
            endpoint: endpoint.map(|addr| addr.to_string()).unwrap_or_default(),
            nat_type: "Unknown".to_string(),
            virtual_ip: virtual_ip.to_string(),
            online: true,
            last_seen: 0,
        }
    }

    fn peer_manager() -> Arc<PeerManager> {
        Arc::new(PeerManager::new(
            Config::generate_default("http://ctrl.test", "default").unwrap(),
        ))
    }

    fn config_for_identity(identity: &NodeIdentity, node_id: &str) -> Config {
        let mut config = Config::generate_default("http://ctrl.test", "default").unwrap();
        config.node.node_id = node_id.to_string();
        config.node.public_key = hex::encode(identity.public_key());
        config.node.private_key = hex::encode(identity.private_key());
        config
    }

    #[test]
    fn adaptive_probe_schedule_covers_all_candidates_on_final_round() {
        let candidates = vec![
            "127.0.0.1:10001".parse().unwrap(),
            "127.0.0.1:10002".parse().unwrap(),
            "127.0.0.1:10003".parse().unwrap(),
            "127.0.0.1:10004".parse().unwrap(),
            "127.0.0.1:10005".parse().unwrap(),
        ];

        let schedule = build_probe_schedule(&candidates, Duration::from_millis(200), 3);

        assert_eq!(schedule.len(), 3);
        assert_eq!(schedule[0].delay_before, Duration::ZERO);
        assert_eq!(schedule[0].endpoints, candidates[..2]);
        assert_eq!(schedule[1].delay_before, Duration::from_millis(60));
        assert_eq!(schedule[1].endpoints, candidates[..4]);
        assert_eq!(schedule[2].delay_before, Duration::from_millis(140));
        assert_eq!(schedule[2].endpoints, candidates);
    }

    #[test]
    fn adaptive_probe_schedule_preserves_single_attempt_full_coverage() {
        let candidates = vec![
            "127.0.0.1:11001".parse().unwrap(),
            "127.0.0.1:11002".parse().unwrap(),
            "127.0.0.1:11001".parse().unwrap(),
        ];

        let schedule = build_probe_schedule(&candidates, Duration::from_millis(200), 1);

        assert_eq!(schedule.len(), 1);
        assert_eq!(schedule[0].delay_before, Duration::ZERO);
        assert_eq!(
            schedule[0].endpoints,
            vec![
                "127.0.0.1:11001".parse().unwrap(),
                "127.0.0.1:11002".parse().unwrap(),
            ]
        );
    }

    fn establish_sessions() -> (TransportSession, TransportSession) {
        let node_a = NodeIdentity::generate();
        let node_b = NodeIdentity::generate();

        let mut initiator = HandshakeInitiator::new(node_a, node_b.public_key(), None);
        let mut responder = HandshakeResponder::new(node_b, None);

        let init = initiator.create_initiation().unwrap();
        let (response, node_b_keys) = responder.consume_initiation_and_respond(&init).unwrap();
        let node_a_keys = initiator.consume_response(&response).unwrap();

        (
            TransportSession::new(node_a_keys),
            TransportSession::new(node_b_keys),
        )
    }

    #[tokio::test]
    async fn gathers_host_candidates_for_bound_udp_port() {
        let peers = peer_manager();
        let transport = UdpTransport::bind("127.0.0.1:0".parse().unwrap(), peers)
            .await
            .unwrap();
        let local_port = transport.local_addr().unwrap().port();

        let candidates = transport
            .gather_candidates(Vec::new(), Duration::from_millis(100))
            .await
            .unwrap();

        assert!(!candidates.is_empty());
        assert!(candidates
            .iter()
            .any(|candidate| candidate.ends_with(&format!(":{local_port}"))));
    }

    #[tokio::test]
    async fn punch_candidates_sends_probe_datagrams() {
        let receiver = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let receiver_addr = receiver.local_addr().unwrap();

        let peers = peer_manager();
        let transport = UdpTransport::bind("127.0.0.1:0".parse().unwrap(), peers)
            .await
            .unwrap();

        let sent = transport
            .punch_candidates("peer-b", vec![receiver_addr], Duration::from_millis(10), 2)
            .await
            .unwrap();

        assert_eq!(sent, 2);

        let mut buf = [0u8; 64];
        let (n, _from) = timeout(Duration::from_secs(1), receiver.recv_from(&mut buf))
            .await
            .unwrap()
            .unwrap();
        let packet = decode_punch_packet(&buf[..n]).unwrap();
        assert_eq!(packet.kind, PunchPacketKind::Punch);
    }

    #[tokio::test]
    async fn send_probe_uses_authenticated_v2_when_key_is_available() {
        let local_identity = NodeIdentity::generate();
        let peer_identity = NodeIdentity::generate();
        let receiver = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let receiver_addr = receiver.local_addr().unwrap();

        let peers = Arc::new(PeerManager::new(config_for_identity(
            &local_identity,
            "peer-a",
        )));
        peers
            .add_peer(&peer_with_public_key(
                "peer-b",
                "10.20.0.2",
                hex::encode(peer_identity.public_key()),
                Some(receiver_addr),
            ))
            .await;

        let transport = UdpTransport::bind("127.0.0.1:0".parse().unwrap(), peers.clone())
            .await
            .unwrap()
            .with_local_node_id("peer-a");
        transport
            .send_probe(Some("peer-b"), receiver_addr)
            .await
            .unwrap();

        let mut buf = [0u8; 512];
        let (n, _from) = timeout(Duration::from_secs(1), receiver.recv_from(&mut buf))
            .await
            .unwrap()
            .unwrap();

        assert!(decode_punch_packet(&buf[..n]).is_none());
        let identity = peek_authenticated_punch_identity(&buf[..n]).unwrap();
        assert_eq!(identity.kind, PunchPacketKind::Punch);
        assert_eq!(identity.source_node_id, "peer-a");
        assert_eq!(identity.target_node_id, "peer-b");

        let key = peers.probe_key_for_peer("peer-b").await.unwrap();
        let packet = decode_authenticated_punch_packet(&buf[..n], &key).unwrap();
        assert_eq!(packet.kind, PunchPacketKind::Punch);
        assert_eq!(packet.source_node_id.as_deref(), Some("peer-a"));
        assert_eq!(packet.target_node_id.as_deref(), Some("peer-b"));
        assert!(packet.authenticated);
    }

    #[tokio::test]
    async fn sends_encrypted_packet_to_peer_endpoint() {
        let receiver = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let receiver_addr = receiver.local_addr().unwrap();

        let peers = peer_manager();
        peers
            .add_peer(&peer("peer-b", "10.20.0.2", Some(receiver_addr)))
            .await;

        let transport = UdpTransport::bind("127.0.0.1:0".parse().unwrap(), peers.clone())
            .await
            .unwrap();
        let payload = vec![4, 1, 2, 3, 4, 5, 6, 7];

        let sent = transport
            .send_packet(&EncryptedPeerPacket {
                peer_id: "peer-b".to_string(),
                dst_ip: "10.20.0.2".to_string(),
                wire_bytes: payload.clone(),
            })
            .await
            .unwrap();
        assert_eq!(sent, Some(payload.len()));

        let mut buf = [0u8; 128];
        let (n, _from) = timeout(Duration::from_secs(1), receiver.recv_from(&mut buf))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(&buf[..n], payload.as_slice());
        assert_eq!(peers.get_connection("peer-b").await.unwrap().bytes_sent, 0);
    }

    #[tokio::test]
    async fn drops_packet_when_endpoint_is_unknown() {
        let peers = peer_manager();
        peers.add_peer(&peer("peer-b", "10.20.0.2", None)).await;

        let transport = UdpTransport::bind("127.0.0.1:0".parse().unwrap(), peers)
            .await
            .unwrap();

        let sent = transport
            .send_packet(&EncryptedPeerPacket {
                peer_id: "peer-b".to_string(),
                dst_ip: "10.20.0.2".to_string(),
                wire_bytes: vec![4, 1, 2, 3],
            })
            .await
            .unwrap();

        assert_eq!(sent, None);
    }

    #[tokio::test]
    async fn run_outbound_sends_wireguard_datagram_that_peer_can_decrypt() {
        let receiver = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let receiver_addr = receiver.local_addr().unwrap();

        let peers = peer_manager();
        peers
            .add_peer(&peer("peer-b", "10.20.0.2", Some(receiver_addr)))
            .await;

        let transport = UdpTransport::bind("127.0.0.1:0".parse().unwrap(), peers)
            .await
            .unwrap();
        let (tx, rx) = mpsc::channel(4);
        let worker = tokio::spawn(transport.run_outbound(rx));

        let (mut node_a_session, mut node_b_session) = establish_sessions();
        let ip_packet = Ipv4Packet::build_icmp_echo_request(
            Ipv4Addr::new(10, 20, 0, 1),
            Ipv4Addr::new(10, 20, 0, 2),
            0x1234,
            1,
            b"ping",
        );
        let wire_bytes = node_a_session.encrypt_to_bytes(&ip_packet).unwrap();

        tx.send(EncryptedPeerPacket {
            peer_id: "peer-b".to_string(),
            dst_ip: "10.20.0.2".to_string(),
            wire_bytes,
        })
        .await
        .unwrap();

        let mut buf = [0u8; 2048];
        let (n, _from) = timeout(Duration::from_secs(1), receiver.recv_from(&mut buf))
            .await
            .unwrap()
            .unwrap();
        let decrypted = node_b_session.decrypt_from_bytes(&buf[..n]).unwrap();
        assert_eq!(decrypted, ip_packet);

        worker.abort();
    }

    #[tokio::test]
    async fn run_inbound_emits_received_encrypted_datagram() {
        let peers = peer_manager();
        let transport = UdpTransport::bind("127.0.0.1:0".parse().unwrap(), peers)
            .await
            .unwrap();
        let local_addr = transport.local_addr().unwrap();
        let (tx, mut rx) = mpsc::channel(4);
        let worker = tokio::spawn(transport.run_inbound(tx));

        let sender = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let payload = vec![4, 9, 8, 7, 6, 5];
        sender.send_to(&payload, local_addr).await.unwrap();

        let received = timeout(Duration::from_secs(1), rx.recv())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(received.source, Some(sender.local_addr().unwrap()));
        assert_eq!(received.wire_bytes, payload);

        worker.abort();
    }

    #[tokio::test]
    async fn live_stun_refresh_does_not_steal_encrypted_datagrams() {
        let peers = peer_manager();
        let transport = UdpTransport::bind("127.0.0.1:0".parse().unwrap(), peers)
            .await
            .unwrap();
        let local_addr = transport.local_addr().unwrap();
        let (tx, mut rx) = mpsc::channel(4);
        let inbound_worker = tokio::spawn(transport.clone().run_inbound(tx));

        let stun_server = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let stun_addr = stun_server.local_addr().unwrap();
        let stun_worker = tokio::spawn(async move {
            let mut buf = [0u8; 2048];
            let (n, client_addr) = stun_server.recv_from(&mut buf).await.unwrap();
            let request = StunMessage::decode(&buf[..n]).unwrap();
            let mapped: SocketAddr = "203.0.113.7:45678".parse().unwrap();
            let mut response =
                StunMessage::with_transaction_id(BINDING_RESPONSE, request.transaction_id);
            response.add_attribute(StunAttribute::XorMappedAddress(mapped));
            stun_server
                .send_to(&response.encode(), client_addr)
                .await
                .unwrap();
        });

        let refresh = {
            let transport = transport.clone();
            tokio::spawn(async move {
                transport
                    .gather_candidate_report_live(vec![stun_addr], Duration::from_secs(1))
                    .await
            })
        };

        let sender = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let encrypted = vec![4, 0x91, 0x82, 0x73, 0x64];
        sender.send_to(&encrypted, local_addr).await.unwrap();

        let received = timeout(Duration::from_secs(1), rx.recv())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(received.wire_bytes, encrypted);
        assert_eq!(received.source, Some(sender.local_addr().unwrap()));

        let report = refresh.await.unwrap().unwrap();
        assert!(report.candidates.iter().any(|candidate| {
            candidate.endpoint.to_string() == "203.0.113.7:45678"
                && candidate.source == p2pnet_nat::CandidateSource::StunObserved
        }));
        assert_eq!(report.nat_profile.observations.len(), 1);
        assert!(report.nat_profile.observations[0].error.is_none());

        stun_worker.await.unwrap();
        inbound_worker.abort();
    }

    #[tokio::test]
    async fn run_inbound_acks_punch_and_does_not_forward_to_wireguard() {
        let peers = peer_manager();
        let sender = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let sender_addr = sender.local_addr().unwrap();

        peers.add_peer(&peer("peer-b", "10.20.0.2", None)).await;
        peers
            .add_candidates("peer-b", &[sender_addr.to_string()])
            .await;

        let transport = UdpTransport::bind("127.0.0.1:0".parse().unwrap(), peers.clone())
            .await
            .unwrap();
        let local_addr = transport.local_addr().unwrap();
        let (tx, mut rx) = mpsc::channel(4);
        let worker = tokio::spawn(transport.run_inbound(tx));

        sender
            .send_to(&p2pnet_nat::build_punch_packet(), local_addr)
            .await
            .unwrap();

        let mut buf = [0u8; 64];
        let (n, _from) = timeout(Duration::from_secs(1), sender.recv_from(&mut buf))
            .await
            .unwrap()
            .unwrap();
        let ack = decode_punch_packet(&buf[..n]).unwrap();
        assert_eq!(ack.kind, PunchPacketKind::Ack);

        assert!(timeout(Duration::from_millis(100), rx.recv())
            .await
            .is_err());

        let conn = peers.get_connection("peer-b").await.unwrap();
        assert_eq!(conn.endpoint, Some(sender_addr));
        assert_eq!(conn.state.to_string(), "hole_punching");
        assert!(conn.direct_health.last_success_at.is_some());

        worker.abort();
    }

    #[tokio::test]
    async fn run_inbound_accepts_authenticated_peer_reflexive_probe() {
        let local_identity = NodeIdentity::generate();
        let peer_identity = NodeIdentity::generate();
        let peers = Arc::new(PeerManager::new(config_for_identity(
            &local_identity,
            "peer-a",
        )));
        peers
            .add_peer(&peer_with_public_key(
                "peer-b",
                "10.20.0.2",
                hex::encode(peer_identity.public_key()),
                None,
            ))
            .await;

        let key = peers.probe_key_for_peer("peer-b").await.unwrap();
        let transport = UdpTransport::bind("127.0.0.1:0".parse().unwrap(), peers.clone())
            .await
            .unwrap()
            .with_local_node_id("peer-a");
        let local_addr = transport.local_addr().unwrap();
        let (tx, mut rx) = mpsc::channel(4);
        let worker = tokio::spawn(transport.run_inbound(tx));

        let sender = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let sender_addr = sender.local_addr().unwrap();
        let (probe, nonce) = build_authenticated_punch_packet("peer-b", "peer-a", 7, &key);
        sender.send_to(&probe, local_addr).await.unwrap();

        let mut buf = [0u8; 512];
        let (n, _from) = timeout(Duration::from_secs(1), sender.recv_from(&mut buf))
            .await
            .unwrap()
            .unwrap();
        let ack = decode_authenticated_punch_packet(&buf[..n], &key).unwrap();
        assert_eq!(ack.kind, PunchPacketKind::Ack);
        assert_eq!(ack.nonce, nonce);
        assert_eq!(ack.source_node_id.as_deref(), Some("peer-a"));
        assert_eq!(ack.target_node_id.as_deref(), Some("peer-b"));

        assert!(timeout(Duration::from_millis(100), rx.recv())
            .await
            .is_err());

        let conn = peers.get_connection("peer-b").await.unwrap();
        assert_eq!(conn.endpoint, Some(sender_addr));
        assert!(conn.candidates.contains(&sender_addr.to_string()));
        assert_eq!(conn.state.to_string(), "hole_punching");
        assert!(conn.direct_health.last_success_at.is_some());

        worker.abort();
    }

    #[tokio::test]
    async fn run_inbound_rejects_authenticated_probe_with_invalid_mac() {
        let local_identity = NodeIdentity::generate();
        let peer_identity = NodeIdentity::generate();
        let peers = Arc::new(PeerManager::new(config_for_identity(
            &local_identity,
            "peer-a",
        )));
        peers
            .add_peer(&peer_with_public_key(
                "peer-b",
                "10.20.0.2",
                hex::encode(peer_identity.public_key()),
                None,
            ))
            .await;

        let key = peers.probe_key_for_peer("peer-b").await.unwrap();
        let transport = UdpTransport::bind("127.0.0.1:0".parse().unwrap(), peers.clone())
            .await
            .unwrap()
            .with_local_node_id("peer-a");
        let local_addr = transport.local_addr().unwrap();
        let (tx, mut rx) = mpsc::channel(4);
        let worker = tokio::spawn(transport.run_inbound(tx));

        let sender = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let (mut probe, _nonce) = build_authenticated_punch_packet("peer-b", "peer-a", 7, &key);
        let last = probe.last_mut().unwrap();
        *last ^= 0x80;
        sender.send_to(&probe, local_addr).await.unwrap();

        let mut buf = [0u8; 512];
        assert!(
            timeout(Duration::from_millis(150), sender.recv_from(&mut buf))
                .await
                .is_err()
        );
        assert!(timeout(Duration::from_millis(100), rx.recv())
            .await
            .is_err());

        let conn = peers.get_connection("peer-b").await.unwrap();
        assert_eq!(conn.endpoint, None);
        assert!(conn.candidates.is_empty());

        worker.abort();
    }

    #[tokio::test]
    async fn probe_ack_records_peer_round_trip_latency() {
        let peers = peer_manager();
        let remote = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let remote_addr = remote.local_addr().unwrap();

        peers
            .add_peer(&peer("peer-b", "10.20.0.2", Some(remote_addr)))
            .await;

        let transport = UdpTransport::bind("127.0.0.1:0".parse().unwrap(), peers.clone())
            .await
            .unwrap();
        let local_addr = transport.local_addr().unwrap();
        let (tx, _rx) = mpsc::channel(4);
        let worker = tokio::spawn(transport.clone().run_inbound(tx));

        transport
            .send_probe(Some("peer-b"), remote_addr)
            .await
            .unwrap();
        let mut buf = [0u8; 64];
        let (n, _from) = timeout(Duration::from_secs(1), remote.recv_from(&mut buf))
            .await
            .unwrap()
            .unwrap();
        let probe = decode_punch_packet(&buf[..n]).unwrap();
        remote
            .send_to(&build_punch_ack(probe.nonce), local_addr)
            .await
            .unwrap();

        timeout(Duration::from_secs(1), async {
            loop {
                let diagnostics = peers.diagnostics().await;
                if diagnostics[0].direct.latency_ms.is_some() {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();

        let diagnostics = peers.diagnostics().await;
        assert!(diagnostics[0].direct.latency_ms.is_some());
        assert_eq!(diagnostics[0].direct.consecutive_failures, 0);

        worker.abort();
    }

    #[tokio::test]
    async fn keepalive_ack_timeout_degrades_direct_after_three_misses() {
        let peers = peer_manager();
        let silent_remote = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let remote_addr = silent_remote.local_addr().unwrap();
        peers
            .add_peer(&peer("peer-b", "10.20.0.2", Some(remote_addr)))
            .await;
        peers
            .record_direct_probe_success_with_latency(
                "peer-b",
                remote_addr,
                Some(Duration::from_millis(5)),
            )
            .await;
        peers
            .record_direct_success("peer-b", Some(remote_addr))
            .await;

        let transport = UdpTransport::bind("127.0.0.1:0".parse().unwrap(), peers.clone())
            .await
            .unwrap();

        transport
            .run_keepalive_round(Duration::from_millis(10))
            .await;
        let after_one = peers.get_connection("peer-b").await.unwrap();
        assert_eq!(after_one.state, ConnectionState::Direct);
        assert_eq!(after_one.direct_health.consecutive_failures, 1);

        transport
            .run_keepalive_round(Duration::from_millis(10))
            .await;
        transport
            .run_keepalive_round(Duration::from_millis(10))
            .await;
        let after_three = peers.get_connection("peer-b").await.unwrap();
        assert_eq!(after_three.state, ConnectionState::FallbackToRelay);
        assert_eq!(after_three.direct_health.consecutive_failures, 3);
        assert_eq!(
            after_three.direct_health.last_error_code.as_deref(),
            Some(crate::peer::REASON_DIRECT_KEEPALIVE_TIMEOUT)
        );
    }

    #[tokio::test]
    async fn matching_keepalive_ack_preserves_direct_health() {
        let peers = peer_manager();
        let remote = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let remote_addr = remote.local_addr().unwrap();
        peers
            .add_peer(&peer("peer-b", "10.20.0.2", Some(remote_addr)))
            .await;
        peers
            .record_direct_probe_success_with_latency(
                "peer-b",
                remote_addr,
                Some(Duration::from_millis(5)),
            )
            .await;
        peers
            .record_direct_success("peer-b", Some(remote_addr))
            .await;

        let transport = UdpTransport::bind("127.0.0.1:0".parse().unwrap(), peers.clone())
            .await
            .unwrap();
        let local_addr = transport.local_addr().unwrap();
        let (tx, _rx) = mpsc::channel(1);
        let inbound_worker = tokio::spawn(transport.clone().run_inbound(tx));
        let responder = tokio::spawn(async move {
            let mut buf = [0u8; 256];
            let (n, _) = remote.recv_from(&mut buf).await.unwrap();
            let probe = decode_punch_packet(&buf[..n]).unwrap();
            remote
                .send_to(&build_punch_ack(probe.nonce), local_addr)
                .await
                .unwrap();
        });

        transport
            .run_keepalive_round(Duration::from_millis(100))
            .await;
        responder.await.unwrap();

        let conn = peers.get_connection("peer-b").await.unwrap();
        assert_eq!(conn.state, ConnectionState::Direct);
        assert_eq!(conn.direct_health.consecutive_failures, 0);

        inbound_worker.abort();
    }

    #[tokio::test]
    async fn authenticated_probe_ack_learns_peer_reflexive_source_without_confirming_data() {
        let local_identity = NodeIdentity::generate();
        let peer_identity = NodeIdentity::generate();
        let remote_candidate = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let remote_candidate_addr = remote_candidate.local_addr().unwrap();

        let peers = Arc::new(PeerManager::new(config_for_identity(
            &local_identity,
            "peer-a",
        )));
        peers
            .add_peer(&peer_with_public_key(
                "peer-b",
                "10.20.0.2",
                hex::encode(peer_identity.public_key()),
                Some(remote_candidate_addr),
            ))
            .await;
        let key = peers.probe_key_for_peer("peer-b").await.unwrap();

        let transport = UdpTransport::bind("127.0.0.1:0".parse().unwrap(), peers.clone())
            .await
            .unwrap()
            .with_local_node_id("peer-a");
        let local_addr = transport.local_addr().unwrap();
        let (tx, _rx) = mpsc::channel(4);
        let worker = tokio::spawn(transport.clone().run_inbound(tx));

        transport
            .send_probe(Some("peer-b"), remote_candidate_addr)
            .await
            .unwrap();
        let mut probe_buf = [0u8; 512];
        let (n, _from) = timeout(
            Duration::from_secs(1),
            remote_candidate.recv_from(&mut probe_buf),
        )
        .await
        .unwrap()
        .unwrap();
        let probe = decode_authenticated_punch_packet(&probe_buf[..n], &key).unwrap();

        let peer_reflexive = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let peer_reflexive_addr = peer_reflexive.local_addr().unwrap();
        let ack = build_authenticated_punch_ack(probe.nonce, "peer-b", "peer-a", 11, &key);
        peer_reflexive.send_to(&ack, local_addr).await.unwrap();

        timeout(Duration::from_secs(1), async {
            loop {
                let conn = peers.get_connection("peer-b").await.unwrap();
                if conn.endpoint == Some(peer_reflexive_addr)
                    && conn.state == ConnectionState::HolePunching
                {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();

        let conn = peers.get_connection("peer-b").await.unwrap();
        assert_eq!(conn.endpoint, Some(peer_reflexive_addr));
        assert!(conn.candidates.contains(&peer_reflexive_addr.to_string()));
        assert_eq!(conn.state, ConnectionState::HolePunching);
        assert_eq!(conn.active_path(), None);

        worker.abort();
    }

    #[tokio::test]
    async fn udp_inbound_decrypts_and_writes_packet_to_tun() {
        let peers = peer_manager();
        peers.add_peer(&peer("peer-a", "10.20.0.1", None)).await;

        let (tun, mut ctrl) = MockTunDevice::new_pair("test0", 1420, "10.20.0.2");
        let (mut dataplane, _outbound_rx, inbound_tx) =
            DataPlane::new_bidirectional(tun, peers.clone());
        let dataplane_worker = tokio::spawn(async move { dataplane.run().await });

        let (mut node_a_session, node_b_session) = establish_sessions();
        let (wireguard, _encrypted_rx) = WireGuardTransport::new();
        wireguard.add_session("peer-a", node_b_session).await;
        let (udp_inbound_tx, udp_inbound_rx) = mpsc::channel(4);
        let wireguard_worker = {
            let wireguard = wireguard.clone();
            let peers = peers.clone();
            tokio::spawn(async move {
                wireguard
                    .run_inbound_with_peers(udp_inbound_rx, inbound_tx, Some(peers))
                    .await
            })
        };

        let udp = UdpTransport::bind("127.0.0.1:0".parse().unwrap(), peers.clone())
            .await
            .unwrap();
        let udp_addr = udp.local_addr().unwrap();
        let udp_worker = tokio::spawn(udp.run_inbound(udp_inbound_tx));

        let ip_packet = Ipv4Packet::build_icmp_echo_request(
            Ipv4Addr::new(10, 20, 0, 1),
            Ipv4Addr::new(10, 20, 0, 2),
            0x1234,
            1,
            b"ping",
        );
        let wire_bytes = node_a_session.encrypt_to_bytes(&ip_packet).unwrap();
        let sender = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        sender.send_to(&wire_bytes, udp_addr).await.unwrap();

        let written = timeout(Duration::from_secs(1), ctrl.recv_written())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(written, ip_packet);

        let conn = peers.get_connection("peer-a").await.unwrap();
        assert_eq!(conn.bytes_received, written.len() as u64);
        assert_eq!(conn.state.to_string(), "direct");
        assert_eq!(conn.endpoint, Some(sender.local_addr().unwrap()));
        assert_eq!(
            conn.candidate_sources
                .get(&sender.local_addr().unwrap().to_string()),
            Some(&crate::peer::CandidatePairSource::PeerReflexive)
        );

        udp_worker.abort();
        wireguard_worker.abort();
        dataplane_worker.abort();
    }
}
