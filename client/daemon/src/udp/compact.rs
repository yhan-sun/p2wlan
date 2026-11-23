use super::*;
use p2pnet_nat::engine::{CompactFrame, CompactSession, EndpointReceipt, FrameKind, PunchTarget};

struct Binding {
    peer: String,
    session: String,
    wire: CompactSession,
    network: u64,
    lifecycle: PeerSessionGeneration,
    remote_epoch: std::sync::atomic::AtomicU32,
}

/// Only the local control or send path may register a negotiated session.
/// Unauthenticated UDP input can never grow this index.
#[derive(Default)]
pub(super) struct CompactIndex {
    sessions: HashMap<u64, (Arc<Binding>, Instant)>,
}

pub(super) struct CompactIngress {
    binding: Arc<Binding>,
    frame: CompactFrame,
    packet: [u8; p2pnet_nat::engine::FRAME_SIZE],
    pub(super) decoded: Vec<u8>,
    pub(super) reply: Option<Vec<u8>>,
    pub(super) endpoint_receipts: bool,
}

impl CompactIngress {
    pub(super) fn reply_for(&self, peer: &str) -> Option<&[u8]> {
        (self.binding.peer == peer)
            .then_some(self.reply.as_deref())
            .flatten()
    }

    pub(super) fn matches_challenge(&self, peer: &str, nonce: [u8; 8]) -> bool {
        self.binding.peer == peer
            && self.frame.kind == FrameKind::Response
            && self.frame.correlation() == nonce
    }
}

impl UdpTransport {
    fn bind_compact(
        &self,
        peer: &str,
        local: &str,
        session: &str,
        key: &[u8; 32],
    ) -> Option<Arc<Binding>> {
        let lifecycle = self.peers.peer_session_generation_sync(peer)?;
        let network = self.peers.current_network_generation_sync();
        let wire = CompactSession::new(key, session, local, peer)?;
        let mut index = self.compact_index.lock().ok()?;
        let now = Instant::now();
        if let Some((current, last_used)) = index.sessions.get_mut(&wire.id) {
            if current.peer != peer || current.session != session {
                return None;
            }
            if current.network == network && current.lifecycle == lifecycle {
                *last_used = now;
                return Some(current.clone());
            }
        }
        index.sessions.retain(|_, (entry, used)| {
            entry.network == network
                && entry.peer != peer
                && now.duration_since(*used) < Duration::from_secs(120)
        });
        if index.sessions.len() >= 1024 {
            return None;
        }
        let binding = Arc::new(Binding {
            peer: peer.to_owned(),
            session: session.to_owned(),
            wire,
            network,
            lifecycle,
            remote_epoch: Default::default(),
        });
        index
            .sessions
            .insert(binding.wire.id, (binding.clone(), now));
        Some(binding)
    }

    pub(super) async fn register_compact_receiver(&self, peer: &str) -> Option<()> {
        let local = self.local_node_id.as_deref()?;
        let (key, session) = self.peers.probe_key_and_session_for_peer(peer).await?;
        self.bind_compact(peer, local, session.as_deref()?, &key)?;
        Some(())
    }

    pub(super) fn compact_request(
        &self,
        peer: &str,
        local: &str,
        session: &str,
        key: &[u8; 32],
        epoch: u32,
        nominate: bool,
    ) -> Option<(Vec<u8>, [u8; 8])> {
        let binding = self.bind_compact(peer, local, session, key)?;
        // The epoch is part of the correlation key. At the physical send
        // limit the counter cannot wrap within the pending lifetime.
        let nonce = self.compact_nonce.fetch_add(1, Ordering::Relaxed);
        let frame = CompactFrame {
            kind: FrameKind::Request,
            nominate,
            epoch,
            nonce,
        };
        Some((binding.wire.encode(frame).to_vec(), frame.correlation()))
    }

    pub(super) fn try_send_compact_challenge(
        &self,
        peer: &str,
        target: PunchTarget,
        epoch: u32,
        bytes: &[u8],
        socket: &UdpSocket,
    ) -> std::io::Result<usize> {
        self.peers
            .with_punch_run(peer, target, u64::from(epoch), |conn, run| {
                if !conn.compact_datagram_is_current(
                    self.local_node_id.as_deref().unwrap_or_default(),
                    bytes,
                ) {
                    return Err(std::io::ErrorKind::Interrupted.into());
                }
                run.pacer.try_send(u64::from(epoch), || {
                    self.compact_budget
                        .try_send(0, || socket.try_send_to(bytes, target.address))
                })
            })
            .unwrap_or_else(|| Err(std::io::ErrorKind::Interrupted.into()))
    }

    pub(super) fn send_compact_reply(
        &self,
        ingress: &CompactIngress,
        socket: &UdpSocket,
        bytes: &[u8],
        source: SocketAddr,
        fresh_socket: Option<usize>,
    ) -> std::io::Result<usize> {
        let binding = &ingress.binding;
        if ingress.frame.epoch != binding.remote_epoch.load(Ordering::Acquire) {
            return Err(std::io::ErrorKind::Interrupted.into());
        }
        let local = self
            .local_node_id
            .as_deref()
            .ok_or(std::io::ErrorKind::NotConnected)?;
        self.peers.try_compact_reply(
            &binding.peer,
            local,
            (binding.network, binding.lifecycle),
            bytes,
            |run| {
                let sent = self
                    .compact_budget
                    .try_send(0, || socket.try_send_to(bytes, source))?;
                if let (Some(run), Some(socket)) =
                    (run.filter(|r| r.remote.udp_endpoint_receipts), fresh_socket)
                {
                    run.endpoint_exchange
                        .lock()
                        .unwrap_or_else(|e| e.into_inner())
                        .answered(
                            binding.wire.id,
                            run.pacer.epoch(),
                            ingress.frame.correlation(),
                            PunchTarget {
                                address: source,
                                socket,
                            },
                        );
                }
                Ok(sent)
            },
        )
    }

    /// The caller consumed a pending response on its exact socket and remote tuple.
    pub(super) fn confirm_compact_pair(
        &self,
        ingress: &CompactIngress,
        target: PunchTarget,
        socket: &UdpSocket,
    ) -> bool {
        let Some(local) = self.local_node_id.as_deref() else {
            return false;
        };
        let challenge = ingress.frame.correlation();
        let epoch = u64::from(ingress.frame.epoch);
        self.peers.with_punch_run(&ingress.binding.peer, target, epoch, |conn, run| {
            let Some(wire) = conn.compact_session(local) else {
                return false;
            };
            if wire.decode(&ingress.packet) != Some(ingress.frame) {
                return false;
            }
            let confirmed = run.confirm_compact_response(target, epoch, challenge);
            if run.remote.udp_endpoint_receipts {
                let receipt = EndpointReceipt {
                    challenge,
                    observed: target.address,
                };
                if let Some(bytes) = wire.encode_endpoint_receipt(receipt) {
                    let sent = run.pacer.try_send(epoch, || {
                        self.compact_budget.try_send(0, || socket.try_send_to(&bytes, target.address))
                    });
                    if let Err(error) = sent {
                        trace!(reason = "endpoint_receipt_send_failed", %error, "UDP endpoint receipt send failed");
                    }
                }
            }
            confirmed
        }).unwrap_or(false)
    }

    pub(super) fn receive_endpoint_receipt(&self, bytes: &[u8], target: PunchTarget) -> Option<()> {
        let id = EndpointReceipt::session_hint(bytes)?;
        let (binding, used) = self.compact_index.lock().ok()?.sessions.get(&id)?.clone();
        if used.elapsed() >= Duration::from_secs(120) {
            return None;
        }
        let local = self.local_node_id.as_deref()?;
        let epoch = self.peers.current_punch_epoch(&binding.peer)?;
        self.peers
            .with_active_punch(&binding.peer, epoch, |conn, run| {
                if !run.remote.udp_endpoint_receipts
                    || self.peers.current_network_generation_sync() != binding.network
                    || !self
                        .peers
                        .peer_session_is_current_sync(&binding.peer, binding.lifecycle)
                {
                    return None;
                }
                let receipt = conn
                    .compact_session(local)?
                    .decode_endpoint_receipt(bytes)?;
                let remote_epoch = u32::from_be_bytes(receipt.challenge[..4].try_into().ok()?);
                if remote_epoch != binding.remote_epoch.load(Ordering::Acquire) {
                    return None;
                }
                let accepted = run
                    .endpoint_exchange
                    .lock()
                    .ok()?
                    .accept(local, id, epoch, target, receipt);
                if !accepted {
                    return None;
                }
                run.queue_witnessed_target(conn, epoch, target);
                Some(())
            })?
    }

    pub(super) async fn decode_compact(&self, packet: &[u8]) -> Option<CompactIngress> {
        let id = CompactFrame::session_hint(packet)?;
        let (binding, used) = self.compact_index.lock().ok()?.sessions.get(&id)?.clone();
        if used.elapsed() >= Duration::from_secs(120)
            || self.peers.current_network_generation_sync() != binding.network
            || !self
                .peers
                .peer_session_is_current_sync(&binding.peer, binding.lifecycle)
        {
            return None;
        }
        let frame = binding.wire.decode(packet)?;
        let local = self.local_node_id.as_deref()?;
        let (key, session) = self
            .peers
            .probe_key_and_session_for_peer(&binding.peer)
            .await?;
        let profile = self.peers.negotiated_profile(&binding.peer).await?;
        if session.as_deref() != Some(&binding.session)
            || self.peers.current_network_generation_sync() != binding.network
            || !self
                .peers
                .peer_session_is_current_sync(&binding.peer, binding.lifecycle)
        {
            return None;
        }
        // Verify against the current key as a same-ID rekey may have retired the cached key.
        let active = CompactSession::new(&key, &binding.session, local, &binding.peer)?;
        if active.decode(packet) != Some(frame) {
            return None;
        }
        match frame.kind {
            FrameKind::Response
                if self.peers.current_punch_epoch(&binding.peer)
                    != Some(u64::from(frame.epoch)) =>
            {
                return None
            }
            FrameKind::Request
                if frame.epoch
                    < binding
                        .remote_epoch
                        .fetch_max(frame.epoch, Ordering::AcqRel) =>
            {
                return None
            }
            _ => {}
        }
        // The existing authenticated ingress owns replay, exact-socket candidate
        // learning, response correlation and WireGuard promotion for both formats.
        let (decoded, reply) = match frame.kind {
            FrameKind::Request => (
                p2pnet_nat::punch::build_authenticated_punch_packet_with_nonce(
                    frame.correlation(),
                    &binding.peer,
                    local,
                    u64::from(frame.epoch),
                    frame.nominate,
                    &key,
                ),
                Some(
                    active
                        .encode(CompactFrame {
                            kind: FrameKind::Response,
                            nominate: false,
                            ..frame
                        })
                        .to_vec(),
                ),
            ),
            FrameKind::Response => (
                build_authenticated_punch_ack(
                    frame.correlation(),
                    &binding.peer,
                    local,
                    binding.network,
                    &key,
                ),
                None,
            ),
        };
        Some(CompactIngress {
            binding,
            frame,
            packet: packet.try_into().ok()?,
            decoded,
            reply,
            endpoint_receipts: profile.udp_endpoint_receipts,
        })
    }
}
