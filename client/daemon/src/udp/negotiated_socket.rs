use super::*;
use crate::peer::PeerPunchRun;
use p2pnet_nat::engine::{EndpointReceipt, Lane, PunchTarget, ENDPOINT_RECEIPT_SIZE, FRAME_SIZE};
use tokio::sync::OwnedSemaphorePermit;

/// One alternate source port for the same published destination, after the
/// primary pair had its first opportunity. No reader or pending-probe entry
/// owns the FD before two independently authenticated answers arrive.
pub(super) struct RoundSocket {
    socket: Arc<UdpSocket>,
    pub(super) target: PunchTarget,
    epoch: u32,
    pending: Option<([u8; 8], Vec<u8>, tokio::time::Instant)>,
    answered_request: bool,
    handoff: Option<ProvisionalSocketGuard>,
    run: Arc<PeerPunchRun>,
    _slot: OwnedSemaphorePermit,
}

impl RoundSocket {
    pub(super) async fn open(
        transport: &UdpTransport,
        peer: &str,
        run: &Arc<PeerPunchRun>,
        epoch: u64,
        address: SocketAddr,
    ) -> Option<Self> {
        let wire_epoch = u32::try_from(epoch).ok()?;
        let slot = transport
            .negotiated_socket_slots
            .clone()
            .try_acquire_owned()
            .ok()?;
        if !address.is_ipv4() {
            return None;
        }
        let (index, socket) = transport.bind_fresh_punch_socket().await.ok()?;
        socket.writable().await.ok()?;
        let target = PunchTarget {
            address,
            socket: index,
        };
        transport
            .peers
            .with_punch_run(peer, target, epoch, |_, current| {
                (std::ptr::eq(current, run.as_ref())
                    && run.pacer.enqueue(epoch, Lane::Predicted, target))
                .then_some(())
            })??;
        run.sockets.store(1, Ordering::Release);
        Some(Self {
            socket,
            target,
            epoch: wire_epoch,
            pending: None,
            answered_request: false,
            handoff: None,
            run: run.clone(),
            _slot: slot,
        })
    }

    pub(super) fn owns_probe(&self, target: PunchTarget) -> bool {
        target == self.target && self.handoff.is_none()
    }

    pub(super) async fn send_challenge(&mut self, udp: &UdpTransport, peer: &str) {
        let Some(local) = udp.local_node_id.as_deref() else {
            return;
        };
        let Some((key, Some(session))) = udp.peers.probe_key_and_session_for_peer(peer).await
        else {
            return;
        };
        let Some((bytes, nonce)) =
            udp.compact_request(peer, local, &session, &key, self.epoch, false)
        else {
            return;
        };
        match udp.try_send_compact_challenge(peer, self.target, self.epoch, &bytes, &self.socket) {
            Ok(_) => {
                self.pending = Some((nonce, bytes, tokio::time::Instant::now()));
                self.answered_request = false;
            }
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                self.run
                    .pacer
                    .enqueue(u64::from(self.epoch), Lane::Predicted, self.target);
            }
            Err(_) => {}
        }
    }

    pub(super) async fn receive(&mut self, udp: &UdpTransport, peer: &str) {
        let Some((nonce, _, sent)) = self.pending.as_ref() else {
            return;
        };
        if sent.elapsed() >= Duration::from_secs(3) {
            self.pending = None;
            return;
        }
        if self.handoff.is_some() {
            return;
        }
        let mut bytes = [0u8; ENDPOINT_RECEIPT_SIZE + 1];
        let Ok((size, source)) = self.socket.try_recv_from(&mut bytes) else {
            return;
        };
        if self.target.address != source {
            return;
        }
        if bytes[..size].starts_with(&EndpointReceipt::MAGIC) {
            udp.receive_endpoint_receipt(&bytes[..size], self.target);
            return;
        }
        if size != FRAME_SIZE {
            return;
        }
        let Some(ingress) = udp.decode_compact(&bytes[..FRAME_SIZE]).await else {
            return;
        };
        if let Some(reply) = ingress.reply_for(peer) {
            // One reply on this exact tuple per outstanding local challenge.
            // A request alone cannot register a socket or satisfy our nonce.
            if !self.answered_request {
                self.answered_request = udp
                    .peers
                    .with_punch_run(peer, self.target, u64::from(self.epoch), |_, current| {
                        std::ptr::eq(current, self.run.as_ref())
                            && udp
                                .send_compact_reply(
                                    &ingress,
                                    &self.socket,
                                    reply,
                                    source,
                                    Some(self.target.socket),
                                )
                                .is_ok()
                    })
                    .unwrap_or(false);
            }
            return;
        }
        if !ingress.matches_challenge(peer, *nonce) {
            return;
        }
        let Some((_, challenge, _)) = self.pending.take() else {
            return;
        };
        if !udp.confirm_compact_pair(&ingress, self.target, &self.socket) {
            return;
        }
        let network = udp.peers.current_network_generation_sync();
        let generation = udp.peers.next_punch_generation(peer).await;
        let Ok(guard) = udp
            .attach_dynamic_punch_socket(
                peer,
                self.target.socket,
                self.socket.clone(),
                network,
                generation,
                None,
            )
            .await
        else {
            return;
        };
        // The normal reader and socket registry now own any incoming data.
        // Commit only under the active peer identity, key, tuple and attempt.
        let current = || {
            !udp.peers.is_direct_sync(peer)
                && udp
                    .peers
                    .with_punch_run(peer, self.target, u64::from(self.epoch), |conn, run| {
                        std::ptr::eq(run, self.run.as_ref())
                            && conn.compact_datagram_is_current(
                                udp.local_node_id.as_deref().unwrap_or_default(),
                                &challenge,
                            )
                    })
                    .unwrap_or(false)
        };
        if guard
            .commit_and_pin_if(udp, peer, self.target.socket, network, generation, current)
            .await
            .committed()
        {
            self.handoff = Some(guard);
            self.run.sockets.store(0, Ordering::Release);
            self.run
                .pacer
                .enqueue(u64::from(self.epoch), Lane::Regular, self.target);
        }
    }
}

impl Drop for RoundSocket {
    fn drop(&mut self) {
        // A registered candidate uses the registry's authenticated-evidence
        // watcher to retain a proven winner or roll back the unproven pin.
        self.run.sockets.store(0, Ordering::Release);
    }
}
