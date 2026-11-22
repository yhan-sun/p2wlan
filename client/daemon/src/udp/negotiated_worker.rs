use super::negotiated_socket::RoundSocket;
use super::*;
use crate::peer::PeerPunchRun;
use p2pnet_nat::engine::{Lane, PunchTarget};
use std::sync::atomic::Ordering;
use tokio::time::Instant as Clock;

struct OwnedRound(Arc<PeerPunchRun>);

impl Drop for OwnedRound {
    fn drop(&mut self) {
        self.0.pacer.clear_punch_state();
        self.0.sockets.store(0, Ordering::Release);
        self.0.ended.store(true, Ordering::Release);
    }
}

impl UdpTransport {
    pub(crate) async fn start_negotiated(
        &self,
        peer: &str,
        network: u64,
        lifecycle: PeerSessionGeneration,
        shutdown: Option<watch::Receiver<bool>>,
    ) -> bool {
        if self.peers.negotiated_profile(peer).await.is_none() {
            return false;
        }
        if self.register_compact_receiver(peer).await.is_none() {
            return true;
        }
        if let Some(run) = self.peers.claim_punch_run(peer, network, lifecycle).await {
            let udp = self.clone();
            let peer = peer.to_owned();
            tokio::spawn(async move {
                udp.drive_negotiated(&peer, network, lifecycle, OwnedRound(run), shutdown)
                    .await;
            });
        }
        true
    }

    async fn drive_negotiated(
        &self,
        peer: &str,
        network: u64,
        lifecycle: PeerSessionGeneration,
        run: OwnedRound,
        mut shutdown: Option<watch::Receiver<bool>>,
    ) {
        let wait_for_shutdown = async {
            if let Some(rx) = shutdown.as_mut() {
                if !*rx.borrow() {
                    let _ = rx.wait_for(|value| *value).await;
                }
            } else {
                std::future::pending::<()>().await;
            }
        };
        let work = async {
            if let Some(ready) = &run.0.business_ready {
                if ready
                    .subscribe()
                    .wait_for(|business| *business)
                    .await
                    .is_err()
                {
                    return;
                }
            }
            if let Some(recheck) = self.blocked_recheck_at(network) {
                use p2pnet_nat::engine::UdpReachability;
                *run.0.firewall.lock().unwrap_or_else(|e| e.into_inner()) =
                    UdpReachability::Blocked;
                let epoch = run.0.pacer.epoch();
                tokio::time::sleep_until(recheck).await;
                let status = self.firewall_verdict(network).await;
                if self.peers.current_punch_epoch(peer) != Some(epoch) {
                    return;
                }
                *run.0.firewall.lock().unwrap_or_else(|e| e.into_inner()) = status;
                if status != UdpReachability::Available {
                    return;
                }
            }
            let started = Clock::now();
            let deadline = started + Duration::from_secs(120);
            tokio::time::sleep(Duration::from_millis(200)).await;
            let mut round = started;
            let mut staged = 0;
            let mut alternate: Option<RoundSocket> = None;
            let mut next_firewall = started + Duration::from_secs(10);
            let mut ticks = tokio::time::interval(run.0.pacer.interval());
            ticks.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            loop {
                ticks.tick().await;
                let now = Clock::now();
                if run.0.ended.load(Ordering::Acquire)
                    || now >= deadline
                    || self.peers.current_network_generation_sync() != network
                    || !self.peers.peer_session_is_current_sync(peer, lifecycle)
                    || self.peers.is_direct_sync(peer)
                {
                    break;
                }
                if now >= next_firewall {
                    let probe_epoch = run.0.pacer.epoch();
                    let status = self.firewall_verdict(network).await;
                    if self.peers.current_network_generation_sync() != network
                        || !self.peers.peer_session_is_current_sync(peer, lifecycle)
                        || run.0.pacer.epoch() != probe_epoch
                    {
                        break;
                    }
                    *run.0.firewall.lock().unwrap_or_else(|p| p.into_inner()) = status;
                    next_firewall = Clock::now() + Duration::from_secs(10);
                    if status == p2pnet_nat::engine::UdpReachability::Blocked {
                        tracing::info!(
                            peer_id = peer,
                            punch_epoch = probe_epoch,
                            reason_code = "UDP_BLOCKED",
                            "Peer traversal paused"
                        );
                        break;
                    }
                }
                if now.duration_since(round) >= Duration::from_secs(20) {
                    if run.0.pacer.clear_punch_state().is_none() {
                        break;
                    }
                    drop(alternate.take());
                    round += Duration::from_secs(20);
                    staged = 0;
                }
                let epoch = run.0.pacer.epoch();
                // Early cone/open traffic alternates between role zero and one.
                let delayed = matches!(run.0.mode, 3 | 5)
                    || (run.0.mode <= 1 && u64::from(run.0.role) != ((epoch / 5) & 1));
                let first = if delayed {
                    Duration::from_secs(2)
                } else {
                    Duration::ZERO
                };
                let age = now.duration_since(round);
                let second = first + Duration::from_secs(5);
                let initial = staged == 0 && age >= first;
                let retry = staged == 1 && age >= second;
                if initial || retry {
                    let Some((remote, mut candidates)) =
                        self.peers.negotiated_candidate_snapshot(peer).await
                    else {
                        break;
                    };
                    if remote != run.0.remote {
                        break;
                    }
                    self.queue_negotiated(&run.0, epoch, &mut candidates, retry);
                    if retry && run.0.mode == 6 {
                        if let Some((_, endpoint)) =
                            candidates.iter().find(|(_, endpoint)| endpoint.is_ipv4())
                        {
                            alternate =
                                RoundSocket::open(self, peer, &run.0, epoch, *endpoint).await;
                        }
                    }
                    staged += 1;
                }
                if let Some(alternate) = &mut alternate {
                    alternate.receive(self, peer).await;
                }
                for target in run.0.pacer.tick(epoch, now).into_iter().flatten() {
                    if let Some(socket) = alternate.as_mut().filter(|s| s.owns_probe(target)) {
                        socket.send_challenge(self, peer).await;
                        continue;
                    }
                    let Ok(wire_epoch) = u32::try_from(epoch) else {
                        return;
                    };
                    if self
                        .peers
                        .with_punch_run(peer, target.address, epoch, |_, _| ())
                        .is_none()
                    {
                        continue;
                    }
                    let _ = self
                        .send_probe_from_socket_with_nomination_result(
                            target.socket,
                            Some(peer),
                            target.address,
                            false,
                            PendingProbePurpose::Negotiated(wire_epoch),
                        )
                        .await;
                }
            }
        };
        tokio::select! { biased; _=wait_for_shutdown=>{}, _=tokio::time::timeout(Duration::from_secs(120),work)=>{} }
    }

    fn queue_negotiated(
        &self,
        run: &PeerPunchRun,
        epoch: u64,
        addresses: &mut [(u8, SocketAddr)],
        escalate: bool,
    ) {
        let settings = self.peers.punch_settings();
        let max = match run.mode {
            2 | 6 if !escalate => usize::from(settings.linear_scan_count.min(256)),
            4 => 256,
            5 => 150,
            7 | 8 => 100,
            9 => 256,
            _ => 96,
        };
        // Probing a candidate never grants permission to try other ports on its host.
        // Match predictions against the addresses the peer actually published.
        let priority = |addr: &SocketAddr| {
            let diff = i32::from(addr.port().wrapping_sub(run.remote.port_hint) as i16);
            let step = run.remote.port_step;
            let order = if step != 0 && diff % step == 0 && diff / step > 0 {
                diff / step
            } else {
                i32::MAX
            };
            (Some(*addr) != run.remote.upnp_mapped_addr, order, *addr)
        };
        addresses.sort_by_key(|(cost, addr)| (*cost, priority(addr)));
        for &(_, address) in addresses.iter().take(max) {
            let lane = if !escalate && matches!(run.mode, 2 | 6) && priority(&address).1 != i32::MAX
            {
                Lane::Predicted
            } else {
                Lane::Regular
            };
            run.pacer
                .enqueue(epoch, lane, PunchTarget { address, socket: 0 });
        }
    }
}
