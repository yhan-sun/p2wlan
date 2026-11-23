use super::*;
use p2pnet_nat::engine::{reserve_sequence, PunchProfile};

#[derive(Clone, Debug)]
pub(super) struct AdvertisedPunchProfile {
    network: u64,
    generation: u64,
    at: Instant,
    profile: PunchProfile,
}

/// Advisory metadata from the same authenticated candidate generation. Reading
/// it requires the candidate owner to have accepted that exact generation.
#[derive(Debug, Clone)]
pub(crate) struct NegotiatedPunchProfile {
    pub(crate) profile: Option<PunchProfile>,
    network: u64,
    session: PeerSessionGeneration,
    sender: String,
    candidate_generation: u64,
    expires: Instant,
}

impl NegotiatedPunchProfile {
    pub(super) fn current(&self, conn: &PeerConnection, network: u64) -> bool {
        self.profile.is_some()
            && self.network == network
            && conn.online
            && conn
                .path_state_machine
                .current_epoch()
                .is_some_and(|epoch| {
                    epoch.network_generation == network
                        && epoch.peer_session_generation == self.session
                })
            && self.candidate_generation == conn.last_candidate_generation()
            && self.sender == conn.public_key
            && Instant::now() < self.expires
    }
}

impl PeerManager {
    pub(crate) fn punch_profile_for_signal(
        &self,
        candidates: &[String],
        sources: &HashMap<String, String>,
    ) -> Option<PunchProfile> {
        let mapped = candidates.iter().find_map(|candidate| {
            matches!(
                sources.get(candidate).map(String::as_str),
                Some("upnp" | "nat_pmp" | "pcp")
            )
            .then(|| candidate.parse::<SocketAddr>().ok())
            .flatten()
        });
        let network = self.current_network_generation_sync();
        let profile = self.local_nat_profile.try_read().ok()?;
        let generation = self.current_local_profile_generation_sync();
        let offer = PunchProfile::advertisement(
            profile.as_ref(),
            mapped,
            !self.config.network.traversal.disable_sym_hole_punching,
        )?;
        *self.advertised_punch_profile.lock().ok()? = Some(AdvertisedPunchProfile {
            network,
            generation,
            at: Instant::now(),
            profile: offer.clone(),
        });
        Some(offer)
    }

    #[cfg(test)]
    pub(crate) async fn stage_punch_profile(
        &self,
        peer: &str,
        profile: PunchProfile,
        sender: Option<&str>,
        revision: u64,
        expires_ms: Option<u64>,
        owner: (u64, Option<PeerSessionGeneration>),
    ) {
        self.stage_candidate_punch_signal(
            peer,
            (Some(profile), false),
            sender,
            revision,
            expires_ms,
            owner,
        )
        .await;
    }

    pub(crate) async fn stage_candidate_punch_signal(
        &self,
        peer: &str,
        (profile, udp_candidates_empty): (Option<PunchProfile>, bool),
        sender: Option<&str>,
        revision: u64,
        expires_ms: Option<u64>,
        owner: (u64, Option<PeerSessionGeneration>),
    ) {
        let (network, Some(session)) = owner else {
            return;
        };
        let pinned = self
            .config
            .network
            .tcp_direct
            .as_ref()
            .and_then(|cfg| cfg.peers.get(peer));
        // A normal candidate revision already retires the previous profile.
        // Legacy signals and unconfigured peers need no extra writer turn.
        if profile.is_none() && (!udp_candidates_empty || pinned.is_none()) {
            return;
        }
        let (_epoch, mut table) = self.lock_epoch_and_connections_write().await;
        if network != self.current_network_generation_sync()
            || !self.peer_session_is_current_sync(peer, session)
        {
            return;
        }
        let Some(ttl) = expires_ms
            .and_then(|expires| expires.checked_sub(crate::gateway_mapping::now_ms()))
            .filter(|ms| *ms > 0)
        else {
            return;
        };
        let Some(conn) = table.get_mut(peer) else {
            return;
        };
        if revision == 0
            || !conn.online
            || conn.public_key.is_empty()
            || sender != Some(&conn.public_key)
            || revision < conn.last_candidate_generation()
            || profile.as_ref().is_some_and(|profile| !profile.valid())
            || conn.negotiated_punch.as_ref().is_some_and(|p| {
                p.network == network && p.session == session && p.candidate_generation >= revision
            })
        {
            return;
        }
        if revision > conn.last_candidate_generation() {
            // UDP's empty-list rule preserves existing UDP routes. Only a
            // named TCP peer can advance the shared replay floor without UDP.
            let permitted = pinned.is_some_and(|pin| {
                profile
                    .as_ref()
                    .is_some_and(|p| p.tcp_only() && p.tcp_candidates.contains(pin))
            });
            let withdrawing = pinned.is_some_and(|pin| {
                conn.negotiated_punch
                    .as_ref()
                    .and_then(|p| p.profile.as_ref())
                    .is_some_and(|p| p.tcp_candidates.contains(pin))
                    && profile
                        .as_ref()
                        .is_none_or(|p| !p.tcp_candidates.contains(pin))
            });
            if !udp_candidates_empty
                || !(permitted || withdrawing)
                || crate::control::candidate_generation_is_malformed_encoded(revision)
                || crate::control::candidate_generation_incarnation(revision).is_some_and(
                    |incoming| {
                        conn.remote_candidate_incarnation_high_water
                            .is_some_and(|accepted| incoming < accepted)
                    },
                )
            {
                return;
            }
            self.record_candidate_revision(conn, revision);
        }
        if profile.is_none() && conn.negotiated_punch.is_none() {
            return;
        }
        conn.negotiated_punch = Some(NegotiatedPunchProfile {
            profile,
            network,
            session,
            sender: conn.public_key.clone(),
            candidate_generation: revision,
            expires: Instant::now() + Duration::from_millis(ttl.min(45_000)),
        });
    }

    pub(crate) async fn negotiated_profile(&self, peer: &str) -> Option<PunchProfile> {
        let table = self.connections.read().await;
        let conn = table.get(peer)?;
        let offered = conn.negotiated_punch.as_ref()?;
        offered
            .current(conn, self.current_network_generation_sync())
            .then(|| offered.profile.clone())
            .flatten()
    }
}

impl PeerManager {
    pub(crate) async fn negotiated_candidate_snapshot(
        &self,
        peer: &str,
    ) -> Option<(PunchProfile, Vec<(u8, SocketAddr)>)> {
        let table = self.connections.read().await;
        let conn = table.get(peer)?;
        let offered = conn.negotiated_punch.as_ref()?;
        if !offered.current(conn, self.current_network_generation_sync()) {
            return None;
        }
        let mut addresses: Vec<_> = conn
            .signaled_candidates
            .iter()
            .filter_map(|s| s.parse().ok())
            .filter(|endpoint| is_negotiated_source(conn.candidate_source_for_endpoint(*endpoint)))
            .map(|endpoint| {
                let cost = if conn.is_on_link_host_candidate(endpoint) {
                    1
                } else if endpoint.is_ipv6() {
                    2
                } else {
                    3
                };
                (cost, endpoint)
            })
            .collect();
        addresses.sort_unstable();
        Some((offered.profile.clone()?, addresses))
    }

    pub(crate) fn configured_firewall_targets(&self) -> Vec<String> {
        let network = &self.config.network;
        let mut seen = std::collections::HashSet::new();
        network
            .traversal
            .firewall_probe_addresses
            .iter()
            .map(ToString::to_string)
            .chain(
                network
                    .udp_observers
                    .iter()
                    .chain(&network.stun_servers)
                    .cloned(),
            )
            .filter(|target| seen.insert(target.clone()))
            .take(8)
            .collect()
    }

    pub(crate) fn punch_settings(&self) -> &p2pnet_nat::engine::PunchSettings {
        &self.config.network.traversal
    }
}

use p2pnet_nat::engine::{select_best_candidate_group_pair, PunchPacer};

#[derive(Debug)]
struct MatchedChallenge {
    epoch: u64,
    nonce: [u8; 8],
    at: Instant,
}

#[derive(Debug)]
pub(crate) struct PeerPunchRun {
    pub(crate) pacer: PunchPacer,
    pub(crate) mode: u8,
    pub(crate) role: u8,
    pub(crate) remote: PunchProfile,
    reversed: std::sync::Mutex<HashMap<(SocketAddr, usize), u64>>,
    confirmations: std::sync::Mutex<HashMap<(SocketAddr, usize), MatchedChallenge>>,
    pub(crate) endpoint_exchange: std::sync::Mutex<super::endpoint_exchange::EndpointExchange>,
    network: u64,
    lifecycle: PeerSessionGeneration,
    candidates: u64,
    business_after_end: std::sync::atomic::AtomicBool,
    pub(crate) business_ready: Option<tokio::sync::watch::Sender<bool>>,
    pub(crate) ended: std::sync::atomic::AtomicBool,
    pub(crate) firewall: std::sync::Mutex<p2pnet_nat::engine::UdpReachability>,
    pub(crate) sockets: std::sync::atomic::AtomicUsize,
}

impl PeerPunchRun {
    pub(super) fn observe_business(&self, bytes: u64) {
        if bytes > 0 && self.ended.load(std::sync::atomic::Ordering::Acquire) {
            self.business_after_end
                .store(true, std::sync::atomic::Ordering::Release);
        }
        if let Some(ready) = self.business_ready.as_ref().filter(|_| bytes > 0) {
            if !*ready.borrow() {
                ready.send_replace(true);
            }
        }
    }
    pub(super) fn current_for_diagnostics(&self, conn: &PeerConnection, network: u64) -> bool {
        conn.path_state_machine
            .current_epoch()
            .is_some_and(|e| self.owns(conn, network, e.peer_session_generation))
    }
    fn owns(&self, conn: &PeerConnection, network: u64, session: PeerSessionGeneration) -> bool {
        self.network == network
            && self.lifecycle == session
            && self.candidates == conn.remote_candidate_epoch()
    }
}

impl PeerManager {
    pub(crate) async fn claim_punch_run(
        &self,
        peer: &str,
        network: u64,
        lifecycle: PeerSessionGeneration,
    ) -> Option<Arc<PeerPunchRun>> {
        let remote = self.negotiated_profile(peer).await?;
        if remote.tcp_only() {
            return None;
        }
        let settings = self.punch_settings();
        if settings.max_punch_pps == 0 {
            return None;
        }
        let local = self
            .advertised_punch_profile
            .lock()
            .ok()?
            .as_ref()
            .filter(|p| {
                p.network == network
                    && p.generation == self.current_local_profile_generation_sync()
                    && p.at.elapsed() < Duration::from_secs(45)
            })
            .map(|p| p.profile.clone());
        let local = local.or_else(|| self.punch_profile_for_signal(&[], &HashMap::new()))?;
        let pair = select_best_candidate_group_pair(
            &self.local_node_id_for_traversal(),
            std::slice::from_ref(&local),
            peer,
            std::slice::from_ref(&remote),
        )?;
        if pair.mode >= 6
            && (!local.supports_sym_punch
                || !remote.supports_sym_punch
                || settings.disable_sym_hole_punching)
        {
            return None;
        }
        let mut table = self.connections.write().await;
        let conn = table.get_mut(peer)?;
        if !self.peer_session_is_current_sync(peer, lifecycle)
            || self.current_network_generation_sync() != network
            || !conn
                .negotiated_punch
                .as_ref()
                .is_some_and(|p| p.current(conn, network) && p.profile.as_ref() == Some(&remote))
        {
            return None;
        }
        let traffic = (conn.bytes_sent.get(), conn.bytes_received.get());
        if let Some(old) = &conn.punch_run {
            if old.owns(conn, network, lifecycle)
                && old.remote == remote
                && (!old.ended.load(std::sync::atomic::Ordering::Acquire)
                    || !old
                        .business_after_end
                        .load(std::sync::atomic::Ordering::Acquire))
            {
                return None;
            }
            old.ended.store(true, std::sync::atomic::Ordering::Release);
            if let Some(ready) = &old.business_ready {
                ready.send_replace(true);
            }
            old.pacer.clear_punch_state();
        }
        static EPOCH: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);
        let epoch = reserve_sequence(&EPOCH, 8, u64::from(u32::MAX))?;
        let run = Arc::new(PeerPunchRun {
            pacer: PunchPacer::new(epoch, settings.max_punch_pps),
            mode: pair.mode,
            role: pair.role,
            reversed: Default::default(),
            confirmations: Default::default(),
            endpoint_exchange: Default::default(),
            remote,
            network,
            lifecycle,
            candidates: conn.remote_candidate_epoch(),
            business_ready: (settings.lazy_p2p && traffic == (0, 0))
                .then(|| tokio::sync::watch::channel(false).0),
            business_after_end: Default::default(),
            ended: Default::default(),
            firewall: Default::default(),
            sockets: Default::default(),
        });
        conn.punch_run = Some(run.clone());
        Some(run)
    }

    pub(crate) fn current_punch_epoch(&self, peer: &str) -> Option<u64> {
        let table = self.connections.try_read().ok()?;
        let conn = table.get(peer)?;
        let run = conn.punch_run.as_ref()?;
        (run.owns(
            conn,
            self.current_network_generation_sync(),
            self.peer_session_generation_sync(peer)?,
        ) && !run.ended.load(std::sync::atomic::Ordering::Acquire))
        .then(|| run.pacer.epoch())
    }

    pub(crate) fn with_active_punch<T>(
        &self,
        peer: &str,
        epoch: u64,
        f: impl FnOnce(&PeerConnection, &PeerPunchRun) -> T,
    ) -> Option<T> {
        let table = self.connections.try_read().ok()?;
        let conn = table.get(peer)?;
        let network = self.current_network_generation_sync();
        let run = conn.punch_run.as_ref()?;
        let offer = conn.negotiated_punch.as_ref()?;
        if !offer.current(conn, network)
            || offer.profile.as_ref() != Some(&run.remote)
            || !run.owns(conn, network, self.peer_session_generation_sync(peer)?)
            || run
                .business_ready
                .as_ref()
                .is_some_and(|ready| !*ready.borrow())
            || run.pacer.epoch() != epoch
            || run.ended.load(std::sync::atomic::Ordering::Acquire)
        {
            return None;
        }
        Some(f(conn, run))
    }

    pub(crate) fn with_punch_run<T>(
        &self,
        peer: &str,
        target: p2pnet_nat::engine::PunchTarget,
        epoch: u64,
        f: impl FnOnce(&PeerConnection, &PeerPunchRun) -> T,
    ) -> Option<T> {
        self.with_active_punch(peer, epoch, |conn, run| {
            let endpoint = target.address;
            let announced = conn.signaled_candidates.contains(&endpoint.to_string())
                && is_negotiated_source(conn.candidate_source_for_endpoint(endpoint));
            let witnessed =
                run.reversed.lock().ok()?.get(&(endpoint, target.socket)) == Some(&epoch);
            (announced || witnessed).then(|| f(conn, run))
        })
        .flatten()
    }

    /// A valid request can witness one exact return address on an announced IP.
    /// Rate, socket and epoch checks still apply to the reverse challenge.
    pub(crate) fn enqueue_compact_confirmation(
        &self,
        peer: &str,
        address: SocketAddr,
        socket: usize,
    ) {
        if let Some(epoch) = self.current_punch_epoch(peer) {
            self.with_active_punch(peer, epoch, |conn, run| {
                run.queue_witnessed_target(
                    conn,
                    epoch,
                    p2pnet_nat::engine::PunchTarget { address, socket },
                );
            });
        }
    }
}

impl PeerPunchRun {
    /// A request and its subsequent receipt share one reverse check. The
    /// address comes from recv_from and the response goes out on that socket.
    pub(crate) fn queue_witnessed_target(
        &self,
        conn: &PeerConnection,
        epoch: u64,
        target: p2pnet_nat::engine::PunchTarget,
    ) {
        if !conn
            .signaled_candidates
            .iter()
            .filter_map(|s| s.parse::<SocketAddr>().ok())
            .any(|announced| {
                announced.ip() == target.address.ip()
                    && is_negotiated_source(conn.candidate_source_for_endpoint(announced))
            })
        {
            return;
        }
        let mut reversed = self.reversed.lock().unwrap_or_else(|e| e.into_inner());
        reversed.retain(|_, round| *round == epoch);
        let pair = (target.address, target.socket);
        if reversed.len() < 4
            && !reversed.contains_key(&pair)
            && self
                .pacer
                .enqueue(epoch, p2pnet_nat::engine::Lane::Regular, target)
        {
            reversed.insert(pair, epoch);
        }
    }

    /// Called under the current peer and key guard, after consuming a pending
    /// challenge on this exact pair. Two independent responses start WG validation.
    pub(crate) fn confirm_compact_response(
        &self,
        target: p2pnet_nat::engine::PunchTarget,
        epoch: u64,
        nonce: [u8; 8],
    ) -> bool {
        let mut recent = self.confirmations.lock().unwrap_or_else(|e| e.into_inner());
        let now = Instant::now();
        recent.retain(|_, sample| {
            sample.epoch == epoch && now.duration_since(sample.at) < Duration::from_secs(3)
        });
        let pair = (target.address, target.socket);
        if let Some(previous) = recent.get(&pair) {
            return previous.nonce != nonce;
        }
        if recent.len() < 64 {
            recent.insert(
                pair,
                MatchedChallenge {
                    epoch,
                    nonce,
                    at: now,
                },
            );
            self.pacer
                .enqueue(epoch, p2pnet_nat::engine::Lane::Regular, target);
        }
        false
    }
}

fn is_negotiated_source(source: CandidatePairSource) -> bool {
    matches!(
        source,
        CandidatePairSource::Signaled
            | CandidatePairSource::Host
            | CandidatePairSource::StunObserved
            | CandidatePairSource::Upnp
            | CandidatePairSource::Pcp
            | CandidatePairSource::NatPmp
    )
}

impl PeerConnection {
    pub(crate) fn compact_session(
        &self,
        local: &str,
    ) -> Option<p2pnet_nat::engine::CompactSession> {
        p2pnet_nat::engine::CompactSession::new(
            &effective_probe_mac_key(self)?,
            self.probe_session_id.as_deref()?,
            local,
            &self.node_id,
        )
    }

    pub(crate) fn compact_datagram_is_current(&self, local: &str, bytes: &[u8]) -> bool {
        self.compact_session(local)
            .is_some_and(|wire| wire.authenticates_outbound(bytes))
    }
}

impl PeerManager {
    /// Final receive-side handoff under the same connection read guard as the
    /// active key and candidate revision. The closure performs one try_send_to.
    pub(crate) fn try_compact_reply<T>(
        &self,
        peer: &str,
        local: &str,
        owner: (u64, PeerSessionGeneration),
        bytes: &[u8],
        send: impl FnOnce(Option<&PeerPunchRun>) -> std::io::Result<T>,
    ) -> std::io::Result<T> {
        let table = self
            .connections
            .try_read()
            .map_err(|_| std::io::ErrorKind::WouldBlock)?;
        let conn = table.get(peer).ok_or(std::io::ErrorKind::NotConnected)?;
        if self.current_network_generation_sync() != owner.0
            || !self.peer_session_is_current_sync(peer, owner.1)
            || !conn
                .negotiated_punch
                .as_ref()
                .is_some_and(|offer| offer.current(conn, owner.0))
            || !conn.compact_datagram_is_current(local, bytes)
        {
            return Err(std::io::ErrorKind::Interrupted.into());
        }
        if let Some(run) = conn.punch_run.as_ref().filter(|r| {
            r.owns(conn, owner.0, owner.1) && !r.ended.load(std::sync::atomic::Ordering::Acquire)
        }) {
            run.pacer.try_send(run.pacer.epoch(), || send(Some(run)))
        } else {
            send(None)
        }
    }
}
