//! Ordinary TCP between per-peer endpoints pinned by both network operators.
//! The accepted candidate generation, probe session and live listener own
//! the path. An offered address by itself never starts a connection.
use super::*;
use crate::config::PathPolicy;
use crate::transport::EncryptedPeerPacket;
use p2pnet_nat::engine::{reserve_sequence, PunchProfile};
use std::io;
use std::num::NonZeroU64;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Mutex;
use tokio::net::tcp::OwnedWriteHalf;

mod service;
mod simultaneous;
mod wire;
pub(crate) use service::serve;

pub(super) struct Publication {
    local: String,
    local_vip: String,
    room: Arc<crate::rooms::RoomAuthorization>,
    address: SocketAddr,
    bound: SocketAddr,
    simultaneous: bool,
    live: AtomicBool,
}

struct Grant {
    listener: Arc<Publication>,
    endpoint: SocketAddr,
    generation: u64,
    session: PeerSessionGeneration,
    public_key: String,
    probe_session: String,
    probe_key: ProbeMacKey,
    simultaneous: bool,
}

impl Grant {
    fn current(&self, conn: &PeerConnection, network: u64) -> bool {
        self.generation == network
            && self.listener.live.load(Ordering::Acquire)
            && conn.public_key == self.public_key
            && conn.probe_session_id.as_ref() == Some(&self.probe_session)
            && conn
                .path_state_machine
                .current_epoch()
                .is_some_and(|epoch| epoch.peer_session_generation == self.session)
            && conn.negotiated_punch.as_ref().is_some_and(|offer| {
                offer.current(conn, network)
                    && offer.profile.as_ref().is_some_and(|p| {
                        p.tcp_candidates.contains(&self.endpoint)
                            && (!self.simultaneous || p.tcp_simultaneous_open)
                    })
            })
            && effective_probe_mac_key(conn) == Some(self.probe_key)
    }

    fn handshake_key(&self, network_id: &str, peer_id: &str) -> [u8; 32] {
        let local = (self.listener.local.as_str(), self.listener.address);
        let peer = (peer_id, self.endpoint);
        let (client, server) = if local.0 < peer.0 {
            (local, peer)
        } else {
            (peer, local)
        };
        let mut context = b"P2WLAN authorized direct TCP v1".to_vec();
        for field in [
            network_id,
            &self.probe_session,
            client.0,
            &client.1.to_string(),
            server.0,
            &server.1.to_string(),
        ] {
            context.extend_from_slice(&(field.len() as u64).to_be_bytes());
            context.extend_from_slice(field.as_bytes());
        }
        hmac(&self.probe_key, &context)
    }
}

pub(crate) struct TcpPath {
    grant: Grant,
    id: NonZeroU64,
    writer: Mutex<Option<OwnedWriteHalf>>,
    live: AtomicBool,
    pub(crate) opening: TcpOpening,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum TcpOpening {
    DialListen,
    Simultaneous,
}

impl TcpOpening {
    pub(super) fn as_str(self) -> &'static str {
        match self {
            Self::DialListen => "dial_listen",
            Self::Simultaneous => "simultaneous",
        }
    }
}

impl std::fmt::Debug for TcpPath {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TcpPath")
            .field("id", &self.id)
            .field("opening", &self.opening)
            .finish_non_exhaustive()
    }
}

impl TcpPath {
    fn new(grant: Grant, writer: OwnedWriteHalf, opening: TcpOpening) -> io::Result<Self> {
        static NEXT: AtomicU64 = AtomicU64::new(1);
        let id = reserve_sequence(&NEXT, 1, u64::MAX)
            .and_then(NonZeroU64::new)
            .ok_or(io::ErrorKind::Other)?;
        Ok(Self {
            id,
            grant,
            writer: Mutex::new(Some(writer)),
            live: AtomicBool::new(true),
            opening,
        })
    }

    #[cfg(test)]
    pub(crate) fn socket_endpoints(&self) -> Option<(SocketAddr, SocketAddr)> {
        let writer = self.writer.lock().ok()?;
        let stream = writer.as_ref()?;
        Some((stream.local_addr().ok()?, stream.peer_addr().ok()?))
    }

    pub(super) fn current(&self, conn: &PeerConnection, network: u64) -> bool {
        self.live.load(Ordering::Acquire) && self.grant.current(conn, network)
    }

    fn close(&self) {
        self.live.store(false, Ordering::Release);
        self.writer.lock().unwrap_or_else(|e| e.into_inner()).take();
    }

    // One bounded nonblocking syscall under the writer lock. A partial frame
    // retires this stream; the caller must not replay its WireGuard counter.
    fn write(&self, record: &[u8]) -> Result<(), WriteFailure> {
        let mut writer = self.writer.lock().unwrap_or_else(|e| e.into_inner());
        if !self.live.load(Ordering::Acquire) || !self.grant.listener.live.load(Ordering::Acquire) {
            return Err(WriteFailure::Unavailable);
        }
        let socket = writer.as_ref().ok_or(WriteFailure::Unavailable)?;
        match socket.try_write(record) {
            Ok(n) if n == record.len() => Ok(()),
            Err(err) if err.kind() == io::ErrorKind::WouldBlock => Err(WriteFailure::Busy),
            result => {
                self.live.store(false, Ordering::Release);
                writer.take();
                if matches!(result, Ok(n) if n > 0) {
                    Err(WriteFailure::Partial)
                } else {
                    Err(WriteFailure::Unavailable)
                }
            }
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum WriteFailure {
    Unavailable,
    Busy,
    Partial,
    Unauthorized,
}

impl PeerManager {
    pub(crate) fn punch_profile_for_peer_signal(
        &self,
        peer: &str,
        candidates: &[String],
        sources: &HashMap<String, String>,
    ) -> Option<PunchProfile> {
        let offer = self.punch_profile_for_signal(candidates, sources);
        if self
            .config
            .network
            .tcp_direct
            .as_ref()
            .is_none_or(|c| !c.peers.contains_key(peer))
        {
            return offer;
        }
        let endpoint = self.tcp_listener.lock().ok().and_then(|listener| {
            listener
                .as_ref()
                .filter(|p| p.live.load(Ordering::Acquire))
                .map(|p| (p.address, p.simultaneous))
        });
        match endpoint {
            Some((endpoint, simultaneous)) => {
                let mut offer = offer.unwrap_or_default();
                offer.tcp_candidates = vec![endpoint];
                offer.tcp_simultaneous_open = simultaneous;
                Some(offer)
            }
            None => offer,
        }
    }

    async fn tcp_grant(&self, peer: &str, listener: &Arc<Publication>) -> Option<Grant> {
        let endpoint = *self.config.network.tcp_direct.as_ref()?.peers.get(peer)?;
        let conns = self.connections.read().await;
        let conn = conns.get(peer)?;
        let network = self.current_network_generation_sync();
        if conn
            .tcp_path
            .as_ref()
            .is_some_and(|p| p.current(conn, network))
        {
            return None;
        }
        let grant = Grant {
            simultaneous: listener.simultaneous
                && conn
                    .negotiated_punch
                    .as_ref()
                    .and_then(|offer| offer.profile.as_ref())
                    .is_some_and(|profile| profile.tcp_simultaneous_open),
            listener: listener.clone(),
            endpoint,
            generation: network,
            session: self.peer_session_generation_sync(peer)?,
            public_key: conn.public_key.clone(),
            probe_session: conn.probe_session_id.clone().filter(|id| !id.is_empty())?,
            probe_key: effective_probe_mac_key(conn)?,
        };
        grant.current(conn, network).then_some(grant)
    }

    async fn tcp_setup_current(&self, peer: &str, grant: &Grant) -> bool {
        self.connections.read().await.get(peer).is_some_and(|conn| {
            self.peer_session_is_current_sync(peer, grant.session)
                && grant.current(conn, self.current_network_generation_sync())
        })
    }

    async fn install_tcp_path(&self, peer: &str, path: &Arc<TcpPath>) -> bool {
        let (_epoch, mut conns) = self.lock_epoch_and_connections_write().await;
        let Some(conn) = conns.get_mut(peer) else {
            return false;
        };
        let network = self.current_network_generation_sync();
        if !path.current(conn, network)
            || !self.peer_session_is_current_sync(peer, path.grant.session)
            || conn
                .tcp_path
                .as_ref()
                .is_some_and(|p| p.current(conn, network))
        {
            return false;
        }
        if let Some(old) = conn.tcp_path.replace(path.clone()) {
            old.close();
        }
        true
    }

    pub(crate) async fn tcp_ingress_current(&self, peer: &str, link: NonZeroU64) -> bool {
        let conns = self.connections.read().await;
        conns.get(peer).is_some_and(|conn| {
            conn.tcp_path.as_ref().is_some_and(|path| {
                path.id == link
                    && self.peer_session_is_current_sync(peer, path.grant.session)
                    && path.current(conn, self.current_network_generation_sync())
            })
        })
    }

    /// Resolve only the configured peer set. Called before WireGuard can
    /// consume a counter or promote a pending responder session.
    pub(crate) async fn tcp_ingress_peer(&self, link: NonZeroU64) -> Option<&str> {
        let pins = &self.config.network.tcp_direct.as_ref()?.peers;
        let conns = self.connections.read().await;
        pins.keys().find_map(|peer| {
            let conn = conns.get(peer)?;
            let path = conn.tcp_path.as_ref()?;
            (path.id == link
                && self.peer_session_is_current_sync(peer, path.grant.session)
                && path.current(conn, self.current_network_generation_sync()))
            .then_some(peer.as_str())
        })
    }

    pub(super) fn select_business_path(
        &self,
        conn: &PeerConnection,
        generation: u64,
        policy: PathPolicy,
        relay: bool,
    ) -> PathSelection {
        let selection = conn.select_path_for_data_with_policy(generation, policy, relay);
        if !selection.direct_confirmed
            && self
                .tcp_data_path(conn, generation, relay, policy)
                .is_some()
        {
            PathSelection::tcp_direct()
        } else {
            selection
        }
    }

    pub(super) fn tcp_data_path<'a>(
        &self,
        conn: &'a PeerConnection,
        network: u64,
        relay: bool,
        policy: PathPolicy,
    ) -> Option<&'a TcpPath> {
        let path = conn.tcp_path.as_deref()?;
        let relay = relay || self.relay_first_required();
        (policy != PathPolicy::RelayOnly
            && !conn.relay_first_confirmation_pending(network, relay)
            && !conn.relay_first_business_pending(network, relay)
            && self.peer_session_is_current_sync(&conn.node_id, path.grant.session)
            && path.current(conn, network))
        .then_some(path)
    }

    pub(crate) async fn write_tcp_business(
        &self,
        packet: &EncryptedPeerPacket,
        network: u64,
        relay: bool,
        prefer_direct: bool,
    ) -> Result<(), WriteFailure> {
        let frame = wire::data_record(&packet.wire_bytes).ok_or(WriteFailure::Unauthorized)?;
        let conns = self.connections.read().await;
        let conn = conns
            .get(&packet.peer_id)
            .ok_or(WriteFailure::Unavailable)?;
        let path = self
            .tcp_data_path(
                conn,
                network,
                relay,
                self.config.relay.effective_path_policy(prefer_direct),
            )
            .ok_or(WriteFailure::Unavailable)?;
        if self.current_network_generation_sync() != network
            || conn
                .select_path_for_data_with_policy(
                    network,
                    self.config.relay.effective_path_policy(prefer_direct),
                    relay,
                )
                .direct_confirmed
        {
            return Err(WriteFailure::Unavailable);
        }
        if !packet.is_business {
            return Err(WriteFailure::Unauthorized);
        }
        let listener = &path.grant.listener;
        let _room = listener
            .room
            .try_original_send_guard(
                packet.room_authorization.as_ref(),
                &packet.peer_id,
                &packet.dst_ip,
                &listener.local_vip,
            )
            .map_err(|error| match error {
                crate::rooms::OriginalRoomSendFailure::Contended => WriteFailure::Busy,
                _ => WriteFailure::Unauthorized,
            })?;
        path.write(&frame)
    }
}

#[cfg(test)]
mod tests;
