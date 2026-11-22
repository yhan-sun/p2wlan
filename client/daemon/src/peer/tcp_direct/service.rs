use super::*;
use crate::config::TcpDirectConfig;
use crate::dataplane_resources::EncryptedRxSink;
use crate::transport::ReceivedEncryptedPacket;
use std::sync::atomic::Ordering::Acquire;
use subtle::ConstantTimeEq;
use tokio::io::AsyncReadExt;
use tokio::net::{tcp::OwnedReadHalf, TcpListener, TcpStream};
use tokio::sync::watch;
use tokio::task::JoinSet;
use tokio::time::{interval, sleep, timeout, MissedTickBehavior};

const MAX_PEERS: usize = 32;
const MAX_HANDSHAKES: usize = 16;
const SETUP: Duration = Duration::from_secs(3);
const RETRY: Duration = Duration::from_secs(2);
const KEEPALIVE: Duration = Duration::from_millis(500);
const ACK_TIMEOUT: Duration = Duration::from_secs(2);

fn concrete(address: SocketAddr) -> bool {
    !address.ip().is_unspecified()
        && !address.ip().is_multicast()
        && !matches!(address, SocketAddr::V4(v4) if v4.ip().is_broadcast())
        && !matches!(address, SocketAddr::V6(v6) if v6.scope_id() != 0)
}

fn valid(config: &TcpDirectConfig, local: &str) -> bool {
    !local.is_empty()
        && local.len() <= wire::MAX_ID
        && concrete(config.listen)
        && config
            .advertise
            .is_none_or(|a| concrete(a) && a.port() != 0 && a.is_ipv4() == config.listen.is_ipv4())
        && (1..=MAX_PEERS).contains(&config.peers.len())
        && config.peers.iter().all(|(peer, address)| {
            !peer.is_empty()
                && peer.len() <= wire::MAX_ID
                && peer != local
                && concrete(*address)
                && address.port() != 0
                && address.is_ipv4() == config.listen.is_ipv4()
        })
}

pub(crate) async fn serve(
    peers: Arc<PeerManager>,
    local: String,
    local_vip: String,
    room: Arc<crate::rooms::RoomAuthorization>,
    rx: EncryptedRxSink,
    stop: watch::Receiver<bool>,
) {
    let Some(config) = peers.config.network.tcp_direct.as_ref() else {
        return;
    };
    if peers.config.relay.effective_path_policy(true) == PathPolicy::RelayOnly {
        return;
    }
    if !valid(config, &local) {
        warn!(
            reason_code = "TCP_DIRECT_CONFIG",
            "invalid direct TCP listener or peer endpoint"
        );
        return;
    }
    match TcpListener::bind(config.listen).await {
        Ok(listener) => {
            let Some(address) = config.advertise.or_else(|| listener.local_addr().ok()) else {
                return;
            };
            let owner = Publication {
                local,
                local_vip,
                room,
                address,
                live: AtomicBool::new(true),
            };
            run_listener(peers, Arc::new(owner), rx, stop, listener).await;
        }
        Err(err) => warn!(reason_code = "TCP_DIRECT_BIND", %err, "direct TCP listener unavailable"),
    }
}

struct ListenerGuard(Arc<Publication>);
impl Drop for ListenerGuard {
    fn drop(&mut self) {
        self.0.live.store(false, Ordering::Release);
    }
}

async fn run_listener(
    peers: Arc<PeerManager>,
    publication: Arc<Publication>,
    rx: EncryptedRxSink,
    mut stop: watch::Receiver<bool>,
    listener: TcpListener,
) {
    let Some(config) = peers.config.network.tcp_direct.as_ref() else {
        return;
    };
    let _guard = ListenerGuard(publication.clone());
    {
        let mut slot = peers.tcp_listener.lock().unwrap_or_else(|e| e.into_inner());
        if slot.as_ref().is_some_and(|p| p.live.load(Acquire)) {
            return;
        }
        *slot = Some(publication.clone());
    }
    let mut tasks = JoinSet::new();
    let handshakes = Arc::new(tokio::sync::Semaphore::new(MAX_HANDSHAKES));
    for (peer, target) in &config.peers {
        if publication.local < *peer {
            let peer = peer.clone();
            let endpoint = *target;
            let source = config.listen.ip();
            let (owner, manager, sink) = (publication.clone(), peers.clone(), rx.clone());
            tasks.spawn(async move {
                loop {
                    if let Some(grant) = manager.tcp_grant(&peer, &owner).await {
                        let setup = async {
                            let mut stream =
                                p2pnet_netbind::connect_tcp_from(endpoint, Some(source), None)
                                    .await?;
                            stream.set_nodelay(true)?;
                            wire::identify(&mut stream, &owner.local).await?;
                            let key =
                                grant.handshake_key(&manager.config.network.network_id, &peer);
                            let key = wire::authenticate(&mut stream, key, true).await?;
                            io::Result::Ok((stream, key))
                        };
                        match timeout(SETUP, setup).await {
                            Ok(Ok((stream, key))) => {
                                run_link(&manager, &peer, &sink, grant, stream, key, true).await
                            }
                            Ok(Err(err)) => {
                                debug!(peer, reason_code = "TCP_DIRECT_SETUP_FAILED", error = %err)
                            }
                            Err(_) => debug!(peer, reason_code = "TCP_DIRECT_SETUP_TIMEOUT"),
                        }
                    }
                    sleep(RETRY).await;
                }
            });
        }
    }
    while !*stop.borrow() {
        tokio::select! {
            result = stop.changed() => if result.is_err() || *stop.borrow() { break; },
            Some(_) = tasks.join_next(), if !tasks.is_empty() => {},
            result = listener.accept() => {
                let (mut stream, source) = match result {
                    Ok(pair) => pair,
                    Err(err) => { warn!(reason_code = "TCP_DIRECT_ACCEPT", %err); break; }
                };
                if tasks.len() >= MAX_PEERS + MAX_HANDSHAKES || !config.peers.iter().any(|(peer, pin)| peer < &publication.local && pin.ip() == source.ip()) { continue; }
                let Ok(permit) = handshakes.clone().try_acquire_owned() else { continue };
                let (owner, manager, sink) = (publication.clone(), peers.clone(), rx.clone());
                tasks.spawn(async move {
                    let setup = async {
                        stream.set_nodelay(true)?;
                        let peer = wire::read_identity(&mut stream).await?;
                        let grant = manager.tcp_grant(&peer, &owner).await.ok_or(io::ErrorKind::PermissionDenied)?;
                        if peer >= owner.local || grant.endpoint.ip() != source.ip() { return Err(io::ErrorKind::PermissionDenied.into()); }
                        let key = grant.handshake_key(&manager.config.network.network_id, &peer);
                        let key = wire::authenticate(&mut stream, key, false).await?;
                        io::Result::Ok((peer, grant, key))
                    };
                    let result = timeout(SETUP, setup).await;
                    drop(permit);
                    if let Ok(Ok((peer, grant, key))) = result {
                        run_link(&manager, &peer, &sink, grant, stream, key, false).await;
                    }
                });
            }
        }
    }
    publication.live.store(false, Ordering::Release);
    tasks.shutdown().await;
}

// Closing the reader or aborting the listener also releases the writer stored
// on PeerConnection, even if the peer hasn't issued another data send.
struct LinkGuard(Arc<TcpPath>);
impl Drop for LinkGuard {
    fn drop(&mut self) {
        self.0.close();
    }
}

struct Liveness {
    key: [u8; 32],
    client: bool,
    pending: Mutex<Option<([u8; 32], Instant)>>,
}

async fn run_link(
    peers: &PeerManager,
    peer: &str,
    sink: &EncryptedRxSink,
    grant: Grant,
    stream: TcpStream,
    key: [u8; 32],
    client: bool,
) {
    let (reader, writer) = stream.into_split();
    let Ok(path) = TcpPath::new(grant, writer).map(Arc::new) else {
        return;
    };
    let _guard = LinkGuard(path.clone());
    if !peers.install_tcp_path(peer, &path).await {
        return;
    }
    let health = Liveness {
        key,
        client,
        pending: Mutex::new(None),
    };
    debug!(
        peer,
        reason_code = "TCP_DIRECT_CONFIRMED",
        "direct TCP stream authenticated"
    );
    tokio::select! {
        result = read_records(reader, &path, &health, peers, peer, sink) => {
            debug!(peer, reason_code = "TCP_DIRECT_READ_END", ?result);
        }
        () = keepalive(&path, &health, peers, peer) => {
            debug!(peer, reason_code = "TCP_DIRECT_EXPIRED");
        }
    }
}

async fn keepalive(path: &TcpPath, health: &Liveness, peers: &PeerManager, peer: &str) {
    let mut ticks = interval(KEEPALIVE);
    ticks.set_missed_tick_behavior(MissedTickBehavior::Skip);
    loop {
        ticks.tick().await;
        if !peers.tcp_ingress_current(peer, path.id).await {
            return;
        }
        let mut pending = health.pending.lock().unwrap_or_else(|e| e.into_inner());
        if let Some((_, at)) = *pending {
            if at.elapsed() >= ACK_TIMEOUT {
                return;
            }
        } else {
            let nonce = rand::random();
            if path
                .write(&wire::heartbeat(
                    &health.key,
                    wire::PING,
                    health.client,
                    &nonce,
                ))
                .is_err()
            {
                return;
            }
            *pending = Some((nonce, Instant::now()));
        }
    }
}

async fn read_records(
    mut reader: OwnedReadHalf,
    path: &TcpPath,
    health: &Liveness,
    peers: &PeerManager,
    peer: &str,
    sink: &EncryptedRxSink,
) -> io::Result<()> {
    let provenance = Arc::new(
        crate::business_evidence::PhysicalIngressContext::direct_tcp(
            path.grant.generation,
            path.id,
        ),
    );
    loop {
        let len = reader.read_u16().await?;
        if len == wire::PING || len == wire::PONG {
            let mut nonce = [0; 32];
            let mut tag = [0; 32];
            reader.read_exact(&mut nonce).await?;
            reader.read_exact(&mut tag).await?;
            let expected = wire::heartbeat(&health.key, len, !health.client, &nonce);
            if !bool::from(tag.as_slice().ct_eq(&expected[34..])) {
                return Err(io::ErrorKind::PermissionDenied.into());
            }
            if len == wire::PING {
                path.write(&wire::heartbeat(
                    &health.key,
                    wire::PONG,
                    health.client,
                    &nonce,
                ))
                .map_err(|_| io::ErrorKind::BrokenPipe)?;
            } else {
                let mut pending = health.pending.lock().unwrap_or_else(|e| e.into_inner());
                if !pending.as_ref().is_some_and(|(n, _)| *n == nonce) {
                    return Err(io::ErrorKind::InvalidData.into());
                }
                *pending = None;
            }
            continue;
        }
        if len < 32 {
            return Err(io::ErrorKind::InvalidData.into());
        }
        let mut wire_bytes = vec![0; usize::from(len)];
        reader.read_exact(&mut wire_bytes).await?;
        if crate::transport::wire_counter(&wire_bytes).is_none()
            || !peers.tcp_ingress_current(peer, path.id).await
        {
            return Err(io::ErrorKind::InvalidData.into());
        }
        sink.send(ReceivedEncryptedPacket {
            source: None,
            local_endpoint: None,
            relay_endpoint: None,
            relay_connection_id: None,
            relay_peer_id: None,
            socket_index: None,
            direct_socket: None,
            udp_transport_owner: None,
            network_generation: Some(path.grant.generation),
            profile_sampled: false,
            udp_received: None,
            transport_queue_send_started: None,
            wire_bytes,
            physical_ingress: Some(provenance.clone()),
            original_relay_read: None,
            original_udp_read: None,
        })
        .await
        .map_err(|_| io::ErrorKind::BrokenPipe)?;
    }
}
