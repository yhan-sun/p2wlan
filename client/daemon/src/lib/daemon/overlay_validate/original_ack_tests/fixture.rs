use super::*;
use crate::config::{Config, PathPolicy};
use crate::control::PeerInfo;
use crate::dataplane::DataPlane;
use crate::overlay_requests::{
    CanonicalOverlayRequest, OriginalOverlayAck, OverlayCreditOutcome, OverlayCreditUnknown,
    PhysicalPublicationState,
};
use crate::peer::{NetworkPath, OriginalOverlayCurrentOwners};
use crate::relay::RelayTransport;
use crate::request_carriage::RawRequestDelivery;
use crate::transport::{InboundEvidenceFeed, OriginalOverlayIngressSource, WireGuardTransport};
use futures_util::FutureExt;
use p2pnet_crypto::NodeIdentity;
use p2pnet_relay::{OriginalRelayDelivery, RelayServer};
use p2pnet_tun::mock::MockTunDevice;
use p2pnet_wireguard::{HandshakeInitiator, HandshakeResponder, TransportSession};
use std::future::Future;
use std::net::SocketAddr;
use std::panic::AssertUnwindSafe;
use std::result::Result;
use tokio::sync::{mpsc, watch};
use tokio::task::JoinHandle;

type Check = Result<(), String>;
#[path = "ack_contention.rs"]
mod ack_contention;
#[path = "contention.rs"]
mod contention;
pub(super) use ack_contention::AckContentionCase;
#[path = "lifecycle.rs"]
mod lifecycle;
#[path = "request_contention.rs"]
mod request_contention;
pub(super) use lifecycle::LifecycleCase;
#[path = "identity.rs"]
mod identity;
pub(super) use identity::IdentityCase;
#[path = "echo_transfer.rs"]
mod echo_transfer;
pub(super) use echo_transfer::EchoCase;
#[path = "echo_contention.rs"]
mod echo_contention;
pub(super) use echo_contention::EchoContentionCase;
#[path = "publication_order.rs"]
mod publication_order;
#[path = "runtime_vip.rs"]
mod runtime_vip;
pub(super) use runtime_vip::RuntimeVipCase;
#[path = "asymmetric_endpoint.rs"]
mod asymmetric_endpoint;
pub(super) use asymmetric_endpoint::{
    exercise_asymmetric_endpoint, exercise_asymmetric_invalidation,
    exercise_asymmetric_receive_socket, exercise_asymmetric_receive_socket_invalidation,
    exercise_equal_remote_distinct_socket,
};
#[path = "common_hub.rs"]
mod common_hub;
pub(super) use common_hub::{exercise_common_native, exercise_common_replacement};
const NODE_A: &str = "original-ack-a";
const NODE_B: &str = "original-ack-b";
const VIP_A: &str = "10.20.0.1";
const VIP_B: &str = "10.20.0.2";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum PathKind {
    Direct,
    Relay,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum Scenario {
    Fresh,
    DuplicateAndNew,
    MissingSource,
    NativeHandler,
    Contention,
    AckContention(AckContentionCase),
    RequestContention(AckContentionCase),
    Lifecycle(LifecycleCase),
    Identity(IdentityCase),
    EchoTransfer(EchoCase),
    EchoContention(EchoContentionCase),
    PublicationOrder,
    RuntimeVip(RuntimeVipCase),
}

fn require(condition: bool, reason: &str) -> Check {
    condition.then_some(()).ok_or_else(|| reason.to_string())
}

fn stats() -> OverlayStats {
    OverlayStats {
        sent: 0,
        received_valid: 0,
        received_invalid: 0,
        verified_round_trips: 0,
        last_seq: 0,
    }
}

#[derive(Clone, Copy)]
struct Budget {
    end: tokio::time::Instant,
}

impl Budget {
    fn new() -> Self {
        Self::with_total(Duration::from_secs(10))
    }

    fn with_total(total: Duration) -> Self {
        Self {
            end: tokio::time::Instant::now() + total,
        }
    }

    fn body_end(self) -> tokio::time::Instant {
        self.end - Duration::from_secs(1)
    }

    async fn step<T>(self, label: &str, future: impl Future<Output = T>) -> Result<T, String> {
        let end = self
            .body_end()
            .min(tokio::time::Instant::now() + Duration::from_secs(2));
        tokio::time::timeout_at(end, future)
            .await
            .map_err(|_| format!("{label}: fixed fixture prerequisite timeout"))
    }
}

struct Task {
    label: &'static str,
    handle: Option<JoinHandle<Check>>,
    graceful: bool,
}

#[derive(Default)]
struct Owners {
    tasks: Vec<Task>,
    readers_stop: Vec<watch::Sender<bool>>,
    relays: Vec<RelayTransport>,
    server: Option<RelayServer>,
}

impl Owners {
    fn spawn(&mut self, label: &'static str, future: impl Future<Output = Check> + Send + 'static) {
        self.tasks.push(Task {
            label,
            handle: Some(tokio::spawn(future)),
            graceful: false,
        });
    }

    fn spawn_graceful(
        &mut self,
        label: &'static str,
        future: impl Future<Output = Check> + Send + 'static,
    ) {
        self.tasks.push(Task {
            label,
            handle: Some(tokio::spawn(future)),
            graceful: true,
        });
    }

    async fn close(&mut self, budget: Budget) -> Check {
        for stop in &self.readers_stop {
            let _ = stop.send(true);
        }
        for task in &self.tasks {
            if !task.graceful {
                if let Some(handle) = &task.handle {
                    handle.abort();
                }
            }
        }
        // Cancel owned converters before intentionally closing their native
        // clients, so an expected Closed item is not mistaken for a body error.
        for relay in &self.relays {
            relay.abort_writer();
        }
        let mut failures = Vec::new();
        for task in &mut self.tasks {
            let Some(handle) = task.handle.as_mut() else {
                continue;
            };
            match tokio::time::timeout_at(budget.end, handle).await {
                Ok(result) => {
                    // Every ready JoinHandle is taken, including error outcomes.
                    // No later cleanup/drop path polls it a second time.
                    task.handle.take();
                    match result {
                        Ok(Ok(())) => {}
                        Err(error) if error.is_cancelled() && !task.graceful => {}
                        other => failures
                            .push(format!("{}: unexpected owned join {other:?}", task.label)),
                    }
                }
                Err(_) => failures.push(format!(
                    "{}: owned join exceeded fixed fixture end",
                    task.label
                )),
            }
        }
        if let Some(server) = self.server.take() {
            if tokio::time::timeout_at(budget.end, server.shutdown())
                .await
                .is_err()
            {
                failures.push("actual Relay server did not join within fixed fixture end".into());
            }
        }
        if failures.is_empty() {
            Ok(())
        } else {
            Err(failures.join("; "))
        }
    }
}

impl Drop for Owners {
    fn drop(&mut self) {
        for stop in &self.readers_stop {
            let _ = stop.send(true);
        }
        for relay in &self.relays {
            relay.abort_writer();
        }
        for task in &self.tasks {
            if let Some(handle) = &task.handle {
                handle.abort();
            }
        }
        // Unwinding fallback is cancellation only. The explicit close above,
        // never this Drop, is the fixture's owned-join success evidence.
    }
}

struct Endpoint {
    node: &'static str,
    identity: NodeIdentity,
    vip: &'static str,
    remote_node: &'static str,
    remote_vip: &'static str,
    peers: Arc<PeerManager>,
    wireguard: WireGuardTransport,
    udp: Arc<RwLock<Option<UdpTransport>>>,
    relay: Arc<RwLock<Option<RelayTransport>>>,
    room: Arc<crate::rooms::RoomAuthorization>,
    controller: MockTunController,
    routed: mpsc::Receiver<RawRequestDelivery>,
    written: mpsc::Receiver<Vec<u8>>,
    overlay: mpsc::Receiver<OverlayIngressDelivery>,
    _udp_publication: watch::Sender<Option<UdpTransport>>,
    timeline: Arc<ConnectionTimeline>,
    seen: VecDeque<(u64, u32)>,
    stats: OverlayStats,
    sent: HashMap<u64, SentOverlayNonce>,
    order: VecDeque<u64>,
    bursts: HashMap<String, OverlayBurst>,
    pending: VecDeque<PendingOverlayEcho>,
    next_nonce: u64,
    next_seq: u32,
    common_encrypted_input: Option<mpsc::Sender<crate::transport::ReceivedEncryptedPacket>>,
}

impl Endpoint {
    #[allow(clippy::too_many_arguments)]
    async fn create(
        node: &'static str,
        vip: &'static str,
        remote_node: &'static str,
        remote_vip: &'static str,
        path: PathKind,
        hub: Option<&str>,
        owners: &mut Owners,
        budget: Budget,
        keep_bootstrap_vip: bool,
    ) -> Result<Self, String> {
        Self::create_inner(
            node,
            vip,
            remote_node,
            remote_vip,
            path,
            hub,
            owners,
            budget,
            keep_bootstrap_vip,
            false,
            1,
            None,
        )
        .await
    }

    async fn create_for_validation(
        node: &'static str,
        vip: &'static str,
        remote_node: &'static str,
        remote_vip: &'static str,
        owners: &mut Owners,
        budget: Budget,
    ) -> Result<Self, String> {
        Self::create_inner(
            node,
            vip,
            remote_node,
            remote_vip,
            PathKind::Direct,
            None,
            owners,
            budget,
            false,
            true,
            1,
            None,
        )
        .await
    }

    #[allow(clippy::too_many_arguments)]
    async fn create_inner(
        node: &'static str,
        vip: &'static str,
        remote_node: &'static str,
        remote_vip: &'static str,
        path: PathKind,
        hub: Option<&str>,
        owners: &mut Owners,
        budget: Budget,
        keep_bootstrap_vip: bool,
        actual_validation: bool,
        pool_count: usize,
        common_hub: Option<&str>,
    ) -> Result<Self, String> {
        let mut config =
            Config::generate_default("http://ctrl.test", "default").map_err(|e| e.to_string())?;
        config.node.node_id = node.to_string();
        if keep_bootstrap_vip {
            require(
                config.network.virtual_ip == "10.20.0.1" && config.network.virtual_ip != vip,
                "runtime VIP fixture must retain the actual different default manager Config",
            )?;
        } else {
            config.network.virtual_ip = vip.to_string();
        }
        config.relay.path_policy = PathPolicy::Auto;
        let identity = if actual_validation {
            let private = hex::decode(&config.node.private_key).map_err(|e| e.to_string())?;
            let private: [u8; 32] = private
                .try_into()
                .map_err(|_| "actual Config private key length")?;
            NodeIdentity::from_private_key(private)
        } else {
            NodeIdentity::generate()
        };
        let peers = Arc::new(PeerManager::new(config));
        let (wireguard, _unused_outbound) = WireGuardTransport::new_with_request_carriage();
        let (encrypted_tx, encrypted_rx) = mpsc::channel(16);
        let udp_transport = if path == PathKind::Direct {
            let udp = budget
                .step(
                    "bind actual UDP",
                    UdpTransport::bind(
                        "127.0.0.1:0"
                            .parse()
                            .map_err(|e: std::net::AddrParseError| e.to_string())?,
                        peers.clone(),
                    ),
                )
                .await?
                .map_err(|e| e.to_string())?;
            let udp = if pool_count > 1 {
                budget
                    .step("bind actual owned pool", udp.with_socket_pool(pool_count))
                    .await?
                    .map_err(|e| e.to_string())?
            } else {
                udp
            };
            let udp = if actual_validation {
                udp.with_local_node_id(node)
                    .with_wireguard_transport(wireguard.clone())
                    .with_inbound_channel(encrypted_tx.clone())
                    .with_dplpmtud_local_virtual_ip(
                        vip.parse()
                            .map_err(|e: std::net::AddrParseError| e.to_string())?,
                    )
            } else {
                udp
            };
            // This is the actual publication consumed by the actual single
            // reader, not a synthesized OriginalUdpIngressSource/fact.
            udp.set_inbound_publication_owner(if node == NODE_A { 28001 } else { 28002 });
            Some(udp)
        } else {
            None
        };
        let mut relay_rx: Option<mpsc::Receiver<OriginalRelayDelivery>> = None;
        let relay_transport = if path == PathKind::Relay {
            let (relay, rx) = if let Some(common) = common_hub {
                let primary = hub.ok_or("missing actual primary Relay")?;
                let preferred = if node == NODE_A { "one" } else { "two" };
                let selected = budget
                    .step(
                        "select actual different primary and common Relay",
                        crate::relay::select_relay_with_cooldowns_for_read::<OriginalRelayDelivery>(
                            &[
                                crate::relay::RelayCandidateConfig::legacy(format!(
                                    "{preferred}@{primary}"
                                )),
                                crate::relay::RelayCandidateConfig::legacy(format!(
                                    "common@{common}"
                                )),
                            ],
                            &[preferred.into()],
                            Duration::from_secs(1),
                            node,
                            peers.clone(),
                            None,
                            None,
                            true,
                            None,
                            &HashMap::new(),
                        ),
                    )
                    .await?;
                let relay = selected
                    .transport
                    .ok_or("actual common Relay selection failed")?;
                owners.relays.push(relay.clone());
                let rx = selected
                    .relay_rx
                    .ok_or("actual common merged reader missing")?;
                (relay, rx)
            } else {
                let (relay, rx) = budget
                    .step(
                        "register original Relay reader",
                        RelayTransport::connect_secure_for_read::<OriginalRelayDelivery>(
                            hub.ok_or("missing actual Relay hub")?,
                            "default",
                            node,
                            peers.clone(),
                            None,
                            true,
                            None,
                        ),
                    )
                    .await?
                    .map_err(|e| e.to_string())?;
                owners.relays.push(relay.clone());
                (relay, rx)
            };
            relay_rx = Some(rx);
            Some(relay)
        } else {
            None
        };
        let udp = Arc::new(RwLock::new(udp_transport.clone()));
        let relay = Arc::new(RwLock::new(relay_transport.clone()));
        let room = Arc::new(crate::rooms::RoomAuthorization::new("default"));
        let timeline = ConnectionTimeline::new(node, 0);
        let (tun, controller) = MockTunDevice::new_pair(node, 1420, vip);
        let (mut plane, routed, inbound_tx) =
            DataPlane::new_bidirectional_with_request_carriage(tun, peers.clone());
        owners.spawn("actual bidirectional DataPlane", async move {
            plane.run().await.map_err(|e| e.to_string())
        });
        let (written_tx, written) = mpsc::channel(8);
        let drain = controller.clone();
        owners.spawn("owned actual MockTun write drain", async move {
            while let Ok(packet) = drain.recv_written().await {
                if written_tx.send(packet).await.is_err() {
                    break;
                }
            }
            Ok(())
        });
        let (overlay_tx, overlay) = mpsc::channel(16);
        let (udp_publication, udp_updates) = watch::channel(udp_transport.clone());
        let common_encrypted_input = common_hub.map(|_| encrypted_tx.clone());
        let inbound_wireguard = wireguard.clone();
        let inbound_peers = peers.clone();
        let evidence = InboundEvidenceFeed {
            relay_transport: relay.clone(),
            timeline: None,
            overlay_ingress_tx: Some(overlay_tx),
        };
        owners.spawn("actual WireGuard inbound actor", async move {
            inbound_wireguard
                .run_inbound_with_peers_live_udp_and_relay(
                    encrypted_rx,
                    inbound_tx,
                    Some(inbound_peers),
                    udp_updates,
                    Some(evidence),
                )
                .await
                .map_err(|e| e.to_string())
        });
        if let Some(transport) = udp_transport {
            for index in 0..transport.socket_count() {
                let (stop, stopped) = watch::channel(false);
                owners.readers_stop.push(stop);
                let transport = transport.clone();
                let encrypted_tx = encrypted_tx.clone();
                owners.spawn("actual original UDP owned reader", async move {
                    if index == 0 {
                        transport
                            .run_original_reader_until_for_test(encrypted_tx, stopped)
                            .await
                    } else {
                        transport
                            .run_original_indexed_reader_until_for_test(
                                index,
                                encrypted_tx,
                                stopped,
                            )
                            .await
                    }
                    .map_err(|e| e.to_string())
                });
            }
        } else if let (Some(transport), Some(rx)) = (relay_transport, relay_rx) {
            owners.spawn("actual original Relay queue converter", async move {
                transport
                    .run_inbound_for_read(rx, encrypted_tx, None)
                    .await
                    .map_err(|e| e.to_string())
            });
        }
        Ok(Self {
            node,
            identity,
            vip,
            remote_node,
            remote_vip,
            peers,
            wireguard,
            udp,
            relay,
            room,
            controller,
            routed,
            written,
            overlay,
            _udp_publication: udp_publication,
            timeline,
            seen: VecDeque::new(),
            stats: stats(),
            sent: HashMap::new(),
            order: VecDeque::new(),
            bursts: HashMap::new(),
            pending: VecDeque::new(),
            next_nonce: 0x28_0000,
            next_seq: 28,
            common_encrypted_input,
        })
    }

    fn sourced_owners(&self) -> SourcedOverlayOwners {
        SourcedOverlayOwners {
            wireguard: self.wireguard.clone(),
            relay: self.relay.clone(),
            room: self.room.clone(),
        }
    }

    fn current_owners(&self) -> OriginalOverlayCurrentOwners<'_> {
        OriginalOverlayCurrentOwners {
            wireguard: &self.wireguard,
            udp: &self.udp,
            relay: &self.relay,
            room: &self.room,
        }
    }

    async fn local_udp(&self) -> Result<Option<SocketAddr>, String> {
        self.udp
            .read()
            .await
            .as_ref()
            .map(|udp| udp.local_addr().map_err(|e| e.to_string()))
            .transpose()
    }

    async fn install_peer(
        &self,
        remote_key: String,
        remote_udp: Option<SocketAddr>,
        session: TransportSession,
        path: PathKind,
        budget: Budget,
    ) -> Check {
        budget
            .step(
                "actual peer registration",
                self.peers.add_peer(&PeerInfo {
                    node_id: self.remote_node.to_string(),
                    public_key: remote_key,
                    endpoint: remote_udp.map_or_else(String::new, |endpoint| endpoint.to_string()),
                    virtual_ip: self.remote_vip.to_string(),
                    online: true,
                    ..PeerInfo::default()
                }),
            )
            .await?;
        let lifecycle = self
            .peers
            .peer_session_generation_sync(self.remote_node)
            .ok_or("actual remote lifecycle missing")?;
        budget
            .step(
                "install actual authorized Noise session",
                self.wireguard
                    .replace_session_for_lifecycle(self.remote_node, session, lifecycle),
            )
            .await?;
        if path == PathKind::Direct {
            let endpoint = remote_udp.ok_or("actual opposite UDP endpoint missing")?;
            let local = self
                .local_udp()
                .await?
                .ok_or("actual local UDP endpoint missing")?;
            budget
                .step(
                    "actual on-link network setup",
                    self.peers
                        .set_local_interface_networks(vec![p2pnet_nat::LocalNetwork::new(
                            "127.0.0.1"
                                .parse()
                                .map_err(|e: std::net::AddrParseError| e.to_string())?,
                            8,
                        )]),
                )
                .await?;
            budget
                .step(
                    "actual host candidate setup",
                    self.peers.add_candidates_with_sources(
                        self.remote_node,
                        &[endpoint.to_string()],
                        &HashMap::from([(endpoint.to_string(), "host".to_string())]),
                    ),
                )
                .await?;
            budget
                .step(
                    "original Direct probe admission",
                    self.peers
                        .record_direct_probe_success_with_latency_and_local_endpoint(
                            self.remote_node,
                            endpoint,
                            Some(Duration::from_millis(1)),
                            Some(local),
                        ),
                )
                .await?;
            budget
                .step(
                    "original Direct compatibility commit",
                    self.peers.record_direct_success_with_local_endpoint(
                        self.remote_node,
                        Some(endpoint),
                        Some(local),
                    ),
                )
                .await?;
            let generation = self.peers.current_network_generation_sync();
            let lan = budget
                .step(
                    "verify actual current LAN admission",
                    self.peers
                        .active_direct_path_snapshot(self.remote_node, generation, true),
                )
                .await?;
            if lan.is_none() {
                let conn = budget
                    .step(
                        "diagnose actual failed LAN admission",
                        self.peers.get_connection(self.remote_node),
                    )
                    .await?
                    .ok_or("actual LAN peer disappeared")?;
                return Err(format!(
                    "actual LAN admission missing: peer={} state={:?} online={} direct_g={} current_g={} endpoint={:?} candidates={:?} health={:?}",
                    self.remote_node, conn.state, conn.online, conn.direct_generation,
                    generation, conn.endpoint, conn.candidates, conn.direct_health
                ));
            }
            if let Some(snapshot) = lan {
                if !self
                    .peers
                    .active_direct_path_snapshot_is_current_sync(self.remote_node, snapshot)
                {
                    return Err(format!(
                        "actual LAN synchronous fence rejected: peer={} snapshot_g={} current_g={} snapshot_seq={} mirror_seq={:?} direct={} snapshot_life={:?} current_life={:?}",
                        self.remote_node,
                        snapshot.generation,
                        self.peers.current_network_generation_sync(),
                        snapshot.direct_commit_seq,
                        self.peers.direct_commit_seq_sync(self.remote_node),
                        self.peers.is_direct_sync(self.remote_node),
                        snapshot.peer_session_generation,
                        self.peers.peer_session_generation_sync(self.remote_node),
                    ));
                }
            }
        } else {
            let relay = self
                .relay
                .read()
                .await
                .clone()
                .ok_or("actual Relay transport missing")?;
            let generation = self.peers.current_network_generation_sync();
            budget
                .step(
                    "actual Relay publication readiness",
                    self.peers.mark_relay_transport_ready_with_transport(
                        self.remote_node,
                        relay.endpoint(),
                        generation,
                        Some(relay.connection_id()),
                    ),
                )
                .await?;
            let admitted = budget
                .step(
                    "explicit fixture Relay route admission",
                    self.peers.confirm_relay_peer_with_transport(
                        self.remote_node,
                        relay.endpoint(),
                        generation,
                        Some(relay.connection_id()),
                    ),
                )
                .await?;
            let connection = budget
                .step(
                    "inspect actual Relay admission",
                    self.peers.get_connection(self.remote_node),
                )
                .await?
                .ok_or("actual admitted peer disappeared")?;
            require(
                connection.online
                    && connection.relay_ready_generation == Some(generation)
                    && connection.relay_ready_endpoint.as_deref() == Some(relay.endpoint())
                    && connection.relay_ready_connection_id == Some(relay.connection_id())
                    && connection.relay_confirmed_generation == Some(generation)
                    && connection.relay_confirmed_endpoint.as_deref() == Some(relay.endpoint())
                    && connection.relay_confirmed_connection_id == Some(relay.connection_id()),
                "fixture admission did not bind actual current ready/confirmed generation and publication",
            )?;
            // The original confirmer returns whether confirmation changed.
            // The unchanged counterpart during a generation/re-add recovery
            // can already own this exact tuple; false is idempotence there.
            let _confirmation_changed = admitted;
        }
        Ok(())
    }
}

fn session_pair_for(
    a: &NodeIdentity,
    b: &NodeIdentity,
) -> Result<(TransportSession, TransportSession, String, String), String> {
    let a_key = hex::encode(a.public_key());
    let b_key = hex::encode(b.public_key());
    let mut initiator = HandshakeInitiator::new(a.clone(), b.public_key(), None);
    let mut responder = HandshakeResponder::new(b.clone(), None);
    let initiation = initiator.create_initiation().map_err(|e| e.to_string())?;
    let (response, b_keys) = responder
        .consume_initiation_and_respond(&initiation)
        .map_err(|e| e.to_string())?;
    let a_keys = initiator
        .consume_response(&response)
        .map_err(|e| e.to_string())?;
    Ok((
        TransportSession::new(a_keys),
        TransportSession::new(b_keys),
        a_key,
        b_key,
    ))
}

#[derive(Clone)]
struct ActualDelivery {
    event: OverlayIngressEvent,
    source: Option<OriginalOverlayIngressSource>,
}

async fn actual_overlay_delivery(
    endpoint: &mut Endpoint,
    budget: Budget,
) -> Result<OverlayIngressDelivery, String> {
    budget
        .step(
            "actual authenticated overlay queue",
            endpoint.overlay.recv(),
        )
        .await?
        .ok_or_else(|| "actual overlay queue ended before delivery".to_string())
}

async fn actual_delivery(
    endpoint: &mut Endpoint,
    budget: Budget,
) -> Result<ActualDelivery, String> {
    let delivery = actual_overlay_delivery(endpoint, budget).await?;
    actual_delivery_from(endpoint, delivery, budget).await
}

// The original WG actor publishes this authenticated feed before its separate
// TUN-facing queue handoff. Wrong runtime destinations reach the native
// entrance with this real source, but are correctly rejected by DataPlane
// before Tun.write. This helper makes no TUN-injection or completed-drop claim.
async fn actual_rx_delivery_without_tun(
    endpoint: &mut Endpoint,
    budget: Budget,
) -> Result<ActualDelivery, String> {
    let delivery = actual_overlay_delivery(endpoint, budget).await?;
    let (event, source) = delivery.into_parts();
    require_actual_delivery_source(endpoint, ActualDelivery { event, source })
}

async fn actual_delivery_from(
    endpoint: &mut Endpoint,
    delivery: OverlayIngressDelivery,
    budget: Budget,
) -> Result<ActualDelivery, String> {
    let (event, source) = delivery.into_parts();
    let written = budget
        .step(
            "actual decrypted DataPlane MockTun write",
            endpoint.written.recv(),
        )
        .await?
        .ok_or("actual DataPlane write drain ended")?;
    require(
        written == event.packet,
        "overlay feed and actual TUN write disagree",
    )?;
    require_actual_delivery_source(endpoint, ActualDelivery { event, source })
}

fn require_actual_delivery_source(
    endpoint: &Endpoint,
    delivery: ActualDelivery,
) -> Result<ActualDelivery, String> {
    require(
        delivery.event.peer_id == endpoint.remote_node,
        "actual authenticated remote node changed",
    )?;
    let original = delivery
        .source
        .as_ref()
        .ok_or("actual successful decrypt did not retain its original source")?;
    require(
        original.session().belongs_to(&endpoint.wireguard),
        "actual decrypt source belongs to a different WG owner",
    )?;
    require(
        original.session().peer_id() == endpoint.remote_node,
        "actual decrypt source peer changed",
    )?;
    require(
        original.session().authorized_peer_lifecycle()
            == endpoint
                .peers
                .peer_session_generation_sync(endpoint.remote_node),
        "actual decrypt key is not authorized for the actual current peer life",
    )?;
    require(
        original.network_generation() == Some(endpoint.peers.current_network_generation_sync()),
        "actual reader/decrypt generation changed",
    )?;
    Ok(delivery)
}

async fn actual_send(
    endpoint: &Endpoint,
    delivery: RawRequestDelivery,
    path: PathKind,
    budget: Budget,
) -> Check {
    let sent = budget
        .step(
            "original WG encryption and network slow send core",
            crate::network_outbound::send_original_for_test(
                delivery,
                &endpoint.wireguard,
                &endpoint.peers,
                endpoint.peers.current_network_generation_sync(),
                path == PathKind::Direct,
                &endpoint.udp,
                &endpoint.relay,
                path == PathKind::Relay,
            ),
        )
        .await?;
    require(sent, "original send core did not report actual Sent")
}

async fn mint_actual(
    endpoint: &mut Endpoint,
    budget: Budget,
) -> Result<(Arc<CanonicalOverlayRequest>, RawRequestDelivery), String> {
    let count = budget
        .step(
            "original periodic canonical minter and real inject",
            crate::overlay_requests::send_overlay_payloads(
                &endpoint.controller,
                &endpoint.peers,
                endpoint.vip,
                true,
                Some(&endpoint.udp),
                &mut endpoint.next_nonce,
                &mut endpoint.next_seq,
                &mut endpoint.stats,
                &mut endpoint.sent,
                &mut endpoint.order,
            ),
        )
        .await?;
    require(
        count == 1,
        "actual minter did not inject exactly one registered peer request",
    )?;
    endpoint.stats.sent = endpoint.stats.sent.saturating_add(count);
    let record = endpoint
        .sent
        .get(&endpoint.next_nonce)
        .cloned()
        .ok_or("actual successful minter did not retain canonical")?;
    let routed = budget
        .step(
            "actual tracked DataPlane route queue",
            endpoint.routed.recv(),
        )
        .await?
        .ok_or("actual tracked route queue ended")?;
    let carried = routed
        .binding()
        .and_then(|binding| binding.token().request())
        .ok_or("actual minter -> TUN -> DataPlane lost the original canonical token")?;
    require(
        Arc::ptr_eq(&record, &carried),
        "route rebound the original canonical Arc",
    )?;
    require(
        routed.packet == record.original_packet(),
        "original route changed canonical packet bytes",
    )?;
    require(
        record.injection_accepted(),
        "original successful injection is not accepted",
    )?;
    require(
        !record.native_ack_credited_for_test(),
        "fresh canonical was credited before any actual ACK",
    )?;
    Ok((record, routed))
}

async fn original_request_and_echo(
    a: &mut Endpoint,
    b: &mut Endpoint,
    path: PathKind,
    budget: Budget,
) -> Result<
    (
        Arc<CanonicalOverlayRequest>,
        RawRequestDelivery,
        ActualDelivery,
    ),
    String,
> {
    let (record, routed) = mint_actual(a, budget).await?;
    actual_send(a, routed, path, budget).await?;
    require(
        record.physical_publication.state() == PhysicalPublicationState::Recorded,
        "actual Full send did not record original physical publication",
    )?;
    require(
        record.physical_publication.record().is_some(),
        "original Full record is missing",
    )?;
    let request = actual_delivery(b, budget).await?;
    require(
        request.event.packet == record.original_packet(),
        "remote actual WG decrypted different REQUEST bytes",
    )?;
    let parsed = OriginalOverlayAck::parse_request(&request.event.packet, &request.event.peer_id)
        .ok_or("remote actual decrypt was not original REQUEST framing")?;
    require(
        parsed.nonce == record.nonce && parsed.seq == record.seq,
        "remote actual REQUEST identity changed",
    )?;
    let echo = inject_actual_echo(b, request, budget).await?;
    // Keep this actual routed sealed echo for a second independent actual send
    // in duplicate controls. No token or source is constructed at this boundary.
    actual_send(b, echo.clone(), path, budget).await?;
    let ack = actual_delivery(a, budget).await?;
    require(
        !record.native_ack_credited_for_test(),
        "actual receive alone consumed canonical native once",
    )?;
    qualify_actual_path(a, &record, &ack, path)?;
    Ok((record, echo, ack))
}

async fn inject_actual_echo(
    b: &mut Endpoint,
    request: ActualDelivery,
    budget: Budget,
) -> Result<RawRequestDelivery, String> {
    let original = OriginalOverlayAck::parse_request(&request.event.packet, &request.event.peer_id)
        .ok_or("actual REQUEST before echo injection has invalid framing")?;
    let verified_before = b.stats.verified_round_trips;
    let echoed = call_native_request(b, request, budget).await?;
    require(
        echoed == OriginalRequestEchoOutcome::Injected,
        &format!("actual sourced REQUEST was not injected as original sealed echo: {echoed:?}"),
    )?;
    require(
        b.stats.verified_round_trips == verified_before,
        "receiving REQUEST falsely credited a remote roundtrip",
    )?;
    take_actual_echo(b, original, budget).await
}

async fn call_native_request(
    b: &mut Endpoint,
    request: ActualDelivery,
    budget: Budget,
) -> Result<OriginalRequestEchoOutcome, String> {
    let owners = b.sourced_owners();
    budget
        .step(
            "actual sourced REQUEST handler and sealed real MockTun echo",
            handle_native_overlay_request(
                request.event,
                request.source,
                &owners,
                &b.udp,
                &b.peers,
                &b.controller,
                b.vip,
                true,
                true,
                &mut b.seen,
                &mut b.stats,
                &mut b.pending,
            ),
        )
        .await
}

async fn take_actual_echo(
    b: &mut Endpoint,
    original: OriginalOverlayAck,
    budget: Budget,
) -> Result<RawRequestDelivery, String> {
    require(
        b.pending.is_empty(),
        "fresh admitted original echo unexpectedly parked",
    )?;
    let echo = budget
        .step(
            "original echo MockTun -> tracked DataPlane route",
            b.routed.recv(),
        )
        .await?
        .ok_or("actual remote echo route ended")?;
    let echo_identity = OriginalOverlayAck::parse(&echo.packet, b.remote_node)
        .ok_or("actual routed echo framing is not ECHO")?;
    require(
        echo_identity.nonce == original.nonce && echo_identity.seq == original.seq,
        "original native REQUEST handler changed nonce/seq",
    )?;
    require(
        echo.original_echo().is_some(),
        "actual native REQUEST -> MockTun -> route lost sealed original echo source",
    )?;
    Ok(echo)
}

fn qualify_actual_path(
    a: &Endpoint,
    request: &CanonicalOverlayRequest,
    ack: &ActualDelivery,
    path: PathKind,
) -> Check {
    let source = ack.source.as_ref().ok_or("actual ACK source missing")?;
    let parsed = OriginalOverlayAck::parse(&ack.event.packet, &ack.event.peer_id)
        .ok_or("actual ACK bytes failed parsing")?;
    require(
        parsed.nonce == request.nonce && parsed.seq == request.seq,
        "actual returned ACK does not match the actual canonical request",
    )?;
    let record = request
        .physical_publication
        .record()
        .ok_or("actual original TX Full record missing")?;
    require(
        record.encryption().belongs_to(&a.wireguard),
        "actual request encryption owner changed",
    )?;
    require(
        record.encryption().session_instance() == source.session().session_instance(),
        "actual original request and returned ACK use different local active session instances",
    )?;
    match path {
        PathKind::Direct => {
            require(
                source.original_relay_read().is_none(),
                "actual Direct ACK gained Relay source",
            )?;
            let read = source
                .original_udp_read()
                .ok_or("actual Direct ACK lost original UDP reader")?;
            let tx = record
                .udp()
                .ok_or("actual Direct send lost original Full UDP fact")?;
            let slot = a
                .udp
                .try_read()
                .map_err(|_| "unexpected fixture UDP slot contention")?;
            let udp = slot
                .as_ref()
                .ok_or("actual current UDP publication missing")?;
            require(
                read.belongs_to_transport(udp),
                "actual ACK belongs to another UDP publication",
            )?;
            let _guard = udp
                .try_original_direct_publication_guard(
                    a.remote_node,
                    request.generation,
                    Some(read),
                    Some(tx),
                )
                .map_err(|e| format!(
                    "actual Direct RX/TX publication guard rejected: {e:?}; fence={:?} direct_commit={:?} capability={:?} owner={} rx_owner={}",
                    tx.fence(), tx.original_direct_commit(),
                    a.peers.try_peer_dplpmtud_capability(a.remote_node),
                    udp.inbound_publication_owner(), read.publication_owner()
                ))?;
        }
        PathKind::Relay => {
            require(
                source.original_udp_read().is_none(),
                "actual Relay ACK gained UDP source",
            )?;
            let read = source
                .original_relay_read()
                .ok_or("actual Relay ACK lost original Relay reader")?;
            let id = source
                .relay_connection_id()
                .ok_or("actual Relay RX lost original connection id")?;
            let tx = record
                .relay()
                .ok_or("actual Relay send lost original Full Forward fact")?;
            let slot = a
                .relay
                .try_read()
                .map_err(|_| "unexpected fixture Relay slot contention")?;
            let relay = slot
                .as_ref()
                .ok_or("actual current Relay publication missing")?;
            require(
                id == relay.connection_id(),
                "actual reader source was relabeled as a replacement publication",
            )?;
            let member = relay
                .try_original_member_guard(tx, read, id)
                .map_err(|e| format!("actual same-client RX/FullTX member rejected: {e:?}"))?;
            let _open = member
                .try_open_guard()
                .map_err(|e| format!("actual original Relay client is not open: {e:?}"))?;
        }
    }
    // All borrowed path guards end here, before any final API or async work.
    Ok(())
}

fn commit(
    a: &Endpoint,
    request: &CanonicalOverlayRequest,
    delivery: &ActualDelivery,
) -> Result<OverlayCreditOutcome, String> {
    let ack = OriginalOverlayAck::parse(&delivery.event.packet, &delivery.event.peer_id)
        .ok_or("actual decrypted ACK failed canonical framing")?;
    Ok(a.peers.try_commit_original_overlay_ack(
        &a.current_owners(),
        request,
        &ack,
        delivery.source.as_ref(),
    ))
}

fn require_fresh(outcome: OverlayCreditOutcome, path: PathKind, first: bool) -> Check {
    match outcome {
        OverlayCreditOutcome::Fresh(receipt) => {
            require(
                receipt.path
                    == if path == PathKind::Direct {
                        NetworkPath::Direct
                    } else {
                        NetworkPath::Relay
                    },
                "committed receipt changed the actual path",
            )?;
            require(
                receipt.attempt_id == 1,
                "fresh actual request used a fabricated/nonfirst attempt",
            )?;
            require(
                receipt.first_usable_new == first,
                "native receipt did not match the actual precommit milestone state",
            )
        }
        other => Err(format!(
            "actual original matching ACK did not commit fresh: {other:?}"
        )),
    }
}

fn commit_fresh(
    a: &Endpoint,
    request: &CanonicalOverlayRequest,
    ack: &ActualDelivery,
    path: PathKind,
) -> Check {
    require(
        !request.native_ack_credited_for_test(),
        "canonical native once was already consumed before the final transaction",
    )?;
    let map = a.peers.connection_map_for_test();
    let previous = {
        let connections = map
            .try_read()
            .map_err(|_| "unexpected connection conflict before fresh commit")?;
        let conn = connections
            .get(a.remote_node)
            .ok_or("actual connection missing before fresh commit")?;
        (
            conn.first_usable_generation,
            conn.first_usable_at,
            conn.first_usable_path,
        )
    };
    // Legacy authenticated inbound may already have published the milestone.
    // It cannot consume this canonical once. Observe its actual owner fields
    // without clearing or resetting them to make the native receipt look new.
    let expected_new = previous.0 != Some(request.generation) || previous.1.is_none();
    require_fresh(commit(a, request, ack)?, path, expected_new)?;
    let connections = map
        .try_read()
        .map_err(|_| "unexpected connection conflict after fresh commit")?;
    let conn = connections
        .get(a.remote_node)
        .ok_or("actual connection missing after fresh commit")?;
    if !expected_new {
        require(
            (
                conn.first_usable_generation,
                conn.first_usable_at,
                conn.first_usable_path,
            ) == previous,
            "native receipt overwrote the earlier actual milestone",
        )?;
    } else {
        require(
            conn.first_usable_generation == Some(request.generation)
                && conn.first_usable_at.is_some(),
            "fresh native receipt did not publish the actual missing milestone",
        )?;
    }
    Ok(())
}

async fn repeat_actual_echo(
    a: &mut Endpoint,
    b: &Endpoint,
    echo: RawRequestDelivery,
    path: PathKind,
    budget: Budget,
) -> Result<ActualDelivery, String> {
    actual_send(b, echo, path, budget).await?;
    actual_delivery(a, budget).await
}

async fn native_handler(a: &mut Endpoint, delivery: ActualDelivery, budget: Budget) -> Check {
    let owners = a.sourced_owners();
    budget
        .step(
            "native ACK handler after actual decrypt",
            handle_native_overlay_ack(
                delivery.event,
                delivery.source,
                &owners,
                &a.udp,
                &a.peers,
                &a.timeline,
                &mut a.seen,
                &mut a.stats,
                &a.sent,
                &mut a.bursts,
            ),
        )
        .await?;
    Ok(())
}

async fn native_fresh(
    a: &mut Endpoint,
    request: &CanonicalOverlayRequest,
    delivery: ActualDelivery,
    path: PathKind,
    budget: Budget,
) -> Check {
    require(
        !request.native_ack_credited_for_test(),
        "actual received ACK consumed once before native handler",
    )?;
    qualify_actual_path(a, request, &delivery, path)?;
    let map = a.peers.connection_map_for_test();
    let previous = {
        let connections = map
            .try_read()
            .map_err(|_| "unexpected native precommit connection conflict")?;
        let conn = connections
            .get(a.remote_node)
            .ok_or("actual native precommit peer missing")?;
        (
            conn.first_usable_generation,
            conn.first_usable_at,
            conn.first_usable_path,
        )
    };
    let valid = a.stats.received_valid;
    let rounds = a.stats.verified_round_trips;
    native_handler(a, delivery, budget).await?;
    require(
        request.native_ack_credited_for_test()
            && a.stats.received_valid == valid + 1
            && a.stats.verified_round_trips == rounds + 1,
        "actual native Fresh did not consume once and add exactly one roundtrip",
    )?;
    let connections = map
        .try_read()
        .map_err(|_| "unexpected native postcommit connection conflict")?;
    let conn = connections
        .get(a.remote_node)
        .ok_or("actual native postcommit peer missing")?;
    if previous.0 == Some(request.generation) && previous.1.is_some() {
        require(
            (
                conn.first_usable_generation,
                conn.first_usable_at,
                conn.first_usable_path,
            ) == previous,
            "actual native Fresh overwrote an earlier ingress milestone",
        )?;
    } else {
        require(
            conn.first_usable_generation == Some(request.generation)
                && conn.first_usable_at.is_some(),
            "actual native Fresh did not publish its missing milestone",
        )?;
    }
    Ok(())
}

async fn exercise_rounds(
    a: &mut Endpoint,
    b: &mut Endpoint,
    path: PathKind,
    scenario: Scenario,
    budget: Budget,
) -> Check {
    require(
        a.node == NODE_A && b.node == NODE_B,
        "actual fixture endpoint roles changed",
    )?;
    if let Scenario::RuntimeVip(case) = scenario {
        return runtime_vip::exercise_runtime_vip(a, b, path, case, budget).await;
    }
    if scenario == Scenario::Contention {
        return contention::exercise_conflicts(a, b, path, budget).await;
    }
    if let Scenario::AckContention(case) = scenario {
        return ack_contention::exercise_native_ack_contention(a, b, path, case, budget).await;
    }
    if let Scenario::RequestContention(case) = scenario {
        return request_contention::exercise_request_contention(a, b, path, case, budget).await;
    }
    if let Scenario::Lifecycle(case) = scenario {
        return lifecycle::exercise_lifecycle(a, b, path, case, budget).await;
    }
    if let Scenario::Identity(case) = scenario {
        return identity::exercise_identity(a, b, path, case, budget).await;
    }
    if let Scenario::EchoTransfer(case) = scenario {
        return echo_transfer::exercise_echo_transfer(a, b, path, case, budget).await;
    }
    if let Scenario::EchoContention(case) = scenario {
        return echo_contention::exercise_echo_contention(a, b, path, case, budget).await;
    }
    let (request, echo, ack) = original_request_and_echo(a, b, path, budget).await?;
    if scenario == Scenario::MissingSource {
        let parsed = OriginalOverlayAck::parse(&ack.event.packet, &ack.event.peer_id)
            .ok_or("actual ACK parse failed")?;
        let missing =
            a.peers
                .try_commit_original_overlay_ack(&a.current_owners(), &request, &parsed, None);
        require(
            missing == OverlayCreditOutcome::Unknown(OverlayCreditUnknown::OriginalSource),
            "actual ACK with source deliberately withheld gained native credit",
        )?;
        require(
            !request.native_ack_credited_for_test(),
            "missing-source rejection consumed canonical once",
        )?;
    }
    if scenario == Scenario::NativeHandler {
        native_fresh(a, &request, ack, path, budget).await?;
        require(
            request.native_ack_credited_for_test(),
            "native handler did not consume actual canonical once",
        )?;
        require(
            a.stats.received_valid == 1 && a.stats.verified_round_trips == 1,
            "native handler did not derive exactly one fresh postcommit observation",
        )?;
        let duplicate = repeat_actual_echo(a, b, echo, path, budget).await?;
        native_handler(a, duplicate, budget).await?;
        require(
            a.stats.received_valid == 1 && a.stats.verified_round_trips == 1,
            "real independently encrypted duplicate echo inflated native diagnostics",
        )?;
        let events = a.timeline.snapshot().events;
        require(
            events
                .iter()
                .filter(|event| event.event == "first_usable_bidirectional_overlay_ms")
                .count()
                == 1,
            "native postcommit scoped first event did not remain once",
        )?;
    } else {
        commit_fresh(a, &request, &ack, path)?;
        require(
            request.native_ack_credited_for_test(),
            "actual final transaction did not consume original canonical once",
        )?;
        if scenario == Scenario::DuplicateAndNew {
            let duplicate = repeat_actual_echo(a, b, echo, path, budget).await?;
            qualify_actual_path(a, &request, &duplicate, path)?;
            require(
                commit(a, &request, &duplicate)? == OverlayCreditOutcome::AlreadyCommitted,
                "real independently encrypted duplicate echo consumed the same canonical twice",
            )?;
            let (next, _next_echo, next_ack) =
                original_request_and_echo(a, b, path, budget).await?;
            require(
                !Arc::ptr_eq(&request, &next) && request.nonce != next.nonce,
                "second actual minter reused the previous canonical identity",
            )?;
            commit_fresh(a, &next, &next_ack, path)?;
            require(
                request.native_ack_credited_for_test() && next.native_ack_credited_for_test(),
                "fresh second canonical inherited or removed the previous canonical once",
            )?;
        }
        require(
            a.stats.verified_round_trips == 0,
            "pure PeerManager transaction invented out-of-transaction diagnostic credit",
        )?;
    }
    Ok(())
}

pub(super) async fn exercise(path: PathKind, scenario: Scenario) -> Check {
    exercise_with_runtime_vip(path, scenario, false).await
}

pub(super) async fn exercise_bootstrap_runtime_vip(path: PathKind, scenario: Scenario) -> Check {
    exercise_with_runtime_vip(path, scenario, true).await
}

async fn exercise_with_runtime_vip(
    path: PathKind,
    scenario: Scenario,
    keep_bootstrap_vip: bool,
) -> Check {
    let budget = if matches!(
        scenario,
        Scenario::Lifecycle(LifecycleCase::OriginalWindow)
            | Scenario::AckContention(AckContentionCase::Deadline)
            | Scenario::RequestContention(AckContentionCase::Deadline)
    ) {
        Budget::with_total(Duration::from_secs(19))
    } else {
        Budget::new()
    };
    let mut owners = Owners::default();
    // Keep the original body on the heap so nested native pipeline futures
    // do not multiply their state on the unchanged test thread stack.
    let body = AssertUnwindSafe(tokio::time::timeout_at(
        budget.body_end(),
        Box::pin(async {
            let hub = if path == PathKind::Relay {
                let server = budget
                    .step("start actual Relay hub", RelayServer::start_random())
                    .await?
                    .map_err(|e| e.to_string())?;
                let endpoint = format!("tcp://{}", server.addr);
                owners.server = Some(server);
                Some(endpoint)
            } else {
                None
            };
            let (vip_a, vip_b) = if keep_bootstrap_vip {
                ("10.20.0.2", "10.20.0.3")
            } else {
                (VIP_A, VIP_B)
            };
            let mut a = Endpoint::create(
                NODE_A,
                vip_a,
                NODE_B,
                vip_b,
                path,
                hub.as_deref(),
                &mut owners,
                budget,
                keep_bootstrap_vip,
            )
            .await?;
            let mut b = Endpoint::create(
                NODE_B,
                vip_b,
                NODE_A,
                vip_a,
                path,
                hub.as_deref(),
                &mut owners,
                budget,
                keep_bootstrap_vip,
            )
            .await?;
            let (session_a, session_b, a_key, b_key) = session_pair_for(&a.identity, &b.identity)?;
            let udp_a = a.local_udp().await?;
            let udp_b = b.local_udp().await?;
            a.install_peer(b_key, udp_b, session_a, path, budget)
                .await?;
            b.install_peer(a_key, udp_a, session_b, path, budget)
                .await?;
            if scenario == Scenario::PublicationOrder {
                require(
                    path == PathKind::Direct,
                    "publication causal fixture requires actual LAN",
                )?;
                publication_order::exercise_publication_order(&mut a, &mut b, &mut owners, budget)
                    .await
            } else {
                exercise_rounds(&mut a, &mut b, path, scenario, budget).await
            }
        }),
    ))
    .catch_unwind()
    .await
    .map(|result| {
        result.unwrap_or_else(|_| Err("original ACK body exceeded its fixed body end".into()))
    });
    // Owners stay outside the caught body. The original fixture end covers
    // every exit, including a panic after real workers have started.
    let explicit_tasks = owners.tasks.len();
    let had_server = owners.server.is_some();
    let cleanup = owners.close(budget).await;
    let body = match body {
        Ok(body) => body,
        Err(panic) => {
            let remaining = owners
                .tasks
                .iter()
                .filter(|task| task.handle.is_some())
                .count();
            if cleanup.is_ok() {
                eprintln!(
                    "b28_owned_panic_cleanup_complete: joined={}/{} remaining_handles={} server={} original_end_unchanged=true",
                    explicit_tasks - remaining,
                    explicit_tasks,
                    remaining,
                    if had_server { "shutdown_completed" } else { "not_started" },
                );
            } else {
                eprintln!(
                    "b28_owned_panic_cleanup_failed: joined={}/{} remaining_handles={} cleanup={cleanup:?} original_end_unchanged=true",
                    explicit_tasks - remaining,
                    explicit_tasks,
                    remaining,
                );
            }
            std::panic::resume_unwind(panic);
        }
    };
    match (body, cleanup) {
        (Ok(()), Ok(())) => Ok(()),
        (Err(error), Ok(())) | (Ok(()), Err(error)) => Err(error),
        (Err(error), Err(cleanup)) => Err(format!("{error}; cleanup: {cleanup}")),
    }
}
