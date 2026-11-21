//! Actual auxiliary reader -> original merge -> WG -> MockTun/source regression.
//! This first boundary control does not claim canonical/native ACK completion.
use super::*;
use crate::dataplane::DataPlane;
use crate::transport::{InboundEvidenceFeed, WireGuardTransport};
use futures_util::FutureExt;
use p2pnet_crypto::NodeIdentity;
use p2pnet_tun::mock::{MockTunController, MockTunDevice};
use p2pnet_wireguard::{HandshakeInitiator, HandshakeResponder, TransportSession};
use std::future::Future;
use std::panic::AssertUnwindSafe;
use std::pin::Pin;
use tokio::sync::{watch, RwLock};
use tokio::task::JoinHandle;

type Check<T = ()> = std::result::Result<T, String>;
const NODE_A: &str = "common-origin-a";
const NODE_B: &str = "common-origin-b";
const VIP_A: &str = "10.20.0.1";
const VIP_B: &str = "10.20.0.2";
const EXPLICIT_CAP: usize = 3;
const POOL_CAP: usize = 4;
const SERVER_CAP: usize = 3;

#[derive(Clone, Copy)]
struct Budget {
    end: tokio::time::Instant,
}

impl Budget {
    fn new() -> Self {
        Self {
            end: tokio::time::Instant::now() + Duration::from_secs(10),
        }
    }

    fn body_end(self) -> tokio::time::Instant {
        self.end - Duration::from_secs(1)
    }

    async fn step<T>(self, label: &str, work: impl Future<Output = T>) -> Check<T> {
        let end = self
            .body_end()
            .min(tokio::time::Instant::now() + Duration::from_secs(2));
        tokio::time::timeout_at(end, work)
            .await
            .map_err(|_| format!("{label}: original fixed fixture prerequisite timeout"))
    }
}

struct Task<T> {
    handle: Option<JoinHandle<T>>,
}

struct Server {
    original: Option<RelayServer>,
    shutdown: Option<Pin<Box<dyn Future<Output = ()> + Send>>>,
}

#[derive(Default)]
struct Owners {
    explicit: Vec<Task<Check>>,
    pool: Vec<Task<()>>,
    relays: Vec<RelayTransport>,
    servers: Vec<Server>,
    controller: Option<MockTunController>,
    routed: Option<mpsc::Receiver<crate::request_carriage::RawRequestDelivery>>,
}

#[derive(Debug, Default)]
struct Cleanup {
    explicit_joined: usize,
    pool_joined: usize,
    servers_completed: usize,
    errors: Vec<String>,
}

impl Owners {
    fn spawn(&mut self, work: impl Future<Output = Check> + Send + 'static) {
        assert!(
            self.explicit.len() < EXPLICIT_CAP,
            "fixed explicit task cap"
        );
        // The actual returned handle is owned before any subsequent await.
        self.explicit.push(Task {
            handle: Some(tokio::spawn(work)),
        });
    }

    async fn close(&mut self, budget: Budget) -> Cleanup {
        let mut collected = Cleanup::default();
        for task in &self.explicit {
            if let Some(handle) = &task.handle {
                handle.abort();
            }
        }
        for relay in &self.relays {
            relay.abort_writer();
            if let Some(pool) = &relay.rendezvous {
                // stop() already closed the actual routes and aborted workers.
                // Move those same original handles to external ownership; no
                // new producer/watcher or shutdown future can detach them.
                let handles =
                    std::mem::take(&mut *pool.tasks.lock().unwrap_or_else(|p| p.into_inner()));
                for handle in handles {
                    handle.abort();
                    self.pool.push(Task {
                        handle: Some(handle),
                    });
                }
            }
        }
        if self.pool.len() > POOL_CAP {
            collected
                .errors
                .push("original pool exceeded fixed four-handle shape".into());
        }
        // Install all original shutdown futures before awaiting any one. A
        // timeout keeps its original future owned instead of dropping/restarting
        // a consuming RelayServer::shutdown(self) call.
        for server in &mut self.servers {
            if let Some(original) = server.original.take() {
                server.shutdown = Some(Box::pin(original.shutdown()));
            }
        }
        for (index, task) in self.explicit.iter_mut().enumerate() {
            let Some(handle) = task.handle.as_mut() else {
                continue;
            };
            match tokio::time::timeout_at(budget.end, handle).await {
                Ok(result) => {
                    task.handle.take();
                    collected.explicit_joined += 1;
                    if !matches!(&result, Ok(Ok(())))
                        && !matches!(&result, Err(error) if error.is_cancelled())
                    {
                        collected
                            .errors
                            .push(format!("explicit {index}: {result:?}"));
                    }
                }
                Err(_) => collected
                    .errors
                    .push(format!("explicit {index}: original end exhausted")),
            }
        }
        for (index, task) in self.pool.iter_mut().enumerate() {
            let Some(handle) = task.handle.as_mut() else {
                continue;
            };
            match tokio::time::timeout_at(budget.end, handle).await {
                Ok(result) => {
                    task.handle.take();
                    collected.pool_joined += 1;
                    if !matches!(&result, Ok(()))
                        && !matches!(&result, Err(error) if error.is_cancelled())
                    {
                        collected.errors.push(format!("pool {index}: {result:?}"));
                    }
                }
                Err(_) => collected
                    .errors
                    .push(format!("pool {index}: original end exhausted")),
            }
        }
        for (index, server) in self.servers.iter_mut().enumerate() {
            let Some(shutdown) = server.shutdown.as_mut() else {
                continue;
            };
            match tokio::time::timeout_at(budget.end, shutdown.as_mut()).await {
                Ok(()) => {
                    server.shutdown.take();
                    collected.servers_completed += 1;
                }
                Err(_) => collected
                    .errors
                    .push(format!("server {index}: original end exhausted")),
            }
        }
        if self.explicit.iter().all(|task| task.handle.is_none()) {
            // The original MockTun sender and routed receiver remain live
            // through actual abort/join, including normal body completion.
            self.controller.take();
            self.routed.take();
        }
        collected
    }
}

impl Drop for Owners {
    fn drop(&mut self) {
        for task in &self.explicit {
            if let Some(handle) = &task.handle {
                handle.abort();
            }
        }
        for task in &self.pool {
            if let Some(handle) = &task.handle {
                handle.abort();
            }
        }
        for relay in &self.relays {
            relay.abort_writer();
        }
        // Drop only cancels. Success requires the explicit same-end close above.
        // Private native RelayClient handles are only aborted, never claimed joined.
    }
}

#[derive(Debug)]
struct Observation {
    common: String,
    primary: String,
    received_endpoint: Option<String>,
    read_is_common: bool,
    read_is_primary: bool,
    original_time_preserved: bool,
    outer_publication_preserved: bool,
    common_guard: std::result::Result<(), RelayMemberFailure>,
    envelope_guard: std::result::Result<(), RelayMemberFailure>,
    native_guard: std::result::Result<(), crate::overlay_requests::OverlayCreditOutcome>,
}

async fn wait_registered(relay: &RelayTransport, budget: Budget) -> Check {
    budget
        .step("actual primary and common registrations", async {
            loop {
                if relay.rendezvous.as_ref().is_some_and(|pool| {
                    pool.routes
                        .lock()
                        .unwrap_or_else(|p| p.into_inner())
                        .clients
                        .len()
                        == 2
                }) {
                    return;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
}

async fn observe(owners: &mut Owners, budget: Budget) -> Check<Observation> {
    for _ in 0..SERVER_CAP {
        let server = budget
            .step("actual Relay server start", RelayServer::start_random())
            .await?
            .map_err(|e| e.to_string())?;
        owners.servers.push(Server {
            original: Some(server),
            shutdown: None,
        });
    }
    let endpoints: Vec<_> = owners
        .servers
        .iter()
        .map(|server| format!("tcp://{}", server.original.as_ref().unwrap().addr))
        .collect();
    let common = endpoints[2].clone();
    let peers_a = peer_manager();
    let mut config_b =
        Config::generate_default("http://ctrl.test", "default").map_err(|e| e.to_string())?;
    config_b.network.virtual_ip = VIP_B.into();
    let peers_b = Arc::new(PeerManager::new(config_b));
    budget
        .step(
            "original receiver peer",
            peers_b.add_peer(&peer(NODE_A, VIP_A)),
        )
        .await?;
    let lifecycle = peers_b
        .peer_session_generation_sync(NODE_A)
        .ok_or("actual original peer lifecycle missing")?;
    let mut queues = Vec::with_capacity(2);
    for (node, preferred, primary, peers) in [
        (NODE_A, "one", &endpoints[0], peers_a),
        (NODE_B, "two", &endpoints[1], peers_b.clone()),
    ] {
        let selected = budget
            .step(
                "actual primary selection",
                select_relay_with_cooldowns_for_read::<OriginalRelayDelivery>(
                    &[
                        RelayCandidateConfig::legacy(format!("{preferred}@{primary}")),
                        RelayCandidateConfig::legacy(format!("common@{common}")),
                    ],
                    &[preferred.into()],
                    Duration::from_secs(1),
                    node,
                    peers,
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
            .ok_or("actual original Relay selection failed")?;
        owners.relays.push(relay);
        queues.push(
            selected
                .relay_rx
                .ok_or("actual original merged queue missing")?,
        );
    }
    for relay in &owners.relays {
        wait_registered(relay, budget).await?;
    }
    let receiver = owners.relays[1].clone();
    if owners.relays[0].endpoint() != endpoints[0] || receiver.endpoint() != endpoints[1] {
        return Err(
            "actual original primary selection did not follow different preferences".into(),
        );
    }
    let receiver_queue = queues.pop().ok_or("actual receiver queue missing")?;
    let _sender_queue = queues.pop().ok_or("actual sender queue missing")?;
    let local = NodeIdentity::generate();
    let remote = NodeIdentity::generate();
    let mut initiator = HandshakeInitiator::new(remote, local.public_key(), None);
    let mut responder = HandshakeResponder::new(local, None);
    let initiation = initiator.create_initiation().map_err(|e| e.to_string())?;
    let (response, keys) = responder
        .consume_initiation_and_respond(&initiation)
        .map_err(|e| e.to_string())?;
    let mut encryptor = TransportSession::new(
        initiator
            .consume_response(&response)
            .map_err(|e| e.to_string())?,
    );
    let (wireguard, _unused_outbound) = WireGuardTransport::new();
    budget
        .step(
            "actual Noise session installation",
            wireguard.replace_session_for_lifecycle(NODE_A, TransportSession::new(keys), lifecycle),
        )
        .await?;
    let (tun, controller) = MockTunDevice::new_pair("common-origin-b", 1420, VIP_B);
    owners.controller = Some(controller.clone());
    let (mut plane, routed, inbound_tx) =
        DataPlane::new_bidirectional_with_request_carriage(tun, peers_b.clone());
    owners.routed = Some(routed);
    owners.spawn(async move { plane.run().await.map_err(|e| e.to_string()) });
    let (encrypted_tx, encrypted_rx) = mpsc::channel(16);
    let (overlay_tx, mut overlay_rx) = mpsc::channel(16);
    let (_udp_publication, udp_updates) = watch::channel(None);
    let current_relay = Arc::new(RwLock::new(Some(receiver.clone())));
    let original_peer_owner = peers_b.clone();
    let original_relay_slot = current_relay.clone();
    let original_udp_slot = Arc::new(RwLock::new(None));
    let inbound_wireguard = wireguard.clone();
    owners.spawn(async move {
        inbound_wireguard
            .run_inbound_with_peers_live_udp_and_relay(
                encrypted_rx,
                inbound_tx,
                Some(peers_b),
                udp_updates,
                Some(InboundEvidenceFeed {
                    relay_transport: current_relay,
                    timeline: None,
                    overlay_ingress_tx: Some(overlay_tx),
                }),
            )
            .await
            .map_err(|e| e.to_string())
    });
    let converter = receiver.clone();
    owners.spawn(async move {
        converter
            .run_inbound_for_read(receiver_queue, encrypted_tx, None)
            .await
            .map_err(|e| e.to_string())
    });
    let payload = crate::build_overlay_payload(crate::OVERLAY_DIRECTION_REQUEST, 0x3000, 1);
    let packet = crate::build_udp_overlay_packet(VIP_A, VIP_B, 39286, 39287, &payload)
        .ok_or("actual test overlay packet construction failed")?;
    let wire_bytes = encryptor
        .encrypt_to_bytes(&packet)
        .map_err(|e| e.to_string())?;
    budget
        .step(
            "original fanout physical write",
            owners.relays[0].send_packet(&EncryptedPeerPacket {
                room_authorization: None,
                peer_id: NODE_B.into(),
                dst_ip: VIP_B.into(),
                wire_bytes,
                is_business: false,
            }),
        )
        .await?
        .map_err(|e| e.to_string())?;
    let written = budget
        .step("actual MockTun inbound write", controller.recv_written())
        .await?
        .map_err(|e| e.to_string())?;
    if written != packet {
        return Err("actual original DataPlane changed decrypted request".into());
    }
    let (event, source) = budget
        .step("actual sourced overlay ingress", overlay_rx.recv())
        .await?
        .ok_or("original authenticated overlay output closed")?
        .into_parts();
    let source = source.ok_or("actual authenticated original source missing")?;
    if event.packet != packet || !source.session().belongs_to(&wireguard) {
        return Err("original decrypt output or owner changed".into());
    }
    let read = source
        .original_relay_read()
        .ok_or("actual original read missing")?;
    let pool = receiver
        .rendezvous
        .as_ref()
        .ok_or("actual receiver pool missing")?;
    let (read_is_common, read_is_primary) = {
        let routes = pool.routes.lock().unwrap_or_else(|p| p.into_inner());
        let actual = routes
            .clients
            .get(&common)
            .ok_or("actual common member missing")?;
        if routes.peers.get(NODE_A) != Some(&common) {
            return Err("original pool did not observe actual request through common".into());
        }
        (
            read.belongs_to_client(actual),
            read.belongs_to_client(&receiver.client),
        )
    };
    let common_guard =
        match receiver.try_original_reader_member_guard(read, &common, receiver.connection_id()) {
            Ok(member) => member.try_open_guard().map(|_| ()),
            Err(error) => Err(error),
        };
    let endpoint = source
        .relay_endpoint()
        .ok_or("original source endpoint missing")?;
    let envelope_guard =
        match receiver.try_original_reader_member_guard(read, endpoint, receiver.connection_id()) {
            Ok(member) => member.try_open_guard().map(|_| ()),
            Err(error) => Err(error),
        };
    let received_endpoint = Some(endpoint.to_string());
    let original_time_preserved = source.received_at() == Some(read.completed_at());
    let outer_publication_preserved =
        source.relay_connection_id() == Some(receiver.connection_id());
    let request =
        crate::overlay_requests::OriginalOverlayAck::parse_request(&event.packet, &event.peer_id)
            .ok_or("actual original REQUEST parser rejected the decrypted packet")?;
    let echo = crate::build_pending_overlay_echo(
        VIP_B,
        NODE_A.into(),
        VIP_A.into(),
        source
            .network_generation()
            .ok_or("original generation missing")?,
        request.nonce,
        request.seq,
    )
    .ok_or("original pending echo construction failed")?;
    let input = crate::overlay_requests::OriginalEchoInput::capture(
        &original_peer_owner,
        &wireguard,
        &original_udp_slot,
        &original_relay_slot,
        request,
        source,
        &echo.packet,
    )
    .ok_or("actual original echo input capture failed")?;
    // The exact production entrance used before native REQUEST echo injection.
    // No custom guard/source factory or relabeled outer publication is used.
    let native_guard = input.qualify_before_injection(&wireguard);
    Ok(Observation {
        common,
        primary: receiver.endpoint().into(),
        received_endpoint,
        read_is_common,
        read_is_primary,
        common_guard,
        envelope_guard,
        native_guard,
        original_time_preserved,
        outer_publication_preserved,
    })
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn actual_common_original_reader_qualifies_native_echo_with_primary_publication() -> Check {
    let budget = Budget::new();
    let mut owners = Owners::default();
    let body = AssertUnwindSafe(tokio::time::timeout_at(
        budget.body_end(),
        observe(&mut owners, budget),
    ))
    .catch_unwind()
    .await;
    let cleanup = owners.close(budget).await;
    eprintln!("r00_common_origin_cleanup: explicit_joined={}/{} pool_joined={}/{} server_shutdown_completed={}/{} errors={:?} original_end_unchanged=true private_relay_native_joined=false",
        cleanup.explicit_joined, owners.explicit.len(), cleanup.pool_joined, owners.pool.len(),
        cleanup.servers_completed, owners.servers.len(), cleanup.errors);
    let body = match body {
        Ok(Ok(body)) => body,
        Ok(Err(_)) => Err("original nine-second body end exhausted".into()),
        Err(panic) => std::panic::resume_unwind(panic),
    };
    assert!(
        cleanup.errors.is_empty(),
        "original owned cleanup failed: {cleanup:?}"
    );
    let observed = body?;
    assert_eq!(
        (
            cleanup.explicit_joined,
            cleanup.pool_joined,
            cleanup.servers_completed
        ),
        (EXPLICIT_CAP, POOL_CAP, SERVER_CAP),
        "actual fixture owner shape or joins changed"
    );
    eprintln!("r00_actual_common_source: {observed:?}");
    assert!(
        observed.read_is_common && !observed.read_is_primary,
        "original read was not the actual common client"
    );
    assert!(
        observed.original_time_preserved && observed.outer_publication_preserved,
        "original time/publication changed"
    );
    assert_ne!(
        observed.primary, observed.common,
        "common unexpectedly became the primary publication"
    );
    assert_eq!(
        observed.common_guard,
        Ok(()),
        "actual common current member/open qualification failed"
    );
    assert_eq!(
        observed.received_endpoint.as_deref(),
        Some(observed.primary.as_str()),
        "original outer publication endpoint changed"
    );
    assert_eq!(
        observed.envelope_guard,
        Err(RelayMemberFailure::UnknownReader),
        "unrelated primary must not qualify the actual common reader"
    );
    assert_eq!(
        observed.native_guard,
        Ok(()),
        "actual production native echo guard rejected the current original common reader"
    );
    Ok(())
}
