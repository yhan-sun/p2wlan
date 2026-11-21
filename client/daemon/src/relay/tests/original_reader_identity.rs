//! Real Relay readers, original route membership and WireGuard source carriage.
//! Identity comparison is historical; it grants no current owner or ACK credit.
use super::*;
use crate::transport::{InboundEvidenceFeed, WireGuardTransport};
use p2pnet_crypto::NodeIdentity;
use p2pnet_wireguard::{HandshakeInitiator, HandshakeResponder, TransportSession};
use tokio::sync::{watch, RwLock};

type Check = std::result::Result<(), String>;

fn require(condition: bool, message: &str) -> Check {
    condition.then_some(()).ok_or_else(|| message.to_string())
}

#[derive(Default)]
struct Owners {
    servers: Vec<RelayServer>,
    transports: Vec<RelayTransport>,
    tasks: Vec<tokio::task::JoinHandle<crate::error::Result<()>>>,
    expected_reader_close: bool,
}

impl Owners {
    async fn close(&mut self, end: tokio::time::Instant) -> Check {
        // Join the fixture's readers before publishing cleanup-only Closed.
        // Otherwise a real reader can finish with local_shutdown between
        // abort_writer and task.abort on a multithreaded runtime. Unexpected
        // errors that completed before teardown must still fail this fixture.
        for task in &self.tasks {
            task.abort();
        }
        for (index, task) in self.tasks.drain(..).enumerate() {
            let result = tokio::time::timeout_at(end, task)
                .await
                .map_err(|_| "original daemon task did not join within fixture end")?;
            require(
                matches!(&result, Ok(Ok(())))
                    || matches!(&result, Err(error) if error.is_cancelled())
                    // Only the actual Relay converter (tasks after the first
                    // decrypt worker) returns Relay on an intentional Closed.
                    || (self.expected_reader_close && index > 0 && matches!(&result, Ok(Err(crate::error::DaemonError::Relay(_))))),
                &format!("original daemon task {index} unexpected result: {result:?}"),
            )?;
        }
        for transport in &self.transports {
            transport.abort_writer();
            if let Some(pool) = &transport.rendezvous {
                tokio::time::timeout_at(end, pool.shutdown())
                    .await
                    .map_err(|_| "original rendezvous tasks did not join within fixture end")?;
            }
        }
        for server in self.servers.drain(..) {
            tokio::time::timeout_at(end, server.shutdown())
                .await
                .map_err(|_| "original Relay server did not stop within fixture end")?;
        }
        Ok(())
    }
}

impl Drop for Owners {
    fn drop(&mut self) {
        for transport in &self.transports {
            transport.abort_writer();
        }
        for task in &self.tasks {
            task.abort();
        }
    }
}

#[path = "original_reader_identity/lifecycle.rs"]
mod lifecycle;

#[tokio::test]
async fn original_reader_same_publication_route_replacement_keeps_old_and_fresh_sources() -> Check {
    original_reader_identity(lifecycle::Mode::Identity).await
}

async fn original_reader_identity(mode: lifecycle::Mode) -> Check {
    let end = tokio::time::Instant::now() + Duration::from_secs(2);
    let mut owners = Owners::default();
    let body = tokio::time::timeout_at(end, async {
        for _ in 0..2 {
            owners.servers.push(
                RelayServer::start_random()
                    .await
                    .map_err(|e| e.to_string())?,
            );
        }
        let primary = format!("tcp://{}", owners.servers[0].addr);
        let common = format!("tcp://{}", owners.servers[1].addr);
        let peers = peer_manager();
        peers.add_peer(&peer("identity-sender", "10.20.0.2")).await;
        let selected = select_relay_with_cooldowns_for_read::<OriginalRelayDelivery>(
            &[
                RelayCandidateConfig::legacy(format!("primary@{primary}")),
                RelayCandidateConfig::legacy(format!("common@{common}")),
            ],
            &["primary".into()],
            Duration::from_secs(1),
            "identity-old",
            peers.clone(),
            None,
            None,
            true,
            None,
            &HashMap::new(),
        )
        .await;
        let outer = selected
            .transport
            .ok_or("original relay selection failed")?;
        owners.transports.push(outer.clone());
        let old_rx = selected.relay_rx.ok_or("original selected queue missing")?;
        wait_for_rendezvous(&outer, 2).await;
        let original_connection = outer.connection_id();
        let pool = outer
            .rendezvous
            .as_ref()
            .ok_or("original rendezvous missing")?;
        let old_client = pool
            .routes
            .lock()
            .unwrap()
            .clients
            .get(&common)
            .cloned()
            .ok_or("actual auxiliary reader missing")?;
        let (sender, _sender_rx) = RelayTransport::connect_secure(
            &common,
            "common",
            "identity-sender",
            peer_manager(),
            None,
            true,
            None,
        )
        .await
        .map_err(|e| e.to_string())?;
        owners.transports.push(sender.clone());

        let remote_identity = NodeIdentity::generate();
        let local_identity = NodeIdentity::generate();
        let mut initiator =
            HandshakeInitiator::new(remote_identity, local_identity.public_key(), None);
        let mut responder = HandshakeResponder::new(local_identity, None);
        let initiation = initiator.create_initiation().map_err(|e| e.to_string())?;
        let (response, local_keys) = responder
            .consume_initiation_and_respond(&initiation)
            .map_err(|e| e.to_string())?;
        let mut remote = TransportSession::new(
            initiator
                .consume_response(&response)
                .map_err(|e| e.to_string())?,
        );
        let (transport, _outbound) = WireGuardTransport::new();
        transport
            .add_session("identity-sender", TransportSession::new(local_keys))
            .await;
        let slot = Arc::new(RwLock::new(Some(outer.clone())));
        let (encrypted_tx, encrypted_rx) = mpsc::channel(16);
        let (inbound_tx, mut inbound_rx) = mpsc::channel(16);
        let (overlay_tx, mut overlay_rx) = mpsc::channel(128);
        let (_udp_tx, udp_rx) = watch::channel(None);
        let inbound_transport = transport.clone();
        owners.tasks.push(tokio::spawn(async move {
            inbound_transport
                .run_inbound_with_peers_live_udp_and_relay(
                    encrypted_rx,
                    inbound_tx,
                    Some(peers),
                    udp_rx,
                    Some(InboundEvidenceFeed {
                        relay_transport: slot,
                        timeline: None,
                        overlay_ingress_tx: Some(overlay_tx),
                    }),
                )
                .await
        }));
        owners
            .tasks
            .push(tokio::spawn(outer.clone().run_inbound_for_read(
                old_rx,
                encrypted_tx.clone(),
                None,
            )));

        let mut sources = Vec::new();
        let mut facts = Vec::new();
        for (sequence, destination) in [(1, "identity-old"), (2, "identity-new")] {
            if sequence == 2 {
                // Keep the old client allocated, deliberately: its liveness
                // must not make it the replacement route member's identity.
                let (replacement, rx) =
                    RelayTransport::connect_secure_for_read::<OriginalRelayDelivery>(
                        &common,
                        "common",
                        destination,
                        peer_manager(),
                        None,
                        true,
                        None,
                    )
                    .await
                    .map_err(|e| e.to_string())?;
                owners.transports.push(replacement.clone());
                require(
                    pool.insert(&common, replacement.client.clone()),
                    "route replacement refused",
                )?;
                // The original daemon converter still has the same outer
                // publication. The actual new reader supplies all provenance;
                // no envelope/fact is fabricated at this test boundary.
                owners
                    .tasks
                    .push(tokio::spawn(outer.clone().run_inbound_for_read(
                        rx,
                        encrypted_tx.clone(),
                        None,
                    )));
            }
            let payload =
                crate::build_overlay_payload(crate::OVERLAY_DIRECTION_REQUEST, 0x2525, sequence);
            let packet =
                crate::build_udp_overlay_packet("10.20.0.2", "10.20.0.1", 32002, 32001, &payload)
                    .ok_or("overlay packet construction failed")?;
            sender
                .send_packet(&EncryptedPeerPacket {
                    room_authorization: None,
                    peer_id: destination.into(),
                    dst_ip: "10.20.0.1".into(),
                    wire_bytes: remote
                        .encrypt_to_bytes(&packet)
                        .map_err(|e| e.to_string())?,
                    is_business: false,
                })
                .await
                .map_err(|e| e.to_string())?;
            let inbound = inbound_rx
                .recv()
                .await
                .ok_or("actual decrypt output closed")?;
            require(inbound.packet == packet, "actual decrypted packet changed")?;
            let (event, source) = overlay_rx
                .recv()
                .await
                .ok_or("actual overlay source closed")?
                .into_parts();
            let source = source.ok_or("actual authenticated source missing")?;
            require(event.packet == packet, "actual overlay candidate changed")?;
            require(
                source.session().belongs_to(&transport),
                "original decrypt owner changed",
            )?;
            require(
                source.relay_connection_id() == Some(original_connection),
                "outer publication changed",
            )?;
            require(
                source.relay_endpoint() == Some(primary.as_str()),
                "outer endpoint was relabeled",
            )?;
            let read = source
                .original_relay_read()
                .ok_or("reader identity lost before overlay")?;
            require(
                source.received_at() == Some(read.completed_at()),
                "reader time was resampled",
            )?;
            {
                let routes = pool.routes.lock().unwrap();
                let current = routes
                    .clients
                    .get(&common)
                    .ok_or("current actual member missing")?;
                require(
                    read.belongs_to_client(current),
                    "fresh source mismatched its actual member",
                )?;
                require(
                    !read.belongs_to_client(&outer.client),
                    "auxiliary read relabeled as primary",
                )?;
            }
            if mode != lifecycle::Mode::Identity {
                let encrypted = transport
                    .encrypt_outbound(crate::dataplane::OutboundPacket {
                        room_authorization: None,
                        trace: None,
                        peer_id: "identity-sender".into(),
                        dst_ip: "10.20.0.2".into(),
                        packet: packet.clone(),
                    })
                    .await
                    .map_err(|e| e.to_string())?
                    .ok_or("actual outgoing encryption missing")?;
                let capture =
                    RelaySendCapture::new(&encrypted).ok_or("capture allocation failed")?;
                outer
                    .send_packet_with_origin(&encrypted, capture.clone())
                    .await
                    .map_err(|e| e.to_string())?;
                let RelayCaptureOutcome::Full(fact) = capture.finish() else {
                    return Err("original write did not complete".into());
                };
                lifecycle::fresh(&outer, &fact, read, original_connection)?;
                facts.push(fact);
            }
            sources.push(source);
        }
        {
            let routes = pool.routes.lock().unwrap();
            let current = routes
                .clients
                .get(&common)
                .ok_or("replacement member missing")?;
            let old_read = sources[0]
                .original_relay_read()
                .ok_or("retained original read missing")?;
            require(
                old_read.belongs_to_client(&old_client),
                "historical old identity changed",
            )?;
            require(
                !old_read.belongs_to_client(current),
                "same endpoint/publication revived old reader",
            )?;
            require(
                sources[1]
                    .original_relay_read()
                    .is_some_and(|read| read.belongs_to_client(current)),
                "fresh replacement reader failed positive control",
            )?;
        }
        if mode != lifecycle::Mode::Identity {
            owners.expected_reader_close = matches!(
                mode,
                lifecycle::Mode::Close | lifecycle::Mode::Replace | lifecycle::Mode::Stop
            );
            lifecycle::check(
                &outer,
                &sender,
                &common,
                &old_client,
                &facts,
                sources[0].original_relay_read().ok_or("old read missing")?,
                sources[1]
                    .original_relay_read()
                    .ok_or("fresh read missing")?,
                original_connection,
                mode,
                end,
            )?;
        }
        Ok::<(), String>(())
    })
    .await
    .unwrap_or_else(|_| Err("reader identity fixture exceeded original two-second end".into()));
    let cleanup = owners.close(end).await;
    match (body, cleanup) {
        (Ok(()), Ok(())) => Ok(()),
        (Err(error), Ok(())) | (Ok(()), Err(error)) => Err(error),
        (Err(error), Err(cleanup)) => Err(format!("{error}; cleanup: {cleanup}")),
    }
}
