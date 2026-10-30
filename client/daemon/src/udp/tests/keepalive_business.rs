//! One ordinary UDP delivery with no application reply, plus real consent.
//! The remote fixture consumes original WG/DataPlane output at MockTun; it
//! neither claims an OS TUN/application socket nor publishes health evidence.

use super::*;
use crate::connection_timeline::ConnectionTimeline;
use crate::network_outbound::{run_network_outbound, RelayStartupWait};
use futures_util::FutureExt;
use p2pnet_tun::mock::MockTunController;
use tokio::sync::{oneshot, watch, RwLock};
use tokio::task::JoinHandle;
use tokio::time::{timeout_at, Instant as TokioInstant};

type Worker = JoinHandle<std::result::Result<(), String>>;

#[derive(Default)]
struct BusinessOwners {
    workers: [Option<Worker>; 6],
    udp: Option<UdpTransport>,
    remote: Option<Arc<UdpSocket>>,
    slots: Option<Arc<RwLock<Option<UdpTransport>>>>,
    available: Option<watch::Sender<bool>>,
    plane: Option<DataPlane<MockTunDevice>>,
}

impl BusinessOwners {
    fn abort_workers(&self) {
        for task in self.workers.iter().flatten() {
            task.abort();
        }
    }
}

impl Drop for BusinessOwners {
    fn drop(&mut self) {
        self.abort_workers(); // Cancellation protection is never a claimed join.
    }
}

async fn collect_workers(owners: &mut BusinessOwners, end: TokioInstant) -> (bool, Vec<String>) {
    let mut joined = true;
    let mut errors = Vec::new();
    for slot in &mut owners.workers {
        let Some(task) = slot.as_mut() else {
            continue;
        };
        match timeout_at(end, task).await {
            Ok(result) => {
                drop(slot.take()); // Consume only the original Ready handle.
                match result {
                    Ok(Ok(())) => {}
                    Ok(Err(error)) => errors.push(error),
                    Err(error) if error.is_cancelled() => {}
                    Err(error) => errors.push(error.to_string()),
                }
            }
            Err(_) => joined = false,
        }
    }
    (joined, errors)
}

#[derive(Debug, PartialEq, Eq)]
struct Health {
    state: ConnectionState,
    successes: u64,
    failures: u64,
    consecutive: u32,
    latency_ms: Option<u64>,
    relay_failures: u64,
    pair_state: crate::peer::CandidatePairState,
    pair_successes: u64,
    pair_failures: u64,
    pair_consecutive: u32,
    path: Option<crate::peer::NetworkPath>,
    endpoint: Option<SocketAddr>,
    confirmed: bool,
}

async fn health(
    peers: &PeerManager,
    endpoint: SocketAddr,
    local: SocketAddr,
) -> std::result::Result<Health, String> {
    let connection = peers
        .get_connection("peer-b")
        .await
        .ok_or("missing original business peer")?;
    let pair = connection
        .candidate_pairs
        .iter()
        .find(|pair| pair.remote_endpoint == endpoint)
        .ok_or("missing original business pair")?;
    let selection = peers
        .select_path_for_data_with_local_endpoint("peer-b", true, false, Some(local))
        .await;
    Ok(Health {
        state: connection.state,
        successes: connection.direct_health.success_count,
        failures: connection.direct_health.failure_count,
        consecutive: connection.direct_health.consecutive_failures,
        latency_ms: connection.direct_health.latency_ms,
        relay_failures: connection.relay_health.failure_count,
        pair_state: pair.state,
        pair_successes: pair.success_count,
        pair_failures: pair.failure_count,
        pair_consecutive: pair.consecutive_failures,
        path: selection.path,
        endpoint: selection.direct_endpoint,
        confirmed: selection.direct_confirmed,
    })
}

// A fixture application reads the actual original DataPlane TUN write, parses
// its ordinary UDP destination and consumes its payload. It has no reply sender.
async fn consume_application(
    controller: &MockTunController,
) -> std::result::Result<Vec<u8>, String> {
    let written = controller.recv_written().await.map_err(|e| e.to_string())?;
    let ip = Ipv4Packet::new(&written).map_err(|e| e.to_string())?;
    let udp = ip.payload();
    if ip.src_addr() != Ipv4Addr::new(10, 20, 0, 1)
        || ip.dst_addr() != Ipv4Addr::new(10, 20, 0, 2)
        || written.get(9) != Some(&17)
        || usize::from(ip.total_len()) != written.len()
        || udp.len() < 8
        || u16::from_be_bytes([udp[0], udp[1]]) != 31001
        || u16::from_be_bytes([udp[2], udp[3]]) != 31002
        || usize::from(u16::from_be_bytes([udp[4], udp[5]])) != udp.len()
    {
        return Err("actual application UDP tuple/length mismatch".into());
    }
    Ok(udp[8..].to_vec())
}

#[derive(Debug)]
struct RemoteFacts {
    business_packets: usize,
    counter: Option<u64>,
    ack_nonce: [u8; 8],
}

// The fixture receiver owns its actual UDP reads. Only ciphertext physically
// read here enters the original WG worker; plaintext is never injected. Punch
// ACKs use the original encoding and actual send_to, with no app response or
// detached ACK retransmission task. The envelope carries no publication claim.
async fn receive_business_and_consent(
    remote: Arc<UdpSocket>,
    source_endpoint: SocketAddr,
    encrypted: mpsc::Sender<ReceivedEncryptedPacket>,
) -> std::result::Result<RemoteFacts, String> {
    let endpoint = remote.local_addr().map_err(|e| e.to_string())?;
    let mut business_packets = 0;
    let mut counter = None;
    let mut ack_nonce = None;
    let mut bytes = [0u8; 2048];
    while business_packets == 0 || ack_nonce.is_none() {
        let (len, source) = remote
            .recv_from(&mut bytes)
            .await
            .map_err(|e| e.to_string())?;
        if source != source_endpoint {
            return Err("actual remote business/consent source mismatch".into());
        }
        if let Some(probe) = decode_punch_packet(&bytes[..len]) {
            if probe.kind != PunchPacketKind::Punch || ack_nonce.is_some() {
                return Err("unexpected remote consent kind/duplicate".into());
            }
            let ack = build_punch_ack(probe.nonce);
            if remote
                .send_to(&ack, source)
                .await
                .map_err(|e| e.to_string())?
                != ack.len()
            {
                return Err("actual consent ACK short send".into());
            }
            ack_nonce = Some(probe.nonce);
        } else {
            business_packets += 1;
            counter = crate::transport::wire_counter(&bytes[..len]);
            if business_packets != 1 || counter != Some(0) {
                return Err("expected one fresh original WG business counter".into());
            }
            encrypted
                .send(ReceivedEncryptedPacket {
                    physical_ingress: None,
                    original_udp_read: None,
                    original_relay_read: None,
                    source: Some(source),
                    local_endpoint: Some(endpoint),
                    relay_endpoint: None,
                    relay_connection_id: None,
                    relay_peer_id: None,
                    socket_index: None,
                    direct_socket: None,
                    udp_transport_owner: None,
                    network_generation: None,
                    profile_sampled: false,
                    udp_received: Some(Instant::now()),
                    transport_queue_send_started: None,
                    wire_bytes: bytes[..len].to_vec(),
                })
                .await
                .map_err(|e| e.to_string())?;
        }
    }
    Ok(RemoteFacts {
        business_packets,
        counter,
        ack_nonce: ack_nonce.unwrap(),
    })
}

#[tokio::test]
async fn c02_delivered_ordinary_udp_without_application_reply_preserves_healthy_consent() {
    let end = TokioInstant::now() + Duration::from_secs(2);
    let work_end = end - Duration::from_secs(1);
    let peers = peer_manager();
    let bursts = Arc::new(ProbeBurstCaptureForTest::new());
    let mut owners = BusinessOwners::default();
    let mut primary = None;
    let mut ipv6 = None;
    let mut remote_weak = None;
    let mut local_addr = None;
    let mut remote_addr = None;
    let payload = b"ordinary-udp-one-request-no-application-reply";

    let body = std::panic::AssertUnwindSafe(async {
        owners.remote = Some(Arc::new(
            UdpSocket::bind("127.0.0.1:0")
                .await
                .map_err(|e| e.to_string())?,
        ));
        let remote = owners.remote.as_ref().unwrap().clone();
        remote_weak = Some(Arc::downgrade(&remote));
        let endpoint = remote.local_addr().map_err(|e| e.to_string())?;
        remote_addr = Some(endpoint);
        peers
            .add_peer(&peer("peer-b", "10.20.0.2", Some(endpoint)))
            .await;
        owners.udp = Some(
            UdpTransport::bind("127.0.0.1:0".parse().unwrap(), peers.clone())
                .await
                .map_err(|e| e.to_string())?,
        );
        let udp = owners.udp.as_mut().unwrap();
        udp.probe_burst_capture_for_test = Some(bursts.clone());
        let source_endpoint = udp.local_addr().map_err(|e| e.to_string())?;
        local_addr = Some(source_endpoint);
        primary = Some(Arc::downgrade(&udp.socket));
        ipv6 = udp.ipv6_socket.as_ref().map(Arc::downgrade);
        // The original confirmed-path setup is only a fixture precondition;
        // actual business delivery below cannot be satisfied by this seed.
        peers
            .record_direct_probe_success_with_latency_and_local_endpoint(
                "peer-b",
                endpoint,
                Some(Duration::from_millis(5)),
                Some(source_endpoint),
            )
            .await;
        peers
            .record_direct_success_with_local_endpoint(
                "peer-b",
                Some(endpoint),
                Some(source_endpoint),
            )
            .await;
        let before = health(&peers, endpoint, source_endpoint).await?;
        let counters_before = udp.probe_rx_snapshot().await;
        let (sender_session, receiver_session) = establish_sessions();
        let (sender_wg, raw_rx) = WireGuardTransport::new();
        sender_wg.add_session("peer-b", sender_session).await;
        let (tun, controller) = MockTunDevice::new_pair("c02-business-source", 1420, "10.20.0.1");
        let (plane, routed) = DataPlane::new(tun, peers.clone());
        owners.plane = Some(plane);
        let forward = sender_wg.clone();
        owners.workers[0] = Some(tokio::spawn(async move {
            forward
                .run_outbound(routed)
                .await
                .map_err(|e| e.to_string())
        }));
        owners.slots = Some(Arc::new(RwLock::new(Some(udp.clone()))));
        let slots = owners.slots.as_ref().unwrap().clone();
        let (available, available_rx) = watch::channel(false);
        owners.available = Some(available);
        let (kick_tx, _kick_rx) = watch::channel(0u64);
        let actor_wg = sender_wg.clone();
        let actor_peers = peers.clone();
        owners.workers[1] = Some(tokio::spawn(async move {
            run_network_outbound(
                raw_rx,
                actor_wg,
                actor_peers,
                true,
                slots,
                Arc::new(RwLock::new(None)),
                available_rx,
                RelayStartupWait {
                    relay_expected: false,
                    timeout: None,
                },
                kick_tx,
                ConnectionTimeline::new("c02-business", 0),
            )
            .await;
            Ok(())
        }));
        let (sender_input, mut sender_received) = mpsc::channel(1);
        let inbound = udp.clone();
        owners.workers[2] = Some(tokio::spawn(async move {
            inbound
                .run_inbound(sender_input)
                .await
                .map_err(|e| e.to_string())
        }));

        let receiver_peers = peer_manager();
        receiver_peers
            .add_peer(&peer("peer-a", "10.20.0.1", None))
            .await;
        let (receiver_wg, _unused_raw) = WireGuardTransport::new();
        receiver_wg.add_session("peer-a", receiver_session).await;
        let (remote_tun, application) =
            MockTunDevice::new_pair("c02-business-sink", 1420, "10.20.0.2");
        let (mut remote_plane, mut application_outbound, remote_input) =
            DataPlane::new_bidirectional(remote_tun, receiver_peers.clone());
        let (encrypted_tx, encrypted_rx) = mpsc::channel(1);
        owners.workers[3] = Some(tokio::spawn(async move {
            receiver_wg
                .run_inbound(encrypted_rx, remote_input)
                .await
                .map_err(|e| e.to_string())
        }));
        owners.workers[4] = Some(tokio::spawn(async move {
            remote_plane.run().await.map_err(|e| e.to_string())
        }));
        let (facts_tx, facts_rx) = oneshot::channel();
        owners.workers[5] = Some(tokio::spawn(async move {
            let facts = receive_business_and_consent(remote, source_endpoint, encrypted_tx).await?;
            facts_tx
                .send(facts)
                .map_err(|_| "original remote fact receiver closed".to_string())
        }));
        let packet =
            crate::build_udp_overlay_packet("10.20.0.1", "10.20.0.2", 31001, 31002, payload)
                .ok_or("ordinary UDP fixture packet")?;
        controller
            .inject(packet.clone())
            .await
            .map_err(|e| e.to_string())?;
        owners
            .plane
            .as_mut()
            .unwrap()
            .read_and_route_once(&mut [0u8; 512])
            .await
            .map_err(|e| e.to_string())?;
        // Drop the real route sink so the original forwarder can finish.
        drop(owners.plane.take());
        let delivered_payload = consume_application(&application).await?;
        // recv_written is the actual application-delivery boundary. The
        // original receive accounting follows that write, so observe its
        // typed completion too without introducing a new receipt authority.
        let receive_bytes = loop {
            let received = receiver_peers
                .get_connection("peer-a")
                .await
                .ok_or("missing actual receiver peer")?
                .bytes_received
                .get();
            if received >= packet.len() as u64 {
                break received;
            }
            tokio::task::yield_now().await;
        };
        let sent_bytes = peers
            .get_connection("peer-b")
            .await
            .ok_or("missing actual sender peer")?
            .bytes_sent
            .get();
        let after_business = health(&peers, endpoint, source_endpoint).await?;

        udp.run_keepalive_round(Duration::from_millis(500)).await;
        let _ack_transaction = udp.lock_peer_adoption_for_direct_validation("peer-b").await;
        let facts = facts_rx.await.map_err(|e| e.to_string())?;
        let after_consent = health(&peers, endpoint, source_endpoint).await?;
        let counters_after = udp.probe_rx_snapshot().await;
        let nonce_consumed = !udp
            .pending_probes
            .lock()
            .await
            .contains_key(&facts.ack_nonce);
        let no_application_outbound = matches!(
            application_outbound.try_recv(),
            Err(mpsc::error::TryRecvError::Empty)
        );
        // A bounded quiet observation of the original sender ingress. Punch
        // ACKs are consumed by that reader, never emitted as application data.
        let no_application_reply = timeout_at(
            work_end.min(TokioInstant::now() + Duration::from_millis(20)),
            sender_received.recv(),
        )
        .await
        .is_err();
        drop(owners.available.take()); // Original actor lifecycle drain.
        Ok::<_, String>((
            before,
            after_business,
            after_consent,
            delivered_payload,
            packet.len(),
            sent_bytes,
            receive_bytes,
            facts,
            counters_before,
            counters_after,
            nonce_consumed,
            no_application_outbound,
            no_application_reply,
        ))
    })
    .catch_unwind();
    let body_result = timeout_at(work_end, body).await;
    let held = owners.workers.iter().flatten().count();
    owners.abort_workers();
    let (burst_count, bursts_joined) = bursts.abort_and_join_until(end).await;
    let (workers_joined, worker_errors) = collect_workers(&mut owners, end).await;
    drop(owners.plane.take());
    drop(owners.available.take());
    drop(owners.slots.take());
    drop(owners.udp.take());
    drop(owners.remote.take());
    let sockets_released = timeout_at(end, async {
        while primary.as_ref().is_some_and(|w| w.upgrade().is_some())
            || ipv6.as_ref().is_some_and(|w| w.upgrade().is_some())
            || remote_weak.as_ref().is_some_and(|w| w.upgrade().is_some())
        {
            tokio::task::yield_now().await;
        }
    })
    .await
    .is_ok();
    let mut ports_reclaimed = true;
    for address in [local_addr, remote_addr].into_iter().flatten() {
        ports_reclaimed &= matches!(timeout_at(end, UdpSocket::bind(address)).await, Ok(Ok(_)));
    }
    assert!(workers_joined && bursts_joined && sockets_released && ports_reclaimed);
    assert!(
        worker_errors.is_empty(),
        "original workers after cleanup: {worker_errors:?}"
    );
    let observed = match body_result {
        Ok(Ok(Ok(value))) => value,
        Ok(Ok(Err(error))) => panic!("business/consent body failed after cleanup: {error}"),
        Ok(Err(panic)) => std::panic::resume_unwind(panic),
        Err(_) => panic!("business/consent body exceeded original work end after cleanup"),
    };
    assert_eq!(held, 6);
    assert_eq!(burst_count, 1, "one original consent producer");
    let (
        before,
        business,
        consent,
        received,
        packet_len,
        sent,
        delivered,
        facts,
        rx_before,
        rx_after,
        consumed,
        no_outbound,
        no_reply,
    ) = observed;
    assert_eq!(received, payload);
    assert_eq!((sent, delivered), (packet_len as u64, packet_len as u64));
    assert_eq!(facts.business_packets, 1);
    assert_eq!(facts.counter, Some(0));
    assert!(consumed && no_outbound && no_reply);
    assert_eq!(
        business, before,
        "ordinary application silence supplies no path failure or synthetic success"
    );
    assert_eq!(consent.successes, business.successes + 1);
    assert_eq!(consent.pair_successes, business.pair_successes + 1);
    assert_eq!(consent.failures, business.failures);
    assert_eq!(consent.relay_failures, business.relay_failures);
    assert_eq!(consent.pair_failures, business.pair_failures);
    assert_eq!((consent.consecutive, consent.pair_consecutive), (0, 0));
    assert_eq!(consent.state, ConnectionState::Direct);
    assert_eq!(
        consent.pair_state,
        crate::peer::CandidatePairState::Selected
    );
    assert_eq!(consent.path, Some(crate::peer::NetworkPath::Direct));
    assert_eq!(consent.endpoint, remote_addr);
    assert!(consent.confirmed && consent.latency_ms.is_some_and(|latency| latency < 500));
    assert_eq!(
        rx_after.legacy_probe_acks_observed,
        rx_before.legacy_probe_acks_observed + 1
    );
    assert_eq!(
        rx_after.probe_acks_received,
        rx_before.probe_acks_received + 1
    );
    assert_eq!(
        rx_after.legacy_probe_acks_unmatched,
        rx_before.legacy_probe_acks_unmatched
    );
}
