fn business_budget_peer(node_id: &str, virtual_ip: &str, endpoint: SocketAddr) -> control::PeerInfo {
    control::PeerInfo {
        node_id: node_id.to_string(),
        device_name: String::new(),
        app_version: String::new(),
        public_key: "pk".to_string(),
        endpoint: endpoint.to_string(),
        nat_type: "Unknown".to_string(),
        virtual_ip: virtual_ip.to_string(),
        online: true,
        last_seen: 0,
        relay_rtt_ms: None,
    }
}

async fn business_budget_commit_direct(
    peers: &Arc<PeerManager>,
    udp: &UdpTransport,
    peer_id: &str,
    remote_endpoint: SocketAddr,
    owner_token: u64,
    request_id: u16,
) -> crate::dplpmtud::DplpmtudPathIdentity {
    let generation = peers.current_network_generation_sync();
    let peer_session_generation = peers
        .peer_session_generation_sync(peer_id)
        .expect("business E2E peer session must be current");
    let remote_candidate_epoch = peers
        .current_remote_candidate_epoch(peer_id)
        .await
        .expect("business E2E peer must own a candidate epoch");
    let epoch = peer::PathEpoch::new(
        generation,
        peer_session_generation,
        remote_candidate_epoch,
    );
    assert!(
        peers
            .mark_direct_validation_started(
                peer_id,
                peer::DirectValidationIdentity::owned(
                    epoch,
                    owner_token,
                    Some(request_id),
                    Some(remote_endpoint),
                ),
            )
            .await
    );
    let validation = peer::DirectValidationIdentity::authenticated_ack(
        epoch,
        owner_token,
        request_id,
        Some(remote_endpoint),
        remote_endpoint,
    );
    let local_endpoint = udp.local_addr().unwrap();
    let epoch_gate = peers.network_epoch_gate();
    let epoch_guard = epoch_gate.lock().await;
    assert!(
        peers
            .record_direct_success_for_generation_with_local_endpoint_and_latency_in_epoch_for_remote_epoch(
                &epoch_guard,
                peer_id,
                Some(remote_endpoint),
                generation,
                Some(local_endpoint),
                None,
                Some(remote_candidate_epoch),
                Some(validation),
            )
            .await
    );
    drop(epoch_guard);
    crate::dplpmtud::DplpmtudPathIdentity::from_committed_validation(
        peer_id,
        validation,
        remote_endpoint,
        local_endpoint,
        udp.transport_instance_id(),
        0,
    )
    .expect("business E2E requires one exact IPv4 Direct identity")
}

fn business_budget_confirm_base(
    runtime: &crate::dplpmtud::DplpmtudRuntime,
    identity: &crate::dplpmtud::DplpmtudPathIdentity,
    lease: &crate::dplpmtud::DplpmtudWorkerLease,
    now: tokio::time::Instant,
) {
    let plan = runtime
        .schedule_probe(
            &identity.peer_id,
            identity,
            lease.worker_owner_token,
            now,
        )
        .expect("BASE recovery must schedule a probe");
    assert_eq!(
        plan.probe_identity.candidate_udp_datagram_size,
        crate::dplpmtud::UdpDatagramSize(
            crate::dplpmtud::DPLPMTUD_BASE_UDP_DATAGRAM_SIZE,
        )
    );
    assert!(runtime.begin_probe_send(&plan, now));
    runtime.finish_probe_send(&plan, Ok(()), now + Duration::from_millis(1));
    assert_eq!(
        runtime.try_accept_ack(
            &identity.peer_id,
            identity,
            plan.wire_token,
            crate::dplpmtud::DplpmtudAckIngress {
                remote_endpoint: identity.authenticated_remote_endpoint,
                local_endpoint: identity.local_endpoint,
                socket: identity.socket,
            },
            now + Duration::from_millis(2),
        ),
        crate::dplpmtud::DplpmtudTransitionDecision::Applied
    );
}

fn business_budget_ack_next_probe(
    runtime: &crate::dplpmtud::DplpmtudRuntime,
    identity: &crate::dplpmtud::DplpmtudPathIdentity,
    lease: &crate::dplpmtud::DplpmtudWorkerLease,
    now: tokio::time::Instant,
) {
    let plan = runtime
        .schedule_probe(
            &identity.peer_id,
            identity,
            lease.worker_owner_token,
            now,
        )
        .expect("upward search must schedule a probe");
    assert!(
        plan.probe_identity.candidate_udp_datagram_size.0
            > crate::dplpmtud::DPLPMTUD_BASE_UDP_DATAGRAM_SIZE
    );
    assert!(runtime.begin_probe_send(&plan, now));
    runtime.finish_probe_send(&plan, Ok(()), now + Duration::from_millis(1));
    assert_eq!(
        runtime.try_accept_ack(
            &identity.peer_id,
            identity,
            plan.wire_token,
            crate::dplpmtud::DplpmtudAckIngress {
                remote_endpoint: identity.authenticated_remote_endpoint,
                local_endpoint: identity.local_endpoint,
                socket: identity.socket,
            },
            now + Duration::from_millis(2),
        ),
        crate::dplpmtud::DplpmtudTransitionDecision::Applied
    );
}

fn business_budget_token(
    runtime: &crate::dplpmtud::DplpmtudRuntime,
    peer_id: &str,
    udp_owner: u64,
) -> crate::dplpmtud::DirectBusinessSendToken {
    let publication = runtime
        .direct_business_budget_entry(peer_id)
        .and_then(|entry| entry.update.budget)
        .expect("business E2E requires a confirmed immutable publication");
    crate::dplpmtud::DirectBusinessSendToken {
        path_identity: publication.path_identity,
        budget_revision: publication.budget_revision,
        max_udp_datagram_size: publication.udp_datagram_size,
        max_overlay_payload_size: publication.overlay_payload_budget,
        udp_publication_owner: udp_owner,
    }
}

fn business_budget_ipv4_packet(total_len: usize, sequence: u16) -> Vec<u8> {
    assert!((28..=u16::MAX as usize).contains(&total_len));
    Ipv4Packet::build_icmp_echo_request(
        "10.20.0.1".parse().unwrap(),
        "10.20.0.2".parse().unwrap(),
        0x2b2b,
        sequence,
        &vec![0x5a; total_len - 28],
    )
}

fn business_budget_icmp_sequence(packet: &[u8]) -> u16 {
    let ip = Ipv4Packet::new(packet).unwrap();
    let payload = ip.payload();
    u16::from_be_bytes([payload[6], payload[7]])
}

fn assert_business_budget_feedback(packet: &[u8], expected_mtu: u16) {
    let ip = Ipv4Packet::new(packet).expect("local feedback must be valid IPv4");
    assert!(ip.verify_checksum());
    assert_eq!(
        ip.src_addr(),
        "10.20.0.2".parse::<Ipv4Addr>().unwrap()
    );
    assert_eq!(
        ip.dst_addr(),
        "10.20.0.1".parse::<Ipv4Addr>().unwrap()
    );
    let icmp = ip.payload();
    assert_eq!(&icmp[..2], &[3, 4]);
    assert_eq!(u16::from_be_bytes([icmp[6], icmp[7]]), expected_mtu);
    assert_eq!(crate::business_mtu::internet_checksum(icmp), 0);
}

async fn business_budget_yield_until(mut predicate: impl FnMut() -> bool, failure: &str) {
    timeout(Duration::from_secs(2), async {
        loop {
            if predicate() {
                return;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap_or_else(|_| panic!("{failure}"));
}

async fn business_budget_wait_for_would_block_attempts(
    attempts: &mut watch::Receiver<usize>,
    expected: usize,
) {
    timeout(Duration::from_secs(2), async {
        while *attempts.borrow_and_update() < expected {
            attempts
                .changed()
                .await
                .expect("WouldBlock injection sender must remain alive");
        }
    })
    .await
    .expect("Direct business send never reached the deterministic WouldBlock seam");
}

async fn business_budget_install_confirmed_direct(
    peers: &Arc<PeerManager>,
    udp: &UdpTransport,
    peer_id: &str,
    remote_endpoint: SocketAddr,
    validation_owner: u64,
    request_id: u16,
) -> (
    crate::dplpmtud::DplpmtudPathIdentity,
    crate::dplpmtud::DplpmtudWorkerLease,
) {
    let identity = business_budget_commit_direct(
        peers,
        udp,
        peer_id,
        remote_endpoint,
        validation_owner,
        request_id,
    )
    .await;
    let peer_session_generation = peers
        .peer_session_generation_sync(peer_id)
        .expect("managed business peer must have a session generation");
    assert!(udp.mark_peer_dplpmtud_supported(peer_id, peer_session_generation));
    let runtime = udp.dplpmtud_runtime();
    let lease = runtime
        .install_path(identity.clone(), true, tokio::time::Instant::now())
        .worker
        .expect("managed Direct peer must own a DPLPMTUD worker lease");
    business_budget_confirm_base(&runtime, &identity, &lease, tokio::time::Instant::now());
    (identity, lease)
}

fn business_budget_ipv6_packet(total_len: usize, next_header: u8) -> Vec<u8> {
    assert!((40..=40 + u16::MAX as usize).contains(&total_len));
    let source: Ipv6Addr = "fd00::1".parse().unwrap();
    let destination: Ipv6Addr = "fd00::2".parse().unwrap();
    let mut packet = vec![0x5a; total_len];
    packet[0..4].copy_from_slice(&0x6000_0000u32.to_be_bytes());
    packet[4..6].copy_from_slice(&u16::try_from(total_len - 40).unwrap().to_be_bytes());
    packet[6] = next_header;
    packet[7] = 64;
    packet[8..24].copy_from_slice(&source.octets());
    packet[24..40].copy_from_slice(&destination.octets());
    packet
}

#[tokio::test]
async fn direct_business_capability_survives_udp_replacement_reconcile() {
    let peers = Arc::new(PeerManager::new(
        Config::generate_default("https://ctrl.test", "net1").unwrap(),
    ));
    peers
        .add_peer(&business_budget_peer(
            "peer-b",
            "10.20.0.2",
            "127.0.0.1:42000".parse().unwrap(),
        ))
        .await;
    let peer_session_generation = peers
        .peer_session_generation_sync("peer-b")
        .expect("replacement test peer session");
    // Model capability negotiation that happened before this concrete UDP
    // transport was constructed. The new runtime itself starts empty.
    peers.mark_dplpmtud_capable_sync("peer-b", peer_session_generation);

    let udp = UdpTransport::bind("127.0.0.1:0".parse().unwrap(), peers.clone())
        .await
        .unwrap()
        .with_dplpmtud_local_virtual_ip("10.20.0.1".parse().unwrap());
    udp.set_inbound_publication_owner(901);
    let identity = business_budget_commit_direct(
        &peers,
        &udp,
        "peer-b",
        "127.0.0.1:42000".parse().unwrap(),
        91,
        93,
    )
    .await;
    udp.reconcile_dplpmtud_paths().await;

    let runtime = udp.dplpmtud_runtime();
    let entry = runtime
        .direct_business_budget_entry("peer-b")
        .expect("replacement reconcile must publish a managed tombstone");
    assert!(entry.enforced);
    assert_eq!(entry.update.path_identity, identity);
    assert!(entry.update.budget.is_none());
    assert!(udp.peer_requires_direct_business_budget("peer-b"));
    assert!(!udp.direct_business_budget_ready_for_peer("peer-b"));
    runtime.cancel_peer(
        "peer-b",
        "replacement_reconcile_test_complete",
        tokio::time::Instant::now(),
    );
    assert_eq!(runtime.active_worker_count(), 0);
}

/// Production-path acceptance fixture:
/// Mock TUN -> DataPlane -> plaintext network actor -> immutable budget token
/// -> WireGuard -> final revision/path/owner gate -> exact UDP -> peer decrypt
/// -> peer Mock TUN. The same fixture exercises Pending, oversize feedback,
/// actual-ciphertext defense, revoke races, EMSGSIZE recovery and path ABA.
#[tokio::test]
async fn direct_business_budget_production_path_e2e() {
    const UDP_OWNER: u64 = 501;
    let peers_a = Arc::new(PeerManager::new(
        Config::generate_default("https://ctrl.test", "net1").unwrap(),
    ));
    let peers_b = Arc::new(PeerManager::new(
        Config::generate_default("https://ctrl.test", "net1").unwrap(),
    ));
    let udp_a = UdpTransport::bind("127.0.0.1:0".parse().unwrap(), peers_a.clone())
        .await
        .unwrap();
    let udp_b = UdpTransport::bind("127.0.0.1:0".parse().unwrap(), peers_b.clone())
        .await
        .unwrap();
    let endpoint_a = udp_a.local_addr().unwrap();
    let endpoint_b = udp_b.local_addr().unwrap();
    let router = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let router_endpoint = router.local_addr().unwrap();
    peers_a
        .add_peer(&business_budget_peer("peer-b", "10.20.0.2", router_endpoint))
        .await;
    peers_b
        .add_peer(&business_budget_peer("peer-a", "10.20.0.1", router_endpoint))
        .await;

    udp_a.set_inbound_publication_owner(UDP_OWNER);
    let identity = business_budget_commit_direct(
        &peers_a,
        &udp_a,
        "peer-b",
        router_endpoint,
        71,
        73,
    )
    .await;
    let peer_session_generation = peers_a
        .peer_session_generation_sync("peer-b")
        .unwrap();
    assert!(udp_a.mark_peer_dplpmtud_supported("peer-b", peer_session_generation));
    let runtime = udp_a.dplpmtud_runtime();
    let lease = runtime
        .install_path(identity.clone(), true, tokio::time::Instant::now())
        .worker
        .expect("modern Direct path must own one DPLPMTUD worker");

    let (session_a, session_b) = part03_establish_sessions();
    let (wireguard_a, network_outbound_rx) = WireGuardTransport::new();
    let (wireguard_b, _network_outbound_b_rx) = WireGuardTransport::new();
    wireguard_a.add_session("peer-b", session_a).await;
    wireguard_b.add_session("peer-a", session_b).await;

    let (tun_a, ctrl_a) = p2pnet_tun::MockTunDevice::new_pair(
        "business-budget-a",
        1500,
        "10.20.0.1",
    );
    let (mut dataplane_a, dataplane_a_rx, _dataplane_a_inbound) =
        DataPlane::new_bidirectional(tun_a, peers_a.clone());
    let dataplane_a_task = tokio::spawn(async move { dataplane_a.run().await });
    let transport_a_task = tokio::spawn({
        let wireguard = wireguard_a.clone();
        async move { wireguard.run_outbound(dataplane_a_rx).await }
    });

    let (tun_b, ctrl_b) = p2pnet_tun::MockTunDevice::new_pair(
        "business-budget-b",
        1500,
        "10.20.0.2",
    );
    let (mut dataplane_b, _dataplane_b_rx, dataplane_b_inbound) =
        DataPlane::new_bidirectional(tun_b, peers_b.clone());
    let dataplane_b_task = tokio::spawn(async move { dataplane_b.run().await });
    let (udp_b_inbound_tx, udp_b_inbound_rx) = mpsc::channel(32);
    let transport_b_task = tokio::spawn({
        let wireguard = wireguard_b.clone();
        async move {
            wireguard
                .run_inbound(udp_b_inbound_rx, dataplane_b_inbound)
                .await
        }
    });
    let udp_b_task = tokio::spawn(udp_b.clone().run_inbound(udp_b_inbound_tx));

    let wire_count = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let wire_sizes = Arc::new(std::sync::Mutex::new(Vec::<usize>::new()));
    let router_task = tokio::spawn({
        let wire_count = wire_count.clone();
        let wire_sizes = wire_sizes.clone();
        async move {
            let mut buffer = vec![0u8; 65_535];
            loop {
                let (size, source) = router.recv_from(&mut buffer).await.unwrap();
                if source == endpoint_a {
                    wire_count.fetch_add(1, std::sync::atomic::Ordering::AcqRel);
                    wire_sizes
                        .lock()
                        .unwrap_or_else(|poisoned| poisoned.into_inner())
                        .push(size);
                    router.send_to(&buffer[..size], endpoint_b).await.unwrap();
                } else if source == endpoint_b {
                    router.send_to(&buffer[..size], endpoint_a).await.unwrap();
                }
            }
        }
    });

    let udp_slot = Arc::new(RwLock::new(Some(udp_a.clone())));
    let relay_slot = Arc::new(RwLock::new(None));
    let (_relay_available_tx, relay_available_rx) = watch::channel(false);
    let (relay_probe_kick_tx, _relay_probe_kick_rx) = watch::channel(0u64);
    let timeline = ConnectionTimeline::new("peer-a", 0);
    let network_task = tokio::spawn(run_network_outbound(
        network_outbound_rx,
        wireguard_a.clone(),
        peers_a.clone(),
        true,
        udp_slot.clone(),
        relay_slot,
        relay_available_rx,
        RelayStartupWait { timeout: None },
        relay_probe_kick_tx,
        timeline.clone(),
    ));

    let committed = peers_a.get_connection("peer-b").await.unwrap();
    assert_eq!(committed.active_path(), Some(peer::NetworkPath::Direct));
    assert!(peers_a.peer_supports_dplpmtud_sync(
        "peer-b",
        peer_session_generation,
    ));
    assert!(udp_a.peer_requires_direct_business_budget("peer-b"));
    assert!(!udp_a.direct_business_budget_ready_for_peer("peer-b"));
    assert!(
        peers_a
            .is_data_path_admitted_for_generation(
                "peer-b",
                peers_a.current_network_generation_sync(),
                false,
            )
            .await
    );

    // ManagedPending parks plaintext, allocates no counter and does not block
    // the actor. BASE publication wakes the queue and preserves FIFO.
    ctrl_a
        .inject(business_budget_ipv4_packet(128, 1))
        .await
        .unwrap();
    ctrl_a
        .inject(business_budget_ipv4_packet(128, 2))
        .await
        .unwrap();
    timeout(Duration::from_secs(2), async {
        loop {
            if peers_a
                .get_connection("peer-b")
                .await
                .is_some_and(|connection| connection.bytes_sent >= 256)
            {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("DataPlane did not route both Pending packets");
    business_budget_yield_until(
        || {
            timeline.snapshot().events.iter().any(|event| {
                event.event == "direct_business_budget_pending"
                    && event.reason_code.as_deref()
                        == Some(crate::network_outbound::REASON_DIRECT_BUDGET_PENDING)
            })
        },
        "managed Direct packets never reached the bounded Pending queue",
    )
    .await;
    assert_eq!(wire_count.load(std::sync::atomic::Ordering::Acquire), 0);
    business_budget_confirm_base(
        &runtime,
        &identity,
        &lease,
        tokio::time::Instant::now(),
    );
    let first = timeout(Duration::from_secs(2), ctrl_b.recv_written())
        .await
        .unwrap()
        .unwrap();
    let second = timeout(Duration::from_secs(2), ctrl_b.recv_written())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        [
            business_budget_icmp_sequence(&first),
            business_budget_icmp_sequence(&second),
        ],
        [1, 2],
        "BASE publication must flush plaintext FIFO"
    );

    // Confirmed UDP=1200 means a complete 1168-byte inner packet becomes one
    // exact 1200-byte WireGuard UDP datagram.
    let max_base_packet = business_budget_ipv4_packet(1168, 3);
    ctrl_a.inject(max_base_packet.clone()).await.unwrap();
    assert_eq!(
        timeout(Duration::from_secs(2), ctrl_b.recv_written())
            .await
            .unwrap()
            .unwrap(),
        max_base_packet
    );
    assert_eq!(
        *wire_sizes
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .last()
            .unwrap(),
        1200
    );

    // 1169 is rejected before encryption/socket handoff and returns a valid
    // local ICMP Fragmentation Needed quoting the original packet.
    let before_oversize = wire_count.load(std::sync::atomic::Ordering::Acquire);
    ctrl_a
        .inject(business_budget_ipv4_packet(1169, 4))
        .await
        .unwrap();
    let oversize_feedback = timeout(Duration::from_secs(2), ctrl_a.recv_written())
        .await
        .unwrap()
        .unwrap();
    assert_business_budget_feedback(&oversize_feedback, 1168);
    assert_eq!(
        wire_count.load(std::sync::atomic::Ordering::Acquire),
        before_oversize,
        "oversize plaintext must produce zero UDP sends"
    );

    // Raise once, then revoke the exact revision while the packet is parked
    // after real encryption. The old high-budget token must send nothing.
    business_budget_ack_next_probe(
        &runtime,
        &identity,
        &lease,
        tokio::time::Instant::now(),
    );
    let raised_token = business_budget_token(&runtime, "peer-b", UDP_OWNER);
    assert!(raised_token.max_overlay_payload_size.0 > 1168);
    let high_packet_len = raised_token.max_overlay_payload_size.0 as usize;
    let race_gate = Arc::new(crate::udp::DirectBusinessSendGate::new());
    udp_a.set_direct_business_send_gate_for_test(race_gate.clone());
    let before_revoke = wire_count.load(std::sync::atomic::Ordering::Acquire);
    ctrl_a
        .inject(business_budget_ipv4_packet(high_packet_len, 5))
        .await
        .unwrap();
    timeout(Duration::from_secs(2), race_gate.reached.wait())
        .await
        .expect("business packet must reach the post-encryption barrier");
    assert!(runtime.invalidate_direct_business_budget(
        &raised_token,
        tokio::time::Instant::now(),
    ));
    let revoked = runtime.direct_business_budget_entry("peer-b").unwrap();
    assert!(revoked.update.budget.is_none());
    assert!(revoked.update.budget_revision > raised_token.budget_revision);
    race_gate.release.wait().await;
    business_budget_yield_until(
        || {
            timeline.snapshot().events.iter().any(|event| {
                event.event == "outbound_send_failure"
                    && event.reason_code.as_deref()
                        == Some(crate::network_outbound::REASON_DIRECT_BUDGET_STALE)
            })
        },
        "revoked post-encryption token was not rejected",
    )
    .await;
    assert_eq!(wire_count.load(std::sync::atomic::Ordering::Acquire), before_revoke);
    assert!(!runtime.invalidate_direct_business_budget(
        &raised_token,
        tokio::time::Instant::now(),
    ));

    // BASE re-confirmation publishes 1200/1168. The queued old large packet
    // is re-routed exactly once, then rejected under the lower budget; a new
    // small packet resumes over the still-active Direct path.
    business_budget_confirm_base(
        &runtime,
        &identity,
        &lease,
        tokio::time::Instant::now(),
    );
    let lowered_feedback = timeout(Duration::from_secs(2), ctrl_a.recv_written())
        .await
        .unwrap()
        .unwrap();
    assert_business_budget_feedback(&lowered_feedback, 1168);
    assert_eq!(wire_count.load(std::sync::atomic::Ordering::Acquire), before_revoke);
    let recovered_packet = business_budget_ipv4_packet(256, 6);
    ctrl_a.inject(recovered_packet.clone()).await.unwrap();
    assert_eq!(
        timeout(Duration::from_secs(2), ctrl_b.recv_written())
            .await
            .unwrap()
            .unwrap(),
        recovered_packet
    );

    // Make the immutable publication deliberately more conservative than
    // the plaintext estimate. The production post-encryption check observes
    // the real 1200-byte ciphertext, blocks it, and invalidates the revision.
    let before_ciphertext = wire_count.load(std::sync::atomic::Ordering::Acquire);
    assert!(runtime.force_business_udp_budget_for_test(
        "peer-b",
        crate::dplpmtud::UdpDatagramSize(1199),
    ));
    ctrl_a
        .inject(business_budget_ipv4_packet(1168, 7))
        .await
        .unwrap();
    let ciphertext_feedback = timeout(Duration::from_secs(2), ctrl_a.recv_written())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(&Ipv4Packet::new(&ciphertext_feedback).unwrap().payload()[..2], &[3, 4]);
    assert_eq!(wire_count.load(std::sync::atomic::Ordering::Acquire), before_ciphertext);
    assert!(runtime
        .direct_business_budget_entry("peer-b")
        .unwrap()
        .update
        .budget
        .is_none());
    business_budget_confirm_base(
        &runtime,
        &identity,
        &lease,
        tokio::time::Instant::now(),
    );

    // Typed EMSGSIZE is injected at the exact syscall seam. It is a definite
    // no-send, revokes only this identity+revision, restarts BASE, and leaves
    // Direct health / Relay selection untouched.
    let emsgsize_token = business_budget_token(&runtime, "peer-b", UDP_OWNER);
    udp_a.inject_direct_business_emsgsize_once_for_test();
    let before_emsgsize = wire_count.load(std::sync::atomic::Ordering::Acquire);
    ctrl_a
        .inject(business_budget_ipv4_packet(1168, 8))
        .await
        .unwrap();
    let emsgsize_feedback = timeout(Duration::from_secs(2), ctrl_a.recv_written())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(&Ipv4Packet::new(&emsgsize_feedback).unwrap().payload()[..2], &[3, 4]);
    assert_eq!(wire_count.load(std::sync::atomic::Ordering::Acquire), before_emsgsize);
    let emsgsize_snapshot = runtime.snapshot_for_peer("peer-b").unwrap();
    assert_eq!(emsgsize_snapshot.state, crate::dplpmtud::DplpmtudState::Base);
    assert!(!emsgsize_snapshot.base_confirmed);
    assert!(emsgsize_snapshot.business_packet_too_large_count >= 3);
    assert!(!runtime.invalidate_direct_business_budget(
        &emsgsize_token,
        tokio::time::Instant::now(),
    ));
    let connection = peers_a.get_connection("peer-b").await.unwrap();
    assert_eq!(connection.active_path(), Some(peer::NetworkPath::Direct));
    assert_eq!(connection.direct_health.failure_count, 0);
    assert_eq!(connection.relay_health.failure_count, 0);

    business_budget_confirm_base(
        &runtime,
        &identity,
        &lease,
        tokio::time::Instant::now(),
    );
    let after_emsgsize_packet = business_budget_ipv4_packet(256, 9);
    ctrl_a.inject(after_emsgsize_packet.clone()).await.unwrap();
    assert_eq!(
        timeout(Duration::from_secs(2), ctrl_b.recv_written())
            .await
            .unwrap()
            .unwrap(),
        after_emsgsize_packet
    );

    // A real path-generation replacement at the same post-encryption barrier
    // also rejects the old token and produces zero UDP wire packets.
    let prior_stale_events = timeline
        .snapshot()
        .events
        .iter()
        .filter(|event| {
            event.reason_code.as_deref()
                == Some(crate::network_outbound::REASON_DIRECT_BUDGET_STALE)
        })
        .count();
    let path_gate = Arc::new(crate::udp::DirectBusinessSendGate::new());
    udp_a.set_direct_business_send_gate_for_test(path_gate.clone());
    let before_path_replace = wire_count.load(std::sync::atomic::Ordering::Acquire);
    ctrl_a
        .inject(business_budget_ipv4_packet(256, 10))
        .await
        .unwrap();
    timeout(Duration::from_secs(2), path_gate.reached.wait())
        .await
        .expect("path race packet must reach the post-encryption barrier");
    let udp_replacement =
        UdpTransport::bind("127.0.0.1:0".parse().unwrap(), peers_a.clone())
            .await
            .unwrap();
    assert_ne!(
        udp_replacement.transport_instance_id(),
        identity.socket.transport_instance_id,
    );
    assert!(udp_a.clear_inbound_publication_owner_if_matches(UDP_OWNER));
    udp_replacement.set_inbound_publication_owner(UDP_OWNER + 1);
    *udp_slot.write().await = Some(udp_replacement.clone());
    assert!(
        udp_replacement.peer_requires_direct_business_budget("peer-b"),
        "a negotiated capability must survive UDP transport replacement"
    );
    assert!(
        !udp_replacement.direct_business_budget_ready_for_peer("peer-b"),
        "the replacement transport must re-confirm BASE rather than becoming unmanaged"
    );
    path_gate.release.wait().await;
    business_budget_yield_until(
        || {
            timeline
                .snapshot()
                .events
                .iter()
                .filter(|event| {
                    event.reason_code.as_deref()
                        == Some(crate::network_outbound::REASON_DIRECT_BUDGET_STALE)
                })
                .count()
                > prior_stale_events
        },
        "exact path replacement did not reject the encrypted old token",
    )
    .await;
    assert_eq!(
        wire_count.load(std::sync::atomic::Ordering::Acquire),
        before_path_replace
    );
    let final_connection = peers_a.get_connection("peer-b").await.unwrap();
    assert_eq!(final_connection.active_path(), Some(peer::NetworkPath::Direct));
    assert_eq!(final_connection.direct_health.failure_count, 0);
    assert_eq!(final_connection.relay_health.failure_count, 0);
    assert_eq!(runtime.active_worker_count(), 0);

    network_task.abort();
    transport_a_task.abort();
    udp_b_task.abort();
    transport_b_task.abort();
    dataplane_a_task.abort();
    dataplane_b_task.abort();
    router_task.abort();
    let _ = network_task.await;
    let _ = transport_a_task.await;
    let _ = udp_b_task.await;
    let _ = transport_b_task.await;
    let _ = dataplane_a_task.await;
    let _ = dataplane_b_task.await;
    let _ = router_task.await;
    println!(
        "BUSINESS_BUDGET_E2E udp=1200 overlay=1168 pending_fifo=true oversize_zero_send=true ciphertext_zero_send=true revoke_race_zero_send=true path_race_zero_send=true emsgsize_recovery=true direct_active=true direct_health_failure_count=0 relay_fallback_count=0 task_leak=false"
    );
}

#[tokio::test]
async fn direct_business_would_block_is_paced_deadline_bounded_and_peer_isolated() {
    const UDP_OWNER: u64 = 601;
    let peers = Arc::new(PeerManager::new(
        Config::generate_default("https://ctrl.test", "net1").unwrap(),
    ));
    let receiver_a = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let receiver_b = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let endpoint_a = receiver_a.local_addr().unwrap();
    let endpoint_b = receiver_b.local_addr().unwrap();
    peers
        .add_peer(&business_budget_peer("peer-a", "10.20.0.2", endpoint_a))
        .await;
    peers
        .add_peer(&business_budget_peer("peer-b", "10.20.0.3", endpoint_b))
        .await;

    let udp = UdpTransport::bind("127.0.0.1:0".parse().unwrap(), peers.clone())
        .await
        .unwrap();
    udp.set_inbound_publication_owner(UDP_OWNER);
    let (_identity_a, _lease_a) = business_budget_install_confirmed_direct(
        &peers, &udp, "peer-a", endpoint_a, 101, 103,
    )
    .await;
    let (_identity_b, _lease_b) = business_budget_install_confirmed_direct(
        &peers, &udp, "peer-b", endpoint_b, 105, 107,
    )
    .await;
    let runtime = udp.dplpmtud_runtime();
    let budget_a_before = runtime
        .direct_business_budget_entry("peer-a")
        .expect("Peer A must have a confirmed business publication");

    let (transport, outbound_rx) = WireGuardTransport::new();
    let outbound_loss = Arc::new(tokio::sync::Mutex::new(
        crate::peer::OutboundLossCounters::default(),
    ));
    peers.set_outbound_loss_sink(outbound_loss.clone());
    transport.set_outbound_loss_sink(Some(outbound_loss));
    let (session_a, _remote_a) = part03_establish_sessions();
    let (session_b, _remote_b) = part03_establish_sessions();
    transport.add_session("peer-a", session_a).await;
    transport.add_session("peer-b", session_b).await;
    let (dataplane_tx, dataplane_rx) = mpsc::channel(8);
    let forwarder = tokio::spawn({
        let transport = transport.clone();
        async move { transport.run_outbound(dataplane_rx).await }
    });
    let timeline = ConnectionTimeline::new("node-a", 0);
    let (_relay_available_tx, relay_available_rx) = watch::channel(false);
    let (relay_probe_kick_tx, _relay_probe_kick_rx) = watch::channel(0u64);
    let worker = tokio::spawn(run_network_outbound(
        outbound_rx,
        transport,
        peers.clone(),
        true,
        Arc::new(RwLock::new(Some(udp.clone()))),
        Arc::new(RwLock::new(None)),
        relay_available_rx,
        RelayStartupWait { timeout: None },
        relay_probe_kick_tx,
        timeline.clone(),
    ));

    // One deterministic local-backpressure result must preserve the token and
    // retry metadata, then succeed through the exact same Direct endpoint.
    let mut once = udp.inject_direct_business_would_block_for_test("peer-a", 1);
    dataplane_tx
        .send(OutboundPacket {
            peer_id: "peer-a".to_string(),
            dst_ip: "10.20.0.2".to_string(),
            packet: business_budget_ipv4_packet(256, 21),
            trace: None,
        })
        .await
        .unwrap();
    business_budget_wait_for_would_block_attempts(&mut once, 1).await;
    let mut wire = vec![0u8; 2048];
    let (sent, _) = timeout(Duration::from_secs(2), receiver_a.recv_from(&mut wire))
        .await
        .expect("Peer A must retry after one WouldBlock")
        .unwrap();
    assert!(sent > 0);
    business_budget_yield_until(
        || {
            timeline.snapshot().events.iter().any(|event| {
                event.event == "direct_business_local_backpressure"
                    && event.reason_code.as_deref()
                        == Some(
                            crate::network_outbound::REASON_DIRECT_LOCAL_BACKPRESSURE,
                        )
                    && event
                        .detail
                        .as_deref()
                        .is_some_and(|detail| detail.contains("direct_budget_reroutes=0"))
            })
        },
        "WouldBlock was not exposed as independent local backpressure with zero stale reroutes",
    )
    .await;
    assert_eq!(
        runtime.direct_business_budget_entry("peer-a"),
        Some(budget_a_before.clone()),
        "WouldBlock must not revoke or revise the confirmed budget"
    );
    assert!(!timeline.snapshot().events.iter().any(|event| {
        event.reason_code.as_deref()
            == Some(crate::network_outbound::REASON_DIRECT_BUDGET_STALE)
    }));

    // Keep Peer A under deterministic backpressure. Peer B must still reach
    // its independent UDP socket before Peer A's delivery deadline expires.
    let local_backpressure_events_before = timeline
        .snapshot()
        .events
        .iter()
        .filter(|event| {
            event.event == "direct_business_local_backpressure"
                && event.reason_code.as_deref()
                    == Some(crate::network_outbound::REASON_DIRECT_LOCAL_BACKPRESSURE)
        })
        .count();
    let mut until_deadline =
        udp.inject_direct_business_would_block_for_test("peer-a", 1024);
    dataplane_tx
        .send(OutboundPacket {
            peer_id: "peer-a".to_string(),
            dst_ip: "10.20.0.2".to_string(),
            packet: business_budget_ipv4_packet(256, 22),
            trace: None,
        })
        .await
        .unwrap();
    business_budget_wait_for_would_block_attempts(&mut until_deadline, 1).await;
    business_budget_yield_until(
        || {
            timeline
                .snapshot()
                .events
                .iter()
                .filter(|event| {
                    event.reason_code.as_deref()
                        == Some(
                            crate::network_outbound::REASON_DIRECT_LOCAL_BACKPRESSURE,
                        )
                })
                .count()
                > local_backpressure_events_before
        },
        "continuous WouldBlock did not return Peer A to its paced plaintext FIFO",
    )
    .await;
    dataplane_tx
        .send(OutboundPacket {
            peer_id: "peer-b".to_string(),
            dst_ip: "10.20.0.3".to_string(),
            packet: Ipv4Packet::build_icmp_echo_request(
                "10.20.0.1".parse().unwrap(),
                "10.20.0.3".parse().unwrap(),
                0x2b2b,
                23,
                &[0x5a; 64],
            ),
            trace: None,
        })
        .await
        .unwrap();
    let (peer_b_sent, _) = timeout(Duration::from_secs(2), receiver_b.recv_from(&mut wire))
        .await
        .expect("Peer B must not wait for Peer A's blocked socket")
        .unwrap();
    assert!(peer_b_sent > 0);

    // Wait on the configured production loss boundary (not an arbitrary test
    // sleep). The remaining Peer A packet receives a backpressure-specific
    // typed drop instead of consuming stale reroute credit.
    timeout(
        crate::network_outbound::OUTBOUND_DELIVERY_DEADLINE
            + crate::network_outbound::OUTBOUND_MAINTENANCE_INTERVAL * 4,
        async {
            loop {
                if timeline.snapshot().events.iter().any(|event| {
                    event.reason_code.as_deref()
                        == Some(
                            crate::network_outbound::REASON_DIRECT_LOCAL_BACKPRESSURE_DEADLINE,
                        )
                }) {
                    break;
                }
                tokio::task::yield_now().await;
            }
        },
    )
    .await
    .expect("continuous WouldBlock did not terminate at the delivery deadline");
    let stats = peers.outbound_loss_stats().await;
    assert_eq!(
        stats
            .drops
            .get(crate::network_outbound::REASON_DIRECT_LOCAL_BACKPRESSURE_DEADLINE)
            .map(|counter| counter.packets),
        Some(1)
    );
    let snapshot = timeline.snapshot();
    let backpressure_events: Vec<_> = snapshot
        .events
        .iter()
        .filter(|event| {
            event.event == "direct_business_local_backpressure"
                && event.reason_code.as_deref()
                    == Some(crate::network_outbound::REASON_DIRECT_LOCAL_BACKPRESSURE)
        })
        .collect();
    assert!(!backpressure_events.is_empty());
    assert!(backpressure_events.iter().all(|event| {
        event
            .detail
            .as_deref()
            .is_some_and(|detail| detail.contains("direct_budget_reroutes=0"))
    }));
    assert!(!snapshot.events.iter().any(|event| {
        matches!(
            event.reason_code.as_deref(),
            Some(
                crate::network_outbound::REASON_DIRECT_BUDGET_STALE
                    | crate::network_outbound::REASON_DIRECT_BUDGET_REROUTE_EXHAUSTED
            )
        )
    }));
    assert_eq!(
        runtime.direct_business_budget_entry("peer-a"),
        Some(budget_a_before),
        "deadline-bounded local backpressure must not revoke the budget"
    );
    assert_eq!(
        receiver_a.try_recv_from(&mut wire).unwrap_err().kind(),
        std::io::ErrorKind::WouldBlock,
        "the continuously blocked packet must produce zero UDP sends"
    );
    for peer_id in ["peer-a", "peer-b"] {
        let connection = peers.get_connection(peer_id).await.unwrap();
        assert_eq!(connection.active_path(), Some(peer::NetworkPath::Direct));
        assert_eq!(connection.direct_health.failure_count, 0);
        assert_eq!(connection.relay_health.failure_count, 0);
        runtime.cancel_peer(
            peer_id,
            "would_block_test_complete",
            tokio::time::Instant::now(),
        );
    }
    assert_eq!(runtime.active_worker_count(), 0);

    worker.abort();
    forwarder.abort();
    let _ = worker.await;
    let _ = forwarder.await;
}

#[tokio::test]
async fn direct_business_ipv6_budget_floor_is_fail_closed_without_invalid_ptb() {
    const UDP_OWNER: u64 = 701;
    let peers = Arc::new(PeerManager::new(
        Config::generate_default("https://ctrl.test", "net1").unwrap(),
    ));
    let receiver = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let endpoint = receiver.local_addr().unwrap();
    peers
        .add_peer(&business_budget_peer("peer-v6", "10.20.0.2", endpoint))
        .await;
    let udp = UdpTransport::bind("127.0.0.1:0".parse().unwrap(), peers.clone())
        .await
        .unwrap();
    udp.set_inbound_publication_owner(UDP_OWNER);
    let (_identity, _lease) = business_budget_install_confirmed_direct(
        &peers, &udp, "peer-v6", endpoint, 111, 113,
    )
    .await;
    let runtime = udp.dplpmtud_runtime();
    assert_eq!(
        runtime
            .direct_business_budget_entry("peer-v6")
            .and_then(|entry| entry.update.budget)
            .map(|publication| publication.overlay_payload_budget.0),
        Some(1168)
    );

    let (transport, outbound_rx) = WireGuardTransport::new();
    let outbound_loss = Arc::new(tokio::sync::Mutex::new(
        crate::peer::OutboundLossCounters::default(),
    ));
    peers.set_outbound_loss_sink(outbound_loss.clone());
    transport.set_outbound_loss_sink(Some(outbound_loss));
    let (session, _remote) = part03_establish_sessions();
    transport.add_session("peer-v6", session).await;
    let (dataplane_tx, dataplane_rx) = mpsc::channel(4);
    let forwarder = tokio::spawn({
        let transport = transport.clone();
        async move { transport.run_outbound(dataplane_rx).await }
    });
    let timeline = ConnectionTimeline::new("node-v6", 0);
    let (_relay_available_tx, relay_available_rx) = watch::channel(false);
    let (relay_probe_kick_tx, _relay_probe_kick_rx) = watch::channel(0u64);
    let worker = tokio::spawn(run_network_outbound(
        outbound_rx,
        transport,
        peers.clone(),
        true,
        Arc::new(RwLock::new(Some(udp.clone()))),
        Arc::new(RwLock::new(None)),
        relay_available_rx,
        RelayStartupWait { timeout: None },
        relay_probe_kick_tx,
        timeline.clone(),
    ));
    let mut feedback_rx = peers.subscribe_local_mtu_feedback();

    // BASE's 1168-byte inner budget cannot be represented by a valid ICMPv6
    // PTB. Fail closed before encryption/socket handoff and publish no feedback
    // instead of clamping the advertised field to 1280.
    dataplane_tx
        .send(OutboundPacket {
            peer_id: "peer-v6".to_string(),
            dst_ip: "fd00::2".to_string(),
            packet: business_budget_ipv6_packet(256, 17),
            trace: None,
        })
        .await
        .unwrap();
    business_budget_yield_until(
        || {
            timeline.snapshot().events.iter().any(|event| {
                event.reason_code.as_deref()
                    == Some(crate::network_outbound::REASON_IPV6_BUDGET_BELOW_MINIMUM_MTU)
            })
        },
        "IPv6 traffic under a 1168-byte budget did not fail closed with the stable reason",
    )
    .await;
    assert!(matches!(
        feedback_rx.try_recv(),
        Err(tokio::sync::broadcast::error::TryRecvError::Empty)
    ));
    let mut wire = vec![0u8; 2048];
    assert_eq!(
        receiver.try_recv_from(&mut wire).unwrap_err().kind(),
        std::io::ErrorKind::WouldBlock
    );
    assert_eq!(
        peers
            .outbound_loss_stats()
            .await
            .drops
            .get(crate::network_outbound::REASON_IPV6_BUDGET_BELOW_MINIMUM_MTU)
            .map(|counter| counter.packets),
        Some(1)
    );

    // At an internally coherent 1280-byte inner budget, an oversize IPv6
    // packet may receive a standards-valid PTB. Verify the field, pseudo-header
    // checksum, bounded quote, recursive suppression and zero UDP handoff.
    assert!(runtime.force_coherent_business_budget_for_test(
        "peer-v6",
        crate::dplpmtud::UdpDatagramSize(1312),
    ));
    let oversize = business_budget_ipv6_packet(1281, 17);
    dataplane_tx
        .send(OutboundPacket {
            peer_id: "peer-v6".to_string(),
            dst_ip: "fd00::2".to_string(),
            packet: oversize.clone(),
            trace: None,
        })
        .await
        .unwrap();
    let feedback = timeout(Duration::from_secs(2), feedback_rx.recv())
        .await
        .expect("valid IPv6 PTB was not published")
        .unwrap();
    let ip = p2pnet_tun::Ipv6Packet::new(&feedback).unwrap();
    assert_eq!(ip.src_addr(), "fd00::2".parse::<Ipv6Addr>().unwrap());
    assert_eq!(ip.dst_addr(), "fd00::1".parse::<Ipv6Addr>().unwrap());
    assert_eq!(ip.next_header(), 58);
    assert_eq!(&ip.payload()[..2], &[2, 0]);
    assert_eq!(
        u32::from_be_bytes(ip.payload()[4..8].try_into().unwrap()),
        crate::business_mtu::IPV6_MINIMUM_MTU
    );
    assert_eq!(
        crate::business_mtu::icmpv6_checksum(ip.src_addr(), ip.dst_addr(), ip.payload()),
        0
    );
    let quoted_len = crate::business_mtu::IPV6_MINIMUM_MTU as usize - 48;
    assert_eq!(&ip.payload()[8..], &oversize[..quoted_len]);
    assert_eq!(
        crate::business_mtu::build_local_mtu_feedback(
            &feedback,
            crate::business_mtu::LocalMtuFeedbackKind::PacketTooBig {
                inner_ip_mtu: crate::business_mtu::IPV6_MINIMUM_MTU,
            },
        ),
        Err(crate::business_mtu::LocalMtuFeedbackSuppression::RecursiveIcmpError)
    );
    assert_eq!(
        receiver.try_recv_from(&mut wire).unwrap_err().kind(),
        std::io::ErrorKind::WouldBlock
    );
    let connection = peers.get_connection("peer-v6").await.unwrap();
    assert_eq!(connection.active_path(), Some(peer::NetworkPath::Direct));
    assert_eq!(connection.direct_health.failure_count, 0);
    assert_eq!(connection.relay_health.failure_count, 0);

    runtime.cancel_peer(
        "peer-v6",
        "ipv6_budget_floor_test_complete",
        tokio::time::Instant::now(),
    );
    assert_eq!(runtime.active_worker_count(), 0);
    worker.abort();
    forwarder.abort();
    let _ = worker.await;
    let _ = forwarder.await;
}
