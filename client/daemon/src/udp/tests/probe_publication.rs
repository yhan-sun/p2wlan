use super::*;

struct Fixture {
    udp: UdpTransport,
    receiver: UdpSocket,
    target: SocketAddr,
    cost: OrdinaryProbeCost,
}

impl Fixture {
    async fn new() -> Self {
        let receiver = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let target = receiver.local_addr().unwrap();
        let mut config = crate::Config::generate_default("https://ctrl.test", "net1").unwrap();
        config.node.node_id = "probe-local".into();
        let peers = Arc::new(PeerManager::new(config));
        let remote = p2pnet_crypto::NodeIdentity::generate();
        peers
            .add_peer(&crate::control::PeerInfo {
                capabilities: crate::control::PeerCapabilities::default(),
                registration_seq: 0,
                node_id: "probe-remote".into(),
                device_name: String::new(),
                app_version: String::new(),
                public_key: hex::encode(remote.public_key()),
                endpoint: target.to_string(),
                nat_type: "Unknown".into(),
                virtual_ip: "10.20.0.2".into(),
                online: true,
                last_seen: 0,
                relay_rtt_ms: None,
            })
            .await;
        let udp = UdpTransport::bind("127.0.0.1:0".parse().unwrap(), peers)
            .await
            .unwrap()
            .with_local_node_id("probe-local");
        udp.set_inbound_publication_owner(260);
        let udp = udp.with_probe_publication_identity(260, 0);
        let cost = udp.ordinary_probe_cost(71, 0, PeerSessionGeneration::for_test(3), 8);
        Self {
            udp,
            receiver,
            target,
            cost,
        }
    }

    async fn probe(
        &self,
        retransmit: bool,
    ) -> std::result::Result<ProbeSendResult, ProbeSendFailure> {
        self.udp
            .send_ordinary_probe_classified_observed(
                0,
                self.udp.socket.clone(),
                Some("probe-remote"),
                self.target,
                retransmit,
                PendingProbePurpose::ConnectivityCheck,
                false,
                &self.cost,
            )
            .await
    }

    async fn assert_quiet(&self) {
        let mut bytes = [0; 2048];
        assert!(timeout(
            Duration::from_millis(10),
            self.receiver.recv_from(&mut bytes)
        )
        .await
        .is_err());
    }
}

#[tokio::test]
async fn ordinary_primary_rechecks_publication_after_wait_and_cleans_pending() {
    for generation_change in [false, true] {
        let fixture = Fixture::new().await;
        let barrier = fixture
            .cost
            .install_gate(OrdinaryProbeTestStage::PrimaryAwait);
        let mut send = Box::pin(fixture.probe(false));
        assert!(futures_util::poll!(send.as_mut()).is_pending());
        barrier.reached.notified().await;
        // Registration has already completed. Change only the authoritative
        // identity while the original send is parked before its syscall.
        let expected = if generation_change {
            fixture
                .udp
                .peers
                .advance_network_generation("probe-test")
                .await;
            ProbeSendFailureKind::NetworkGenerationChanged
        } else {
            fixture.udp.set_inbound_publication_owner(261);
            ProbeSendFailureKind::SocketRevoked
        };
        barrier.release.notify_one();
        let failure = send.await.unwrap_err();
        assert_eq!(failure.kind, expected);
        assert_eq!(failure.physical_send_errors, 0);
        assert!(fixture.udp.pending_probes.lock().await.is_empty());
        assert_eq!(fixture.cost.snapshot().primary.returned_errors, 0);
        fixture.assert_quiet().await;

        let current = fixture.udp.clone().with_probe_publication_identity(
            fixture.udp.inbound_publication_owner(),
            fixture.udp.peers.current_network_generation_sync(),
        );
        assert_eq!(
            current
                .send_publication_scoped_probe_datagram(&current.socket, b"current", fixture.target)
                .await
                .unwrap(),
            7
        );
        let mut bytes = [0; 64];
        assert_eq!(fixture.receiver.recv_from(&mut bytes).await.unwrap().0, 7);
    }
}

#[tokio::test]
async fn publication_revoked_after_primary_preserves_cost_and_suppresses_compat_and_bursts() {
    let mut fixture = Fixture::new().await;
    let capture = Arc::new(ProbeBurstCaptureForTest::new());
    fixture.udp.probe_burst_capture_for_test = Some(capture.clone());
    let barrier = fixture
        .cost
        .install_gate(OrdinaryProbeTestStage::PrimaryResult);
    let mut send = Box::pin(fixture.probe(true));
    // Readiness may initially need the runtime's IO driver.
    timeout(Duration::from_secs(1), async {
        loop {
            assert!(futures_util::poll!(send.as_mut()).is_pending());
            if fixture.cost.snapshot().primary.accepted_datagrams == 1 {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    barrier.reached.notified().await;
    let mut bytes = [0; 2048];
    let (primary_bytes, _) = fixture.receiver.recv_from(&mut bytes).await.unwrap();
    assert!(fixture.udp.clear_inbound_publication_owner_if_matches(260));
    barrier.release.notify_one();
    let result = send.await.unwrap();
    assert_eq!(result.datagrams_sent, 1);
    assert_eq!(result.physical_bytes_sent, primary_bytes as u64);
    assert_eq!(result.physical_send_errors, 0);
    let cost = fixture.cost.snapshot();
    assert_eq!(cost.primary.accepted_datagrams, 1);
    assert_eq!(cost.compatibility.accepted_datagrams, 0);
    assert_eq!(cost.compatibility.returned_errors, 0);
    assert_eq!(capture.tasks.lock().unwrap().reserved, 0);
    fixture.assert_quiet().await;
}

#[tokio::test]
async fn retransmit_keeps_original_publication_identity() {
    let mut fixture = Fixture::new().await;
    let capture = Arc::new(ProbeBurstCaptureForTest::new());
    fixture.udp.probe_burst_capture_for_test = Some(capture.clone());
    let result = fixture.probe(true).await.unwrap();
    assert_eq!(result.datagrams_sent, 2);
    // Revoke before yielding to either newly spawned retransmit child.
    fixture.udp.set_inbound_publication_owner(261);
    let mut bytes = [0; 2048];
    for _ in 0..2 {
        fixture.receiver.recv_from(&mut bytes).await.unwrap();
    }
    // Join the actual burst children after their first scheduled sends. The
    // immutable scope must reject both even though the socket still exists.
    let handles = {
        let mut tasks = capture.tasks.lock().unwrap();
        tasks
            .handles
            .iter_mut()
            .filter_map(Option::take)
            .collect::<Vec<_>>()
    };
    assert_eq!(handles.len(), 2);
    for handle in handles {
        timeout(Duration::from_secs(1), handle)
            .await
            .unwrap()
            .unwrap();
    }
    assert_eq!(
        fixture.udp.socket_pool_diagnostics.lock().await[0].probe_retransmissions_sent,
        0
    );
    fixture.assert_quiet().await;
}

#[tokio::test(start_paused = true)]
async fn publication_and_epoch_contention_have_bounded_pre_handoff_waits() {
    let fixture = Fixture::new().await;
    fixture.udp.socket.writable().await.unwrap();
    let epoch = fixture.udp.network_epoch_gate.lock().await;
    let mut send = Box::pin(fixture.udp.send_publication_scoped_probe_datagram(
        &fixture.udp.socket,
        b"blocked",
        fixture.target,
    ));
    assert!(futures_util::poll!(send.as_mut()).is_pending());
    tokio::time::advance(PROBE_PUBLICATION_HANDOFF_TIMEOUT).await;
    assert_eq!(
        send.await.unwrap_err().kind,
        ProbeSendFailureKind::PreHandoffTimeout
    );
    drop(epoch);
    let publication = fixture
        .udp
        .dplpmtud
        .try_original_business_publication_guard()
        .unwrap();
    let mut send = Box::pin(fixture.udp.send_publication_scoped_probe_datagram(
        &fixture.udp.socket,
        b"blocked",
        fixture.target,
    ));
    assert!(futures_util::poll!(send.as_mut()).is_pending());
    tokio::time::advance(PROBE_PUBLICATION_HANDOFF_TIMEOUT).await;
    assert_eq!(
        send.await.unwrap_err().kind,
        ProbeSendFailureKind::PreHandoffTimeout
    );
    drop(publication);
    fixture.assert_quiet().await;
}

#[tokio::test(start_paused = true)]
async fn owner_is_rechecked_after_actual_publication_gate_contention() {
    let fixture = Fixture::new().await;
    fixture.udp.socket.writable().await.unwrap();
    let publication = fixture
        .udp
        .dplpmtud
        .try_original_business_publication_guard()
        .unwrap();
    let mut send = Box::pin(fixture.udp.send_publication_scoped_probe_datagram(
        &fixture.udp.socket,
        b"obsolete",
        fixture.target,
    ));
    assert!(futures_util::poll!(send.as_mut()).is_pending());
    drop(publication);
    fixture.udp.set_inbound_publication_owner(261);
    tokio::time::advance(Duration::from_millis(1)).await;
    let failure = send.await.unwrap_err();
    assert_eq!(failure.kind, ProbeSendFailureKind::SocketRevoked);
    assert_eq!(failure.physical_send_errors, 0);
    fixture.assert_quiet().await;
}

#[tokio::test]
async fn provisional_finalize_rechecks_owner_after_socket_writer_wait() {
    for replace_owner in [false, true] {
        let fixture = Fixture::new().await;
        let (inbound, _inbound_rx) = mpsc::channel(8);
        let udp = fixture.udp.clone().with_inbound_channel(inbound);
        let (index, socket) = udp.bind_fresh_punch_socket().await.unwrap();
        let mut guard = udp
            .attach_dynamic_punch_socket("probe-remote", index, socket, 0, 1, None)
            .await
            .unwrap();
        assert!(guard
            .commit_and_pin(&udp, "probe-remote", index, 0, 1)
            .await
            .committed());
        let state = udp.socket_state.lock().await;
        let mut finalize = Box::pin(guard.finalize());
        assert!(futures_util::poll!(finalize.as_mut()).is_pending());
        if replace_owner {
            udp.set_inbound_publication_owner(261);
        }
        drop(state);
        assert_eq!(finalize.await, !replace_owner);
        assert_eq!(
            udp.socket_state.lock().await.dynamic[&index].phase,
            if replace_owner {
                DynamicSocketPhase::CommittedPendingHandoff
            } else {
                DynamicSocketPhase::Finalized
            }
        );
        timeout(
            Duration::from_secs(1),
            guard.join_original_watcher_for_test(),
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!(
            udp.socket_state.lock().await.dynamic.contains_key(&index),
            !replace_owner,
            "a refused old handoff must remain rollback-owned"
        );
        udp.detach_all_dynamic_punch_sockets("publication-test-cleanup")
            .await;
    }
}
