async fn candidate_publication_daemon() -> (crate::Daemon, crate::UdpTransport) {
    let mut config = test_config();
    config.network.gather_host_candidates = false;
    let mut daemon = crate::Daemon::new(config);
    daemon.control = ControlClient::disabled_for_test();
    daemon
        .peers
        .add_peer(&PeerInfo {
            node_id: "peer".into(),
            online: true,
            virtual_ip: "10.20.0.2".into(),
            public_key: hex::encode(p2pnet_crypto::NodeIdentity::generate().public_key()),
            ..PeerInfo::default()
        })
        .await;
    let udp = crate::UdpTransport::bind("127.0.0.1:0".parse().unwrap(), daemon.peers.clone())
        .await
        .unwrap();
    daemon.udp_transport_publication.publish(udp.clone()).await;
    (daemon, udp)
}

#[tokio::test]
async fn candidate_publication_queue_rejects_owner_and_snapshot_aba() {
    for replace_owner in [false, true] {
        let (daemon, udp) = candidate_publication_daemon().await;
        daemon
            .publish_candidate_snapshot(
                vec!["198.51.100.1:40000".into()],
                HashMap::new(),
                Vec::new(),
            )
            .await;
        let selected = daemon
            .candidate_signal_set_for_publication(&udp, "peer event")
            .await
            .unwrap();
        let old_fence = selected.publication_fence(
            &daemon,
            "peer",
            daemon.peers.peer_session_generation_sync("peer").unwrap(),
        );
        let server = MockControlServer::spawn(|_, _| MockAction::Ok).await;
        let base_url = format!("http://{}", server.address);
        let http = route_aware_control_http_clients(
            crate::config::ControlProxyMode::Direct,
            &base_url,
            None,
            None,
        )
        .0;
        let (auth_tx, auth_rx) = dispatch_auth_for_test();
        let mut auth = auth_tx.borrow().clone().unwrap();
        auth.base_url = base_url;
        auth_tx.send_replace(None);
        let (candidate_tx, candidate_rx) = mpsc::channel(CANDIDATE_OFFER_QUEUE_CAPACITY);
        let (event_tx, _) = mpsc::unbounded_channel();
        let worker = tokio::spawn(run_candidate_offer_worker(
            candidate_rx,
            http,
            auth_rx,
            event_tx,
        ));
        let mut client = ControlClient::disabled_for_test();
        client.candidate_offer_tx = candidate_tx;
        let send = client.send_peer_offer_with_sources_and_punch_at_fenced(
            "peer",
            &selected.candidates,
            &selected.sources,
            &[],
            None,
            None,
            Some(old_fence),
        );
        tokio::pin!(send);
        assert!(futures_util::poll!(send.as_mut()).is_pending());
        let current_udp = if replace_owner {
            daemon.udp_transport_publication.clear_current().await;
            let replacement =
                crate::UdpTransport::bind("127.0.0.1:0".parse().unwrap(), daemon.peers.clone())
                    .await
                    .unwrap();
            daemon
                .udp_transport_publication
                .publish(replacement.clone())
                .await;
            replacement
        } else {
            // Same hash after a later commit is still a distinct publication.
            daemon
                .publish_candidate_snapshot(
                    selected.candidates.clone(),
                    selected.sources.clone(),
                    Vec::new(),
                )
                .await;
            udp
        };
        auth_tx.send_replace(Some(auth));
        assert_eq!(
            timeout(Duration::from_secs(2), send).await.unwrap(),
            Err(PeerOfferSendFailure::Cancelled)
        );
        assert!(server.signal_posts.lock().unwrap().is_empty());
        let current = daemon
            .candidate_signal_set_for_publication(
                &current_udp,
                "remote incarnation candidate replay",
            )
            .await
            .unwrap();
        let fence = current.publication_fence(
            &daemon,
            "peer",
            daemon.peers.peer_session_generation_sync("peer").unwrap(),
        );
        client
            .send_peer_offer_with_sources_and_punch_at_fenced(
                "peer",
                &current.candidates,
                &current.sources,
                &[],
                None,
                None,
                Some(fence),
            )
            .await
            .unwrap();
        assert_eq!(server.signal_posts.lock().unwrap().len(), 1);
        worker.abort();
        server.task.abort();
    }
}

#[tokio::test]
async fn candidate_publication_rejects_retired_endpoint_response_and_recovers() {
    use p2pnet_nat::{StunAttribute, StunMessage, BINDING_RESPONSE};
    for replace_owner in [false, true] {
        let (mut daemon, udp) = candidate_publication_daemon().await;
        let observer = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        *daemon.runtime_stun_servers.write().await = vec![observer.local_addr().unwrap()];
        *daemon.runtime_stun_timeout.write().await = Duration::from_secs(1);
        let (inbound_tx, _inbound_rx) = mpsc::channel(4);
        let reader = tokio::spawn(udp.clone().run_inbound(inbound_tx));
        let stun = tokio::spawn(async move {
            let mut bytes = [0; 2048];
            let (length, source) = observer.recv_from(&mut bytes).await.unwrap();
            let request = StunMessage::decode(&bytes[..length]).unwrap();
            let mut response =
                StunMessage::with_transaction_id(BINDING_RESPONSE, request.transaction_id);
            response.add_attribute(StunAttribute::XorMappedAddress(
                "93.184.216.34:45678".parse().unwrap(),
            ));
            observer.send_to(&response.encode(), source).await.unwrap();
        });
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let base = format!("http://{}", listener.local_addr().unwrap());
        let (arrived_tx, arrived_rx) = oneshot::channel();
        let (release_tx, release_rx) = oneshot::channel();
        let server = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let request = read_http_request(&mut socket).await.unwrap();
            assert!(request
                .line
                .starts_with("PATCH /api/v1/devices/node-a/endpoint"));
            arrived_tx.send(()).unwrap();
            release_rx.await.unwrap();
            socket.write_all(b"HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: 16\r\nconnection: close\r\n\r\n{\"success\":true}").await.unwrap();
        });
        let harness = CommandHarness::new(&base);
        let (critical_tx, mut critical_rx) = mpsc::channel(CRITICAL_CTRL_QUEUE_CAPACITY);
        daemon.control.critical_ctrl_tx = critical_tx;
        let (_auth_tx, auth_rx) = watch::channel(Some(CriticalControlAuth {
            accepted_peer_capabilities: PeerCapabilities::current(),
            base_url: base,
            token: harness.token.clone(),
            self_node_id: harness.self_node_id.clone(),
            registration_seq: harness.registration_seq,
            signal_signing_identity: None,
        }));
        let (lifecycle_tx, _) = mpsc::unbounded_channel();
        let endpoint_worker = tokio::spawn(async move {
            let Some(CriticalControlCommand::UpdateEndpoint {
                endpoint,
                nat_type,
                publication_fence,
                response_tx,
            }) = critical_rx.recv().await
            else {
                panic!("bootstrap must reach the real endpoint worker");
            };
            run_critical_endpoint_command(
                harness.http,
                auth_rx,
                endpoint,
                nat_type,
                publication_fence,
                response_tx,
                harness.event_tx,
                Arc::new(Semaphore::new(1)),
                None,
                Some(harness.health),
                harness.advertised_snapshot,
                lifecycle_tx,
            )
            .await;
        });
        let signals = Arc::new(std::sync::Mutex::new(Vec::<TestControlSignal>::new()));
        let recorded = signals.clone();
        daemon.control.set_test_signal_forwarder(
            "local",
            "local-key",
            Arc::new(move |signal| {
                recorded.lock().unwrap().push(signal);
            }),
        );
        let daemon = Arc::new(daemon);
        let publishing_daemon = daemon.clone();
        let publishing = tokio::spawn(async move {
            publishing_daemon
                .publish_current_candidates_to_peer("peer", "bootstrap")
                .await;
        });
        timeout(Duration::from_secs(2), arrived_rx)
            .await
            .unwrap()
            .unwrap();
        if replace_owner {
            daemon.udp_transport_publication.clear_current().await;
            let replacement =
                crate::UdpTransport::bind("127.0.0.1:0".parse().unwrap(), daemon.peers.clone())
                    .await
                    .unwrap();
            daemon.udp_transport_publication.publish(replacement).await;
        } else {
            daemon
                .peers
                .advance_network_generation("endpoint response handover")
                .await;
        }
        let replacement_candidates = vec!["198.51.100.3:42000".into()];
        daemon
            .publish_candidate_snapshot(replacement_candidates.clone(), HashMap::new(), Vec::new())
            .await;
        release_tx.send(()).unwrap();
        timeout(Duration::from_secs(2), publishing)
            .await
            .unwrap()
            .unwrap();
        assert!(
            signals.lock().unwrap().is_empty(),
            "old endpoint failure/success cannot fall back to a stale candidate offer"
        );
        daemon
            .publish_current_candidates_to_peer("peer", "remote incarnation candidate replay")
            .await;
        {
            let sent = signals.lock().unwrap();
            assert_eq!(sent.len(), 1);
            assert_eq!(sent[0].candidates, replacement_candidates);
        }
        endpoint_worker.await.unwrap();
        server.await.unwrap();
        stun.await.unwrap();
        reader.abort();
    }
}

#[tokio::test]
async fn candidate_fanout_retains_publication_across_roster_wait() {
    for replace_owner in [false, true] {
        let (mut daemon, udp) = candidate_publication_daemon().await;
        let candidates = vec!["198.51.100.1:40000".into()];
        let sources = HashMap::new();
        let version = crate::publish_candidate_snapshot_to_store(
            &daemon.candidate_snapshot,
            candidates.clone(),
            sources.clone(),
            Vec::new(),
        )
        .await;
        let endpoint = crate::EndpointPublicationFence::new(&udp, &daemon.peers);
        let signals = Arc::new(std::sync::Mutex::new(Vec::<TestControlSignal>::new()));
        let recorded = signals.clone();
        daemon.control.set_test_signal_forwarder(
            "local",
            "local-key",
            Arc::new(move |signal| {
                recorded.lock().unwrap().push(signal);
            }),
        );
        let mut roster = daemon.control.state.write().await;
        roster.peers.insert(
            "peer".into(),
            PeerInfo {
                node_id: "peer".into(),
                online: true,
                ..PeerInfo::default()
            },
        );
        let signal = crate::HolePunchSignalContext {
            control: daemon.control.clone(),
            candidate_snapshot: daemon.candidate_snapshot.clone(),
            stun_servers: Vec::new(),
            stun_timeout: Duration::from_millis(10),
            boot_epoch_ms: 0,
        };
        let pending = crate::candidate_refresh::publish_local_candidates_to_known_peers(
            &daemon.control,
            daemon.peers.clone(),
            udp.clone(),
            daemon.punch_attempts.clone(),
            &candidates,
            &sources,
            version,
            endpoint,
            Duration::from_millis(10),
            1,
            "delayed volatile publication",
            Some(signal.clone()),
        );
        tokio::pin!(pending);
        assert!(futures_util::poll!(pending.as_mut()).is_pending());
        let current_udp = if replace_owner {
            daemon.udp_transport_publication.clear_current().await;
            let replacement =
                crate::UdpTransport::bind("127.0.0.1:0".parse().unwrap(), daemon.peers.clone())
                    .await
                    .unwrap();
            daemon
                .udp_transport_publication
                .publish(replacement.clone())
                .await;
            replacement
        } else {
            udp
        };
        // Even a byte-identical new commit must not be re-stamped as the
        // delayed fanout's source version after its roster wait completes.
        let current_version = if replace_owner {
            // Keep the snapshot/version unchanged to isolate owner fencing.
            version
        } else {
            let replaced = crate::publish_candidate_snapshot_to_store(
                &daemon.candidate_snapshot,
                candidates.clone(),
                sources.clone(),
                Vec::new(),
            )
            .await;
            assert!(replaced > version);
            replaced
        };
        drop(roster);
        timeout(Duration::from_secs(2), pending).await.unwrap();
        assert!(signals.lock().unwrap().is_empty());
        crate::candidate_refresh::publish_local_candidates_to_known_peers(
            &daemon.control,
            daemon.peers.clone(),
            current_udp.clone(),
            daemon.punch_attempts.clone(),
            &candidates,
            &sources,
            current_version,
            crate::EndpointPublicationFence::new(&current_udp, &daemon.peers),
            Duration::from_millis(10),
            1,
            "current publication",
            Some(signal),
        )
        .await;
        assert_eq!(signals.lock().unwrap().len(), 1);
    }
}

#[tokio::test]
async fn fresh_prediction_queue_preserves_original_owner_without_binding_candidate_hash() {
    let (daemon, udp) = candidate_publication_daemon().await;
    daemon
        .publish_candidate_snapshot(
            vec!["198.51.100.1:40000".into()],
            HashMap::new(),
            Vec::new(),
        )
        .await;
    let selected = daemon
        .candidate_signal_set_for_publication(&udp, "fresh optimization")
        .await
        .unwrap();
    let original = selected.publication_fence(
        &daemon,
        "peer",
        daemon.peers.peer_session_generation_sync("peer").unwrap(),
    );
    let fresh_fence = original.for_fresh_prediction();
    daemon
        .publish_candidate_snapshot(
            vec!["198.51.100.1:40001".into()],
            HashMap::new(),
            Vec::new(),
        )
        .await;
    assert!(!original.is_current().await);
    assert!(
        fresh_fence.is_current().await,
        "fresh measurement owns an independent candidate tuple"
    );

    let server = MockControlServer::spawn(|_, _| MockAction::Ok).await;
    let base_url = format!("http://{}", server.address);
    let http = route_aware_control_http_clients(
        crate::config::ControlProxyMode::Direct,
        &base_url,
        None,
        None,
    )
    .0;
    let (auth_tx, auth_rx) = dispatch_auth_for_test();
    let mut auth = auth_tx.borrow().clone().unwrap();
    auth.base_url = base_url;
    auth_tx.send_replace(None);
    let (candidate_tx, candidate_rx) = mpsc::channel(CANDIDATE_OFFER_QUEUE_CAPACITY);
    let (event_tx, _) = mpsc::unbounded_channel();
    let worker = tokio::spawn(run_candidate_offer_worker(
        candidate_rx,
        http,
        auth_rx,
        event_tx,
    ));
    let mut client = ControlClient::disabled_for_test();
    client.candidate_offer_tx = candidate_tx;
    let ownership = Arc::new(crate::PunchSessionCancellation::default());
    let candidates = vec!["198.51.100.1:50000".into()];
    let sources = HashMap::new();
    let mut send = Box::pin(
        client.send_fresh_peer_offer_with_sources_and_punch_at_fenced(
            "peer",
            &candidates,
            &sources,
            &[],
            None,
            ownership.clone(),
            Some(fresh_fence),
        ),
    );
    assert!(futures_util::poll!(send.as_mut()).is_pending());
    let generation = daemon.peers.current_network_generation_sync();
    daemon.udp_transport_publication.clear_current().await;
    let replacement =
        crate::UdpTransport::bind("127.0.0.1:0".parse().unwrap(), daemon.peers.clone())
            .await
            .unwrap();
    daemon
        .udp_transport_publication
        .publish(replacement.clone())
        .await;
    assert_eq!(daemon.peers.current_network_generation_sync(), generation);
    assert!(
        !ownership.is_cancelled(),
        "this regression revokes only the UDP owner"
    );
    auth_tx.send_replace(Some(auth));
    assert_eq!(
        timeout(Duration::from_secs(2), send).await.unwrap(),
        Err(PeerOfferSendFailure::Cancelled)
    );
    assert!(server.signal_posts.lock().unwrap().is_empty());

    let current = daemon
        .candidate_signal_set_for_publication(&replacement, "fresh replacement")
        .await
        .unwrap();
    let fence = current
        .publication_fence(
            &daemon,
            "peer",
            daemon.peers.peer_session_generation_sync("peer").unwrap(),
        )
        .for_fresh_prediction();
    client
        .send_fresh_peer_offer_with_sources_and_punch_at_fenced(
            "peer",
            &candidates,
            &sources,
            &[],
            None,
            ownership,
            Some(fence),
        )
        .await
        .unwrap();
    assert_eq!(server.signal_posts.lock().unwrap().len(), 1);
    worker.abort();
    server.task.abort();
    daemon.udp_transport_publication.clear_current().await;
}
