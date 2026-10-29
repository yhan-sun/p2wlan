async fn endpoint_publication_test_owner() -> (crate::Daemon, crate::EndpointPublicationFence) {
    let daemon = crate::Daemon::new(test_config());
    let udp = crate::UdpTransport::bind("127.0.0.1:0".parse().unwrap(), daemon.peers.clone())
        .await
        .unwrap();
    daemon.udp_transport_publication.publish(udp.clone()).await;
    let fence = crate::EndpointPublicationFence::new(&udp, &daemon.peers);
    assert!(fence.is_current());
    (daemon, fence)
}

async fn retire_endpoint_publication(daemon: &crate::Daemon, change_generation: bool) {
    if change_generation {
        daemon
            .peers
            .advance_network_generation("endpoint fence test")
            .await;
    } else {
        daemon.udp_transport_publication.clear_current().await;
    }
}

async fn invoke_fenced_endpoint(
    harness: &mut CommandHarness,
    fence: crate::EndpointPublicationFence,
    critical: bool,
) -> Result<()> {
    let (response_tx, response_rx) = oneshot::channel();
    if critical {
        let (_auth_tx, auth_rx) = watch::channel(Some(CriticalControlAuth {
            accepted_peer_capabilities: PeerCapabilities::current(),
            base_url: harness.base_url.clone(),
            token: harness.token.clone(),
            self_node_id: harness.self_node_id.clone(),
            registration_seq: harness.registration_seq,
            signal_signing_identity: None,
        }));
        let (lifecycle_tx, _lifecycle_rx) = mpsc::unbounded_channel();
        run_critical_endpoint_command(
            harness.http.clone(),
            auth_rx,
            "203.0.113.7:41000".into(),
            "p2v2:m=endpoint_independent".into(),
            Some(fence),
            response_tx,
            harness.event_tx.clone(),
            Arc::new(Semaphore::new(1)),
            None,
            Some(harness.health.clone()),
            harness.advertised_snapshot.clone(),
            lifecycle_tx,
        )
        .await;
    } else {
        assert_eq!(
            harness
                .invoke(
                    ControlCommand::UpdateEndpoint {
                        endpoint: "203.0.113.7:41000".into(),
                        nat_type: "p2v2:m=endpoint_independent".into(),
                        publication_fence: Some(fence),
                        response_tx,
                    },
                    None
                )
                .await,
            ControlCommandDisposition::Continue,
        );
    }
    response_rx
        .await
        .expect("retired endpoint caller receives a terminal result")
}

#[tokio::test]
async fn endpoint_fence_rejects_retired_queued_publications() {
    for critical in [false, true] {
        for change_generation in [false, true] {
            let (daemon, fence) = endpoint_publication_test_owner().await;
            retire_endpoint_publication(&daemon, change_generation).await;
            assert!(!fence.is_current());
            let stub = ControlStub::start(|_| (200, r#"{"success":true}"#.into())).await;
            let mut harness = CommandHarness::new(&stub.base_url);
            harness.health.set_device_lease_healthy(true);
            let result = invoke_fenced_endpoint(&mut harness, fence, critical).await;
            assert!(result.is_err());
            assert!(
                stub.requests().is_empty(),
                "a retired queued owner must not start HTTP"
            );
            assert!(harness.advertised().endpoint.is_empty());
            assert!(harness.device_lease_healthy().await);
            assert!(harness.events().is_empty());
        }
    }
}

#[tokio::test]
async fn endpoint_fence_does_not_commit_retired_inflight_success() {
    for critical in [false, true] {
        for change_generation in [false, true] {
            let (daemon, fence) = endpoint_publication_test_owner().await;
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
            let mut harness = CommandHarness::new(&base);
            harness.health.set_device_lease_healthy(true);
            let snapshot = harness.advertised_snapshot.clone();
            {
                let request = invoke_fenced_endpoint(&mut harness, fence, critical);
                tokio::pin!(request);
                timeout(Duration::from_secs(2), async {
                    tokio::select! {
                        result = &mut request => panic!("HTTP finished before controlled handover: {result:?}"),
                        arrived = arrived_rx => arrived.unwrap(),
                    }
                }).await.unwrap();
                retire_endpoint_publication(&daemon, change_generation).await;
                snapshot.lock().unwrap().endpoint = "203.0.113.8:42000".into();
                release_tx.send(()).unwrap();
                assert!(request.await.is_err());
            }
            server.await.unwrap();
            assert_eq!(harness.advertised().endpoint, "203.0.113.8:42000");
            assert!(harness.device_lease_healthy().await);
            assert!(harness.events().is_empty());
        }
    }
}
