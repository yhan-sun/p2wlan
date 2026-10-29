fn periodic_commit_context(
    daemon: &Daemon,
    udp: UdpTransport,
    observer: SocketAddr,
) -> UdpCandidateRefreshContext {
    UdpCandidateRefreshContext {
        udp,
        stun_servers: vec![observer],
        stun_server_specs: vec![observer.to_string()],
        udp_observer_specs: Vec::new(),
        runtime_stun_servers: daemon.runtime_stun_servers.clone(),
        udp_transport_publication: daemon.udp_transport_publication.clone(),
        stun_timeout: Duration::from_secs(1),
        udp_advertise: None,
        upnp_enabled: false,
        allow_loopback_stun_endpoint: false,
        published_endpoint: None,
        local_candidates: daemon.local_candidates.clone(),
        local_candidate_sources: daemon.local_candidate_sources.clone(),
        local_network_identity: daemon.local_network_identity.clone(),
        candidate_snapshot: daemon.candidate_snapshot.clone(),
        candidate_refresh_lock: daemon.candidate_refresh_lock.clone(),
        nat_profile: daemon.nat_profile.clone(),
        gateway_mapping_runtime: daemon.gateway_mapping_runtime.clone(),
        gateway_mapping_diagnostics: daemon.gateway_mapping_diagnostics.clone(),
        punch_deduplicator: daemon.punch_attempts.clone(),
        control: daemon.control.clone(),
        peers: daemon.peers.clone(),
        probe_interval: Duration::from_millis(10),
        punch_attempts: 1,
        boot_epoch_ms: 0,
    }
}

async fn periodic_stun_response(observer: &tokio::net::UdpSocket) -> (Vec<u8>, SocketAddr) {
    let mut bytes = [0; 2048];
    let (length, source) = timeout(Duration::from_secs(2), observer.recv_from(&mut bytes))
        .await
        .unwrap()
        .unwrap();
    let request = p2pnet_nat::StunMessage::decode(&bytes[..length]).unwrap();
    let mut response = p2pnet_nat::StunMessage::with_transaction_id(
        p2pnet_nat::BINDING_RESPONSE,
        request.transaction_id,
    );
    response.add_attribute(p2pnet_nat::StunAttribute::XorMappedAddress(
        "93.184.216.34:45678".parse().unwrap(),
    ));
    (response.encode(), source)
}

fn periodic_answer_remaining_stun(
    observer: Arc<tokio::net::UdpSocket>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut bytes = [0; 2048];
        loop {
            let (length, source) = observer.recv_from(&mut bytes).await.unwrap();
            let request = p2pnet_nat::StunMessage::decode(&bytes[..length]).unwrap();
            let mut response = p2pnet_nat::StunMessage::with_transaction_id(
                p2pnet_nat::BINDING_RESPONSE,
                request.transaction_id,
            );
            response.add_attribute(p2pnet_nat::StunAttribute::XorMappedAddress(
                "93.184.216.34:45678".parse().unwrap(),
            ));
            observer.send_to(&response.encode(), source).await.unwrap();
        }
    })
}

#[tokio::test]
async fn periodic_commit_rechecks_owner_and_generation_after_local_writer_wait() {
    for snapshot_wait in [false, true] {
        for owner_change in [false, true] {
            let mut config = Config::generate_default("http://127.0.0.1:1", "net1").unwrap();
            config.network.gather_host_candidates = false;
            let mut daemon = Daemon::new(config);
            daemon.control = ControlClient::disabled_for_test();
            let udp = UdpTransport::bind("127.0.0.1:0".parse().unwrap(), daemon.peers.clone())
                .await
                .unwrap()
                .with_socket_pool(2)
                .await
                .unwrap();
            daemon.udp_transport_publication.publish(udp.clone()).await;
            // A stale successful gather would turn this existing policy off.
            udp.set_socket_pool_active(true);
            let (inbound, _receiver) = tokio::sync::mpsc::channel(4);
            let reader = tokio::spawn(udp.clone().run_inbound(inbound));
            let observer = Arc::new(tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap());
            let baseline_version = publish_candidate_snapshot_to_store(
                &daemon.candidate_snapshot,
                Vec::new(),
                HashMap::new(),
                vec!["public-ip:93.184.216.35".into()],
            )
            .await;
            let baseline_generation = daemon.peers.current_network_generation_sync();
            let worker = tokio::spawn(run_udp_candidate_refresh(periodic_commit_context(
                &daemon,
                udp.clone(),
                observer.local_addr().unwrap(),
            )));
            let (response, source) = periodic_stun_response(&observer).await;
            let held_profile = if snapshot_wait {
                None
            } else {
                Some(daemon.nat_profile.read().await)
            };
            let held_snapshot = if snapshot_wait {
                Some(daemon.candidate_snapshot.read().await)
            } else {
                None
            };
            observer.send_to(&response, source).await.unwrap();
            let responder = periodic_answer_remaining_stun(observer.clone());
            // The actual worker has passed discovery validation and is now
            // queued on its local writer. This is not an entry-only fence test.
            timeout(Duration::from_secs(2), async {
                loop {
                    let queued = if snapshot_wait {
                        daemon.candidate_snapshot.try_read().is_err()
                    } else {
                        daemon.nat_profile.try_read().is_err()
                    };
                    if queued {
                        break;
                    }
                    tokio::task::yield_now().await;
                }
            })
            .await
            .expect("periodic commit must reach its actual writer");
            let current_udp = if owner_change {
                let next = UdpTransport::bind("127.0.0.1:0".parse().unwrap(), daemon.peers.clone())
                    .await
                    .unwrap();
                daemon.udp_transport_publication.publish(next.clone()).await;
                next
            } else {
                daemon
                    .peers
                    .advance_network_generation("periodic commit contention")
                    .await;
                udp.clone()
            };
            let generation = baseline_generation + u64::from(!owner_change);
            drop(held_profile);
            drop(held_snapshot);
            // This lock was already held by the production writer; obtaining
            // it proves that the old local commit has finished rejecting.
            let finished = timeout(Duration::from_secs(2), daemon.candidate_refresh_lock.lock())
                .await
                .unwrap();
            assert_eq!(daemon.peers.current_network_generation_sync(), generation);
            assert_eq!(daemon.peers.current_local_profile_generation_sync(), 0);
            assert_eq!(daemon.peers.current_local_profile_observation_sync(), None);
            assert!(daemon.nat_profile.read().await.is_none());
            assert!(
                udp.socket_pool_active(),
                "stale report must not change socket scheduling"
            );
            let snapshot = daemon.candidate_snapshot.read().await.clone().unwrap();
            assert_eq!(snapshot.version, baseline_version);
            assert!(snapshot.candidates.is_empty());
            assert_eq!(snapshot.network_identity, vec!["public-ip:93.184.216.35"]);
            assert!(daemon.local_candidates.read().await.is_empty());
            assert!(daemon.local_candidate_sources.read().await.is_empty());
            assert!(daemon.local_network_identity.read().await.is_empty());
            drop(finished);
            worker.abort();
            responder.abort();
            let _ = worker.await;
            let _ = responder.await;
            reader.abort();
            let _ = reader.await;

            // The current owner/generation must still be able to gather and
            // commit through the identical production periodic path.
            let (inbound, _receiver) = tokio::sync::mpsc::channel(4);
            let reader = tokio::spawn(current_udp.clone().run_inbound(inbound));
            let worker = tokio::spawn(run_udp_candidate_refresh(periodic_commit_context(
                &daemon,
                current_udp,
                observer.local_addr().unwrap(),
            )));
            let (response, source) = periodic_stun_response(&observer).await;
            observer.send_to(&response, source).await.unwrap();
            let responder = periodic_answer_remaining_stun(observer.clone());
            timeout(Duration::from_secs(2), async {
                while daemon.nat_profile.read().await.is_none() {
                    tokio::task::yield_now().await;
                }
            })
            .await
            .unwrap();
            let finished = daemon.candidate_refresh_lock.lock().await;
            let snapshot = daemon.candidate_snapshot.read().await.clone().unwrap();
            assert_eq!(snapshot.version, baseline_version + 1);
            assert!(snapshot.candidates.contains(&"93.184.216.34:45678".into()));
            assert_eq!(
                daemon.peers.current_network_generation_sync(),
                generation + 1
            );
            assert!(daemon
                .peers
                .current_local_profile_observation_sync()
                .is_some());
            drop(finished);
            worker.abort();
            reader.abort();
            responder.abort();
            let _ = responder.await;
            let _ = worker.await;
            let _ = reader.await;
            daemon.udp_transport_publication.clear_current().await;
        }
    }
}

#[tokio::test]
async fn periodic_unchanged_candidates_renew_observation_without_replacing_snapshot() {
    let mut config = Config::generate_default("http://127.0.0.1:1", "net1").unwrap();
    config.network.gather_host_candidates = false;
    let daemon = Daemon::new(config);
    let udp = UdpTransport::bind("127.0.0.1:0".parse().unwrap(), daemon.peers.clone())
        .await
        .unwrap();
    daemon.udp_transport_publication.publish(udp.clone()).await;
    let report = p2pnet_nat::candidate_report_from_observations(
        udp.local_addr().unwrap(),
        false,
        vec![p2pnet_nat::StunObservation {
            server: "192.0.2.1:3478".into(),
            mapped_address: Some("93.184.216.34:45678".into()),
            rtt_ms: Some(1),
            error: None,
        }],
    );
    let (candidates, sources) = candidate_endpoints_from_report(&report);
    let identity = stable_network_candidate_signature(&candidates, &sources);
    let version = publish_candidate_snapshot_to_store_with_readiness(
        &daemon.candidate_snapshot,
        candidates.clone(),
        sources.clone(),
        identity.clone(),
        false,
    )
    .await;
    *daemon.local_candidates.write().await = candidates.clone();
    *daemon.local_candidate_sources.write().await = sources.clone();
    *daemon.local_network_identity.write().await = identity;
    let first = daemon
        .peers
        .update_nat_profile(report.nat_profile.clone())
        .await;
    *daemon.nat_profile.write().await = Some(report.nat_profile.clone());
    let baseline = daemon.candidate_snapshot.read().await.clone().unwrap();
    let generation = daemon.peers.current_network_generation_sync();
    let guard = daemon.candidate_refresh_lock.lock().await;
    let fence =
        CandidateGatherFence::capture(&guard, &udp, &daemon.peers, &daemon.candidate_snapshot)
            .await;
    let mut next_report = report;
    next_report.nat_profile.observations[0].rtt_ms = Some(42);
    let committed = commit_candidate_report(
        PreSignalCandidateCommitContext {
            publication: &daemon.udp_transport_publication,
            peers: &daemon.peers,
            nat_profile: &daemon.nat_profile,
            snapshot: &daemon.candidate_snapshot,
            candidates: &daemon.local_candidates,
            sources: &daemon.local_candidate_sources,
            network_identity: &daemon.local_network_identity,
        },
        &guard,
        &fence,
        &udp,
        next_report.clone(),
        candidates.clone(),
        sources.clone(),
        CandidateCommitMode::Periodic,
    )
    .await
    .expect("current periodic measurement must commit");
    assert!(!committed.snapshot_changed);
    assert!(committed.profile_changed);
    assert_eq!(committed.nat_publication.generation, first.generation);
    assert_eq!(
        committed.nat_publication.observation,
        first.observation.map(|o| o + 1)
    );
    assert!(committed.nat_publication.observation_advanced);
    assert_eq!(committed.publication.snapshot_version, version);
    assert!(committed.publication.endpoint_fence.is_current());
    assert_eq!(
        committed.publication.nat_type,
        next_report
            .nat_profile
            .control_label_with_generation_and_observation(
                committed.nat_publication.generation,
                committed.nat_publication.observation,
            )
    );
    assert_eq!(
        *daemon.nat_profile.read().await,
        Some(next_report.nat_profile)
    );
    let snapshot = daemon.candidate_snapshot.read().await.clone().unwrap();
    assert_eq!(snapshot.version, version);
    assert_eq!(snapshot.gathered_at, baseline.gathered_at);
    assert!(!snapshot.initial_gather_complete);
    assert_eq!(snapshot.candidates, candidates);
    assert_eq!(snapshot.candidate_sources, sources);
    assert_eq!(daemon.peers.current_network_generation_sync(), generation);
    drop(guard);
    daemon.udp_transport_publication.clear_current().await;
}
