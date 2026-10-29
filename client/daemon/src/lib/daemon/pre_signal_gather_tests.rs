mod pre_signal_gather_tests {
    use super::*;
    use p2pnet_nat::{StunAttribute, StunMessage, BINDING_RESPONSE};
    use tokio::net::UdpSocket;

    #[derive(Clone, Copy)]
    enum SignalRefresh {
        Maintenance,
        Foreground,
    }

    #[derive(Clone, Copy)]
    enum Race {
        LateResponse,
        WaitingWriter,
        PreparationTimeout,
        BegunCommit,
    }

    async fn refresh(
        daemon: &Daemon,
        udp: &UdpTransport,
        path: SignalRefresh,
    ) -> Option<(Vec<String>, HashMap<String, String>)> {
        match path {
            SignalRefresh::Foreground => daemon
                .refresh_local_candidates_core(udp, "handover regression")
                .await
                .map(|result| (result.candidates, result.sources)),
            SignalRefresh::Maintenance => {
                refresh_candidate_cache_for_maintenance_signal(
                    &daemon.peers,
                    &daemon.control,
                    &daemon.udp_transport,
                    &daemon.udp_transport_publication,
                    &daemon.runtime_stun_servers,
                    &daemon.runtime_stun_timeout,
                    None,
                    &daemon.local_candidates,
                    &daemon.local_candidate_sources,
                    &daemon.local_network_identity,
                    &daemon.candidate_snapshot,
                    &daemon.candidate_refresh_lock,
                    &daemon.nat_profile,
                    "handover regression",
                )
                .await
            }
        }
    }

    async fn rebind(
        daemon: &Daemon,
        owner: UdpTransportOwner,
    ) -> (UdpTransport, UdpTransportOwner, u64) {
        assert!(daemon.udp_transport_publication.clear_if_owner(owner).await);
        let generation = daemon
            .peers
            .advance_network_generation("test physical handover")
            .await;
        let replacement = UdpTransport::bind("127.0.0.1:0".parse().unwrap(), daemon.peers.clone())
            .await
            .unwrap();
        let lease = daemon
            .udp_transport_publication
            .publish(replacement.clone())
            .await;
        (replacement, lease.owner(), generation)
    }

    async fn await_profile_writer(daemon: &Daemon) {
        // The test holds a reader. Tokio's fair RwLock refuses new readers
        // once the production writer has reached its real wait queue.
        timeout(Duration::from_secs(2), async {
            while daemon.nat_profile.try_read().is_ok() {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("gather must reach the profile write boundary");
    }

    async fn exercise_race(path: SignalRefresh, race: Race) {
        let mut config = Config::generate_default("http://127.0.0.1:1", "net1").unwrap();
        config.network.gather_host_candidates = false;
        let mut daemon = Daemon::new(config);
        daemon.control = ControlClient::disabled_for_test();
        let daemon = Arc::new(daemon);
        let udp = UdpTransport::bind("127.0.0.1:0".parse().unwrap(), daemon.peers.clone())
            .await
            .unwrap();
        let lease = daemon.udp_transport_publication.publish(udp.clone()).await;
        let (inbound_tx, _inbound_rx) = tokio::sync::mpsc::channel(4);
        let reader = tokio::spawn(udp.clone().run_inbound(inbound_tx));
        let observer = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        *daemon.runtime_stun_servers.write().await = vec![observer.local_addr().unwrap()];
        *daemon.runtime_stun_timeout.write().await = Duration::from_secs(1);
        // These are only encoded STUN mapping values; all network I/O stays
        // on loopback. Documentation addresses are deliberately excluded by
        // the production identity classifier, so use its real public mapping
        // signature to exercise an actual network generation transition.
        let previous_identity = crate::candidate_refresh::stable_network_candidate_signature(
            &["93.184.216.35:45678".into()],
            &HashMap::from([("93.184.216.35:45678".into(), "stun_observed".into())]),
        );
        assert_eq!(previous_identity, vec!["public-ip:93.184.216.35"]);
        // The replacement startup writer must wait on candidate_refresh_lock.
        // Establish this empty baseline BEFORE gathering so only owner/epoch
        // changes can reject the old report, without a snapshot-version change.
        publish_candidate_snapshot_to_store(
            &daemon.candidate_snapshot,
            Vec::new(),
            HashMap::new(),
            previous_identity.clone(),
        )
        .await;
        let baseline_version = daemon
            .candidate_snapshot
            .read()
            .await
            .as_ref()
            .unwrap()
            .version;
        let baseline_generation = daemon.peers.current_network_generation_sync();
        let refresh_daemon = daemon.clone();
        let refresh_udp = udp.clone();
        let mut worker =
            tokio::spawn(async move { refresh(&refresh_daemon, &refresh_udp, path).await });

        // A real STUN request establishes that the production gather started;
        // release its response at each specific lifecycle/lock boundary.
        let mut bytes = [0; 2048];
        let (length, source) = timeout(Duration::from_secs(2), observer.recv_from(&mut bytes))
            .await
            .unwrap()
            .unwrap();
        let request = StunMessage::decode(&bytes[..length]).unwrap();
        let mut response =
            StunMessage::with_transaction_id(BINDING_RESPONSE, request.transaction_id);
        response.add_attribute(StunAttribute::XorMappedAddress(
            "93.184.216.34:45678".parse().unwrap(),
        ));
        let response = response.encode();
        let mut expected_profile = None;
        let mut expected_profile_generation = 0;
        let (expected_owner, expected_generation, committed) = match race {
            Race::LateResponse => {
                let (replacement, owner, generation) = rebind(&daemon, lease.owner()).await;
                let profile = p2pnet_nat::candidate_report_from_observations(
                    replacement.local_addr().unwrap(),
                    false,
                    Vec::new(),
                )
                .nat_profile;
                daemon.peers.update_nat_profile(profile.clone()).await;
                *daemon.nat_profile.write().await = Some(profile.clone());
                expected_profile = Some(profile);
                expected_profile_generation = daemon.peers.current_local_profile_generation_sync();
                observer.send_to(&response, source).await.unwrap();
                (owner, generation, false)
            }
            Race::WaitingWriter => {
                let held_profile = daemon.nat_profile.read().await;
                observer.send_to(&response, source).await.unwrap();
                await_profile_writer(&daemon).await;
                // A gather-return-only check would already have passed. The
                // rebind must stay available while commit preparation waits.
                let (_, owner, generation) = rebind(&daemon, lease.owner()).await;
                drop(held_profile);
                (owner, generation, false)
            }
            Race::PreparationTimeout => {
                let held_profile = daemon.nat_profile.read().await;
                observer.send_to(&response, source).await.unwrap();
                await_profile_writer(&daemon).await;
                // Wait for completion while the production writer is blocked,
                // proving the preparation deadline causes no partial mutation.
                timeout(Duration::from_secs(2), async {
                    while !worker.is_finished() {
                        tokio::task::yield_now().await;
                    }
                })
                .await
                .expect("contended preparation must stop within its budget");
                drop(held_profile);
                (lease.owner(), baseline_generation, false)
            }
            Race::BegunCommit => {
                let held_sessions = daemon.peers.hold_hard_hard_session_writer_for_test().await;
                observer.send_to(&response, source).await.unwrap();
                timeout(Duration::from_secs(2), async {
                    while daemon.peers.current_local_profile_generation_sync() == 0 {
                        tokio::task::yield_now().await;
                    }
                })
                .await
                .expect("profile mutation must begin under the authoritative guards");
                let handover = rebind(&daemon, lease.owner());
                tokio::pin!(handover);
                assert!(
                    futures_util::poll!(&mut handover).is_pending(),
                    "withdrawal must serialize after an already-started commit"
                );
                // Cross the preparation deadline after mutation has begun.
                // Cancellation here would expose a half-completed transition.
                tokio::time::sleep(Duration::from_millis(120)).await;
                assert!(
                    !worker.is_finished(),
                    "the mutation phase has no preparation timeout"
                );
                drop(held_sessions);
                let (_, owner, generation) = timeout(Duration::from_secs(2), &mut handover)
                    .await
                    .unwrap();
                assert_eq!(
                    generation,
                    baseline_generation + 2,
                    "candidate and physical handover each advance exactly once"
                );
                (owner, generation, true)
            }
        };
        let result = timeout(Duration::from_secs(2), &mut worker)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(result.is_some(), committed);
        assert_eq!(
            daemon.peers.current_network_generation_sync(),
            expected_generation
        );
        assert_eq!(
            daemon.udp_transport_publication.current_owner().await,
            Some(expected_owner)
        );
        let snapshot = daemon.candidate_snapshot.read().await.clone().unwrap();
        if committed {
            assert_eq!(snapshot.version, baseline_version + 1);
            assert!(snapshot
                .candidates
                .iter()
                .any(|endpoint| endpoint == "93.184.216.34:45678"));
            assert_eq!(snapshot.network_identity, vec!["public-ip:93.184.216.34"]);
        } else {
            assert_eq!(
                daemon.peers.current_local_profile_generation_sync(),
                expected_profile_generation
            );
            assert_eq!(*daemon.nat_profile.read().await, expected_profile);
            assert_eq!(snapshot.version, baseline_version);
            assert!(snapshot.candidates.is_empty());
            assert_eq!(snapshot.network_identity, previous_identity);
            assert!(daemon.local_candidates.read().await.is_empty());
            assert!(daemon.local_candidate_sources.read().await.is_empty());
            assert!(daemon.local_network_identity.read().await.is_empty());
        }
        reader.abort();
        let _ = reader.await;
        daemon.udp_transport_publication.clear_current().await;
    }

    #[tokio::test]
    async fn maintenance_late_stun_cannot_replace_new_udp_publication() {
        exercise_race(SignalRefresh::Maintenance, Race::LateResponse).await;
    }
    #[tokio::test]
    async fn foreground_late_stun_cannot_replace_new_udp_publication() {
        exercise_race(SignalRefresh::Foreground, Race::LateResponse).await;
    }
    #[tokio::test]
    async fn maintenance_rechecks_handover_after_waiting_for_local_writer() {
        exercise_race(SignalRefresh::Maintenance, Race::WaitingWriter).await;
    }
    #[tokio::test]
    async fn foreground_rechecks_handover_after_waiting_for_local_writer() {
        exercise_race(SignalRefresh::Foreground, Race::WaitingWriter).await;
    }
    #[tokio::test]
    async fn maintenance_preparation_deadline_has_no_partial_writes() {
        exercise_race(SignalRefresh::Maintenance, Race::PreparationTimeout).await;
    }
    #[tokio::test]
    async fn foreground_preparation_deadline_has_no_partial_writes() {
        exercise_race(SignalRefresh::Foreground, Race::PreparationTimeout).await;
    }
    #[tokio::test]
    async fn maintenance_begun_commit_serializes_handover_without_cancellation() {
        exercise_race(SignalRefresh::Maintenance, Race::BegunCommit).await;
    }
    #[tokio::test]
    async fn foreground_begun_commit_serializes_handover_without_cancellation() {
        exercise_race(SignalRefresh::Foreground, Race::BegunCommit).await;
    }
    #[tokio::test]
    async fn endpoint_fence_does_not_retain_a_retired_transport() {
        let peers = Arc::new(PeerManager::new(
            Config::generate_default("http://127.0.0.1:1", "net1").unwrap(),
        ));
        let udp = UdpTransport::bind("127.0.0.1:0".parse().unwrap(), peers.clone())
            .await
            .unwrap();
        udp.set_inbound_publication_owner(1);
        let owner = udp.inbound_publication_owner_weak();
        let fence = EndpointPublicationFence::new(&udp, &peers);
        assert!(fence.is_current());
        drop(udp);
        assert!(
            owner.upgrade().is_none(),
            "queued fence must not retain the transport"
        );
        assert!(!fence.is_current());
    }
}
