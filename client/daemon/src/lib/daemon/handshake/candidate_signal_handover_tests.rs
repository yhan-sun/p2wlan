mod candidate_signal_handover_tests {
    use super::*;

    async fn fixture() -> (Arc<Daemon>, UdpTransport) {
        let mut daemon =
            Daemon::new(Config::generate_default("http://127.0.0.1:1", "net1").unwrap());
        daemon.control = ControlClient::disabled_for_test();
        daemon
            .peers
            .add_peer(&control::PeerInfo {
                node_id: "observer".into(),
                online: true,
                public_key: hex::encode(p2pnet_crypto::NodeIdentity::generate().public_key()),
                virtual_ip: "10.20.0.2".into(),
                ..control::PeerInfo::default()
            })
            .await;
        let udp = UdpTransport::bind("127.0.0.1:0".parse().unwrap(), daemon.peers.clone())
            .await
            .unwrap();
        daemon.udp_transport_publication.publish(udp.clone()).await;
        daemon
            .publish_candidate_snapshot_with_readiness(
                vec!["198.51.100.1:40000".into()],
                HashMap::new(),
                vec!["host:192.168.1.2".into()],
                false,
            )
            .await;
        (Arc::new(daemon), udp)
    }

    fn observation(daemon: &Daemon, udp: &UdpTransport) -> PendingPeerReflexive {
        PendingPeerReflexive {
            from_node_id: "observer".into(),
            observed_endpoint: "198.51.100.2:40001".into(),
            punch_at_ms: None,
            endpoint_fence: Some(EndpointPublicationFence::new(udp, &daemon.peers)),
            peer_session_generation: daemon.peers.peer_session_generation_sync("observer"),
            delivery_receipt: None,
        }
    }

    #[tokio::test]
    async fn malformed_peer_reflexive_is_terminal_without_waiting_for_candidate_writer() {
        let (daemon, udp) = fixture().await;
        let mut work = observation(&daemon, &udp);
        work.observed_endpoint = "invalid-endpoint".into();
        let before = daemon.cached_candidate_snapshot().await.unwrap();
        let _writer = daemon.candidate_refresh_lock.lock().await;
        let (_cancel, mut cancellation) = watch::channel(false);
        let outcome = timeout(
            Duration::from_millis(20),
            daemon.handle_peer_reflexive_work(&work, &mut cancellation),
        )
        .await
        .expect("malformed payload must not enter the retryable writer path");
        assert_eq!(outcome, control::SignalApplyOutcome::TerminalRejected);
        let after = daemon.cached_candidate_snapshot().await.unwrap();
        assert_eq!(before.version, after.version);
        assert_eq!(before.candidates, after.candidates);
    }

    #[tokio::test]
    async fn peer_reflexive_waits_cannot_cross_local_publication() {
        for wait_for_snapshot in [false, true] {
            let (daemon, udp) = fixture().await;
            let work = observation(&daemon, &udp);
            let refresh = if wait_for_snapshot {
                None
            } else {
                Some(daemon.candidate_refresh_lock.lock().await)
            };
            let mut snapshot = if wait_for_snapshot {
                Some(daemon.candidate_snapshot.write().await)
            } else {
                None
            };
            let pending = daemon.add_local_peer_reflexive_candidate(&work);
            tokio::pin!(pending);
            // Polling reaches the real refresh/snapshot writer wait; there is
            // no synthetic hook and no sleep whose timing could hide the race.
            assert!(futures_util::poll!(pending.as_mut()).is_pending());
            daemon.udp_transport_publication.clear_current().await;
            daemon
                .peers
                .advance_network_generation("peer-reflexive handover test")
                .await;
            let replacement =
                UdpTransport::bind("127.0.0.1:0".parse().unwrap(), daemon.peers.clone())
                    .await
                    .unwrap();
            daemon
                .udp_transport_publication
                .publish(replacement.clone())
                .await;
            if let Some(held) = snapshot.as_mut() {
                // The new owner publishes under the real store writer before
                // the old writer is allowed to resume from its wait queue.
                let current = held.as_mut().unwrap();
                current.version += 1;
                current.candidates = vec!["198.51.100.3:42000".into()];
                current.candidate_sources.clear();
                current.hash = candidate_set_hash(&current.candidates, &current.candidate_sources);
                current.network_identity = vec!["host:192.168.2.2".into()];
            } else {
                daemon
                    .publish_candidate_snapshot_with_readiness(
                        vec!["198.51.100.3:42000".into()],
                        HashMap::new(),
                        vec!["host:192.168.2.2".into()],
                        false,
                    )
                    .await;
            }
            let before = if let Some(held) = snapshot.as_ref() {
                held.as_ref().unwrap().clone()
            } else {
                daemon.cached_candidate_snapshot().await.unwrap()
            };
            drop(snapshot);
            drop(refresh);
            assert!(
                pending.await.is_none(),
                "retired queued observation must not mutate replacement"
            );
            let after = daemon.cached_candidate_snapshot().await.unwrap();
            assert_eq!(after.version, before.version);
            assert_eq!(after.candidates, before.candidates);
            assert_eq!(after.network_identity, before.network_identity);
            assert!(!after.initial_gather_complete);
            let current = observation(&daemon, &replacement);
            let (changed, selected) = daemon
                .add_local_peer_reflexive_candidate(&current)
                .await
                .unwrap();
            assert!(changed, "current observation must still recover");
            assert!(selected.candidates.contains(&current.observed_endpoint));
            let after = daemon.cached_candidate_snapshot().await.unwrap();
            assert_eq!(after.network_identity, before.network_identity);
            assert!(
                !after.initial_gather_complete,
                "observation cannot finish startup STUN"
            );
            assert_eq!(
                after.gathered_at, before.gathered_at,
                "observation cannot renew STUN lease"
            );
            assert_eq!(*daemon.local_candidates.read().await, after.candidates);
            *daemon.candidate_snapshot.write().await = None;
            assert!(daemon
                .add_local_peer_reflexive_candidate(&current)
                .await
                .is_none());
            assert!(daemon.candidate_snapshot.read().await.is_none());
        }
    }
}
