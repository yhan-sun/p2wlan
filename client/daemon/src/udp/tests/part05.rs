/// Barrier test for the watcher rollback vs fresh evidence: after commit,
/// authenticated Fresh evidence (production `SocketEvidence::Fresh` path via
/// `remember_peer_socket`) arrives on the committed socket; the session is
/// then cancelled (guard dropped); the watcher must PROMOTE the socket to
/// Finalized and keep it — never restore a predecessor or delete a working
/// data socket.
#[tokio::test]
async fn commit_fresh_evidence_then_cancellation_keeps_the_working_socket() {
    let (outcome, peers, transport, _nat, _seen) = run_generation_roundtrip(1, false).await;
    let (result, guard) = match outcome {
        FreshMappingOutcome::Accepted(result, guard) => (*result, *guard),
        FreshMappingOutcome::Rejected(reason) => {
            panic!("expected an accepted generation, got Rejected({reason:?})")
        }
    };

    // The commit installed the pin with no authenticated evidence yet.
    {
        let state = transport.socket_state.lock().await;
        let entry = state.dynamic.get(&result.socket_index).unwrap();
        assert_eq!(
            entry.phase,
            crate::udp::DynamicSocketPhase::CommittedPendingHandoff
        );
        assert_eq!(entry.authenticated_evidence, 0);
    }

    // FORCED INTERLEAVING: authenticated Fresh evidence arrives on the
    // committed socket AFTER the commit, while the durable handoff is still
    // pending.  This is the production path taken by a matched ACK, an
    // accepted authenticated punch or a decrypted WireGuard datagram.
    transport
        .remember_peer_socket("peer-b", result.socket_index, SocketEvidence::Fresh)
        .await;
    {
        let state = transport.socket_state.lock().await;
        assert_eq!(
            state
                .dynamic
                .get(&result.socket_index)
                .unwrap()
                .authenticated_evidence,
            1,
            "fresh evidence must be recorded on the entry itself, not merely inferred from the affinity epoch"
        );
    }

    // The durable handoff never happens: the session is cancelled and the
    // guard drops, firing the watcher's post-commit rollback.  The evidence
    // must win: the socket is promoted to Finalized and stays as the path.
    drop(guard);
    timeout(Duration::from_secs(2), async {
        loop {
            let state = transport.socket_state.lock().await;
            let promoted = state
                .dynamic
                .get(&result.socket_index)
                .is_some_and(|entry| entry.phase == crate::udp::DynamicSocketPhase::Finalized);
            if promoted {
                return;
            }
            drop(state);
            sleep(Duration::from_millis(25)).await;
        }
    })
    .await
    .expect("the watcher must promote the evidenced socket to Finalized instead of rolling it back");
    let state = transport.socket_state.lock().await;
    assert!(
        state.dynamic.contains_key(&result.socket_index),
        "the working socket must still be attached"
    );
    assert_eq!(
        state.affinity.get("peer-b").map(|pin| pin.socket_index),
        Some(result.socket_index),
        "the evidenced socket must stay pinned as the peer's path"
    );
    drop(state);
    let _ = peers;
}

#[tokio::test]
async fn stale_udp_peerleft_cleanup_cancels_replacement_validation_owner() {
    // The control-event loop can clone an old UDP transport immediately before
    // a rebind. Lifecycle cleanup must resolve the PeerManager's current
    // registry, not merely cancel ownership in that stale clone.
    let peers = Arc::new(PeerManager::new(
        Config::generate_default("https://ctrl.test", "net1").unwrap(),
    ));
    peers
        .add_peer(&peer("peer-b", "10.20.0.2", None))
        .await;
    let stale = UdpTransport::bind("127.0.0.1:0".parse().unwrap(), peers.clone())
        .await
        .unwrap();
    let replacement = UdpTransport::bind("127.0.0.1:0".parse().unwrap(), peers.clone())
        .await
        .unwrap();
    let endpoint: SocketAddr = "127.0.0.1:47001".parse().unwrap();
    let owner = match replacement
        .begin_or_merge_direct_validation("peer-b", endpoint, 0)
        .await
    {
        DirectValidationSessionStart::Spawn(lease) => lease.owner_token,
        _ => panic!("the active replacement transport must own the validation lease"),
    };
    assert!(replacement
        .expect_direct_validation_ack_owned("peer-b", 41, 0, owner, endpoint)
        .await);

    stale
        .cleanup_peer_lifecycle("peer-b", "peer_left", true)
        .await;

    assert!(peers.get_connection("peer-b").await.is_none());
    assert!(
        replacement
            .direct_validation_target("peer-b")
            .await
            .is_none(),
        "PeerLeft via a stale UDP clone must revoke the replacement owner's session"
    );
    assert!(
        !replacement.has_direct_validation_expectation("peer-b").await,
        "PeerLeft via a stale UDP clone must clear the replacement expectation"
    );
}

#[tokio::test]
async fn dplpmtud_ack_reverse_route_is_session_socket_and_lifecycle_bound() {
    let peers = peer_manager();
    peers
        .add_peer(&peer("peer-b", "10.20.0.2", None))
        .await;
    let transport = UdpTransport::bind("127.0.0.1:0".parse().unwrap(), peers.clone())
        .await
        .unwrap();
    let generation = peers.current_network_generation_sync();
    let peer_session_generation = peers
        .peer_session_generation_sync("peer-b")
        .expect("the online peer must have a lifecycle generation");
    let local_endpoint = transport.local_addr().unwrap();
    let remote_endpoint: SocketAddr = "127.0.0.1:47011".parse().unwrap();

    assert!(transport.remember_dplpmtud_ack_reverse_route(
        "peer-b",
        generation,
        peer_session_generation,
        remote_endpoint,
        Some(local_endpoint),
        Some(0),
    ));
    assert_eq!(
        transport.dplpmtud_ack_reverse_endpoint(
            "peer-b",
            peer_session_generation,
            local_endpoint,
            0,
        ),
        Some(remote_endpoint),
    );
    assert_eq!(
        transport.dplpmtud_ack_reverse_endpoint(
            "peer-b",
            peer_session_generation,
            local_endpoint,
            1,
        ),
        None,
        "the reverse response route must not cross sockets",
    );
    assert!(!transport.remember_dplpmtud_ack_reverse_route(
        "peer-b",
        generation,
        PeerSessionGeneration::for_test(peer_session_generation.value() + 1),
        remote_endpoint,
        Some(local_endpoint),
        Some(0),
    ));

    transport
        .cleanup_peer_lifecycle("peer-b", "peer_left", true)
        .await;
    assert!(
        transport
            .dplpmtud_ack_reverse_routes
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .is_empty(),
        "peer lifecycle cleanup must erase the UDP-publication-owned route",
    );
}

#[tokio::test]
async fn validation_ack_requires_exact_endpoint_and_socket() {
    let peers = Arc::new(PeerManager::new(
        Config::generate_default("https://ctrl.test", "net1").unwrap(),
    ));
    peers
        .add_peer(&peer("peer-b", "10.20.0.2", None))
        .await;
    let udp = UdpTransport::bind("127.0.0.1:0".parse().unwrap(), peers)
        .await
        .unwrap();
    let endpoint: SocketAddr = "198.51.100.20:51820".parse().unwrap();
    let owner = match udp
        .begin_or_merge_direct_validation("peer-b", endpoint, 0)
        .await
    {
        DirectValidationSessionStart::Spawn(lease) => lease.owner_token,
        _ => panic!("the first validation observation must own the session"),
    };
    assert!(udp
        .expect_direct_validation_ack_owned_on_socket(
            "peer-b",
            0x4101,
            0,
            owner,
            endpoint,
            Some(0),
        )
        .await);

    let endpoint_rejection = udp
        .consume_direct_validation_ack(
            "peer-b",
            0x4101,
            0,
            owner,
            0,
            "198.51.100.21:51820".parse().unwrap(),
            Some(0),
            false,
        )
        .await
        .expect_err("an ACK from an unauthenticated endpoint must be rejected");
    assert_eq!(
        endpoint_rejection.reason_code(),
        "direct_validation_ack_endpoint_mismatch"
    );
    assert!(udp.has_direct_validation_expectation("peer-b").await);
    assert!(udp
        .consume_direct_validation_ack(
            "peer-b",
            0x4101,
            0,
            owner,
            0,
            endpoint,
            Some(1),
            false,
        )
        .await
        .is_err());
    assert!(udp.has_direct_validation_expectation("peer-b").await);
    assert!(udp
        .consume_direct_validation_ack(
            "peer-b",
            0x4101,
            0,
            owner,
            0,
            endpoint,
            Some(0),
            false,
        )
        .await
        .is_ok());
}

#[tokio::test]
async fn direct_validation_allows_on_link_upgrade_but_rejects_public_alternate() {
    let peers = Arc::new(PeerManager::new(
        Config::generate_default("https://ctrl.test", "net1").unwrap(),
    ));
    let public_endpoint: SocketAddr = "198.51.100.24:51820".parse().unwrap();
    let lan_endpoint: SocketAddr = "192.168.2.24:51820".parse().unwrap();
    peers
        .add_peer(&peer("peer-b", "10.20.0.2", Some(public_endpoint)))
        .await;
    peers
        .set_local_interface_networks(vec![p2pnet_nat::LocalNetwork::new(
            "192.168.2.14".parse().unwrap(),
            24,
        )])
        .await;
    peers
        .add_candidates_with_sources(
            "peer-b",
            &[public_endpoint.to_string(), lan_endpoint.to_string()],
            &HashMap::from([
                (public_endpoint.to_string(), "peer_reflexive".to_string()),
                (lan_endpoint.to_string(), "host".to_string()),
            ]),
        )
        .await;
    peers
        .record_direct_probe_success_with_latency(
            "peer-b",
            public_endpoint,
            Some(Duration::from_millis(160)),
        )
        .await;
    peers
        .record_direct_success("peer-b", Some(public_endpoint))
        .await;

    let udp = UdpTransport::bind("127.0.0.1:0".parse().unwrap(), peers.clone())
        .await
        .unwrap();
    assert!(matches!(
        udp.begin_or_merge_direct_validation("peer-b", public_endpoint, 0)
            .await,
        DirectValidationSessionStart::IgnoredInactive
    ));
    assert!(matches!(
        udp.begin_or_merge_direct_validation("peer-b", lan_endpoint, 0)
            .await,
        DirectValidationSessionStart::Spawn(_)
    ));
}

#[tokio::test]
async fn direct_validation_target_keeps_lan_over_public_churn() {
    let peers = Arc::new(PeerManager::new(
        Config::generate_default("https://ctrl.test", "net1").unwrap(),
    ));
    peers
        .add_peer(&peer("peer-b", "10.20.0.2", None))
        .await;
    peers
        .add_peer(&peer("peer-c", "10.20.0.3", None))
        .await;
    peers
        .set_local_interface_networks(vec![p2pnet_nat::LocalNetwork::new(
            "192.168.2.14".parse().unwrap(),
            24,
        )])
        .await;

    let public_endpoint: SocketAddr = "198.51.100.24:51820".parse().unwrap();
    let lan_endpoint: SocketAddr = "192.168.2.24:51820".parse().unwrap();
    let udp = UdpTransport::bind("127.0.0.1:0".parse().unwrap(), peers)
        .await
        .unwrap();

    let lan_owner = match udp
        .begin_or_merge_direct_validation("peer-b", lan_endpoint, 0)
        .await
    {
        DirectValidationSessionStart::Spawn(lease) => lease.owner_token,
        _ => panic!("the first LAN observation must own the validation session"),
    };
    assert!(udp
        .expect_direct_validation_ack_owned("peer-b", 0x5101, 0, lan_owner, lan_endpoint)
        .await);
    assert!(matches!(
        udp.begin_or_merge_direct_validation("peer-b", public_endpoint, 0)
            .await,
        DirectValidationSessionStart::Merged
    ));
    assert_eq!(
        udp.direct_validation_target("peer-b")
            .await
            .unwrap()
            .endpoint,
        lan_endpoint,
        "a later public observation must not displace an on-link target"
    );
    assert!(
        udp.has_direct_validation_expectation("peer-b").await,
        "same-class/public churn must not cancel an in-flight LAN expectation"
    );
    udp.finish_direct_validation_session("peer-b", lan_owner).await;

    let public_owner = match udp
        .begin_or_merge_direct_validation("peer-c", public_endpoint, 0)
        .await
    {
        DirectValidationSessionStart::Spawn(lease) => lease.owner_token,
        _ => panic!("the first public observation must own the validation session"),
    };
    assert!(udp
        .expect_direct_validation_ack_owned(
            "peer-c",
            0x5102,
            0,
            public_owner,
            public_endpoint,
        )
        .await);
    assert!(matches!(
        udp.begin_or_merge_direct_validation("peer-c", lan_endpoint, 0)
            .await,
        DirectValidationSessionStart::Merged
    ));
    assert_eq!(
        udp.direct_validation_target("peer-c")
            .await
            .unwrap()
            .endpoint,
        lan_endpoint,
        "an on-link observation must take over from a public target"
    );
    assert!(
        !udp.has_direct_validation_expectation("peer-c").await,
        "a public in-flight expectation must be revoked when LAN takes over"
    );
    udp.finish_direct_validation_session("peer-c", public_owner).await;
}

#[tokio::test]
async fn direct_validation_target_prefers_public_over_off_link_private() {
    let peers = Arc::new(PeerManager::new(
        Config::generate_default("https://ctrl.test", "net1").unwrap(),
    ));
    peers
        .add_peer(&peer("peer-b", "10.20.0.2", None))
        .await;
    peers
        .set_local_interface_networks(vec![p2pnet_nat::LocalNetwork::new(
            "192.168.1.10".parse().unwrap(),
            24,
        )])
        .await;

    let remote_private: SocketAddr = "192.168.50.20:51820".parse().unwrap();
    let public_endpoint: SocketAddr = "198.51.100.20:51820".parse().unwrap();
    let udp = UdpTransport::bind("127.0.0.1:0".parse().unwrap(), peers)
        .await
        .unwrap();

    let owner = match udp
        .begin_or_merge_direct_validation("peer-b", remote_private, 0)
        .await
    {
        DirectValidationSessionStart::Spawn(lease) => lease.owner_token,
        _ => panic!("the first off-link private observation must own the session"),
    };
    assert!(matches!(
        udp.begin_or_merge_direct_validation("peer-b", public_endpoint, 0)
            .await,
        DirectValidationSessionStart::Merged
    ));
    assert_eq!(
        udp.direct_validation_target("peer-b")
            .await
            .unwrap()
            .endpoint,
        public_endpoint,
        "a usable public candidate must outrank an off-link private endpoint"
    );

    assert!(matches!(
        udp.begin_or_merge_direct_validation("peer-b", remote_private, 0)
            .await,
        DirectValidationSessionStart::Merged
    ));
    assert_eq!(
        udp.direct_validation_target("peer-b")
            .await
            .unwrap()
            .endpoint,
        public_endpoint,
        "later off-link private churn must not displace the public hole-punch target"
    );
    udp.finish_direct_validation_session("peer-b", owner).await;
}

#[tokio::test]
async fn remote_candidate_refresh_cancels_direct_validation_owner() {
    let peers = Arc::new(PeerManager::new(
        Config::generate_default("https://ctrl.test", "net1").unwrap(),
    ));
    peers
        .add_peer(&peer("peer-b", "10.20.0.2", None))
        .await;
    let udp = UdpTransport::bind("127.0.0.1:0".parse().unwrap(), peers.clone())
        .await
        .unwrap();
    let old_endpoint: SocketAddr = "198.51.100.20:51820".parse().unwrap();
    let fresh_endpoint: SocketAddr = "198.51.100.20:51821".parse().unwrap();

    assert!(matches!(
        peers
            .add_candidates_with_metadata(
                "peer-b",
                &[old_endpoint.to_string()],
                &HashMap::new(),
                10,
                Some(u64::MAX),
            )
            .await,
        crate::peer::CandidateSetApplyResult::Applied
    ));
    let generation = peers.current_network_generation().await;
    let owner = match udp
        .begin_or_merge_direct_validation("peer-b", old_endpoint, generation)
        .await
    {
        DirectValidationSessionStart::Spawn(lease) => lease.owner_token,
        _ => panic!("expected a validation owner"),
    };
    assert!(udp
        .expect_direct_validation_ack_owned(
            "peer-b",
            0x5101,
            generation,
            owner,
            old_endpoint,
        )
        .await);

    assert!(matches!(
        peers
            .add_candidates_with_metadata(
                "peer-b",
                &[fresh_endpoint.to_string()],
                &HashMap::new(),
                11,
                Some(u64::MAX),
            )
            .await,
        crate::peer::CandidateSetApplyResult::Applied
    ));

    // ABA handover: the peer can receive the same endpoint again after the
    // cellular mapping is replaced.  The wire generation/remote epoch, not
    // SocketAddr equality, is authoritative; the old owner must stay
    // cancelled even when endpoint A is advertised again.
    assert!(matches!(
        peers
            .add_candidates_with_metadata(
                "peer-b",
                &[old_endpoint.to_string()],
                &HashMap::new(),
                12,
                Some(u64::MAX),
            )
            .await,
        crate::peer::CandidateSetApplyResult::Applied
    ));

    assert!(udp.direct_validation_target("peer-b").await.is_none());
    assert!(!udp.has_direct_validation_expectation("peer-b").await);
    assert!(udp
        .consume_direct_validation_ack(
            "peer-b",
            0x5101,
            generation,
            owner,
            generation,
            old_endpoint,
            Some(0),
            true,
        )
        .await
        .is_err());
}

#[tokio::test]
async fn stale_udp_offline_and_key_change_cleanup_cancel_replacement_validation_owner() {
    // Offline and public-key-change events use the same lifecycle cleanup
    // with `remove_connection = false`. Exercise both after a rebind so the
    // cleanup cannot accidentally operate only on the stale UDP clone.
    for (reason, new_public_key) in [("peer_offline", None), ("public_key_changed", Some("pk2"))]
    {
        let peers = Arc::new(PeerManager::new(
            Config::generate_default("https://ctrl.test", "net1").unwrap(),
        ));
        peers
            .add_peer(&peer("peer-b", "10.20.0.2", None))
            .await;
        let stale = UdpTransport::bind("127.0.0.1:0".parse().unwrap(), peers.clone())
            .await
            .unwrap();
        let replacement = UdpTransport::bind("127.0.0.1:0".parse().unwrap(), peers.clone())
            .await
            .unwrap();
        let endpoint: SocketAddr = "127.0.0.1:47002".parse().unwrap();
        let owner = match replacement
            .begin_or_merge_direct_validation("peer-b", endpoint, 0)
            .await
        {
            DirectValidationSessionStart::Spawn(lease) => lease.owner_token,
            _ => panic!("the active replacement transport must own the validation lease"),
        };
        assert!(replacement
            .expect_direct_validation_ack_owned("peer-b", 42, 0, owner, endpoint)
            .await);

        if let Some(public_key) = new_public_key {
            let mut updated = peer("peer-b", "10.20.0.2", None);
            updated.public_key = public_key.to_string();
            assert!(peers.add_peer(&updated).await.public_key_changed);
        } else {
            let mut updated = peer("peer-b", "10.20.0.2", None);
            updated.online = false;
            peers.add_peer(&updated).await;
        }

        stale
            .cleanup_peer_lifecycle("peer-b", reason, false)
            .await;

        assert!(
            replacement
                .direct_validation_target("peer-b")
                .await
                .is_none(),
            "{reason} via a stale UDP clone must revoke the replacement owner's session"
        );
        assert!(
            !replacement.has_direct_validation_expectation("peer-b").await,
            "{reason} via a stale UDP clone must clear the replacement expectation"
        );
    }
}

/// Barrier test for the network-epoch gate: a generation advance that lands
/// between a stale generation's commit and its durable handoff must refuse
/// the finalize — and the old-generation socket must roll back and never
/// remain as affinity.
#[tokio::test]
async fn network_generation_advance_refuses_stale_finalize_and_rolls_back() {
    let (outcome, peers, transport, _nat, _seen) = run_generation_roundtrip(1, false).await;
    let (result, guard) = match outcome {
        FreshMappingOutcome::Accepted(result, guard) => (*result, *guard),
        FreshMappingOutcome::Rejected(reason) => {
            panic!("expected an accepted generation, got Rejected({reason:?})")
        }
    };

    // The commit succeeded under generation 0.  Now the network generation
    // advances while the durable handoff is still pending: the finalize MUST
    // refuse (the socket belongs to the old generation).
    peers.advance_network_generation("barrier test").await;
    assert!(
        !guard.finalize().await,
        "finalize must refuse once the network generation moved on"
    );

    // No post-commit evidence existed, so the watcher rolls the old socket
    // back: it detaches and the affinity disappears.
    drop(guard);
    timeout(Duration::from_secs(4), async {
        loop {
            let state = transport.socket_state.lock().await;
            if !state.dynamic.contains_key(&result.socket_index) {
                return;
            }
            drop(state);
            sleep(Duration::from_millis(25)).await;
        }
    })
    .await
    .expect("the old-generation socket must be detached after the advance");
    let state = transport.socket_state.lock().await;
    assert!(
        !state.affinity.contains_key("peer-b"),
        "the old generation must never remain as affinity"
    );
    drop(state);
}

/// Barrier test for the lifecycle cleanup: a REAL PeerLeft cleanup running
/// against a REAL in-flight pending probe and its late ACK must be
/// linearized.  The cleanup (connection removal, pending-probe drop with the
/// epoch bump, affinity clear) runs as one transaction under the adoption
/// lock, so the late ACK can neither match nor leave any state behind.
#[tokio::test]
async fn peer_left_cleanup_linearizes_with_late_ack() {
    let peers = peer_manager();
    let remote = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let remote_addr = remote.local_addr().unwrap();
    peers
        .add_peer(&peer("peer-b", "10.20.0.2", Some(remote_addr)))
        .await;

    let transport = UdpTransport::bind("127.0.0.1:0".parse().unwrap(), peers.clone())
        .await
        .unwrap();
    let local_addr = transport.local_addr().unwrap();
    let (tx, _rx) = mpsc::channel(4);
    let worker = tokio::spawn(transport.clone().run_inbound(tx));

    // A real probe is in flight toward the peer's endpoint.
    transport
        .send_probe(Some("peer-b"), remote_addr)
        .await
        .unwrap();
    let mut buf = [0u8; 64];
    let (n, _) = timeout(Duration::from_secs(1), remote.recv_from(&mut buf))
        .await
        .unwrap()
        .unwrap();
    let probe = decode_punch_packet(&buf[..n]).unwrap();
    assert!(
        transport
            .pending_probes
            .lock()
            .await
            .contains_key(&probe.nonce),
        "the pending probe must be registered before the cleanup"
    );

    // BARRIER: the peer leaves while the probe's ACK is still in flight.  The
    // whole lifecycle cleanup runs under the adoption lock.
    transport
        .cleanup_peer_lifecycle("peer-b", "peer_left", true)
        .await;

    // The ACK arrives AFTER the cleanup: it must not match, must not learn an
    // endpoint and must not leave pool affinity behind.
    remote
        .send_to(&build_punch_ack(probe.nonce), local_addr)
        .await
        .unwrap();
    sleep(Duration::from_millis(150)).await;

    assert!(
        peers.get_connection("peer-b").await.is_none(),
        "the peer connection must be gone"
    );
    {
        let state = transport.socket_state.lock().await;
        assert!(
            !state.affinity.contains_key("peer-b"),
            "no stale pool affinity may survive the cleanup"
        );
        assert!(
            transport
                .pending_probes
                .lock()
                .await
                .values()
                .all(|pending| pending.peer_id.as_deref() != Some("peer-b")),
            "no pending probe may survive the cleanup"
        );
    }
    assert_eq!(
        transport.peer_probe_cleanup_epoch("peer-b").await,
        1,
        "the cleanup epoch must have advanced exactly once"
    );

    worker.abort();
}

/// Barrier test for the reverse interleaving: the ACK adoption completes
/// first (it wins the adoption lock), and the PeerLeft cleanup that follows
/// must remove EVERYTHING the ACK created — the connection, the endpoint, the
/// candidates and the pool affinity.
#[tokio::test]
async fn peer_left_cleanup_removes_everything_a_winning_ack_created() {
    let peers = peer_manager();
    let remote = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let remote_addr = remote.local_addr().unwrap();
    peers
        .add_peer(&peer("peer-b", "10.20.0.2", Some(remote_addr)))
        .await;

    let transport = UdpTransport::bind("127.0.0.1:0".parse().unwrap(), peers.clone())
        .await
        .unwrap();
    let local_addr = transport.local_addr().unwrap();
    let (tx, _rx) = mpsc::channel(4);
    let worker = tokio::spawn(transport.clone().run_inbound(tx));

    // The probe is sent and ACKed BEFORE any cleanup: the ACK adoption
    // creates pool affinity and direct success state.
    transport
        .send_probe(Some("peer-b"), remote_addr)
        .await
        .unwrap();
    let mut buf = [0u8; 64];
    let (n, _) = timeout(Duration::from_secs(1), remote.recv_from(&mut buf))
        .await
        .unwrap()
        .unwrap();
    let probe = decode_punch_packet(&buf[..n]).unwrap();
    remote
        .send_to(&build_punch_ack(probe.nonce), local_addr)
        .await
        .unwrap();
    timeout(Duration::from_secs(1), async {
        loop {
            let state = transport.socket_state.lock().await;
            if state.affinity.contains_key("peer-b") {
                return;
            }
            drop(state);
            sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("the ACK adoption must create pool affinity before the cleanup");

    // The PeerLeft cleanup then runs: it must remove the connection, the
    // endpoint/candidates and the affinity in one transaction.
    transport
        .cleanup_peer_lifecycle("peer-b", "peer_left", true)
        .await;
    assert!(
        peers.get_connection("peer-b").await.is_none(),
        "the connection must be removed"
    );
    {
        let state = transport.socket_state.lock().await;
        assert!(
            !state.affinity.contains_key("peer-b"),
            "the affinity the winning ACK created must be removed by the cleanup"
        );
    }
    worker.abort();
}

#[tokio::test]
async fn peer_reflexive_ingress_retains_newest_endpoint_when_full() {
    let ingress = PeerReflexiveIngress::new();
    for index in 0..MAX_PENDING_PEER_REFLEXIVE_INGRESS_PEERS {
        assert!(ingress.submit(PeerReflexiveObservation {
            peer_id: format!("peer-{index}"),
            observed_endpoint: SocketAddr::from(([127, 0, 0, 1], 40_000 + index as u16)),
        }));
    }
    assert_eq!(
        ingress.pending_len(),
        MAX_PENDING_PEER_REFLEXIVE_INGRESS_PEERS,
        "the ingress must have one slot per distinct peer"
    );

    let newest = SocketAddr::from(([127, 0, 0, 1], 45_000));
    assert!(ingress.submit(PeerReflexiveObservation {
        peer_id: "peer-0".to_string(),
        observed_endpoint: newest,
    }));
    assert!(
        !ingress.submit(PeerReflexiveObservation {
            peer_id: "overflow-peer".to_string(),
            observed_endpoint: SocketAddr::from(([127, 0, 0, 1], 45_001)),
        }),
        "only a new peer is refused when the hard ingress bound is full"
    );

    let mut peer_zero_endpoint = None;
    for _ in 0..MAX_PENDING_PEER_REFLEXIVE_INGRESS_PEERS {
        let observation = timeout(Duration::from_secs(1), ingress.next())
            .await
            .expect("every admitted peer must remain consumable");
        if observation.peer_id == "peer-0" {
            peer_zero_endpoint = Some(observation.observed_endpoint);
        }
    }
    assert_eq!(
        peer_zero_endpoint,
        Some(newest),
        "a full ingress must preserve the newest endpoint for an admitted peer"
    );
}

#[test]
fn triggered_check_is_peer_limited_across_endpoint_churn() {
    let mut checks = HashMap::new();
    let now = Instant::now();
    let first = SocketAddr::from(([127, 0, 0, 1], 46_000));
    let churned = SocketAddr::from(([127, 0, 0, 1], 46_001));
    let newest = SocketAddr::from(([127, 0, 0, 1], 46_002));

    assert_eq!(
        UdpTransport::admit_triggered_check(&mut checks, "peer-b", first, now),
        Some(first)
    );
    assert_eq!(
        UdpTransport::admit_triggered_check(
            &mut checks,
            "peer-b",
            churned,
            now + Duration::from_millis(1),
        ),
        None,
        "a changed endpoint cannot open a second in-flight reverse check"
    );
    assert_eq!(
        checks.get("peer-b").map(|record| record.latest_endpoint),
        Some(churned),
        "the one peer record must still retain the churned endpoint"
    );

    UdpTransport::complete_triggered_check(&mut checks, "peer-b", now);
    assert_eq!(
        UdpTransport::admit_triggered_check(
            &mut checks,
            "peer-b",
            newest,
            now + Duration::from_millis(2),
        ),
        None,
        "a changed endpoint cannot bypass the peer-level cooldown"
    );
    assert_eq!(
        UdpTransport::admit_triggered_check(
            &mut checks,
            "peer-b",
            newest,
            now + TRIGGERED_CHECK_COOLDOWN,
        ),
        Some(newest),
        "the next admitted check must use the newest observed endpoint"
    );
    assert_eq!(checks.len(), 1, "endpoint churn must not allocate peer state");
}
