#[tokio::test]
async fn path_selector_prefers_relay_until_direct_is_confirmed() {
    let config = test_config();
    let manager = PeerManager::new(config);
    let endpoint: SocketAddr = "127.0.0.1:51831".parse().unwrap();

    manager.add_peer(&test_peer("peer1", endpoint)).await;

    let waiting = manager.select_path_for_data("peer1", true, true).await;
    assert_eq!(waiting.path, Some(NetworkPath::Relay));
    assert_eq!(waiting.reason_code, REASON_PATH_DIRECT_NOT_CONFIRMED);
    assert_eq!(waiting.direct_endpoint, None);

    let no_relay = manager.select_path_for_data("peer1", true, false).await;
    assert_eq!(no_relay.path, None);
    assert_eq!(no_relay.reason_code, REASON_PATH_UNAVAILABLE);
    assert_eq!(no_relay.direct_endpoint, None);
    assert!(!no_relay.direct_confirmed);

    manager
        .record_direct_probe_success_with_latency("peer1", endpoint, Some(Duration::from_millis(6)))
        .await;
    let provisional = manager.select_path_for_data("peer1", true, true).await;
    assert_eq!(provisional.path, Some(NetworkPath::Relay));
    assert!(!provisional.direct_confirmed);
    assert_eq!(
        manager.get_connection("peer1").await.unwrap().active_path(),
        None
    );
    manager.record_direct_success("peer1", Some(endpoint)).await;
    let confirmed = manager.select_path_for_data("peer1", true, true).await;
    assert_eq!(confirmed.path, Some(NetworkPath::Direct));
    assert_eq!(confirmed.reason_code, REASON_PATH_DIRECT_CONFIRMED);
    assert_eq!(confirmed.direct_endpoint, Some(endpoint));
    assert!(confirmed.direct_confirmed);
    assert!(
        confirmed.direct_score.as_ref().unwrap().score
            > confirmed.relay_score.as_ref().unwrap().score
    );
}

#[tokio::test]
async fn authoritative_direct_confirmation_bypasses_ready_relay_business_gate() {
    let config = test_config();
    let manager = PeerManager::new(config);
    let endpoint: SocketAddr = "198.51.100.41:51831".parse().unwrap();
    let relay_endpoint = "tcp://relay.test:18081";

    manager.add_peer(&test_peer("peer1", endpoint)).await;
    let generation = manager.current_network_generation().await;
    manager
        .record_relay_observation("peer1", relay_endpoint)
        .await;
    manager
        .mark_relay_transport_ready("peer1", relay_endpoint, generation)
        .await;
    manager
        .record_direct_probe_success_with_latency("peer1", endpoint, Some(Duration::from_millis(8)))
        .await;
    manager.record_direct_success("peer1", Some(endpoint)).await;
    assert!(manager
        .confirm_relay_peer("peer1", relay_endpoint, generation)
        .await);

    let selected = manager.select_path_for_data("peer1", true, true).await;
    assert_eq!(selected.path, Some(NetworkPath::Direct));
    assert_eq!(selected.reason_code, REASON_PATH_DIRECT_CONFIRMED);
    assert!(selected.direct_confirmed);
    assert!(manager
        .is_data_path_admitted_for_generation("peer1", generation, true)
        .await);
    let diagnostics = manager
        .diagnostics_with_path_selection(true, true, Duration::from_secs(5), None)
        .await;
    assert_eq!(diagnostics[0].active_path, Some(NetworkPath::Direct));

    assert!(manager
        .mark_relay_first_business_sent_for_generation("peer1", generation)
        .await);
    let still_direct = manager.select_path_for_data("peer1", true, true).await;
    assert_eq!(still_direct.path, Some(NetworkPath::Direct));
    assert!(manager
        .mark_relay_first_business_received_for_generation(
            "peer1",
            relay_endpoint,
            generation,
        )
        .await);
    let after_business = manager.select_path_for_data("peer1", true, true).await;
    assert_eq!(after_business.path, Some(NetworkPath::Direct));
    let connection = manager.get_connection("peer1").await.unwrap();
    assert_eq!(connection.state, ConnectionState::Direct);
    assert_eq!(
        connection.last_path_selection.as_ref().unwrap().path,
        Some(NetworkPath::Direct)
    );
}

#[tokio::test]
async fn on_link_direct_bypasses_relay_first_gate() {
    let config = test_config();
    let manager = PeerManager::new(config);
    let endpoint: SocketAddr = "192.168.2.8:51831".parse().unwrap();
    let relay_endpoint = "tcp://relay.test:18081";

    manager.add_peer(&test_peer("peer1", endpoint)).await;
    manager
        .set_local_interface_networks(vec![p2pnet_nat::LocalNetwork::new(
            "192.168.2.16".parse().unwrap(),
            24,
        )])
        .await;
    let generation = manager.current_network_generation().await;
    manager
        .mark_relay_transport_ready("peer1", relay_endpoint, generation)
        .await;
    manager
        .record_direct_probe_success_with_latency("peer1", endpoint, Some(Duration::from_millis(4)))
        .await;
    manager.record_direct_success("peer1", Some(endpoint)).await;

    let selected = manager.select_path_for_data("peer1", true, true).await;
    assert_eq!(selected.path, Some(NetworkPath::Direct));
    assert_eq!(selected.reason_code, REASON_PATH_DIRECT_CONFIRMED);
    assert!(selected.direct_confirmed);
    assert!(manager
        .is_data_path_admitted_for_generation("peer1", generation, true)
        .await);

    let diagnostics = manager
        .diagnostics_with_path_selection(true, true, Duration::from_secs(5), None)
        .await;
    assert_eq!(diagnostics[0].active_path, Some(NetworkPath::Direct));
    assert_eq!(diagnostics[0].direct_type, DirectPathType::Lan);
}

#[tokio::test]
async fn on_link_direct_business_can_be_first_usable_without_relay_business() {
    let manager = PeerManager::new(test_config());
    let endpoint: SocketAddr = "192.168.2.8:51831".parse().unwrap();
    let relay_endpoint = "tcp://relay.test:18081";

    manager.add_peer(&test_peer("peer1", endpoint)).await;
    manager
        .set_local_interface_networks(vec![p2pnet_nat::LocalNetwork::new(
            "192.168.2.16".parse().unwrap(),
            24,
        )])
        .await;
    let generation = manager.current_network_generation().await;
    manager
        .mark_relay_transport_ready("peer1", relay_endpoint, generation)
        .await;
    assert!(manager
        .confirm_relay_peer("peer1", relay_endpoint, generation)
        .await);
    manager
        .record_direct_probe_success_with_latency("peer1", endpoint, Some(Duration::from_millis(4)))
        .await;
    manager.record_direct_success("peer1", Some(endpoint)).await;

    assert!(manager
        .record_verified_first_usable("peer1", generation, NetworkPath::Direct, "direct")
        .await);
    assert!(!manager
        .record_verified_first_usable("peer1", generation, NetworkPath::Direct, "direct")
        .await);

    let connection = manager.get_connection("peer1").await.unwrap();
    assert_eq!(connection.first_usable_generation, Some(generation));
    assert_eq!(connection.first_usable_path, Some(NetworkPath::Direct));
}

#[tokio::test]
async fn relay_ticket_renewal_does_not_rearm_completed_relay_first_gate() {
    let manager = PeerManager::new(test_config());
    let endpoint: SocketAddr = "198.51.100.62:51831".parse().unwrap();
    let relay_endpoint = "tcp://relay.test:18083";

    manager.add_peer(&test_peer("peer1", endpoint)).await;
    let generation = manager.current_network_generation().await;
    manager
        .mark_relay_transport_ready_with_transport(
            "peer1",
            relay_endpoint,
            generation,
            Some(101),
        )
        .await;
    manager
        .record_direct_probe_success_with_latency("peer1", endpoint, Some(Duration::from_millis(7)))
        .await;
    manager.record_direct_success("peer1", Some(endpoint)).await;
    assert!(manager
        .confirm_relay_peer_with_transport(
            "peer1",
            relay_endpoint,
            generation,
            Some(101),
        )
        .await);
    assert!(manager
        .mark_relay_first_business_sent_for_generation("peer1", generation)
        .await);
    assert!(manager
        .mark_relay_first_business_received_for_generation_with_transport(
            "peer1",
            relay_endpoint,
            generation,
            Some(101),
        )
        .await);

    let completed = manager.get_connection("peer1").await.unwrap();
    assert_eq!(
        completed
            .relay_first
            .business_gate_completed_generation,
        Some(generation)
    );
    assert_eq!(
        manager
            .select_path_for_data("peer1", true, true)
            .await
            .path,
        Some(NetworkPath::Direct)
    );

    // A make-before-break ticket renewal replaces the relay transport and
    // revokes only the old relay confirmation. It must not make an already
    // established Direct path wait for the first-business exchange again.
    manager
        .mark_relay_transport_ready_with_transport(
            "peer1",
            relay_endpoint,
            generation,
            Some(202),
        )
        .await;
    let replacement = manager.get_connection("peer1").await.unwrap();
    assert_eq!(replacement.relay_confirmed_generation, None);
    assert_eq!(
        replacement
            .relay_first
            .business_gate_completed_generation,
        Some(generation)
    );
    assert_eq!(
        manager
            .select_path_for_data("peer1", true, true)
            .await
            .path,
        Some(NetworkPath::Direct)
    );

    assert!(manager
        .confirm_relay_peer_with_transport(
            "peer1",
            relay_endpoint,
            generation,
            Some(202),
        )
        .await);
    let after_confirmation = manager.select_path_for_data("peer1", true, true).await;
    assert_eq!(after_confirmation.path, Some(NetworkPath::Direct));
    assert!(manager.path_commit_targets().await.is_empty());
}

#[tokio::test]
async fn authoritative_direct_does_not_wait_for_one_way_relay_business() {
    // One-directional traffic must not strand a peer on Relay after the
    // current-generation encrypted Direct ACK has selected its pair.  Relay
    // business markers remain useful warm-standby evidence, but are no longer
    // an admission gate for an already authoritative Direct path.
    let config = test_config();
    let manager = PeerManager::new(config);
    let endpoint: SocketAddr = "198.51.100.61:51831".parse().unwrap();
    let relay_endpoint = "tcp://relay.test:18082";

    manager.add_peer(&test_peer("peer1", endpoint)).await;
    let generation = manager.current_network_generation().await;
    manager
        .record_relay_observation("peer1", relay_endpoint)
        .await;
    manager
        .mark_relay_transport_ready("peer1", relay_endpoint, generation)
        .await;
    manager
        .record_direct_probe_success_with_latency("peer1", endpoint, Some(Duration::from_millis(7)))
        .await;
    manager.record_direct_success("peer1", Some(endpoint)).await;

    assert!(manager
        .confirm_relay_peer("peer1", relay_endpoint, generation)
        .await);

    // Outbound business has crossed the relay (local send direction)...
    assert!(manager
        .mark_relay_first_business_sent_for_generation("peer1", generation)
        .await);
    // ...but the peer sends nothing back. Direct is already authoritative.
    let selected = manager.select_path_for_data("peer1", true, true).await;
    assert_eq!(selected.path, Some(NetworkPath::Direct));

    // A later path-commit remains accepted as relay standby evidence and is
    // idempotent with respect to the already-selected Direct path.
    assert!(manager
        .mark_relay_first_business_pathcommit_for_generation("peer1", generation, relay_endpoint)
        .await);
    let promoted = manager.select_path_for_data("peer1", true, true).await;
    assert_eq!(promoted.path, Some(NetworkPath::Direct));
    assert!(manager
        .is_data_path_admitted_for_generation("peer1", generation, true)
        .await);
}

#[tokio::test]
async fn stale_pathcommit_does_not_override_authoritative_direct() {
    // A path-commit marker for a stale generation must not mutate the current
    // relay standby state or change an already authoritative Direct path.
    let manager = PeerManager::new(test_config());
    let endpoint: SocketAddr = "198.51.100.62:51831".parse().unwrap();
    let relay_endpoint = "tcp://relay.test:18083";

    manager.add_peer(&test_peer("peer1", endpoint)).await;
    let generation = manager.current_network_generation().await;
    manager
        .record_relay_observation("peer1", relay_endpoint)
        .await;
    manager
        .mark_relay_transport_ready("peer1", relay_endpoint, generation)
        .await;
    manager.record_direct_success("peer1", Some(endpoint)).await;
    assert!(manager
        .confirm_relay_peer("peer1", relay_endpoint, generation)
        .await);

    // A path-commit marked for a generation that is NOT the current one is
    // refused (stale) and does not release the gate.
    assert!(!manager
        .mark_relay_first_business_pathcommit_for_generation("peer1", generation + 1, relay_endpoint)
        .await);
    let still = manager.select_path_for_data("peer1", true, true).await;
    assert_eq!(still.path, Some(NetworkPath::Direct));
}

#[tokio::test]
async fn relay_transport_replacement_revokes_old_confirmation_and_rejects_old_ack() {
    let manager = PeerManager::new(test_config());
    let endpoint: SocketAddr = "198.51.100.52:51831".parse().unwrap();
    let relay_endpoint = "tls://relay.test:443";

    manager.add_peer(&test_peer("peer1", endpoint)).await;
    let generation = manager.current_network_generation().await;
    manager
        .mark_relay_transport_ready_with_transport(
            "peer1",
            relay_endpoint,
            generation,
            Some(101),
        )
        .await;
    assert!(manager
        .confirm_relay_peer_with_transport(
            "peer1",
            relay_endpoint,
            generation,
            Some(101),
        )
        .await);
    assert!(manager
        .is_relay_peer_confirmed_for_generation("peer1", generation)
        .await);

    // Same endpoint and generation, but a new TCP/TLS connection: the old
    // encrypted ACK is no longer evidence for the replacement transport.
    manager
        .mark_relay_transport_ready_with_transport(
            "peer1",
            relay_endpoint,
            generation,
            Some(202),
        )
        .await;
    let replaced = manager.get_connection("peer1").await.unwrap();
    assert_eq!(replaced.relay_ready_connection_id, Some(202));
    assert_eq!(replaced.relay_confirmed_generation, None);
    assert_eq!(replaced.relay_confirmed_connection_id, None);
    assert!(!manager
        .is_relay_peer_confirmed_for_generation("peer1", generation)
        .await);

    // A delayed ACK from the retired connection cannot re-admit the peer.
    assert!(!manager
        .confirm_relay_peer_with_transport(
            "peer1",
            relay_endpoint,
            generation,
            Some(101),
        )
        .await);
    assert!(!manager
        .is_relay_peer_confirmed_for_generation("peer1", generation)
        .await);

    // The replacement must earn its own encrypted ACK.
    assert!(manager
        .confirm_relay_peer_with_transport(
            "peer1",
            relay_endpoint,
            generation,
            Some(202),
        )
        .await);
    let confirmed = manager.get_connection("peer1").await.unwrap();
    assert_eq!(confirmed.relay_confirmed_connection_id, Some(202));
}

#[tokio::test]
async fn retiring_old_relay_transport_does_not_clear_replacement_confirmation() {
    let manager = PeerManager::new(test_config());
    let endpoint: SocketAddr = "198.51.100.53:51831".parse().unwrap();
    let relay_endpoint = "tls://relay.test:443";

    manager.add_peer(&test_peer("peer1", endpoint)).await;
    let generation = manager.current_network_generation().await;
    manager
        .mark_relay_transport_ready_with_transport(
            "peer1",
            relay_endpoint,
            generation,
            Some(301),
        )
        .await;
    assert!(manager
        .confirm_relay_peer_with_transport(
            "peer1",
            relay_endpoint,
            generation,
            Some(301),
        )
        .await);

    // Make-before-break publishes and confirms the replacement before the
    // retired reader's cleanup callback runs.
    manager
        .mark_relay_transport_ready_with_transport(
            "peer1",
            relay_endpoint,
            generation,
            Some(302),
        )
        .await;
    assert!(manager
        .confirm_relay_peer_with_transport(
            "peer1",
            relay_endpoint,
            generation,
            Some(302),
        )
        .await);

    manager
        .invalidate_relay_transport_for_connection(
            relay_endpoint,
            Some(301),
            "relay_transport_replaced",
            "retired reader closed",
        )
        .await;

    let connection = manager.get_connection("peer1").await.unwrap();
    assert_eq!(connection.relay_ready_connection_id, Some(302));
    assert_eq!(connection.relay_confirmed_connection_id, Some(302));
    assert!(manager
        .is_relay_peer_confirmed_for_generation("peer1", generation)
        .await);
}

#[tokio::test]
async fn direct_business_cannot_be_first_usable_before_relay_receive() {
    let manager = PeerManager::new(test_config());
    let endpoint: SocketAddr = "198.51.100.44:51831".parse().unwrap();
    let relay_endpoint = "tcp://relay.test:18081";

    manager.add_peer(&test_peer("peer1", endpoint)).await;
    let generation = manager.current_network_generation().await;
    manager
        .mark_relay_transport_ready("peer1", relay_endpoint, generation)
        .await;
    assert!(manager
        .confirm_relay_peer("peer1", relay_endpoint, generation)
        .await);

    assert!(!manager
        .record_verified_first_usable(
            "peer1",
            generation,
            NetworkPath::Direct,
            "direct",
        )
        .await);
    assert!(manager
        .mark_relay_first_business_received_for_generation(
            "peer1",
            relay_endpoint,
            generation,
        )
        .await);
    // Relay business received + first-usable are one atomic connection
    // transaction now; the compatibility call is therefore idempotent.
    assert!(!manager
        .record_verified_first_usable(
            "peer1",
            generation,
            NetworkPath::Relay,
            "relay:tcp://relay.test:18081",
        )
        .await);
}

#[test]
fn relay_business_pending_ledger_is_newest_wins_ttl_and_capacity_bounded() {
    let manager = PeerManager::new(test_config());
    let base = Instant::now();
    let evidence = |peer_id: String, received_at: Instant| PendingRelayBusinessEvidence {
        peer_id,
        network_generation: 1,
        peer_session_generation: PeerSessionGeneration(1),
        wireguard_session_instance: 7,
        relay_endpoint: "tcp://relay.test:18081".to_string(),
        relay_connection_id: Some(11),
        received_at,
    };

    let expired_at = base
        .checked_sub(PENDING_RELAY_BUSINESS_EVIDENCE_TTL + Duration::from_millis(1))
        .expect("test instant is representable");
    assert!(!manager.retain_pending_relay_business_evidence(evidence(
        "expired".to_string(),
        expired_at,
    )));
    assert_eq!(manager.pending_relay_business_evidence_len(), 0);

    for index in 0..=MAX_PENDING_RELAY_BUSINESS_EVIDENCE {
        assert!(manager.retain_pending_relay_business_evidence(evidence(
            format!("peer-{index}"),
            base + Duration::from_nanos(index as u64),
        )));
    }
    assert_eq!(
        manager.pending_relay_business_evidence_len(),
        MAX_PENDING_RELAY_BUSINESS_EVIDENCE
    );
    assert!(!manager.pending_relay_business_evidence_present("peer-0"));
    let newest_peer = format!("peer-{MAX_PENDING_RELAY_BUSINESS_EVIDENCE}");
    assert!(manager.pending_relay_business_evidence_present(&newest_peer));

    let current_received_at = base
        + Duration::from_nanos(MAX_PENDING_RELAY_BUSINESS_EVIDENCE as u64);
    assert!(!manager.retain_pending_relay_business_evidence(evidence(
        newest_peer.clone(),
        base,
    )));
    let retained = manager
        .pending_relay_business_evidence_for_lifecycle(
            &newest_peer,
            1,
            PeerSessionGeneration(1),
            7,
            "tcp://relay.test:18081",
            Some(11),
            Instant::now(),
        )
        .expect("newest entry remains retained");
    assert_eq!(retained.received_at, current_received_at);
}

#[tokio::test]
async fn relay_receive_before_local_send_completes_after_local_send() {
    let manager = PeerManager::new(test_config());
    let endpoint: SocketAddr = "198.51.100.47:51831".parse().unwrap();
    let relay_endpoint = "tcp://relay.test:18081";

    manager.add_peer(&test_peer("peer1", endpoint)).await;
    let generation = manager.current_network_generation().await;
    manager
        .mark_relay_transport_ready("peer1", relay_endpoint, generation)
        .await;
    assert!(manager
        .confirm_relay_peer("peer1", relay_endpoint, generation)
        .await);
    assert!(manager
        .mark_relay_first_business_received_for_generation(
            "peer1",
            relay_endpoint,
            generation,
        )
        .await);

    // The inbound relay packet arrived before this daemon had sent its own
    // first relay business packet. Its receive marker and Relay first-usable
    // evidence commit atomically, while Direct remains gated until this daemon
    // also sends one.
    assert!(!manager
        .record_verified_first_usable("peer1", generation, NetworkPath::Direct, "direct")
        .await);
    assert!(manager
        .mark_relay_first_business_sent_for_generation("peer1", generation)
        .await);
    manager
        .record_direct_probe_success_with_latency("peer1", endpoint, Some(Duration::from_millis(7)))
        .await;
    manager.record_direct_success("peer1", Some(endpoint)).await;
    // Receive-before-send is not discarded: the send marker completes the
    // two-direction gate without requiring an unrelated later TUN packet.
    let selection = manager.select_path_for_data("peer1", true, true).await;
    assert_eq!(selection.path, Some(NetworkPath::Direct));
    assert!(!manager
        .record_verified_first_usable("peer1", generation, NetworkPath::Direct, "direct")
        .await);
    let connection = manager.get_connection("peer1").await.unwrap();
    assert_eq!(connection.first_usable_path, Some(NetworkPath::Relay));
}

#[tokio::test]
async fn authoritative_direct_business_can_be_first_usable_before_relay_receive() {
    let manager = PeerManager::new(test_config());
    let endpoint: SocketAddr = "198.51.100.46:51831".parse().unwrap();
    let relay_endpoint = "tcp://relay.test:18081";

    manager.add_peer(&test_peer("peer1", endpoint)).await;
    let generation = manager.current_network_generation().await;
    manager
        .mark_relay_transport_ready("peer1", relay_endpoint, generation)
        .await;
    assert!(manager
        .confirm_relay_peer("peer1", relay_endpoint, generation)
        .await);
    manager
        .record_direct_probe_success_with_latency("peer1", endpoint, Some(Duration::from_millis(7)))
        .await;
    manager.record_direct_success("peer1", Some(endpoint)).await;
    {
        let mut connections = manager.connections.write().await;
        let connection = connections.get_mut("peer1").expect("peer exists");
        let expired_at = Instant::now()
            .checked_sub(RELAY_FIRST_CONFIRMATION_GRACE + Duration::from_millis(1))
            .expect("test instant is representable");
        connection.relay_ready_at = Some(expired_at);
        connection.relay_confirmed_at = Some(expired_at);
    }
    let selection = manager.select_path_for_data("peer1", true, true).await;
    assert_eq!(selection.reason_code, REASON_PATH_DIRECT_CONFIRMED);
    assert_eq!(selection.path, Some(NetworkPath::Direct));
    assert!(manager
        .record_verified_first_usable("peer1", generation, NetworkPath::Direct, "direct")
        .await);
    let connection = manager.get_connection("peer1").await.unwrap();
    assert_eq!(connection.first_usable_path, Some(NetworkPath::Direct));
}

#[tokio::test]
async fn relay_first_receive_before_ack_is_promoted_on_confirmation() {
    let manager = PeerManager::new(test_config());
    let endpoint: SocketAddr = "198.51.100.45:51831".parse().unwrap();
    let relay_endpoint = "tcp://relay.test:18081";

    manager.add_peer(&test_peer("peer1", endpoint)).await;
    let generation = manager.current_network_generation().await;
    manager
        .mark_relay_transport_ready("peer1", relay_endpoint, generation)
        .await;
    assert!(!manager
        .mark_relay_first_business_received_for_generation(
            "peer1",
            relay_endpoint,
            generation,
        )
        .await);
    assert!(manager
        .confirm_relay_peer("peer1", relay_endpoint, generation)
        .await);
    // Confirmation consumes the bounded pre-confirmation evidence.  The
    // packet cannot be replayed through WireGuard a second time just to make
    // this marker, so the later call is intentionally idempotent.
    assert!(!manager
        .mark_relay_first_business_received_for_generation(
            "peer1",
            relay_endpoint,
            generation,
        )
        .await);

    let connection = manager.get_connection("peer1").await.unwrap();
    assert_eq!(connection.relay_first.business_received_generation, Some(generation));
    assert_eq!(connection.first_usable_generation, Some(generation));
    assert_eq!(connection.first_usable_path, Some(NetworkPath::Relay));
}

#[tokio::test]
async fn encrypted_business_ingress_can_confirm_relay_before_probe_ack() {
    let manager = PeerManager::new(test_config());
    let endpoint: SocketAddr = "198.51.100.50:51831".parse().unwrap();
    let relay_endpoint = "tcp://relay.test:18081";

    manager.add_peer(&test_peer("peer1", endpoint)).await;
    let generation = manager.current_network_generation().await;
    manager
        .mark_relay_transport_ready_with_transport(
            "peer1",
            relay_endpoint,
            generation,
            Some(17),
        )
        .await;

    // This models the real ordering seen in dual-end logs: the peer's
    // encrypted business packet crossed the relay before this daemon
    // consumed its forced path-probe ACK.  Business ingress is an
    // end-to-end proof and must close the relay confirmation race.
    assert!(manager
        .confirm_relay_peer_from_business_ingress(
            "peer1",
            relay_endpoint,
            generation,
            Some(17),
        )
        .await);
    assert!(manager
        .mark_relay_first_business_received_for_generation_with_transport(
            "peer1",
            relay_endpoint,
            generation,
            Some(17),
        )
        .await);
    // The typed Relay business transaction records first-usable atomically
    // with the receive marker.
    assert!(!manager
        .record_verified_first_usable(
            "peer1",
            generation,
            NetworkPath::Relay,
            "relay:tcp://relay.test:18081",
        )
        .await);

    let connection = manager.get_connection("peer1").await.unwrap();
    assert_eq!(connection.relay_confirmed_generation, Some(generation));
    assert_eq!(connection.relay_confirmed_connection_id, Some(17));
    assert_eq!(connection.relay_first.business_received_generation, Some(generation));
    assert_eq!(connection.first_usable_path, Some(NetworkPath::Relay));
}

#[tokio::test]
async fn preconfirmation_business_from_replaced_relay_transport_is_rejected() {
    let manager = PeerManager::new(test_config());
    let endpoint: SocketAddr = "198.51.100.49:51831".parse().unwrap();
    let relay_endpoint = "tcp://relay.test:18081";

    manager.add_peer(&test_peer("peer1", endpoint)).await;
    let generation = manager.current_network_generation().await;
    manager
        .mark_relay_transport_ready_with_transport(
            "peer1",
            relay_endpoint,
            generation,
            Some(12),
        )
        .await;

    // The business packet belonged to the old connection incarnation.  A
    // same-endpoint replacement must not inherit that evidence.
    assert!(!manager
        .mark_relay_first_business_received_for_generation_with_transport(
            "peer1",
            relay_endpoint,
            generation,
            Some(11),
        )
        .await);
    assert!(manager
        .confirm_relay_peer_with_transport(
            "peer1",
            relay_endpoint,
            generation,
            Some(12),
        )
        .await);
    let connection = manager.get_connection("peer1").await.unwrap();
    assert_eq!(connection.relay_first.business_received_generation, None);
    assert_eq!(connection.first_usable_generation, None);

    assert!(manager
        .mark_relay_first_business_received_for_generation_with_transport(
            "peer1",
            relay_endpoint,
            generation,
            Some(12),
        )
        .await);
}

#[tokio::test]
async fn unconfirmed_relay_ingress_cannot_be_first_usable() {
    let manager = PeerManager::new(test_config());
    let endpoint: SocketAddr = "198.51.100.48:51831".parse().unwrap();
    let relay_endpoint = "tcp://relay.test:18081";

    manager.add_peer(&test_peer("peer1", endpoint)).await;
    let generation = manager.current_network_generation().await;
    manager
        .mark_relay_transport_ready("peer1", relay_endpoint, generation)
        .await;

    assert!(!manager
        .record_verified_first_usable(
            "peer1",
            generation,
            NetworkPath::Relay,
            "relay:tcp://relay.test:18081",
        )
        .await);
    assert_eq!(
        manager
            .get_connection("peer1")
            .await
            .unwrap()
            .first_usable_path,
        None
    );
}

#[tokio::test]
async fn direct_confirmation_is_bounded_fallback_when_relay_probe_does_not_ack() {
    let manager = PeerManager::new(test_config());
    let endpoint: SocketAddr = "198.51.100.42:51831".parse().unwrap();
    let relay_endpoint = "tcp://relay.test:18081";

    manager.add_peer(&test_peer("peer1", endpoint)).await;
    let generation = manager.current_network_generation().await;
    manager
        .mark_relay_transport_ready("peer1", relay_endpoint, generation)
        .await;
    manager
        .record_direct_probe_success_with_latency("peer1", endpoint, Some(Duration::from_millis(8)))
        .await;
    manager.record_direct_success("peer1", Some(endpoint)).await;
    {
        let mut connections = manager.connections.write().await;
        connections
            .get_mut("peer1")
            .expect("peer exists")
            .relay_ready_at = Some(
                Instant::now()
                    .checked_sub(RELAY_FIRST_CONFIRMATION_GRACE + Duration::from_millis(1))
                    .expect("test instant is representable"),
            );
    }

    let selection = manager.select_path_for_data("peer1", true, true).await;
    assert_eq!(selection.path, Some(NetworkPath::Direct));
    assert_eq!(selection.reason_code, REASON_PATH_DIRECT_CONFIRMED);
    assert!(manager
        .is_data_path_admitted_for_generation("peer1", generation, true)
        .await);
}

#[tokio::test]
async fn authoritative_direct_ack_wins_before_per_peer_relay_ready_is_published() {
    let manager = PeerManager::new(test_config());
    let endpoint: SocketAddr = "198.51.100.43:51831".parse().unwrap();

    manager.add_peer(&test_peer("peer1", endpoint)).await;
    let generation = manager.current_network_generation().await;
    manager
        .record_direct_probe_success_with_latency("peer1", endpoint, Some(Duration::from_millis(8)))
        .await;
    manager.record_direct_success("peer1", Some(endpoint)).await;

    // A shared relay transport exists, but this peer has not published its
    // relay-ready milestone yet. The encrypted Direct ACK is stronger than
    // the startup gate and may consume a counter immediately.
    assert!(manager
        .is_data_path_admitted_for_generation("peer1", generation, true)
        .await);
    let selected = manager.select_path_for_data("peer1", true, true).await;
    assert_eq!(selected.path, Some(NetworkPath::Direct));
    assert_eq!(selected.reason_code, REASON_PATH_DIRECT_CONFIRMED);

    // The startup gate marker remains available for relay recovery, but does
    // not demote the current Direct selection.
    {
        let mut connections = manager.connections.write().await;
        connections
            .get_mut("peer1")
            .expect("peer exists")
            .relay_first.gate_started_at = Some(
                Instant::now()
                    .checked_sub(RELAY_FIRST_CONFIRMATION_GRACE + Duration::from_millis(1))
                    .expect("test instant is representable"),
            );
    }
    assert!(manager
        .is_data_path_admitted_for_generation("peer1", generation, true)
        .await);
    let after_expiry = manager.select_path_for_data("peer1", true, true).await;
    assert_eq!(after_expiry.path, Some(NetworkPath::Direct));
}

#[tokio::test]
async fn relay_catalog_gate_does_not_override_authoritative_direct_ack() {
    let manager = PeerManager::new(test_config());
    manager.configure_relay_first(true).await;
    let endpoint: SocketAddr = "198.51.100.64:51864".parse().unwrap();

    manager.add_peer(&test_peer("peer1", endpoint)).await;
    let generation = manager.current_network_generation().await;
    manager
        .record_direct_probe_success_with_latency("peer1", endpoint, Some(Duration::from_millis(6)))
        .await;
    manager.record_direct_success("peer1", Some(endpoint)).await;

    // The catalog gate still arms relay standby state, but an exact encrypted
    // Direct ACK is authoritative for the current generation.
    let selected = manager.select_path_for_data("peer1", true, true).await;
    assert_eq!(selected.path, Some(NetworkPath::Direct));
    assert_eq!(selected.reason_code, REASON_PATH_DIRECT_CONFIRMED);
    assert!(manager
        .is_data_path_admitted_for_generation("peer1", generation, true)
        .await);

    let connection = manager.get_connection("peer1").await.unwrap();
    assert_eq!(connection.state, ConnectionState::Direct);
    assert_eq!(connection.relay_first.gate_generation, Some(generation));
}

#[tokio::test]
async fn encrypted_validation_rtt_replaces_delayed_candidate_probe_rtt() {
    let config = test_config();
    let manager = PeerManager::new(config);
    let endpoint: SocketAddr = "198.51.100.31:51831".parse().unwrap();

    manager.add_peer(&test_peer("peer1", endpoint)).await;
    manager
        .record_direct_probe_success_with_latency(
            "peer1",
            endpoint,
            Some(Duration::from_millis(700)),
        )
        .await;
    manager
        .record_relay_success_with_latency(
            "peer1",
            "relay.test:443",
            false,
            Duration::from_millis(20),
        )
        .await;

    let generation = manager.current_network_generation().await;
    let epoch_gate = manager.network_epoch_gate();
    let epoch_guard = epoch_gate.lock().await;
    assert!(manager
        .record_direct_success_for_generation_with_local_endpoint_and_latency_in_epoch(
            &epoch_guard,
            "peer1",
            Some(endpoint),
            generation,
            None,
            Some(Duration::from_millis(8)),
        )
        .await);
    drop(epoch_guard);

    let connection = manager.get_connection("peer1").await.unwrap();
    let pair = connection
        .candidate_pairs
        .iter()
        .find(|pair| pair.remote_endpoint == endpoint && pair.local_generation == generation)
        .unwrap();
    assert_eq!(pair.state, CandidatePairState::Selected);
    assert_eq!(pair.rtt_ewma_ms.or(pair.rtt_ms), Some(8));
    assert_eq!(connection.direct_health.rtt_ewma_ms, Some(8));
    assert_eq!(connection.direct_health.latency_ms, Some(8));

    let selection = manager.select_path_for_data("peer1", true, true).await;
    assert_eq!(selection.path, Some(NetworkPath::Direct));
    assert_eq!(selection.reason_code, REASON_PATH_DIRECT_CONFIRMED);
    assert!(selection.direct_confirmed);
}

#[tokio::test]
async fn alternate_endpoint_probe_rtt_does_not_replace_active_direct_health() {
    let manager = PeerManager::new(test_config());
    let selected: SocketAddr = "198.51.100.32:51831".parse().unwrap();
    let alternate: SocketAddr = "198.51.100.32:51832".parse().unwrap();
    manager.add_peer(&test_peer("peer1", selected)).await;
    manager
        .add_candidates("peer1", &[selected.to_string(), alternate.to_string()])
        .await;
    manager
        .record_direct_probe_success_with_latency(
            "peer1",
            selected,
            Some(Duration::from_millis(8)),
        )
        .await;
    manager.record_direct_success("peer1", Some(selected)).await;

    let before = manager.get_connection("peer1").await.unwrap();
    assert_eq!(before.endpoint, Some(selected));
    assert_eq!(before.direct_health.rtt_ewma_ms, Some(8));
    manager
        .record_direct_probe_success_with_latency(
            "peer1",
            alternate,
            Some(Duration::from_millis(408)),
        )
        .await;

    let after = manager.get_connection("peer1").await.unwrap();
    assert_eq!(after.endpoint, Some(selected));
    assert_eq!(after.direct_health.rtt_ewma_ms, Some(8));
    assert_eq!(after.direct_health.latency_ms, Some(8));
    let alternate_pair = after
        .candidate_pairs
        .iter()
        .find(|pair| pair.remote_endpoint == alternate)
        .expect("alternate ACK must remain useful candidate evidence");
    assert_eq!(alternate_pair.rtt_ewma_ms.or(alternate_pair.rtt_ms), Some(408));
}

#[tokio::test]
async fn slow_encrypted_direct_validation_confirms_and_promotes_direct() {
    let manager = PeerManager::new(test_config());
    let endpoint: SocketAddr = "198.51.100.61:51861".parse().unwrap();
    let relay_endpoint = "tcp://relay.test:18081";

    manager.add_peer(&test_peer("peer1", endpoint)).await;
    let generation = manager.current_network_generation().await;
    manager
        .record_relay_success_with_latency(
            "peer1",
            relay_endpoint,
            false,
            Duration::from_millis(35),
        )
        .await;
    manager
        .mark_relay_transport_ready("peer1", relay_endpoint, generation)
        .await;
    assert!(manager
        .confirm_relay_peer("peer1", relay_endpoint, generation)
        .await);
    assert!(manager
        .mark_relay_first_business_sent_for_generation("peer1", generation)
        .await);
    assert!(manager
        .mark_relay_first_business_received_for_generation("peer1", relay_endpoint, generation)
        .await);
    manager
        .record_direct_probe_success_with_latency(
            "peer1",
            endpoint,
            Some(Duration::from_millis(505)),
        )
        .await;

    let epoch_gate = manager.network_epoch_gate();
    let epoch_guard = epoch_gate.lock().await;
    let promoted = manager
        .record_direct_success_for_generation_with_local_endpoint_and_latency_in_epoch(
            &epoch_guard,
            "peer1",
            Some(endpoint),
            generation,
            None,
            Some(Duration::from_millis(505)),
        )
        .await;
    drop(epoch_guard);

    assert!(
        promoted,
        "an exact encrypted Direct ACK must promote even when its RTT is high"
    );
    let connection = manager.get_connection("peer1").await.unwrap();
    assert_eq!(connection.state, ConnectionState::Direct);
    let pair = connection
        .candidate_pairs
        .iter()
        .find(|pair| pair.remote_endpoint == endpoint && pair.local_generation == generation)
        .unwrap();
    assert_eq!(pair.state, CandidatePairState::Selected);
    assert_eq!(pair.rtt_ewma_ms.or(pair.rtt_ms), Some(505));
    assert!(pair.selected_at.is_some());
    assert!(connection.direct_events.iter().any(|event| {
        event.stage == "direct_confirmed" && event.network_generation == generation
    }));
    assert!(!connection
        .direct_events
        .iter()
        .any(|event| event.stage == "direct_validation_succeeded_relay_retained"));
    // An exact encrypted Request -> ACK is the make-before-break proof.  A
    // later probe observation must not demote that proof or put the business
    // path back behind an arbitrary slow-relay cooldown.
    manager
        .record_direct_probe_success_with_latency(
            "peer1",
            endpoint,
            Some(Duration::from_millis(490)),
        )
        .await;
    let selection = manager.select_path_for_data("peer1", true, true).await;
    assert_eq!(selection.path, Some(NetworkPath::Direct));
    assert_eq!(
        selection.reason_code,
        REASON_PATH_DIRECT_CONFIRMED
    );
    assert!(selection.direct_confirmed);
}

#[tokio::test]
async fn slow_direct_probe_does_not_start_validation_over_confirmed_relay() {
    let manager = PeerManager::new(test_config());
    let endpoint: SocketAddr = "198.51.100.63:51863".parse().unwrap();
    let relay_endpoint = "tcp://relay.test:18081";

    manager.add_peer(&test_peer("peer1", endpoint)).await;
    let generation = manager.current_network_generation().await;
    manager
        .record_relay_success_with_latency(
            "peer1",
            relay_endpoint,
            false,
            Duration::from_millis(35),
        )
        .await;
    manager
        .mark_relay_transport_ready("peer1", relay_endpoint, generation)
        .await;
    assert!(manager
        .confirm_relay_peer("peer1", relay_endpoint, generation)
        .await);
    assert!(manager
        .mark_relay_first_business_sent_for_generation("peer1", generation)
        .await);

    let validation_trigger = manager
        .record_direct_probe_success_with_latency_for_generation_and_local_endpoint(
            "peer1",
            endpoint,
            Some(Duration::from_millis(505)),
            generation,
            None,
        )
        .await;

    assert!(!validation_trigger);
    let connection = manager.get_connection("peer1").await.unwrap();
    assert_eq!(connection.state, ConnectionState::Relay);
    let pair = connection
        .candidate_pairs
        .iter()
        .find(|pair| pair.remote_endpoint == endpoint && pair.local_generation == generation)
        .unwrap();
    assert_eq!(pair.state, CandidatePairState::Degraded);
    assert_eq!(pair.last_error_code.as_deref(), Some(REASON_DIRECT_SLOW_RELAY_RETAINED));
    assert_eq!(pair.slow_validation_count, 1);
    assert!(connection
        .direct_events
        .iter()
        .any(|event| event.stage == "direct_probe_succeeded_relay_retained"));
}

#[tokio::test]
async fn slow_probe_evidence_does_not_replace_active_endpoint() {
    let manager = PeerManager::new(test_config());
    let active_endpoint: SocketAddr = "198.51.100.64:51864".parse().unwrap();
    let slow_endpoint: SocketAddr = "198.51.100.65:51865".parse().unwrap();
    let relay_endpoint = "tcp://relay.test:18081";

    manager
        .add_peer(&test_peer("peer1", active_endpoint))
        .await;
    let generation = manager.current_network_generation().await;
    manager
        .record_relay_success_with_latency(
            "peer1",
            relay_endpoint,
            false,
            Duration::from_millis(35),
        )
        .await;
    manager
        .mark_relay_transport_ready("peer1", relay_endpoint, generation)
        .await;
    assert!(manager
        .confirm_relay_peer("peer1", relay_endpoint, generation)
        .await);
    assert!(manager
        .mark_relay_first_business_sent_for_generation("peer1", generation)
        .await);

    assert!(!manager
        .record_direct_probe_success_with_latency_for_generation_and_local_endpoint(
            "peer1",
            slow_endpoint,
            Some(Duration::from_millis(505)),
            generation,
            None,
        )
        .await);

    let connection = manager.get_connection("peer1").await.unwrap();
    assert_eq!(connection.state, ConnectionState::Relay);
    assert_eq!(
        connection.endpoint,
        Some(active_endpoint),
        "a quarantined slow candidate must remain evidence only; it must not become the active endpoint"
    );
}

#[tokio::test]
async fn slow_confirmed_direct_is_not_active_over_confirmed_relay() {
    let manager = PeerManager::new(test_config());
    let endpoint: SocketAddr = "198.51.100.62:51862".parse().unwrap();
    let relay_endpoint = "tcp://relay.test:18081";

    manager.add_peer(&test_peer("peer1", endpoint)).await;
    let generation = manager.current_network_generation().await;
    manager
        .record_relay_success_with_latency(
            "peer1",
            relay_endpoint,
            false,
            Duration::from_millis(35),
        )
        .await;
    manager
        .mark_relay_transport_ready("peer1", relay_endpoint, generation)
        .await;
    assert!(manager
        .confirm_relay_peer("peer1", relay_endpoint, generation)
        .await);
    assert!(manager
        .mark_relay_first_business_sent_for_generation("peer1", generation)
        .await);
    assert!(manager
        .mark_relay_first_business_received_for_generation("peer1", relay_endpoint, generation)
        .await);
    manager
        .record_direct_probe_success_with_latency(
            "peer1",
            endpoint,
            Some(Duration::from_millis(505)),
        )
        .await;
    manager.record_direct_success("peer1", Some(endpoint)).await;
    let selection = manager.select_path_for_data("peer1", true, true).await;
    assert_eq!(selection.path, Some(NetworkPath::Relay));
    assert_eq!(
        selection.reason_code,
        REASON_PATH_DIRECT_SLOW_RELAY_RETAINED
    );
    assert!(!selection.direct_confirmed);
}

#[tokio::test]
async fn encrypted_direct_confirmation_ignores_stale_probe_failures_for_admission() {
    let config = test_config();
    let manager = PeerManager::new(config);
    let endpoint: SocketAddr = "198.51.100.32:51832".parse().unwrap();

    manager.add_peer(&test_peer("peer1", endpoint)).await;
    manager
        .record_direct_probe_success_with_latency(
            "peer1",
            endpoint,
            Some(Duration::from_millis(700)),
        )
        .await;
    manager
        .record_relay_success_with_latency(
            "peer1",
            "relay.test:443",
            false,
            Duration::from_millis(20),
        )
        .await;
    manager.record_direct_success("peer1", Some(endpoint)).await;

    {
        let mut connections = manager.connections.write().await;
        let connection = connections.get_mut("peer1").unwrap();
        // These failures happened while Direct was still a probe candidate.
        // The encrypted Request/ACK below has already reset the current
        // failure streak, but the cumulative counter remains diagnostic data.
        connection.direct_health.failure_count = 5;
        connection.direct_health.consecutive_failures = 0;
        connection.direct_health.rtt_ewma_ms = Some(500);
        connection.direct_health.jitter_ms = Some(0);
    }

    let selected = manager.select_path_for_data("peer1", true, true).await;
    assert_eq!(selected.path, Some(NetworkPath::Direct));
    assert_eq!(selected.reason_code, REASON_PATH_DIRECT_CONFIRMED);
    assert!(selected.direct_confirmed);
    assert_eq!(selected.direct_endpoint, Some(endpoint));
}

#[tokio::test]
async fn path_selector_uses_scores_and_hysteresis_for_degraded_direct() {
    let config = test_config();
    let manager = PeerManager::new(config);
    let endpoint: SocketAddr = "127.0.0.1:51836".parse().unwrap();

    manager.add_peer(&test_peer("peer1", endpoint)).await;
    manager
        .record_direct_probe_success_with_latency(
            "peer1",
            endpoint,
            Some(Duration::from_millis(18)),
        )
        .await;
    manager.record_direct_success("peer1", Some(endpoint)).await;
    manager
        .record_relay_success("peer1", "relay.test:443", false)
        .await;
    let generation = manager.current_network_generation().await;
    assert!(
        manager
            .confirm_relay_peer("peer1", "relay.test:443", generation)
            .await
    );

    let healthy = manager.select_path_for_data("peer1", true, true).await;
    assert_eq!(healthy.path, Some(NetworkPath::Direct));
    assert_eq!(healthy.reason_code, REASON_PATH_DIRECT_CONFIRMED);

    {
        let mut conns = manager.connections.write().await;
        let conn = conns.get_mut("peer1").unwrap();
        conn.direct_health.consecutive_failures = 3;
        conn.direct_health.failure_count = 3;
        conn.direct_health.rtt_ewma_ms = Some(650);
        conn.direct_health.jitter_ms = Some(120);
    }

    let degraded = manager.select_path_for_data("peer1", true, true).await;
    assert_eq!(degraded.path, Some(NetworkPath::Relay));
    assert_eq!(degraded.reason_code, REASON_PATH_DIRECT_DEGRADED);
    assert!(!degraded.direct_confirmed);
    assert!(!degraded.relay_hedged);
    assert!(
        degraded.direct_score.as_ref().unwrap().score + DIRECT_TO_RELAY_HYSTERESIS_MARGIN
            < degraded.relay_score.as_ref().unwrap().score
    );
}

#[tokio::test]
async fn path_selector_retains_low_latency_private_direct_over_relay() {
    let config = test_config();
    let manager = PeerManager::new(config);
    let endpoint: SocketAddr = "192.168.2.11:51839".parse().unwrap();

    manager.add_peer(&test_peer("peer1", endpoint)).await;
    manager
        .record_direct_probe_success_with_latency("peer1", endpoint, Some(Duration::from_millis(6)))
        .await;
    manager.record_direct_success("peer1", Some(endpoint)).await;
    manager
        .record_relay_success("peer1", "relay.test:443", false)
        .await;
    let generation = manager.current_network_generation().await;
    assert!(
        manager
            .confirm_relay_peer("peer1", "relay.test:443", generation)
            .await
    );

    {
        let mut conns = manager.connections.write().await;
        let conn = conns.get_mut("peer1").unwrap();
        conn.direct_health.consecutive_failures = 3;
        conn.direct_health.failure_count = 5;
        conn.direct_health.rtt_ewma_ms = Some(650);
        conn.direct_health.jitter_ms = Some(120);
    }

    let selected = manager.select_path_for_data("peer1", true, true).await;
    assert_eq!(selected.path, Some(NetworkPath::Direct));
    assert_eq!(selected.reason_code, REASON_PATH_DIRECT_CONFIRMED);
    assert!(selected.direct_confirmed);
    let direct_score = selected.direct_score.as_ref().unwrap().score;
    let relay_score = selected.relay_score.as_ref().unwrap().score;
    assert!(direct_score < DIRECT_CONFIRMED_MIN_SCORE);
    assert!(direct_score < relay_score);
}

#[tokio::test]
async fn candidate_refresh_retains_low_latency_private_direct() {
    let config = test_config();
    let manager = PeerManager::new(config);
    let endpoint: SocketAddr = "192.168.2.11:51840".parse().unwrap();

    manager.add_peer(&test_peer("peer1", endpoint)).await;
    manager
        .record_direct_probe_success_with_latency("peer1", endpoint, Some(Duration::from_millis(7)))
        .await;
    manager.record_direct_success("peer1", Some(endpoint)).await;
    manager
        .record_relay_success_with_latency(
            "peer1",
            "relay.test:443",
            false,
            Duration::from_millis(31),
        )
        .await;
    assert_eq!(
        manager
            .get_connection("peer1")
            .await
            .unwrap()
            .relay_health
            .rtt_ewma_ms,
        Some(31)
    );
    assert_eq!(manager.current_network_generation().await, 0);

    let generation = manager
        .advance_candidate_refresh_generation("refreshed UDP candidates")
        .await;
    assert_eq!(generation, 1);

    let conn = manager.get_connection("peer1").await.unwrap();
    assert_eq!(conn.state, ConnectionState::Direct);
    assert_eq!(conn.direct_generation, generation);
    assert_eq!(conn.endpoint, Some(endpoint));
    assert_eq!(conn.direct_health.rtt_ewma_ms, Some(7));
    assert!(conn.relay_health.latency_ms.is_none());
    assert!(conn.relay_health.rtt_ewma_ms.is_none());
    assert!(conn.candidate_pairs.iter().any(|pair| {
        pair.local_generation == 0
            && pair.remote_endpoint == endpoint
            && pair.state == CandidatePairState::Degraded
            && pair.last_error_code.as_deref() == Some(REASON_NETWORK_GENERATION_CHANGED)
    }));
    assert!(conn.candidate_pairs.iter().any(|pair| {
        pair.local_generation == generation
            && pair.remote_endpoint == endpoint
            && pair.state == CandidatePairState::Selected
            && pair.rtt_ewma_ms.or(pair.rtt_ms) == Some(7)
    }));
    assert_eq!(
        manager.direct_endpoint_for_send("peer1").await,
        Some(endpoint)
    );
    assert!(
        manager
            .should_use_direct_for_data("peer1", true, true)
            .await
    );
}

#[tokio::test]
async fn candidate_refresh_generation_keeps_confirmed_relay_admission() {
    let manager = PeerManager::new(test_config());
    let endpoint: SocketAddr = "192.168.2.11:51840".parse().unwrap();

    manager.add_peer(&test_peer("peer1", endpoint)).await;
    let generation = manager.current_network_generation().await;
    manager
        .confirm_relay_peer("peer1", "relay.test:443", generation)
        .await;
    assert!(
        manager
            .is_relay_peer_confirmed_for_generation("peer1", generation)
            .await
    );

    let refreshed_generation = manager
        .advance_candidate_refresh_generation("refreshed UDP candidates")
        .await;
    assert_eq!(refreshed_generation, generation + 1);
    assert!(
        manager
            .is_relay_peer_confirmed_for_generation("peer1", refreshed_generation)
            .await,
        "candidate refresh must not revoke an already encrypted-confirmed relay ingress"
    );
    let conn = manager.get_connection("peer1").await.unwrap();
    assert_eq!(conn.relay_confirmed_endpoint.as_deref(), Some("relay.test:443"));
}

#[tokio::test]
async fn candidate_refresh_retains_confirmed_public_direct() {
    let config = test_config();
    let manager = PeerManager::new(config);
    let endpoint: SocketAddr = "8.8.8.8:51841".parse().unwrap();

    manager.add_peer(&test_peer("peer1", endpoint)).await;
    manager
        .record_direct_probe_success_with_latency("peer1", endpoint, Some(Duration::from_millis(7)))
        .await;
    manager.record_direct_success("peer1", Some(endpoint)).await;

    let generation = manager
        .advance_candidate_refresh_generation("refreshed UDP candidates")
        .await;

    let conn = manager.get_connection("peer1").await.unwrap();
    assert_eq!(generation, 1);
    assert_eq!(conn.state, ConnectionState::Direct);
    assert_eq!(conn.direct_generation, generation);
    assert_eq!(conn.endpoint, Some(endpoint));
    assert!(conn.candidate_pairs.iter().any(|pair| {
        pair.local_generation == generation
            && pair.remote_endpoint == endpoint
            && pair.state == CandidatePairState::Selected
            && pair.source == CandidatePairSource::Signaled
    }));
    assert!(
        manager
            .should_use_direct_for_data("peer1", true, true)
            .await
    );
}

#[tokio::test]
async fn candidate_refresh_retains_confirmed_peer_reflexive_direct() {
    let config = test_config();
    let manager = PeerManager::new(config);
    let endpoint: SocketAddr = "8.8.4.4:51842".parse().unwrap();
    let candidates = vec![endpoint.to_string()];
    let sources = HashMap::from([(endpoint.to_string(), "peer_reflexive".to_string())]);

    manager.add_peer(&test_peer("peer1", endpoint)).await;
    manager
        .add_candidates_with_sources("peer1", &candidates, &sources)
        .await;
    manager
        .record_direct_probe_success_with_latency("peer1", endpoint, Some(Duration::from_millis(42)))
        .await;
    manager.record_direct_success("peer1", Some(endpoint)).await;

    let generation = manager
        .advance_candidate_refresh_generation("refreshed UDP candidates")
        .await;

    let conn = manager.get_connection("peer1").await.unwrap();
    assert_eq!(conn.state, ConnectionState::Direct);
    assert_eq!(conn.direct_generation, generation);
    assert_eq!(conn.endpoint, Some(endpoint));
    assert!(conn.candidate_pairs.iter().any(|pair| {
        pair.local_generation == generation
            && pair.remote_endpoint == endpoint
            && pair.state == CandidatePairState::Selected
            && pair.source == CandidatePairSource::PeerReflexive
            && pair.rtt_ewma_ms.or(pair.rtt_ms) == Some(42)
    }));
}

#[tokio::test]
async fn confirmed_public_peer_reflexive_direct_survives_peer_updated() {
    let manager = PeerManager::new(test_config());
    let public: SocketAddr = "8.8.4.4:51843".parse().unwrap();
    let private: SocketAddr = "192.168.0.159:51843".parse().unwrap();
    manager.add_peer(&test_peer("peer1", public)).await;
    manager
        .learn_authenticated_endpoint("peer1", public)
        .await;
    manager
        .record_direct_probe_success_with_latency("peer1", public, Some(Duration::from_millis(9)))
        .await;
    manager.record_direct_success("peer1", Some(public)).await;
    let before = manager.get_connection("peer1").await.unwrap();
    let mut update = test_peer("peer1", private);
    update.last_seen = 1;
    manager.add_peer(&update).await;

    let after = manager.get_connection("peer1").await.unwrap();
    assert_eq!(after.state, ConnectionState::Direct);
    assert_eq!(after.endpoint, Some(public));
    assert_eq!(after.direct_generation, before.direct_generation);
    assert_eq!(after.direct_commit_seq, before.direct_commit_seq);
    assert!(after.direct_events.len() >= before.direct_events.len());
    assert!(after.candidate_pairs.iter().any(|pair| {
        pair.remote_endpoint == public
            && pair.state == CandidatePairState::Selected
            && pair.source == CandidatePairSource::PeerReflexive
    }));
}

#[tokio::test]
async fn stale_hole_punch_transition_cannot_overwrite_direct() {
    let manager = PeerManager::new(test_config());
    let endpoint: SocketAddr = "8.8.8.8:51844".parse().unwrap();
    manager.add_peer(&test_peer("peer1", endpoint)).await;
    let stale_generation = manager.current_network_generation().await;
    let stale_commit_seq = manager.direct_commit_seq_sync("peer1");
    manager
        .record_direct_probe_success_with_latency("peer1", endpoint, Some(Duration::from_millis(7)))
        .await;
    manager.record_direct_success("peer1", Some(endpoint)).await;

    assert!(!manager
        .begin_hole_punch_if_current("peer1", stale_generation, stale_commit_seq)
        .await);
    let conn = manager.get_connection("peer1").await.unwrap();
    assert_eq!(conn.state, ConnectionState::Direct);
    assert_eq!(conn.active_path(), Some(NetworkPath::Direct));
    assert_eq!(conn.endpoint, Some(endpoint));
    assert!(conn.direct_commit_seq > stale_commit_seq.unwrap_or(0));
}

#[tokio::test]
async fn diagnostics_current_pair_prefers_confirmed_public_pair() {
    let manager = PeerManager::new(test_config());
    let public: SocketAddr = "8.8.8.8:51845".parse().unwrap();
    let private: SocketAddr = "192.168.0.159:51845".parse().unwrap();
    manager.add_peer(&test_peer("peer1", public)).await;
    manager
        .learn_authenticated_endpoint("peer1", public)
        .await;
    manager.record_direct_success("peer1", Some(public)).await;
    manager.learn_authenticated_endpoint("peer1", private).await;

    let peer = manager.diagnostics().await.pop().unwrap();
    assert_eq!(peer.state, ConnectionState::Direct);
    assert_eq!(peer.active_path, Some(NetworkPath::Direct));
    assert_eq!(
        peer.current_direct_pair.unwrap().remote_endpoint,
        public.to_string()
    );
}

#[tokio::test]
async fn diagnostics_reports_the_same_validated_pair_used_for_outbound_direct() {
    let manager = PeerManager::new(test_config());
    let public: SocketAddr = "8.8.8.8:51855".parse().unwrap();
    let host: SocketAddr = "192.168.31.20:51820".parse().unwrap();
    manager.add_peer(&test_peer("peer1", public)).await;
    manager
        .add_candidates_with_sources(
            "peer1",
            &[public.to_string(), host.to_string()],
            &HashMap::from([
                (public.to_string(), "stun_observed".to_string()),
                (host.to_string(), "host".to_string()),
            ]),
        )
        .await;
    manager.record_direct_success("peer1", Some(public)).await;
    manager.record_direct_success("peer1", Some(host)).await;

    let peer = manager.diagnostics().await.pop().unwrap();
    assert_eq!(peer.state, ConnectionState::Direct);
    assert_eq!(peer.endpoint, Some(host.to_string()));
    assert_eq!(
        peer.current_direct_pair.unwrap().remote_endpoint,
        host.to_string(),
        "diagnostics must describe the pair that the direct selector currently sends to"
    );
}

#[tokio::test]
async fn diagnostics_does_not_keep_reporting_public_pair_after_host_pair_wins() {
    let manager = PeerManager::new(test_config());
    let public: SocketAddr = "8.8.8.8:51856".parse().unwrap();
    let host: SocketAddr = "192.168.31.20:51821".parse().unwrap();
    manager.add_peer(&test_peer("peer1", public)).await;

    {
        let mut connections = manager.connections.write().await;
        let connection = connections.get_mut("peer1").unwrap();
        connection.state = ConnectionState::Direct;
        connection.endpoint = Some(host);

        let mut public_pair = CandidatePair::new_with_source(
            public,
            0,
            CandidatePairSource::StunObserved,
        );
        public_pair.record_success(Some(Duration::from_millis(100)), true, None);
        let mut host_pair =
            CandidatePair::new_with_source(host, 0, CandidatePairSource::Host);
        host_pair.record_success(Some(Duration::from_millis(2)), true, None);
        connection.candidate_pairs = vec![public_pair, host_pair];
    }

    let peer = manager
        .diagnostics_with_path_selection(true, false, Duration::from_secs(5), None)
        .await
        .pop()
        .unwrap();
    assert_eq!(peer.active_path, Some(NetworkPath::Direct));
    assert_eq!(peer.endpoint, Some(host.to_string()));
    assert_eq!(
        peer.current_direct_pair.unwrap().remote_endpoint,
        host.to_string(),
        "diagnostics must not pin the old public proof after outbound selection moves to Host"
    );
}

#[tokio::test]
async fn diagnostics_direct_state_overrides_stale_relay_selection() {
    let manager = PeerManager::new(test_config());
    let public: SocketAddr = "8.8.8.8:51846".parse().unwrap();
    manager.add_peer(&test_peer("peer1", public)).await;
    manager.record_direct_success("peer1", Some(public)).await;
    {
        let mut conns = manager.connections.write().await;
        conns.get_mut("peer1").unwrap().last_path_selection =
            Some(PathSelection::relay("stale", "stale relay selector snapshot"));
    }

    let peer = manager
        .diagnostics_with_path_selection(true, true, Duration::from_secs(5), None)
        .await
        .pop()
        .unwrap();
    assert_eq!(peer.state, ConnectionState::Direct);
    assert_eq!(peer.active_path, Some(NetworkPath::Direct));
    assert!(matches!(peer.direct_type, DirectPathType::PublicUdp | DirectPathType::PeerReflexive));
    assert_eq!(peer.selected_pair.as_ref().unwrap().remote_endpoint, public.to_string());
    assert_eq!(peer.current_direct_pair.as_ref().unwrap().remote_endpoint, public.to_string());
    assert_eq!(peer.last_path_selection.as_ref().unwrap().path, Some(NetworkPath::Direct));
}

#[tokio::test]
async fn direct_promotion_updates_selection_atomically() {
    let manager = PeerManager::new(test_config());
    let public: SocketAddr = "8.8.8.8:51847".parse().unwrap();
    manager.add_peer(&test_peer("peer1", public)).await;
    manager.record_direct_success("peer1", Some(public)).await;
    let conn = manager.get_connection("peer1").await.unwrap();
    let selection = conn.last_path_selection.expect("promotion selector snapshot");
    assert_eq!(conn.state, ConnectionState::Direct);
    assert!(conn.candidate_pairs.iter().any(|pair| {
        pair.local_generation == conn.direct_generation
            && pair.state == CandidatePairState::Selected
            && pair.selected_at.is_some()
    }));
    assert_eq!(selection.path, Some(NetworkPath::Direct));
    assert!(selection.direct_confirmed);
    assert_eq!(selection.direct_endpoint, Some(public));
}

#[tokio::test]
async fn path_selector_prefers_relay_when_confirmed_direct_quality_is_poor() {
    let config = test_config();
    let manager = PeerManager::new(config);
    let endpoint: SocketAddr = "127.0.0.1:51838".parse().unwrap();

    manager.add_peer(&test_peer("peer1", endpoint)).await;
    manager
        .record_direct_probe_success_with_latency(
            "peer1",
            endpoint,
            Some(Duration::from_millis(700)),
        )
        .await;
    manager.record_direct_success("peer1", Some(endpoint)).await;
    manager
        .record_relay_success("peer1", "relay.test:443", false)
        .await;
    let generation = manager.current_network_generation().await;
    assert!(
        manager
            .confirm_relay_peer("peer1", "relay.test:443", generation)
            .await
    );

    {
        let mut conns = manager.connections.write().await;
        let conn = conns.get_mut("peer1").unwrap();
        conn.direct_health.consecutive_failures = 1;
        conn.direct_health.failure_count = 1;
        conn.direct_health.rtt_ewma_ms = Some(650);
        conn.direct_health.jitter_ms = Some(120);
    }

    let selected = manager.select_path_for_data("peer1", true, true).await;
    assert_eq!(selected.path, Some(NetworkPath::Relay));
    assert_eq!(selected.reason_code, REASON_PATH_DIRECT_DEGRADED);
    assert!(!selected.direct_confirmed);
    assert!(!selected.relay_hedged);
    let direct_score = selected.direct_score.as_ref().unwrap().score;
    let relay_score = selected.relay_score.as_ref().unwrap().score;
    assert!(direct_score < DIRECT_CONFIRMED_MIN_SCORE);
    assert!(direct_score < relay_score);
}

#[tokio::test]
async fn degraded_direct_is_retained_until_relay_peer_path_is_confirmed() {
    let config = test_config();
    let manager = PeerManager::new(config);
    let endpoint: SocketAddr = "127.0.0.1:51842".parse().unwrap();

    manager.add_peer(&test_peer("peer1", endpoint)).await;
    manager
        .record_direct_probe_success_with_latency(
            "peer1",
            endpoint,
            Some(Duration::from_millis(700)),
        )
        .await;
    manager.record_direct_success("peer1", Some(endpoint)).await;
    {
        let mut conns = manager.connections.write().await;
        let conn = conns.get_mut("peer1").unwrap();
        conn.direct_health.consecutive_failures = 2;
        conn.direct_health.failure_count = 2;
        conn.direct_health.rtt_ewma_ms = Some(650);
        conn.direct_health.jitter_ms = Some(120);
    }

    let selected = manager.select_path_for_data("peer1", true, true).await;
    assert_eq!(selected.path, Some(NetworkPath::Direct));
    assert!(selected.direct_confirmed);
    assert!(!selected.relay_hedged);
    assert_eq!(selected.reason_code, REASON_PATH_DIRECT_DEGRADED);

    let diagnostics = manager
        .diagnostics_with_path_selection(true, true, Duration::from_secs(5), None)
        .await;
    assert_eq!(diagnostics[0].active_path, Some(NetworkPath::Direct));
    assert!(!diagnostics[0]
        .current_path_selection
        .as_ref()
        .unwrap()
        .relay_hedged);
}

#[tokio::test]
async fn in_flight_hole_punch_completion_after_direct_promotion_is_refused() {
    // Chained regression for the stale hole-punch transition: a hole-punch
    // task captures (generation, commit_seq) before setup, enters HolePunching
    // through the gate, then Direct is confirmed while the task is in flight.
    // Every later write-back attempt using the pre-promotion observations must
    // be refused: no state demotion, no selection change, no recovery restart.
    let manager = PeerManager::new(test_config());
    let endpoint: SocketAddr = "8.8.8.8:51850".parse().unwrap();
    manager.add_peer(&test_peer("peer1", endpoint)).await;
    let task_generation = manager.current_network_generation().await;
    let task_commit_seq = manager.direct_commit_seq_sync("peer1");
    manager
        .record_direct_probe_success_with_latency("peer1", endpoint, Some(Duration::from_millis(4)))
        .await;
    assert!(manager
        .begin_hole_punch_if_current("peer1", task_generation, task_commit_seq)
        .await);
    let started = manager.get_connection("peer1").await.unwrap();
    assert_eq!(started.state, ConnectionState::HolePunching);

    manager.record_direct_success("peer1", Some(endpoint)).await;
    let promoted = manager.get_connection("peer1").await.unwrap();
    assert_eq!(promoted.state, ConnectionState::Direct);
    assert_eq!(promoted.active_path(), Some(NetworkPath::Direct));
    let promoted_seq = promoted.direct_commit_seq;
    assert!(!manager.recovery_epoch_active("peer1").await);
    drop(promoted);

    assert!(!manager
        .begin_hole_punch_if_current("peer1", task_generation, task_commit_seq)
        .await);
    let conn = manager.get_connection("peer1").await.unwrap();
    assert_eq!(conn.state, ConnectionState::Direct);
    assert_eq!(conn.active_path(), Some(NetworkPath::Direct));
    assert_eq!(conn.endpoint, Some(endpoint));
    assert_eq!(conn.direct_commit_seq, promoted_seq);
    assert!(conn.direct_commit_seq > task_commit_seq.unwrap_or(0));
    assert!(!manager.recovery_epoch_active("peer1").await);
}

#[tokio::test]
async fn relay_connection_metadata_survives_direct_promotion_for_recovery() {
    // The relay path must remain available as a recovery mechanism after
    // Direct is confirmed: the relay server binding and relay health are
    // retained, relay keepalives keep refreshing relay bookkeeping, and none
    // of that may demote the confirmed Direct path or change the endpoint.
    let manager = PeerManager::new(test_config());
    let endpoint: SocketAddr = "8.8.8.8:51851".parse().unwrap();
    manager.add_peer(&test_peer("peer1", endpoint)).await;
    manager
        .record_relay_success("peer1", "tcp://relay.test:18081", true)
        .await;
    let relay = manager.get_connection("peer1").await.unwrap();
    assert_eq!(relay.state, ConnectionState::Relay);
    assert_eq!(relay.relay_server.as_deref(), Some("tcp://relay.test:18081"));

    manager.record_direct_success("peer1", Some(endpoint)).await;
    let promoted = manager.get_connection("peer1").await.unwrap();
    assert_eq!(promoted.state, ConnectionState::Direct);
    assert_eq!(promoted.active_path(), Some(NetworkPath::Direct));
    assert_eq!(promoted.endpoint, Some(endpoint));
    assert_eq!(
        promoted.relay_server.as_deref(),
        Some("tcp://relay.test:18081"),
        "relay binding must survive Direct promotion"
    );

    manager
        .record_relay_success_with_latency(
            "peer1",
            "tcp://relay.test:18081",
            false,
            Duration::from_millis(3),
        )
        .await;
    let keepalive = manager.get_connection("peer1").await.unwrap();
    assert_eq!(keepalive.state, ConnectionState::Direct);
    assert_eq!(keepalive.active_path(), Some(NetworkPath::Direct));
    assert_eq!(keepalive.endpoint, Some(endpoint));
    assert_eq!(
        keepalive.relay_server.as_deref(),
        Some("tcp://relay.test:18081")
    );
    assert!(
        keepalive
            .relay_health
            .rtt_ewma_ms
            .or(keepalive.relay_health.latency_ms)
            .is_some(),
        "relay health must keep refreshing while Direct is confirmed"
    );

    let diagnostics = manager
        .diagnostics_with_path_selection(true, true, Duration::from_secs(5), None)
        .await;
    assert_eq!(diagnostics[0].state, ConnectionState::Direct);
    assert_eq!(diagnostics[0].active_path, Some(NetworkPath::Direct));
}

#[tokio::test]
async fn untimed_relay_ingress_does_not_refresh_timed_validation_freshness() {
    let manager = PeerManager::new(test_config());
    let endpoint: SocketAddr = "198.51.100.71:51831".parse().unwrap();
    let relay_endpoint = "tls://relay.test:443";
    manager.add_peer(&test_peer("peer1", endpoint)).await;

    manager
        .record_relay_observation("peer1", relay_endpoint)
        .await;

    let connection = manager.get_connection("peer1").await.unwrap();
    assert!(connection.relay_health.last_observation_at.is_some());
    assert_eq!(connection.relay_health.observation_count, 1);
    assert!(connection.relay_health.last_success_at.is_none());
    assert!(connection.relay_health.latency_ms.is_none());
    assert!(connection.relay_health.rtt_ewma_ms.is_none());
    assert!(manager
        .relay_validation_targets(Duration::from_secs(15))
        .await
        .iter()
        .any(|(peer_id, _)| peer_id == "peer1"));
}

#[tokio::test]
async fn relay_probe_ack_records_monotonic_rtt_and_replacement_clears_it() {
    let manager = PeerManager::new(test_config());
    let endpoint: SocketAddr = "198.51.100.72:51831".parse().unwrap();
    let relay_endpoint = "tls://relay.test:443";
    manager.add_peer(&test_peer("peer1", endpoint)).await;
    let generation = manager.current_network_generation().await;
    manager
        .mark_relay_transport_ready_with_transport("peer1", relay_endpoint, generation, Some(41))
        .await;
    assert!(manager.register_relay_probe_expectation_for_transport(
        "peer1",
        generation,
        7,
        0xabc,
        relay_endpoint,
        41,
    ));
    tokio::time::sleep(Duration::from_millis(15)).await;
    assert!(
        manager
            .consume_relay_probe_ack_with_transport(
                "peer1",
                crate::relay_probe::RelayProbeToken {
                    kind: crate::relay_probe::RelayProbeKind::Ack,
                    generation,
                    request_id: 7,
                    owner_token: 0xabc,
                },
                relay_endpoint,
                Some(41),
            )
            .await
    );

    let confirmed = manager.get_connection("peer1").await.unwrap();
    assert!(confirmed.relay_health.last_success_at.is_some());
    assert!(confirmed
        .relay_health
        .latency_ms
        .is_some_and(|rtt| rtt >= 10));
    assert_eq!(
        confirmed.relay_health.rtt_ewma_ms,
        confirmed.relay_health.latency_ms
    );

    manager
        .mark_relay_transport_ready_with_transport("peer1", relay_endpoint, generation, Some(42))
        .await;
    let replaced = manager.get_connection("peer1").await.unwrap();
    assert!(replaced.relay_health.last_success_at.is_none());
    assert!(replaced.relay_health.latency_ms.is_none());
    assert!(replaced.relay_health.rtt_ewma_ms.is_none());
    assert!(replaced.relay_health.jitter_ms.is_none());
}

#[tokio::test]
async fn relay_probe_rtt_starts_at_writer_boundary_not_local_enqueue_time() {
    let manager = PeerManager::new(test_config());
    let endpoint: SocketAddr = "198.51.100.76:51831".parse().unwrap();
    let relay_endpoint = "tls://relay.test:443";
    manager.add_peer(&test_peer("peer1", endpoint)).await;
    let generation = manager.current_network_generation().await;
    let peer_session_generation = manager.peer_session_generation_sync("peer1").unwrap();
    manager
        .mark_relay_transport_ready_with_transport("peer1", relay_endpoint, generation, Some(81))
        .await;

    let queued_at = Instant::now()
        .checked_sub(Duration::from_secs(5))
        .unwrap();
    let write_boundary = Instant::now();
    assert!(manager.register_relay_probe_expectation_at_write_boundary(
        "peer1",
        generation,
        11,
        0x789,
        relay_endpoint,
        81,
        peer_session_generation,
        write_boundary,
    ));
    tokio::time::sleep(Duration::from_millis(12)).await;
    assert!(
        manager
            .consume_relay_probe_ack_with_transport(
                "peer1",
                crate::relay_probe::RelayProbeToken {
                    kind: crate::relay_probe::RelayProbeKind::Ack,
                    generation,
                    request_id: 11,
                    owner_token: 0x789,
                },
                relay_endpoint,
                Some(81),
            )
            .await
    );
    let latency_ms = manager
        .get_connection("peer1")
        .await
        .unwrap()
        .relay_health
        .latency_ms
        .unwrap();
    assert!(latency_ms >= 8, "writer-boundary RTT should include the ACK wait");
    assert!(
        latency_ms < 500,
        "the five-second local queue wait must not enter relay RTT"
    );
    assert!(write_boundary > queued_at);
}

#[tokio::test]
async fn periodic_relay_sample_cannot_overwrite_forced_confirmation_expectation() {
    let manager = PeerManager::new(test_config());
    let endpoint: SocketAddr = "198.51.100.77:51831".parse().unwrap();
    let relay_endpoint = "tls://relay.test:443";
    manager.add_peer(&test_peer("peer1", endpoint)).await;
    let generation = manager.current_network_generation().await;
    let peer_session_generation = manager.peer_session_generation_sync("peer1").unwrap();
    manager
        .mark_relay_transport_ready_with_transport("peer1", relay_endpoint, generation, Some(82))
        .await;
    assert!(
        manager
            .confirm_relay_peer_with_transport("peer1", relay_endpoint, generation, Some(82))
            .await
    );
    assert!(manager.register_relay_probe_expectation_at_write_boundary(
        "peer1",
        generation,
        12,
        0xaaa,
        relay_endpoint,
        82,
        peer_session_generation,
        Instant::now(),
    ));
    let permit = manager
        .relay_validation_write_permit_for_transport(
            "peer1",
            generation,
            relay_endpoint,
            82,
        )
        .await
        .unwrap();
    assert!(!manager.register_relay_validation_expectation_at_write_boundary(
        "peer1",
        generation,
        13,
        0xbbb,
        relay_endpoint,
        82,
        permit,
        Instant::now(),
    ));
    let installed = manager.relay_probe_expectations.lock().unwrap();
    let installed = installed.get("peer1").unwrap();
    assert_eq!(installed.request_id, 12);
    assert_eq!(
        installed.purpose,
        crate::relay_probe::RelayProbePurpose::Confirmation
    );
}

#[tokio::test]
async fn relay_probe_ack_rejects_closed_peer_and_retired_peer_lifecycle() {
    let manager = PeerManager::new(test_config());
    let endpoint: SocketAddr = "198.51.100.73:51831".parse().unwrap();
    let relay_endpoint = "tls://relay.test:443";
    manager.add_peer(&test_peer("peer1", endpoint)).await;
    let old_lifecycle = manager.peer_session_generation_sync("peer1").unwrap();
    let generation = manager.current_network_generation().await;
    manager
        .mark_relay_transport_ready_with_transport("peer1", relay_endpoint, generation, Some(51))
        .await;
    assert!(manager.register_relay_probe_expectation_for_transport(
        "peer1",
        generation,
        8,
        0xdef,
        relay_endpoint,
        51,
    ));
    manager.update_state("peer1", ConnectionState::Closed).await;
    assert!(
        !manager
            .consume_relay_probe_ack_with_transport(
                "peer1",
                crate::relay_probe::RelayProbeToken {
                    kind: crate::relay_probe::RelayProbeKind::Ack,
                    generation,
                    request_id: 8,
                    owner_token: 0xdef,
                },
                relay_endpoint,
                Some(51),
            )
            .await
    );

    manager.remove_peer("peer1").await;
    manager.add_peer(&test_peer("peer1", endpoint)).await;
    manager
        .mark_relay_transport_ready_with_transport("peer1", relay_endpoint, generation, Some(51))
        .await;
    assert_ne!(
        manager.peer_session_generation_sync("peer1"),
        Some(old_lifecycle)
    );
    manager.relay_probe_expectations.lock().unwrap().insert(
        "peer1".to_string(),
        crate::relay_probe::RelayProbeExpectation {
            purpose: crate::relay_probe::RelayProbePurpose::Confirmation,
            peer_session_generation: old_lifecycle,
            generation,
            request_id: 9,
            owner_token: 0x123,
            relay_endpoint: relay_endpoint.to_string(),
            relay_connection_id: Some(51),
            sent_at: Instant::now(),
            rtt_sample_eligible: true,
        },
    );
    assert!(
        !manager
            .consume_relay_probe_ack_with_transport(
                "peer1",
                crate::relay_probe::RelayProbeToken {
                    kind: crate::relay_probe::RelayProbeKind::Ack,
                    generation,
                    request_id: 9,
                    owner_token: 0x123,
                },
                relay_endpoint,
                Some(51),
            )
            .await
    );
    let current = manager.get_connection("peer1").await.unwrap();
    assert!(current.relay_confirmed_at.is_none());
    assert!(current.relay_health.latency_ms.is_none());
}

#[tokio::test]
async fn relay_business_marker_rejects_retired_connection_incarnation() {
    let manager = PeerManager::new(test_config());
    let endpoint: SocketAddr = "198.51.100.74:51831".parse().unwrap();
    let relay_endpoint = "tls://relay.test:443";
    manager.add_peer(&test_peer("peer1", endpoint)).await;
    let generation = manager.current_network_generation().await;
    manager
        .mark_relay_transport_ready_with_transport("peer1", relay_endpoint, generation, Some(62))
        .await;
    assert!(
        manager
            .confirm_relay_peer_with_transport("peer1", relay_endpoint, generation, Some(62),)
            .await
    );

    assert!(
        !manager
            .mark_relay_first_business_sent_for_generation_with_transport(
                "peer1",
                generation,
                relay_endpoint,
                Some(61),
            )
            .await
    );
    assert!(
        manager
            .mark_relay_first_business_sent_for_generation_with_transport(
                "peer1",
                generation,
                relay_endpoint,
                Some(62),
            )
            .await
    );
}

#[tokio::test]
async fn path_commit_ack_is_bound_to_relay_connection_incarnation() {
    let manager = PeerManager::new(test_config());
    let endpoint: SocketAddr = "198.51.100.75:51831".parse().unwrap();
    let relay_endpoint = "tls://relay.test:443";
    manager.add_peer(&test_peer("peer1", endpoint)).await;
    let generation = manager.current_network_generation().await;
    manager
        .mark_relay_transport_ready_with_transport("peer1", relay_endpoint, generation, Some(71))
        .await;
    assert!(
        manager
            .confirm_relay_peer_with_transport("peer1", relay_endpoint, generation, Some(71),)
            .await
    );
    let peer_session_generation = manager.peer_session_generation_sync("peer1").unwrap();
    assert!(manager.register_path_commit_expectation_at_write_boundary(
        "peer1",
        generation,
        10,
        0x456,
        relay_endpoint,
        71,
        peer_session_generation,
        Instant::now(),
    ));
    let token = crate::path_commit::PathCommitToken {
        kind: crate::path_commit::PathCommitKind::Ack,
        generation,
        request_id: 10,
        owner_token: 0x456,
    };

    assert!(
        !manager
            .consume_path_commit_ack_with_transport("peer1", token, relay_endpoint, Some(72),)
            .await
    );
    assert!(
        manager
            .consume_path_commit_ack_with_transport("peer1", token, relay_endpoint, Some(71),)
            .await
    );
    assert_eq!(
        manager
            .get_connection("peer1")
            .await
            .unwrap()
            .relay_first
            .business_pathcommit_generation,
        Some(generation)
    );
}
