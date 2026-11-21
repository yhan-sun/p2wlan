// Unit boundary controls: the existing fixture installs its authoritative
// Direct/DPL proof explicitly. These are not native REQUEST/ACK or application
// performance evidence. The sockets and competing pool affinity are real.
struct CommittedBudgetAffinityFixture {
    peers: Arc<PeerManager>,
    udp: UdpTransport,
    _remote: UdpSocket,
    identity: crate::dplpmtud::DplpmtudPathIdentity,
    _lease: crate::dplpmtud::DplpmtudWorkerLease,
}

impl CommittedBudgetAffinityFixture {
    async fn new() -> Self {
        let peers = Arc::new(PeerManager::new(
            Config::generate_default("https://ctrl.test", "net1").unwrap(),
        ));
        let remote = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let remote_endpoint = remote.local_addr().unwrap();
        peers
            .add_peer(&business_budget_peer(
                "peer-b",
                "10.20.0.2",
                remote_endpoint,
            ))
            .await;
        let udp = UdpTransport::bind("127.0.0.1:0".parse().unwrap(), peers.clone())
            .await
            .unwrap()
            .with_socket_pool(2)
            .await
            .unwrap()
            .with_dplpmtud_local_virtual_ip("10.20.0.1".parse().unwrap());
        udp.set_socket_pool_active(true);
        udp.set_inbound_publication_owner(772);
        let (identity, lease) = business_budget_install_confirmed_direct(
            &peers,
            &udp,
            "peer-b",
            remote_endpoint,
            773,
            774,
        )
        .await;
        assert!(udp.direct_business_budget_ready_for_peer("peer-b"));
        Self {
            peers,
            udp,
            _remote: remote,
            identity,
            _lease: lease,
        }
    }

    async fn observe_other_probe_socket(&self) {
        self.udp
            .remember_peer_socket("peer-b", 1, crate::udp::SocketEvidence::Fresh)
            .await;
        let (index, socket) = self.udp.socket_for_peer(Some("peer-b")).await.unwrap();
        assert_eq!(
            index, 1,
            "the competing probe mapping must actually be selected"
        );
        assert_ne!(socket.local_addr().unwrap(), self.identity.local_endpoint);
        assert_eq!(
            self.peers
                .direct_commit_pair_snapshot_sync("peer-b")
                .unwrap()
                .local_endpoint,
            Some(self.identity.local_endpoint),
            "a probe observation cannot change the authoritative Direct tuple",
        );
    }
}

impl Drop for CommittedBudgetAffinityFixture {
    fn drop(&mut self) {
        self.udp.dplpmtud_runtime().close(
            "committed_affinity_fixture_closed",
            tokio::time::Instant::now(),
        );
    }
}

#[tokio::test]
async fn direct_budget_reconcile_preserves_committed_socket_after_probe_affinity_changes() {
    let fixture = CommittedBudgetAffinityFixture::new().await;
    fixture.observe_other_probe_socket().await;
    fixture.udp.reconcile_dplpmtud_paths().await;
    let snapshot = fixture
        .udp
        .dplpmtud_runtime()
        .snapshot_for_peer("peer-b")
        .unwrap();
    assert!(
        snapshot.base_confirmed && snapshot.live_worker,
        "a different probe socket revoked the unchanged committed budget: {snapshot:?}",
    );
    assert!(fixture.udp.direct_business_budget_ready_for_peer("peer-b"));
    assert_eq!(
        fixture.udp.socket_for_peer(Some("peer-b")).await.unwrap().0,
        1
    );
}

#[tokio::test]
async fn direct_business_prepare_uses_committed_socket_after_probe_affinity_changes() {
    let fixture = CommittedBudgetAffinityFixture::new().await;
    fixture.observe_other_probe_socket().await;
    let prepared = fixture
        .udp
        .prepare_direct_business_send("peer-b", fixture.identity.authenticated_remote_endpoint)
        .await;
    let crate::udp::DirectBusinessBudgetGate::Ready(prepared) = prepared else {
        panic!("a different probe socket hid the unchanged confirmed business path");
    };
    assert_eq!(prepared.socket_index, fixture.identity.socket.socket_index);
    assert_eq!(prepared.token.path_identity, fixture.identity);
    assert_eq!(
        prepared.socket.local_addr().unwrap(),
        fixture.identity.local_endpoint
    );
    assert_eq!(
        fixture.udp.socket_for_peer(Some("peer-b")).await.unwrap().0,
        1
    );
}

#[tokio::test]
async fn committed_direct_socket_resolution_is_exact_for_ipv6_and_generation() {
    let fixture = CommittedBudgetAffinityFixture::new().await;
    fixture.observe_other_probe_socket().await;
    let ipv6 = Arc::new(
        p2pnet_netbind::bind_udp("[::1]:0".parse().unwrap(), None)
            .await
            .unwrap(),
    );
    let local = ipv6.local_addr().unwrap();
    let udp = fixture.udp.clone().with_ipv6_socket(ipv6.clone());
    let generation = fixture.peers.current_network_generation_sync();
    let (index, resolved, _) = udp
        .resolve_committed_direct_socket_with_lease("peer-b", local, generation)
        .await
        .unwrap();
    assert_eq!(index, crate::udp::IPV6_SOCKET_INDEX);
    assert!(Arc::ptr_eq(&resolved, &ipv6));
    assert!(udp
        .resolve_committed_direct_socket_with_lease("peer-b", local, generation + 1)
        .await
        .is_none());
    let unregistered = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    assert!(udp
        .resolve_committed_direct_socket_with_lease(
            "peer-b",
            unregistered.local_addr().unwrap(),
            generation,
        )
        .await
        .is_none());
    assert_eq!(udp.socket_for_peer(Some("peer-b")).await.unwrap().0, 1);
}
