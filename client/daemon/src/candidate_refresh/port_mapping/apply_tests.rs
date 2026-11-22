#[test]
fn gateway_grant_promotes_an_existing_observer_candidate() {
    let endpoint = "203.0.113.9:48321";
    let mut candidates = vec!["192.0.2.1:12345".into(), endpoint.into()];
    let mut sources = HashMap::from([(endpoint.into(), "stun_observed".into())]);
    for _ in 0..2 {
        prefer_gateway_candidate(endpoint, "pcp", &mut candidates, &mut sources);
        assert_eq!(candidates, [endpoint, "192.0.2.1:12345"]);
        assert_eq!(sources[endpoint], "pcp");
    }
}

#[tokio::test]
async fn pcp_requires_a_positive_matching_grant_and_reuses_nonce_for_renewal() {
    use tokio::net::UdpSocket;
    let gateway = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let other = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let gateway_addr = gateway.local_addr().unwrap();
    let endpoint: SocketAddr = "203.0.113.9:48321".parse().unwrap();
    let local: SocketAddr = "127.0.0.1:32761".parse().unwrap();
    let identity = crate::gateway_mapping::GatewayMappingIdentity {
        bind_endpoint: local,
        local_endpoint: local,
        gateway: Some(Ipv4Addr::LOCALHOST),
        network_generation: 1,
        transport_instance: 2,
        publication_owner: 3,
    };
    let mut runtime = GatewayMappingRuntime::default();
    runtime.bind_identity(identity);
    let (nonce, suggestion) = runtime.pcp_request().unwrap();
    assert!(suggestion.is_none());
    for case in [
        "wrong_nonce",
        "zero_lifetime",
        "wrong_internal_port",
        "wrong_protocol",
        "grant",
        "renew",
    ] {
        let request = runtime.pcp_request().unwrap();
        let serve = async {
            let mut bytes = [0; 96];
            let (n, client) = gateway.recv_from(&mut bytes).await.unwrap();
            assert_eq!(n, 60);
            assert_eq!(&bytes[24..36], &nonce);
            if case == "renew" {
                assert_eq!(&bytes[42..44], &endpoint.port().to_be_bytes());
                assert_eq!(
                    &bytes[44..60],
                    &ipv4_mapped_octets(Ipv4Addr::new(203, 0, 113, 9))
                );
            }
            bytes[1] = 0x81;
            bytes[4..8].copy_from_slice(&8u32.to_be_bytes());
            bytes[42..44].copy_from_slice(&endpoint.port().to_be_bytes());
            bytes[44..60].copy_from_slice(&ipv4_mapped_octets(Ipv4Addr::new(203, 0, 113, 9)));
            // An unsolicited reply from the right IP on another UDP port cannot grant the lease.
            other.send_to(&bytes[..n], client).await.unwrap();
            match case {
                "wrong_nonce" => bytes[24] ^= 1,
                "zero_lifetime" => bytes[4..8].fill(0),
                "wrong_internal_port" => bytes[41] ^= 1,
                "wrong_protocol" => bytes[36] = 6,
                "grant" | "renew" => assert_eq!(bytes[36], 17),
                _ => unreachable!(),
            }
            gateway.send_to(&bytes[..n], client).await.unwrap();
        };
        let ((), result) = tokio::join!(
            serve,
            request_pcp_udp_mapping(Ipv4Addr::LOCALHOST, local.port(), gateway_addr, request)
        );
        if matches!(case, "grant" | "renew") {
            let (granted, lifetime) = result.unwrap();
            assert_eq!((granted, lifetime), (endpoint, 8));
            assert!(runtime.record_success(
                identity,
                granted.to_string(),
                "pcp",
                Duration::from_secs(lifetime.into())
            ));
            let snapshot = runtime.snapshot(true, 3600, Default::default());
            assert_eq!(snapshot.lease_seconds, 8);
            assert!((3000..=4000).contains(&snapshot.renewal_remaining_ms.unwrap()));
        } else {
            assert!(result.is_err(), "{case} created a mapping");
        }
    }
    runtime.bind_identity(crate::gateway_mapping::GatewayMappingIdentity {
        network_generation: 2,
        ..identity
    });
    let (new_nonce, old_endpoint) = runtime.pcp_request().unwrap();
    assert_ne!(new_nonce, nonce);
    assert!(old_endpoint.is_none());
}

#[tokio::test(start_paused = true)]
async fn gateway_cache_locks_share_one_deadline_and_timeout_cannot_commit_a_result() {
    let identity = crate::gateway_mapping::GatewayMappingIdentity {
        bind_endpoint: "0.0.0.0:51820".parse().unwrap(),
        local_endpoint: "192.168.1.7:51820".parse().unwrap(),
        gateway: Some("192.168.1.1".parse().unwrap()),
        network_generation: 4,
        transport_instance: 2,
        publication_owner: 3,
    };
    let runtime = RwLock::new(GatewayMappingRuntime::default());
    let diagnostics = RwLock::new(GatewayMappingDiagnostics::default());
    let mut held_runtime = runtime.write().await;
    held_runtime.bind_identity(identity);
    assert!(held_runtime.record_success(
        identity,
        "203.0.113.8:51820".into(),
        "upnp",
        Duration::from_secs(120),
    ));
    let held_diagnostics = diagnostics.write().await;
    let mut pending = Box::pin(async {
        let Some(mut commit) =
            lock_gateway_mapping_commit(&runtime, &diagnostics, "discovery_result").await
        else {
            return false;
        };
        commit.diagnostics.candidate_endpoint = Some("203.0.113.9:51820".into());
        commit
            .runtime
            .record_failure(identity, Duration::from_secs(60))
    });
    assert!(futures_util::poll!(&mut pending).is_pending());
    tokio::time::advance(Duration::from_millis(80)).await;
    drop(held_runtime);
    assert!(futures_util::poll!(&mut pending).is_pending());
    assert!(
        runtime.try_write().is_err(),
        "runtime is held while diagnostics waits"
    );

    // The second lock gets only the remainder of the original 100ms budget,
    // not another full timeout. Its permanent holder must not pin the cache.
    tokio::time::advance(Duration::from_millis(20)).await;
    assert!(!pending.await);
    let current = runtime
        .try_write()
        .expect("timeout releases the first guard");
    assert_eq!(
        current.candidate_endpoint.as_deref(),
        Some("203.0.113.8:51820")
    );
    assert!(
        current.retry_at.is_none(),
        "timed-out result cannot install backoff"
    );
    assert!(held_diagnostics.candidate_endpoint.is_none());
}

#[tokio::test(start_paused = true)]
async fn cancellation_while_waiting_for_gateway_diagnostics_releases_the_cache() {
    let runtime = RwLock::new(GatewayMappingRuntime::default());
    let diagnostics = RwLock::new(GatewayMappingDiagnostics::default());
    let held_diagnostics = diagnostics.write().await;
    let mut pending = Box::pin(lock_gateway_mapping_commit(
        &runtime,
        &diagnostics,
        "cache_lookup",
    ));
    assert!(futures_util::poll!(&mut pending).is_pending());
    assert!(runtime.try_write().is_err());
    drop(pending);
    assert!(
        runtime.try_write().is_ok(),
        "cancelled commit releases the cache guard"
    );
    drop(held_diagnostics);
    assert!(
        lock_gateway_mapping_commit(&runtime, &diagnostics, "cache_lookup")
            .await
            .is_some()
    );
}
