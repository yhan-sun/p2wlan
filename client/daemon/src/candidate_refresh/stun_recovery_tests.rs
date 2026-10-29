#[test]
fn empty_defaults_are_recoverable_but_explicit_stun_disable_stays_disabled() {
    assert!(stun_discovery_configured(&[], &[]));
    for disabled in [
        "off", "none", "false", "clear", "unset", "disable", "disabled", " ",
    ] {
        assert!(!stun_discovery_configured(&[disabled.into()], &[]));
        assert!(!stun_discovery_configured(
            &[disabled.into()],
            &["none".into()]
        ));
        assert!(stun_discovery_configured(
            &[disabled.into()],
            &["localhost:3478".into()]
        ));
    }
}

#[tokio::test]
async fn recovered_stun_commit_rechecks_owner_and_generation_after_writer_wait() {
    for replace_owner in [false, true] {
        let daemon = Daemon::new(Config::generate_default("https://ctrl.test", "net1").unwrap());
        let udp = UdpTransport::bind("127.0.0.1:0".parse().unwrap(), daemon.peers.clone())
            .await
            .unwrap();
        let lease = daemon.udp_transport_publication.publish(udp).await;
        let generation = daemon.peers.current_network_generation_sync();
        let original = vec!["192.0.2.1:3478".parse().unwrap()];
        let stale = vec!["198.51.100.1:3478".parse().unwrap()];
        let mut writer = daemon.runtime_stun_servers.write().await;
        *writer = original.clone();
        let mut commit = Box::pin(commit_recovered_stun_sources(
            &daemon.runtime_stun_servers,
            &daemon.udp_transport_publication,
            &daemon.peers,
            lease.owner(),
            generation,
            &stale,
        ));
        assert!(futures_util::poll!(commit.as_mut()).is_pending());
        if replace_owner {
            let replacement =
                UdpTransport::bind("127.0.0.1:0".parse().unwrap(), daemon.peers.clone())
                    .await
                    .unwrap();
            daemon.udp_transport_publication.publish(replacement).await;
        } else {
            daemon
                .peers
                .advance_network_generation("DNS recovery handover")
                .await;
        }
        drop(writer);
        assert_eq!(
            commit.await,
            Err(if replace_owner {
                "udp_transport_replaced"
            } else {
                "network_generation_changed"
            })
        );
        assert_eq!(*daemon.runtime_stun_servers.read().await, original);
        daemon.udp_transport_publication.clear_current().await;
    }
}

#[tokio::test(start_paused = true)]
async fn recovered_stun_commit_writer_wait_is_bounded() {
    let daemon = Daemon::new(Config::generate_default("https://ctrl.test", "net1").unwrap());
    let udp = UdpTransport::bind("127.0.0.1:0".parse().unwrap(), daemon.peers.clone())
        .await
        .unwrap();
    let lease = daemon.udp_transport_publication.publish(udp).await;
    let writer = daemon.runtime_stun_servers.write().await;
    let resolved = vec!["192.0.2.1:3478".parse().unwrap()];
    let mut commit = Box::pin(commit_recovered_stun_sources(
        &daemon.runtime_stun_servers,
        &daemon.udp_transport_publication,
        &daemon.peers,
        lease.owner(),
        daemon.peers.current_network_generation_sync(),
        &resolved,
    ));
    assert!(futures_util::poll!(commit.as_mut()).is_pending());
    tokio::time::advance(Duration::from_millis(101)).await;
    assert_eq!(commit.await, Err("stun_sources_contended"));
    drop(writer);
    assert!(daemon.runtime_stun_servers.read().await.is_empty());
    daemon.udp_transport_publication.clear_current().await;
}
