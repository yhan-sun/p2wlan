impl Daemon {
    async fn spawn_dataplane_tasks(
        &self,
        tun: Option<TunDevice>,
        network_inbound_rx: mpsc::Receiver<ReceivedEncryptedPacket>,
    ) {
        if let Some(tun) = tun {
            let peers = self.peers.clone();
            let transport = self.transport.clone();
            let (dataplane, outbound_rx, inbound_tx) = DataPlane::new_bidirectional(tun, peers);
            let mut dataplane = dataplane
                .with_acl(self.acl.clone(), self.config.node.node_id.clone())
                .with_overlay_cidr(&self.config.network.cidr);

            let outbound_transport = transport.clone();
            self.task_manager
                .spawn_result("wireguard-outbound", true, async move {
                    outbound_transport.run_outbound(outbound_rx).await
                })
                .await;

            let inbound_transport = transport.clone();
            let inbound_peers = self.peers.clone();
            let inbound_udp_updates = self.udp_transport_publication.subscribe();
            self.task_manager
                .spawn_result("wireguard-inbound", true, async move {
                    // UDP direct binds asynchronously and can later be
                    // replaced after a socket failure.  Keep a live watch
                    // receiver instead of taking one startup-time snapshot;
                    // WireGuard inbound resolves it for every packet.
                    inbound_transport
                        .run_inbound_with_peers_live_udp(
                            network_inbound_rx,
                            inbound_tx,
                            Some(inbound_peers),
                            inbound_udp_updates,
                        )
                        .await
                })
                .await;

            self.task_manager
                .spawn_result("dataplane", true, async move { dataplane.run().await })
                .await;
        } else if self.config.network.validate_overlay {
            // Independent validation harness: drive a real encrypted overlay
            // payload through the production dataplane + WireGuard + direct
            // UDP pipeline over an in-memory mock TUN.  This is off by
            // default and never created by a production daemon; it requires
            // no privileges and exercises the exact same outbound/inbound
            // paths as a system TUN would.
            let peers = self.peers.clone();
            let transport = self.transport.clone();
            let local_vip = self.config.network.virtual_ip.clone();
            let interface_name = self.config.network.interface.clone();
            let mtu = self.config.network.mtu;
            let (tun, controller) = p2pnet_tun::mock::MockTunDevice::new_pair(&interface_name, mtu, &local_vip);
            let (dataplane, outbound_rx, inbound_tx) =
                DataPlane::new_bidirectional(tun, peers.clone());
            let mut dataplane = dataplane
                .with_acl(self.acl.clone(), self.config.node.node_id.clone())
                .with_overlay_cidr(&self.config.network.cidr);

            let outbound_transport = transport.clone();
            self.task_manager
                .spawn_result("wireguard-outbound", true, async move {
                    outbound_transport.run_outbound(outbound_rx).await
                })
                .await;

            let inbound_transport = transport.clone();
            let inbound_peers = self.peers.clone();
            let inbound_udp_updates = self.udp_transport_publication.subscribe();
            self.task_manager
                .spawn_result("wireguard-inbound", true, async move {
                    inbound_transport
                        .run_inbound_with_peers_live_udp(
                            network_inbound_rx,
                            inbound_tx,
                            Some(inbound_peers),
                            inbound_udp_updates,
                        )
                        .await
                })
                .await;

            self.task_manager
                .spawn_result("dataplane", true, async move { dataplane.run().await })
                .await;

            let overlay_peers = self.peers.clone();
            let overlay_local_vip = local_vip.clone();
            let overlay_node_id = self.config.node.node_id.clone();
            let shutdown_rx = self.shutdown_rx.clone();
            self.task_manager
                .spawn("overlay-validate", false, async move {
                    run_overlay_validate_loop(
                        controller,
                        overlay_peers,
                        overlay_local_vip,
                        overlay_node_id,
                        shutdown_rx,
                    )
                    .await
                })
                .await;
            info!("validate_overlay: mock-TUN overlay dataplane is up at {local_vip}");
        } else {
            let (inbound_tx, inbound_rx) = mpsc::channel(1024);
            let inbound_transport = self.transport.clone();
            let inbound_peers = self.peers.clone();
            let inbound_udp_updates = self.udp_transport_publication.subscribe();
            self.task_manager
                .spawn_result("wireguard-inbound", true, async move {
                    inbound_transport
                        .run_inbound_with_peers_live_udp(
                            network_inbound_rx,
                            inbound_tx,
                            Some(inbound_peers),
                            inbound_udp_updates,
                        )
                        .await
                })
                .await;
            self.task_manager
                .spawn(
                    "tun-disabled-inbound-log",
                    false,
                    log_inbound_packets_without_tun(inbound_rx),
                )
                .await;
        }

    }
}
