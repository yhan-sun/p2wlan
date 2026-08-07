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
