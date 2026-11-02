impl Daemon {
    async fn spawn_dataplane_tasks(
        &self,
        tun: Option<crate::os_request_capture::SystemTun>,
        network_inbound_rx: crate::dataplane_resources::EncryptedRxReceiver,
        capture_setup: Option<crate::os_request_capture::CaptureSetup>,
        tun_worker_ready: Option<tokio::sync::oneshot::Sender<()>>,
    ) -> Result<()> {
        let local_sources = if self.config.network.network_id.starts_with("room-") {
            tokio::task::spawn_blocking(|| {
                p2pnet_nat::gather_local_addresses()
                    .into_iter()
                    .filter_map(|ip| match ip {
                        std::net::IpAddr::V4(ip) => Some(ip),
                        _ => None,
                    })
                    .collect::<Vec<_>>()
            })
            .await
            .unwrap_or_default()
        } else {
            Vec::new()
        };
        if let Some(mut tun) = tun {
            let room_authorization = self.control.room_authorization().await;
            if let Some(setup) = &capture_setup {
                setup.session.bind_original_current_owners(
                    &self.transport,
                    &self.udp_transport,
                    &self.relay_transport,
                    &room_authorization,
                );
            }
            let kernel_runtime = capture_setup
                .as_ref()
                .map(|setup| setup.session.inbound_runtime(&room_authorization));
            if let Some(setup) = capture_setup {
                tun = tun.with_capture(setup.session);
                self.task_manager
                    .spawn_result("os-request-capture", false, async move {
                        setup.channel.run().await.map_err(|error| {
                            DaemonError::Network(format!("OS request capture retired: {error}"))
                        })
                    })
                    .await;
            }
            let track_registered_reads = tun.tracks_registered_reads();
            let peers = self.peers.clone();
            let transport = self.transport.clone();
            let (dataplane, outbound_rx, inbound_tx) = DataPlane::new_bidirectional_for_daemon(
                tun,
                peers,
                track_registered_reads,
                self.transport.resource_capture().cloned(),
            );
            let mut dataplane = dataplane
                .with_acl(self.acl.clone(), self.config.node.node_id.clone())
                .with_overlay_cidr(&self.config.network.cidr)
                .with_room_authorization(room_authorization)
                .with_local_source_addresses(local_sources);

            let outbound_transport = transport.clone();
            self.task_manager
                .spawn_result("wireguard-outbound", true, async move {
                    outbound_transport.run_outbound_inner(outbound_rx).await
                })
                .await;

            let inbound_transport = match kernel_runtime {
                Some(runtime) => transport.clone().with_kernel_capture(runtime),
                None => transport.clone(),
            };
            let inbound_peers = self.peers.clone();
            let inbound_udp_updates = self.udp_transport_publication.subscribe();
            let inbound_evidence = Some(crate::transport::InboundEvidenceFeed {
                relay_transport: self.relay_transport.clone(),
                timeline: Some(self.timeline.clone()),
                overlay_ingress_tx: None,
            });
            self.task_manager
                .spawn_result("wireguard-inbound", true, async move {
                    // UDP direct binds asynchronously and can later be
                    // replaced after a socket failure.  Keep a live watch
                    // receiver instead of taking one startup-time snapshot;
                    // WireGuard inbound resolves it for every packet.
                    inbound_transport
                        .run_inbound_with_peers_live_udp_and_relay(
                            network_inbound_rx,
                            inbound_tx,
                            Some(inbound_peers),
                            inbound_udp_updates,
                            inbound_evidence,
                        )
                        .await
                })
                .await;

            self.task_manager
                .spawn_result("dataplane", true, async move {
                    if let Some(ready) = tun_worker_ready {
                        dataplane.run_with_tun_worker_ready(ready).await
                    } else {
                        dataplane.run().await
                    }
                })
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
            let (tun, controller) =
                p2pnet_tun::mock::MockTunDevice::new_pair(&interface_name, mtu, &local_vip);
            let (dataplane, outbound_rx, inbound_tx) = DataPlane::new_bidirectional_for_daemon(
                tun,
                peers.clone(),
                true,
                self.transport.resource_capture().cloned(),
            );
            let mut dataplane = dataplane
                .with_acl(self.acl.clone(), self.config.node.node_id.clone())
                .with_overlay_cidr(&self.config.network.cidr)
                .with_room_authorization(self.control.room_authorization().await)
                .with_local_source_addresses(local_sources);

            let outbound_transport = transport.clone();
            self.task_manager
                .spawn_result("wireguard-outbound", true, async move {
                    outbound_transport.run_outbound_inner(outbound_rx).await
                })
                .await;

            let inbound_transport = transport.clone();
            let inbound_peers = self.peers.clone();
            let inbound_udp_updates = self.udp_transport_publication.subscribe();
            // The overlay harness subscribes to the decrypted inbound feed so it
            // sees each overlay payload WITH its real relay/direct ingress
            // metadata (never back-inferred from active_path).
            let (overlay_ingress_tx, overlay_ingress_rx) = mpsc::channel(128);
            let inbound_evidence = Some(InboundEvidenceFeed {
                relay_transport: self.relay_transport.clone(),
                timeline: Some(self.timeline.clone()),
                overlay_ingress_tx: Some(overlay_ingress_tx),
            });
            self.task_manager
                .spawn_result("wireguard-inbound", true, async move {
                    inbound_transport
                        .run_inbound_with_peers_live_udp_and_relay(
                            network_inbound_rx,
                            inbound_tx,
                            Some(inbound_peers),
                            inbound_udp_updates,
                            inbound_evidence,
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
            let overlay_start_gate_file = self.config.network.overlay_start_gate_file.clone();
            let overlay_any_path = self.config.network.overlay_any_path;
            let overlay_udp_transport = self.udp_transport.clone();
            let overlay_burst = self.config.network.overlay_burst;
            let overlay_timeline = self.timeline.clone();
            let shutdown_rx = self.shutdown_rx.clone();
            let overlay_native_owners = SourcedOverlayOwners {
                wireguard: self.transport.clone(),
                relay: self.relay_transport.clone(),
                room: self.control.room_authorization().await,
            };
            self.task_manager
                .spawn("overlay-validate", false, async move {
                    run_sourced_overlay_validate_loop(
                        controller,
                        overlay_peers,
                        overlay_local_vip,
                        overlay_node_id,
                        overlay_start_gate_file,
                        overlay_any_path,
                        overlay_udp_transport,
                        overlay_burst,
                        overlay_timeline,
                        overlay_ingress_rx,
                        shutdown_rx,
                        overlay_native_owners,
                    )
                    .await
                })
                .await;
            info!("validate_overlay: mock-TUN overlay dataplane is up at {local_vip}");
        } else {
            let resource_capture = self.transport.resource_capture().cloned();
            let (inbound_tx, inbound_rx) = crate::dataplane_resources::PlaintextRxSink::channel(
                1024,
                resource_capture.clone(),
            );
            let inbound_transport = self.transport.clone();
            let inbound_peers = self.peers.clone();
            let inbound_udp_updates = self.udp_transport_publication.subscribe();
            let inbound_evidence = Some(InboundEvidenceFeed {
                relay_transport: self.relay_transport.clone(),
                timeline: Some(self.timeline.clone()),
                overlay_ingress_tx: None,
            });
            self.task_manager
                .spawn_result("wireguard-inbound", true, async move {
                    inbound_transport
                        .run_inbound_with_peers_live_udp_and_relay(
                            network_inbound_rx,
                            inbound_tx,
                            Some(inbound_peers),
                            inbound_udp_updates,
                            inbound_evidence,
                        )
                        .await
                })
                .await;
            self.task_manager
                .spawn(
                    "tun-disabled-inbound-log",
                    false,
                    log_inbound_packets_without_tun(inbound_rx, resource_capture),
                )
                .await;
        }
        Ok(())
    }
}
