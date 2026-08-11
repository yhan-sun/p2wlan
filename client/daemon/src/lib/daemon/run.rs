impl Daemon {
    /// Run the daemon main loop.
    pub async fn run(&mut self) -> Result<()> {
        info!("P2WLAN daemon v{} starting...", env!("CARGO_PKG_VERSION"));
        info!("Node ID: {}", self.config.node.node_id);
        info!(
            "Network: {} ({})",
            self.config.network.network_id, self.config.network.cidr
        );
        info!("Control server: {}", self.config.control.server_url);

        let mut virtual_ip = self.config.network.virtual_ip.clone();
        let mut netmask = self.config.network.netmask.clone();
        let mut cidr = self.config.network.cidr.clone();
        let mut assigned_node_id = self.config.node.node_id.clone();
        let mut relay_servers = self.config.relay.servers.clone();
        let mut relay_catalog = Vec::new();

        let mut control_event_registered = None;

        if !self.config.network.manual {
            info!("Running in managed mode. Waiting for control plane registration...");
            // Wait for Registered event
            while let Some(event) = self.control_rx.recv().await {
                match event {
                    ControlEvent::Registered {
                        node_id,
                        virtual_ip: vip,
                        cidr: dyn_cidr,
                        relay_servers: rs,
                        relay_catalog: catalog,
                    } => {
                        info!("Control plane registration confirmed. Assigned IP: {}", vip);
                        self.health.mark_control_success().await;

                        // Validate virtual IP
                        if vip.parse::<std::net::Ipv4Addr>().is_err() {
                            return Err(DaemonError::Network(format!(
                                "Server returned invalid virtual IP: {}",
                                vip
                            )));
                        }

                        // Validate CIDR
                        let actual_cidr = dyn_cidr.unwrap_or_else(|| "10.20.0.0/16".to_string());
                        if !is_ip_in_cidr(&vip, &actual_cidr) {
                            return Err(DaemonError::Network(format!(
                                "Server returned virtual IP {} that is outside network CIDR {}",
                                vip, actual_cidr
                            )));
                        }

                        virtual_ip = vip;
                        if let Some(derived_mask) = cidr_to_netmask(&actual_cidr) {
                            netmask = derived_mask;
                        }
                        cidr = actual_cidr;
                        if let Some(nid) = node_id {
                            assigned_node_id = nid;
                        }
                        if !rs.is_empty() {
                            relay_servers = rs;
                        }
                        if !catalog.is_empty() {
                            relay_catalog = catalog;
                        }
                        if relay_servers.is_empty() && relay_catalog.is_empty() {
                            relay_servers =
                                infer_default_relay_servers(&self.config.control.server_url);
                        }

                        control_event_registered = Some(ControlEvent::Registered {
                            node_id: Some(assigned_node_id.clone()),
                            virtual_ip: virtual_ip.clone(),
                            cidr: Some(cidr.clone()),
                            relay_servers: relay_servers.clone(),
                            relay_catalog: relay_catalog.clone(),
                        });
                        break;
                    }
                    ControlEvent::ServerError { code, message } => {
                        return Err(DaemonError::ControlPlane(format!(
                            "Server returned error code {code}: {message}"
                        )));
                    }
                    ControlEvent::ReauthRequired { message } => {
                        return Err(DaemonError::Auth(message));
                    }
                    _ => {
                        warn!("Received event before registration, ignoring: {:?}", event);
                    }
                }
            }
        } else {
            info!("Running in manual/offline mode. Using local configurations.");
        }

        let relay_allow_insecure_plaintext = effective_relay_allow_insecure_plaintext(
            &self.config.control.server_url,
            &relay_catalog,
            &relay_servers,
            self.config.relay.allow_insecure_plaintext,
        );
        if relay_allow_insecure_plaintext && !self.config.relay.allow_insecure_plaintext {
            info!(
                "Allowing plaintext relay because HTTP control plane supplied legacy relay candidates"
            );
        }

        let mut resolved_config = (*self.config).clone();
        resolved_config.network.virtual_ip = virtual_ip.clone();
        resolved_config.network.netmask = netmask.clone();
        resolved_config.network.cidr = cidr.clone();
        resolved_config.node.node_id = assigned_node_id.clone();
        resolved_config.relay.servers = relay_servers.clone();
        resolved_config.relay.allow_insecure_plaintext = relay_allow_insecure_plaintext;
        resolved_config.network.udp_observers =
            udp_observers_from_sources(&relay_catalog, &resolved_config.network.udp_observers);
        self.config = Arc::new(resolved_config);

        // Initialize TUN using the resolved IP details
        let tun = self.init_tun_with(&virtual_ip, &netmask, self.config.network.mtu)?;
        if let Some(ref tun) = tun {
            self.route_manager.set_interface(tun.name().to_string());
        }

        // Install overlay route
        self.route_manager.add_cidr_route(&cidr)?;

        let Some(encrypted_rx) = self.encrypted_rx.take() else {
            return Err(DaemonError::Network(
                "encrypted packet receiver already attached".to_string(),
            ));
        };
        let udp_bind = self.config.network.udp_bind.parse().map_err(|e| {
            DaemonError::Config(format!(
                "invalid network.udp_bind '{}': {e}",
                self.config.network.udp_bind
            ))
        })?;
        let udp_advertise = self.config.network.udp_advertise.clone();
        let stun_timeout = Duration::from_millis(self.config.network.stun_timeout_ms);
        let mut stun_servers =
            parse_stun_servers(&self.config.network.stun_servers, stun_timeout).await?;
        let udp_observers = if self.config.network.udp_observers.is_empty() {
            Vec::new()
        } else {
            parse_stun_servers(&self.config.network.udp_observers, stun_timeout).await?
        };
        for observer in &udp_observers {
            if !stun_servers.contains(observer) {
                stun_servers.push(*observer);
            }
        }
        if stun_servers.is_empty() {
            info!("STUN/UDP-observer candidate gathering is disabled");
        } else if udp_observers.is_empty() {
            info!("Using STUN endpoints: {stun_servers:?}");
        } else {
            info!("Using STUN/UDP observer endpoints: stun_and_observers={stun_servers:?} observers={udp_observers:?}");
        }
        *self.runtime_stun_servers.write().await = stun_servers.clone();
        *self.runtime_stun_timeout.write().await = stun_timeout;
        let configured_keepalive = Duration::from_secs(self.config.network.keepalive_interval_secs);
        let keepalive_interval = if configured_keepalive.is_zero() {
            Duration::ZERO
        } else {
            configured_keepalive.min(DIRECT_LIVENESS_INTERVAL_MAX)
        };
        let upnp_enabled = self.config.network.upnp_enabled;
        let socket_pool_enabled = self.config.network.socket_pool_enabled;
        let socket_pool_size = self.config.network.socket_pool_size;
        let prefer_direct = self.config.relay.prefer_direct;
        let punch_interval = Duration::from_millis(self.config.network.punch_interval_ms);
        let punch_attempts = self.config.network.punch_attempts;

        let (network_inbound_tx, network_inbound_rx) = mpsc::channel(1024);
        self.task_manager
            .spawn(
                "network-outbound",
                true,
                run_network_outbound(
                    encrypted_rx,
                    self.peers.clone(),
                    prefer_direct,
                    self.udp_transport.clone(),
                    self.relay_transport.clone(),
                ),
            )
            .await;
        self.task_manager
            .spawn(
                "direct-probe",
                false,
                run_direct_probe_loop(
                    self.peers.clone(),
                    self.udp_transport.clone(),
                    self.local_candidates.clone(),
                    self.candidate_snapshot.clone(),
                    self.punch_attempts.clone(),
                    self.control.clone(),
                    self.runtime_stun_servers.clone(),
                    self.runtime_stun_timeout.clone(),
                    self.boot_epoch_ms,
                    DIRECT_RETRY_BASE_INTERVAL,
                    punch_interval,
                    punch_attempts.clamp(1, 3),
                ),
            )
            .await;
        self.task_manager
            .spawn(
                "relay-peer-validation",
                false,
                run_relay_peer_validation_loop(
                    self.peers.clone(),
                    self.transport.clone(),
                    self.relay_transport.clone(),
                    virtual_ip.clone(),
                ),
            )
            .await;
        if self.config.diagnostics.enabled {
            let diagnostics_bind = self.config.diagnostics.bind.clone();
            let diagnostics_context = DiagnosticsContext::new(
                self.config.clone(),
                self.peers.clone(),
                self.udp_transport.clone(),
                self.candidate_snapshot.clone(),
                self.nat_profile.clone(),
                self.gateway_mapping_diagnostics.clone(),
                self.relay_transport.clone(),
                self.relay_selection.clone(),
                self.health.clone(),
                self.task_manager.clone(),
                self.shutdown_tx.clone(),
            );
            let shutdown_rx = self.shutdown_rx.clone();
            self.task_manager
                .spawn("diagnostics", false, async move {
                    if let Err(err) = run_diagnostics_server_with_retry(
                        diagnostics_bind,
                        diagnostics_context,
                        shutdown_rx,
                    )
                    .await
                    {
                        warn!("Diagnostics endpoint stopped: {err}");
                    }
                })
                .await;

            if tun.is_some() {
                let speed_test_virtual_ip = self.config.network.virtual_ip.clone();
                let speed_test_shutdown_rx = self.shutdown_rx.clone();
                self.task_manager
                    .spawn("speed-test", false, async move {
                        if let Err(err) = run_speedtest_server_with_retry(
                            speed_test_virtual_ip,
                            speed_test_shutdown_rx,
                        )
                        .await
                        {
                            warn!("Speed-test endpoint stopped: {err}");
                        }
                    })
                    .await;
            }
        }
        self.spawn_dataplane_tasks(tun, network_inbound_rx).await;

        let local_candidate_sources = self.local_candidate_sources.clone();
let udp_direct_context = UdpDirectTaskContext {
    udp_bind,
    peers: self.peers.clone(),
    control: self.control.clone(),
    local_candidates: self.local_candidates.clone(),
     local_candidate_sources: local_candidate_sources.clone(),
     local_network_identity: self.local_network_identity.clone(),
     candidate_snapshot: self.candidate_snapshot.clone(),
    candidate_refresh_lock: self.candidate_refresh_lock.clone(),
    nat_profile: self.nat_profile.clone(),
    gateway_mapping_runtime: self.gateway_mapping_runtime.clone(),
    gateway_mapping_diagnostics: self.gateway_mapping_diagnostics.clone(),
    udp_transport_publication: self.udp_transport_publication.clone(),
    direct_validation_transport: self.transport.clone(),
    direct_validation_local_ip: self.config.network.virtual_ip.clone(),
    udp_inbound_tx: network_inbound_tx.clone(),
    local_node_id: self.config.node.node_id.clone(),
    stun_servers,
    stun_timeout,
    udp_advertise,
    upnp_enabled,
    socket_pool_enabled,
    socket_pool_size,
    keepalive_interval,
    punch_deduplicator: self.punch_attempts.clone(),
    udp_punch_interval: punch_interval,
    udp_punch_attempts: punch_attempts,
    boot_epoch_ms: self.boot_epoch_ms,
    shutdown_rx: self.shutdown_rx.clone(),
};
self.task_manager
    .spawn_result("udp-direct", false, run_udp_direct_task(udp_direct_context))
    .await;

        // Relay registration must use the node ID assigned by the control plane.
        let mut relay_started = false;

        // If we had a cached control_event_registered, process it first
        if let Some(ControlEvent::Registered {
            ref node_id,
            ref relay_servers,
            ref relay_catalog,
            ..
        }) = control_event_registered
        {
            let relay_node_id = node_id
                .clone()
                .unwrap_or_else(|| self.config.node.node_id.clone());
            let relay_servers = if relay_servers.is_empty() {
                self.config.relay.servers.clone()
            } else {
                relay_servers.clone()
            };
            let relay_candidates = relay_candidates_from_sources(relay_catalog, &relay_servers);
            if relay_candidates.is_empty() {
                debug!(
                    "No relay servers configured; direct UDP only unless peers provide relay later"
                );
            } else {
                relay_started = true;
spawn_relay_inbound(RelayInboundSpawnContext {
    task_manager: self.task_manager.clone(),
    relay_candidates,
    preferred_regions: self.config.relay.preferred_regions.clone(),
    selection_timeout: Duration::from_millis(
        self.config.relay.selection_timeout_ms.max(1),
    ),
    node_id: relay_node_id,
    peers: self.peers.clone(),
    relay_transport: self.relay_transport.clone(),
    relay_selection: self.relay_selection.clone(),
    inbound_tx: network_inbound_tx.clone(),
    control: self.control.clone(),
    allow_insecure_plaintext: self.config.relay.allow_insecure_plaintext,
    ca_cert_path: self.config.relay.ca_cert_path.clone(),
})
.await;
            }
        }

// Periodic session rekey checker — truly invokes needs_rekey / is_expired.
self.task_manager
    .spawn(
        "handshake-maintenance",
        false,
        run_handshake_maintenance(HandshakeMaintenanceContext {
            peers: self.peers.clone(),
            transport: self.transport.clone(),
            pending: self.pending_handshakes.clone(),
            handshake_arbiter: self.handshake_arbiter.clone(),
            control: self.control.clone(),
            local_candidates: self.local_candidates.clone(),
            local_candidate_sources: local_candidate_sources.clone(),
            local_network_identity: self.local_network_identity.clone(),
            candidate_snapshot: self.candidate_snapshot.clone(),
            candidate_refresh_lock: self.candidate_refresh_lock.clone(),
            nat_profile: self.nat_profile.clone(),
            udp_transport: self.udp_transport.clone(),
            runtime_stun_servers: self.runtime_stun_servers.clone(),
            runtime_stun_timeout: self.runtime_stun_timeout.clone(),
            udp_advertise: self.config.network.udp_advertise.clone(),
            node_private_key: self.config.node.private_key.clone(),
        }),
    )
    .await;

        self.run_control_event_loop(&mut relay_started, network_inbound_tx.clone())
            .await;

        info!("Daemon shutting down");
        // Explicit cleanup: notify control loop and clean routes without relying on Drop.
        if let Some(udp) = self.udp_transport.read().await.clone() {
            udp.detach_all_dynamic_punch_sockets("daemon_shutdown").await;
        }
        // Withdraw the live publication before background tasks are aborted so
        // inbound consumers and the instance-owned peer-reflexive worker see
        // a deterministic shutdown transition instead of retaining a stale
        // socket clone through daemon teardown.
        self.udp_transport_publication.clear_current().await;
        self.request_shutdown();
        let _ = self.control.shutdown().await;
        self.task_manager.shutdown_all(Duration::from_secs(5)).await;
        self.route_manager.cleanup();
        Ok(())
    }
}
