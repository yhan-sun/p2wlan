// A selected TCP connection is not a network-wide rendezvous agreement. Keep
// independently renewed registrations on the other configured relays so peers
// with different preferences (or asymmetric reachability) can find a common hub.
struct RelayRendezvousPlan {
    candidates: Vec<RelayCandidate>,
    node_id: String,
    peers: Arc<PeerManager>,
    ticket_cache: Option<Arc<RelayTicketCache>>,
    static_relay_ticket: Option<String>,
    allow_insecure_plaintext: bool,
    ca_cert_path: Option<String>,
    connect_timeout: Duration,
}

type StandbyTransport = (RelayTransport, mpsc::Receiver<OriginalRelayDelivery>);
type StandbyTransfer = tokio::sync::oneshot::Sender<StandbyTransport>;

struct RegisteredStandby {
    connection_id: u64,
    transfer: tokio::sync::oneshot::Sender<StandbyTransfer>,
}

#[derive(Default)]
struct RendezvousRoutes {
    clients: HashMap<String, Arc<RelayClient>>,
    standbys: HashMap<String, RegisteredStandby>,
    peers: HashMap<String, String>,
}

struct RelayRendezvous {
    plan: Arc<RelayRendezvousPlan>,
    routes: std::sync::Mutex<RendezvousRoutes>,
    tasks: std::sync::Mutex<Vec<tokio::task::JoinHandle<()>>>,
    stopped: std::sync::atomic::AtomicBool,
    #[cfg(test)]
    stop_attempted: std::sync::atomic::AtomicBool,
}

impl RelayRendezvous {
    fn stop(&self) {
        #[cfg(test)]
        self.stop_attempted
            .store(true, std::sync::atomic::Ordering::Release);
        {
            let mut routes = self.routes.lock().unwrap_or_else(|p| p.into_inner());
            // The original routes gate freezes membership and this sole stop
            // flag together for borrowed current-member qualification.
            self.stopped
                .store(true, std::sync::atomic::Ordering::Release);
            for client in routes.clients.values() {
                client.abort();
            }
            routes.clients.clear();
            routes.standbys.clear();
            routes.peers.clear();
        }
        // Never nest the tasks gate with routes or a client close gate.
        for task in self.tasks.lock().unwrap_or_else(|p| p.into_inner()).iter() {
            task.abort();
        }
    }

    async fn shutdown(&self) {
        self.stop();
        let tasks = std::mem::take(&mut *self.tasks.lock().unwrap_or_else(|p| p.into_inner()));
        for task in tasks {
            let _ = task.await;
        }
    }

    fn insert(&self, endpoint: &str, client: Arc<RelayClient>) -> bool {
        let mut routes = self.routes.lock().unwrap_or_else(|p| p.into_inner());
        if self.stopped.load(std::sync::atomic::Ordering::Acquire) {
            client.abort();
            return false;
        }
        routes.clients.insert(endpoint.to_string(), client);
        true
    }

    fn remove_if_client(&self, endpoint: &str, original: &Arc<RelayClient>) {
        let mut routes = self.routes.lock().unwrap_or_else(|p| p.into_inner());
        if !routes
            .clients
            .get(endpoint)
            .is_some_and(|client| Arc::ptr_eq(client, original))
        {
            return;
        }
        if let Some(client) = routes.clients.remove(endpoint) {
            client.abort();
        }
        routes.standbys.remove(endpoint);
        routes.peers.retain(|_, route| route != endpoint);
    }

    fn register_standby(
        &self,
        endpoint: &str,
        writer: &Arc<RelayClient>,
        connection_id: u64,
        transfer: tokio::sync::oneshot::Sender<StandbyTransfer>,
    ) {
        let mut routes = self.routes.lock().unwrap_or_else(|p| p.into_inner());
        if !self.stopped.load(std::sync::atomic::Ordering::Acquire)
            && routes
                .clients
                .get(endpoint)
                .is_some_and(|ready| Arc::ptr_eq(ready, writer))
        {
            routes.standbys.insert(
                endpoint.to_owned(),
                RegisteredStandby {
                    connection_id,
                    transfer,
                },
            );
        }
    }

    fn detach_standby(&self, endpoint: &str, writer: &Arc<RelayClient>) -> bool {
        let mut routes = self.routes.lock().unwrap_or_else(|p| p.into_inner());
        if !routes
            .clients
            .get(endpoint)
            .is_some_and(|ready| Arc::ptr_eq(ready, writer))
        {
            return false;
        }
        routes.clients.remove(endpoint);
        routes.peers.retain(|_, route| route != endpoint);
        true
    }

    fn retire_primary(&self) {
        if self.plan.peers.warm_relay_failover() {
            let _routes = self.routes.lock().unwrap_or_else(|p| p.into_inner());
            self.stopped
                .store(true, std::sync::atomic::Ordering::Release);
        } else {
            self.stop();
        }
    }

    fn send_clients(&self, peer: &str) -> Vec<Arc<RelayClient>> {
        let routes = self.routes.lock().unwrap_or_else(|p| p.into_inner());
        if self.stopped.load(std::sync::atomic::Ordering::Acquire) {
            return Vec::new();
        }
        if let Some(client) = routes
            .peers
            .get(peer)
            .and_then(|endpoint| routes.clients.get(endpoint))
        {
            return vec![client.clone()];
        }
        routes.clients.values().cloned().collect()
    }

    // One original selection and one routes lock. Metadata allocation failure
    // keeps this exact business vector; it never performs a second selection.
    fn send_clients_with_origins(
        &self,
        peer: &str,
    ) -> (
        Vec<Arc<RelayClient>>,
        Option<Vec<send_origin::SelectedRelayWriter>>,
    ) {
        let routes = self.routes.lock().unwrap_or_else(|p| p.into_inner());
        if self.stopped.load(std::sync::atomic::Ordering::Acquire) {
            return (Vec::new(), None);
        }
        if let Some((endpoint, client)) = routes.peers.get(peer).and_then(|endpoint| {
            routes
                .clients
                .get(endpoint)
                .map(|client| (endpoint, client))
        }) {
            let clients = vec![client.clone()];
            let origins = send_origin::SelectedRelayWriter::single(endpoint, client);
            return (clients, origins);
        }
        // HashMap::iter and values visit the same entries in the same order.
        // Do not add a fanout limit or keep additional strong client owners.
        let clients: Vec<_> = routes.clients.values().cloned().collect();
        let mut origins = Vec::new();
        if origins.try_reserve_exact(clients.len()).is_err() {
            return (clients, None);
        }
        for (endpoint, client) in &routes.clients {
            let Some(origin) = send_origin::SelectedRelayWriter::capture(endpoint, client) else {
                return (clients, None);
            };
            origins.push(origin);
        }
        (clients, Some(origins))
    }

    fn observe(&self, endpoint: &str, message: &RelayMessage) -> bool {
        let mut routes = self.routes.lock().unwrap_or_else(|p| p.into_inner());
        match message {
            RelayMessage::Data { from_node, .. } => {
                // This is a routing hint only. WireGuard authentication and the
                // encrypted round-trip proof still gate business-path promotion.
                if routes.clients.contains_key(endpoint) {
                    routes.peers.insert(from_node.clone(), endpoint.to_string());
                }
                true
            }
            RelayMessage::Error { code: 404, message } => {
                if let Some(peer) = relay_error_peer_id(message) {
                    if routes
                        .peers
                        .get(peer)
                        .is_some_and(|route| route == endpoint)
                    {
                        routes.peers.remove(peer);
                    }
                }
                // One hub's miss must not quarantine a peer present on another.
                // The encrypted peer lease, not a TCP registration, detects loss.
                false
            }
            _ => true,
        }
    }
}

impl Drop for RelayRendezvous {
    fn drop(&mut self) {
        self.stop();
    }
}

// A worker can be cancelled while its client is also retained in the route map.
// Explicitly close it on every exit, rather than relying on the last Arc drop.
struct RendezvousClientGuard(Option<Arc<RelayClient>>);
impl Drop for RendezvousClientGuard {
    fn drop(&mut self) {
        if let Some(client) = &self.0 {
            client.abort();
        }
    }
}

impl RelayTransport {
    fn with_rendezvous<I: RelayReadItem>(
        mut self,
        mut primary_rx: mpsc::Receiver<I>,
        plan: Arc<RelayRendezvousPlan>,
    ) -> (Self, mpsc::Receiver<I>) {
        if plan.candidates.len() < 2 {
            return (self, primary_rx);
        }
        let pool = Arc::new(RelayRendezvous {
            plan: plan.clone(),
            routes: std::sync::Mutex::new(RendezvousRoutes::default()),
            tasks: std::sync::Mutex::new(Vec::new()),
            stopped: std::sync::atomic::AtomicBool::new(false),
            #[cfg(test)]
            stop_attempted: std::sync::atomic::AtomicBool::new(false),
        });
        pool.insert(self.endpoint(), self.client.clone());
        let (tx, rx) = mpsc::channel(256);
        let weak = Arc::downgrade(&pool);
        let primary_endpoint = self.endpoint().to_string();
        let primary_tx = tx.clone();
        let primary_task = tokio::spawn(async move {
            while let Some(message) = primary_rx.recv().await {
                let closed = matches!(message.message(), RelayMessage::Closed { .. });
                let forward = match weak.upgrade() {
                    Some(pool) => pool.observe(&primary_endpoint, message.message()),
                    None => return,
                };
                if forward && primary_tx.send(message).await.is_err() {
                    return;
                }
                if closed {
                    if let Some(pool) = weak.upgrade() {
                        pool.retire_primary();
                    }
                    return;
                }
            }
            // Auxiliary senders keep the merged channel open; preserve primary
            // EOF explicitly so the supervisor still owns reconnect and renewal.
            let _ = primary_tx
                .send(
                    RelayMessage::Closed {
                        reason: p2pnet_relay::RelayCloseReason::ServerEof,
                    }
                    .into(),
                )
                .await;
            if let Some(pool) = weak.upgrade() {
                pool.retire_primary();
            }
        });
        pool.tasks
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .push(primary_task);
        for candidate in &plan.candidates {
            if candidate.endpoint == self.endpoint() {
                continue;
            }
            let candidate = candidate.clone();
            let weak = Arc::downgrade(&pool);
            let plan = plan.clone();
            let tx = tx.clone();
            let task = tokio::spawn(async move {
                loop {
                    if weak
                        .upgrade()
                        .is_none_or(|pool| pool.stopped.load(std::sync::atomic::Ordering::Acquire))
                    {
                        return;
                    }
                    let connected = timeout(plan.connect_timeout, async {
                        let ticket = relay_ticket_for_candidate(
                            &candidate,
                            plan.ticket_cache.clone(),
                            plan.static_relay_ticket.clone(),
                        )
                        .await?;
                        let expiry = ticket
                            .as_ref()
                            .map(|(_, expiry)| *expiry)
                            .filter(|expiry| *expiry > 0);
                        let (transport, rx) = RelayTransport::connect_in_region_for_read::<I>(
                            &candidate.endpoint,
                            &candidate.region,
                            &plan.node_id,
                            plan.peers.clone(),
                            ticket.map(|(ticket, _)| ticket),
                            plan.allow_insecure_plaintext,
                            plan.ca_cert_path.clone(),
                        )
                        .await
                        .map_err(RelayAttemptError::Relay)?;
                        let transport = match (candidate.audience.as_deref(), expiry) {
                            (Some(audience), Some(expiry)) => {
                                transport.with_ticket_metadata(audience, &candidate.region, expiry)
                            }
                            _ => transport,
                        };
                        Ok::<_, RelayAttemptError>((transport, rx, expiry))
                    })
                    .await;
                    let (transport, mut input, expiry) = match connected {
                        Ok(Ok(connection)) => connection,
                        _ => {
                            tokio::time::sleep(Duration::from_secs(5)).await;
                            continue;
                        }
                    };
                    let client = transport.client.clone();
                    let mut guard = RendezvousClientGuard(Some(client.clone()));
                    if weak
                        .upgrade()
                        .is_none_or(|pool| !pool.insert(&candidate.endpoint, client))
                    {
                        return;
                    }
                    let (transfer_tx, mut transfer_rx) = tokio::sync::oneshot::channel();
                    let eligible = I::ORIGINAL_READER
                        && plan.peers.warm_relay_failover()
                        && transport.ticket_expiry().is_some();
                    if eligible {
                        if let Some(pool) = weak.upgrade() {
                            pool.register_standby(
                                &candidate.endpoint,
                                &transport.client,
                                transport.connection_id(),
                                transfer_tx,
                            );
                        }
                    }
                    // ticket_for() refreshes at the same margin; after this
                    // deadline the next registration cannot reuse an expiring ticket.
                    let renewal_at = expiry.map(|expiry| {
                        tokio::time::Instant::now()
                            + Duration::from_secs(
                                expiry
                                    .saturating_sub(now_unix())
                                    .saturating_sub(RELAY_TICKET_REFRESH_MARGIN_SECS)
                                    .max(1) as u64,
                            )
                    });
                    let mut planned_renewal = false;
                    loop {
                        tokio::select! {
                            transfer = &mut transfer_rx, if eligible => {
                                if let Ok(reply) = transfer {
                                    let fresh = expiry.is_some_and(|at| at > now_unix() + RELAY_TICKET_REFRESH_MARGIN_SECS);
                                    if fresh && weak.upgrade().is_some_and(|pool| pool.detach_standby(&candidate.endpoint, &transport.client)) {
                                        if let Some(original) = I::take_original_reader(input) {
                                            if reply.send((transport, original)).is_ok() { guard.0.take(); }
                                        }
                                        return;
                                    }
                                }
                                break;
                            }
                            _ = tokio::time::sleep_until(renewal_at.unwrap_or_else(tokio::time::Instant::now)), if renewal_at.is_some() => {
                                planned_renewal = true;
                                break;
                            }
                            message = input.recv() => {
                                let Some(message) = message else { break; };
                                if matches!(message.message(), RelayMessage::Closed { .. }) { break; }
                                // Auxiliary RTT is not the selected connection's RTT.
                                if matches!(message.message(), RelayMessage::Pong { .. }) { continue; }
                                let forward = match weak.upgrade() {
                                    Some(pool) => pool.observe(&candidate.endpoint, message.message()),
                                    None => return,
                                };
                                if forward && tx.send(message).await.is_err() { return; }
                            }
                        }
                    }
                    if let Some(pool) = weak.upgrade() {
                        pool.remove_if_client(&candidate.endpoint, &transport.client);
                    }
                    drop(guard);
                    if !planned_renewal {
                        tokio::time::sleep(Duration::from_secs(5)).await;
                    }
                }
            });
            pool.tasks
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .push(task);
        }
        self.rendezvous = Some(pool);
        (self, rx)
    }

    pub(crate) fn retire_ended_writer(&self) {
        self.retire_write_boundaries();
        self.client.abort();
        if let Some(pool) = &self.rendezvous {
            pool.retire_primary();
        }
    }

    pub(crate) async fn take_registered_standby(&self) -> Option<StandbyTransport> {
        let pool = self.rendezvous.as_ref()?;
        if !self.peers.warm_relay_failover() {
            return None;
        }
        let sender = {
            let mut routes = pool.routes.lock().unwrap_or_else(|p| p.into_inner());
            pool.plan
                .candidates
                .iter()
                .find_map(|candidate| routes.standbys.remove(&candidate.endpoint))
        };
        let result = if let Some(sender) = sender {
            let (reply, receiver) = tokio::sync::oneshot::channel();
            if sender.transfer.send(reply).is_ok() {
                timeout(Duration::from_millis(300), receiver)
                    .await
                    .ok()
                    .and_then(|result| result.ok())
            } else {
                None
            }
        } else {
            None
        };
        pool.shutdown().await;
        result.map(|(mut transport, input)| {
            transport.resume_rendezvous = Some(pool.plan.clone());
            (transport, input)
        })
    }

    pub(crate) async fn handoff_rendezvous<I: RelayReadItem>(
        &self,
        replacement: Self,
        rx: mpsc::Receiver<I>,
    ) -> (Self, mpsc::Receiver<I>) {
        match &self.rendezvous {
            Some(pool) => {
                // Fully cancel old reconnects before any replacement auxiliary
                // registration: an old worker must not win a newest-wins race.
                pool.shutdown().await;
                replacement.with_rendezvous(rx, pool.plan.clone())
            }
            None => match &self.resume_rendezvous {
                Some(plan) => replacement.with_rendezvous(rx, plan.clone()),
                None => (replacement, rx),
            },
        }
    }
}
