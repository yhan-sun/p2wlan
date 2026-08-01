struct RelayInboundSpawnContext {
    task_manager: Arc<tasks::TaskManager>,
    relay_candidates: Vec<relay::RelayCandidateConfig>,
    preferred_regions: Vec<String>,
    selection_timeout: Duration,
    node_id: String,
    peers: Arc<PeerManager>,
    relay_transport: Arc<RwLock<Option<RelayTransport>>>,
    relay_selection: Arc<RwLock<RelaySelectionDiagnostics>>,
    inbound_tx: mpsc::Sender<ReceivedEncryptedPacket>,
    control: ControlClient,
    allow_insecure_plaintext: bool,
    ca_cert_path: Option<String>,
}

async fn spawn_relay_inbound(ctx: RelayInboundSpawnContext) {
    ctx.task_manager
        .spawn(
            "relay-inbound",
            false,
            RelaySupervisor {
                relay_candidates: ctx.relay_candidates,
                preferred_regions: ctx.preferred_regions,
                selection_timeout: ctx.selection_timeout,
                node_id: ctx.node_id,
                peers: ctx.peers,
                relay_transport: ctx.relay_transport,
                relay_selection: ctx.relay_selection,
                inbound_tx: ctx.inbound_tx,
                ticket_cache: Some(Arc::new(RelayTicketCache::new(ctx.control))),
                relay_ticket: None,
                allow_insecure_plaintext: ctx.allow_insecure_plaintext,
                ca_cert_path: ctx.ca_cert_path,
            }
            .run(),
        )
        .await;
}
