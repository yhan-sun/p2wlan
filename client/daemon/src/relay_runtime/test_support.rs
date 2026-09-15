use super::*;

pub(super) fn test_supervisor(ticket_cache: Option<Arc<RelayTicketCache>>) -> RelaySupervisor {
    let config = crate::Config::generate_default("https://ctrl.test", "net1").unwrap();
    let peers = Arc::new(PeerManager::new(config));
    let (inbound_tx, _inbound_rx) = mpsc::channel(4);
    let (relay_available_tx, _relay_available_rx) = tokio::sync::watch::channel(false);
    RelaySupervisor {
        relay_candidates: Vec::new(),
        preferred_regions: Vec::new(),
        selection_timeout: Duration::from_millis(500),
        node_id: "node-a".to_string(),
        peers,
        relay_transport: Arc::new(RwLock::new(None)),
        relay_selection: Arc::new(RwLock::new(RelaySelectionDiagnostics::default())),
        relay_available_tx,
        timeline: crate::connection_timeline::ConnectionTimeline::new("node-a", 0),
        inbound_tx,
        android_network_change_rx: None,
        ticket_cache,
        relay_ticket: None,
        allow_insecure_plaintext: true,
        ca_cert_path: None,
    }
}
pub(super) async fn wait_for_relay_transport(
    relay_transport: &Arc<RwLock<Option<RelayTransport>>>,
    endpoint: &str,
) {
    tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            let current = relay_transport.read().await.clone();
            if current.as_ref().is_some_and(|t| t.endpoint() == endpoint) {
                break;
            }
            sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .expect("the supervisor must publish the renewal replacement");
}
