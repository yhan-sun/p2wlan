use super::*;

impl WireGuardTransport {
    /// Share the peer manager's outbound-loss counters with this transport so
    /// session-not-ready queue loss lands in `/status.stats.outbound_drops`
    /// under the same map as the worker's drops.  Installed once by the
    /// daemon before any traffic flows.
    pub fn set_outbound_loss_sink(
        &self,
        sink: Option<Arc<tokio::sync::Mutex<crate::peer::OutboundLossCounters>>>,
    ) {
        *self
            .outbound_loss_sink
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = sink;
    }

    /// Install the daemon timeline and peer-generation source used by the
    /// transport-level session backlog. This queue is retained for handshake
    /// handoff compatibility, so its losses must carry the same audit fields
    /// as the network-outbound actor's losses.
    pub(crate) fn set_outbound_loss_context(
        &self,
        peers: &Arc<PeerManager>,
        timeline: Arc<crate::connection_timeline::ConnectionTimeline>,
    ) {
        *self
            .outbound_loss_context
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = Some(OutboundLossContext {
            peers: Arc::downgrade(peers),
            timeline,
        });
    }

    /// The shared loss sink, if the daemon installed one.
    pub(in crate::transport) fn outbound_loss_registry(
        &self,
    ) -> Option<Arc<tokio::sync::Mutex<crate::peer::OutboundLossCounters>>> {
        self.outbound_loss_sink
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clone()
    }

    /// Record TERMINAL dropped business packets against the shared sink, if
    /// installed.
    pub(crate) async fn record_outbound_drop(
        &self,
        reason_code: &str,
        packets: usize,
        bytes: usize,
    ) {
        if packets == 0 {
            return;
        }
        if let Some(sink) = self.outbound_loss_registry() {
            let mut loss = sink.lock().await;
            let entry = loss.drops.entry(reason_code.to_string()).or_default();
            entry.packets = entry.packets.saturating_add(packets as u64);
            entry.bytes = entry.bytes.saturating_add(bytes as u64);
        }
    }

    /// Record a transient outbound send-failure ATTEMPT against the shared
    /// sink (never counted as a terminal drop).
    pub(crate) async fn record_outbound_send_failure(
        &self,
        reason_code: &str,
        attempts: usize,
        bytes: usize,
    ) {
        if attempts == 0 {
            return;
        }
        if let Some(sink) = self.outbound_loss_registry() {
            let mut loss = sink.lock().await;
            let entry = loss
                .send_failures
                .entry(reason_code.to_string())
                .or_default();
            entry.packets = entry.packets.saturating_add(attempts as u64);
            entry.bytes = entry.bytes.saturating_add(bytes as u64);
        }
    }

    /// Record a loss event emitted by the legacy session queue. Production
    /// relay-first traffic is owned by `network_outbound`, but this queue is
    /// still reachable during session teardown; it must not disappear from
    /// the same queryable event ledger. The daemon installs a weak generation
    /// source and the shared monotonic timeline during construction, so these
    /// events have the same audit fields as actor-owned losses.
    pub(in crate::transport) async fn record_outbound_queue_event(
        &self,
        kind: &str,
        peer_id: &str,
        reason_code: &str,
        packets: usize,
        bytes: usize,
    ) {
        if packets == 0 {
            return;
        }
        let Some(sink) = self.outbound_loss_registry() else {
            return;
        };
        let context = self
            .outbound_loss_context
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clone();
        let (generation, correlation_id, at_ms, timeline) = match context {
            Some(context) => {
                let generation = context
                    .peers
                    .upgrade()
                    .map(|peers| peers.current_network_generation_sync())
                    .unwrap_or(0);
                let correlation_id = context.timeline.correlation_id().to_string();
                let at_ms = context.timeline.uptime_ms();
                (generation, correlation_id, at_ms, Some(context.timeline))
            }
            None => (0, "transport-session-queue".to_string(), 0, None),
        };
        let mut loss = sink.lock().await;
        const MAX_OUTBOUND_LOSS_EVENTS: usize = 512;
        if loss.events.len() >= MAX_OUTBOUND_LOSS_EVENTS {
            loss.events.remove(0);
        }
        loss.events.push(crate::peer::OutboundLossEvent {
            kind: kind.to_string(),
            peer_id: peer_id.to_string(),
            generation,
            reason_code: reason_code.to_string(),
            packets: packets as u64,
            bytes: bytes as u64,
            correlation_id: correlation_id.clone(),
            at_ms,
        });
        drop(loss);
        if let Some(timeline) = timeline {
            timeline.emit(
                "outbound_session_queue_event",
                None,
                Some(reason_code),
                Some(format!(
                    "kind={kind} peer={peer_id} generation={generation} packets={packets} bytes={bytes}"
                )),
            );
        }
    }
}
