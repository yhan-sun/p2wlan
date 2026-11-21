//! Transfer one genuine routed Echo into the existing per-peer FIFO owner.
//! No source, crypto, publication or ACK authority is fabricated here.
use super::*;

pub(crate) struct OriginalEchoQueueForTest {
    queue: Option<PeerPendingQueue>,
    peer_id: String,
    ctx: PeerWorkContext,
}

impl OriginalEchoQueueForTest {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        packet: RawRequestDelivery,
        transport: WireGuardTransport,
        peers: Arc<PeerManager>,
        prefer_direct: bool,
        udp: Arc<RwLock<Option<UdpTransport>>>,
        relay: Arc<RwLock<Option<RelayTransport>>>,
        relay_expected: bool,
        timeline: Arc<ConnectionTimeline>,
    ) -> Self {
        let mut queue = PeerPendingQueue::new();
        queue.wait_generation = Some(peers.current_network_generation_sync());
        queue.delivery_deadline = Some(Instant::now() + OUTBOUND_DELIVERY_DEADLINE);
        let peer_id = packet.peer_id.clone();
        assert!(queue.enqueue(PendingPacket::plain(packet)).0.is_empty());
        Self {
            queue: Some(queue),
            peer_id,
            ctx: PeerWorkContext {
                transport,
                peers,
                prefer_direct,
                udp_transport: udp,
                relay_transport: relay,
                startup_wait: RelayStartupWait {
                    relay_expected,
                    timeout: None,
                },
                timeline,
                stopping: Arc::new(AtomicBool::new(false)),
            },
        }
    }

    pub(crate) fn deadline(&self) -> Instant {
        self.queue.as_ref().unwrap().delivery_deadline.unwrap()
    }

    pub(crate) fn retry_after(&self) -> Option<Instant> {
        self.queue.as_ref().unwrap().retry_after
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.queue.as_ref().unwrap().queue.is_empty()
    }

    pub(crate) fn retains_exact_echo(&self, original: &RawRequestDelivery) -> bool {
        let Some(PendingPacket::Plain { packet, .. }) = self.queue.as_ref().unwrap().queue.front()
        else {
            return false;
        };
        packet.packet == original.packet
            && packet
                .original_echo()
                .zip(original.original_echo())
                .is_some_and(|(retained, source)| Arc::ptr_eq(retained, source))
            && self.queue.as_ref().unwrap().queue.len() == 1
    }

    pub(crate) async fn flush(&mut self) {
        let (_, queue) = flush_one_peer(
            self.peer_id.clone(),
            self.queue.take().unwrap(),
            self.ctx.transport.clone(),
            self.ctx.peers.clone(),
            self.ctx.prefer_direct,
            self.ctx.udp_transport.clone(),
            self.ctx.relay_transport.clone(),
            self.ctx.startup_wait.relay_expected,
            self.ctx.timeline.clone(),
        )
        .await;
        self.queue = Some(queue);
    }
}
