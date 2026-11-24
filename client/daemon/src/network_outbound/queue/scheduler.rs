use super::{PendingPacket, OUTBOUND_DELIVERY_DEADLINE};
use p2pnet_tun::packet::{traffic_class, TrafficClass};
use std::collections::VecDeque;
use std::time::{Duration, Instant};

const SCHEDULE: [usize; 13] = [0, 0, 0, 0, 1, 1, 0, 0, 0, 0, 1, 1, 2];
const QUEUE_AGE: Duration = Duration::from_millis(220);

#[derive(Default)]
pub(super) struct PacketQueues {
    lanes: [VecDeque<PendingPacket>; 3],
    cursor: usize,
    pub(super) enabled: bool,
}

impl PacketQueues {
    fn lane(&self, packet: &PendingPacket) -> usize {
        if crate::transport_tuning::is_internal(packet.raw_packet()) {
            return 0;
        }
        let PendingPacket::Plain { packet: raw, .. } = packet;
        if !self.enabled || !raw.tunes_transport() {
            return 2;
        }
        match traffic_class(packet.raw_packet()) {
            TrafficClass::Control => 0,
            TrafficClass::Interactive => 1,
            TrafficClass::Bulk => 2,
        }
    }

    pub(super) fn len(&self) -> usize {
        self.lanes.iter().map(VecDeque::len).sum()
    }

    pub(super) fn is_empty(&self) -> bool {
        self.lanes.iter().all(VecDeque::is_empty)
    }

    #[cfg(test)]
    pub(super) fn iter(&self) -> impl Iterator<Item = &PendingPacket> {
        self.lanes.iter().flatten()
    }

    pub(super) fn iter_mut(&mut self) -> impl Iterator<Item = &mut PendingPacket> {
        self.lanes.iter_mut().flatten()
    }

    pub(super) fn push_back(&mut self, packet: PendingPacket) {
        let lane = self.lane(&packet);
        self.lanes[lane].push_back(packet);
    }

    pub(super) fn push_front(&mut self, packet: PendingPacket) {
        let lane = self.lane(&packet);
        self.lanes[lane].push_front(packet);
    }

    fn next(&self) -> Option<usize> {
        (0..SCHEDULE.len())
            .map(|step| (self.cursor + step) % SCHEDULE.len())
            .find(|index| !self.lanes[SCHEDULE[*index]].is_empty())
    }

    pub(super) fn front(&self) -> Option<&PendingPacket> {
        self.lanes[SCHEDULE[self.next()?]].front()
    }

    pub(super) fn pop_front(&mut self) -> Option<PendingPacket> {
        let next = self.next()?;
        self.cursor = (next + 1) % SCHEDULE.len();
        self.lanes[SCHEDULE[next]].pop_front()
    }

    pub(super) fn evict_for(&mut self, arriving: &PendingPacket) -> Option<PendingPacket> {
        let lane = self.lane(arriving);
        (lane..self.lanes.len())
            .rev()
            .find_map(|candidate| self.lanes[candidate].pop_front())
    }

    pub(super) fn is_expired(&self, packet: &PendingPacket, delivery: Option<Instant>) -> bool {
        let PendingPacket::Plain { packet: raw, .. } = packet;
        if raw.tuning_expired() {
            return true;
        }
        if !self.enabled || !raw.tunes_transport() || self.lane(packet) == 0 {
            return false;
        }
        let packet = raw;
        let Some(ready) =
            delivery.and_then(|deadline| deadline.checked_sub(OUTBOUND_DELIVERY_DEADLINE))
        else {
            return false;
        };
        // The existing startup deadline remains the authority while waiting
        // for a peer's first usable path.
        packet.trace.as_ref().is_some_and(|trace| {
            let start = ready.max(trace.tun_read_completed);
            tokio::time::Instant::now().saturating_duration_since(start.into()) > QUEUE_AGE
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        dataplane::{DataplaneTxTrace, OutboundPacket},
        network_outbound::{
            queue::PeerPendingQueue, MAX_PENDING_BYTES_PER_PEER, MAX_PENDING_PACKETS_PER_PEER,
        },
    };

    fn packet(class: usize, at: Instant) -> PendingPacket {
        let size: u16 = [64, 128, 1400][class];
        let mut ip = vec![0; usize::from(size)];
        ip[0] = 0x45;
        ip[2..4].copy_from_slice(&size.to_be_bytes());
        ip[8] = 64;
        ip[9] = if class == 0 { 1 } else { 17 };
        ip[12..20].copy_from_slice(&[10, 80, 0, 1, 10, 80, 0, 2]);
        ip[20..24].copy_from_slice(&[48, 1, 48, 2]);
        ip[24..26].copy_from_slice(&(size - 20).to_be_bytes());
        PendingPacket::plain(
            crate::request_carriage::RawRequestDelivery::from(OutboundPacket {
                room_authorization: None,
                peer_id: "selected-peer".into(),
                dst_ip: "10.80.0.2".into(),
                packet: ip,
                trace: Some(DataplaneTxTrace {
                    sampled: false,
                    tun_read_started: at,
                    tun_read_completed: at,
                    route_ready: Some(at),
                    dataplane_queue_send_started: None,
                    transport_queue_dequeued: None,
                    transport_queue_send_started: None,
                    network_queue_dequeued: None,
                }),
            })
            .mark_tun_read(),
        )
    }

    #[tokio::test(start_paused = true)]
    async fn priorities_bound_mean_and_tail_latency_with_bulk_saturation() {
        let mut queue = PeerPendingQueue::new();
        queue.queue.enabled = true;
        let start = tokio::time::Instant::now();
        let deadline = start.into_std() + OUTBOUND_DELIVERY_DEADLINE;
        let mut delays = [Vec::new(), Vec::new(), Vec::new()];
        let mut arrivals = [0; 3];
        let mut allocated = 0;
        let mut max_resident = 0;
        let mut evicted = 0;
        let mut expired = 0;
        let mut link_ready = start;
        const BYTES_PER_MS: u64 = 500;
        for tick in 0..4000 {
            let now = tokio::time::Instant::now();
            for class in [2, 2, 2]
                .into_iter()
                .chain((tick % 17 == 0).then_some(0))
                .chain((tick % 13 == 0).then_some(1))
            {
                arrivals[class] += 1;
                let (dropped, _) = queue.enqueue(packet(class, now.into_std()));
                evicted += dropped.len();
            }
            max_resident = max_resident.max(queue.queue.len());
            allocated = allocated.max(queue.bytes);
            if now >= link_ready {
                while let Some(packet) = queue.pop_front() {
                    if queue.queue.is_expired(&packet, Some(deadline)) {
                        expired += 1;
                        continue;
                    }
                    let bucket = queue.queue.lane(&packet);
                    let PendingPacket::Plain { packet, .. } = packet;
                    let trace = packet.trace.as_ref().unwrap();
                    delays[bucket].push(
                        now.duration_since(trace.tun_read_completed.into())
                            .as_micros() as u64,
                    );
                    link_ready = now
                        + Duration::from_micros(
                            (packet.payload().len() as u64 * 1000).div_ceil(BYTES_PER_MS),
                        );
                    break;
                }
            }
            tokio::time::advance(Duration::from_millis(1)).await;
        }
        assert!(
            max_resident <= MAX_PENDING_PACKETS_PER_PEER && allocated <= MAX_PENDING_BYTES_PER_PEER
        );
        assert!(evicted > 0 || expired > 0);
        assert!(delays[2].len() > 300);
        assert!(delays[0].len() + 1 >= arrivals[0] && delays[1].len() + 1 >= arrivals[1]);
        let latencies = delays.each_mut().map(|samples| {
            samples.sort_unstable();
            let mean = samples.iter().sum::<u64>() as f64 / samples.len() as f64;
            let p99 = samples[(samples.len() * 99).div_ceil(100) - 1];
            (mean, p99)
        });
        eprintln!("4 Mbit/s queue mean/P99 µs {latencies:?}, peak {max_resident} frames and {allocated} bytes, dropped {evicted}+{expired}");
        for (mean, p99) in &latencies[..2] {
            assert!(*mean < latencies[2].0 / 5.0);
            assert!(*p99 < latencies[2].1 / 5);
        }
    }

    #[tokio::test(start_paused = true)]
    async fn stale_bulk_is_discarded_after_delivery_begins() {
        let lanes = PacketQueues {
            enabled: true,
            ..PacketQueues::default()
        };
        let now = tokio::time::Instant::now();
        let bulk = packet(2, now.into_std());
        let control = packet(0, now.into_std());
        tokio::time::advance(QUEUE_AGE + Duration::from_millis(1)).await;
        assert!(!lanes.is_expired(&bulk, None));
        let delivery = Some(now.into_std() + OUTBOUND_DELIVERY_DEADLINE);
        assert!(lanes.is_expired(&bulk, delivery));
        assert!(!lanes.is_expired(&control, delivery));
    }
}
