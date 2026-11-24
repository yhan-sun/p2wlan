use super::*;
use crate::config::TransportConfig;
use p2pnet_crypto::NodeIdentity;
use p2pnet_wireguard::{HandshakeInitiator, HandshakeResponder, TransportSession};
use std::{collections::BTreeMap, num::NonZeroUsize, time::Duration};

const KEY: SessionKey = SessionKey {
    generation: 7,
    instance: 19,
};
const PATH: IngressKey = IngressKey {
    relay: None,
    socket_owner: Some(2),
    socket_index: Some(1),
    address: None,
};
const PEER: &str = "test-peer";

fn sessions() -> (TransportSession, TransportSession) {
    let first = NodeIdentity::generate();
    let second = NodeIdentity::generate();
    let mut a = HandshakeInitiator::new(first, second.public_key(), None);
    let mut b = HandshakeResponder::new(second, None);
    let offer = a.create_initiation().unwrap();
    let (answer, b) = b.consume_initiation_and_respond(&offer).unwrap();
    let a = a.consume_response(&answer).unwrap();
    (TransportSession::new(a), TransportSession::new(b))
}

#[derive(Clone, Copy)]
enum LossModel {
    Healthy,
    FixedEvery(NonZeroUsize),
    RandomPercent(u8),
    Bursty,
}

struct Link {
    random: u64,
    impaired: bool,
    phase: LossModel,
    arrived_originals: usize,
    serial: u64,
    mtu: usize,
    bytes_per_tick: Option<NonZeroUsize>,
    next_link_tick: u64,
    tick: u64,
    packets: BTreeMap<(u64, u64), Vec<u8>>,
}

impl Link {
    fn new() -> Self {
        Self {
            random: 0x612e_ccba_d994_59a3,
            impaired: false,
            phase: LossModel::Healthy,
            arrived_originals: 0,
            serial: 0,
            mtu: usize::MAX,
            bytes_per_tick: None,
            next_link_tick: 0,
            tick: 0,
            packets: BTreeMap::new(),
        }
    }

    fn draw(&mut self, max: u64) -> u64 {
        let mut x = self.random;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.random = x;
        x % max
    }

    fn send(&mut self, wire: Vec<u8>, original: bool) {
        let drop_packet = match self.phase {
            LossModel::Healthy => false,
            LossModel::FixedEvery(period) => (self.serial + 1).is_multiple_of(period.get() as u64),
            LossModel::RandomPercent(percent) => self.draw(100) < u64::from(percent),
            LossModel::Bursty => {
                // Stationary loss about 9%, with correlated misses in a bad state.
                let transition = self.draw(100);
                self.impaired = if self.impaired {
                    transition >= 34
                } else {
                    transition < 5
                };
                self.draw(100) < if self.impaired { 59 } else { 2 }
            }
        };
        self.serial += 1;
        let jitter = self.draw(7);
        if drop_packet || wire.len().saturating_add(28) > self.mtu {
            return;
        }
        let start = self.tick.max(self.next_link_tick);
        if let Some(rate) = self.bytes_per_tick {
            self.next_link_tick = start + wire.len().div_ceil(rate.get()) as u64;
        }
        let earliest = start + 1 + jitter;
        self.arrived_originals += usize::from(original);
        self.packets.insert((earliest, self.serial), wire);
    }

    fn next(&mut self) -> Option<Vec<u8>> {
        if self.packets.first_key_value()?.0 .0 > self.tick {
            return None;
        }
        self.packets.pop_first().map(|(_, wire)| wire)
    }
}

fn ip_packet(index: u64, length: u16) -> Vec<u8> {
    let mut packet = vec![0; usize::from(length)];
    packet[0] = 0x45;
    packet[2..4].copy_from_slice(&length.to_be_bytes());
    packet[8] = 64;
    packet[9] = 17;
    packet[12..20].copy_from_slice(&[10, 3, 0, 1, 10, 3, 0, 2]);
    packet[28..36].copy_from_slice(&index.to_be_bytes());
    packet[36..].fill(index as u8);
    packet
}

struct Exchange {
    tx: Tuning,
    rx: Tuning,
    sender: TransportSession,
    receiver: TransportSession,
    config: TransportConfig,
    link: Link,
    received: Vec<bool>,
    raw_received: usize,
    fec_received: usize,
    parity: usize,
    length: u16,
}

impl Exchange {
    fn new(length: u16, count: usize) -> Self {
        let (sender, receiver) = sessions();
        Self {
            tx: Tuning::default(),
            rx: Tuning::default(),
            sender,
            receiver,
            config: TransportConfig::default(),
            link: Link::new(),
            received: vec![false; count],
            raw_received: 0,
            fec_received: 0,
            parity: 0,
            length,
        }
    }

    fn submit(&mut self, index: usize) {
        let ip = ip_packet(index as u64, self.length);
        let counter = self.sender.send_counter();
        let wire = self.sender.encrypt_to_bytes(&ip).unwrap();
        let records = self
            .tx
            .sent(PEER, KEY, None, None, counter, &wire, &self.config);
        self.link.send(wire, true);
        for record in records {
            self.parity += usize::from(matches!(decode(&record), Some(Message::Parity(_))));
            self.link
                .send(self.sender.encrypt_to_bytes(&record).unwrap(), false);
        }
    }

    fn deliver(&mut self) {
        while let Some(wire) = self.link.next() {
            let counter = crate::transport::wire_counter(&wire).unwrap();
            let opened = match self.receiver.decrypt_from_bytes(&wire) {
                Ok(packet) => packet,
                Err(p2pnet_wireguard::WireGuardError::ReplayDetected(_)) => {
                    if let Some((_, _, feedback)) =
                        self.rx.late_original(KEY.generation, PATH, counter, &wire)
                    {
                        self.feedback(&feedback);
                    }
                    continue;
                }
                Err(error) => panic!("{error}"),
            };
            let message = decode(&opened);
            let input = self
                .rx
                .input(PEER, KEY, PATH, message, counter, Some(&wire), &self.config);
            if let Some(record) = input.record {
                self.feedback(&record);
            }
            if message.is_none() {
                self.record(&opened, false);
            }
            for recovered in input.recovered {
                match self.receiver.decrypt_from_bytes(&recovered) {
                    Ok(plain) => {
                        self.rx.authenticated_recovery(
                            PEER,
                            KEY,
                            crate::transport::wire_counter(&recovered).unwrap(),
                            &recovered,
                        );
                        self.record(&plain, true);
                    }
                    Err(p2pnet_wireguard::WireGuardError::ReplayDetected(_)) => {}
                    Err(error) => {
                        panic!("FEC produced ciphertext that failed authentication: {error}")
                    }
                }
            }
        }
    }

    fn feedback(&mut self, record: &[u8]) {
        let counter = self.receiver.send_counter();
        let return_wire = self.receiver.encrypt_to_bytes(record).unwrap();
        let reported = self.sender.decrypt_from_bytes(&return_wire).unwrap();
        self.tx.input(
            PEER,
            KEY,
            PATH,
            decode(&reported),
            counter,
            Some(&return_wire),
            &self.config,
        );
    }

    fn record(&mut self, packet: &[u8], fec: bool) {
        let index = u64::from_be_bytes(packet[28..36].try_into().unwrap()) as usize;
        assert_eq!(
            packet,
            ip_packet(index as u64, self.length),
            "payload integrity"
        );
        assert!(
            !std::mem::replace(&mut self.received[index], true),
            "replay passed"
        );
        if fec {
            self.fec_received += 1;
        } else {
            self.raw_received += 1;
        }
    }

    async fn tick(&mut self) {
        self.link.tick += 1;
        tokio::time::advance(Duration::from_millis(1)).await;
        self.deliver();
    }

    async fn send_range(&mut self, indices: std::ops::Range<usize>) {
        for index in indices {
            self.submit(index);
            self.tick().await;
        }
        for _ in 0..8 {
            self.tick().await;
        }
    }
}

#[test]
fn fixed_loss_queueing_and_mtu_blackhole_are_deterministic() {
    let mut link = Link::new();
    link.phase = LossModel::FixedEvery(NonZeroUsize::new(20).unwrap());
    link.bytes_per_tick = NonZeroUsize::new(500);
    link.mtu = 1340;
    let too_large = vec![0; 1313];
    link.send(too_large, false);
    for _ in 0..999 {
        link.send(vec![0; 1200], true);
    }
    assert_eq!(link.arrived_originals, 949);
    assert_eq!(link.packets.len(), 949);
    let end = link.packets.last_key_value().unwrap().0 .0;
    assert!(end >= 2845);
    link.tick = end;
    assert_eq!(std::iter::from_fn(|| link.next()).count(), 949);
}

#[tokio::test(start_paused = true)]
async fn adaptive_fec_authenticates_recovery_and_retires_parity_on_a_healthy_path() {
    const WARM: usize = 500;
    const SAMPLE: usize = 18_000;
    const COOL: usize = 3000;
    for (name, model, threshold) in [
        ("random 10%", LossModel::RandomPercent(10), 0.97),
        ("Gilbert–Elliott", LossModel::Bursty, 0.97),
    ] {
        let mut link = Exchange::new(800, WARM + SAMPLE + COOL * 2);
        link.send_range(0..WARM).await;
        assert_eq!(link.parity, 0);
        assert_eq!(link.raw_received, WARM);
        link.link.phase = model;
        link.send_range(WARM..WARM + SAMPLE).await;
        let raw = (link.link.arrived_originals - WARM) as f64 / SAMPLE as f64;
        let recovered = (link.raw_received + link.fec_received - WARM) as f64 / SAMPLE as f64;
        eprintln!(
            "{name}: unprotected={raw:.4} delivered={recovered:.4} recovered_packets={} parity={}",
            link.fec_received, link.parity
        );
        assert!(link.parity > 0);
        assert!(recovered >= threshold && recovered > raw + 0.025);
        link.link.phase = LossModel::Healthy;
        link.send_range(WARM + SAMPLE..WARM + SAMPLE + COOL).await;
        let stable_parity = link.parity;
        assert_eq!(
            link.tx
                .peer_metrics(PEER, KEY.generation, link.config.fec_mode)
                .1,
            "off"
        );
        link.send_range(WARM + SAMPLE + COOL..WARM + SAMPLE + COOL * 2)
            .await;
        assert_eq!(link.parity, stable_parity);
    }
}

#[tokio::test(start_paused = true)]
async fn lz4_roundtrips_ip_skips_small_packets_and_suspends_incompressible_flow() {
    let mut encoder = Compression::default();
    let now = tokio::time::Instant::now();
    let packet = ip_packet(16, 1400);
    let compressed = encoder.encode(&packet, now).unwrap();
    assert!(compressed.len() < packet.len() / 4);
    let Some(Message::Compressed { length, data }) = decode(&compressed) else {
        panic!("expected compressed packet")
    };
    assert_eq!(Compression::decode(length, data).unwrap(), packet);
    assert!(encoder.encode(&ip_packet(1, 100), now).is_none());
    let mut link = Link::new();
    let mut entropy = packet.clone();
    for byte in &mut entropy[20..] {
        *byte = link.draw(256) as u8;
    }
    let copy = entropy.clone();
    for _ in 0..4 {
        assert!(encoder.encode(&entropy, now).is_none());
    }
    assert_eq!(entropy, copy);
    assert!(!encoder.should_try(packet.len(), now));
    assert!(encoder.encode(&packet, now).is_none());
    tokio::time::advance(Duration::from_secs(2)).await;
    assert!(encoder
        .encode(&packet, tokio::time::Instant::now())
        .is_some());
    eprintln!(
        "LZ4 translated {} into {} bytes",
        packet.len(),
        compressed.len()
    );
}

#[tokio::test(start_paused = true)]
async fn inbound_actor_authenticates_recovered_fragments_and_counts_replays() {
    use crate::{
        config::Config,
        control::PeerInfo,
        peer::PeerManager,
        transport::{ReceivedEncryptedPacket, WireGuardTransport},
    };
    use std::sync::{atomic::Ordering, Arc};
    use tokio::sync::mpsc;

    let mut config = Config::generate_default("https://control.invalid", "test-net").unwrap();
    config.transport.fec_mode = crate::config::FecMode::Strong;
    let peers = Arc::new(PeerManager::new(config));
    peers
        .add_peer(&PeerInfo {
            capabilities: Default::default(),
            registration_seq: 0,
            node_id: PEER.into(),
            virtual_ip: "10.3.0.1".into(),
            device_name: "Sender".into(),
            app_version: String::new(),
            public_key: "test-session".into(),
            endpoint: "127.0.0.1:1234".into(),
            nat_type: "Unknown".into(),
            online: true,
            last_seen: 0,
            relay_rtt_ms: None,
        })
        .await;

    let (mut sender, receiver) = sessions();
    let (transport, _outbound) = WireGuardTransport::new();
    let _ = transport.add_session(PEER, receiver).await;
    let generation = peers.current_network_generation_sync();
    let (wire_tx, wire_rx) = mpsc::channel(32);
    let (tun_tx, mut tun_rx) = mpsc::channel(16);
    let worker = tokio::spawn({
        let peers = peers.clone();
        async move {
            transport
                .run_inbound_with_peers(wire_rx, tun_tx, Some(peers), None)
                .await
        }
    });
    let envelope = |wire_bytes| ReceivedEncryptedPacket {
        source: None,
        local_endpoint: None,
        relay_endpoint: Some("tls://127.0.0.1:1234".into()),
        relay_connection_id: Some(3),
        relay_peer_id: Some(PEER.into()),
        socket_index: None,
        direct_socket: None,
        udp_transport_owner: None,
        network_generation: Some(generation),
        profile_sampled: false,
        udp_received: None,
        transport_queue_send_started: None,
        wire_bytes,
        physical_ingress: None,
        original_relay_read: None,
        original_udp_read: None,
    };
    let hello = sender
        .encrypt_to_bytes(&wire::hello(false, true, true))
        .unwrap();
    wire_tx.send(envelope(hello)).await.unwrap();

    let mut encoder = super::erasure::Encoder::default();
    let mut originals = Vec::new();
    let mut parity = Vec::new();
    for index in 0..wire::DATA {
        let counter = sender.send_counter();
        let wire = sender
            .encrypt_to_bytes(&ip_packet(index as u64, 1300))
            .unwrap();
        parity.extend(encoder.add(counter, &wire, 3, tokio::time::Instant::now()));
        originals.push(wire);
    }
    for (index, frame) in originals.iter().enumerate() {
        assert_eq!(frame.len(), 1332);
        if !matches!(index, 1 | 3) {
            wire_tx.send(envelope(frame.clone())).await.unwrap();
        }
    }
    assert_eq!(parity.len(), 6);
    for record in parity {
        let wire = sender.encrypt_to_bytes(&record).unwrap();
        wire_tx.send(envelope(wire)).await.unwrap();
    }
    // Identical bytes of a now-recovered packet are a replay at TUN delivery.
    wire_tx.send(envelope(originals[1].clone())).await.unwrap();
    drop(wire_tx);
    worker.await.unwrap().unwrap();
    let mut packets = Vec::new();
    while let Some(delivered) = tun_rx.recv().await {
        assert_eq!(delivered.peer_id, PEER);
        packets.push(delivered.packet);
    }
    packets.sort_unstable();
    let mut expected: Vec<_> = (0..wire::DATA)
        .map(|index| ip_packet(index as u64, 1300))
        .collect();
    expected.sort_unstable();
    assert_eq!(packets, expected);
    assert_eq!(peers.tuning().fec_recovered.load(Ordering::Relaxed), 2);
    assert_eq!(peers.tuning().replay_rejected.load(Ordering::Relaxed), 1);
}
