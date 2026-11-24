use super::{
    compression::Compression,
    erasure::{Encoder, Recovery},
    loss::Loss,
    wire::{self, Message},
};
use crate::{
    config::{CompressionMode, FecMode, TransportConfig},
    peer::ActiveBusinessPath,
    rooms::RoomSendPermit,
};
use std::{
    collections::HashMap,
    net::SocketAddr,
    sync::{atomic::AtomicU64, Mutex},
    time::Duration,
};
use tokio::time::Instant;

const MAX_PEERS: usize = 128;
const HELLO_INTERVAL: Duration = Duration::from_secs(2);

#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) struct SessionKey {
    pub(crate) generation: u64,
    pub(crate) instance: u64,
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) struct IngressKey {
    pub(crate) relay: Option<u64>,
    pub(crate) socket_owner: Option<u64>,
    pub(crate) socket_index: Option<usize>,
    pub(crate) address: Option<SocketAddr>,
}

struct Peer {
    key: SessionKey,
    touched: Instant,
    supports: bool,
    sent_hello: Option<Instant>,
    hello_attempts: u8,
    fixed_receive: bool,
    peer_accepts_fec: bool,
    tx_loss: Loss,
    rx_loss: Loss,
    encoding_path: Option<ActiveBusinessPath>,
    encoding_start: u64,
    encoder_last_counter: u64,
    last_feedback_counter: Option<u64>,
    encoding_room: Option<RoomSendPermit>,
    ingress: Option<IngressKey>,
    compression: Compression,
    encoder: Encoder,
    recovery: Recovery,
}

impl Peer {
    fn new(key: SessionKey, now: Instant) -> Self {
        Self {
            key,
            touched: now,
            supports: false,
            sent_hello: None,
            hello_attempts: 0,
            fixed_receive: false,
            peer_accepts_fec: false,
            tx_loss: Loss::default(),
            rx_loss: Loss::default(),
            encoding_path: None,
            encoding_start: 0,
            encoder_last_counter: 0,
            last_feedback_counter: None,
            encoding_room: None,
            ingress: None,
            compression: Compression::default(),
            encoder: Encoder::default(),
            recovery: Recovery::default(),
        }
    }
}

#[derive(Default)]
pub(crate) struct Tuning {
    peers: Mutex<HashMap<String, Peer>>,
    pub(crate) pooled_tx_packets: AtomicU64,
    pub(crate) pooled_rx_packets: AtomicU64,
    pub(crate) compressed_saved_bytes: AtomicU64,
    pub(crate) compressed_original_bytes: AtomicU64,
    rates: Mutex<HashMap<String, RateSample>>,
    pub(crate) fec_recovered: AtomicU64,
    pub(crate) fec_parity_queued: AtomicU64,
    pub(crate) replay_rejected: AtomicU64,
}

struct RateSample {
    at: Instant,
    tx: u64,
    rx: u64,
    tx_bps: u64,
    rx_bps: u64,
}

#[derive(Default)]
pub(crate) struct Input {
    pub(crate) record: Option<Vec<u8>>,
    pub(crate) path_loss: Option<(ActiveBusinessPath, u16)>,
    pub(crate) recovered: Vec<Vec<u8>>,
}

impl Tuning {
    fn with_peer<R>(
        &self,
        id: &str,
        key: SessionKey,
        now: Instant,
        operation: impl FnOnce(&mut Peer) -> R,
    ) -> Option<R> {
        let mut peers = self.peers.lock().unwrap_or_else(|error| error.into_inner());
        if !peers.contains_key(id) {
            if peers.len() >= MAX_PEERS {
                let oldest = peers
                    .iter()
                    .min_by_key(|(_, peer)| peer.touched)
                    .map(|(id, _)| id.clone())?;
                peers.remove(&oldest);
            }
            peers.insert(id.to_owned(), Peer::new(key, now));
        }
        let peer = peers.get_mut(id)?;
        if peer.key != key {
            if key.generation < peer.key.generation
                || (key.generation == peer.key.generation && key.instance < peer.key.instance)
            {
                return None;
            }
            *peer = Peer::new(key, now);
        }
        peer.touched = now;
        Some(operation(peer))
    }

    pub(crate) fn needs_tuning(
        &self,
        id: &str,
        key: SessionKey,
        length: usize,
        config: &TransportConfig,
    ) -> bool {
        if config.fec_mode == FecMode::Off && config.compression == CompressionMode::Off {
            return false;
        }
        let now = Instant::now();
        let peers = self.peers.lock().unwrap_or_else(|error| error.into_inner());
        let Some(peer) = peers.get(id).filter(|peer| peer.key == key) else {
            return true;
        };
        if !peer.supports {
            return hello_due(peer, now);
        }
        (peer.peer_accepts_fec && peer.tx_loss.rows(config.fec_mode, now) != 0)
            || (config.compression == CompressionMode::Auto
                && peer.compression.should_try(length, now))
    }

    pub(crate) fn compress(&self, id: &str, key: SessionKey, packet: &[u8]) -> Option<Vec<u8>> {
        let mut peers = self.peers.lock().unwrap_or_else(|error| error.into_inner());
        let peer = peers.get_mut(id)?;
        if peer.key != key || !peer.supports {
            return None;
        }
        peer.compression.encode(packet, Instant::now())
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn sent(
        &self,
        id: &str,
        key: SessionKey,
        path: Option<ActiveBusinessPath>,
        room: Option<RoomSendPermit>,
        counter: u64,
        wire: &[u8],
        config: &TransportConfig,
    ) -> Vec<Vec<u8>> {
        if config.fec_mode == FecMode::Off && config.compression == CompressionMode::Off {
            return Vec::new();
        }
        let now = Instant::now();
        self.with_peer(id, key, now, |peer| {
            mark_send_path(peer, path, counter);
            if peer.encoding_room != room {
                peer.encoder = Encoder::default();
                peer.encoding_room = room;
            }
            if !peer.supports {
                if hello_due(peer, now) {
                    peer.hello_attempts = peer.hello_attempts.saturating_add(1);
                    peer.sent_hello = Some(now);
                    return vec![wire::hello(
                        false,
                        fixed(config.fec_mode),
                        config.fec_mode != FecMode::Off,
                    )];
                }
                return Vec::new();
            }
            let rows = if peer.peer_accepts_fec {
                peer.tx_loss.rows(config.fec_mode, now)
            } else {
                0
            };
            peer.encoder.add(counter, wire, rows, now)
        })
        .unwrap_or_default()
    }

    pub(crate) fn sent_unmodified(
        &self,
        id: &str,
        key: SessionKey,
        current_path: Option<ActiveBusinessPath>,
        counter: u64,
    ) {
        self.with_peer(id, key, Instant::now(), |peer| {
            mark_send_path(peer, current_path, counter)
        });
    }

    pub(crate) fn needs_wire_copy(
        &self,
        id: &str,
        key: SessionKey,
        config: &TransportConfig,
    ) -> bool {
        config.fec_mode != FecMode::Off
            && self
                .peers
                .lock()
                .unwrap_or_else(|error| error.into_inner())
                .get(id)
                .is_some_and(|peer| {
                    peer.key == key
                        && peer.supports
                        && (peer.fixed_receive || peer.rx_loss.estimate() >= 0.007)
                })
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn input(
        &self,
        id: &str,
        key: SessionKey,
        path: IngressKey,
        message: Option<Message<'_>>,
        counter: u64,
        wire: Option<&[u8]>,
        config: &TransportConfig,
    ) -> Input {
        let now = Instant::now();
        self.with_peer(id, key, now, |peer| {
            let mut input = Input::default();
            if let Some(Message::Hello {
                acknowledgement,
                fixed_fec,
                accept_fec,
            }) = message
            {
                peer.supports = true;
                peer.fixed_receive = fixed_fec;
                peer.peer_accepts_fec = accept_fec;
                if !acknowledgement {
                    input.record = Some(wire::hello(
                        true,
                        fixed(config.fec_mode),
                        config.fec_mode != FecMode::Off,
                    ));
                }
                return input;
            }
            if !peer.supports {
                return input;
            }
            if peer.ingress != Some(path) {
                peer.rx_loss = Loss::default();
                peer.recovery = Recovery::default();
                peer.ingress = Some(path);
            }
            if let Some(Message::Feedback {
                loss_bp,
                through_counter,
            }) = message
            {
                if through_counter >= peer.encoding_start.saturating_add(32)
                    && through_counter <= peer.encoder_last_counter.saturating_add(64)
                    && peer
                        .last_feedback_counter
                        .is_none_or(|last| through_counter > last)
                {
                    peer.last_feedback_counter = Some(through_counter);
                    peer.tx_loss.receive_feedback(loss_bp, now);
                    input.path_loss = peer.encoding_path.clone().map(|path| (path, loss_bp));
                }
            }
            if config.fec_mode != FecMode::Off {
                if let Some(loss) = peer.rx_loss.observe(counter, now) {
                    input.record = Some(wire::encode_feedback(loss, counter));
                }
            }
            match message {
                Some(Message::Parity(share)) if config.fec_mode != FecMode::Off => {
                    input.recovered = peer.recovery.parity(share, now);
                }
                None | Some(Message::Compressed { .. })
                    if config.fec_mode != FecMode::Off
                        && (peer.fixed_receive || peer.rx_loss.estimate() >= 0.007) =>
                {
                    if let Some(wire) = wire {
                        input.recovered = peer.recovery.add(counter, wire.to_vec(), now);
                    }
                }
                _ => {}
            }
            input
        })
        .unwrap_or_default()
    }

    pub(crate) fn authenticated_recovery(
        &self,
        id: &str,
        key: SessionKey,
        counter: u64,
        wire: &[u8],
    ) {
        let mut peers = self.peers.lock().unwrap_or_else(|error| error.into_inner());
        if let Some(peer) = peers.get_mut(id).filter(|peer| peer.key == key) {
            peer.recovery.authenticated_recovery(counter, wire);
        }
    }

    /// A delayed original can name a previously reconstructed counter. Match
    /// its complete authenticated wire bytes before using it as a loss sample.
    pub(crate) fn late_original(
        &self,
        generation: u64,
        path: IngressKey,
        counter: u64,
        wire: &[u8],
    ) -> Option<(String, SessionKey, Vec<u8>)> {
        let mut peers = self.peers.lock().unwrap_or_else(|error| error.into_inner());
        for (id, peer) in peers.iter_mut() {
            if peer.key.generation == generation
                && peer.ingress == Some(path)
                && peer.recovery.late_original(counter, wire)
            {
                return peer
                    .rx_loss
                    .observe(counter, Instant::now())
                    .map(|loss| (id.clone(), peer.key, wire::encode_feedback(loss, counter)));
            }
        }
        None
    }

    pub(crate) fn rate(&self, id: &str, tx: u64, rx: u64) -> (u64, u64) {
        let now = Instant::now();
        let mut rates = self.rates.lock().unwrap_or_else(|error| error.into_inner());
        if rates.len() >= MAX_PEERS && !rates.contains_key(id) {
            if let Some(oldest) = rates
                .iter()
                .min_by_key(|(_, sample)| sample.at)
                .map(|(id, _)| id.clone())
            {
                rates.remove(&oldest);
            }
        }
        let sample = rates.entry(id.to_owned()).or_insert(RateSample {
            at: now,
            tx,
            rx,
            tx_bps: 0,
            rx_bps: 0,
        });
        let elapsed = now.duration_since(sample.at);
        if elapsed >= Duration::from_secs(1) {
            let bps = |new: u64, old: u64| {
                let bits = f64::from(8) * new.saturating_sub(old) as f64;
                (bits / elapsed.as_secs_f64()) as u64
            };
            *sample = RateSample {
                at: now,
                tx,
                rx,
                tx_bps: bps(tx, sample.tx),
                rx_bps: bps(rx, sample.rx),
            };
        }
        (sample.tx_bps, sample.rx_bps)
    }

    pub(crate) fn peer_metrics(
        &self,
        id: &str,
        generation: u64,
        configured: FecMode,
    ) -> (f64, &'static str) {
        let peers = self.peers.lock().unwrap_or_else(|error| error.into_inner());
        peers
            .get(id)
            .filter(|peer| peer.supports && peer.key.generation == generation)
            .map_or((0.0, "off"), |peer| {
                let rows = peer.tx_loss.rows(configured, Instant::now());
                (
                    peer.rx_loss.estimate(),
                    match rows {
                        1 => "light",
                        3 => "strong",
                        _ => "off",
                    },
                )
            })
    }
}

fn mark_send_path(peer: &mut Peer, path: Option<ActiveBusinessPath>, counter: u64) {
    if peer.encoding_path != path {
        peer.tx_loss = Loss::default();
        peer.encoding_start = counter;
        peer.last_feedback_counter = None;
        peer.encoder = Encoder::default();
        peer.encoding_path = path;
    }
    peer.encoder_last_counter = counter;
}

fn hello_due(peer: &Peer, now: Instant) -> bool {
    let interval = if peer.hello_attempts < 3 {
        HELLO_INTERVAL
    } else {
        Duration::from_secs(60)
    };
    peer.sent_hello
        .is_none_or(|when| now.duration_since(when) >= interval)
}

fn fixed(mode: FecMode) -> bool {
    matches!(mode, FecMode::Light | FecMode::Strong)
}
