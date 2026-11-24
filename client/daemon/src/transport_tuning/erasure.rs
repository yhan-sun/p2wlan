use super::field;
use super::wire::{encode_parity, Parity, CHUNK, DATA, MAX_CIPHERTEXT, MAX_PARITY};
use std::{
    collections::{BTreeMap, BTreeSet, VecDeque},
    time::Duration,
};
use tokio::time::Instant;

const HOLD: Duration = Duration::from_millis(40);
const RECENT: usize = 64;
const PENDING: usize = 8;

#[derive(Default)]
pub(crate) struct Encoder {
    outstanding: Vec<(u64, Vec<u8>)>,
    rows: usize,
    started: Option<Instant>,
}

impl Encoder {
    pub(crate) fn add(
        &mut self,
        counter: u64,
        sealed: &[u8],
        rows: usize,
        now: Instant,
    ) -> Vec<Vec<u8>> {
        if rows != self.rows
            || self
                .started
                .is_some_and(|start| now.duration_since(start) >= HOLD)
            || self
                .outstanding
                .last()
                .is_some_and(|(last, _)| *last >= counter)
        {
            self.outstanding.clear();
            self.started = None;
            self.rows = rows;
        }
        if rows == 0 || !(32..=MAX_CIPHERTEXT).contains(&sealed.len()) {
            return Vec::new();
        }
        self.started.get_or_insert(now);
        self.outstanding.push((counter, sealed.to_vec()));
        if self.outstanding.len() != DATA {
            return Vec::new();
        }
        self.started = None;
        self.encode()
    }

    fn encode(&mut self) -> Vec<Vec<u8>> {
        let mut ids = [0u64; DATA];
        let mut lengths = [0usize; DATA];
        let width = self
            .outstanding
            .iter()
            .map(|(_, data)| data.len())
            .max()
            .unwrap_or(0);
        for (index, (counter, packet)) in self.outstanding.iter().enumerate() {
            ids[index] = *counter;
            lengths[index] = packet.len();
        }
        let mut records = Vec::with_capacity(self.rows * width.div_ceil(CHUNK));
        let mut shard = vec![0; width];
        for row in 0..self.rows {
            shard.fill(0);
            for (column, (_, data)) in self.outstanding.iter().enumerate() {
                field::accumulate(self.rows, row, column, data, &mut shard);
            }
            for (index, data) in shard.chunks(CHUNK).enumerate() {
                records.push(encode_parity(Parity {
                    ids,
                    lengths,
                    rows: self.rows,
                    row,
                    offset: index * CHUNK,
                    data,
                }));
            }
        }
        self.outstanding.clear();
        records
    }
}

struct Shard {
    bytes: Vec<u8>,
    collected: u8,
    length: usize,
}

struct Block {
    ids: [u64; DATA],
    lengths: [usize; DATA],
    width: usize,
    rows: usize,
    shares: [Option<Shard>; MAX_PARITY],
    expires: Instant,
}

#[derive(Default)]
pub(crate) struct Recovery {
    received: BTreeMap<u64, Vec<u8>>,
    reconstructed: BTreeSet<u64>,
    outstanding: VecDeque<Block>,
}

impl Recovery {
    pub(crate) fn add(&mut self, counter: u64, bytes: Vec<u8>, now: Instant) -> Vec<Vec<u8>> {
        if (32..=MAX_CIPHERTEXT).contains(&bytes.len()) {
            self.cache(counter, bytes);
        }
        self.recover(now)
    }

    pub(crate) fn parity(&mut self, share: Parity<'_>, now: Instant) -> Vec<Vec<u8>> {
        self.outstanding.retain(|block| now < block.expires);
        let index = self
            .outstanding
            .iter()
            .position(|block| block.ids[0] == share.ids[0]);
        let block = match index {
            Some(index) => &mut self.outstanding[index],
            None if self.outstanding.len() < PENDING => {
                let width = share.lengths.into_iter().max().unwrap_or(0);
                self.outstanding.push_back(Block {
                    ids: share.ids,
                    lengths: share.lengths,
                    width,
                    rows: share.rows,
                    shares: std::array::from_fn(|_| None),
                    expires: now + HOLD,
                });
                let Some(block) = self.outstanding.back_mut() else {
                    return Vec::new();
                };
                block
            }
            None => return Vec::new(),
        };
        if block.ids != share.ids || block.lengths != share.lengths || block.rows != share.rows {
            return Vec::new();
        }
        let shard = block.shares[share.row].get_or_insert_with(|| Shard {
            bytes: vec![0; block.width],
            collected: 0,
            length: 0,
        });
        let bit = 1u8 << (share.offset / CHUNK);
        if shard.collected & bit == 0 {
            shard.collected |= bit;
            shard.bytes[share.offset..share.offset + share.data.len()].copy_from_slice(share.data);
            shard.length += share.data.len();
        }
        self.recover(now)
    }

    pub(crate) fn authenticated_recovery(&mut self, counter: u64, wire: &[u8]) {
        if self
            .received
            .get(&counter)
            .is_some_and(|stored| stored == wire)
        {
            self.reconstructed.insert(counter);
        }
    }

    pub(crate) fn late_original(&mut self, counter: u64, wire: &[u8]) -> bool {
        self.received
            .get(&counter)
            .is_some_and(|stored| stored == wire)
            && self.reconstructed.remove(&counter)
    }

    fn cache(&mut self, counter: u64, packet: Vec<u8>) {
        self.received.entry(counter).or_insert(packet);
        if self.received.len() > RECENT {
            if let Some((oldest, _)) = self.received.pop_first() {
                self.reconstructed.remove(&oldest);
            }
        }
    }

    fn recover(&mut self, now: Instant) -> Vec<Vec<u8>> {
        let mut recovered = Vec::new();
        let mut index = 0;
        while index < self.outstanding.len() {
            let block = &self.outstanding[index];
            if now >= block.expires {
                self.outstanding.remove(index);
                continue;
            }
            let originals = block
                .ids
                .iter()
                .filter(|id| self.received.contains_key(id))
                .count();
            if originals == DATA {
                self.outstanding.remove(index);
                continue;
            }
            let parity = block
                .shares
                .iter()
                .flatten()
                .filter(|shard| shard.length == block.width)
                .count();
            if originals + parity < DATA {
                index += 1;
                continue;
            }
            let Some(block) = self.outstanding.remove(index) else {
                break;
            };
            for (counter, packet) in block.recover(&self.received) {
                self.cache(counter, packet.clone());
                recovered.push(packet);
            }
        }
        recovered
    }
}

impl Block {
    fn recover(self, received: &BTreeMap<u64, Vec<u8>>) -> Vec<(u64, Vec<u8>)> {
        let shards = std::array::from_fn(|index| {
            received
                .get(&self.ids[index])
                .filter(|data| data.len() == self.lengths[index])
                .map(Vec::as_slice)
        });
        let parity = self.shares.map(|share| {
            share
                .filter(|part| part.length == self.width)
                .map(|part| part.bytes)
        });
        field::restore(self.rows, shards, parity, self.width)
            .into_iter()
            .enumerate()
            .filter_map(|(index, shard)| {
                let mut bytes = shard?;
                let counter = u64::from_le_bytes(bytes.get(8..16)?.try_into().ok()?);
                if counter != self.ids[index] {
                    return None;
                }
                bytes.truncate(self.lengths[index]);
                Some((counter, bytes))
            })
            .collect()
    }
}
