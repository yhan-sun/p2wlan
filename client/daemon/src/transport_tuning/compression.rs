use super::wire;
use lz4_flex::block;
use std::time::Duration;
use tokio::time::Instant;

const COOL_DOWN: Duration = Duration::from_secs(2);
const LOW_SAVINGS_LIMIT: u8 = 4;
const MAX_PLAINTEXT: usize = 65503;

#[derive(Default)]
pub(crate) struct Compression {
    low_savings: u8,
    retry_at: Option<Instant>,
    scratch: Vec<u8>,
}

impl Compression {
    pub(crate) fn should_try(&self, length: usize, now: Instant) -> bool {
        (128..=MAX_PLAINTEXT).contains(&length) && self.retry_at.is_none_or(|until| now >= until)
    }

    pub(crate) fn encode(&mut self, packet: &[u8], now: Instant) -> Option<Vec<u8>> {
        if !self.should_try(packet.len(), now) {
            return None;
        }
        self.scratch
            .resize(block::get_maximum_output_size(packet.len()), 0);
        let size = block::compress_into(packet, &mut self.scratch).ok()?;
        if (size + wire::COMPRESSED_OVERHEAD) * 100 > packet.len() * 92 {
            self.low_savings += 1;
            if self.low_savings >= LOW_SAVINGS_LIMIT {
                self.retry_at = Some(now + COOL_DOWN);
                self.low_savings = 0;
            }
            return None;
        }
        self.low_savings = 0;
        let mut encoded = wire::envelope(1, 2 + size);
        encoded.extend_from_slice(&(packet.len() as u16).to_be_bytes());
        encoded.extend_from_slice(&self.scratch[..size]);
        Some(encoded)
    }

    pub(crate) fn decode(length: usize, block: &[u8]) -> Option<Vec<u8>> {
        if !(128..=MAX_PLAINTEXT).contains(&length) || block.len() >= length {
            return None;
        }
        let mut decoded = vec![0u8; length];
        if block::decompress_into(block, &mut decoded).ok()? != length {
            return None;
        }
        let ip = p2pnet_tun::IpPacket::new(&decoded).ok()?;
        (ip.total_len() == decoded.len()).then_some(decoded)
    }
}
