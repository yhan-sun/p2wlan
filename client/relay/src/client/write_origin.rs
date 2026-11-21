// Neutral fact captured only by the two original successful Forward writers.
// It certifies local application write completion, not remote/current ownership.

use super::{ClientCommand, RelayClient};
use std::time::Instant;
use tokio::sync::mpsc;

/// Opaque local full Forward-frame write on the original command channel.
///
/// The original general and legacy writers create this only after their actual
/// write helper returns Ok. It does not prove NIC transmission, relay forwarding,
/// peer receipt/decryption, causal ACK, or current transport/owner eligibility.
pub struct OriginalRelayWriteFact {
    writer: mpsc::WeakSender<ClientCommand>,
    destination: String,
    data_len: usize,
    encoded_frame_len: usize,
    write_started_at: Instant,
    completed_at: Instant,
}

impl OriginalRelayWriteFact {
    // Only the original two writer success arms call this private factory.
    pub(super) fn completed(
        writer: &mpsc::WeakSender<ClientCommand>,
        destination: String,
        data_len: usize,
        encoded_frame_len: usize,
        write_started_at: Instant,
        completed_at: Instant,
    ) -> Self {
        Self {
            writer: writer.clone(),
            destination,
            data_len,
            encoded_frame_len,
            write_started_at,
            completed_at,
        }
    }

    pub fn destination(&self) -> &str {
        &self.destination
    }

    pub fn data_len(&self) -> usize {
        self.data_len
    }

    pub fn encoded_frame_len(&self) -> usize {
        self.encoded_frame_len
    }

    /// The existing prewrite-hook time, excluding command queue wait.
    pub fn write_started_at(&self) -> Instant {
        self.write_started_at
    }

    /// Sampled immediately after the original full-write helper returned Ok.
    pub fn completed_at(&self) -> Instant {
        self.completed_at
    }

    /// Compare the original command allocation, using a temporary weak upgrade.
    ///
    /// Channel identity alone is not a close/revocation/current-owner check.
    /// Existing client lifecycle policy must still be applied by the caller.
    pub fn belongs_to_writer(&self, client: &RelayClient) -> bool {
        self.writer
            .upgrade()
            .is_some_and(|writer| writer.same_channel(&client.cmd_tx))
    }

    #[cfg(test)]
    pub(super) fn writer_channel_retired(&self) -> bool {
        self.writer.upgrade().is_none()
    }
}

impl std::fmt::Debug for OriginalRelayWriteFact {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OriginalRelayWriteFact")
            .field("destination", &self.destination)
            .field("data_len", &self.data_len)
            .field("encoded_frame_len", &self.encoded_frame_len)
            .field("write_started_at", &self.write_started_at)
            .field("completed_at", &self.completed_at)
            .finish_non_exhaustive()
    }
}
