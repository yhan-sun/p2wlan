//! One original control attempt's diagnostics, never a send/owner authority.
//! One optional scalar snapshot and at most 4 KiB of error text; no queue,
//! task, timer, packet clone or extra wire buffer. Drop flushes submission only.
use super::*;

struct WireLog {
    bytes: usize,
    counter: Option<u64>,
    business: bool,
    fingerprint: u64,
}
pub(crate) struct DeferredRelaySend {
    owner: Arc<PeerManager>,
    peer: String,
    endpoint: String,
    region: String,
    connection: u64,
    submission_pending: bool,
    wire: Option<WireLog>,
    sent: bool,
    failure: Option<String>,
    error_truncated: bool,
}
impl DeferredRelaySend {
    pub(super) fn new(relay: &RelayTransport, peer: &str) -> Self {
        Self {
            owner: relay.peers.clone(),
            peer: peer.into(),
            endpoint: relay.relay_endpoint.clone(),
            region: relay.relay_region.clone(),
            connection: relay.relay_connection_id,
            submission_pending: false,
            wire: None,
            sent: false,
            failure: None,
            error_truncated: false,
        }
    }
    pub(super) fn capture(&mut self, relay: &RelayTransport, packet: &EncryptedPeerPacket) -> bool {
        if self.wire.is_some()
            || self.peer != packet.peer_id
            || self.connection != relay.relay_connection_id
            || !Arc::ptr_eq(&self.owner, &relay.peers)
            || self.endpoint != relay.relay_endpoint
            || self.region != relay.relay_region
        {
            return false;
        }
        let wire = WireLog {
            bytes: packet.wire_bytes.len(),
            counter: crate::transport::wire_counter(&packet.wire_bytes),
            business: packet.is_business,
            fingerprint: crate::transport::wire_fingerprint(&packet.wire_bytes),
        };
        self.submission_pending = true;
        self.wire = Some(wire);
        true
    }
    pub(super) fn sent(&mut self) {
        self.sent = true;
    }
    pub(super) fn failed(&mut self, error: &p2pnet_relay::RelayError) {
        let mut text = error.to_string();
        if text.len() > 4096 {
            let mut n = 4096;
            while !text.is_char_boundary(n) {
                n -= 1;
            }
            text.truncate(n);
            self.error_truncated = true;
        }
        self.failure = Some(text);
    }
    fn submission(&mut self) {
        if std::mem::take(&mut self.submission_pending) {
            let Some(wire) = self.wire.as_ref() else {
                return;
            };
            debug!(target: RELAY_SEND_LOG_TARGET, event = "relay_outbound_write_submitted",
                peer_id = %self.peer, relay_connection_id = self.connection, relay_region = %self.region,
                bytes = wire.bytes, counter = ?wire.counter, is_business = wire.business,
                wire_fp = format_args!("{:016x}", wire.fingerprint), relay_endpoint = %self.endpoint,
                "opaque encrypted frame submitted to the relay client's bounded command queue");
        }
    }
    pub(crate) async fn finish(mut self) {
        self.submission();
        let Some(wire) = self.wire.as_ref() else {
            return;
        };
        if self.sent {
            self.owner
                .record_relay_attempt(&self.peer, &self.endpoint)
                .await;
            debug!(target: RELAY_SEND_LOG_TARGET, event = "relay_outbound_write_completed",
                peer_id = %self.peer, relay_connection_id = self.connection, relay_region = %self.region,
                bytes = wire.bytes, counter = ?wire.counter, is_business = wire.business,
                wire_fp = format_args!("{:016x}", wire.fingerprint), relay_endpoint = %self.endpoint,
                "opaque encrypted frame completed the relay client write boundary");
            debug!(target: RELAY_SEND_LOG_TARGET, "Sent {} encrypted bytes to peer {} through relay {}", wire.bytes, self.peer, self.endpoint);
        } else if let Some(error) = self.failure.as_ref() {
            warn!(target: RELAY_SEND_LOG_TARGET, event = "relay_outbound_write_failed",
                peer_id = %self.peer, relay_connection_id = self.connection, relay_region = %self.region,
                bytes = wire.bytes, counter = ?wire.counter, is_business = wire.business,
                wire_fp = format_args!("{:016x}", wire.fingerprint), relay_endpoint = %self.endpoint,
                error = %error, error_truncated = self.error_truncated,
                "relay client writer rejected or failed the encrypted frame");
        }
    }
}
impl Drop for DeferredRelaySend {
    fn drop(&mut self) {
        self.submission();
    }
}
