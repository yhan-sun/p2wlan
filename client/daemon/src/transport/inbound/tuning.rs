use super::*;
use crate::dataplane_resources::PlaintextRxSink;
use crate::transport_tuning::SessionKey;
use std::sync::atomic::Ordering;

pub(super) struct TuningIngress<'a> {
    pub(super) generation: Option<u64>,
    pub(super) counter: Option<u64>,
    pub(super) source: IngressKey,
    pub(super) wire: Option<&'a [u8]>,
}

impl WireGuardTransport {
    pub(super) async fn observe_tuning_ingress(
        &self,
        peers: &PeerManager,
        sink: &PlaintextRxSink,
        inbound: &InboundPacket,
        plaintext: &[u8],
        ingress: &TuningIngress<'_>,
    ) -> Result<()> {
        let (Some(generation), Some(counter), Some(instance)) = (
            ingress.generation,
            ingress.counter,
            inbound.session_instance,
        ) else {
            return Ok(());
        };
        if peers.current_network_generation_sync() != generation {
            return Ok(());
        }
        let message = transport_tuning::decode(plaintext);
        if message.is_none()
            && (transport_tuning::is_internal(plaintext)
                || p2pnet_tun::IpPacket::new(plaintext).is_err())
        {
            return Ok(());
        }
        let Some(guard) = self
            .acquire_current_session_evidence_guard(&inbound.peer_id, Some(instance))
            .await
        else {
            return Ok(());
        };
        let key = SessionKey {
            generation,
            instance,
        };
        let input = peers.tuning().input(
            &inbound.peer_id,
            key,
            ingress.source,
            message,
            counter,
            ingress.wire,
            peers.transport_config(),
        );
        if let Some(record) = input.record {
            self.send_tuning_reply(peers, &inbound.peer_id, key, record);
        }
        drop(guard);
        if let Some((path, loss)) = input.path_loss {
            peers.record_transport_loss(&inbound.peer_id, path, loss);
        }
        for ciphertext in input.recovered {
            self.deliver_recovered_wire(peers, sink, &inbound.peer_id, key, &ciphertext)
                .await?;
        }
        Ok(())
    }

    pub(super) fn report_tuning_replay(&self, peers: &PeerManager, ingress: &TuningIngress<'_>) {
        peers
            .tuning()
            .replay_rejected
            .fetch_add(1, Ordering::Relaxed);
        if let (Some(generation), Some(counter), Some(wire)) =
            (ingress.generation, ingress.counter, ingress.wire)
        {
            if generation == peers.current_network_generation_sync() {
                if let Some((id, key, record)) =
                    peers
                        .tuning()
                        .late_original(generation, ingress.source, counter, wire)
                {
                    self.send_tuning_reply(peers, &id, key, record);
                }
            }
        }
    }

    fn send_tuning_reply(&self, peers: &PeerManager, id: &str, key: SessionKey, record: Vec<u8>) {
        if let Some(path) = peers
            .committed_business_path_snapshot_sync(id)
            .filter(|path| path.is_online_in_generation(key.generation))
        {
            if !self.queue_tuning_record(id, &path.virtual_ip, None, key, record) {
                peers.count_qos_drops(1);
            }
        }
    }

    pub(super) async fn deliver_recovered_wire(
        &self,
        peers: &PeerManager,
        inbound: &PlaintextRxSink,
        peer_id: &str,
        key: SessionKey,
        wire: &[u8],
    ) -> Result<()> {
        if peers.current_network_generation_sync() != key.generation {
            return Ok(());
        }
        let packet = match self.decrypt_inbound_for_peer(wire, Some(peer_id)).await {
            Ok(Some(decrypted)) => decrypted.packet,
            Err(error) if error.is_replay() => {
                peers
                    .tuning()
                    .replay_rejected
                    .fetch_add(1, Ordering::Relaxed);
                return Ok(());
            }
            _ => return Ok(()),
        };
        let (lease, mut packet) = packet.into_parts();
        if packet.session_instance != Some(key.instance)
            || packet.peer_id != peer_id
            || peers.current_network_generation_sync() != key.generation
            || !self.session_instance_state(peer_id, key.instance).await.0
        {
            return Ok(());
        }
        if transport_tuning::is_internal(&packet.packet) {
            let Some(Message::Compressed { length, data }) =
                transport_tuning::decode(&packet.packet)
            else {
                return Ok(());
            };
            let Some(decoded) = Compression::decode(length, data) else {
                return Ok(());
            };
            packet.packet = decoded;
        }
        if peers.current_network_generation_sync() != key.generation
            || p2pnet_tun::IpPacket::new(&packet.packet).is_err()
        {
            return Ok(());
        }
        if let Some(counter) = wire_counter(wire) {
            peers
                .tuning()
                .authenticated_recovery(peer_id, key, counter, wire);
        }
        // A reconstructed datagram participates only in ordinary TUN delivery.
        // No socket, direct-path evidence, or overlay request proof is minted.
        inbound
            .send_owned(crate::dataplane_resources::RxOwned::from_parts(
                packet, lease,
            ))
            .await
            .map_err(|_| DaemonError::Network("inbound packet channel closed".into()))?;
        peers.tuning().fec_recovered.fetch_add(1, Ordering::Relaxed);
        Ok(())
    }
}
