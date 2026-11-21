//! Bounded test observation of real previous-key decrypts excluded from the
//! normal overlay feed. Source/role are moved from the original actor only.
use super::*;

impl WireGuardTransport {
    pub(crate) fn install_previous_overlay_observer_for_test(
        &self,
    ) -> mpsc::Receiver<OverlayIngressDelivery> {
        let (sender, receiver) = mpsc::channel(4);
        *self.previous_overlay_observer.lock().unwrap() = Some(sender);
        receiver
    }

    #[allow(clippy::too_many_arguments)]
    pub(super) fn observe_previous_overlay_for_test(
        &self,
        inbound: &InboundPacket,
        relay_endpoint: Option<&str>,
        owns_direct: bool,
        remote: Option<SocketAddr>,
        generation: Option<u64>,
        original_source: Option<OriginalOverlayIngressSource>,
    ) {
        let sender = self.previous_overlay_observer.lock().unwrap().clone();
        let (Some(sender), Some(source)) = (sender, original_source) else {
            return;
        };
        let ingress = match relay_endpoint {
            Some(endpoint) => OverlayIngress::Relay(endpoint.to_string()),
            None if owns_direct && remote.is_some() => OverlayIngress::Direct,
            None => return,
        };
        let Some(generation) = generation else {
            return;
        };
        let _ = sender.try_send(OverlayIngressDelivery::authenticated(
            OverlayIngressEvent {
                peer_id: inbound.peer_id.clone(),
                packet: inbound.packet.clone(),
                ingress,
                connection_generation: generation,
            },
            source,
        ));
    }
}
