//! Test-only borrowed observation of the original raw receiver retirement.
//! No flag, sender clone, queue, task, timer or request owner is introduced.

pub(crate) async fn wait_tracked_outbound_receiver_closed(transport: &super::WireGuardTransport) {
    match &transport.outbound_tx {
        crate::request_carriage::RawOutboundSink::Tracked(sender) => sender.closed().await,
        crate::request_carriage::RawOutboundSink::Legacy(_) => {
            panic!("graceful drain control requires its original tracked constructor");
        }
    }
}
