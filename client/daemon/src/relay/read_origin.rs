//! Private payload mode for original selection, merge and renewal algorithms.
//! No fact factory, G, authentication, physical receipt or ACK authority.
use super::*;

pub(crate) trait RelayReadItem: From<RelayMessage> + Send + 'static {
    fn message(&self) -> &RelayMessage;
    fn into_parts(self) -> (RelayMessage, Option<OriginalRelayFrameRead>);
    fn connect_client<'a>(
        endpoint: &'a str,
        node_id: &'a str,
        config: RelayClientConfig,
    ) -> impl std::future::Future<
        Output = std::result::Result<(RelayClient, mpsc::Receiver<Self>), p2pnet_relay::RelayError>,
    > + Send
           + 'a;
}

impl RelayReadItem for RelayMessage {
    fn message(&self) -> &RelayMessage {
        self
    }
    fn into_parts(self) -> (RelayMessage, Option<OriginalRelayFrameRead>) {
        (self, None)
    }
    fn connect_client<'a>(
        endpoint: &'a str,
        node_id: &'a str,
        config: RelayClientConfig,
    ) -> impl std::future::Future<
        Output = std::result::Result<(RelayClient, mpsc::Receiver<Self>), p2pnet_relay::RelayError>,
    > + Send
           + 'a {
        RelayClient::connect_with_endpoint(endpoint, node_id, config)
    }
}

impl RelayReadItem for OriginalRelayDelivery {
    fn message(&self) -> &RelayMessage {
        OriginalRelayDelivery::message(self)
    }
    fn into_parts(self) -> (RelayMessage, Option<OriginalRelayFrameRead>) {
        OriginalRelayDelivery::into_parts(self)
    }
    fn connect_client<'a>(
        endpoint: &'a str,
        node_id: &'a str,
        config: RelayClientConfig,
    ) -> impl std::future::Future<
        Output = std::result::Result<(RelayClient, mpsc::Receiver<Self>), p2pnet_relay::RelayError>,
    > + Send
           + 'a {
        RelayClient::connect_with_endpoint_and_read_origin(endpoint, node_id, config)
    }
}
