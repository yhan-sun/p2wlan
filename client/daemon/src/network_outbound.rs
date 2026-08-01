//! Network outbound path selection: choose direct UDP vs relay fallback for
//! each encrypted peer packet and forward it over the selected path.

use std::sync::Arc;

use tokio::sync::{mpsc, RwLock};
use tracing::{debug, warn};

use crate::peer::{NetworkPath, PeerManager, REASON_DIRECT_SEND_FAILED, REASON_PATH_DIRECT_TRIAL};
use crate::relay::RelayTransport;
use crate::transport::EncryptedPeerPacket;
use crate::udp::UdpTransport;

pub(super) async fn run_network_outbound(
    mut encrypted_rx: mpsc::Receiver<EncryptedPeerPacket>,
    peers: Arc<PeerManager>,
    prefer_direct: bool,
    udp_transport: Arc<RwLock<Option<UdpTransport>>>,
    relay_transport: Arc<RwLock<Option<RelayTransport>>>,
) {
    while let Some(packet) = encrypted_rx.recv().await {
        let relay = relay_transport.read().await.clone();
        let relay_available = relay.is_some();
        let udp = udp_transport.read().await.clone();
        let udp_local_endpoint = udp.as_ref().and_then(|udp| udp.local_addr().ok());
        let selection = peers
            .select_path_for_data_with_local_endpoint(
                &packet.peer_id,
                prefer_direct,
                relay_available,
                udp_local_endpoint,
            )
            .await;
        debug!(
            "Path selection for peer {}: path={:?} relay_hedged={} reason_code={} reason={}",
            packet.peer_id,
            selection.path,
            selection.relay_hedged,
            selection.reason_code,
            selection.reason
        );

        let sent_direct = if selection.path == Some(NetworkPath::Direct) {
            match (udp.clone(), selection.direct_endpoint) {
                (Some(udp), Some(endpoint)) => {
                    if !selection.direct_confirmed
                        && selection.reason_code == REASON_PATH_DIRECT_TRIAL
                    {
                        if let Err(err) = udp.send_nomination_probe(&packet.peer_id, endpoint).await
                        {
                            debug!(
                                "Failed to send nominated UDP connectivity check for peer {} at {}: {err}",
                                packet.peer_id, endpoint
                            );
                        }
                    }
                    match udp.send_packet_to(&packet, endpoint).await {
                        Ok(_) => true,
                        Err(err) => {
                            warn!(
                                "Direct UDP send failed for peer {}; trying relay fallback: {err}",
                                packet.peer_id
                            );
                            peers
                                .record_direct_failure_with_code_and_local_endpoint(
                                    &packet.peer_id,
                                    REASON_DIRECT_SEND_FAILED,
                                    err.to_string(),
                                    udp_local_endpoint,
                                )
                                .await;
                            false
                        }
                    }
                }
                (None, _) => {
                    peers
                        .record_direct_failure_with_code_and_local_endpoint(
                            &packet.peer_id,
                            REASON_DIRECT_SEND_FAILED,
                            "UDP transport unavailable for encrypted packet",
                            udp_local_endpoint,
                        )
                        .await;
                    false
                }
                (_, None) => {
                    peers
                        .record_direct_failure_with_code_and_local_endpoint(
                            &packet.peer_id,
                            REASON_DIRECT_SEND_FAILED,
                            "path selector chose direct without an endpoint",
                            udp_local_endpoint,
                        )
                        .await;
                    false
                }
            }
        } else {
            false
        };

        if sent_direct && selection.direct_confirmed && !selection.relay_hedged {
            continue;
        }

        if let Some(relay) = relay {
            if let Err(err) = relay.send_packet(&packet).await {
                warn!(
                    "Relay fallback send failed for peer {}: {err}",
                    packet.peer_id
                );
            }
        } else if !sent_direct {
            debug!(
                "Encrypted packet for peer {} has no selected path: {} ({})",
                packet.peer_id, selection.reason, selection.reason_code
            );
        }
    }
}
