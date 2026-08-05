//! Network outbound path selection: choose direct UDP vs relay fallback for
//! each encrypted peer packet and forward it over the selected path.

use std::{net::SocketAddr, sync::Arc, time::Duration};

use tokio::{
    sync::{mpsc, RwLock},
    time::{sleep, Instant},
};
use tracing::{debug, warn};

use crate::peer::{
    NetworkPath, PathSelection, PeerManager, REASON_DIRECT_SEND_FAILED, REASON_PATH_DIRECT_TRIAL,
};
use crate::relay::RelayTransport;
use crate::transport::{EncryptedPeerPacket, OrderedEncryptedPeerPacket};
use crate::udp::UdpTransport;

const OUTBOUND_RETRY_TTL: Duration = Duration::from_secs(3);
const OUTBOUND_RETRY_DELAY: Duration = Duration::from_millis(50);

enum OutboundSendResult {
    Sent,
    Retryable(RetryableOutboundFailure),
}

enum RetryableOutboundFailure {
    NoSelectedPath {
        reason: String,
        reason_code: &'static str,
    },
    RelaySendFailed {
        err: String,
    },
}

impl RetryableOutboundFailure {
    fn log_drop(self, peer_id: &str) {
        match self {
            RetryableOutboundFailure::NoSelectedPath {
                reason,
                reason_code,
            } => {
                debug!(
                    "Encrypted packet for peer {} has no selected path: {} ({})",
                    peer_id, reason, reason_code
                );
            }
            RetryableOutboundFailure::RelaySendFailed { err } => {
                warn!("Relay fallback send failed for peer {}: {err}", peer_id);
            }
        }
    }
}

pub(super) async fn run_network_outbound(
    mut encrypted_rx: mpsc::Receiver<OrderedEncryptedPeerPacket>,
    peers: Arc<PeerManager>,
    prefer_direct: bool,
    udp_transport: Arc<RwLock<Option<UdpTransport>>>,
    relay_transport: Arc<RwLock<Option<RelayTransport>>>,
) {
    while let Some(packet) = encrypted_rx.recv().await {
        let first_attempt = Instant::now();

        loop {
            let result = send_encrypted_packet_once(
                &packet,
                &peers,
                prefer_direct,
                &udp_transport,
                &relay_transport,
            )
            .await;

            match result {
                OutboundSendResult::Sent => break,
                OutboundSendResult::Retryable(_)
                    if first_attempt.elapsed() <= OUTBOUND_RETRY_TTL =>
                {
                    sleep(OUTBOUND_RETRY_DELAY).await;
                    continue;
                }
                OutboundSendResult::Retryable(failure) => {
                    failure.log_drop(&packet.peer_id);
                    break;
                }
            }
        }
    }
}

async fn send_encrypted_packet_once(
    packet: &EncryptedPeerPacket,
    peers: &PeerManager,
    prefer_direct: bool,
    udp_transport: &RwLock<Option<UdpTransport>>,
    relay_transport: &RwLock<Option<RelayTransport>>,
) -> OutboundSendResult {
    let relay = relay_transport.read().await.clone();
    let relay_available = relay.is_some();
    let udp = udp_transport.read().await.clone();
    let udp_local_endpoint = udp.as_ref().and_then(|udp| udp.local_addr().ok());
    let selection = select_outbound_path(
        packet,
        peers,
        prefer_direct,
        relay_available,
        udp_local_endpoint,
    )
    .await;

    if selection.direct_confirmed {
        let sent_direct =
            send_direct_if_selected(packet, peers, udp, &selection, udp_local_endpoint).await;

        if sent_direct && !selection.relay_hedged {
            return OutboundSendResult::Sent;
        }

        if let Some(relay) = relay {
            return match relay.send_packet(packet).await {
                Ok(_) => OutboundSendResult::Sent,
                Err(err) if sent_direct => {
                    debug!(
                        "Relay hedge send failed for peer {} after confirmed direct send: {err}",
                        packet.peer_id
                    );
                    OutboundSendResult::Sent
                }
                Err(err) => {
                    OutboundSendResult::Retryable(RetryableOutboundFailure::RelaySendFailed {
                        err: err.to_string(),
                    })
                }
            };
        }

        return if sent_direct {
            OutboundSendResult::Sent
        } else {
            OutboundSendResult::Retryable(RetryableOutboundFailure::NoSelectedPath {
                reason: selection.reason,
                reason_code: selection.reason_code,
            })
        };
    }

    // Until Direct is confirmed by decrypted traffic, Relay is the reliable
    // data-plane. A UDP send during Direct trial is only a hedge/probe: it must
    // never make the user packet look delivered if Relay is absent or fails.
    if let Some(relay) = relay {
        match relay.send_packet(packet).await {
            Ok(_) => {
                let _ = send_direct_if_selected(packet, peers, udp, &selection, udp_local_endpoint)
                    .await;
                OutboundSendResult::Sent
            }
            Err(err) => {
                let _ = send_direct_if_selected(packet, peers, udp, &selection, udp_local_endpoint)
                    .await;
                OutboundSendResult::Retryable(RetryableOutboundFailure::RelaySendFailed {
                    err: err.to_string(),
                })
            }
        }
    } else {
        let _ = send_direct_if_selected(packet, peers, udp, &selection, udp_local_endpoint).await;
        OutboundSendResult::Retryable(RetryableOutboundFailure::NoSelectedPath {
            reason: selection.reason,
            reason_code: selection.reason_code,
        })
    }
}

async fn select_outbound_path(
    packet: &EncryptedPeerPacket,
    peers: &PeerManager,
    prefer_direct: bool,
    relay_available: bool,
    udp_local_endpoint: Option<SocketAddr>,
) -> PathSelection {
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
    selection
}

async fn send_direct_if_selected(
    packet: &EncryptedPeerPacket,
    peers: &PeerManager,
    udp: Option<UdpTransport>,
    selection: &PathSelection,
    udp_local_endpoint: Option<SocketAddr>,
) -> bool {
    if selection.path != Some(NetworkPath::Direct) {
        return false;
    }

    match (udp, selection.direct_endpoint) {
        (Some(udp), Some(endpoint)) => {
            if !selection.direct_confirmed && selection.reason_code == REASON_PATH_DIRECT_TRIAL {
                if let Err(err) = udp.send_nomination_probe(&packet.peer_id, endpoint).await {
                    debug!(
                        "Failed to send nominated UDP connectivity check for peer {} at {}: {err}",
                        packet.peer_id, endpoint
                    );
                }
            }
            match udp.send_packet_to(packet, endpoint).await {
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
}
