/// Drain and log routed packets until a real WireGuard/UDP transport is attached.
pub async fn log_outbound_packets(mut outbound_rx: mpsc::Receiver<OutboundPacket>) {
    while let Some(packet) = outbound_rx.recv().await {
        debug!(
            "Outbound packet ready for peer {} (dst={}, {} bytes)",
            packet.peer_id,
            packet.dst_ip,
            packet.packet.len()
        );
    }
}
