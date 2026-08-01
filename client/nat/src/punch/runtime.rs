use super::packet::PunchPacket;
use super::*;

/// Send one PUNCH probe to a candidate endpoint.
pub async fn send_punch(socket: &UdpSocket, peer_addr: SocketAddr) -> Result<()> {
    let bytes = build_punch_packet();
    socket
        .send_to(&bytes, peer_addr)
        .await
        .map_err(|e| NatError::Network(format!("punch send failed: {e}")))?;
    Ok(())
}

/// Perform UDP hole punching to establish a direct P2P connection.
///
/// This function uses the provided `socket` (which should be the same socket
/// used for WireGuard to maintain NAT mappings) and tries to connect to the
/// peer by sending punch packets to all candidate addresses.
///
/// Both sides must call this function simultaneously (coordinated via signaling).
pub async fn hole_punch(
    socket: &UdpSocket,
    peer_candidates: &[SocketAddr],
    config: &PunchConfig,
) -> Result<PunchResult> {
    if peer_candidates.is_empty() {
        return Err(NatError::NoCandidates);
    }

    let start = std::time::Instant::now();
    let mut packets_sent: u32 = 0;
    let mut seen_punches: std::collections::HashSet<[u8; 8]> = std::collections::HashSet::new();
    let mut send_interval = interval(config.interval);

    info!(
        "Starting hole punch to {} candidates (timeout={:?})",
        peer_candidates.len(),
        config.timeout
    );

    // Create a random nonce for our punch packets
    let my_punch = PunchPacket::new_punch();
    let punch_bytes = my_punch.encode();

    loop {
        // Check timeout
        if start.elapsed() >= config.timeout {
            warn!(
                "Hole punch timed out after {:?} (sent {} packets)",
                start.elapsed(),
                packets_sent
            );
            return Ok(PunchResult {
                connected: false,
                peer_addr: None,
                elapsed: start.elapsed(),
                packets_sent,
            });
        }

        // Check max attempts
        if packets_sent >= config.max_attempts * peer_candidates.len() as u32 {
            warn!("Max punch attempts reached");
            return Ok(PunchResult {
                connected: false,
                peer_addr: None,
                elapsed: start.elapsed(),
                packets_sent,
            });
        }

        // Send a punch packet to each candidate
        send_interval.tick().await;
        for &peer_addr in peer_candidates {
            match socket.send_to(&punch_bytes, peer_addr).await {
                Ok(_) => {
                    packets_sent += 1;
                    debug!("Sent punch to {} (attempt {})", peer_addr, packets_sent);
                }
                Err(e) => {
                    debug!("Failed to send punch to {}: {}", peer_addr, e);
                }
            }
        }

        // Try to receive a response (with short timeout)
        let mut buf = vec![0u8; 64];
        let recv_timeout = Duration::from_millis(100);

        match timeout(recv_timeout, socket.recv_from(&mut buf)).await {
            Ok(Ok((len, from_addr))) => {
                let data = &buf[..len];
                if let Some(packet) = PunchPacket::decode(data) {
                    if packet.is_punch() {
                        // Received a punch from peer — send ACK back
                        debug!("Received PUNCH from {}", from_addr);

                        // Avoid replying to the same punch repeatedly
                        if seen_punches.insert(packet.nonce) {
                            let ack = PunchPacket::new_ack(packet.nonce);
                            let ack_bytes = ack.encode();
                            let _ = socket.send_to(&ack_bytes, from_addr).await;
                            debug!("Sent ACK to {}", from_addr);
                        }
                    } else if packet.is_ack() {
                        // Received an ACK — connection established!
                        info!("Received ACK from {} — connection established!", from_addr);
                        return Ok(PunchResult {
                            connected: true,
                            peer_addr: Some(from_addr),
                            elapsed: start.elapsed(),
                            packets_sent,
                        });
                    }
                } else {
                    // Not a punch packet — might be WireGuard traffic, ignore
                    debug!(
                        "Received non-punch packet from {} ({} bytes)",
                        from_addr, len
                    );
                }
            }
            Ok(Err(e)) => {
                debug!("recv_from error: {}", e);
            }
            Err(_) => {
                // Timeout — continue sending punches
            }
        }
    }
}

/// Send a keepalive packet to maintain NAT mapping.
///
/// Should be called periodically (e.g., every 25 seconds) to prevent
/// the NAT mapping from expiring.
pub async fn send_keepalive(socket: &UdpSocket, peer_addr: SocketAddr) -> Result<()> {
    send_punch(socket, peer_addr)
        .await
        .map_err(|e| NatError::Network(format!("keepalive send failed: {e}")))?;
    Ok(())
}
