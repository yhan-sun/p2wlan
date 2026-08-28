from pathlib import Path

path = Path("client/daemon/src/lib/daemon/handshake/initiate.rs")
text = path.read_text(encoding="utf-8")


def replace_once(old: str, new: str, label: str) -> None:
    global text
    count = text.count(old)
    if count != 1:
        raise SystemExit(f"{label}: expected one match, found {count}")
    text = text.replace(old, new, 1)


def replace_last(old: str, new: str, label: str) -> None:
    global text
    index = text.rfind(old)
    if index < 0:
        raise SystemExit(f"{label}: match not found")
    text = text[:index] + new + text[index + len(old):]


replace_once(
    """        let emit_guard = self
            .transport
            .acquire_outbound_emit_guard(&peer_info.node_id)
            .await;
        let epoch_gate = self.peers.network_epoch_gate();
        let epoch_guard = epoch_gate.lock().await;
""",
    """        self.timeline.emit(
            "initiator_publish_emit_wait",
            None,
            None,
            Some(format!("peer={} owner={} generation={}", peer_info.node_id, reservation.owner, handshake_generation)),
        );
        let emit_guard = self
            .transport
            .acquire_outbound_emit_guard(&peer_info.node_id)
            .await;
        self.timeline.emit(
            "initiator_publish_emit_acquired",
            None,
            None,
            Some(format!("peer={} owner={} generation={}", peer_info.node_id, reservation.owner, handshake_generation)),
        );
        let epoch_gate = self.peers.network_epoch_gate();
        self.timeline.emit(
            "initiator_publish_epoch_wait",
            None,
            None,
            Some(format!("peer={} owner={} generation={}", peer_info.node_id, reservation.owner, handshake_generation)),
        );
        let epoch_guard = epoch_gate.lock().await;
        self.timeline.emit(
            "initiator_publish_epoch_acquired",
            None,
            None,
            Some(format!("peer={} owner={} generation={}", peer_info.node_id, reservation.owner, handshake_generation)),
        );
""",
    "emit and epoch boundaries",
)

replace_last(
    """        let status = self.transport.session_status(&peer_info.node_id).await;
        if status.has_active || status.has_pending_responder {
""",
    """        self.timeline.emit(
            "initiator_publish_session_status_wait",
            None,
            None,
            Some(format!("peer={} owner={} generation={}", peer_info.node_id, reservation.owner, handshake_generation)),
        );
        let status = self.transport.session_status(&peer_info.node_id).await;
        self.timeline.emit(
            "initiator_publish_session_status_ready",
            None,
            None,
            Some(format!("peer={} owner={} generation={} active={} pending={}", peer_info.node_id, reservation.owner, handshake_generation, status.has_active, status.has_pending_responder)),
        );
        if status.has_active || status.has_pending_responder {
""",
    "publish session status boundary",
)

replace_once(
    """        let Some((attempt_no, pending_id)) = ({
            let mut state = self.pending_handshakes.lock().await;
""",
    """        self.timeline.emit(
            "initiator_publish_pending_lock_wait",
            None,
            None,
            Some(format!("peer={} owner={} generation={}", peer_info.node_id, reservation.owner, handshake_generation)),
        );
        let Some((attempt_no, pending_id)) = ({
            let mut state = self.pending_handshakes.lock().await;
            self.timeline.emit(
                "initiator_publish_pending_lock_acquired",
                None,
                None,
                Some(format!("peer={} owner={} generation={}", peer_info.node_id, reservation.owner, handshake_generation)),
            );
""",
    "pending-handshake boundary",
)

replace_once(
    """        if self
            .peers
            .stage_probe_session_binding(
""",
    """        self.timeline.emit(
            "initiator_publish_probe_binding_wait",
            None,
            None,
            Some(format!("peer={} owner={} generation={} pending_id={pending_id}", peer_info.node_id, reservation.owner, handshake_generation)),
        );
        if self
            .peers
            .stage_probe_session_binding(
""",
    "probe binding wait boundary",
)

replace_once(
    """            return Err(DaemonError::Peer(format!(
                "failed to stage Probe v2 handshake binding for {peer_id}"
            )));
        }
        self.timeline.emit(
            "initiator_session_staged",
""",
    """            return Err(DaemonError::Peer(format!(
                "failed to stage Probe v2 handshake binding for {peer_id}"
            )));
        }
        self.timeline.emit(
            "initiator_publish_probe_binding_ready",
            None,
            None,
            Some(format!("peer={peer_id} owner={} generation={handshake_generation} pending_id={pending_id}", reservation.owner)),
        );
        self.timeline.emit(
            "initiator_session_staged",
""",
    "probe binding ready boundary",
)

path.write_text(text, encoding="utf-8")
