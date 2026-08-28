from pathlib import Path


def replace_once(path: Path, old: str, new: str, label: str) -> None:
    text = path.read_text(encoding="utf-8")
    count = text.count(old)
    if count != 1:
        raise SystemExit(f"{label}: expected exactly one match, found {count}")
    path.write_text(text.replace(old, new, 1), encoding="utf-8")


core = Path("client/daemon/src/peer/connection/core.rs")
replace_once(
    core,
    """    pub(crate) fn next_path_mtu_probe(
""",
    """    /// Re-open a terminal connection only at an authenticated lifecycle
    /// boundary (for example, an authoritative control-plane offline->online
    /// replacement). Ordinary late path evidence must continue to use
    /// `transition_for_generation` and cannot resurrect `Closed`.
    pub(crate) fn reset_path_for_authenticated_lifecycle(
        &mut self,
        new_state: ConnectionState,
        reason: &'static str,
    ) {
        let previous = self.path_state_machine.snapshot();
        self.path_state_machine.reset(new_state);
        let current = self.path_state_machine.snapshot();
        let previous_state = self.state;
        self.state = new_state;
        self.connected_at = if matches!(new_state, ConnectionState::Direct | ConnectionState::Relay)
        {
            Some(Instant::now())
        } else {
            None
        };
        self.sync_direct_cache();
        info!(target: "p2pnet_daemon::peer::connection",
            event = "peer_connection_lifecycle_reset",
            peer_id = %self.node_id,
            previous_state = ?previous_state,
            new_state = ?new_state,
            previous_path = ?previous.active_path,
            active_path = ?current.active_path,
            path_revision = current.revision,
            transition_reason = reason,
            "peer connection path state reset at authenticated lifecycle boundary"
        );
    }

    pub(crate) fn next_path_mtu_probe(
""",
    "authenticated lifecycle reset API",
)

peers = Path("client/daemon/src/peer/manager/peers.rs")
replace_once(
    peers,
    """        } else if conn.state == ConnectionState::Closed {
            conn.transition(ConnectionState::Idle);
        }
""",
    """        } else if conn.state == ConnectionState::Closed {
            // The control plane rotated the peer lifecycle above (offline ->
            // online). This is the explicit authenticated reset boundary that
            // may reopen terminal Closed; late transport/probe evidence cannot.
            conn.reset_path_for_authenticated_lifecycle(
                ConnectionState::Idle,
                "control_plane_peer_rejoined",
            );
        }
""",
    "offline to online authenticated reset",
)

quarantine = Path("client/daemon/src/peer/manager/quarantine.rs")
replace_once(
    quarantine,
    """        let epoch_gate = self.network_epoch_gate();
        let _epoch_guard = epoch_gate.lock().await;
        let now = Instant::now();
""",
    """        let epoch_gate = self.network_epoch_gate();
        let _epoch_guard = epoch_gate.lock().await;
        // Keep the authoritative epoch snapshot before relay readiness fields
        // are cleared below. Compatibility generation inference would become
        // zero after that cleanup and incorrectly reject Relay -> fallback.
        let generation = self.current_network_generation_sync();
        let now = Instant::now();
""",
    "quarantine generation snapshot",
)
replace_once(
    quarantine,
    """                    if conn.state == ConnectionState::Relay {
                        conn.transition(ConnectionState::FallbackToRelay);
                    }
""",
    """                    if conn.state == ConnectionState::Relay {
                        let candidate_generation = conn.last_candidate_generation;
                        let transitioned = conn.transition_for_generation(
                            ConnectionState::FallbackToRelay,
                            generation,
                            candidate_generation,
                            "relay_peer_quarantined",
                        );
                        debug_assert!(
                            transitioned,
                            "authoritative relay quarantine transition must commit in the current epoch"
                        );
                    }
""",
    "generation-bound relay quarantine transition",
)
