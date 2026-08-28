from pathlib import Path
import re


def replace_once(path: Path, old: str, new: str, label: str) -> None:
    text = path.read_text()
    count = text.count(old)
    if count != 1:
        raise SystemExit(f"{label}: expected exactly one match, found {count}")
    path.write_text(text.replace(old, new, 1))


peer = Path("client/daemon/src/peer.rs")
replace_once(
    peer,
    'include!("peer/connection/core.rs");\n',
    'include!("peer/path_state_machine.rs");\ninclude!("peer/connection/core.rs");\n',
    "peer include",
)

core = Path("client/daemon/src/peer/connection/core.rs")
replace_once(
    core,
    "    /// Current connection state.\n    pub state: ConnectionState,\n",
    "    /// Current connection state.\n"
    "    pub state: ConnectionState,\n"
    "    /// Prepared/commit transition authority. The compatibility `state`\n"
    "    /// mirror changes only after this machine commits under the same peer lock.\n"
    "    pub(crate) path_state_machine: PathStateMachine,\n",
    "state machine field",
)
replace_once(
    core,
    "            state: ConnectionState::Idle,\n",
    "            state: ConnectionState::Idle,\n"
    "            path_state_machine: PathStateMachine::new(ConnectionState::Idle),\n",
    "state machine constructor",
)
replace_once(
    core,
    "        self.state = ConnectionState::Idle;\n",
    "        self.path_state_machine.reset(ConnectionState::Idle);\n"
    "        self.state = ConnectionState::Idle;\n",
    "state machine reset",
)

text = core.read_text()
pattern = re.compile(
    r"    /// Transition to a new state\.\n"
    r"    pub fn transition\(&mut self, new_state: ConnectionState\) \{.*?\n"
    r"        self\.sync_direct_cache\(\);\n"
    r"    \}\n",
    re.DOTALL,
)
replacement = '''    pub(crate) fn path_state_machine_snapshot(&self) -> PathStateMachineSnapshot {
        self.path_state_machine.snapshot()
    }

    pub(crate) fn path_mtu_snapshot(&self) -> PathMtuSnapshot {
        self.path_state_machine.mtu_snapshot()
    }

    fn current_path_generation(&self) -> u64 {
        self.direct_generation
            .max(self.relay_ready_generation.unwrap_or(0))
            .max(self.relay_confirmed_generation.unwrap_or(0))
    }

    pub(crate) fn prepare_path_transition(
        &self,
        new_state: ConnectionState,
        network_generation: u64,
        candidate_generation: u64,
        reason: &'static str,
    ) -> Result<PreparedPathTransition, PathTransitionRejection> {
        self.path_state_machine.prepare(
            new_state,
            network_generation,
            candidate_generation,
            reason,
        )
    }

    pub(crate) fn commit_prepared_path_transition(
        &mut self,
        prepared: PreparedPathTransition,
    ) -> bool {
        let requested = prepared.next_snapshot();
        let outcome = match self.path_state_machine.commit(prepared) {
            Ok(outcome) => outcome,
            Err(rejection) => {
                warn!(target: "p2pnet_daemon::peer::connection",
                    event = "peer_path_transition_rejected",
                    peer_id = %self.node_id,
                    requested_state = ?requested.state,
                    rejection = ?rejection,
                    network_generation = requested.network_generation,
                    candidate_generation = requested.candidate_generation,
                    reason = requested.transition_reason,
                    "prepared peer path transition was rejected"
                );
                return false;
            }
        };
        let new_state = outcome.current.state;
        if self.state != new_state {
            info!(target: "p2pnet_daemon::peer::connection",
                event = "peer_connection_state_changed",
                peer_id = %self.node_id,
                previous_state = ?outcome.previous.state,
                new_state = ?new_state,
                previous_path = ?outcome.previous.active_path,
                active_path = ?outcome.current.active_path,
                network_generation = outcome.current.network_generation,
                candidate_generation = outcome.current.candidate_generation,
                path_revision = outcome.current.revision,
                transition_reason = outcome.current.transition_reason,
                direct_generation = self.direct_generation,
                relay_ready_generation = ?self.relay_ready_generation,
                relay_confirmed_generation = ?self.relay_confirmed_generation,
                relay_confirmed_connection_id = ?self.relay_confirmed_connection_id,
                relay_server = ?self.relay_server,
                direct_endpoint = ?self.endpoint,
                "peer connection state changed"
            );
            info!("Peer {} state: {} → {}", self.node_id, self.state, new_state);
        }
        let was_active = self.is_active();
        let becomes_active = matches!(new_state, ConnectionState::Direct | ConnectionState::Relay);
        if becomes_active {
            if !was_active || self.connected_at.is_none() {
                self.connected_at = Some(Instant::now());
            }
        } else {
            self.connected_at = None;
        }
        self.state = new_state;
        self.sync_direct_cache();
        true
    }

    pub(crate) fn transition_for_generation(
        &mut self,
        new_state: ConnectionState,
        network_generation: u64,
        candidate_generation: u64,
        reason: &'static str,
    ) -> bool {
        let prepared = match self.prepare_path_transition(
            new_state,
            network_generation,
            candidate_generation,
            reason,
        ) {
            Ok(prepared) => prepared,
            Err(rejection) => {
                warn!(target: "p2pnet_daemon::peer::connection",
                    event = "peer_path_transition_rejected",
                    peer_id = %self.node_id,
                    previous_state = ?self.state,
                    requested_state = ?new_state,
                    rejection = ?rejection,
                    network_generation,
                    candidate_generation,
                    reason,
                    "peer path transition rejected before mutation"
                );
                return false;
            }
        };
        self.commit_prepared_path_transition(prepared)
    }

    /// Compatibility transition for non-path evidence. Confirmation paths use
    /// prepare/commit explicitly so stale evidence cannot partially mutate the
    /// endpoint, health, generation or direct-cache mirrors.
    pub fn transition(&mut self, new_state: ConnectionState) {
        let generation = self.current_path_generation();
        let candidate_generation = self.last_candidate_generation;
        let _ = self.transition_for_generation(
            new_state,
            generation,
            candidate_generation,
            "compatibility_transition",
        );
    }

    pub(crate) fn next_path_mtu_probe(
        &self,
        path: NetworkPath,
        generation: u64,
    ) -> Option<u32> {
        self.path_state_machine.next_mtu_probe(path, generation)
    }

    pub(crate) fn record_path_mtu_probe(
        &mut self,
        path: NetworkPath,
        generation: u64,
        size: u32,
        succeeded: bool,
    ) -> bool {
        let changed = self
            .path_state_machine
            .record_mtu_probe(path, generation, size, succeeded);
        if changed {
            let snapshot = self.path_state_machine.mtu_snapshot();
            info!(target: "p2pnet_daemon::peer::connection",
                event = "peer_path_mtu_probe_result",
                peer_id = %self.node_id,
                path = ?path,
                generation,
                probe_size = size,
                succeeded,
                direct_effective_mtu = snapshot.direct_effective_mtu,
                relay_effective_mtu = snapshot.relay_effective_mtu,
                "peer path MTU probe result committed"
            );
        }
        changed
    }

    pub(crate) fn effective_path_mtu(&self, path: NetworkPath, generation: u64) -> u32 {
        self.path_state_machine.effective_mtu(path, generation)
    }
'''
updated, count = pattern.subn(replacement, text, count=1)
if count != 1:
    raise SystemExit(f"transition method: expected one match, found {count}")
core.write_text(updated)

# Opportunistic live PLPMTUD: authenticated received payloads at or above the
# next ladder size confirm that size on the current path. The same state also
# accepts explicit padded-probe timeout failures through record_path_mtu_probe.
replace_once(
    core,
    """    pub fn record_received(&mut self, n: u64) {
        self.bytes_received += n;
    }
""",
    """    pub fn record_received(&mut self, n: u64) {
        self.bytes_received += n;
        if let Some(path) = self.active_path() {
            let generation = self.current_path_generation();
            if let Some(probe_size) = self.next_path_mtu_probe(path, generation) {
                if n >= u64::from(probe_size) {
                    let _ = self.record_path_mtu_probe(path, generation, probe_size, true);
                }
            }
        }
    }
""",
    "live MTU receive observation",
)

# Direct is prepared before endpoint/health/cache mutation, then committed
# under the same connection write lock.
direct = Path("client/daemon/src/peer/manager/direct_success.rs")
replace_once(
    direct,
    """            let was_direct = conn.state == ConnectionState::Direct;
            let previous_endpoint = conn.endpoint;
""",
    """            let candidate_generation = conn.last_candidate_generation;
            let prepared_path_transition = match conn.prepare_path_transition(
                ConnectionState::Direct,
                generation,
                candidate_generation,
                "direct_confirmed",
            ) {
                Ok(prepared) => prepared,
                Err(_) => return false,
            };
            let was_direct = conn.state == ConnectionState::Direct;
            let previous_endpoint = conn.endpoint;
""",
    "Direct transition prepare",
)
replace_once(
    direct,
    """            conn.transition(ConnectionState::Direct);
            if direct_confirmation_changed {
""",
    """            if !conn.commit_prepared_path_transition(prepared_path_transition) {
                return false;
            }
            if direct_confirmation_changed {
""",
    "Direct transition commit",
)
