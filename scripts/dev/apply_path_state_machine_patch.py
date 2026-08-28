from pathlib import Path
import re


def replace_once(path: Path, old: str, new: str) -> None:
    text = path.read_text(encoding="utf-8")
    count = text.count(old)
    if count != 1:
        raise SystemExit(f"expected exactly one match in {path}, found {count}")
    path.write_text(text.replace(old, new, 1), encoding="utf-8")


peer = Path("client/daemon/src/peer.rs")
replace_once(
    peer,
    'include!("peer/connection/core.rs");\n',
    'include!("peer/path_state_machine.rs");\ninclude!("peer/connection/core.rs");\n',
)

core = Path("client/daemon/src/peer/connection/core.rs")
replace_once(
    core,
    "    /// Current connection state.\n    pub state: ConnectionState,\n",
    "    /// Current connection state.\n"
    "    pub state: ConnectionState,\n"
    "    /// Generation-aware transition authority. `state` above is the\n"
    "    /// compatibility mirror and may only change after this machine accepts\n"
    "    /// the request.\n"
    "    pub(crate) path_state_machine: PathStateMachine,\n",
)
replace_once(
    core,
    "            state: ConnectionState::Idle,\n",
    "            state: ConnectionState::Idle,\n"
    "            path_state_machine: PathStateMachine::new(ConnectionState::Idle),\n",
)
replace_once(
    core,
    "        self.state = ConnectionState::Idle;\n",
    "        self.path_state_machine.reset(ConnectionState::Idle);\n"
    "        self.state = ConnectionState::Idle;\n",
)

text = core.read_text(encoding="utf-8")
pattern = re.compile(
    r"    /// Transition to a new state\.\n"
    r"    pub fn transition\(&mut self, new_state: ConnectionState\) \{.*?\n"
    r"        self\.sync_direct_cache\(\);\n"
    r"    \}\n",
    re.DOTALL,
)
replacement = '''    /// Immutable machine snapshot for diagnostics and transition tests.
    pub(crate) fn path_state_machine_snapshot(&self) -> PathStateMachineSnapshot {
        self.path_state_machine.snapshot()
    }

    fn current_path_generation(&self) -> u64 {
        self.direct_generation
            .max(self.relay_ready_generation.unwrap_or(0))
            .max(self.relay_confirmed_generation.unwrap_or(0))
    }

    /// Apply a generation-bound path transition. Returns false when stale or
    /// illegal evidence was rejected and leaves every compatibility mirror
    /// unchanged in that case.
    pub(crate) fn transition_for_generation(
        &mut self,
        new_state: ConnectionState,
        network_generation: u64,
        candidate_generation: u64,
        reason_code: &'static str,
    ) -> bool {
        let outcome = self.path_state_machine.apply(
            new_state,
            network_generation,
            candidate_generation,
        );
        if !outcome.accepted() {
            warn!(target: "p2pnet_daemon::peer::connection",
                event = "peer_path_transition_rejected",
                peer_id = %self.node_id,
                previous_state = ?outcome.previous_state,
                requested_state = ?outcome.requested_state,
                decision = ?outcome.decision,
                network_generation,
                candidate_generation,
                machine_generation = outcome.snapshot.network_generation,
                machine_candidate_generation = outcome.snapshot.candidate_generation,
                path_revision = outcome.snapshot.revision,
                rejected_transitions = outcome.snapshot.rejected_transitions,
                reason_code,
                "peer path transition rejected"
            );
            return false;
        }

        if self.state != new_state {
            let previous_state = self.state;
            info!(target: "p2pnet_daemon::peer::connection",
                event = "peer_connection_state_changed",
                peer_id = %self.node_id,
                previous_state = ?previous_state,
                new_state = ?new_state,
                network_generation,
                candidate_generation,
                path_revision = outcome.snapshot.revision,
                transition_reason = reason_code,
                direct_generation = self.direct_generation,
                relay_ready_generation = ?self.relay_ready_generation,
                relay_confirmed_generation = ?self.relay_confirmed_generation,
                relay_confirmed_connection_id = ?self.relay_confirmed_connection_id,
                relay_server = ?self.relay_server,
                direct_endpoint = ?self.endpoint,
                "peer connection state changed peer_id={} previous={:?} new={:?}",
                self.node_id,
                previous_state,
                new_state,
            );
            info!(
                "Peer {} state: {} → {}",
                self.node_id, self.state, new_state
            );
        }
        let was_active = self.is_active();
        let becomes_active = matches!(new_state, ConnectionState::Direct | ConnectionState::Relay);
        if becomes_active {
            // Direct <-> Relay is one continuously usable connection, but the
            // first active state after any inactive interval begins a new
            // session clock. This prevents diagnostics from charging outage
            // time (or a previous connection's lifetime) to a reconnect.
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

    /// Compatibility transition for call sites that already performed their
    /// own epoch validation. New path confirmation code should prefer
    /// `transition_for_generation` so stale evidence returns an explicit
    /// result instead of relying only on the caller's pre-check.
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
'''
text, count = pattern.subn(replacement, text, count=1)
if count != 1:
    raise SystemExit(f"failed to replace transition implementation in {core}")
core.write_text(text, encoding="utf-8")

direct = Path("client/daemon/src/peer/manager/direct_success.rs")
replace_once(
    direct,
    "            conn.transition(ConnectionState::Direct);\n",
    "            let candidate_generation = conn.last_candidate_generation;\n"
    "            if !conn.transition_for_generation(\n"
    "                ConnectionState::Direct,\n"
    "                generation,\n"
    "                candidate_generation,\n"
    "                \"direct_confirmed\",\n"
    "            ) {\n"
    "                return false;\n"
    "            }\n",
)

relay = Path("client/daemon/src/peer/manager/relay.rs")
text = relay.read_text(encoding="utf-8")
old = """                    if conn.state == ConnectionState::Relay {
                        conn.transition(ConnectionState::FallbackToRelay);
                    }
"""
new = """                    if conn.state == ConnectionState::Relay {
                        let candidate_generation = conn.last_candidate_generation;
                        let _ = conn.transition_for_generation(
                            ConnectionState::FallbackToRelay,
                            generation,
                            candidate_generation,
                            "relay_transport_replaced",
                        );
                    }
"""
if text.count(old) != 1:
    raise SystemExit(f"expected one relay replacement transition, found {text.count(old)}")
text = text.replace(old, new, 1)
old = """                    if conn.state != ConnectionState::Direct {
                        conn.transition(ConnectionState::Relay);
                    }
"""
new = """                    if conn.state != ConnectionState::Direct {
                        let candidate_generation = conn.last_candidate_generation;
                        if !conn.transition_for_generation(
                            ConnectionState::Relay,
                            generation,
                            candidate_generation,
                            "relay_peer_confirmed",
                        ) {
                            return false;
                        }
                    }
"""
count = text.count(old)
if count != 2:
    raise SystemExit(f"expected two relay confirmation transitions, found {count}")
text = text.replace(old, new)
relay.write_text(text, encoding="utf-8")
