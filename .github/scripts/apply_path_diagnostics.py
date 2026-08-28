from pathlib import Path


def replace_once(path: Path, old: str, new: str, label: str) -> None:
    text = path.read_text(encoding="utf-8")
    count = text.count(old)
    if count != 1:
        raise SystemExit(f"{label}: expected exactly one match, found {count}")
    path.write_text(text.replace(old, new, 1), encoding="utf-8")


path = Path("client/daemon/src/peer/diagnostics/peer.rs")

replace_once(
    path,
    """    pub state: ConnectionState,
    pub active_path: Option<NetworkPath>,
    pub direct_type: DirectPathType,
""",
    """    pub state: ConnectionState,
    pub active_path: Option<NetworkPath>,
    /// Atomic path-state snapshot committed under the peer write lock.
    #[serde(default)]
    pub path_state_revision: u64,
    #[serde(default)]
    pub path_network_generation: u64,
    #[serde(default)]
    pub path_candidate_generation: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub previous_path: Option<NetworkPath>,
    #[serde(default)]
    pub path_transition_reason: String,
    /// Per-path, per-network-generation PLPMTUD state. Direct and Relay are
    /// deliberately independent so one path cannot inherit the other's MTU.
    #[serde(default)]
    pub direct_path_mtu_generation: u64,
    #[serde(default)]
    pub direct_path_effective_mtu: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub direct_path_next_mtu_probe: Option<u32>,
    #[serde(default)]
    pub relay_path_mtu_generation: u64,
    #[serde(default)]
    pub relay_path_effective_mtu: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub relay_path_next_mtu_probe: Option<u32>,
    pub direct_type: DirectPathType,
""",
    "PeerDiagnostics path fields",
)

replace_once(
    path,
    """        Self {
            node_id: conn.node_id.clone(),
""",
    """        let path_state = conn.path_state_machine_snapshot();
        let path_mtu = conn.path_mtu_snapshot();
        let direct_path_effective_mtu = conn.effective_path_mtu(
            NetworkPath::Direct,
            path_mtu.direct_generation,
        );
        let relay_path_effective_mtu = conn.effective_path_mtu(
            NetworkPath::Relay,
            path_mtu.relay_generation,
        );

        Self {
            node_id: conn.node_id.clone(),
""",
    "PeerDiagnostics path snapshots",
)

replace_once(
    path,
    """            state: conn.state,
            active_path,
            direct_type,
""",
    """            state: conn.state,
            active_path,
            path_state_revision: path_state.revision,
            path_network_generation: path_state.network_generation,
            path_candidate_generation: path_state.candidate_generation,
            previous_path: path_state.previous_path,
            path_transition_reason: path_state.transition_reason.to_string(),
            direct_path_mtu_generation: path_mtu.direct_generation,
            direct_path_effective_mtu,
            direct_path_next_mtu_probe: path_mtu.direct_next_probe,
            relay_path_mtu_generation: path_mtu.relay_generation,
            relay_path_effective_mtu,
            relay_path_next_mtu_probe: path_mtu.relay_next_probe,
            direct_type,
""",
    "PeerDiagnostics path initialization",
)
