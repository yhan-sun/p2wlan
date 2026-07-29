/** Shared client-side types for the p2wlan desktop console. */

export type ConnectionState =
  | "idle"
  | "connecting"
  | "hole_punching"
  | "direct"
  | "fallback_to_relay"
  | "relay"
  | "failed"
  | "closed";

export type NetworkPath = "direct" | "relay";
export type PeerPath = NetworkPath | "direct_trial" | "offline";
export type DirectPathType = "lan" | "public_udp" | "overlay" | "relay" | "probing" | "unknown";
export type ConnectionType =
  | "lan_direct"
  | "public_direct"
  | "overlay_direct"
  | "direct"
  | "direct_trial"
  | "relay"
  | "offline"
  | "unknown";

export type CandidatePairSource =
  | "signaled"
  | "host"
  | "stun_observed"
  | "upnp"
  | "pcp"
  | "nat_pmp"
  | "predicted"
  | "birthday"
  | "learned"
  | "peer_reflexive";

export type CandidatePairState =
  | "frozen"
  | "waiting"
  | "probing"
  | "succeeded"
  | "selected"
  | "failed"
  | "degraded";

export type HealthStatus = "healthy" | "degraded" | "unhealthy" | "shutting_down";

export type DaemonLifecycle = "running" | "stopped" | "unknown" | "error";

export type DaemonOperationPhase =
  | "stopped"
  | "authorizing"
  | "launching"
  | "waiting_for_daemon"
  | "running"
  | "stopping"
  | "error";

export type RelayPolicy = "auto" | "direct-first" | "relay-only";

export type CloseBehavior = "keep-running" | "stop-and-quit";

export type DiagnosticCheckStatus = "pass" | "warn" | "fail" | "unknown" | "skipped";

export type DataSource = "live" | "fallback" | "cached";

const DEFAULT_TUN_INTERFACE =
  typeof navigator !== "undefined" && navigator.userAgent.toLowerCase().includes("win")
    ? "p2wlan"
    : "p2pnet0";

export interface PathHealthDiagnostics {
  last_success_age_ms: number | null;
  last_failure_age_ms: number | null;
  consecutive_failures: number;
  last_error: string | null;
  last_error_code?: string | null;
  latency_ms: number | null;
  rtt_ewma_ms?: number | null;
  jitter_ms?: number | null;
  success_count?: number;
  failure_count?: number;
}

export interface CandidatePairDiagnostics {
  local_endpoint: string | null;
  remote_endpoint: string;
  local_candidate_type: CandidatePairSource | null;
  remote_candidate_type: CandidatePairSource;
  local_interface: string | null;
  local_source: string | null;
  remote_source: CandidatePairSource;
  source: CandidatePairSource;
  local_generation: number;
  state: CandidatePairState;
  pair_state: CandidatePairState;
  nominated: boolean;
  selected: boolean;
  nominated_age_ms: number | null;
  selected_age_ms: number | null;
  last_probe_age_ms: number | null;
  probe_count: number;
  probe_due: boolean;
  probe_retry_after_ms: number | null;
  probe_retry_remaining_ms: number | null;
  first_success_age_ms: number | null;
  last_success_age_ms: number | null;
  last_failure_age_ms: number | null;
  consecutive_failures: number;
  last_error: string | null;
  last_error_code: string | null;
  rtt_ms: number | null;
  rtt_ewma_ms: number | null;
  jitter_ms: number | null;
  success_count: number;
  failure_count: number;
  direct_type: DirectPathType;
  is_public_udp_direct: boolean;
  is_overlay_direct: boolean;
  is_relay: boolean;
  warning: string | null;
}

export interface CandidatePairSourceStats {
  source: CandidatePairSource;
  pair_count: number;
  current_pair_count: number;
  selected_count: number;
  succeeded_count: number;
  probing_count: number;
  failed_count: number;
  degraded_count: number;
  success_count: number;
  failure_count: number;
  success_rate_per_mille: number | null;
  last_success_age_ms: number | null;
  last_failure_age_ms: number | null;
  history_success_count: number | null;
  history_failure_count: number | null;
  history_consecutive_failures: number | null;
  history_success_rate_per_mille: number | null;
  history_cooldown_remaining_ms: number | null;
  source_quality_rank: number | null;
  probe_budget_per_cycle: number | null;
  probe_budget_reason: string | null;
}

export interface PeerDiagnostics {
  node_id: string;
  device_name?: string;
  virtual_ip: string;
  endpoint: string | null;
  nat_type: string;
  state: ConnectionState;
  active_path: NetworkPath | null;
  direct_type: DirectPathType;
  probe_session_id?: string | null;
  probe_key_type?: string;
  selected_pair: CandidatePairDiagnostics | null;
  current_direct_pair: CandidatePairDiagnostics | null;
  consent_endpoint: string | null;
  is_public_udp_direct: boolean;
  is_overlay_direct: boolean;
  is_relay: boolean;
  warning: string | null;
  connected_for_ms: number | null;
  bytes_sent: number;
  bytes_received: number;
  relay_server: string | null;
  candidates: string[];
  direct: PathHealthDiagnostics;
  relay: PathHealthDiagnostics;
  candidate_pair_stats?: CandidatePairSourceStats[];
  candidate_pairs?: CandidatePairDiagnostics[];
  current_path_selection?: PathSelectionDiagnostics | null;
  last_path_selection?: PathSelectionDiagnostics | null;
}

export interface PathScoreDiagnostics {
  path: NetworkPath;
  score: number;
  reachable: boolean;
  reachability_score: number;
  preference_score: number;
  latency_score: number;
  stability_score: number;
  penalty_score: number;
  reason: string;
}

export interface PathSelectionDiagnostics {
  path: NetworkPath | null;
  direct_endpoint: string | null;
  reason_code: string;
  reason: string;
  direct_confirmed: boolean;
  relay_hedged: boolean;
  direct_score?: PathScoreDiagnostics | null;
  relay_score?: PathScoreDiagnostics | null;
}

export interface PeerManagerStats {
  total_peers: number;
  direct_connections: number;
  relay_connections: number;
  total_bytes_sent: number;
  total_bytes_received: number;
}

export interface TaskStatus {
  name: string;
  critical: boolean;
  running: boolean;
  finished: boolean;
  error: string | null;
}

export interface HealthSnapshot {
  status: HealthStatus;
  reason: string | null;
  critical_tasks: TaskStatus[];
  control_connected: boolean;
  last_control_success_secs_ago: number | null;
  reauth_required: boolean;
}

export interface RelayCandidateDiagnostics {
  region: string;
  endpoint: string;
  connect_latency_ms: number | null;
  error: string | null;
}

export interface RelaySelectionDiagnostics {
  selected_region: string | null;
  selected_endpoint: string | null;
  selected_connect_latency_ms: number | null;
  candidates: RelayCandidateDiagnostics[];
  last_error: string | null;
}

export interface GatewayMappingMethodDiagnostics {
  status: "idle" | "success" | "unavailable" | "failed" | string;
  last_error: string | null;
  attempts: number;
  last_attempt_age_ms: number | null;
  last_success_age_ms: number | null;
}

/** Result of opening the daemon UDP socket on the local NAT gateway. */
export interface GatewayMappingDiagnostics {
  enabled: boolean;
  local_endpoint: string | null;
  candidate_endpoint: string | null;
  candidate_source: "upnp" | "pcp" | "nat_pmp" | string | null;
  lease_seconds: number;
  renewal_remaining_ms: number | null;
  next_discovery_remaining_ms: number | null;
  upnp: GatewayMappingMethodDiagnostics;
  pcp: GatewayMappingMethodDiagnostics;
  nat_pmp: GatewayMappingMethodDiagnostics;
}

export interface NatProfileDiagnostics {
  mapping_behavior?: string;
  filtering_behavior?: string;
  public_endpoint?: string | null;
  likely_symmetric?: boolean | null;
  prediction_candidate?: boolean;
  birthday_candidate?: boolean;
  observations?: Array<{
    server: string;
    mapped_address: string | null;
    rtt_ms: number | null;
    error: string | null;
  }>;
}

export interface UdpSocketPoolMemberDiagnostics {
  socket_index: number;
  probes_sent: number;
  probe_acks_sent: number;
  probe_acks_received: number;
  encrypted_packets_sent: number;
  encrypted_packets_received: number;
  stun_mappings_discovered?: number;
}

export interface ProtocolDiagnostics {
  data_plane: string;
  handshake: string;
  key_exchange: string;
  aead: string;
  hash_kdf: string;
  device_identity: string;
  relay_transport: string;
  wireguard_interop: boolean;
  turn_compatible: boolean;
  security_audit: string;
}

export interface MtuDiagnostics {
  configured_mtu: number;
  profile: "low" | "relay_safe" | "default" | "high" | "jumbo_high_risk" | string;
  ipv6_safe_min_mtu: number;
  relay_safe_mtu: number;
  wireguard_style_mtu: number;
  common_ethernet_mtu: number;
  automatic_pmtu: boolean;
}

export interface TraversalSourceHistoryDiagnostics {
  source: string;
  success_count: number;
  failure_count: number;
  consecutive_failures: number;
  success_rate_per_mille: number | null;
  last_success_age_ms: number | null;
  last_failure_age_ms: number | null;
  cooldown_remaining_ms: number | null;
}

export interface TraversalHistoryDiagnostics {
  sources: TraversalSourceHistoryDiagnostics[];
}

/** Raw JSON from daemon `GET /status`. */
export interface DiagnosticsSnapshot {
  version?: string;
  process_id?: number;
  node_id: string;
  virtual_ip: string;
  network_id: string;
  network_generation?: number;
  protocol?: ProtocolDiagnostics;
  mtu?: MtuDiagnostics;
  udp_local_addr: string | null;
  udp_socket_count?: number;
  udp_socket_pool_active?: boolean;
  udp_socket_pool?: UdpSocketPoolMemberDiagnostics[];
  local_candidates?: string[];
  nat_profile?: NatProfileDiagnostics | null;
  gateway_mapping?: GatewayMappingDiagnostics;
  relay_servers: string[];
  relay_connected: boolean;
  relay_selection: RelaySelectionDiagnostics;
  traversal_history?: TraversalHistoryDiagnostics;
  peers: PeerDiagnostics[];
  stats: PeerManagerStats;
  health: HealthSnapshot;
}

export interface DaemonOperationStatus {
  phase: DaemonOperationPhase;
  message: string;
  startedAtMs: number;
  lastError: string | null;
}

export interface DesktopStatus {
  operation: DaemonOperationStatus;
  diagnostics: DiagnosticsSnapshot | null;
  diagnosticsUrl?: string;
  diagnosticsAlive?: boolean;
  diagnosticsStale?: boolean;
  diagnosticsError?: string | null;
}

export interface DaemonStatus {
  lifecycle: DaemonLifecycle;
  reachable: boolean;
  source: DataSource;
  nodeId: string;
  deviceName: string;
  virtualIp: string;
  networkId: string;
  overlayCidr: string;
  tunInterface: string;
  mtu: number;
  udpLocalAddr: string | null;
  diagnosticsUrl: string;
  controlConnected: boolean;
  controlServer: string;
  reauthRequired: boolean;
  healthStatus: HealthStatus;
  healthReason: string | null;
  relayConnected: boolean;
  relayEndpoint: string | null;
  relayRegion: string | null;
  relayServers: string[];
  natType: string;
  activePathSummary: string;
  lastError: string | null;
  lastControlSuccessSecsAgo: number | null;
  peerStats: PeerManagerStats;
  criticalTasks: TaskStatus[];
  updatedAt: number;
}

export interface PeerStatus {
  id: string;
  name: string;
  virtualIp: string;
  state: ConnectionState;
  path: PeerPath;
  connectionType: ConnectionType;
  connectionLabel: string;
  connectionDetail: string;
  latencyMs: number | null;
  endpoint: string;
  natType: string;
  lastActiveMs: number | null;
  bytesSent: number;
  bytesReceived: number;
  relayServer: string | null;
  lastError: string | null;
  candidates?: string[];
  directHealth?: PathHealthDiagnostics;
  relayHealth?: PathHealthDiagnostics;
  selectedPair?: CandidatePairDiagnostics | null;
  currentDirectPair?: CandidatePairDiagnostics | null;
  pathSelectionReason?: string | null;
  pathSelectionReasonCode?: string | null;
}

export interface TunnelStatus {
  interfaceName: string;
  mtu: number;
  cidr: string;
  virtualIp: string;
  udpBind: string | null;
  installed: boolean;
  up: boolean;
  source: DataSource;
}

export type RouteInstallState = "installed" | "missing" | "conflict" | "unknown";

export interface RouteEntry {
  destination: string;
  interfaceName: string;
  state: RouteInstallState;
  detail: string;
}

export interface RouteStatus {
  overlayCidr: string;
  interfaceName: string;
  entries: RouteEntry[];
  lastError: string | null;
  source: DataSource;
}

export interface ClientStatusSnapshot {
  daemon: DaemonStatus;
  peers: PeerStatus[];
  tunnel: TunnelStatus;
  route: RouteStatus;
  operation: DaemonOperationStatus;
  source: DataSource;
  error?: string;
}

export interface DiagnosticCheck {
  id: string;
  name: string;
  category:
    | "control"
    | "nat"
    | "relay"
    | "tun"
    | "route"
    | "daemon"
    | "protocol"
    | "performance";
  status: DiagnosticCheckStatus;
  detail: string;
  latencyMs?: number | null;
}

export interface DiagnosticsReport {
  checks: DiagnosticCheck[];
  logs: string[];
  protocol?: ProtocolDiagnostics;
  mtu?: MtuDiagnostics;
  source: DataSource;
  generatedAt: number;
}

export interface ClientSettings {
  controlServer: string;
  deviceName: string;
  networkId: string;
  mtu: number;
  overlayCidr: string;
  tunInterface: string;
  udpBind: string;
  udpAdvertise: string;
  socketPool: string;
  diagnosticsUrl: string;
  authToken: string;
  relayPolicy: RelayPolicy;
  relayServers: string;
  startOnBoot: boolean;
  closeBehavior: CloseBehavior;
  /** @deprecated use closeBehavior. Kept for migration from older builds. */
  minimizeToTray: boolean;
}

export interface PermissionCheck {
  id: string;
  label: string;
  status: "pass" | "warn" | "fail" | "unknown";
  detail: string;
}

export interface PermissionStatus {
  platform: "macos" | "windows" | "linux" | "unknown" | string;
  canCreateTun: "true" | "false" | "unknown" | string;
  canModifyRoutes: "true" | "false" | "unknown" | string;
  needsElevation: boolean;
  recommendedAction: string;
  sudoCommand?: string | null;
  details: string[];
  checks: PermissionCheck[];
}

export interface ApiResult<T> {
  data: T;
  source: DataSource;
  error?: string;
}

export const DEFAULT_SETTINGS: ClientSettings = {
  controlServer: "http://47.109.40.237:18080",
  deviceName: "this-device",
  networkId: "default",
  mtu: 1420,
  overlayCidr: "10.20.0.0/16",
  tunInterface: DEFAULT_TUN_INTERFACE,
  udpBind: "0.0.0.0:0",
  udpAdvertise: "",
  socketPool: "3",
  diagnosticsUrl: "http://127.0.0.1:39277/status",
  authToken: "",
  relayPolicy: "auto",
  relayServers: "",
  startOnBoot: false,
  closeBehavior: "keep-running",
  minimizeToTray: true,
};

export function emptyPeerStats(): PeerManagerStats {
  return {
    total_peers: 0,
    direct_connections: 0,
    relay_connections: 0,
    total_bytes_sent: 0,
    total_bytes_received: 0,
  };
}

export function stoppedOperationStatus(): DaemonOperationStatus {
  return {
    phase: "stopped",
    message: "TUN 未启动",
    startedAtMs: Date.now(),
    lastError: null,
  };
}

export function stoppedDaemonStatus(settings: ClientSettings, error?: string): DaemonStatus {
  return {
    lifecycle: error ? "error" : "stopped",
    reachable: false,
    source: "fallback",
    nodeId: "",
    deviceName: settings.deviceName,
    virtualIp: "",
    networkId: settings.networkId,
    overlayCidr: settings.overlayCidr,
    tunInterface: settings.tunInterface,
    mtu: settings.mtu,
    udpLocalAddr: null,
    diagnosticsUrl: settings.diagnosticsUrl,
    controlConnected: false,
    controlServer: settings.controlServer,
    reauthRequired: false,
    healthStatus: "unhealthy",
    healthReason: error ?? "守护进程未启动",
    relayConnected: false,
    relayEndpoint: null,
    relayRegion: null,
    relayServers: settings.relayServers
      ? settings.relayServers.split(",").map((s) => s.trim()).filter(Boolean)
      : [],
    natType: "unknown",
    activePathSummary: "offline",
    lastError: error ?? null,
    lastControlSuccessSecsAgo: null,
    peerStats: emptyPeerStats(),
    criticalTasks: [],
    updatedAt: Date.now(),
  };
}
