import type { DataSource, DiagnosticCheckStatus, HealthStatus } from "./base";
import type { PeerDiagnostics, PeerManagerStats } from "./peer";

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
