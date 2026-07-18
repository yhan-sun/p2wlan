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

export type HealthStatus = "healthy" | "degraded" | "unhealthy" | "shutting_down";

export type DaemonLifecycle = "running" | "stopped" | "unknown" | "error";

export type RelayPolicy = "auto" | "direct-first" | "relay-only";

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
}

export interface PeerDiagnostics {
  node_id: string;
  virtual_ip: string;
  endpoint: string | null;
  nat_type: string;
  state: ConnectionState;
  active_path: NetworkPath | null;
  connected_for_ms: number | null;
  bytes_sent: number;
  bytes_received: number;
  relay_server: string | null;
  candidates: string[];
  direct: PathHealthDiagnostics;
  relay: PathHealthDiagnostics;
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

/** Raw JSON from daemon `GET /status`. */
export interface DiagnosticsSnapshot {
  node_id: string;
  virtual_ip: string;
  network_id: string;
  udp_local_addr: string | null;
  relay_servers: string[];
  relay_connected: boolean;
  relay_selection: RelaySelectionDiagnostics;
  peers: PeerDiagnostics[];
  stats: PeerManagerStats;
  health: HealthSnapshot;
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
  path: NetworkPath | "offline";
  latencyMs: number | null;
  endpoint: string;
  natType: string;
  lastActiveMs: number | null;
  bytesSent: number;
  bytesReceived: number;
  relayServer: string | null;
  lastError: string | null;
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

export interface DiagnosticCheck {
  id: string;
  name: string;
  category: "control" | "nat" | "relay" | "tun" | "route" | "daemon";
  status: DiagnosticCheckStatus;
  detail: string;
  latencyMs?: number | null;
}

export interface DiagnosticsReport {
  checks: DiagnosticCheck[];
  logs: string[];
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
  diagnosticsUrl: string;
  authToken: string;
  relayPolicy: RelayPolicy;
  relayServers: string;
  startOnBoot: boolean;
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
  diagnosticsUrl: "http://127.0.0.1:39277/status",
  authToken: "",
  relayPolicy: "auto",
  relayServers: "",
  startOnBoot: false,
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
    controlConnected: false,
    controlServer: settings.controlServer,
    reauthRequired: false,
    healthStatus: "unhealthy",
    healthReason: error ?? "守护进程不可访问",
    relayConnected: false,
    relayEndpoint: null,
    relayRegion: null,
    relayServers: settings.relayServers
      ? settings.relayServers.split(",").map((s) => s.trim()).filter(Boolean)
      : [],
    natType: "unknown",
    activePathSummary: "offline",
    lastError: error ?? "诊断端点无法访问守护进程",
    lastControlSuccessSecsAgo: null,
    peerStats: emptyPeerStats(),
    criticalTasks: [],
    updatedAt: Date.now(),
  };
}
