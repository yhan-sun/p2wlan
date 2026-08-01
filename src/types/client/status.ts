import type {
  ConnectionState,
  ConnectionType,
  DaemonLifecycle,
  DaemonOperationPhase,
  DataSource,
  HealthStatus,
  PeerPath,
} from "./base";
import type { DiagnosticsSnapshot, TaskStatus } from "./diagnostics";
import type {
  CandidatePairDiagnostics,
  PathHealthDiagnostics,
  PeerManagerStats,
} from "./peer";
import type { ClientSettings } from "./settings";

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
      ? settings.relayServers
          .split(",")
          .map((s) => s.trim())
          .filter(Boolean)
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
