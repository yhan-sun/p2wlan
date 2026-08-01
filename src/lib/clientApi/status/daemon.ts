import {
  type ClientSettings,
  type DaemonStatus,
  type DiagnosticsSnapshot,
  type PeerDiagnostics,
} from "../../../types/client";

import { CONTROL_STALE_AFTER_SECS } from "../types";

function inferNatType(peers: PeerDiagnostics[]): string {
  const types = peers.map((p) => p.nat_type).filter((t) => t && t !== "Unknown");
  if (types.length === 0) return "unknown";
  // Most common peer-reported remote NAT is not local; surface first non-empty as hint.
  return types[0] ?? "unknown";
}

function activePathSummary(snapshot: DiagnosticsSnapshot): string {
  const { direct_connections, relay_connections, total_peers } = snapshot.stats;
  if (total_peers === 0) return "no peers";
  if (direct_connections + relay_connections === 0) return "peers offline";
  if (direct_connections > 0 && relay_connections === 0) {
    return `direct (${direct_connections})`;
  }
  if (relay_connections > 0 && direct_connections === 0) {
    return `relay (${relay_connections})`;
  }
  return `mixed d${direct_connections}/r${relay_connections}`;
}

function lastErrorFromSnapshot(snapshot: DiagnosticsSnapshot): string | null {
  const directPathAvailable = snapshot.stats.direct_connections > 0;
  // A healthy TCP/TLS session to the relay service does not prove that any
  // destination peer is registered and reachable through it.
  const relayPathAvailable = snapshot.stats.relay_connections > 0;
  const anyPathAvailable = directPathAvailable || relayPathAvailable;
  const isOptionalRelayIssue = (message: string) => {
    const normalized = message.toLowerCase();
    return normalized.includes("relay-inbound") || normalized.startsWith("relay ");
  };

  if (
    snapshot.health.reason &&
    !(anyPathAvailable && isOptionalRelayIssue(snapshot.health.reason))
  ) {
    return snapshot.health.reason;
  }
  if (snapshot.relay_selection.last_error && !anyPathAvailable) {
    return snapshot.relay_selection.last_error;
  }
  const failedTask = snapshot.health.critical_tasks.find((t) => t.error);
  if (failedTask?.error && !(anyPathAvailable && failedTask.name === "relay-inbound")) {
    return `${failedTask.name}: ${failedTask.error}`;
  }
  return null;
}

export function mapSnapshotToDaemonStatus(
  snapshot: DiagnosticsSnapshot,
  settings: ClientSettings
): DaemonStatus {
  const lastControlSuccessSecsAgo = snapshot.health.last_control_success_secs_ago;
  const controlStale =
    lastControlSuccessSecsAgo != null && lastControlSuccessSecsAgo > CONTROL_STALE_AFTER_SECS;
  const controlConnected = snapshot.health.control_connected && !controlStale;
  const healthReason = controlStale
    ? `控制面最近成功同步已 ${lastControlSuccessSecsAgo} 秒，peer/候选状态可能已过期`
    : snapshot.health.reason;
  const healthStatus =
    snapshot.health.status === "healthy" && controlStale ? "degraded" : snapshot.health.status;

  return {
    lifecycle: "running",
    reachable: true,
    source: "live",
    nodeId: snapshot.node_id,
    deviceName: settings.deviceName,
    virtualIp: snapshot.virtual_ip,
    networkId: snapshot.network_id,
    overlayCidr: settings.overlayCidr,
    tunInterface: settings.tunInterface,
    mtu: settings.mtu,
    udpLocalAddr: snapshot.udp_local_addr,
    diagnosticsUrl: settings.diagnosticsUrl,
    controlConnected,
    controlServer: settings.controlServer,
    reauthRequired: snapshot.health.reauth_required,
    healthStatus,
    healthReason,
    relayConnected: snapshot.relay_connected,
    relayEndpoint: snapshot.relay_selection.selected_endpoint,
    relayRegion: snapshot.relay_selection.selected_region,
    relayServers: snapshot.relay_servers,
    natType: inferNatType(snapshot.peers),
    activePathSummary: activePathSummary(snapshot),
    lastError: lastErrorFromSnapshot(snapshot),
    lastControlSuccessSecsAgo,
    peerStats: snapshot.stats,
    criticalTasks: snapshot.health.critical_tasks,
    updatedAt: Date.now(),
  };
}
