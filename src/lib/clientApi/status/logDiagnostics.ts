import {
  type ClientSettings,
  type DiagnosticsSnapshot,
  type PathHealthDiagnostics,
  type PeerDiagnostics,
} from "../../../types/client";

function emptyPathHealth(lastError: string | null = null): PathHealthDiagnostics {
  return {
    last_success_age_ms: null,
    last_failure_age_ms: lastError ? 0 : null,
    consecutive_failures: lastError ? 1 : 0,
    last_error: lastError,
    latency_ms: null,
  };
}

function findLastIndexOfLine(lines: string[], predicate: (line: string) => boolean): number {
  for (let i = lines.length - 1; i >= 0; i -= 1) {
    if (predicate(lines[i])) return i;
  }
  return -1;
}

function findLastLine(lines: string[], predicate: (line: string) => boolean): string | undefined {
  const index = findLastIndexOfLine(lines, predicate);
  return index >= 0 ? lines[index] : undefined;
}

export function diagnosticsFromDaemonLogs(
  logs: string[],
  settings: ClientSettings
): DiagnosticsSnapshot | null {
  const lastLaunch = findLastIndexOfLine(logs, line => line.includes("desktop-launcher: launching "));
  const scoped = lastLaunch >= 0 ? logs.slice(lastLaunch) : logs;
  const hasReady = scoped.some(line => line.includes("diagnostics endpoint is ready"));
  const hasTun = scoped.some(line => line.includes("TUN interface") && line.includes(" is up at "));
  const hasControl = scoped.some(line => line.includes("Control plane registration confirmed."));
  const assignedIpLine = findLastLine(scoped, line => line.includes("Assigned IP: "));
  const virtualIp =
    assignedIpLine?.match(/Assigned IP:\s*([0-9.]+)/)?.[1] ??
    findLastLine(scoped, line => line.includes("TUN interface") && line.includes(" is up at "))
      ?.match(/ is up at\s*([0-9.]+)/)?.[1] ??
    "";

  if (!hasReady || !hasTun || !hasControl || !virtualIp) return null;

  const nodeId =
    findLastLine(scoped, line => line.includes("Node ID: "))?.match(/Node ID:\s*(\S+)/)?.[1] ?? "";
  const udpLocalAddr =
    findLastLine(scoped, line => line.includes("UDP transport listening on "))
      ?.match(/UDP transport listening on\s*([^;]+)/)?.[1] ?? null;
  const relayLine = findLastLine(scoped, line => line.includes("Selected relay region "));
  const relayMatch = relayLine?.match(/Selected relay region\s+(\S+)\s+at\s+(\S+)\s+\((\d+)\s+ms/);
  const relayEndpoint =
    relayMatch?.[2] ??
    findLastLine(scoped, line => line.includes("Connected to relay server at "))
      ?.match(/Connected to relay server at\s+(\S+)/)?.[1] ??
    null;
  const relayRegion = relayMatch?.[1] ?? (relayEndpoint ? "default" : null);
  const relayLatency = relayMatch?.[3] ? Number(relayMatch[3]) : null;

  const peersById = new Map<string, PeerDiagnostics>();
  for (const line of scoped) {
    const joined = line.match(/Peer joined:\s+(\S+)\s+\(([0-9.]+)\)/);
    if (joined) {
      const [, peerId, peerIp] = joined;
      peersById.set(peerId, {
        node_id: peerId,
        virtual_ip: peerIp,
        endpoint: null,
        nat_type: "unknown",
        state: "connecting",
        active_path: null,
        direct_type: "unknown",
        selected_pair: null,
        current_direct_pair: null,
        consent_endpoint: null,
        is_public_udp_direct: false,
        is_overlay_direct: false,
        is_relay: false,
        warning: null,
        connected_for_ms: null,
        bytes_sent: 0,
        bytes_received: 0,
        relay_server: relayEndpoint,
        candidates: [],
        direct: emptyPathHealth(),
        relay: emptyPathHealth(),
        candidate_pair_stats: [],
        candidate_pairs: [],
      });
    }

    const state = line.match(/Peer\s+(\S+)\s+state:\s+.*(?:→|->)\s+(\S+)/);
    if (state) {
      const [, peerId, rawState] = state;
      const peer = peersById.get(peerId);
      if (peer) {
        const normalized = rawState as PeerDiagnostics["state"];
        peer.state = normalized;
        peer.active_path =
          normalized === "direct" ? "direct" : normalized === "relay" ? "relay" : null;
        peer.direct_type =
          normalized === "direct" ? "probing" : normalized === "relay" ? "relay" : "unknown";
        peer.is_relay = normalized === "relay";
        if (normalized === "relay") {
          peer.relay = { ...emptyPathHealth(), last_success_age_ms: 0, latency_ms: relayLatency };
          peer.direct = emptyPathHealth("UDP 打洞未成功，已切到中继");
          peer.relay_server = relayEndpoint;
        }
      }
    }
  }

  const peers = Array.from(peersById.values());
  const directConnections = peers.filter(peer => peer.active_path === "direct").length;
  const relayConnections = peers.filter(peer => peer.active_path === "relay").length;

  return {
    node_id: nodeId,
    virtual_ip: virtualIp,
    network_id: settings.networkId,
    udp_local_addr: udpLocalAddr,
    relay_servers: relayEndpoint ? [relayEndpoint] : settings.relayServers.split(",").map(s => s.trim()).filter(Boolean),
    relay_connected: Boolean(relayEndpoint),
    relay_selection: {
      selected_region: relayRegion,
      selected_endpoint: relayEndpoint,
      selected_connect_latency_ms: relayLatency,
      candidates: relayEndpoint
        ? [{ region: relayRegion ?? "default", endpoint: relayEndpoint, connect_latency_ms: relayLatency, error: null }]
        : [],
      last_error: null,
    },
    peers,
    stats: {
      total_peers: peers.length,
      direct_connections: directConnections,
      relay_connections: relayConnections,
      total_bytes_sent: 0,
      total_bytes_received: 0,
    },
    health: {
      status: "degraded",
      reason: "HTTP 诊断详情暂不可用，已从守护进程日志恢复关键状态",
      critical_tasks: [],
      control_connected: hasControl,
      last_control_success_secs_ago: 0,
      reauth_required: false,
    },
  };
}
