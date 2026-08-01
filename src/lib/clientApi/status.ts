// Daemon status snapshot assembly and peer/route/tunnel mapping for the
// unified client API.
//
// Split out of `clientApi.ts`.

import {
  type ApiResult,
  type CandidatePairDiagnostics,
  type ClientSettings,
  type ClientStatusSnapshot,
  type ConnectionType,
  type DaemonStatus,
  type DesktopStatus,
  type DiagnosticsSnapshot,
  type PathHealthDiagnostics,
  type PeerDiagnostics,
  type PeerPath,
  type PeerStatus,
  type RouteStatus,
  type TunnelStatus,
  stoppedDaemonStatus,
  stoppedOperationStatus,
} from "../../types/client";

import { appendLog, getDaemonLogTail } from "./log";
import { getSettings } from "./config";
import {
  fetchDiagnosticsSnapshot,
  invokeDaemonStatusSnapshot,
  isTauri,
  normalizeControlServer,
  readJsonBody,
  tryInvoke,
} from "./http";
import {
  CONTROL_STALE_AFTER_SECS,
  RELAY_PRESENTATION_FRESH_MS,
} from "./types";

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

function diagnosticsFromDaemonLogs(
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

export function udpPoolSummary(snapshot: DiagnosticsSnapshot | null): string | null {
  const socketCount = snapshot?.udp_socket_count ?? 0;
  if (socketCount <= 1) return null;
  const members = snapshot?.udp_socket_pool ?? [];
  const probes = members.reduce((sum, member) => sum + (member.probes_sent ?? 0), 0);
  const acksReceived = members.reduce((sum, member) => sum + (member.probe_acks_received ?? 0), 0);
  const acksSent = members.reduce((sum, member) => sum + (member.probe_acks_sent ?? 0), 0);
  const stunMappings = members.reduce(
    (sum, member) => sum + (member.stun_mappings_discovered ?? 0),
    0
  );
  return `socket pool=${socketCount} ${snapshot?.udp_socket_pool_active ? "active" : "standby"}, STUN映射=${stunMappings}, probe=${probes}, ACK=${acksReceived}/${acksSent}`;
}

export function natProfileSummary(snapshot: DiagnosticsSnapshot | null): string | null {
  const profile = snapshot?.nat_profile;
  if (!profile) return null;
  const parts = [
    profile.mapping_behavior ? `mapping=${profile.mapping_behavior}` : null,
    profile.filtering_behavior ? `filter=${profile.filtering_behavior}` : null,
    profile.public_endpoint ? `public=${profile.public_endpoint}` : null,
  ].filter(Boolean);
  return parts.length ? parts.join(" ") : null;
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

function mapSnapshotToDaemonStatus(
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

function endpointHost(endpoint: string | null | undefined): string | null {
  const value = endpoint?.trim();
  if (!value) return null;
  if (value.startsWith("[")) {
    const end = value.indexOf("]");
    return end > 1 ? value.slice(1, end).toLowerCase() : null;
  }
  const separator = value.lastIndexOf(":");
  return (separator > 0 ? value.slice(0, separator) : value).toLowerCase();
}

function isPrivateEndpoint(endpoint: string | null | undefined): boolean {
  const host = endpointHost(endpoint);
  if (!host) return false;
  if (host === "localhost" || host === "::1") return true;
  if (host.startsWith("fe80:") || host.startsWith("fc") || host.startsWith("fd")) return true;
  const octets = host.split(".").map(part => Number(part));
  if (octets.length !== 4 || octets.some(part => !Number.isInteger(part))) return false;
  const [a, b] = octets;
  return (
    a === 10 ||
    a === 127 ||
    (a === 169 && b === 254) ||
    (a === 172 && b >= 16 && b <= 31) ||
    (a === 192 && b === 168)
  );
}

function directPairForPresentation(peer: PeerDiagnostics): CandidatePairDiagnostics | null {
  return peer.current_direct_pair ?? peer.selected_pair ?? null;
}

function directPairLatencyMs(peer: PeerDiagnostics): number | null {
  const pair = directPairForPresentation(peer);
  return pair?.rtt_ewma_ms ?? pair?.rtt_ms ?? peer.direct.latency_ms;
}

function minNullable(values: Array<number | null | undefined>): number | null {
  const present = values.filter((value): value is number => value != null);
  return present.length ? Math.min(...present) : null;
}

function pathSuccessAgeMs(peer: PeerDiagnostics, path: PeerPath): number | null {
  if (path === "relay") return peer.relay.last_success_age_ms;
  if (path === "direct") return peer.direct.last_success_age_ms;
  return minNullable([peer.direct.last_success_age_ms, peer.relay.last_success_age_ms]);
}

function hasFreshRelayConfirmation(peer: PeerDiagnostics): boolean {
  return (
    peer.relay.last_success_age_ms != null &&
    peer.relay.last_success_age_ms <= RELAY_PRESENTATION_FRESH_MS &&
    peer.relay.consecutive_failures === 0
  );
}

function controlLastSeenAgeMs(peer: PeerDiagnostics): number | null {
  if (!peer.last_seen) return null;
  const timestampMs = peer.last_seen < 10_000_000_000 ? peer.last_seen * 1000 : peer.last_seen;
  const ageMs = Date.now() - timestampMs;
  return Number.isFinite(ageMs) ? Math.max(0, ageMs) : null;
}

function connectionPresentation(
  peer: PeerDiagnostics,
  path: PeerPath
): { type: ConnectionType; label: string; detail: string } {
  const pair = directPairForPresentation(peer);
  const endpoint = pair?.remote_endpoint ?? peer.endpoint ?? null;
  const reason = peer.current_path_selection?.reason;
  const relayHedged = peer.current_path_selection?.relay_hedged === true;

  if (path === "offline") {
    if (peer.online === false) {
      return {
        type: "offline",
        label: "离线",
        detail: "控制面标记该设备离线；等待对端重新注册或续租",
      };
    }
    return {
      type: "offline",
      label: "不可达",
      detail:
        peer.warning ??
        peer.relay.last_error ??
        peer.direct.last_error ??
        "当前没有可用路径",
    };
  }

  if (path === "connecting") {
    const waitingForRelay =
      peer.state === "fallback_to_relay" || peer.current_path_selection?.path === "relay";
    return {
      type: "connecting",
      label: waitingForRelay ? "中继确认中" : "连接中",
      detail:
        reason ??
        (waitingForRelay
          ? `直连仍在探测，正在等待 relay peer 确认${peer.direct.last_error ? `：${peer.direct.last_error}` : ""}`
          : endpoint
            ? `正在验证 ${endpoint}`
            : "正在建立可用路径"),
    };
  }

  if (path === "relay") {
    const directFailure = peer.direct.last_error ? `；直连不可用：${peer.direct.last_error}` : "";
    return {
      type: "relay",
      label: peer.direct.last_error ? "中继兜底" : "中继",
      detail:
        (reason ?? (peer.relay_server ? `通过 ${peer.relay_server}` : "当前流量经中继转发")) +
        directFailure,
    };
  }

  if (path === "direct_trial") {
    return {
      type: "direct_trial",
      label: "直连试探",
      detail: reason ?? (endpoint ? `正在验证 ${endpoint}` : "正在验证直连路径"),
    };
  }

  if (path === "direct") {
    const directType = pair?.direct_type ?? peer.direct_type;
    if (pair?.is_public_udp_direct || directType === "public_udp") {
      return {
        type: "public_direct",
        label: relayHedged ? "公网直连 + 中继备用" : "公网直连",
        detail: relayHedged
          ? reason ?? (endpoint ? `当前直连端点 ${endpoint}，同时发送中继备用流量` : "当前走公网 UDP 直连，并启用中继备用")
          : endpoint
            ? `当前直连端点 ${endpoint}`
            : "当前走公网 UDP 直连",
      };
    }
    if (directType === "lan") {
      return {
        type: "lan_direct",
        label: "局域网直连",
        detail: endpoint ? `当前直连端点 ${endpoint}` : "当前走局域网直连",
      };
    }
    if (pair?.is_overlay_direct || directType === "overlay") {
      return {
        type: "overlay_direct",
        label: "Overlay 直连",
        detail: endpoint ? `当前直连端点 ${endpoint}` : "当前走 overlay 端点直连",
      };
    }
    if (endpoint && isPrivateEndpoint(endpoint)) {
      return {
        type: "lan_direct",
        label: "局域网直连",
        detail: `当前直连端点 ${endpoint}`,
      };
    }
    if (directType === "probing") {
      return {
        type: "direct_trial",
        label: "直连试探",
        detail: endpoint ? `正在验证 ${endpoint}` : "正在验证直连路径",
      };
    }
    return {
      type: "direct",
      label: relayHedged ? "直连 + 中继备用" : "直连",
      detail: relayHedged
        ? reason ?? (endpoint ? `当前直连端点 ${endpoint}，同时发送中继备用流量` : "当前走直连路径，并启用中继备用")
        : endpoint
          ? `当前直连端点 ${endpoint}`
          : "当前走直连路径",
    };
  }

  return {
    type: "unknown",
    label: "未知",
    detail: "当前路径类型未知",
  };
}

function mapPeer(peer: PeerDiagnostics): PeerStatus {
  const selection = peer.current_path_selection;
  const isDirectTrial =
    selection?.path === "direct" &&
    selection?.reason_code === "path_direct_trial" &&
    (selection?.relay_hedged === true ||
      peer.active_path === null ||
      peer.active_path === undefined);
  const path: PeerPath = isDirectTrial
    ? "direct_trial"
    : peer.online === false
      ? "offline"
      : peer.active_path ??
        (selection?.path === "relay" && hasFreshRelayConfirmation(peer)
          ? "relay"
          : selection?.path === "relay" ||
              peer.state === "fallback_to_relay" ||
              peer.state === "hole_punching" ||
              peer.state === "connecting"
            ? "connecting"
            : "offline");
  const pathErrors = [peer.direct, peer.relay]
    .filter(health => health.last_error)
    .sort(
      (left, right) =>
        (left.last_failure_age_ms ?? Number.POSITIVE_INFINITY) -
        (right.last_failure_age_ms ?? Number.POSITIVE_INFINITY)
    );
  const lastActiveMs =
    peer.online === false
      ? controlLastSeenAgeMs(peer) ?? pathSuccessAgeMs(peer, path) ?? peer.connected_for_ms
      : pathSuccessAgeMs(peer, path) ?? peer.connected_for_ms ?? controlLastSeenAgeMs(peer);
  const latencyMs =
    path === "direct"
      ? directPairLatencyMs(peer)
      : path === "direct_trial"
        ? directPairLatencyMs(peer) ?? peer.relay.latency_ms
        : path === "relay"
          ? peer.relay.latency_ms
          : null;
  const presentation = connectionPresentation(peer, path);
  return {
    id: peer.node_id,
    name: peer.device_name?.trim() || peer.node_id.slice(0, 12),
    virtualIp: peer.virtual_ip,
    state: peer.state,
    path,
    connectionType: presentation.type,
    connectionLabel: presentation.label,
    connectionDetail: presentation.detail,
    latencyMs,
    endpoint: peer.endpoint ?? "",
    natType: peer.nat_type || "unknown",
    lastActiveMs,
    bytesSent: peer.bytes_sent,
    bytesReceived: peer.bytes_received,
    relayServer: peer.relay_server,
    lastError: pathErrors[0]?.last_error ?? null,
    candidates: peer.candidates,
    directHealth: peer.direct,
    relayHealth: peer.relay,
    selectedPair: peer.selected_pair,
    currentDirectPair: peer.current_direct_pair,
    pathSelectionReason: peer.current_path_selection?.reason ?? null,
    pathSelectionReasonCode: peer.current_path_selection?.reason_code ?? null,
  };
}

function tunnelFromDaemon(
  daemon: DaemonStatus,
  settings: ClientSettings,
  source: ApiResult<unknown>["source"]
): TunnelStatus {
  const running = daemon.lifecycle === "running" && daemon.reachable;
  return {
    interfaceName: settings.tunInterface,
    mtu: settings.mtu,
    cidr: settings.overlayCidr,
    virtualIp: daemon.virtualIp,
    udpBind: daemon.udpLocalAddr,
    installed: running && Boolean(daemon.virtualIp),
    up: running,
    source,
  };
}

function routeFromDaemon(daemon: DaemonStatus, settings: ClientSettings): RouteStatus {
  const running = daemon.lifecycle === "running" && daemon.reachable;
  const state = running ? (daemon.virtualIp ? "installed" : "missing") : "unknown";
  return {
    overlayCidr: settings.overlayCidr,
    interfaceName: settings.tunInterface,
    entries: [
      {
        destination: settings.overlayCidr,
        interfaceName: settings.tunInterface,
        state,
        detail: running
          ? daemon.virtualIp
            ? "守护进程健康，Overlay 路由按已安装处理"
            : "守护进程运行中，但尚未分配虚拟 IP"
          : "守护进程离线，路由状态未知",
      },
    ],
    lastError: daemon.lastError,
    source: "fallback",
  };
}

function daemonFromDesktopStatus(
  desktop: DesktopStatus,
  settings: ClientSettings
): DaemonStatus {
  if (desktop.diagnostics) {
    const daemon = mapSnapshotToDaemonStatus(desktop.diagnostics, settings);
    daemon.diagnosticsUrl = desktop.diagnosticsUrl ?? settings.diagnosticsUrl;
    if (desktop.diagnosticsStale) {
      daemon.source = "cached";
      daemon.healthStatus = "degraded";
      daemon.healthReason =
        desktop.diagnosticsError ?? "本地健康检查可访问，完整诊断详情暂时刷新中";
      daemon.lastError = null;
    }
    return daemon;
  }

  const error = desktop.operation.phase === "error" ? desktop.operation.lastError ?? desktop.operation.message : undefined;
  const daemon = stoppedDaemonStatus(settings, error);
  daemon.diagnosticsUrl = desktop.diagnosticsUrl ?? settings.diagnosticsUrl;
  if (desktop.diagnosticsAlive || desktop.operation.phase === "running") {
    daemon.lifecycle = "running";
    daemon.reachable = true;
    daemon.source = "cached";
    daemon.healthStatus = "degraded";
    daemon.healthReason =
      desktop.diagnosticsAlive
        ? desktop.diagnosticsError ?? "本地健康检查可访问，完整诊断详情暂时刷新中"
        : desktop.diagnosticsError ?? "TUN 已连接，完整诊断详情暂时刷新中";
    daemon.lastError = null;
  }
  if (
    desktop.operation.phase === "authorizing" ||
    desktop.operation.phase === "launching" ||
    desktop.operation.phase === "waiting_for_daemon" ||
    desktop.operation.phase === "stopping"
  ) {
    daemon.lifecycle = "unknown";
    daemon.healthStatus = "degraded";
    daemon.healthReason = desktop.operation.message;
    daemon.lastError = null;
  }
  return daemon;
}

export function clientStatusFromDesktopStatus(desktop: DesktopStatus): ClientStatusSnapshot {
  const settings = getSettings();
  const daemon = daemonFromDesktopStatus(desktop, settings);
  const source = desktop.diagnostics
    ? desktop.diagnosticsStale
      ? "cached"
      : "live"
    : desktop.diagnosticsAlive || isTauri()
      ? "cached"
      : "fallback";
  const error =
    desktop.operation.phase === "error"
      ? desktop.operation.lastError ?? desktop.operation.message
      : undefined;

  return {
    daemon,
    peers: desktop.diagnostics?.peers.map(mapPeer) ?? [],
    tunnel: tunnelFromDaemon(daemon, settings, source),
    route: routeFromDaemon(daemon, settings),
    operation: desktop.operation,
    source,
    error,
  };
}

export async function getClientStatusSnapshot(): Promise<ClientStatusSnapshot> {
  const settings = getSettings();
  let desktop: DesktopStatus;

  if (isTauri()) {
    try {
      desktop =
        (await tryInvoke<DesktopStatus>("desktop_status", {
          diagnosticsUrl: settings.diagnosticsUrl,
        })) ?? {
          operation: stoppedOperationStatus(),
          diagnostics: null,
        };
    } catch (error) {
      const message = String(error);
      desktop = {
        operation: {
          ...stoppedOperationStatus(),
          phase: "error",
          message: "无法读取桌面状态",
          lastError: message,
        },
        diagnostics: null,
      };
    }

    if (!desktop.diagnostics) {
      const diagnostics = await invokeDaemonStatusSnapshot(
        desktop.diagnosticsUrl ?? settings.diagnosticsUrl
      );
      if (diagnostics) {
        appendLog("daemon direct status recovered running state");
        desktop = {
          ...desktop,
          operation: {
            phase: "running",
            message: "TUN 已连接",
            startedAtMs: desktop.operation.startedAtMs || Date.now(),
            lastError: null,
          },
          diagnostics,
          diagnosticsUrl: desktop.diagnosticsUrl ?? settings.diagnosticsUrl,
          diagnosticsAlive: true,
          diagnosticsStale: false,
          diagnosticsError: null,
        };
      }
    }

    if (!desktop.diagnostics) {
      const diagnostics = diagnosticsFromDaemonLogs(await getDaemonLogTail(180), settings);
      if (diagnostics) {
        appendLog("daemon log snapshot recovered running state");
        desktop = {
          ...desktop,
          operation: {
            phase: "running",
            message: "TUN 已连接",
            startedAtMs: desktop.operation.startedAtMs || Date.now(),
            lastError: null,
          },
          diagnostics,
          diagnosticsUrl: desktop.diagnosticsUrl ?? settings.diagnosticsUrl,
          diagnosticsAlive: true,
          diagnosticsStale: true,
          diagnosticsError: "HTTP 诊断详情暂不可用，已从守护进程日志恢复关键状态",
        };
      }
    }
  } else {
    const diagnostics = await fetchDiagnosticsSnapshot(settings.diagnosticsUrl);
    desktop = {
      operation: diagnostics
        ? {
            phase: "running",
            message: "TUN 已连接",
            startedAtMs: Date.now(),
            lastError: null,
          }
        : stoppedOperationStatus(),
      diagnostics,
    };
  }

  return clientStatusFromDesktopStatus(desktop);
}

export async function getDaemonStatus(): Promise<ApiResult<DaemonStatus>> {
  const snapshot = await getClientStatusSnapshot();
  return { data: snapshot.daemon, source: snapshot.source, error: snapshot.error };
}

export async function listPeers(): Promise<ApiResult<PeerStatus[]>> {
  const snapshot = await getClientStatusSnapshot();
  return { data: snapshot.peers, source: snapshot.source, error: snapshot.error };
}

export async function getTunnelStatus(): Promise<ApiResult<TunnelStatus>> {
  const snapshot = await getClientStatusSnapshot();
  return { data: snapshot.tunnel, source: snapshot.source, error: snapshot.error };
}

export async function getRouteStatus(): Promise<ApiResult<RouteStatus>> {
  const snapshot = await getClientStatusSnapshot();
  return { data: snapshot.route, source: "fallback", error: snapshot.error };
}

export async function renamePeerDevice(
  peerId: string,
  deviceNameInput: string
): Promise<ApiResult<{ deviceName: string }>> {
  const settings = getSettings();
  const deviceName = deviceNameInput.trim();
  const fallback = { deviceName };
  if (!deviceName) {
    return { data: fallback, source: "fallback", error: "设备名称不能为空" };
  }
  if ([...deviceName].length > 128) {
    return { data: fallback, source: "fallback", error: "设备名称不能超过 128 个字符" };
  }
  if (!settings.authToken.trim()) {
    return { data: fallback, source: "fallback", error: "登录状态已失效，请重新登录" };
  }

  try {
    const controlServer = normalizeControlServer(settings.controlServer);
    if (isTauri()) {
      const response = await tryInvoke<{ deviceName: string }>("control_rename_device", {
        request: {
          controlServer,
          authToken: settings.authToken,
          deviceId: peerId,
          deviceName,
        },
      });
      if (response?.deviceName) {
        appendLog(`device renamed (${peerId}) via native bridge`);
        return { data: { deviceName: response.deviceName }, source: "live" };
      }
    }

    const response = await fetch(
      `${controlServer}/api/v1/devices/${encodeURIComponent(peerId)}`,
      {
        method: "PATCH",
        headers: {
          Authorization: `Bearer ${settings.authToken}`,
          "Content-Type": "application/json",
          Accept: "application/json",
        },
        body: JSON.stringify({ device_name: deviceName }),
      }
    );
    const body = await readJsonBody<{ success?: boolean; error?: string }>(response);
    if (!response.ok || !body?.success) {
      let message = body?.error || "设备名称保存失败";
      if (response.status === 401 || response.status === 403) {
        message = "当前账号没有权限修改该设备";
      } else if (response.status === 404) {
        message = "控制服务器暂不支持设备重命名，请先更新服务端";
      }
      appendLog(`device rename failed (${peerId}): ${message}`);
      return { data: fallback, source: "fallback", error: message };
    }
    appendLog(`device renamed (${peerId})`);
    return { data: fallback, source: "live" };
  } catch (error) {
    const message =
      error instanceof TypeError
        ? "无法连接控制服务器，请检查网络后重试"
        : error instanceof Error
          ? error.message
          : typeof error === "string"
            ? error
          : "设备名称保存失败";
    appendLog(`device rename failed (${peerId}): ${message}`);
    return { data: fallback, source: "fallback", error: message };
  }
}
