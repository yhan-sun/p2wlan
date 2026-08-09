import {
  type ApiResult,
  type ClientSettings,
  type ClientStatusSnapshot,
  type DaemonStatus,
  type PeerStatus,
  type RouteStatus,
  type TunnelStatus,
  stoppedDaemonStatus,
  stoppedOperationStatus,
} from "../../../types/client";

import { getSettings } from "../config";
import { fetchDiagnosticsSnapshot } from "../http";
import { mapSnapshotToDaemonStatus } from "./daemon";
import { mapPeer } from "./peer";

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

export async function getClientStatusSnapshot(): Promise<ClientStatusSnapshot> {
  const settings = getSettings();
  const diagnostics = await fetchDiagnosticsSnapshot(settings.diagnosticsUrl);
  const daemon = diagnostics
    ? mapSnapshotToDaemonStatus(diagnostics, settings)
    : stoppedDaemonStatus(settings);
  const source = diagnostics ? "live" : "fallback";
  const operation = diagnostics
    ? {
        phase: "running" as const,
        message: "TUN 已连接",
        startedAtMs: Date.now(),
        lastError: null,
      }
    : stoppedOperationStatus();

  return {
    daemon,
    peers: diagnostics?.peers.map(mapPeer) ?? [],
    tunnel: tunnelFromDaemon(daemon, settings, source),
    route: routeFromDaemon(daemon, settings),
    operation,
    source,
  };
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
