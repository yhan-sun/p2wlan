import {
  type ApiResult,
  type ClientSettings,
  type ClientStatusSnapshot,
  type DaemonStatus,
  type DesktopStatus,
  type RouteStatus,
  type TunnelStatus,
  stoppedDaemonStatus,
} from "../../../types/client";

import { getSettings } from "../config";
import { isTauri } from "../http";
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
