import {
  type ApiResult,
  type ClientStatusSnapshot,
  type DaemonStatus,
  type DesktopStatus,
  type PeerStatus,
  type RouteStatus,
  type TunnelStatus,
  stoppedOperationStatus,
} from "../../../types/client";

import { getSettings } from "../config";
import {
  fetchDiagnosticsSnapshot,
  invokeDaemonStatusSnapshot,
  isTauri,
  tryInvoke,
} from "../http";
import { appendLog, getDaemonLogTail } from "../log";
import { clientStatusFromDesktopStatus } from "./desktop";
import { diagnosticsFromDaemonLogs } from "./logDiagnostics";

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
