// Daemon lifecycle and system actions for the unified client API.
//
// Split out of `clientApi.ts`.

import type { ApiResult, PermissionStatus } from "../../types/client";

import { appendLog } from "./log";

export async function startDaemon(): Promise<ApiResult<{ started: boolean; message: string }>> {
  appendLog("daemon start unavailable from web console");
  return {
    data: {
      started: false,
      message:
        "请在终端启动守护进程：p2pnet-daemon --diagnostics-bind 127.0.0.1:39277。",
    },
    source: "fallback",
    error: "网页控制台无法启动本地守护进程",
  };
}

export async function startDaemonElevated(): Promise<ApiResult<{ started: boolean; message: string }>> {
  appendLog("elevated daemon start unavailable from web console");
  return {
    data: {
      started: false,
      message: "请在管理员终端中启动守护进程以创建 TUN 网卡。",
    },
    source: "fallback",
    error: "网页控制台无法请求系统授权",
  };
}

export async function stopDaemon(): Promise<ApiResult<{ stopped: boolean; message: string }>> {
  appendLog("daemon stop unavailable from web console");
  return {
    data: {
      stopped: false,
      message: "请通过本地守护进程或终端停止 p2pnet-daemon。",
    },
    source: "fallback",
    error: "网页控制台无法停止本地守护进程",
  };
}

export async function rebuildRoutes(): Promise<ApiResult<{ ok: boolean; message: string }>> {
  appendLog("rebuild routes requested (stub)");
  return {
    data: {
      ok: false,
      message: "路由重建 API 尚未暴露；请重启守护进程以重新安装 Overlay 路由。",
    },
    source: "fallback",
    error: "尚未实现",
  };
}

export async function openLogs(): Promise<ApiResult<{ opened: boolean; message: string }>> {
  return {
    data: {
      opened: false,
      message: "请在本地终端或守护进程日志目录中查看日志。",
    },
    source: "fallback",
    error: "无法打开日志目录",
  };
}

export async function getPermissionStatus(): Promise<ApiResult<PermissionStatus>> {
  const isMac = navigator.userAgent.toLowerCase().includes("mac");
  const isLinux = navigator.userAgent.toLowerCase().includes("linux");
  const platform = isMac ? "macos" : isLinux ? "linux" : "windows";

  return {
    data: {
      platform,
      canCreateTun: "unknown",
      canModifyRoutes: "unknown",
      needsElevation: true,
      recommendedAction: isMac
        ? "请在终端使用 sudo 命令启动守护进程。"
        : isLinux
          ? "请使用 sudo 启动守护进程，或配置 CAP_NET_ADMIN。"
          : "请通过管理员终端启动守护进程。",
      sudoCommand: isMac || isLinux
        ? "sudo -E p2pnet-daemon --diagnostics-bind 127.0.0.1:39277"
        : null,
      details: ["网页控制台无法直接验证本地守护进程 euid。"],
      checks: [
        {
          id: "web_euid_defer",
          label: "权限检查延后",
          status: "unknown",
          detail: "需要在本地终端或守护进程日志中确认权限。",
        }
      ],
    },
    source: "fallback",
  };
}
