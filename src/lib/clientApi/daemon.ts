// Daemon lifecycle and system actions for the unified client API.
//
// Split out of `clientApi.ts`.

import type {
  ApiResult,
  DaemonOperationStatus,
  PermissionStatus,
} from "../../types/client";

import { appendLog } from "./log";
import { daemonStartOptions, getSettings } from "./config";
import { isTauri, tryInvoke } from "./http";

export async function startDaemon(): Promise<ApiResult<{ started: boolean; message: string }>> {
  const settings = getSettings();
  if (isTauri()) {
    try {
      const res = await tryInvoke<string>("daemon_start", {
        options: {
          diagnosticsUrl: settings.diagnosticsUrl,
          controlServer: settings.controlServer,
          authToken: settings.authToken,
          networkId: settings.networkId,
          deviceName: settings.deviceName,
          tunInterface: settings.tunInterface,
          mtu: settings.mtu,
        },
      });
      appendLog(`daemon start succeeded: ${res}`);
      return { data: { started: true, message: String(res) }, source: "live" };
    } catch (err) {
      appendLog(`daemon start failed: ${err}`);
      return {
        data: { started: false, message: String(err) },
        source: "fallback",
        error: String(err),
      };
    }
  }
  appendLog("daemon start unavailable (no tauri bridge)");
  return {
    data: {
      started: false,
      message:
        "守护进程生命周期控制需要桌面壳。请手动运行 p2pnet-daemon --diagnostics-bind 127.0.0.1:39277。",
    },
    source: "fallback",
    error: "浏览器模式无法启动守护进程",
  };
}

export async function startDaemonElevated(): Promise<ApiResult<{ started: boolean; message: string }>> {
  const settings = getSettings();
  if (isTauri()) {
    try {
      const operation = await tryInvoke<DaemonOperationStatus>("daemon_start_elevated", {
        options: daemonStartOptions(settings),
      });
      const message = operation?.message ?? "已请求系统授权。";
      appendLog(`daemon elevated start requested: ${message}`);
      return { data: { started: true, message }, source: "live" };
    } catch (err) {
      appendLog(`daemon elevated start failed: ${err}`);
      return {
        data: { started: false, message: String(err) },
        source: "fallback",
        error: String(err),
      };
    }
  }
  return {
    data: {
      started: false,
      message: "提权启动 TUN 模式需要桌面客户端。",
    },
    source: "fallback",
    error: "浏览器模式无法提权启动守护进程",
  };
}

export async function stopDaemon(): Promise<ApiResult<{ stopped: boolean; message: string }>> {
  const settings = getSettings();
  if (isTauri()) {
    try {
      const operation = await tryInvoke<DaemonOperationStatus>("daemon_stop", {
        diagnosticsUrl: settings.diagnosticsUrl,
      });
      const message = operation?.message ?? "正在停止 TUN。";
      appendLog(`daemon stop requested: ${message}`);
      return { data: { stopped: true, message }, source: "live" };
    } catch (err) {
      appendLog(`daemon stop failed: ${err}`);
      return {
        data: { stopped: false, message: String(err) },
        source: "fallback",
        error: String(err),
      };
    }
  }
  appendLog("daemon stop unavailable (no tauri bridge)");
  return {
    data: {
      stopped: false,
      message: "停止守护进程需要桌面壳。请手动结束本地 p2pnet-daemon 进程。",
    },
    source: "fallback",
    error: "浏览器模式无法停止守护进程",
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
  if (isTauri()) {
    try {
      const res = await tryInvoke<string>("open_logs");
      return { data: { opened: true, message: String(res) }, source: "live" };
    } catch (err) {
      return {
        data: { opened: false, message: String(err) },
        source: "fallback",
        error: String(err),
      };
    }
  }
  return {
    data: {
      opened: false,
      message: "打开日志目录需要桌面壳。",
    },
    source: "fallback",
    error: "无法打开日志目录",
  };
}

export async function quitApp(): Promise<ApiResult<{ message: string }>> {
  const settings = getSettings();
  if (isTauri()) {
    try {
      const res = await tryInvoke<string>("app_quit", {
        diagnosticsUrl: settings.diagnosticsUrl,
      });
      appendLog(`app quit requested: ${res}`);
      return { data: { message: String(res) }, source: "live" };
    } catch (err) {
      appendLog(`app quit failed: ${err}`);
      return {
        data: { message: String(err) },
        source: "fallback",
        error: String(err),
      };
    }
  }
  return {
    data: { message: "退出程序需要桌面客户端。" },
    source: "fallback",
    error: "浏览器模式无法退出桌面程序",
  };
}

export async function getPermissionStatus(): Promise<ApiResult<PermissionStatus>> {
  if (isTauri()) {
    try {
      const status = await tryInvoke<PermissionStatus>("permission_status");
      if (status) {
        return { data: status, source: "live" };
      }
    } catch (err) {
      return {
        data: {
          platform: "unknown",
          canCreateTun: "unknown",
          canModifyRoutes: "unknown",
          needsElevation: true,
          recommendedAction: "权限状态未知，查询失败。",
          sudoCommand: null,
          details: [String(err)],
          checks: [],
        },
        source: "fallback",
        error: String(err),
      };
    }
  }

  // Browser mode fallback
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
      details: ["浏览器模式无法直接验证本地守护进程 euid。"],
      checks: [
        {
          id: "browser_euid_defer",
          label: "权限检查延后",
          status: "unknown",
          detail: "需要在桌面壳环境或本地终端日志中确认权限。",
        }
      ],
    },
    source: "fallback",
  };
}
