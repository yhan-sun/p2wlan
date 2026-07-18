/**
 * Unified client API for the p2wlan desktop console.
 *
 * Primary source: local daemon diagnostics endpoint (`/status`).
 * Secondary: localStorage settings, optional Tauri commands when available.
 * Pages must not hardcode mock data — fallbacks live only in this layer.
 */

import {
  type ApiResult,
  type ClientSettings,
  type DaemonStatus,
  type DiagnosticCheck,
  type DiagnosticsReport,
  type DiagnosticsSnapshot,
  type PeerDiagnostics,
  type PeerStatus,
  type RouteStatus,
  type TunnelStatus,
  type PermissionStatus,
  DEFAULT_SETTINGS,
  stoppedDaemonStatus,
} from "../types/client";

const SETTINGS_KEY = "p2wlan.client.settings";
const LOG_KEY = "p2wlan.client.logs";
const MAX_LOG_LINES = 400;

export type AuthMode = "login" | "register";

export interface AuthUser {
  id?: string;
  email?: string;
  created_at?: number;
  createdAt?: number;
}

export interface AuthSession {
  token: string;
  user?: AuthUser;
  controlServer: string;
}

interface AuthResponseBody {
  success?: boolean;
  token?: string;
  user?: AuthUser;
  error?: string;
}

function isTauri(): boolean {
  return typeof window !== "undefined" && "__TAURI_INTERNALS__" in window;
}

async function tryInvoke<T>(command: string, args?: Record<string, unknown>): Promise<T | null> {
  if (!isTauri()) return null;
  const { invoke } = await import("@tauri-apps/api/core");
  return (await invoke<T>(command, args)) as T;
}

export function getSettings(): ClientSettings {
  try {
    const raw = localStorage.getItem(SETTINGS_KEY);
    if (!raw) return { ...DEFAULT_SETTINGS };
    const parsed = JSON.parse(raw) as Partial<ClientSettings>;
    const settings = { ...DEFAULT_SETTINGS, ...parsed };
    const legacyLocalControl =
      settings.controlServer === "http://127.0.0.1:8080" ||
      settings.controlServer === "http://localhost:8080";
    if (legacyLocalControl && !settings.authToken) {
      settings.controlServer = DEFAULT_SETTINGS.controlServer;
    }
    return settings;
  } catch {
    return { ...DEFAULT_SETTINGS };
  }
}

export function saveSettings(settings: ClientSettings): ApiResult<ClientSettings> {
  const errors = validateSettings(settings);
  if (errors.length > 0) {
    return { data: settings, source: "fallback", error: errors.join("; ") };
  }
  localStorage.setItem(SETTINGS_KEY, JSON.stringify(settings));
  appendLog(`settings saved (control=${settings.controlServer}, mtu=${settings.mtu})`);
  return { data: settings, source: "live" };
}

async function readJsonBody<T>(res: Response): Promise<T | null> {
  const text = await res.text();
  if (!text) return null;
  try {
    return JSON.parse(text) as T;
  } catch {
    return null;
  }
}

function normalizeControlServer(url: string): string {
  const trimmed = url.trim().replace(/\/+$/, "");
  const parsed = new URL(trimmed);
  if (parsed.protocol !== "http:" && parsed.protocol !== "https:") {
    throw new Error("控制服务器必须使用 http 或 https");
  }
  return parsed.toString().replace(/\/+$/, "");
}

function zhAuthError(message: string, status?: number): string {
  const normalized = message.toLowerCase();
  if (normalized.includes("failed to fetch") || normalized.includes("load failed") || normalized.includes("networkerror")) {
    return "无法连接控制服务器，请检查服务器地址或网络";
  }
  if (normalized.includes("invalid credentials")) return "邮箱或密码错误";
  if (normalized.includes("invalid email")) return "邮箱格式不正确";
  if (normalized.includes("invalid password")) return "密码不符合要求，至少需要 6 个字符";
  if (normalized.includes("registration failed")) return "注册失败，邮箱可能已存在";
  if (normalized.includes("rate limit")) return "请求过于频繁，请稍后再试";
  if (status === 401) return "认证失败，请检查邮箱和密码";
  if (status === 409) return "账号已存在";
  return message || "控制服务器请求失败";
}

export async function authenticateWithControl(
  mode: AuthMode,
  controlServerInput: string,
  emailInput: string,
  password: string
): Promise<ApiResult<AuthSession>> {
  const controlServer = normalizeControlServer(controlServerInput);
  const email = emailInput.trim().toLowerCase();
  if (!email) throw new Error("请输入邮箱");
  if (!password) throw new Error("请输入密码");
  if (password.length < 6) throw new Error("密码至少需要 6 个字符");

  const controller = new AbortController();
  const timer = window.setTimeout(() => controller.abort(), 8000);
  try {
    const endpoint = `${controlServer}/api/v1/${mode === "register" ? "register" : "login"}`;
    const res = await fetch(endpoint, {
      method: "POST",
      signal: controller.signal,
      headers: {
        "Content-Type": "application/json",
        Accept: "application/json",
      },
      body: JSON.stringify({ email, password }),
    });
    const body = await readJsonBody<AuthResponseBody>(res);
    if (!res.ok) {
      throw new Error(zhAuthError(body?.error || "", res.status));
    }
    if (!body?.success || !body.token) {
      throw new Error(body?.error || "控制服务器没有返回有效 token");
    }

    const settings = getSettings();
    const nextSettings = {
      ...settings,
      controlServer,
      authToken: body.token,
    };
    saveSettings(nextSettings);
    localStorage.setItem("token", body.token);
    appendLog(`${mode === "register" ? "registered" : "logged in"} control user (${email})`);
    return {
      data: {
        token: body.token,
        user: body.user,
        controlServer,
      },
      source: "live",
    };
  } catch (err) {
    if (err instanceof DOMException && err.name === "AbortError") {
      throw new Error("连接控制服务器超时");
    }
    if (err instanceof TypeError) {
      throw new Error("无法连接控制服务器，请检查服务器地址或网络");
    }
    if (err instanceof Error) {
      throw new Error(zhAuthError(err.message));
    }
    throw err;
  } finally {
    window.clearTimeout(timer);
  }
}

export function validateSettings(settings: ClientSettings): string[] {
  const errors: string[] = [];
  if (!settings.controlServer.trim()) {
    errors.push("控制服务器不能为空");
  } else {
    try {
      // eslint-disable-next-line no-new
      new URL(settings.controlServer);
    } catch {
      errors.push("控制服务器必须是有效 URL");
    }
  }
  if (!settings.deviceName.trim()) {
    errors.push("设备名称不能为空");
  }
  if (settings.mtu < 576 || settings.mtu > 9000) {
    errors.push("MTU 必须在 576 到 9000 之间");
  }
  if (!settings.networkId.trim()) {
    errors.push("网络 ID 不能为空");
  }
  if (!settings.diagnosticsUrl.trim()) {
    errors.push("诊断地址不能为空");
  } else {
    try {
      // eslint-disable-next-line no-new
      new URL(settings.diagnosticsUrl);
    } catch {
      errors.push("诊断地址必须是有效 URL");
    }
  }
  if (settings.overlayCidr && !/^\d+\.\d+\.\d+\.\d+\/\d+$/.test(settings.overlayCidr)) {
    errors.push("Overlay CIDR 格式应类似 10.20.0.0/16");
  }
  return errors;
}

function appendLog(line: string): void {
  const stamp = new Date().toISOString().replace("T", " ").replace("Z", "");
  const entry = `${stamp}  ${line}`;
  try {
    const existing = localStorage.getItem(LOG_KEY);
    const lines = existing ? existing.split("\n") : [];
    lines.push(entry);
    while (lines.length > MAX_LOG_LINES) lines.shift();
    localStorage.setItem(LOG_KEY, lines.join("\n"));
  } catch {
    // ignore quota errors
  }
}

export function getRecentLogs(limit = 300): string[] {
  try {
    const existing = localStorage.getItem(LOG_KEY);
    if (!existing) return [];
    const lines = existing.split("\n").filter(Boolean);
    return lines.slice(-Math.min(limit, MAX_LOG_LINES));
  } catch {
    return [];
  }
}

async function fetchDiagnosticsSnapshot(url: string): Promise<DiagnosticsSnapshot | null> {
  const controller = new AbortController();
  const timer = window.setTimeout(() => controller.abort(), 1500);
  try {
    const res = await fetch(url, {
      method: "GET",
      signal: controller.signal,
      headers: { Accept: "application/json" },
    });
    if (!res.ok) return null;
    return (await res.json()) as DiagnosticsSnapshot;
  } catch {
    return null;
  } finally {
    window.clearTimeout(timer);
  }
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

function lastErrorFromSnapshot(snapshot: DiagnosticsSnapshot): string | null {
  if (snapshot.health.reason) return snapshot.health.reason;
  if (snapshot.relay_selection.last_error) return snapshot.relay_selection.last_error;
  const failedTask = snapshot.health.critical_tasks.find((t) => t.error);
  if (failedTask?.error) return `${failedTask.name}: ${failedTask.error}`;
  return null;
}

function mapSnapshotToDaemonStatus(
  snapshot: DiagnosticsSnapshot,
  settings: ClientSettings
): DaemonStatus {
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
    controlConnected: snapshot.health.control_connected,
    controlServer: settings.controlServer,
    reauthRequired: snapshot.health.reauth_required,
    healthStatus: snapshot.health.status,
    healthReason: snapshot.health.reason,
    relayConnected: snapshot.relay_connected,
    relayEndpoint: snapshot.relay_selection.selected_endpoint,
    relayRegion: snapshot.relay_selection.selected_region,
    relayServers: snapshot.relay_servers,
    natType: inferNatType(snapshot.peers),
    activePathSummary: activePathSummary(snapshot),
    lastError: lastErrorFromSnapshot(snapshot),
    lastControlSuccessSecsAgo: snapshot.health.last_control_success_secs_ago,
    peerStats: snapshot.stats,
    criticalTasks: snapshot.health.critical_tasks,
    updatedAt: Date.now(),
  };
}

function mapPeer(peer: PeerDiagnostics): PeerStatus {
  const path =
    peer.active_path ??
    (peer.state === "direct" || peer.state === "relay" ? peer.state : "offline");
  const lastActiveMs =
    peer.direct.last_success_age_ms ??
    peer.relay.last_success_age_ms ??
    peer.connected_for_ms;
  const latencyMs =
    peer.direct.last_success_age_ms != null && peer.direct.consecutive_failures === 0
      ? null
      : null;
  return {
    id: peer.node_id,
    name: peer.node_id.slice(0, 12),
    virtualIp: peer.virtual_ip,
    state: peer.state,
    path: path === "direct" || path === "relay" ? path : "offline",
    latencyMs,
    endpoint: peer.endpoint ?? "",
    natType: peer.nat_type || "unknown",
    lastActiveMs,
    bytesSent: peer.bytes_sent,
    bytesReceived: peer.bytes_received,
    relayServer: peer.relay_server,
    lastError: peer.direct.last_error ?? peer.relay.last_error,
  };
}

export async function getDaemonStatus(): Promise<ApiResult<DaemonStatus>> {
  const settings = getSettings();

  if (isTauri()) {
    try {
      const fromTauri = await tryInvoke<DiagnosticsSnapshot>("daemon_status", {
        diagnosticsUrl: settings.diagnosticsUrl,
      });
      if (fromTauri) {
        return { data: mapSnapshotToDaemonStatus(fromTauri, settings), source: "live" };
      }
    } catch (err) {
      return {
        data: stoppedDaemonStatus(settings, String(err)),
        source: "fallback",
        error: String(err),
      };
    }
  }

  const snapshot = await fetchDiagnosticsSnapshot(settings.diagnosticsUrl);
  if (snapshot) {
    return { data: mapSnapshotToDaemonStatus(snapshot, settings), source: "live" };
  }

  return {
    data: stoppedDaemonStatus(settings, "诊断端点不可访问"),
    source: "fallback",
    error: "诊断端点不可访问",
  };
}

export async function listPeers(): Promise<ApiResult<PeerStatus[]>> {
  const settings = getSettings();
  const snapshot = await fetchDiagnosticsSnapshot(settings.diagnosticsUrl);
  if (!snapshot) {
    return {
      data: [],
      source: "fallback",
      error: "诊断端点不可访问",
    };
  }
  return {
    data: snapshot.peers.map(mapPeer),
    source: "live",
  };
}

export async function getTunnelStatus(): Promise<ApiResult<TunnelStatus>> {
  const settings = getSettings();
  const status = await getDaemonStatus();
  const running = status.data.lifecycle === "running" && status.data.reachable;
  return {
    data: {
      interfaceName: settings.tunInterface,
      mtu: settings.mtu,
      cidr: settings.overlayCidr,
      virtualIp: status.data.virtualIp,
      udpBind: status.data.udpLocalAddr,
      installed: running && Boolean(status.data.virtualIp),
      up: running,
      source: status.source,
    },
    source: status.source,
    error: status.error,
  };
}

export async function getRouteStatus(): Promise<ApiResult<RouteStatus>> {
  const settings = getSettings();
  const status = await getDaemonStatus();
  const running = status.data.lifecycle === "running" && status.data.reachable;
  const entryState = running
    ? status.data.virtualIp
      ? "installed"
      : "missing"
    : "unknown";
  return {
    data: {
      overlayCidr: settings.overlayCidr,
      interfaceName: settings.tunInterface,
      entries: [
        {
          destination: settings.overlayCidr,
          interfaceName: settings.tunInterface,
          state: entryState,
          detail: running
            ? status.data.virtualIp
              ? "守护进程健康，Overlay 路由按已安装处理"
              : "守护进程运行中，但尚未分配虚拟 IP"
            : "守护进程离线，路由状态未知",
        },
      ],
      lastError: status.data.lastError,
      source: status.source === "live" ? "fallback" : "fallback",
    },
    source: "fallback",
    error:
      status.source === "live"
        ? "诊断 API 尚未暴露真实路由生命周期，当前显示推断状态"
        : status.error,
  };
}

export async function getDiagnostics(): Promise<ApiResult<DiagnosticsReport>> {
  const settings = getSettings();
  const statusResult = await getDaemonStatus();
  const status = statusResult.data;
  const snapshot =
    statusResult.source === "live"
      ? await fetchDiagnosticsSnapshot(settings.diagnosticsUrl)
      : null;

  const checks: DiagnosticCheck[] = [];

  checks.push({
    id: "daemon",
    name: "守护进程",
    category: "daemon",
    status: status.reachable ? "pass" : "fail",
    detail: status.reachable
      ? `可访问 (${status.healthStatus})`
      : status.lastError ?? "不可访问",
  });

  checks.push({
    id: "control",
    name: "控制面",
    category: "control",
    status: !status.reachable
      ? "skipped"
      : status.reauthRequired
        ? "fail"
        : status.controlConnected
          ? "pass"
          : "warn",
    detail: !status.reachable
      ? "守护进程离线"
      : status.reauthRequired
        ? "需要重新登录"
        : status.controlConnected
          ? `connected${
              status.lastControlSuccessSecsAgo != null
                ? ` (上次成功 ${status.lastControlSuccessSecsAgo}s 前)`
                : ""
            }`
          : "未连接",
  });

  checks.push({
    id: "udp",
    name: "UDP / 打洞",
    category: "nat",
    status: !status.reachable
      ? "skipped"
      : status.udpLocalAddr
        ? status.peerStats.direct_connections > 0
          ? "pass"
          : "warn"
        : "fail",
    detail: !status.reachable
      ? "守护进程离线"
      : status.udpLocalAddr
        ? `已绑定 ${status.udpLocalAddr}; 直连节点=${status.peerStats.direct_connections}`
        : "未获取 UDP 本地地址",
  });

  checks.push({
    id: "relay",
    name: "中继连通性",
    category: "relay",
    status: !status.reachable
      ? "skipped"
      : status.relayConnected
        ? "pass"
        : status.relayServers.length > 0
          ? "warn"
          : "unknown",
    detail: !status.reachable
      ? "守护进程离线"
      : status.relayConnected
        ? `已连接 ${status.relayRegion ?? ""} ${status.relayEndpoint ?? ""}`.trim()
        : status.relayServers.length > 0
          ? `已配置但未连接 (${status.relayServers.length} 个候选)`
          : "未配置中继服务器",
    latencyMs: snapshot?.relay_selection.selected_connect_latency_ms ?? null,
  });

  checks.push({
    id: "tun",
    name: "TUN 网卡",
    category: "tun",
    status: !status.reachable
      ? "skipped"
      : status.virtualIp
        ? "pass"
        : "warn",
    detail: !status.reachable
      ? "守护进程离线"
      : status.virtualIp
        ? `${settings.tunInterface} ${status.virtualIp} mtu=${settings.mtu}`
        : "尚未分配虚拟 IP",
  });

  const route = await getRouteStatus();
  const routeState = route.data.entries[0]?.state ?? "unknown";
  checks.push({
    id: "route",
    name: "Overlay 路由",
    category: "route",
    status:
      routeState === "installed"
        ? "pass"
        : routeState === "missing"
          ? "fail"
          : routeState === "conflict"
            ? "fail"
            : "unknown",
    detail: route.data.entries[0]?.detail ?? "unknown",
  });

  if (snapshot) {
    for (const peer of snapshot.peers.slice(0, 8)) {
      if (peer.direct.last_error || peer.relay.last_error) {
        checks.push({
          id: `peer-${peer.node_id}`,
          name: `节点 ${peer.node_id.slice(0, 8)}`,
          category: "nat",
          status: peer.active_path ? "warn" : "fail",
          detail: peer.direct.last_error ?? peer.relay.last_error ?? peer.state,
        });
      }
    }
  }

  const logs = getRecentLogs(300);
  if (statusResult.error) {
    appendLog(`diagnostics: ${statusResult.error}`);
  }

  return {
    data: {
      checks,
      logs: getRecentLogs(300).length ? getRecentLogs(300) : logs,
      source: statusResult.source,
      generatedAt: Date.now(),
    },
    source: statusResult.source,
    error: statusResult.error,
  };
}

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
      const options = {
        diagnosticsUrl: settings.diagnosticsUrl,
        controlServer: settings.controlServer,
        authToken: settings.authToken,
        networkId: settings.networkId,
        deviceName: settings.deviceName,
        tunInterface: settings.tunInterface,
        mtu: settings.mtu,
      };
      const res = await tryInvoke<string>("daemon_start_elevated", { options });
      appendLog(`daemon elevated start succeeded: ${res}`);
      return { data: { started: true, message: String(res) }, source: "live" };
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
      const res = await tryInvoke<string>("daemon_stop", {
        diagnosticsUrl: settings.diagnosticsUrl,
      });
      appendLog(`daemon stop succeeded: ${res}`);
      return { data: { stopped: true, message: String(res) }, source: "live" };
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
