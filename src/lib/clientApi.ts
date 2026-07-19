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
  type ClientStatusSnapshot,
  type CloseBehavior,
  type DaemonOperationStatus,
  type DaemonStatus,
  type DiagnosticCheck,
  type DiagnosticsReport,
  type DiagnosticsSnapshot,
  type DesktopStatus,
  type PeerDiagnostics,
  type PeerStatus,
  type RouteStatus,
  type TunnelStatus,
  type PermissionStatus,
  DEFAULT_SETTINGS,
  stoppedDaemonStatus,
  stoppedOperationStatus,
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

export function isTauri(): boolean {
  return typeof window !== "undefined" && "__TAURI_INTERNALS__" in window;
}

function daemonStartOptions(settings: ClientSettings) {
  return {
    diagnosticsUrl: settings.diagnosticsUrl,
    controlServer: settings.controlServer,
    authToken: settings.authToken,
    networkId: settings.networkId,
    deviceName: settings.deviceName,
    tunInterface: settings.tunInterface,
    mtu: settings.mtu,
  };
}

export async function configureDaemon(): Promise<DaemonOperationStatus | null> {
  if (!isTauri()) return null;
  const settings = getSettings();
  return tryInvoke<DaemonOperationStatus>("daemon_configure", {
    options: daemonStartOptions(settings),
  });
}

export function clearControlSession(): void {
  const settings = getSettings();
  saveSettings({ ...settings, authToken: "" });
  localStorage.removeItem("token");
  void configureDaemon();
}

async function tryInvoke<T>(command: string, args?: Record<string, unknown>): Promise<T | null> {
  if (!isTauri()) return null;
  const { invoke } = await import("@tauri-apps/api/core");
  return (await invoke<T>(command, args)) as T;
}

function normalizeCloseBehavior(settings: Partial<ClientSettings>): CloseBehavior {
  if (settings.closeBehavior === "keep-running" || settings.closeBehavior === "stop-and-quit") {
    return settings.closeBehavior;
  }
  if (settings.minimizeToTray === false) return "stop-and-quit";
  return DEFAULT_SETTINGS.closeBehavior;
}

export function getSettings(): ClientSettings {
  try {
    const raw = localStorage.getItem(SETTINGS_KEY);
    if (!raw) return { ...DEFAULT_SETTINGS };
    const parsed = JSON.parse(raw) as Partial<ClientSettings>;
    const settings = { ...DEFAULT_SETTINGS, ...parsed };
    settings.closeBehavior = normalizeCloseBehavior(parsed);
    settings.minimizeToTray = settings.closeBehavior === "keep-running";
    const legacyLocalControl =
      settings.controlServer === "http://127.0.0.1:8080" ||
      settings.controlServer === "http://localhost:8080";
    if (legacyLocalControl && !settings.authToken) {
      settings.controlServer = DEFAULT_SETTINGS.controlServer;
    }
    const isWindows = typeof navigator !== "undefined" && navigator.userAgent.toLowerCase().includes("win");
    if (isWindows && settings.tunInterface === "p2pnet0") {
      settings.tunInterface = DEFAULT_SETTINGS.tunInterface;
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
  const normalizedSettings: ClientSettings = {
    ...settings,
    closeBehavior: normalizeCloseBehavior(settings),
    minimizeToTray: normalizeCloseBehavior(settings) === "keep-running",
  };
  localStorage.setItem(SETTINGS_KEY, JSON.stringify(normalizedSettings));
  appendLog(`settings saved (control=${settings.controlServer}, mtu=${settings.mtu})`);
  return { data: normalizedSettings, source: "live" };
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

  if (isTauri()) {
    try {
      const session = await tryInvoke<AuthSession>("control_authenticate", {
        request: {
          mode,
          controlServer,
          email,
          password,
        },
      });
      if (session?.token) {
        const settings = getSettings();
        const nextSettings = {
          ...settings,
          controlServer: session.controlServer,
          authToken: session.token,
        };
        saveSettings(nextSettings);
        localStorage.setItem("token", session.token);
        appendLog(`${mode === "register" ? "registered" : "logged in"} control user (${email}) via native bridge`);
        return {
          data: session,
          source: "live",
        };
      }
    } catch (err) {
      if (err instanceof Error) {
        throw new Error(zhAuthError(err.message));
      }
      throw new Error(zhAuthError(String(err)));
    }
  }

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
  if (settings.closeBehavior !== "keep-running" && settings.closeBehavior !== "stop-and-quit") {
    errors.push("关闭窗口行为配置无效");
  }
  return errors;
}

export function appendLog(line: string): void {
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

export async function getDaemonLogTail(limit = 120): Promise<string[]> {
  if (!isTauri()) return [];
  try {
    return (await tryInvoke<string[]>("daemon_log_tail", { maxLines: limit })) ?? [];
  } catch (err) {
    appendLog(`daemon log tail unavailable: ${err}`);
    return [];
  }
}

async function fetchDiagnosticsSnapshot(url: string): Promise<DiagnosticsSnapshot | null> {
  const controller = new AbortController();
  const timer = window.setTimeout(() => controller.abort(), 3500);
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
  const directPathAvailable = snapshot.stats.direct_connections > 0;
  const isOptionalRelayIssue = (message: string) => {
    const normalized = message.toLowerCase();
    return normalized.includes("relay-inbound") || normalized.startsWith("relay ");
  };

  if (
    snapshot.health.reason &&
    !(directPathAvailable && isOptionalRelayIssue(snapshot.health.reason))
  ) {
    return snapshot.health.reason;
  }
  if (snapshot.relay_selection.last_error && !directPathAvailable) {
    return snapshot.relay_selection.last_error;
  }
  const failedTask = snapshot.health.critical_tasks.find((t) => t.error);
  if (failedTask?.error && !(directPathAvailable && failedTask.name === "relay-inbound")) {
    return `${failedTask.name}: ${failedTask.error}`;
  }
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
    diagnosticsUrl: settings.diagnosticsUrl,
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
    path === "direct"
      ? peer.direct.latency_ms
      : path === "relay"
        ? peer.relay.latency_ms
        : null;
  return {
    id: peer.node_id,
    name: peer.device_name?.trim() || peer.node_id.slice(0, 12),
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
    candidates: peer.candidates,
    directHealth: peer.direct,
    relayHealth: peer.relay,
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
  if (desktop.diagnosticsAlive) {
    daemon.lifecycle = "running";
    daemon.reachable = true;
    daemon.source = "cached";
    daemon.healthStatus = "degraded";
    daemon.healthReason =
      desktop.diagnosticsError ?? "本地健康检查可访问，完整诊断详情暂时刷新中";
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
          : "设备名称保存失败";
    appendLog(`device rename failed (${peerId}): ${message}`);
    return { data: fallback, source: "fallback", error: message };
  }
}

export async function getTunnelStatus(): Promise<ApiResult<TunnelStatus>> {
  const snapshot = await getClientStatusSnapshot();
  return { data: snapshot.tunnel, source: snapshot.source, error: snapshot.error };
}

export async function getRouteStatus(): Promise<ApiResult<RouteStatus>> {
  const snapshot = await getClientStatusSnapshot();
  return { data: snapshot.route, source: "fallback", error: snapshot.error };
}

export async function getDiagnostics(): Promise<ApiResult<DiagnosticsReport>> {
  const settings = getSettings();
  const statusResult = await getDaemonStatus();
  const status = statusResult.data;
  const snapshot =
    statusResult.source === "live"
      ? await fetchDiagnosticsSnapshot(status.diagnosticsUrl)
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
  const appLogs = getRecentLogs(300).length ? getRecentLogs(300) : logs;
  const daemonLogs = (await getDaemonLogTail(120)).map(line => `daemon-log: ${line}`);
  const combinedLogs = [...appLogs, ...daemonLogs].slice(-MAX_LOG_LINES);

  return {
    data: {
      checks,
      logs: combinedLogs,
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
