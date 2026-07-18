import { useState } from "react";
import { useNavigate } from "react-router-dom";
import {
  Activity,
  AlertTriangle,
  FolderOpen,
  RefreshCw,
  ShieldCheck,
  Square,
  Network,
  ArrowRight,
} from "lucide-react";
import ControlAuthPanel from "../components/ControlAuthPanel";
import { StatusPill, zhLabel, formatAge, formatBytes, pathTone } from "../components/StatusPill";
import { useClientStatus } from "../hooks/useClientStatus";
import { getSettings, openLogs } from "../lib/clientApi";

type ActionTone = "info" | "error";

export default function DashboardPage() {
  const {
    daemon,
    peers,
    lastError,
    refresh,
    connectElevated,
    disconnect,
    refreshing,
    operation,
    lastFetchedAt,
  } = useClientStatus();
  const [actionLoading, setActionLoading] = useState(false);
  const [actionMessage, setActionMessage] = useState<string | null>(null);
  const [actionTone, setActionTone] = useState<ActionTone>("info");
  const [showControlAuth, setShowControlAuth] = useState(false);
  const navigate = useNavigate();

  const startTun = async () => {
    setActionLoading(true);
    setActionMessage(null);
    if (!getSettings().authToken.trim()) {
      setShowControlAuth(true);
      setActionTone("error");
      setActionMessage("请先登录或注册控制面账号，再启动 TUN。");
      setActionLoading(false);
      return;
    }
    try {
      await connectElevated();
      setActionTone("info");
      setActionMessage(null);
      setShowControlAuth(false);
    } catch (err) {
      setActionTone("error");
      setActionMessage(err instanceof Error ? err.message : "启动失败");
    } finally {
      setActionLoading(false);
    }
  };

  const stopTun = async () => {
    setActionLoading(true);
    setActionMessage(null);
    try {
      await disconnect();
      setActionTone("info");
      setActionMessage(null);
    } catch (err) {
      setActionTone("error");
      setActionMessage(err instanceof Error ? err.message : "停止失败");
    } finally {
      setActionLoading(false);
    }
  };

  const handleOpenLogs = async () => {
    setActionTone("info");
    try {
      const res = await openLogs();
      setActionMessage(res.data.message);
    } catch (err) {
      setActionTone("error");
      setActionMessage(err instanceof Error ? err.message : "无法打开日志目录");
    }
  };

  const operationBusy =
    operation.phase === "authorizing" ||
    operation.phase === "launching" ||
    operation.phase === "waiting_for_daemon" ||
    operation.phase === "stopping";
  const running = daemon.lifecycle === "running" && daemon.reachable;
  const onlineCount = daemon.peerStats.direct_connections + daemon.peerStats.relay_connections;
  const hasLiveMetrics = running;

  // Determine top status values
  const tunStatusText = operationBusy
    ? operation.message
    : running
      ? "运行中"
      : operation.phase === "error" || daemon.lifecycle === "error"
        ? "异常"
        : "未启动";
  const tunStatusTone = operationBusy
    ? "warn"
    : running
      ? "ok"
      : operation.phase === "error" || daemon.lifecycle === "error"
        ? "bad"
        : "muted";

  const controlStatusText = daemon.reauthRequired
    ? "需要重新登录"
    : daemon.controlConnected
    ? "已连接"
    : "断开";
  const controlStatusTone = daemon.reauthRequired
    ? "bad"
    : daemon.controlConnected
    ? "ok"
    : "warn";

  const getPathStatus = () => {
    if (!running) return "未启动";
    const { total_peers, direct_connections, relay_connections } = daemon.peerStats;
    if (total_peers === 0) return "无设备";
    if (direct_connections > 0 && relay_connections === 0) return "直连";
    if (relay_connections > 0 && direct_connections === 0) return "中继";
    if (direct_connections > 0 && relay_connections > 0) return "混合";
    return "未知";
  };
  const pathStatusText = getPathStatus();
  const pathStatusTone =
    pathStatusText === "直连" || pathStatusText === "混合"
      ? "ok"
      : pathStatusText === "中继"
      ? "warn"
      : "muted";

  const virtualIpText = daemon.virtualIp || "未分配";

  // Banner status message
  const statusBanner = (() => {
    if (operationBusy) return null;
    if (!daemon.reachable && lastError) {
      return { title: "守护进程未连接", detail: lastError };
    }
    if (daemon.reauthRequired) {
      return { title: "需要重新登录", detail: "控制面 token 已失效，请重新登录后再启动或刷新 TUN。" };
    }
    if (daemon.reachable && !daemon.controlConnected) {
      return { title: "控制面连接异常", detail: lastError ?? "守护进程仍在运行，但暂时没有连上控制服务器。" };
    }
    if (lastError) {
      return { title: "网络路径异常", detail: lastError };
    }
    return null;
  })();

  const operationElapsed = Math.max(0, Math.floor((Date.now() - operation.startedAtMs) / 1000));
  const controlHeartbeat = !hasLiveMetrics
    ? "—"
    : daemon.lastControlSuccessSecsAgo == null
      ? daemon.controlConnected
        ? "刚刚"
        : "未知"
      : formatAge(daemon.lastControlSuccessSecsAgo * 1000);
  const localUpdated = lastFetchedAt == null ? "—" : formatAge(Date.now() - lastFetchedAt);

  const previewPeers = peers.slice(0, 3);

  return (
    <div className="page-container dashboard-page">
      <div className="page-header">
        <div>
          <h2>概览</h2>
          <p className="page-subtitle">查看虚拟网卡连接路径与当前在线设备。</p>
        </div>
        <div className="header-actions">
          <button
            className="btn btn-ghost btn-sm"
            onClick={refresh}
            disabled={refreshing || actionLoading}
          >
            <RefreshCw size={14} className={refreshing ? "spin" : ""} />
            <span>刷新</span>
          </button>
        </div>
      </div>

      {/* Top Status Bar Grid */}
      <div className="status-bar-grid">
        <div className="status-bar-card">
          <div className="card-label">TUN 状态</div>
          <div className="card-value">
            <StatusPill label={tunStatusText} tone={tunStatusTone} />
          </div>
        </div>
        <div className="status-bar-card">
          <div className="card-label">控制面</div>
          <div className="card-value">
            <StatusPill label={controlStatusText} tone={controlStatusTone} />
          </div>
        </div>
        <div className="status-bar-card">
          <div className="card-label">当前路径</div>
          <div className="card-value">
            <StatusPill label={pathStatusText} tone={pathStatusTone} />
          </div>
        </div>
        <div className="status-bar-card">
          <div className="card-label">虚拟 IP</div>
          <div className="card-value text-mono text-accent font-semibold">
            {virtualIpText}
          </div>
        </div>
      </div>

      {/* Banner / Alerts */}
      {statusBanner && (
        <div className="banner banner-error">
          <AlertTriangle size={16} />
          <div className="banner-content">
            <span className="banner-title">{statusBanner.title}</span>
            <span className="banner-desc">{statusBanner.detail}</span>
          </div>
          <div className="banner-actions">
            <button className="btn btn-ghost btn-xs text-danger" onClick={() => navigate("/diagnostics")}>
              诊断
            </button>
            <button className="btn btn-ghost btn-xs text-danger" onClick={handleOpenLogs}>
              日志
            </button>
          </div>
        </div>
      )}

      {operationBusy && (
        <div className="banner banner-info" role="status" aria-live="polite">
          <ShieldCheck size={16} />
          <div className="banner-content">
            <span className="banner-title">{operation.message}</span>
            <span className="banner-desc">
              {operation.phase === "authorizing"
                ? "请在系统窗口确认管理员授权。p2wlan 不会读取或保存密码。"
                : operation.phase === "stopping"
                  ? "正在注销虚拟网卡并清理 Overlay 路由。"
                  : "守护进程正在连接控制面并初始化虚拟网卡，可继续使用其他页面。"}
              {operationElapsed > 4 ? ` 已等待 ${operationElapsed} 秒。` : ""}
            </span>
          </div>
          {operationElapsed > 4 && (
            <button className="btn btn-ghost btn-xs" onClick={handleOpenLogs}>
              查看日志
            </button>
          )}
        </div>
      )}

      {actionMessage && (
        <div className={`banner banner-${actionTone === "error" ? "error" : "info"}`}>
          {actionTone === "error" ? <AlertTriangle size={16} /> : <Activity size={16} />}
          <div className="banner-content">
            <span className="banner-desc">{actionMessage}</span>
          </div>
          {actionTone === "error" && (
            <button className="btn btn-ghost btn-xs text-danger" onClick={handleOpenLogs}>
              日志
            </button>
          )}
        </div>
      )}

      {/* Control Authentication Card */}
      {showControlAuth && (
        <div className="panel-section">
          <div className="panel-header">
            <h3>控制面账号</h3>
          </div>
          <div className="panel-body flex-col gap-md">
            <p className="text-sm text-secondary">
              TUN 启动前需要控制面 token，用于注册设备和分配虚拟 IP。
            </p>
            <ControlAuthPanel onAuthenticated={startTun} />
          </div>
        </div>
      )}

      <div className="dashboard-main-grid">
        {/* Left Area: Control Area & Connect summary */}
        <div className="flex-col gap-md">
          {/* Main Action Control */}
          <section className="panel-section">
            <div className="panel-header">
              <h3>网卡控制</h3>
            </div>
            <div className="panel-body flex-col gap-md">
              <p className="text-sm text-secondary">
                {running
                  ? "虚拟网络已建立。此设备可在虚拟内网 10.20.0.0/16 范围内与其他在线设备通信。"
                  : "启动虚拟网卡需要系统管理员权限，以配置虚拟网口和系统路由表。"}
              </p>
              <div className="flex-row gap-md items-center">
                {running || operation.phase === "stopping" ? (
                  <button className="btn btn-danger flex-1" onClick={stopTun} disabled={actionLoading || operationBusy}>
                    <Square size={14} />
                    <span>{operation.phase === "stopping" ? "正在停止..." : "停止 TUN"}</span>
                  </button>
                ) : (
                  <button className="btn btn-primary flex-1" onClick={startTun} disabled={actionLoading || operationBusy}>
                    <ShieldCheck size={14} />
                    <span>{operationBusy ? operation.message : "授权启动 TUN"}</span>
                  </button>
                )}
              </div>
              <div className="flex-row gap-sm justify-between border-t border-light pt-sm mt-xs">
                <button className="btn btn-ghost btn-xs text-secondary" onClick={handleOpenLogs}>
                  <FolderOpen size={12} />
                  <span>打开日志</span>
                </button>
                <button
                  className="btn btn-ghost btn-xs text-secondary"
                  onClick={() => setShowControlAuth(!showControlAuth)}
                >
                  <span>重新登录控制面</span>
                </button>
              </div>
            </div>
          </section>

          {/* Connection Summary */}
          <section className="panel-section">
            <div className="panel-header">
              <h3>连接摘要</h3>
            </div>
            <div className="panel-body flex-col gap-sm">
              <div className="status-row">
                <span className="status-label-text">已发现设备</span>
                <span className="status-value-text-mono font-semibold">
                  {hasLiveMetrics ? `${daemon.peerStats.total_peers} 台` : "—"}
                </span>
              </div>
              <div className="status-row">
                <span className="status-label-text">当前在线</span>
                <span className="status-value-text-mono font-semibold">
                  {hasLiveMetrics ? `${onlineCount} 台` : "—"}
                </span>
              </div>
              <div className="status-row">
                <span className="status-label-text">连接路径</span>
                <span className="status-value-text-mono">
                  {hasLiveMetrics
                    ? `直连 ${daemon.peerStats.direct_connections} · 中继 ${daemon.peerStats.relay_connections}`
                    : "—"}
                </span>
              </div>
              <div className="status-row">
                <span className="status-label-text">总流量</span>
                <span className="status-value-text-mono">
                  {hasLiveMetrics
                    ? `↓ ${formatBytes(daemon.peerStats.total_bytes_received)} · ↑ ${formatBytes(daemon.peerStats.total_bytes_sent)}`
                    : "—"}
                </span>
              </div>
              <div className="status-row">
                <span className="status-label-text">控制面心跳</span>
                <span className="status-value-text-mono text-secondary text-sm">
                  {controlHeartbeat}
                </span>
              </div>
              <div className="status-row">
                <span className="status-label-text">状态更新</span>
                <span className="status-value-text-mono text-secondary text-sm">
                  {localUpdated}
                </span>
              </div>
            </div>
          </section>
        </div>

        {/* Right Area: Devices Preview */}
        <section className="panel-section flex-col">
          <div className="panel-header justify-between items-center">
            <h3>设备预览</h3>
            {peers.length > 3 && (
              <button
                className="btn btn-ghost btn-xs text-accent flex-row items-center gap-xs"
                onClick={() => navigate("/nodes")}
              >
                <span>查看全部 ({peers.length})</span>
                <ArrowRight size={12} />
              </button>
            )}
          </div>
          <div className="panel-body flex-col flex-1 gap-sm">
            {previewPeers.length === 0 ? (
              <div className="flex-col items-center justify-center flex-1 py-md text-center">
                <Network size={28} className="text-muted mb-xs" />
                <span className="text-sm font-semibold text-secondary">暂无节点设备</span>
                <p className="text-xs text-muted max-w-xs mt-xs">
                  在另一台设备上安装并运行相同的控制面账号以建立连接。
                </p>
              </div>
            ) : (
              <div className="flex-col gap-sm">
                {previewPeers.map((peer) => (
                  <div
                    key={peer.id}
                    className="device-preview-row flex-row justify-between items-center py-sm px-md border-b border-light"
                    onClick={() => navigate("/nodes")}
                    style={{ cursor: "pointer" }}
                  >
                    <div className="flex-col">
                      <span className="font-semibold text-sm">{peer.name}</span>
                      <span className="text-xs text-mono text-accent mt-xs">{peer.virtualIp}</span>
                    </div>
                    <div className="flex-row items-center gap-sm">
                      <StatusPill label={zhLabel(peer.path)} tone={pathTone(peer.path)} />
                      {peer.lastActiveMs != null && (
                        <span className="text-xs text-secondary">{formatAge(peer.lastActiveMs)}</span>
                      )}
                    </div>
                  </div>
                ))}
                {peers.length <= 3 && (
                  <button
                    className="btn btn-ghost btn-xs text-accent full-width mt-xs"
                    onClick={() => navigate("/nodes")}
                  >
                    <span>跳转至设备列表</span>
                  </button>
                )}
              </div>
            )}
          </div>
        </section>
      </div>
    </div>
  );
}
