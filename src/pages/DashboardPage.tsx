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
import { StatusPill, zhLabel, formatAge, pathTone } from "../components/StatusPill";
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
      const msg = await connectElevated();
      setActionTone("info");
      setActionMessage(msg);
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
      const msg = await disconnect();
      setActionTone("info");
      setActionMessage(msg);
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

  const running = daemon.lifecycle === "running";
  const activePeers = peers.filter((peer) => peer.path === "direct" || peer.path === "relay");

  // Determine top status values
  const tunStatusText = running ? "运行中" : daemon.lifecycle === "error" ? "异常" : "未启动";
  const tunStatusTone = running ? "ok" : daemon.lifecycle === "error" ? "bad" : "muted";

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

      {actionLoading && (
        <div className="banner banner-info">
          <ShieldCheck size={16} />
          <div className="banner-content">
            <span className="banner-title">等待系统授权</span>
            <span className="banner-desc">
              请确认密码窗口。Windows 首次启动可能需要 30 到 45 秒。
            </span>
          </div>
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
                  : "启动虚拟网卡需要超级管理员特权 (sudo)，以配置虚拟网口和系统路由表。"}
              </p>
              <div className="flex-row gap-md items-center">
                {running ? (
                  <button className="btn btn-danger flex-1" onClick={stopTun} disabled={actionLoading}>
                    <Square size={14} />
                    <span>停止 TUN</span>
                  </button>
                ) : (
                  <button className="btn btn-primary flex-1" onClick={startTun} disabled={actionLoading}>
                    <ShieldCheck size={14} />
                    <span>{actionLoading ? "等待授权..." : "授权启动 TUN"}</span>
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
                <span className="status-label-text">在线设备</span>
                <span className="status-value-text-mono font-semibold">{activePeers.length} 台</span>
              </div>
              <div className="status-row">
                <span className="status-label-text">直连数量 (P2P)</span>
                <span className="status-value-text-mono text-success font-semibold">
                  {daemon.peerStats.direct_connections}
                </span>
              </div>
              <div className="status-row">
                <span className="status-label-text">中继数量 (Relay)</span>
                <span className="status-value-text-mono text-warning font-semibold">
                  {daemon.peerStats.relay_connections}
                </span>
              </div>
              <div className="status-row">
                <span className="status-label-text">同步时间</span>
                <span className="status-value-text-mono text-secondary text-sm">
                  {daemon.updatedAt ? new Date(daemon.updatedAt).toLocaleTimeString() : "—"}
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
