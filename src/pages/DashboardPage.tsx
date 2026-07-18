import { useState } from "react";
import { useNavigate } from "react-router-dom";
import {
  Activity,
  AlertTriangle,
  FolderOpen,
  RefreshCw,
  Settings,
  ShieldCheck,
  Square,
} from "lucide-react";
import ControlAuthPanel from "../components/ControlAuthPanel";
import { StatusPill, zhLabel } from "../components/StatusPill";
import { useClientStatus } from "../hooks/useClientStatus";
import { getSettings, openLogs } from "../lib/clientApi";

type ActionTone = "info" | "error";

export default function DashboardPage() {
  const {
    daemon,
    peers,
    tunnel,
    route,
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

  const routeState = route?.entries[0]?.state ?? "unknown";
  const running = daemon.lifecycle === "running";
  const activePeers = peers.filter((peer) => peer.state === "direct" || peer.state === "relay");
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

  return (
    <div className="page-container simple-dashboard">
      <div className="page-header">
        <div>
          <h2>p2wlan</h2>
          <p className="page-subtitle">登录控制面，授权启动 TUN，建立虚拟内网。</p>
        </div>
        <div className="header-actions">
          <button className="btn btn-ghost btn-sm" onClick={refresh} disabled={refreshing || actionLoading}>
            <RefreshCw size={14} className={refreshing ? "spin" : ""} />
            <span>刷新</span>
          </button>
          {running ? (
            <button className="btn btn-danger btn-sm" onClick={stopTun} disabled={actionLoading}>
              <Square size={14} />
              <span>停止</span>
            </button>
          ) : (
            <button className="btn btn-primary btn-sm" onClick={startTun} disabled={actionLoading}>
              <ShieldCheck size={14} />
              <span>{actionLoading ? "等待系统授权..." : "授权启动 TUN"}</span>
            </button>
          )}
        </div>
      </div>

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
              <FolderOpen size={12} />
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
              请确认 macOS 密码窗口或 Windows UAC 弹窗。Windows 弹窗可能在任务栏闪烁，确认后首次启动可能需要 30 到 45 秒。
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
              <FolderOpen size={12} />
              日志
            </button>
          )}
        </div>
      )}

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

      <div className="simple-status-grid">
        <section className="panel-section">
          <div className="panel-header">
            <h3>当前状态</h3>
            <StatusPill
              label={running ? "运行中" : zhLabel(daemon.lifecycle)}
              tone={running ? "ok" : daemon.lifecycle === "error" ? "bad" : "muted"}
            />
          </div>
          <div className="panel-body flex-col gap-sm">
            <div className="status-row">
              <span className="status-label-text">控制服务器</span>
              <span className="status-value-text-mono">{daemon.controlServer}</span>
            </div>
            <div className="status-row">
              <span className="status-label-text">虚拟 IP</span>
              <span className="status-value-text-mono">{daemon.virtualIp || "未分配"}</span>
            </div>
            <div className="status-row">
              <span className="status-label-text">TUN 网卡</span>
              <span className="status-value-text-mono">{daemon.tunInterface || tunnel?.interfaceName || "未创建"} / {daemon.mtu}</span>
            </div>
            <div className="status-row">
              <span className="status-label-text">Overlay 路由</span>
              <StatusPill
                label={zhLabel(routeState)}
                tone={routeState === "installed" ? "ok" : routeState === "conflict" ? "warn" : "muted"}
              />
            </div>
            <div className="status-row">
              <span className="status-label-text">在线节点</span>
              <span className="status-value-text-mono">{activePeers.length}</span>
            </div>
          </div>
        </section>

        <section className="panel-section">
          <div className="panel-header">
            <h3>操作</h3>
          </div>
          <div className="panel-body flex-col gap-md">
            <p className="text-sm text-secondary">
              {running
                ? "TUN 已运行，可以在另一台设备登录同一控制面后测试虚拟 IP 互通。"
                : "启动时会交给系统管理员授权。macOS 可能在短时间内复用刚输入过的授权，因此重复启动不一定再次弹窗；p2wlan 不会读取或保存密码。"}
            </p>
            {running ? (
              <button className="btn btn-danger" onClick={stopTun} disabled={actionLoading}>
                <Square size={14} />
                <span>停止 TUN</span>
              </button>
            ) : (
              <button className="btn btn-primary" onClick={startTun} disabled={actionLoading}>
                <ShieldCheck size={14} />
                <span>{actionLoading ? "等待系统授权..." : "授权启动 TUN"}</span>
              </button>
            )}
            <div className="simple-action-row">
              <button className="btn btn-ghost" onClick={() => navigate("/diagnostics")}>
                <Activity size={14} />
                <span>诊断</span>
              </button>
              <button className="btn btn-ghost" onClick={() => navigate("/settings")}>
                <Settings size={14} />
                <span>设置</span>
              </button>
            </div>
          </div>
        </section>
      </div>
    </div>
  );
}
