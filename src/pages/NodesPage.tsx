import { useCallback, useState } from "react";
import { useClientStatus } from "../hooks/useClientStatus";
import {
  StatusPill,
  connectionTone,
  pathTone,
  formatAge,
  formatBytes,
  zhLabel,
} from "../components/StatusPill";
import {
  RefreshCw,
  Copy,
  Terminal,
  Network,
  Info,
  AlertTriangle,
  Gauge,
  Pencil,
} from "lucide-react";
import DeviceEditorDialog from "../components/DeviceEditorDialog";
import { getSettings, renamePeerDevice } from "../lib/clientApi";
import type { PeerStatus } from "../types/client";

function latencyTone(latencyMs: number | null): string {
  if (latencyMs == null) return "latency-unknown";
  if (latencyMs <= 60) return "latency-good";
  if (latencyMs <= 150) return "latency-medium";
  return "latency-high";
}

export default function NodesPage() {
  const { daemon, peers, refreshing, refresh } = useClientStatus();
  const [editingPeer, setEditingPeer] = useState<PeerStatus | null>(null);
  const [nameOverrides, setNameOverrides] = useState<Record<string, string>>({});
  const [savingName, setSavingName] = useState(false);
  const [editError, setEditError] = useState<string | null>(null);
  const [copiedId, setCopiedId] = useState<string | null>(null);
  const [copiedType, setCopiedType] = useState<"ip" | "ping" | null>(null);

  const isLoggedIn =
    getSettings().authToken.trim().length > 0 ||
    Boolean(localStorage.getItem("token")?.trim());
  const daemonRunning = daemon.lifecycle === "running" && daemon.reachable;

  const handleCopy = async (text: string, id: string, type: "ip" | "ping") => {
    try {
      if (navigator.clipboard?.writeText) {
        await navigator.clipboard.writeText(text);
      } else {
        const textarea = document.createElement("textarea");
        textarea.value = text;
        textarea.setAttribute("readonly", "true");
        textarea.style.position = "fixed";
        textarea.style.opacity = "0";
        document.body.appendChild(textarea);
        textarea.select();
        document.execCommand("copy");
        document.body.removeChild(textarea);
      }
      setCopiedId(id);
      setCopiedType(type);
      setTimeout(() => {
        setCopiedId(null);
        setCopiedType(null);
      }, 1500);
    } catch {
      setCopiedId(id);
      setCopiedType(null);
      setTimeout(() => setCopiedId(null), 1500);
    }
  };

  const closeEditor = useCallback(() => {
    if (savingName) return;
    setEditingPeer(null);
    setEditError(null);
  }, [savingName]);

  const openEditor = (peer: PeerStatus) => {
    setEditError(null);
    setEditingPeer({ ...peer, name: nameOverrides[peer.id] ?? peer.name });
  };

  const saveDeviceName = async (deviceName: string) => {
    if (!editingPeer) return;
    setSavingName(true);
    setEditError(null);
    const result = await renamePeerDevice(editingPeer.id, deviceName);
    if (result.error) {
      setEditError(result.error);
      setSavingName(false);
      return;
    }
    setNameOverrides((current) => ({ ...current, [editingPeer.id]: result.data.deviceName }));
    setSavingName(false);
    setEditingPeer(null);
    void refresh();
  };

  // Stats
  const directCount = peers.filter((p) => p.path === "direct").length;
  const relayCount = peers.filter((p) => p.path === "relay").length;
  const offlineCount = peers.filter((p) => p.path === "offline").length;

  return (
    <div className="page-container nodes-page">
      <div className="page-header">
        <div>
          <h2>设备</h2>
          <p className="page-subtitle">查看网络中的其他节点，管理 P2P 直连与中继链路状态。</p>
        </div>
        <div className="header-actions">
          <button className="btn btn-ghost btn-sm" onClick={refresh} disabled={refreshing}>
            <RefreshCw size={14} className={refreshing ? "spin" : ""} />
            <span>刷新</span>
          </button>
        </div>
      </div>

      {/* Conditionally Render Empty States */}
      {!isLoggedIn ? (
        <div className="empty-panel flex-col items-center justify-center py-xl border border-dashed rounded-lg bg-secondary">
          <Info size={32} className="text-warning mb-md" />
          <span className="empty-title font-semibold mb-xs text-lg">未登录控制面</span>
          <p className="empty-desc text-muted max-w-sm text-center text-sm mb-md">
            请先在“概览”或“设置”页面登录您的控制面账号以拉取节点配置。
          </p>
        </div>
      ) : !daemonRunning ? (
        <div className="empty-panel flex-col items-center justify-center py-xl border border-dashed rounded-lg bg-secondary">
          <AlertTriangle size={32} className="text-danger mb-md" />
          <span className="empty-title font-semibold mb-xs text-lg">守护进程未启动</span>
          <p className="empty-desc text-muted max-w-sm text-center text-sm mb-md">
            TUN 网卡尚未启动。请返回“概览”首页，点击“授权启动 TUN”。
          </p>
        </div>
      ) : peers.length === 0 ? (
        <div className="empty-panel flex-col items-center justify-center py-xl border border-dashed rounded-lg bg-secondary">
          <Network size={32} className="text-muted mb-md" />
          <span className="empty-title font-semibold mb-xs text-lg">暂无在线设备</span>
          <p className="empty-desc text-muted max-w-sm text-center text-sm">
            请在另一台设备登录相同的控制面账号，并同样启动 TUN 以便自动组网。
          </p>
        </div>
      ) : (
        <>
          {/* Summary Strip */}
          <div className="summary-strip">
            <div className="summary-item">
              <span className="summary-label">设备总数</span>
              <span className="summary-value">{peers.length}</span>
            </div>
            <div className="summary-item">
              <span className="summary-label">直连 P2P</span>
              <span className="summary-value text-success">{directCount}</span>
            </div>
            <div className="summary-item">
              <span className="summary-label">中继 Relay</span>
              <span className="summary-value text-warning">{relayCount}</span>
            </div>
            <div className="summary-item">
              <span className="summary-label">离线</span>
              <span className="summary-value text-muted">{offlineCount}</span>
            </div>
          </div>

          {/* Devices Cards List */}
          <div className="devices-list flex-col gap-sm">
            {peers.map((peer) => {
              const displayName = nameOverrides[peer.id] ?? peer.name;

              return (
                <div key={peer.id} className="device-card-row">
                  <div className="device-card-header">
                    <div className="device-info-col flex-row items-center gap-md">
                      <div className="device-main flex-col">
                        <span className="device-name font-semibold" title={peer.id}>
                          {displayName}
                        </span>
                        <span className="device-ip text-mono text-accent font-semibold">
                          {peer.virtualIp}
                        </span>
                      </div>
                      <div className="device-status-box flex-row gap-xs">
                        <StatusPill
                          label={zhLabel(peer.state)}
                          tone={connectionTone(peer.state)}
                        />
                        {peer.path !== peer.state && (
                          <StatusPill label={zhLabel(peer.path)} tone={pathTone(peer.path)} />
                        )}
                      </div>
                    </div>

                    <div className="device-meta-col flex-row items-center gap-lg">
                      <div className="device-meta-item latency-meta flex-col text-right">
                        <span className="meta-label">延迟</span>
                        <span
                          className={`meta-value latency-value ${latencyTone(peer.latencyMs)}`}
                          title={
                            peer.latencyMs == null
                              ? "尚未获得当前路径的往返延迟"
                              : `最近一次路径探测往返延迟：${peer.latencyMs} 毫秒`
                          }
                          aria-label={
                            peer.latencyMs == null
                              ? "延迟未知"
                              : `延迟 ${peer.latencyMs} 毫秒`
                          }
                        >
                          <Gauge size={13} aria-hidden="true" />
                          <span className="latency-number">
                            {peer.latencyMs != null ? Math.round(peer.latencyMs) : "--"}
                          </span>
                          {peer.latencyMs != null && <span className="latency-unit">ms</span>}
                        </span>
                      </div>
                      <div className="device-meta-item flex-col text-right hide-mobile">
                        <span className="meta-label">流量</span>
                        <span className="meta-value text-mono text-xs">
                          {formatBytes(peer.bytesReceived)} ↓ / {formatBytes(peer.bytesSent)} ↑
                        </span>
                      </div>
                      <div className="device-meta-item flex-col text-right hide-mobile">
                        <span className="meta-label">最近活跃</span>
                        <span className="meta-value">
                          {peer.lastActiveMs != null ? formatAge(peer.lastActiveMs) : "离线"}
                        </span>
                      </div>
                      <div className="device-actions-row flex-row gap-xs items-center">
                        <button
                          className={`btn btn-ghost btn-icon device-row-action ${
                            copiedId === peer.id && copiedType === "ip" ? "is-copied" : ""
                          }`}
                          onClick={() => handleCopy(peer.virtualIp, peer.id, "ip")}
                          title={
                            copiedId === peer.id && copiedType === "ip"
                              ? "已复制"
                              : "复制虚拟 IP"
                          }
                          aria-label={
                            copiedId === peer.id && copiedType === "ip"
                              ? "虚拟 IP 已复制"
                              : "复制虚拟 IP"
                          }
                        >
                          <Copy size={14} />
                        </button>
                        <button
                          className={`btn btn-ghost btn-icon device-row-action ${
                            copiedId === peer.id && copiedType === "ping" ? "is-copied" : ""
                          }`}
                          onClick={() =>
                            handleCopy(`ping ${peer.virtualIp}`, peer.id, "ping")
                          }
                          title={
                            copiedId === peer.id && copiedType === "ping"
                              ? "已复制"
                              : "复制 ping 命令"
                          }
                          aria-label={
                            copiedId === peer.id && copiedType === "ping"
                              ? "Ping 命令已复制"
                              : "复制 ping 命令"
                          }
                        >
                          <Terminal size={14} />
                        </button>
                        <button
                          className="btn btn-ghost btn-xs device-edit-button"
                          onClick={() => openEditor(peer)}
                          title="编辑设备"
                        >
                          <Pencil size={13} />
                          <span>编辑</span>
                        </button>
                      </div>
                    </div>
                  </div>
                </div>
              );
            })}
          </div>
        </>
      )}
      {editingPeer && (
        <DeviceEditorDialog
          peer={editingPeer}
          saving={savingName}
          error={editError}
          onClose={closeEditor}
          onSave={saveDeviceName}
          onCopyIp={() => handleCopy(editingPeer.virtualIp, editingPeer.id, "ip")}
        />
      )}
    </div>
  );
}
