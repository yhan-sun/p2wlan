import { useState } from "react";
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
  ChevronDown,
  ChevronUp,
  Terminal,
  Network,
  Info,
  CheckCircle,
  XCircle,
  AlertTriangle,
} from "lucide-react";
import { getSettings } from "../lib/clientApi";

export default function NodesPage() {
  const { daemon, peers, refreshing, refresh } = useClientStatus();
  const [expandedId, setExpandedId] = useState<string | null>(null);
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

  const toggleExpand = (id: string) => {
    setExpandedId(expandedId === id ? null : id);
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
              const isExpanded = expandedId === peer.id;
              const directOk = peer.directHealth && peer.directHealth.consecutive_failures === 0;

              return (
                <div key={peer.id} className="device-card-row">
                  {/* Card Header Summary */}
                  <div className="device-card-header flex-row items-center justify-between">
                    <div className="device-info-col flex-row items-center gap-md">
                      <div className="device-main flex-col">
                        <span className="device-name font-semibold" title={peer.id}>
                          {peer.name}
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
                        <StatusPill label={zhLabel(peer.path)} tone={pathTone(peer.path)} />
                      </div>
                    </div>

                    <div className="device-meta-col flex-row items-center gap-lg">
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
                          className="btn btn-ghost btn-xs"
                          onClick={() => handleCopy(peer.virtualIp, peer.id, "ip")}
                          title="复制虚拟 IP"
                        >
                          <Copy size={12} />
                          <span>
                            {copiedId === peer.id && copiedType === "ip"
                              ? "已复制"
                              : copiedId === peer.id && copiedType === null
                              ? "复制失败"
                              : "复制 IP"}
                          </span>
                        </button>
                        <button
                          className="btn btn-ghost btn-xs"
                          onClick={() =>
                            handleCopy(`ping ${peer.virtualIp}`, peer.id, "ping")
                          }
                          title="复制 ping 命令"
                        >
                          <Terminal size={12} />
                          <span>
                            {copiedId === peer.id && copiedType === "ping"
                              ? "已复制"
                              : copiedId === peer.id && copiedType === null
                              ? "复制失败"
                              : "Ping"}
                          </span>
                        </button>
                        <button
                          className="btn btn-ghost btn-xs btn-icon"
                          onClick={() => toggleExpand(peer.id)}
                          title="展开诊断详情"
                        >
                          {isExpanded ? <ChevronUp size={14} /> : <ChevronDown size={14} />}
                        </button>
                      </div>
                    </div>
                  </div>

                  {/* Expanded Diagnostics Details */}
                  {isExpanded && (
                    <div className="device-card-details border-t border-light mt-sm pt-sm flex-col gap-sm">
                      <div className="details-grid">
                        <div className="details-item">
                          <span className="details-label">完整节点 ID:</span>
                          <span className="details-value text-mono text-secondary">{peer.id}</span>
                        </div>
                        <div className="details-item">
                          <span className="details-label">物理端点:</span>
                          <span className="details-value text-mono text-secondary">
                            {peer.endpoint || "—"}
                          </span>
                        </div>
                        <div className="details-item">
                          <span className="details-label">NAT 类型:</span>
                          <span className="details-value text-secondary">{peer.natType}</span>
                        </div>
                        <div className="details-item">
                          <span className="details-label">中继服务器:</span>
                          <span className="details-value text-mono text-secondary">
                            {peer.relayServer || "—"}
                          </span>
                        </div>
                        <div className="details-item">
                          <span className="details-label">直连打洞:</span>
                          <span className="details-value flex-row items-center gap-xs">
                            {directOk ? (
                              <>
                                <CheckCircle size={12} className="text-success" />
                                <span className="text-success text-sm">成功</span>
                              </>
                            ) : (
                              <>
                                <XCircle size={12} className="text-danger" />
                                <span className="text-danger text-sm">
                                  {peer.directHealth?.last_error || "未连接"}
                                </span>
                              </>
                            )}
                          </span>
                        </div>
                      </div>

                      {peer.candidates && peer.candidates.length > 0 && (
                        <div className="candidates-section mt-xs">
                          <span className="details-label mb-xs block">候选物理端点:</span>
                          <div className="candidates-list flex-row flex-wrap gap-xs">
                            {peer.candidates.map((cand, idx) => (
                              <span key={idx} className="candidate-badge text-mono text-xs">
                                {cand}
                              </span>
                            ))}
                          </div>
                        </div>
                      )}

                      <div className="raw-json-diagnostics border-t border-light pt-sm mt-xs">
                        <span className="details-label mb-xs block">诊断 JSON 摘要:</span>
                        <pre className="json-pre">
                          {JSON.stringify(
                            {
                              direct: peer.directHealth,
                              relay: peer.relayHealth,
                              bytes: { sent: peer.bytesSent, received: peer.bytesReceived },
                            },
                            null,
                            2
                          )}
                        </pre>
                      </div>
                    </div>
                  )}
                </div>
              );
            })}
          </div>
        </>
      )}
    </div>
  );
}
