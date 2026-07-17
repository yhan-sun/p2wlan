import { useClientStatus } from "../hooks/useClientStatus";
import { StatusPill, connectionTone, pathTone, formatAge, formatBytes, zhLabel } from "../components/StatusPill";
import { RefreshCw, Users } from "lucide-react";

export default function NodesPage() {
  const { peers, refreshing, refresh } = useClientStatus();
  const directCount = peers.filter((peer) => peer.path === "direct").length;
  const relayCount = peers.filter((peer) => peer.path === "relay").length;
  const offlineCount = peers.filter((peer) => peer.path === "offline").length;

  return (
    <div className="page-container">
      <div className="page-header">
        <div>
          <h2>节点</h2>
          <p className="page-subtitle">查看节点身份、连接路径和流量计数。</p>
        </div>
        <div className="header-actions">
          <button className="btn btn-ghost btn-sm" onClick={refresh} disabled={refreshing}>
            <RefreshCw size={14} className={refreshing ? "spin" : ""} />
            <span>刷新</span>
          </button>
        </div>
      </div>

      <div className="summary-strip">
        <div className="summary-item">
          <span className="summary-label">总数</span>
          <span className="summary-value">{peers.length}</span>
        </div>
        <div className="summary-item">
          <span className="summary-label">直连</span>
          <span className="summary-value text-success">{directCount}</span>
        </div>
        <div className="summary-item">
          <span className="summary-label">中继</span>
          <span className="summary-value text-warning">{relayCount}</span>
        </div>
        <div className="summary-item">
          <span className="summary-label">离线</span>
          <span className="summary-value text-muted">{offlineCount}</span>
        </div>
      </div>

      <div className="panel-section">
        {peers.length === 0 ? (
          <div className="empty-panel flex-col items-center justify-center py-xl">
            <Users size={32} className="text-muted mb-md" />
            <span className="empty-title font-semibold mb-xs">还没有发现节点</span>
            <p className="empty-desc text-muted max-w-sm text-center">
              在同一网络启动另一台客户端，或检查控制面注册状态。
            </p>
          </div>
        ) : (
          <div className="table-wrapper">
            <table className="table">
              <thead>
                <tr>
                  <th>节点 ID</th>
                  <th>虚拟 IP</th>
                  <th>状态</th>
                  <th>路径</th>
                  <th>延迟</th>
                  <th>物理端点</th>
                  <th>NAT 类型</th>
                  <th>接收/发送</th>
                  <th>最近活跃</th>
                </tr>
              </thead>
              <tbody>
                {peers.map((peer) => (
                  <tr key={peer.id}>
                    <td>
                      <span className="mono-label font-bold" title={peer.id}>{peer.name}</span>
                    </td>
                    <td className="text-mono font-semibold text-accent">{peer.virtualIp}</td>
                    <td>
                      <StatusPill label={zhLabel(peer.state)} tone={connectionTone(peer.state)} />
                    </td>
                    <td>
                      <StatusPill label={zhLabel(peer.path)} tone={pathTone(peer.path)} />
                    </td>
                    <td className="text-mono">
                      {peer.latencyMs != null ? `${peer.latencyMs} ms` : "—"}
                    </td>
                    <td className="text-mono text-sm text-secondary">
                      {peer.endpoint || "—"}
                    </td>
                    <td className="text-sm">{peer.natType}</td>
                    <td className="text-mono text-xs text-secondary">
                      {formatBytes(peer.bytesReceived)} / {formatBytes(peer.bytesSent)}
                    </td>
                    <td className="text-sm text-secondary">
                      {peer.lastActiveMs != null ? formatAge(peer.lastActiveMs) : "离线"}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  );
}
