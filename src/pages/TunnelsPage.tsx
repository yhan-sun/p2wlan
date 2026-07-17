import { useClientStatus } from "../hooks/useClientStatus";
import { StatusPill, zhLabel } from "../components/StatusPill";
import { RefreshCw, Wrench, AlertCircle } from "lucide-react";
import { rebuildRoutes } from "../lib/clientApi";
import { useState } from "react";

export default function TunnelsPage() {
  const { tunnel, route, refreshing, refresh } = useClientStatus();
  const [rebuildResult, setRebuildResult] = useState<string | null>(null);
  const [rebuilding, setRebuilding] = useState(false);
  const primaryRoute = route?.entries[0];

  const handleRebuildRoutes = async () => {
    setRebuilding(true);
    setRebuildResult(null);
    try {
      const res = await rebuildRoutes();
      setRebuildResult(res.data.message);
    } catch (e) {
      setRebuildResult(e instanceof Error ? e.message : "路由重建执行失败");
    } finally {
      setRebuilding(false);
    }
  };

  return (
    <div className="page-container">
      <div className="page-header">
        <div>
          <h2>隧道</h2>
          <p className="page-subtitle">查看虚拟网卡、UDP 绑定和 Overlay 路由生命周期。</p>
        </div>
        <div className="header-actions">
          <button className="btn btn-ghost btn-sm" onClick={refresh} disabled={refreshing}>
            <RefreshCw size={14} className={refreshing ? "spin" : ""} />
            <span>刷新</span>
          </button>
          <button className="btn btn-primary btn-sm" onClick={handleRebuildRoutes} disabled={rebuilding}>
            <Wrench size={14} />
            <span>重装路由</span>
          </button>
        </div>
      </div>

      {rebuildResult && (
        <div className="banner banner-info">
          <AlertCircle size={16} />
          <div className="banner-content">
            <span className="banner-desc">{rebuildResult}</span>
          </div>
        </div>
      )}

      <div className="summary-strip">
        <div className="summary-item">
          <span className="summary-label">网卡</span>
          <span className="summary-value text-mono">{tunnel?.interfaceName || "—"}</span>
        </div>
        <div className="summary-item">
          <span className="summary-label">状态</span>
          <StatusPill label={tunnel?.up ? "启用 (UP)" : "关闭 (DOWN)"} tone={tunnel?.up ? "ok" : "bad"} />
        </div>
        <div className="summary-item">
          <span className="summary-label">路由</span>
          <StatusPill
            label={zhLabel(primaryRoute?.state || "unknown")}
            tone={primaryRoute?.state === "installed" ? "ok" : primaryRoute?.state === "conflict" ? "warn" : "muted"}
          />
        </div>
        <div className="summary-item">
          <span className="summary-label">UDP</span>
          <span className="summary-value text-mono">{tunnel?.udpBind || "—"}</span>
        </div>
      </div>

      <div className="split-layout">
        <div className="column flex-col gap-md">
          <div className="panel-section">
            <div className="panel-header">
              <h3>虚拟网卡</h3>
            </div>
            <div className="panel-body flex-col gap-sm">
              <div className="status-row">
                <span className="status-label-text">网卡名称</span>
                <span className="status-value-text-mono font-bold">{tunnel?.interfaceName || "—"}</span>
              </div>
              <div className="status-row">
                <span className="status-label-text">IP 分配 (CIDR)</span>
                <span className="status-value-text-mono">{tunnel?.cidr || "—"}</span>
              </div>
              <div className="status-row">
                <span className="status-label-text">虚拟 IP</span>
                <span className="status-value-text-mono text-accent font-bold">{tunnel?.virtualIp || "—"}</span>
              </div>
              <div className="status-row">
                <span className="status-label-text">MTU</span>
                <span className="status-value-text">{tunnel?.mtu || "—"} 字节</span>
              </div>
              <div className="status-row">
                <span className="status-label-text">UDP 监听</span>
                <span className="status-value-text-mono">{tunnel?.udpBind || "—"}</span>
              </div>
              <div className="status-row">
                <span className="status-label-text">链路状态</span>
                <StatusPill
                  label={tunnel?.up ? "已启用 (UP)" : "未启用 (DOWN)"}
                  tone={tunnel?.up ? "ok" : "bad"}
                />
              </div>
            </div>
          </div>
        </div>

        <div className="column flex-col gap-md">
          <div className="panel-section">
            <div className="panel-header">
              <h3>路由</h3>
            </div>
            <div className="panel-body flex-col gap-md">
              {route?.entries && route.entries.length > 0 ? (
                <div className="route-entries-list flex-col gap-sm">
                  {route.entries.map((entry, index) => (
                    <div key={index} className="route-entry-card">
                      <div className="route-entry-header">
                        <span className="route-dest">{entry.destination}</span>
                        <StatusPill
                          label={zhLabel(entry.state)}
                          tone={entry.state === "installed" ? "ok" : entry.state === "missing" ? "bad" : "warn"}
                        />
                      </div>
                      <div className="route-entry-body">
                        <div className="route-detail-row">
                          <span className="lbl">目标网卡</span>
                          <span className="val-mono">{entry.interfaceName}</span>
                        </div>
                        <p className="route-desc-text">{entry.detail}</p>
                      </div>
                    </div>
                  ))}
                </div>
              ) : (
                <div className="empty-state-text">暂无路由状态。</div>
              )}
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
