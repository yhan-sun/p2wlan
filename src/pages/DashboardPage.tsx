import { useState, useEffect } from "react";

interface DashboardData {
  onlineNodes: number;
  totalNodes: number;
  activeTunnels: number;
  directConns: number;
  relayConns: number;
  networkCIDR: string;
  virtualIP: string;
}

export default function DashboardPage() {
  const [data, setData] = useState<DashboardData>({
    onlineNodes: 0,
    totalNodes: 0,
    activeTunnels: 0,
    directConns: 0,
    relayConns: 0,
    networkCIDR: "10.20.0.0/16",
    virtualIP: "10.20.0.1",
  });

  useEffect(() => {
    // In production, fetch from Tauri backend
    // For now, show demo data
    setData({
      onlineNodes: 3,
      totalNodes: 5,
      activeTunnels: 1,
      directConns: 2,
      relayConns: 1,
      networkCIDR: "10.20.0.0/16",
      virtualIP: "10.20.0.1",
    });
  }, []);

  return (
    <div>
      <h2 style={{ marginBottom: "1.5rem" }}>Dashboard</h2>

      <div className="stats-grid">
        <div className="card stat-card">
          <div className="stat-value" style={{ color: "var(--success)" }}>{data.onlineNodes}</div>
          <div className="stat-label">Online Nodes</div>
        </div>
        <div className="card stat-card">
          <div className="stat-value">{data.totalNodes}</div>
          <div className="stat-label">Total Nodes</div>
        </div>
        <div className="card stat-card">
          <div className="stat-value" style={{ color: "var(--accent)" }}>{data.directConns}</div>
          <div className="stat-label">Direct P2P</div>
        </div>
        <div className="card stat-card">
          <div className="stat-value" style={{ color: "var(--warning)" }}>{data.relayConns}</div>
          <div className="stat-label">Via Relay</div>
        </div>
      </div>

      <div className="card" style={{ marginBottom: "1.5rem" }}>
        <div className="card-header">
          <h3 className="card-title">Network Info</h3>
        </div>
        <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: "1rem" }}>
          <div>
            <div className="form-label">Virtual IP</div>
            <div style={{ fontFamily: "monospace" }}>{data.virtualIP}</div>
          </div>
          <div>
            <div className="form-label">Network CIDR</div>
            <div style={{ fontFamily: "monospace" }}>{data.networkCIDR}</div>
          </div>
          <div>
            <div className="form-label">P2P Ratio</div>
            <div>
              {data.directConns + data.relayConns > 0
                ? Math.round(
                    (data.directConns / (data.directConns + data.relayConns)) * 100
                  )
                : 0}
              %
            </div>
          </div>
          <div>
            <div className="form-label">Active Tunnels</div>
            <div>{data.activeTunnels}</div>
          </div>
        </div>
      </div>

      <div className="card">
        <div className="card-header">
          <h3 className="card-title">Connection Status</h3>
          <span className="status-dot online" />
        </div>
        <p style={{ color: "var(--text-secondary)", fontSize: "0.875rem" }}>
          Connected to control server. All systems operational.
        </p>
      </div>
    </div>
  );
}
