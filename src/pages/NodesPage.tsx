import { useState, useEffect } from "react";

interface Node {
  id: string;
  deviceName: string;
  virtualIP: string;
  endpoint: string;
  natType: string;
  online: boolean;
  platform: string;
  lastSeen: number;
}

export default function NodesPage() {
  const [nodes, setNodes] = useState<Node[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    const fetchNodes = async () => {
      try {
        const token = localStorage.getItem("token");
        const res = await fetch("http://localhost:8080/api/v1/nodes", {
          headers: { Authorization: `Bearer ${token}` },
        });
        const data = await res.json();
        setNodes(data.nodes || []);
      } catch {
        // Demo data
        setNodes([
          { id: "node-abc", deviceName: "laptop-win", virtualIP: "10.20.0.2", endpoint: "203.0.113.1:5000", natType: "FullCone", online: true, platform: "windows", lastSeen: Date.now() / 1000 },
          { id: "node-def", deviceName: "server-linux", virtualIP: "10.20.0.3", endpoint: "198.51.100.2:5000", natType: "PortRestricted", online: true, platform: "linux", lastSeen: Date.now() / 1000 },
          { id: "node-ghi", deviceName: "phone-mac", virtualIP: "10.20.0.4", endpoint: "", natType: "Symmetric", online: false, platform: "macos", lastSeen: 0 },
        ]);
      } finally {
        setLoading(false);
      }
    };
    fetchNodes();
  }, []);

  if (loading) return <div>Loading...</div>;

  const onlineCount = nodes.filter((n) => n.online).length;

  return (
    <div>
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "1.5rem" }}>
        <h2>Nodes</h2>
        <span style={{ color: "var(--text-secondary)", fontSize: "0.875rem" }}>
          {onlineCount} online / {nodes.length} total
        </span>
      </div>

      <div className="card">
        <table className="table">
          <thead>
            <tr>
              <th>Status</th>
              <th>Name</th>
              <th>Virtual IP</th>
              <th>Endpoint</th>
              <th>NAT Type</th>
              <th>Platform</th>
            </tr>
          </thead>
          <tbody>
            {nodes.map((node) => (
              <tr key={node.id}>
                <td>
                  <span className={`status-dot ${node.online ? "online" : "offline"}`} />
                </td>
                <td>{node.deviceName}</td>
                <td style={{ fontFamily: "monospace" }}>{node.virtualIP}</td>
                <td style={{ fontFamily: "monospace", fontSize: "0.8rem" }}>
                  {node.endpoint || "-"}
                </td>
                <td>{node.natType || "-"}</td>
                <td>{node.platform}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}
