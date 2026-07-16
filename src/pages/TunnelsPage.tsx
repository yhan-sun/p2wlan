import { useState, useEffect } from "react";

interface Tunnel {
  id: string;
  protocol: string;
  localAddress: string;
  localPort: number;
  remotePort: number;
  publicEndpoint: string;
  active: boolean;
}

export default function TunnelsPage() {
  const [tunnels, setTunnels] = useState<Tunnel[]>([]);
  const [showCreate, setShowCreate] = useState(false);
  const [newTunnel, setNewTunnel] = useState({
    protocol: "tcp",
    localAddress: "127.0.0.1",
    localPort: 8080,
    remotePort: 30000,
  });

  useEffect(() => {
    // Demo data
    setTunnels([
      { id: "tunnel-1", protocol: "tcp", localAddress: "127.0.0.1", localPort: 8080, remotePort: 30000, publicEndpoint: "relay.p2pnet.io:30000", active: true },
    ]);
  }, []);

  const handleCreate = async (e: React.FormEvent) => {
    e.preventDefault();
    try {
      const token = localStorage.getItem("token");
      const res = await fetch("http://localhost:8080/api/v1/tunnels", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Authorization: `Bearer ${token}`,
        },
        body: JSON.stringify(newTunnel),
      });
      const data = await res.json();
      if (data.success) {
        setTunnels((prev) => [
          ...prev,
          {
            id: data.tunnel_id,
            protocol: newTunnel.protocol,
            localAddress: newTunnel.localAddress,
            localPort: newTunnel.localPort,
            remotePort: newTunnel.remotePort,
            publicEndpoint: data.public_endpoint,
            active: true,
          },
        ]);
        setShowCreate(false);
      }
    } catch {
      // Handle error
    }
  };

  const handleDelete = async (tunnelId: string) => {
    try {
      const token = localStorage.getItem("token");
      await fetch(`http://localhost:8080/api/v1/tunnels/${tunnelId}`, {
        method: "DELETE",
        headers: { Authorization: `Bearer ${token}` },
      });
      setTunnels((prev) => prev.filter((t) => t.id !== tunnelId));
    } catch {
      // Handle error
    }
  };

  return (
    <div>
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "1.5rem" }}>
        <h2>Port Mappings</h2>
        <button className="btn btn-primary" onClick={() => setShowCreate(!showCreate)}>
          + Create Tunnel
        </button>
      </div>

      {showCreate && (
        <div className="card" style={{ marginBottom: "1.5rem" }}>
          <h3 className="card-title" style={{ marginBottom: "1rem" }}>New Tunnel</h3>
          <form onSubmit={handleCreate}>
            <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: "1rem" }}>
              <div className="form-group">
                <label className="form-label">Protocol</label>
                <select
                  className="form-input"
                  value={newTunnel.protocol}
                  onChange={(e) => setNewTunnel({ ...newTunnel, protocol: e.target.value })}
                >
                  <option value="tcp">TCP</option>
                  <option value="udp">UDP</option>
                </select>
              </div>
              <div className="form-group">
                <label className="form-label">Local Address</label>
                <input
                  className="form-input"
                  value={newTunnel.localAddress}
                  onChange={(e) => setNewTunnel({ ...newTunnel, localAddress: e.target.value })}
                />
              </div>
              <div className="form-group">
                <label className="form-label">Local Port</label>
                <input
                  className="form-input"
                  type="number"
                  value={newTunnel.localPort}
                  onChange={(e) => setNewTunnel({ ...newTunnel, localPort: parseInt(e.target.value) })}
                />
              </div>
              <div className="form-group">
                <label className="form-label">Remote Port</label>
                <input
                  className="form-input"
                  type="number"
                  value={newTunnel.remotePort}
                  onChange={(e) => setNewTunnel({ ...newTunnel, remotePort: parseInt(e.target.value) })}
                />
              </div>
            </div>
            <div style={{ display: "flex", gap: "0.5rem", marginTop: "1rem" }}>
              <button className="btn btn-primary" type="submit">Create</button>
              <button className="btn btn-ghost" type="button" onClick={() => setShowCreate(false)}>Cancel</button>
            </div>
          </form>
        </div>
      )}

      <div className="card">
        <table className="table">
          <thead>
            <tr>
              <th>Protocol</th>
              <th>Local</th>
              <th>Public Endpoint</th>
              <th>Status</th>
              <th>Actions</th>
            </tr>
          </thead>
          <tbody>
            {tunnels.map((tunnel) => (
              <tr key={tunnel.id}>
                <td style={{ textTransform: "uppercase" }}>{tunnel.protocol}</td>
                <td style={{ fontFamily: "monospace" }}>
                  {tunnel.localAddress}:{tunnel.localPort}
                </td>
                <td style={{ fontFamily: "monospace" }}>{tunnel.publicEndpoint}</td>
                <td>
                  <span className={`status-dot ${tunnel.active ? "online" : "offline"}`} />
                </td>
                <td>
                  <button className="btn btn-ghost" style={{ color: "var(--danger)", fontSize: "0.75rem" }} onClick={() => handleDelete(tunnel.id)}>
                    Delete
                  </button>
                </td>
              </tr>
            ))}
            {tunnels.length === 0 && (
              <tr>
                <td colSpan={5} style={{ textAlign: "center", color: "var(--text-secondary)" }}>
                  No tunnels configured
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
}
