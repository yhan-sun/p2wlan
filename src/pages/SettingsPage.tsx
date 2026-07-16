import { useState } from "react";

export default function SettingsPage() {
  const [settings, setSettings] = useState({
    controlServer: "https://control.p2pnet.io",
    networkID: "default",
    mtu: 1420,
    dnsEnabled: true,
    dnsSuffix: "p2pnet.local",
    aclEnabled: false,
    preferDirect: true,
    relayFallback: true,
  });

  const [saved, setSaved] = useState(false);

  const handleSave = () => {
    // In production, save via Tauri backend
    setSaved(true);
    setTimeout(() => setSaved(false), 2000);
  };

  return (
    <div>
      <h2 style={{ marginBottom: "1.5rem" }}>Settings</h2>

      <div className="card" style={{ marginBottom: "1.5rem" }}>
        <div className="card-header">
          <h3 className="card-title">Network</h3>
        </div>
        <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: "1rem" }}>
          <div className="form-group">
            <label className="form-label">Control Server</label>
            <input
              className="form-input"
              value={settings.controlServer}
              onChange={(e) => setSettings({ ...settings, controlServer: e.target.value })}
            />
          </div>
          <div className="form-group">
            <label className="form-label">Network ID</label>
            <input
              className="form-input"
              value={settings.networkID}
              onChange={(e) => setSettings({ ...settings, networkID: e.target.value })}
            />
          </div>
          <div className="form-group">
            <label className="form-label">MTU</label>
            <input
              className="form-input"
              type="number"
              value={settings.mtu}
              onChange={(e) => setSettings({ ...settings, mtu: parseInt(e.target.value) })}
            />
          </div>
        </div>
      </div>

      <div className="card" style={{ marginBottom: "1.5rem" }}>
        <div className="card-header">
          <h3 className="card-title">DNS</h3>
        </div>
        <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: "1rem" }}>
          <div className="form-group">
            <label className="form-label">DNS Enabled</label>
            <select
              className="form-input"
              value={settings.dnsEnabled ? "yes" : "no"}
              onChange={(e) => setSettings({ ...settings, dnsEnabled: e.target.value === "yes" })}
            >
              <option value="yes">Yes</option>
              <option value="no">No</option>
            </select>
          </div>
          <div className="form-group">
            <label className="form-label">DNS Suffix</label>
            <input
              className="form-input"
              value={settings.dnsSuffix}
              onChange={(e) => setSettings({ ...settings, dnsSuffix: e.target.value })}
            />
          </div>
        </div>
      </div>

      <div className="card" style={{ marginBottom: "1.5rem" }}>
        <div className="card-header">
          <h3 className="card-title">Connection</h3>
        </div>
        <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: "1rem" }}>
          <div className="form-group">
            <label className="form-label">Prefer Direct P2P</label>
            <select
              className="form-input"
              value={settings.preferDirect ? "yes" : "no"}
              onChange={(e) => setSettings({ ...settings, preferDirect: e.target.value === "yes" })}
            >
              <option value="yes">Yes</option>
              <option value="no">No</option>
            </select>
          </div>
          <div className="form-group">
            <label className="form-label">Relay Fallback</label>
            <select
              className="form-input"
              value={settings.relayFallback ? "yes" : "no"}
              onChange={(e) => setSettings({ ...settings, relayFallback: e.target.value === "yes" })}
            >
              <option value="yes">Yes</option>
              <option value="no">No</option>
            </select>
          </div>
          <div className="form-group">
            <label className="form-label">ACL Enabled</label>
            <select
              className="form-input"
              value={settings.aclEnabled ? "yes" : "no"}
              onChange={(e) => setSettings({ ...settings, aclEnabled: e.target.value === "yes" })}
            >
              <option value="yes">Yes</option>
              <option value="no">No</option>
            </select>
          </div>
        </div>
      </div>

      <button className="btn btn-primary" onClick={handleSave}>
        {saved ? "Saved!" : "Save Settings"}
      </button>
    </div>
  );
}
