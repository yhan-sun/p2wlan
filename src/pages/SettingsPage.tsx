import { useState } from "react";
import { getSettings, saveSettings, validateSettings } from "../lib/clientApi";
import type { ClientSettings, CloseBehavior, RelayPolicy } from "../types/client";
import { Save, AlertTriangle, ShieldCheck } from "lucide-react";

export default function SettingsPage() {
  const [settings, setSettings] = useState<ClientSettings>(() => getSettings());
  const [errors, setErrors] = useState<string[]>([]);
  const [saveStatus, setSaveStatus] = useState<{ type: "success" | "error"; message: string } | null>(null);

  const handleFieldChange = <K extends keyof ClientSettings>(key: K, value: ClientSettings[K]) => {
    setSettings(prev => ({
      ...prev,
      [key]: value
    }));
  };

  const handleCloseBehaviorChange = (closeBehavior: CloseBehavior) => {
    setSettings(prev => ({
      ...prev,
      closeBehavior,
      minimizeToTray: closeBehavior === "keep-running",
    }));
  };

  const handleSave = (e: React.FormEvent) => {
    e.preventDefault();
    setErrors([]);
    setSaveStatus(null);

    const validationErrors = validateSettings(settings);
    if (validationErrors.length > 0) {
      setErrors(validationErrors);
      setSaveStatus({ type: "error", message: "配置校验失败，请检查输入。" });
      return;
    }

    const res = saveSettings(settings);
    if (res.error) {
      setSaveStatus({ type: "error", message: res.error });
    } else {
      setSaveStatus({ type: "success", message: "设置已保存。" });
      // Notify parent/hook of potential update changes if needed
      window.dispatchEvent(new Event("storage"));
    }
  };

  return (
    <div className="page-container">
      <div className="page-header">
        <div>
          <h2>设置</h2>
          <p className="page-subtitle">配置控制面、虚拟网卡、中继策略和桌面行为。</p>
        </div>
      </div>

      {saveStatus && (
        <div className={`banner banner-${saveStatus.type === "success" ? "info" : "error"}`}>
          {saveStatus.type === "error" ? <AlertTriangle size={16} /> : <ShieldCheck size={16} />}
          <div className="banner-content">
            <span className="banner-desc">{saveStatus.message}</span>
          </div>
        </div>
      )}

      {errors.length > 0 && (
        <div className="banner banner-error flex-col items-start gap-xs">
              <span className="banner-title">配置错误</span>
          <ul className="error-list text-sm">
            {errors.map((err, idx) => (
              <li key={idx}>{err}</li>
            ))}
          </ul>
        </div>
      )}

      <form onSubmit={handleSave} className="settings-form flex-col gap-md">
        <div className="split-layout">
          {/* Column 1: Core Networking & Daemon Details */}
          <div className="column flex-col gap-md">
            <div className="panel-section">
              <div className="panel-header">
                <h3>控制面</h3>
              </div>
              <div className="panel-body flex-col gap-md">
                <div className="form-group">
                  <label className="form-label">控制服务器</label>
                  <input
                    className="form-input text-mono"
                    type="url"
                    value={settings.controlServer}
                    onChange={(e) => handleFieldChange("controlServer", e.target.value)}
                    required
                  />
                  <span className="form-hint">用于节点注册、信令交换和网络配置分配。</span>
                </div>

                <div className="form-group">
                  <label className="form-label">设备名称</label>
                  <input
                    className="form-input text-mono"
                    type="text"
                    value={settings.deviceName}
                    onChange={(e) => handleFieldChange("deviceName", e.target.value)}
                    required
                  />
                  <span className="form-hint">显示给同一虚拟网络中的其他设备。</span>
                </div>

                <div className="form-group">
                  <label className="form-label">网络 ID</label>
                  <input
                    className="form-input text-mono"
                    type="text"
                    value={settings.networkId}
                    onChange={(e) => handleFieldChange("networkId", e.target.value)}
                    required
                  />
                  <span className="form-hint">要加入的虚拟网络范围。</span>
                </div>

                <div className="form-group">
                  <label className="form-label">认证 token</label>
                  <input
                    className="form-input text-mono"
                    type="password"
                    value={settings.authToken}
                    onChange={(e) => handleFieldChange("authToken", e.target.value)}
                    placeholder="登录或注册后会自动写入..."
                  />
                  <span className="form-hint">用于守护进程向控制面注册设备。</span>
                </div>
              </div>
            </div>
          </div>

          {/* Column 2: TUN & Relay Settings */}
          <div className="column flex-col gap-md">
            <div className="panel-section">
              <div className="panel-header">
                <h3>网络</h3>
              </div>
              <div className="panel-body flex-col gap-md">
                <div className="form-group">
                  <label className="form-label">网卡名称</label>
                  <input
                    className="form-input text-mono"
                    type="text"
                    value={settings.tunInterface}
                    onChange={(e) => handleFieldChange("tunInterface", e.target.value)}
                    required
                  />
                  <span className="form-hint">TUN 设备名称，例如 tun0、p2pnet0。</span>
                </div>

                <div className="form-group-row">
                  <div className="form-group">
                  <label className="form-label">MTU</label>
                    <input
                      className="form-input"
                      type="number"
                      value={settings.mtu}
                      onChange={(e) => handleFieldChange("mtu", parseInt(e.target.value) || 0)}
                      required
                    />
                  </div>
                  <div className="form-group">
                    <label className="form-label">Overlay CIDR</label>
                    <input
                      className="form-input text-mono"
                      type="text"
                      value={settings.overlayCidr}
                      onChange={(e) => handleFieldChange("overlayCidr", e.target.value)}
                      placeholder="10.20.0.0/16"
                    />
                  </div>
                </div>

                <div className="form-group">
                  <label className="form-label">诊断地址</label>
                  <input
                    className="form-input text-mono"
                    type="url"
                    value={settings.diagnosticsUrl}
                    onChange={(e) => handleFieldChange("diagnosticsUrl", e.target.value)}
                    required
                  />
                </div>

                <div className="form-group">
                  <label className="form-label">中继策略</label>
                  <select
                    className="form-input"
                    value={settings.relayPolicy}
                    onChange={(e) => handleFieldChange("relayPolicy", e.target.value as RelayPolicy)}
                  >
                    <option value="auto">自动：优先直连，失败后中继</option>
                    <option value="direct-first">优先直连 P2P</option>
                    <option value="relay-only">仅使用中继</option>
                  </select>
                </div>
              </div>
            </div>

            <div className="panel-section">
              <div className="panel-header">
                <h3>桌面</h3>
              </div>
              <div className="panel-body flex-col gap-sm">
                <label className="checkbox-row">
                  <input
                    type="checkbox"
                    checked={settings.startOnBoot}
                    onChange={(e) => handleFieldChange("startOnBoot", e.target.checked)}
                  />
                  <span className="checkbox-label flex-col">
                    <span className="title text-sm">登录系统后启动</span>
                    <span className="desc text-xs text-muted">系统登录后自动启动桌面客户端。</span>
                  </span>
                </label>

                <div className="form-group">
                  <label className="form-label">关闭窗口时</label>
                  <div className="choice-list">
                    <label
                      className={`choice-row ${settings.closeBehavior === "keep-running" ? "active" : ""}`}
                    >
                      <input
                        type="radio"
                        name="closeBehavior"
                        value="keep-running"
                        checked={settings.closeBehavior === "keep-running"}
                        onChange={() => handleCloseBehaviorChange("keep-running")}
                      />
                      <span className="choice-dot" aria-hidden="true" />
                      <span className="choice-copy">
                        <span className="title text-sm">保留后台运行</span>
                        <span className="desc text-xs text-muted">窗口隐藏到状态栏，TUN 与虚拟内网继续工作。</span>
                      </span>
                    </label>

                    <label
                      className={`choice-row ${settings.closeBehavior === "stop-and-quit" ? "active" : ""}`}
                    >
                      <input
                        type="radio"
                        name="closeBehavior"
                        value="stop-and-quit"
                        checked={settings.closeBehavior === "stop-and-quit"}
                        onChange={() => handleCloseBehaviorChange("stop-and-quit")}
                      />
                      <span className="choice-dot" aria-hidden="true" />
                      <span className="choice-copy">
                        <span className="title text-sm">停止 TUN 并退出</span>
                        <span className="desc text-xs text-muted">关闭窗口时先关闭守护进程，再退出 p2wlan。</span>
                      </span>
                    </label>
                  </div>
                </div>
              </div>
            </div>
          </div>
        </div>

        <div className="form-actions flex-row justify-between gap-sm">
          <button
            type="button"
            className="btn btn-ghost text-warning"
            onClick={() => {
              localStorage.removeItem("p2wlan.setup.completed");
              alert("配置向导状态已重置，下次启动会重新显示。");
            }}
          >
            <span>重置向导</span>
          </button>
          <button type="submit" className="btn btn-primary">
            <Save size={14} />
            <span>保存</span>
          </button>
        </div>
      </form>
    </div>
  );
}
