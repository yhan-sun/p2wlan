import { useState } from "react";
import { getSettings, saveSettings, validateSettings } from "../lib/clientApi";
import type { ClientSettings, CloseBehavior } from "../types/client";
import { Save, AlertTriangle, ShieldCheck, ChevronDown, ChevronUp } from "lucide-react";

export default function SettingsPage() {
  const [settings, setSettings] = useState<ClientSettings>(() => getSettings());
  const [errors, setErrors] = useState<string[]>([]);
  const [saveStatus, setSaveStatus] = useState<{ type: "success" | "error"; message: string } | null>(null);
  const [showAdvanced, setShowAdvanced] = useState(false);

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
      setSaveStatus({ type: "success", message: "设置已成功保存。" });
      window.dispatchEvent(new Event("storage"));
      setTimeout(() => setSaveStatus(null), 3000);
    }
  };

  return (
    <div className="page-container settings-page">
      <div className="page-header">
        <div>
          <h2>设置</h2>
          <p className="page-subtitle">配置网络标识、中继选线与桌面行为策略。</p>
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
          {/* Left Column: Basic Networking settings */}
          <div className="column flex-col gap-md">
            <div className="panel-section">
              <div className="panel-header">
                <h3>基本网络配置</h3>
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
                  <span className="form-hint">用户注册与设备认证的控制面服务器地址。</span>
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
                  <span className="form-hint">本设备在虚拟内网中显示的广播名称。</span>
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
                  <span className="form-hint">加入的专用虚拟内网网络标识符。</span>
                </div>

                <div className="form-group">
                  <label className="form-label">当前选路</label>
                  <div className="readonly-row">
                    <span className="readonly-value">自动直连，中继兜底</span>
                  </div>
                  <span className="form-hint">实际路径由守护进程按 NAT、UDP 可达性和中继可用性自动决策。</span>
                </div>
              </div>
            </div>
          </div>

          {/* Right Column: Desktop & MTU Settings */}
          <div className="column flex-col gap-md">
            <div className="panel-section">
              <div className="panel-header">
                <h3>系统与行为</h3>
              </div>
              <div className="panel-body flex-col gap-md">
                <div className="form-group">
                  <label className="form-label">物理 MTU</label>
                  <input
                    className="form-input"
                    type="number"
                    value={settings.mtu}
                    onChange={(e) => handleFieldChange("mtu", parseInt(e.target.value) || 0)}
                    required
                  />
                  <span className="form-hint">隧道网络接口的最大传输单元大小。</span>
                </div>

                <div className="form-group">
                  <label className="form-label">关闭窗口行为</label>
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
                        <span className="title text-sm">后台静默运行</span>
                        <span className="desc text-xs text-muted">关闭主窗口时窗口缩小到系统状态栏，不中断内网。</span>
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
                        <span className="title text-sm">完全停止并退出</span>
                        <span className="desc text-xs text-muted">关闭主窗口时先确认，再注销网卡、停止后台守护进程并退出。</span>
                      </span>
                    </label>
                  </div>
                </div>
              </div>
            </div>
          </div>
        </div>

        {/* Collapsible Advanced Settings Region */}
        <div className="panel-section advanced-section">
          <button
            type="button"
            className="advanced-header-toggle flex-row justify-between items-center"
            onClick={() => setShowAdvanced(!showAdvanced)}
          >
            <span>高级配置项</span>
            {showAdvanced ? <ChevronUp size={16} /> : <ChevronDown size={16} />}
          </button>

          {showAdvanced && (
            <div className="panel-body flex-col gap-md pt-md border-t border-light">
              <div className="form-group">
                <label className="form-label">认证 Token</label>
                <input
                  className="form-input text-mono"
                  type="password"
                  value={settings.authToken}
                  onChange={(e) => handleFieldChange("authToken", e.target.value)}
                  placeholder="未配置 Token"
                />
                <span className="form-hint">直接修改或查看登录后在本地缓存的控制面 Session 密钥。</span>
              </div>

              <div className="form-group-row">
                <div className="form-group flex-1">
                  <label className="form-label">网卡设备名称</label>
                  <input
                    className="form-input text-mono"
                    type="text"
                    value={settings.tunInterface}
                    onChange={(e) => handleFieldChange("tunInterface", e.target.value)}
                    required
                  />
                  <span className="form-hint">虚拟 TUN 接口的物理层命名。</span>
                </div>
                <div className="form-group flex-1">
                  <label className="form-label">Overlay CIDR 地址块</label>
                  <input
                    className="form-input text-mono"
                    type="text"
                    value={settings.overlayCidr}
                    onChange={(e) => handleFieldChange("overlayCidr", e.target.value)}
                    placeholder="10.20.0.0/16"
                  />
                  <span className="form-hint">虚拟子网段寻址规范。</span>
                </div>
              </div>

              <div className="form-group-row">
                <div className="form-group flex-1">
                  <label className="form-label">UDP 监听地址</label>
                  <input
                    className="form-input text-mono"
                    type="text"
                    value={settings.udpBind}
                    onChange={(e) => handleFieldChange("udpBind", e.target.value)}
                    placeholder="0.0.0.0:60207"
                  />
                  <span className="form-hint">直连传输使用的本机 UDP 端口；云主机建议固定端口。</span>
                </div>
                <div className="form-group flex-1">
                  <label className="form-label">公网 UDP 地址</label>
                  <input
                    className="form-input text-mono"
                    type="text"
                    value={settings.udpAdvertise}
                    onChange={(e) => handleFieldChange("udpAdvertise", e.target.value)}
                    placeholder="203.0.113.10:60207"
                  />
                  <span className="form-hint">发布给其他节点的可达公网地址；没有公网入口时留空。</span>
                </div>
              </div>

              <div className="form-group">
                <label className="form-label">增强打洞 socket pool</label>
                <select
                  className="form-input text-mono"
                  value={settings.socketPool}
                  onChange={(e) => handleFieldChange("socketPool", e.target.value)}
                >
                  <option value="off">off</option>
                  <option value="2">2 sockets</option>
                  <option value="3">3 sockets（推荐）</option>
                  <option value="4">4 sockets</option>
                </select>
                <span className="form-hint">
                  仅在守护进程判断本机为地址/端口依赖 NAT 时激活，用多条受控 UDP 映射增加打洞机会。
                </span>
              </div>

              <div className="form-group">
                <label className="form-label">本地守护进程诊断端口 (URL)</label>
                <input
                  className="form-input text-mono"
                  type="url"
                  value={settings.diagnosticsUrl}
                  onChange={(e) => handleFieldChange("diagnosticsUrl", e.target.value)}
                  required
                />
                <span className="form-hint">桌面客户端用来监听和轮询守护进程状态的 API 诊断服务终点。</span>
              </div>
            </div>
          )}
        </div>

        <div className="form-actions flex-row justify-end gap-sm border-t border-light pt-md">
          <button type="submit" className="btn btn-primary">
            <Save size={14} />
            <span>保存设置</span>
          </button>
        </div>
      </form>
    </div>
  );
}
