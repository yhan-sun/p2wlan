import { useEffect, useState, type FormEvent, type MouseEvent } from "react";
import { createPortal } from "react-dom";
import { CheckCircle2, Copy, Save, X } from "lucide-react";
import type { PeerStatus } from "../types/client";
import { StatusPill, connectionTone, pathTone, zhLabel } from "./StatusPill";

interface DeviceEditorDialogProps {
  peer: PeerStatus;
  saving: boolean;
  error: string | null;
  onClose: () => void;
  onSave: (deviceName: string) => Promise<void>;
  onCopyIp: () => void;
}

export default function DeviceEditorDialog({
  peer,
  saving,
  error,
  onClose,
  onSave,
  onCopyIp,
}: DeviceEditorDialogProps) {
  const [deviceName, setDeviceName] = useState(peer.name);
  const normalizedName = deviceName.trim();
  const canSave = normalizedName.length > 0 && normalizedName !== peer.name && !saving;

  useEffect(() => {
    const previousOverflow = document.body.style.overflow;
    document.body.style.overflow = "hidden";
    const handleKeyDown = (event: KeyboardEvent) => {
      if (event.key === "Escape" && !saving) onClose();
    };
    document.addEventListener("keydown", handleKeyDown);
    return () => {
      document.body.style.overflow = previousOverflow;
      document.removeEventListener("keydown", handleKeyDown);
    };
  }, [onClose, saving]);

  const handleBackdrop = (event: MouseEvent<HTMLDivElement>) => {
    if (event.currentTarget === event.target && !saving) onClose();
  };

  const handleSubmit = (event: FormEvent) => {
    event.preventDefault();
    if (canSave) void onSave(normalizedName);
  };

  const directHealthy =
    peer.directHealth?.last_success_age_ms != null &&
    peer.directHealth.consecutive_failures === 0;

  return createPortal(
    <div className="device-dialog-backdrop" onMouseDown={handleBackdrop}>
      <form
        className="device-dialog"
        role="dialog"
        aria-modal="true"
        aria-labelledby="device-dialog-title"
        onSubmit={handleSubmit}
      >
        <header className="device-dialog-header">
          <div>
            <h3 id="device-dialog-title">编辑设备</h3>
            <p>{peer.virtualIp}</p>
          </div>
          <button
            className="btn btn-ghost btn-icon device-dialog-close"
            type="button"
            onClick={onClose}
            disabled={saving}
            aria-label="关闭编辑设备弹窗"
            title="关闭"
          >
            <X size={17} />
          </button>
        </header>

        <div className="device-dialog-body">
          <div className="device-name-editor">
            <label htmlFor="device-name-input">设备名称</label>
            <input
              id="device-name-input"
              className="form-input"
              value={deviceName}
              onChange={(event) => setDeviceName(event.target.value)}
              maxLength={128}
              autoFocus
              disabled={saving}
              placeholder="例如：书房 Mac"
            />
            <span>保存后会同步到同一控制面账号下的其他客户端。</span>
          </div>

          {error && (
            <div className="device-dialog-error" role="alert">
              {error}
            </div>
          )}

          <section className="device-dialog-section" aria-labelledby="connection-details-title">
            <div className="device-dialog-section-title">
              <h4 id="connection-details-title">连接信息</h4>
              <div className="device-dialog-pills">
                <StatusPill label={zhLabel(peer.state)} tone={connectionTone(peer.state)} />
                {peer.path !== peer.state && (
                  <StatusPill label={zhLabel(peer.path)} tone={pathTone(peer.path)} />
                )}
              </div>
            </div>

            <dl className="device-details-list">
              <div>
                <dt>虚拟 IP</dt>
                <dd className="device-detail-copy">
                  <code>{peer.virtualIp}</code>
                  <button
                    type="button"
                    className="btn btn-ghost btn-icon"
                    onClick={onCopyIp}
                    aria-label="复制虚拟 IP"
                    title="复制虚拟 IP"
                  >
                    <Copy size={14} />
                  </button>
                </dd>
              </div>
              <div>
                <dt>延迟</dt>
                <dd>{peer.latencyMs == null ? "--" : `${Math.round(peer.latencyMs)} ms`}</dd>
              </div>
              <div>
                <dt>物理端点</dt>
                <dd><code>{peer.endpoint || "--"}</code></dd>
              </div>
              <div>
                <dt>NAT 类型</dt>
                <dd>{peer.natType || "unknown"}</dd>
              </div>
              <div>
                <dt>中继服务器</dt>
                <dd><code>{peer.relayServer || "--"}</code></dd>
              </div>
              <div>
                <dt>直连探测</dt>
                <dd className={directHealthy ? "text-success" : "text-danger"}>
                  {directHealthy ? <CheckCircle2 size={14} /> : null}
                  {directHealthy ? "可达" : peer.directHealth?.last_error || "未连接"}
                </dd>
              </div>
            </dl>
          </section>

          {peer.candidates && peer.candidates.length > 0 && (
            <section className="device-dialog-section" aria-labelledby="candidate-title">
              <div className="device-dialog-section-title">
                <h4 id="candidate-title">候选端点</h4>
                <span>{peer.candidates.length} 个</span>
              </div>
              <div className="device-dialog-candidates">
                {peer.candidates.map((candidate) => (
                  <code key={candidate}>{candidate}</code>
                ))}
              </div>
            </section>
          )}

          <details className="device-node-id">
            <summary>节点标识</summary>
            <code>{peer.id}</code>
          </details>
        </div>

        <footer className="device-dialog-footer">
          <button className="btn btn-ghost" type="button" onClick={onClose} disabled={saving}>
            取消
          </button>
          <button className="btn btn-primary" type="submit" disabled={!canSave}>
            <Save size={14} />
            {saving ? "保存中..." : "保存名称"}
          </button>
        </footer>
      </form>
    </div>,
    document.body
  );
}
