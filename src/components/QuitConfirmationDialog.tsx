import { useEffect, type MouseEvent } from "react";
import { createPortal } from "react-dom";
import { AlertTriangle, Power } from "lucide-react";

interface QuitConfirmationDialogProps {
  quitting: boolean;
  error: string | null;
  onCancel: () => void;
  onConfirm: () => void;
}

export default function QuitConfirmationDialog({
  quitting,
  error,
  onCancel,
  onConfirm,
}: QuitConfirmationDialogProps) {
  useEffect(() => {
    const previousOverflow = document.body.style.overflow;
    document.body.style.overflow = "hidden";

    const handleKeyDown = (event: KeyboardEvent) => {
      if (event.key === "Escape" && !quitting) onCancel();
    };
    document.addEventListener("keydown", handleKeyDown);

    return () => {
      document.body.style.overflow = previousOverflow;
      document.removeEventListener("keydown", handleKeyDown);
    };
  }, [onCancel, quitting]);

  const handleBackdrop = (event: MouseEvent<HTMLDivElement>) => {
    if (event.currentTarget === event.target && !quitting) onCancel();
  };

  return createPortal(
    <div className="quit-dialog-backdrop" onMouseDown={handleBackdrop}>
      <section
        className="quit-dialog"
        role="alertdialog"
        aria-modal="true"
        aria-labelledby="quit-dialog-title"
        aria-describedby="quit-dialog-description"
      >
        <div className="quit-dialog-heading">
          <span className="quit-dialog-icon" aria-hidden="true">
            <AlertTriangle size={20} />
          </span>
          <div>
            <h3 id="quit-dialog-title">确认完全退出 p2wlan？</h3>
            <p id="quit-dialog-description">退出会立即停止本机的虚拟内网服务。</p>
          </div>
        </div>

        <ul className="quit-impact-list">
          <li>断开当前虚拟内网连接</li>
          <li>注销 TUN 网卡并清理相关路由</li>
          <li>停止 p2wlan 后台守护进程</li>
        </ul>

        {error ? <div className="quit-dialog-error" role="alert">退出失败：{error}</div> : null}

        <footer className="quit-dialog-actions">
          <button className="btn btn-ghost" type="button" onClick={onCancel} disabled={quitting} autoFocus>
            继续运行
          </button>
          <button className="btn btn-danger" type="button" onClick={onConfirm} disabled={quitting}>
            <Power size={15} />
            {quitting ? "正在停止并退出..." : "停止并退出"}
          </button>
        </footer>
      </section>
    </div>,
    document.body
  );
}
