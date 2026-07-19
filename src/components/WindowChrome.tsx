import { useEffect, type MouseEvent as ReactMouseEvent } from "react";
import { Maximize2, Minus, X } from "lucide-react";
import { invoke } from "@tauri-apps/api/core";
import { getCurrentWindow } from "@tauri-apps/api/window";

export type DesktopPlatform = "macos" | "windows" | "linux" | "web";

export function detectDesktopPlatform(): DesktopPlatform {
  if (typeof window === "undefined" || !("__TAURI_INTERNALS__" in window)) return "web";

  const platform = navigator.platform.toLowerCase();
  const userAgent = navigator.userAgent.toLowerCase();
  if (platform.includes("mac") || userAgent.includes("mac os")) return "macos";
  if (platform.includes("win") || userAgent.includes("windows")) return "windows";
  return "linux";
}

async function withCurrentWindow(
  action: (window: ReturnType<typeof getCurrentWindow>) => Promise<void>
) {
  await action(getCurrentWindow());
}

async function toggleMaximize() {
  await withCurrentWindow(async window => {
    if (await window.isMaximized()) {
      await window.unmaximize();
    } else {
      await window.maximize();
    }
  });
}

interface WindowChromeProps {
  platform: DesktopPlatform;
}

export default function WindowChrome({ platform }: WindowChromeProps) {
  useEffect(() => {
    if (platform === "web") return;
    void invoke("window_chrome_ready").catch(error =>
      console.error("Failed to apply native window chrome", error)
    );
  }, [platform]);

  if (platform === "web") return null;

  const handleDrag = (event: ReactMouseEvent<HTMLDivElement>) => {
    if (event.button !== 0 || event.detail > 1) return;
    if (event.target instanceof Element && event.target.closest("button")) return;
    void getCurrentWindow().startDragging().catch(error => {
      console.error("Failed to start window dragging", error);
    });
  };

  const handleDoubleClick = () => {
    if (platform !== "macos") void toggleMaximize();
  };

  return (
    <div
      className={`window-chrome window-chrome-${platform}`}
      onDoubleClick={handleDoubleClick}
      role="presentation"
    >
      <div
        className="window-drag-region"
        data-tauri-drag-region
        onMouseDown={handleDrag}
        role="presentation"
      />
      {platform !== "macos" && (
        <div className="window-controls" data-no-window-drag>
          <button
            type="button"
            className="window-control"
            aria-label="最小化窗口"
            title="最小化"
            onClick={() => void withCurrentWindow(window => window.minimize())}
          >
            <Minus size={15} strokeWidth={1.7} />
          </button>
          <button
            type="button"
            className="window-control"
            aria-label="最大化或还原窗口"
            title="最大化或还原"
            onClick={() => void toggleMaximize()}
          >
            <Maximize2 size={13} strokeWidth={1.7} />
          </button>
          <button
            type="button"
            className="window-control window-control-close"
            aria-label="关闭窗口"
            title="关闭"
            onClick={() => void withCurrentWindow(window => window.close())}
          >
            <X size={15} strokeWidth={1.7} />
          </button>
        </div>
      )}
    </div>
  );
}
