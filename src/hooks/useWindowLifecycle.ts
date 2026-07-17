import { useEffect } from "react";
import { getCurrentWindow } from "@tauri-apps/api/window";

function isTauri(): boolean {
  return typeof window !== "undefined" && "__TAURI_INTERNALS__" in window;
}

export function useWindowLifecycle() {
  useEffect(() => {
    if (!isTauri()) return;

    let unlisten: (() => void) | null = null;

    const setupListener = async () => {
      const appWindow = getCurrentWindow();
      unlisten = await appWindow.onCloseRequested(async (event) => {
        // Read local storage settings
        let minimize = true; // default fallback
        try {
          const raw = localStorage.getItem("p2wlan.client.settings");
          if (raw) {
            const parsed = JSON.parse(raw);
            if (parsed.minimizeToTray !== undefined) {
              minimize = parsed.minimizeToTray;
            }
          }
        } catch {
          // ignore
        }

        if (minimize) {
          // Prevent window from closing
          event.preventDefault();
          // Hide window instead
          await appWindow.hide();
        }
      });
    };

    setupListener();

    return () => {
      if (unlisten) unlisten();
    };
  }, []);
}
