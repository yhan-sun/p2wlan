import { useEffect } from "react";
import { getCurrentWindow } from "@tauri-apps/api/window";
import { getSettings, quitApp } from "../lib/clientApi";

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
        let closeBehavior = "keep-running";
        try {
          closeBehavior = getSettings().closeBehavior;
        } catch {
          closeBehavior = "keep-running";
        }

        event.preventDefault();
        if (closeBehavior === "keep-running") {
          await appWindow.hide();
          return;
        }

        try {
          await appWindow.hide();
          await quitApp();
        } catch (err) {
          console.error("Failed to quit p2wlan from close request", err);
        }
      });
    };

    setupListener();

    return () => {
      if (unlisten) unlisten();
    };
  }, []);
}
