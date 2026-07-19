import { useCallback, useEffect, useState } from "react";
import { getCurrentWindow } from "@tauri-apps/api/window";
import { getSettings, quitApp } from "../lib/clientApi";

function isTauri(): boolean {
  return typeof window !== "undefined" && "__TAURI_INTERNALS__" in window;
}

export function useWindowLifecycle() {
  const [quitConfirmationOpen, setQuitConfirmationOpen] = useState(false);
  const [quitting, setQuitting] = useState(false);
  const [quitError, setQuitError] = useState<string | null>(null);

  const requestQuit = useCallback(() => {
    setQuitError(null);
    setQuitConfirmationOpen(true);
  }, []);

  const cancelQuit = useCallback(() => {
    if (quitting) return;
    setQuitConfirmationOpen(false);
    setQuitError(null);
  }, [quitting]);

  const confirmQuit = useCallback(async () => {
    if (quitting) return;
    setQuitting(true);
    setQuitError(null);

    const result = await quitApp();
    if (result.error) {
      setQuitError(result.error);
      setQuitting(false);
    }
  }, [quitting]);

  useEffect(() => {
    if (!isTauri()) return;

    let unlisten: (() => void) | null = null;
    let disposed = false;

    const setupListener = async () => {
      const appWindow = getCurrentWindow();
      const stopListening = await appWindow.onCloseRequested(async (event) => {
        let closeBehavior = "keep-running";
        try {
          closeBehavior = getSettings().closeBehavior;
        } catch {
          closeBehavior = "keep-running";
        }

        event.preventDefault();
        if (closeBehavior === "keep-running") {
          try {
            await appWindow.hide();
          } catch (err) {
            console.error("Failed to hide p2wlan after close request", err);
          }
          return;
        }

        requestQuit();
      });

      if (disposed) {
        stopListening();
      } else {
        unlisten = stopListening;
      }
    };

    void setupListener().catch(err => {
      console.error("Failed to register p2wlan close listener", err);
    });

    return () => {
      disposed = true;
      if (unlisten) unlisten();
    };
  }, [requestQuit]);

  return {
    quitConfirmationOpen,
    quitting,
    quitError,
    requestQuit,
    cancelQuit,
    confirmQuit,
  };
}
