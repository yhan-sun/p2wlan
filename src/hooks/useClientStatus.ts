import {
  createContext,
  createElement,
  type PropsWithChildren,
  useCallback,
  useContext,
  useEffect,
  useRef,
  useState,
} from "react";
import {
  appendLog,
  clientStatusFromDesktopStatus,
  configureDaemon,
  getClientStatusSnapshot,
  getSettings,
  isTauri,
  startDaemon,
  startDaemonElevated,
  stopDaemon,
} from "../lib/clientApi";
import type {
  ClientSettings,
  DaemonOperationStatus,
  DaemonStatus,
  DesktopStatus,
  PeerStatus,
  RouteStatus,
  TunnelStatus,
} from "../types/client";
import {
  DEFAULT_SETTINGS,
  stoppedDaemonStatus,
  stoppedOperationStatus,
} from "../types/client";

const VISIBLE_POLL_MS = 2000;
const HIDDEN_POLL_MS = 10_000;

export interface ClientStatusState {
  daemon: DaemonStatus;
  peers: PeerStatus[];
  tunnel: TunnelStatus | null;
  route: RouteStatus | null;
  operation: DaemonOperationStatus;
  settings: ClientSettings;
  loading: boolean;
  refreshing: boolean;
  lastError: string | null;
  lastFetchedAt: number | null;
  refresh: () => Promise<void>;
  connect: () => Promise<string>;
  connectElevated: () => Promise<string>;
  disconnect: () => Promise<string>;
  reloadSettings: () => void;
}

const ClientStatusContext = createContext<ClientStatusState | null>(null);

function useClientStatusController(): ClientStatusState {
  const [settings, setSettings] = useState<ClientSettings>(() => getSettings());
  const [daemon, setDaemon] = useState<DaemonStatus>(() => stoppedDaemonStatus(getSettings()));
  const [peers, setPeers] = useState<PeerStatus[]>([]);
  const [tunnel, setTunnel] = useState<TunnelStatus | null>(null);
  const [route, setRoute] = useState<RouteStatus | null>(null);
  const [operation, setOperation] = useState<DaemonOperationStatus>(() =>
    stoppedOperationStatus()
  );
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const [lastError, setLastError] = useState<string | null>(null);
  const [lastFetchedAt, setLastFetchedAt] = useState<number | null>(null);
  const inFlight = useRef(false);
  const eventFallbackInFlight = useRef(false);
  const lastOperationLogKey = useRef<string | null>(null);

  const applySnapshot = useCallback((snapshot: Awaited<ReturnType<typeof getClientStatusSnapshot>>) => {
    const { operation } = snapshot;
    const operationLogKey = `${operation.phase}|${operation.message}|${operation.lastError ?? ""}`;
    if (lastOperationLogKey.current !== operationLogKey) {
      lastOperationLogKey.current = operationLogKey;
      if (operation.phase !== "stopped") {
        appendLog(
          `daemon operation ${operation.phase}: ${operation.message}${
            operation.lastError ? `; ${operation.lastError}` : ""
          }`
        );
      }
    }
    setSettings(getSettings());
    setDaemon(snapshot.daemon);
    setPeers(snapshot.peers);
    setTunnel(snapshot.tunnel);
    setRoute(snapshot.route);
    setOperation(snapshot.operation);
    setLastError(snapshot.error ?? snapshot.daemon.lastError ?? null);
    setLastFetchedAt(Date.now());
    setLoading(false);
    setRefreshing(false);
  }, []);

  const refresh = useCallback(async () => {
    if (inFlight.current) return;
    inFlight.current = true;
    setRefreshing(true);
    try {
      applySnapshot(await getClientStatusSnapshot());
    } catch (error) {
      const message = error instanceof Error ? error.message : "读取状态失败";
      setLastError(message);
      setDaemon(stoppedDaemonStatus(getSettings(), message));
      setOperation({
        ...stoppedOperationStatus(),
        phase: "error",
        message: "读取状态失败",
        lastError: message,
      });
      setLoading(false);
      setRefreshing(false);
    } finally {
      inFlight.current = false;
    }
  }, [applySnapshot]);

  const applyDesktopStatus = useCallback((desktop: DesktopStatus) => {
    const shouldRecoverRunningStatus =
      isTauri() &&
      !desktop.diagnostics &&
      (desktop.diagnosticsAlive || desktop.operation.phase === "running");

    if (!shouldRecoverRunningStatus) {
      applySnapshot(clientStatusFromDesktopStatus(desktop));
      return;
    }

    if (eventFallbackInFlight.current) return;
    eventFallbackInFlight.current = true;
    void getClientStatusSnapshot()
      .then(applySnapshot)
      .catch(() => applySnapshot(clientStatusFromDesktopStatus(desktop)))
      .finally(() => {
        eventFallbackInFlight.current = false;
      });
  }, [applySnapshot]);

  useEffect(() => {
    let disposed = false;
    let unlisten: (() => void) | null = null;
    let timer: number | null = null;

    const syncConfiguration = async () => {
      try {
        await configureDaemon();
      } catch {
        // The desktop bridge may not be ready during browser-only development.
      }
    };

    const scheduleBrowserPoll = () => {
      if (disposed || isTauri()) return;
      const delay = document.visibilityState === "hidden" ? HIDDEN_POLL_MS : VISIBLE_POLL_MS;
      timer = window.setTimeout(async () => {
        await refresh();
        scheduleBrowserPoll();
      }, delay);
    };

    void syncConfiguration();
    void refresh();

    if (isTauri()) {
      void import("@tauri-apps/api/event")
        .then(async ({ listen }) => {
          const stopListening = await listen<DesktopStatus>("p2wlan-status", event => {
            if (!disposed) applyDesktopStatus(event.payload);
          });
          if (disposed) {
            stopListening();
          } else {
            unlisten = stopListening;
          }
        })
        .catch(error => {
          if (!disposed) setLastError(`无法订阅桌面状态：${String(error)}`);
        });
    } else {
      scheduleBrowserPoll();
    }

    const handleStorage = () => {
      setSettings(getSettings());
      void syncConfiguration();
      void refresh();
    };
    const handleVisibility = () => {
      if (timer != null) window.clearTimeout(timer);
      timer = null;
      if (document.visibilityState === "visible") void refresh();
      scheduleBrowserPoll();
    };
    window.addEventListener("storage", handleStorage);
    document.addEventListener("visibilitychange", handleVisibility);

    return () => {
      disposed = true;
      if (unlisten) unlisten();
      if (timer != null) window.clearTimeout(timer);
      window.removeEventListener("storage", handleStorage);
      document.removeEventListener("visibilitychange", handleVisibility);
    };
  }, [applyDesktopStatus, refresh]);

  const connect = useCallback(async () => {
    const result = await startDaemon();
    await refresh();
    if (result.error || !result.data.started) {
      throw new Error(result.data.message || result.error || "启动守护进程失败");
    }
    return result.data.message;
  }, [refresh]);

  const waitForElevatedOutcome = useCallback(async () => {
    const deadline = Date.now() + 60_000;
    let lastSnapshot: Awaited<ReturnType<typeof getClientStatusSnapshot>> | null = null;

    while (Date.now() < deadline) {
      const snapshot = await getClientStatusSnapshot();
      lastSnapshot = snapshot;
      applySnapshot(snapshot);

      if (snapshot.daemon.reachable || snapshot.operation.phase === "running") {
        return snapshot.operation.message || "TUN 已连接";
      }

      if (snapshot.operation.phase === "error") {
        throw new Error(snapshot.operation.lastError ?? snapshot.operation.message ?? "TUN 启动失败");
      }

      await new Promise(resolve => window.setTimeout(resolve, 1_000));
    }

    const lastOperation = lastSnapshot?.operation;
    throw new Error(
      lastOperation?.lastError ??
        `${lastOperation?.message ?? "TUN 启动"}超时，诊断端点仍不可访问。请打开诊断页复制最近日志。`
    );
  }, [applySnapshot]);

  const connectElevated = useCallback(async () => {
    const result = await startDaemonElevated();
    if (result.error || !result.data.started) {
      throw new Error(result.data.message || result.error || "提权启动 TUN 失败");
    }
    return waitForElevatedOutcome();
  }, [waitForElevatedOutcome]);

  const disconnect = useCallback(async () => {
    const result = await stopDaemon();
    await refresh();
    if (result.error || !result.data.stopped) {
      throw new Error(result.data.message || result.error || "停止守护进程失败");
    }
    return result.data.message;
  }, [refresh]);

  const reloadSettings = useCallback(() => {
    setSettings(getSettings());
    void configureDaemon();
  }, []);

  return {
    daemon,
    peers,
    tunnel,
    route,
    operation,
    settings: settings ?? DEFAULT_SETTINGS,
    loading,
    refreshing,
    lastError,
    lastFetchedAt,
    refresh,
    connect,
    connectElevated,
    disconnect,
    reloadSettings,
  };
}

export function ClientStatusProvider({ children }: PropsWithChildren) {
  const value = useClientStatusController();
  return createElement(ClientStatusContext.Provider, { value }, children);
}

export function useClientStatus(): ClientStatusState {
  const context = useContext(ClientStatusContext);
  if (!context) {
    throw new Error("useClientStatus must be used within ClientStatusProvider");
  }
  return context;
}
