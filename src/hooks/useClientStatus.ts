import { useCallback, useEffect, useRef, useState } from "react";
import {
  getDaemonStatus,
  getRouteStatus,
  getSettings,
  getTunnelStatus,
  listPeers,
  startDaemon,
  startDaemonElevated,
  stopDaemon,
} from "../lib/clientApi";
import type {
  ClientSettings,
  DaemonStatus,
  PeerStatus,
  RouteStatus,
  TunnelStatus,
} from "../types/client";
import { DEFAULT_SETTINGS, stoppedDaemonStatus } from "../types/client";

/** Low-frequency poll interval. Keep between 1500–2500ms. */
const POLL_MS = 2000;

export interface ClientStatusState {
  daemon: DaemonStatus;
  peers: PeerStatus[];
  tunnel: TunnelStatus | null;
  route: RouteStatus | null;
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

export function useClientStatus(): ClientStatusState {
  const [settings, setSettings] = useState<ClientSettings>(() => getSettings());
  const [daemon, setDaemon] = useState<DaemonStatus>(() =>
    stoppedDaemonStatus(getSettings())
  );
  const [peers, setPeers] = useState<PeerStatus[]>([]);
  const [tunnel, setTunnel] = useState<TunnelStatus | null>(null);
  const [route, setRoute] = useState<RouteStatus | null>(null);
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const [lastError, setLastError] = useState<string | null>(null);
  const [lastFetchedAt, setLastFetchedAt] = useState<number | null>(null);
  const inFlight = useRef(false);

  const refresh = useCallback(async () => {
    if (inFlight.current) return;
    inFlight.current = true;
    setRefreshing(true);
    try {
      const currentSettings = getSettings();
      setSettings(currentSettings);

      const [daemonRes, peersRes, tunnelRes, routeRes] = await Promise.all([
        getDaemonStatus(),
        listPeers(),
        getTunnelStatus(),
        getRouteStatus(),
      ]);

      setDaemon(daemonRes.data);
      setPeers(peersRes.data);
      setTunnel(tunnelRes.data);
      setRoute(routeRes.data);
      setLastFetchedAt(Date.now());

      const daemonRunning =
        daemonRes.source === "live" &&
        daemonRes.data.reachable &&
        daemonRes.data.lifecycle === "running";
      const derivedError =
        peersRes.error ?? tunnelRes.error ?? routeRes.error ?? null;
      // Once the daemon is reachable, do not keep showing stale fallback errors from
      // peer/tunnel/route helpers. Those helpers are derived from the daemon snapshot.
      if (daemonRunning) {
        setLastError(daemonRes.data.lastError ?? null);
      } else if (daemonRes.source === "fallback") {
        setLastError(daemonRes.error ?? "daemon offline");
      } else {
        setLastError(
          derivedError && derivedError.includes("not yet exposed")
            ? null
            : derivedError
        );
      }
    } catch (e) {
      const message = e instanceof Error ? e.message : "status refresh failed";
      setLastError(message);
      setDaemon(stoppedDaemonStatus(getSettings(), message));
    } finally {
      setLoading(false);
      setRefreshing(false);
      inFlight.current = false;
    }
  }, []);

  useEffect(() => {
    void refresh();
    const id = window.setInterval(() => {
      void refresh();
    }, POLL_MS);
    return () => window.clearInterval(id);
  }, [refresh]);

  const connect = useCallback(async () => {
    const result = await startDaemon();
    await refresh();
    if (result.error || !result.data.started) {
      throw new Error(result.data.message || result.error || "启动守护进程失败");
    }
    return result.data.message;
  }, [refresh]);

  const connectElevated = useCallback(async () => {
    const result = await startDaemonElevated();
    await refresh();
    if (result.error || !result.data.started) {
      throw new Error(result.data.message || result.error || "提权启动 TUN 失败");
    }
    return result.data.message;
  }, [refresh]);

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
  }, []);

  return {
    daemon,
    peers,
    tunnel,
    route,
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
