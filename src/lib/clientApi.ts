/**
 * Unified client API for the p2wlan web console.
 *
 * Primary source: local daemon diagnostics endpoint (`/status`).
 * Secondary: localStorage settings.
 * Pages must not hardcode mock data — fallbacks live only in this layer.
 *
 * This module is a facade: the implementation lives in `clientApi/`
 * submodules and is re-exported here to keep the public API stable.
 */

export { clearControlSession, authenticateWithControl } from "./clientApi/auth";
export { getSettings, saveSettings, validateSettings } from "./clientApi/config";
export { appendLog, getRecentLogs } from "./clientApi/log";
export {
  getClientStatusSnapshot,
  getDaemonStatus,
  listPeers,
  renamePeerDevice,
  getTunnelStatus,
  getRouteStatus,
} from "./clientApi/status";
export { getDiagnostics } from "./clientApi/diagnostics";
export {
  startDaemon,
  startDaemonElevated,
  stopDaemon,
  rebuildRoutes,
  openLogs,
  getPermissionStatus,
} from "./clientApi/daemon";
export type { AuthMode, AuthUser, AuthSession } from "./clientApi/types";
