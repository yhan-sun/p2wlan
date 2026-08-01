// Daemon status snapshot assembly and peer/route/tunnel mapping for the
// unified client API.
//
// Split out of `clientApi.ts`.

export { clientStatusFromDesktopStatus } from "./status/desktop";
export {
  getClientStatusSnapshot,
  getDaemonStatus,
  getRouteStatus,
  getTunnelStatus,
  listPeers,
} from "./status/snapshot";
export { natProfileSummary, udpPoolSummary } from "./status/summaries";
export { renamePeerDevice } from "./status/rename";
