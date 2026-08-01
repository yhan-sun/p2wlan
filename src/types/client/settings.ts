import type { CloseBehavior, RelayPolicy } from "./base";

const DEFAULT_TUN_INTERFACE =
  typeof navigator !== "undefined" && navigator.userAgent.toLowerCase().includes("win")
    ? "p2wlan"
    : "p2pnet0";

export interface ClientSettings {
  controlServer: string;
  deviceName: string;
  networkId: string;
  mtu: number;
  overlayCidr: string;
  tunInterface: string;
  udpBind: string;
  udpAdvertise: string;
  socketPool: string;
  diagnosticsUrl: string;
  authToken: string;
  relayPolicy: RelayPolicy;
  relayServers: string;
  startOnBoot: boolean;
  closeBehavior: CloseBehavior;
  /** @deprecated use closeBehavior. Kept for migration from older builds. */
  minimizeToTray: boolean;
}

export const DEFAULT_SETTINGS: ClientSettings = {
  controlServer: "http://47.109.40.237:18080",
  deviceName: "this-device",
  networkId: "default",
  mtu: 1420,
  overlayCidr: "10.20.0.0/16",
  tunInterface: DEFAULT_TUN_INTERFACE,
  udpBind: "0.0.0.0:0",
  udpAdvertise: "",
  socketPool: "3",
  diagnosticsUrl: "http://127.0.0.1:39277/status",
  authToken: "",
  relayPolicy: "auto",
  relayServers: "",
  startOnBoot: false,
  closeBehavior: "keep-running",
  minimizeToTray: true,
};
