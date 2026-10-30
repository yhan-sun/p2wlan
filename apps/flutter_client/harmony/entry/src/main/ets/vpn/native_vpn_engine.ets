export interface OhosVpnIdentityV1 {
  instanceId: string;
  generation: number;
}

export interface NativeVpnEngineSettingsV1 {
  controlServer: string;
  authToken: string;
  networkId: string;
  manualMode: boolean;
  virtualIp: string;
  deviceName: string;
  overlayCidr: string;
  tunInterface: string;
  mtu: number;
  udpBind: string;
  udpAdvertise: string | null;
  socketPool: string;
  relayServers: Array<string>;
}

export interface NativeVpnEngineSettingsSnapshotV1 {
  schemaVersion: 1;
  revision: number;
  settings: NativeVpnEngineSettingsV1;
}

export interface NativeVpnStartRequestV1 {
  version: 1;
  identity: OhosVpnIdentityV1;
  fd: number;
  configuredRoutes: Array<string>;
  processProtected: true;
  identityStorePath: string;
  settingsSnapshot: NativeVpnEngineSettingsSnapshotV1;
}

export interface NativeVpnNetworkRequestV1 {
  identityStorePath: string;
  settingsSnapshot: NativeVpnEngineSettingsSnapshotV1;
}

export interface NativeVpnNetworkReadyV1 {
  status: 'ready';
  virtualIp: string;
  cidr: string;
}

export interface NativeVpnNetworkFailedV1 {
  status: 'failed';
  code: string;
}

export type NativeVpnNetworkResultV1 =
  | NativeVpnNetworkReadyV1
  | NativeVpnNetworkFailedV1;

export interface NativeVpnStartReadyV1 {
  status: 'ready';
}

export interface NativeVpnStartFailedV1 {
  status: 'failed';
  code: string;
}

export type NativeVpnStartResultV1 = NativeVpnStartReadyV1 | NativeVpnStartFailedV1;

export interface NativeVpnStoppedV1 {
  status: 'stopped';
}

export interface NativeVpnDrainingV1 {
  status: 'draining';
  code: 'stop_timeout' | 'native_stop_failed';
}

export type NativeVpnStopResultV1 = NativeVpnStoppedV1 | NativeVpnDrainingV1;

// The asynchronous stop resolves only after the native owner and its workers
// have exited and the duplicated fd is closed. Bounded callers use the
// separate extension-destroy method, which may return `draining`.
export interface NativeVpnStopCompleteV1 {
  status: 'stopped';
}

export interface NativeVpnEngineModuleV1 {
  prepareVpnNetworkV1(request: NativeVpnNetworkRequestV1): Promise<NativeVpnNetworkResultV1>;
  discardVpnNetworkV1(identityStorePath: string): boolean;
  startVpnEngineV1(request: NativeVpnStartRequestV1): Promise<NativeVpnStartResultV1>;
  stopVpnEngineV1(identity: OhosVpnIdentityV1): Promise<NativeVpnStopCompleteV1>;
  stopVpnEngineForExtensionDestroyV1(
    identity: OhosVpnIdentityV1,
    timeoutMs: number
  ): NativeVpnStopResultV1;
}

interface NativeVpnEngineModuleNamespaceV1 {
  default: NativeVpnEngineModuleV1;
}

export class NativeVpnAdapterError extends Error {
  code: string;

  constructor(code: string) {
    super(code);
    this.code = code;
  }
}

export async function loadNativeVpnEngineV1(): Promise<NativeVpnEngineModuleV1> {
  let loaded: NativeVpnEngineModuleNamespaceV1;
  try {
    loaded = await import('libp2wlan_harmony_native.so');
  } catch {
    throw new NativeVpnAdapterError('NATIVE_VPN_API_UNAVAILABLE');
  }

  const candidate = loaded.default;
  if (candidate == undefined ||
      typeof candidate.prepareVpnNetworkV1 != 'function' ||
      typeof candidate.discardVpnNetworkV1 != 'function' ||
      typeof candidate.startVpnEngineV1 != 'function' ||
      typeof candidate.stopVpnEngineV1 != 'function' ||
      typeof candidate.stopVpnEngineForExtensionDestroyV1 != 'function') {
    throw new NativeVpnAdapterError('NATIVE_VPN_API_UNAVAILABLE');
  }
  return candidate;
}

export function isNativeVpnStopped(result: NativeVpnStopResultV1): boolean {
  return result != undefined && result.status == 'stopped';
}
