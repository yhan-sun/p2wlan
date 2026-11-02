export interface OhosVpnIdentityV1 {
  instanceId: string;
  generation: number;
}

export interface VpnEngineSettingsV1 {
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
  socketPool: 'off' | '2' | '3' | '4';
  relayServers: Array<string>;
}

export interface VpnEngineSettingsSnapshotV1 {
  schemaVersion: 1;
  revision: number;
  settings: VpnEngineSettingsV1;
}

export interface NativeVpnStartRequestV1 {
  version: 1;
  identity: OhosVpnIdentityV1;
  fd: number;
  configuredRoutes: Array<string>;
  processProtected: true;
  identityStorePath: string;
  settingsSnapshot: VpnEngineSettingsSnapshotV1;
}

export interface NativeVpnNetworkRequestV1 {
  identityStorePath: string;
  settingsSnapshot: VpnEngineSettingsSnapshotV1;
}

export type NativeVpnNetworkResultV1 =
  | { status: 'ready'; virtualIp: string; cidr: string }
  | { status: 'failed'; code: string };

export interface NativeVpnStartReadyV1 {
  status: 'ready';
}

export interface NativeVpnStartFailedV1 {
  status: 'failed';
  code: string;
}

export type NativeVpnStartResultV1 =
  NativeVpnStartReadyV1 | NativeVpnStartFailedV1;

export interface NativeVpnStoppedV1 {
  status: 'stopped';
}

export interface NativeVpnDrainingV1 {
  status: 'draining';
  code: 'stop_timeout' | 'native_stop_failed';
}

export type NativeVpnStopResultV1 =
  NativeVpnStoppedV1 | NativeVpnDrainingV1;

export type NativeVpnEngineStatusV1 =
  | { status: 'starting' }
  | { status: 'ready' }
  | { status: 'stopping' }
  | { status: 'stopped' }
  | { status: 'failed'; code: string };

interface NativeVpnEngineModuleV1 {
  prepareVpnNetworkV1(request: NativeVpnNetworkRequestV1): Promise<NativeVpnNetworkResultV1>;
  discardVpnNetworkV1(identityStorePath: string): boolean;
  startVpnEngineV1(request: NativeVpnStartRequestV1): Promise<NativeVpnStartResultV1>;
  stopVpnEngineV1(identity: OhosVpnIdentityV1): Promise<NativeVpnStoppedV1>;
  stopVpnEngineForExtensionDestroyV1(
    identity: OhosVpnIdentityV1,
    timeoutMs: number
  ): NativeVpnStopResultV1;
  getVpnEngineStatusV1(identity: OhosVpnIdentityV1): NativeVpnEngineStatusV1;
}

interface NativeVpnEngineModuleNamespaceV1 {
  default: NativeVpnEngineModuleV1;
}

export class NativeVpnEngineError extends Error {
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
    throw new NativeVpnEngineError('NATIVE_VPN_API_UNAVAILABLE');
  }

  const nativeModule = loaded.default;
  if (nativeModule == undefined ||
      typeof nativeModule.prepareVpnNetworkV1 != 'function' ||
      typeof nativeModule.discardVpnNetworkV1 != 'function' ||
      typeof nativeModule.startVpnEngineV1 != 'function' ||
      typeof nativeModule.stopVpnEngineV1 != 'function' ||
      typeof nativeModule.stopVpnEngineForExtensionDestroyV1 != 'function' ||
      typeof nativeModule.getVpnEngineStatusV1 != 'function') {
    throw new NativeVpnEngineError('NATIVE_VPN_API_UNAVAILABLE');
  }
  return nativeModule;
}
