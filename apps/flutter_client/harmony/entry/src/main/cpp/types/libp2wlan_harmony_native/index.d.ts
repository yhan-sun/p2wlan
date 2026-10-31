declare module 'libp2wlan_harmony_native.so' {
  export interface P2wlanNativeBuildInfo {
    abiVersion: number;
    engineVersion: string;
    target: string;
    arch: string;
  }

  export type P2wlanNativeErrorCode = 'NATIVE_QUERY_FAILED' | 'NATIVE_ABI_MISMATCH';

  export interface P2wlanNativeBuildInfoSuccess {
    ok: true;
    data: P2wlanNativeBuildInfo;
  }

  export interface P2wlanNativeBuildInfoFailure {
    ok: false;
    error: { code: P2wlanNativeErrorCode };
  }

  export type P2wlanNativeBuildInfoResult =
    P2wlanNativeBuildInfoSuccess | P2wlanNativeBuildInfoFailure;

  export interface P2wlanHarmonyNativeModule {
    getBuildInfo(): P2wlanNativeBuildInfoResult;
    prepareVpnNetworkV1(request: P2wlanNativeVpnNetworkRequestV1): Promise<P2wlanNativeVpnNetworkResultV1>;
    discardVpnNetworkV1(identityStorePath: string): boolean;
    startVpnEngineV1(request: P2wlanNativeVpnStartRequestV1): Promise<P2wlanNativeVpnStartResultV1>;
    stopVpnEngineV1(identity: P2wlanNativeVpnIdentityV1): Promise<P2wlanNativeVpnStoppedV1>;
    stopVpnEngineForExtensionDestroyV1(
      identity: P2wlanNativeVpnIdentityV1,
      timeoutMs: number
    ): P2wlanNativeVpnStopResultV1;
    getVpnEngineStatusV1(identity: P2wlanNativeVpnIdentityV1): P2wlanNativeVpnStatusV1;
  }

  export interface P2wlanNativeVpnIdentityV1 {
    instanceId: string;
    generation: number;
  }

  export interface P2wlanNativeVpnSettingsV1 {
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

  export interface P2wlanNativeVpnSettingsSnapshotV1 {
    schemaVersion: 1;
    revision: number;
    settings: P2wlanNativeVpnSettingsV1;
  }

  export interface P2wlanNativeVpnStartRequestV1 {
    version: 1;
    identity: P2wlanNativeVpnIdentityV1;
    fd: number;
    configuredRoutes: Array<string>;
    processProtected: true;
    identityStorePath: string;
    settingsSnapshot: P2wlanNativeVpnSettingsSnapshotV1;
  }

  export interface P2wlanNativeVpnNetworkRequestV1 {
    identityStorePath: string;
    settingsSnapshot: P2wlanNativeVpnSettingsSnapshotV1;
  }

  export type P2wlanNativeVpnNetworkResultV1 =
    | { status: 'ready'; virtualIp: string; cidr: string }
    | { status: 'failed'; code: string };

  export interface P2wlanNativeVpnStartReadyV1 {
    status: 'ready';
  }

  export interface P2wlanNativeVpnStartFailedV1 {
    status: 'failed';
    code: string;
  }

  export type P2wlanNativeVpnStartResultV1 =
    P2wlanNativeVpnStartReadyV1 | P2wlanNativeVpnStartFailedV1;

  export interface P2wlanNativeVpnStoppedV1 {
    status: 'stopped';
  }

  export interface P2wlanNativeVpnDrainingV1 {
    status: 'draining';
    code: 'stop_timeout' | 'native_stop_failed';
  }

  export type P2wlanNativeVpnStopResultV1 =
    P2wlanNativeVpnStoppedV1 | P2wlanNativeVpnDrainingV1;

  export type P2wlanNativeVpnStatusV1 =
    | { status: 'starting' }
    | { status: 'ready' }
    | { status: 'stopping' }
    | { status: 'stopped' }
    | { status: 'failed'; code: string };

  const p2wlanHarmonyNative: P2wlanHarmonyNativeModule;
  export default p2wlanHarmonyNative;
}
