import { Want } from '@kit.AbilityKit';
import { util } from '@kit.ArkTS';
import { vpnExtension, VpnExtensionAbility } from '@kit.NetworkKit';
import {
  createVpnConfig,
  getConfiguredRouteSnapshot,
  parseP2wlanVpnStartCommand,
  P2wlanVpnRequestError,
  P2wlanVpnStartCommandV1,
  P2wlanVpnNetworkV1
} from './vpn_request';
import {
  consumeP2wlanVpnStopCommand,
  P2wlanVpnStopCommandV1
} from './vpn_lifecycle_command';
import {
  P2wlanVpnEngineSettingsV1,
  P2wlanVpnEngineSettingsSnapshotV1,
  P2wlanVpnSettingsSnapshotError,
  readP2wlanVpnEngineSettingsSnapshot
} from './vpn_settings_snapshot';
import {
  publishP2wlanVpnEngineStatusSnapshot,
  P2wlanVpnEngineStatusSnapshotError,
  P2wlanVpnEngineStatusIdentityV1,
  P2wlanVpnEngineStatusValueV1,
  readP2wlanVpnEngineStatusSnapshot
} from './vpn_engine_status_snapshot';
import {
  isNativeVpnStopped,
  loadNativeVpnEngineV1,
  NativeVpnAdapterError,
  NativeVpnEngineModuleV1,
  NativeVpnEngineSettingsV1,
  NativeVpnEngineSettingsSnapshotV1,
  OhosVpnIdentityV1
} from './native_vpn_engine';

const EXTENSION_STOP_TIMEOUT_MS: number = 3000;

interface HarmonyVpnErrorV1 extends Error {
  code?: number;
}

type VpnExtensionState =
  | 'idle'
  | 'starting'
  | 'protecting'
  | 'network_preparing'
  | 'creating'
  | 'engine_starting'
  | 'running'
  | 'stopping'
  | 'draining'
  | 'stopped'
  | 'failed';

export default class P2wlanVpnExtensionAbility extends VpnExtensionAbility {
  private state: VpnExtensionState = 'idle';
  private lifecycleEpoch: number = 0;
  private generation: number = 0;
  private destroying: boolean = false;
  private startInFlight: boolean = false;
  private engineMayOwnFd: boolean = false;
  private vpnCreated: boolean = false;
  private vpnDestroyStarted: boolean = false;
  private connection: vpnExtension.VpnConnection | null = null;
  private nativeEngine: NativeVpnEngineModuleV1 | null = null;
  private identity: OhosVpnIdentityV1 | null = null;
  private statusHeartbeatTimer: number = -1;
  private statusRequestId: string = '';
  private statusOperation: 'start' | 'stop' = 'start';
  private settingsRevision: number = 0;
  private preflightReserved: boolean = false;

  onCreate(want: Want): void {
    if (this.state != 'idle' || this.startInFlight || this.connection != null ||
        this.destroying) {
      return;
    }
    this.state = 'starting';
    this.startInFlight = true;
    const epoch = ++this.lifecycleEpoch;
    try {
      const command = parseP2wlanVpnStartCommand(want);
      this.statusRequestId = command.requestId;
      this.settingsRevision = command.settingsRevision;
    } catch (_error) {
      this.statusRequestId = this.createStatusRequestId();
      this.settingsRevision = 1;
    }
    this.statusOperation = 'start';
    try {
      this.claimStatusSession('START_REQUESTED');
      this.startStatusHeartbeat();
    } catch (error) {
      this.state = 'failed';
      this.startInFlight = false;
      const code = error instanceof Error
        ? this.errorCode(error) : 'VPN_STATUS_SESSION_CLAIM_FAILED';
      console.info(`[P2WLAN][VPN] ${code}`);
      return;
    }
    void this.startEngine(want, epoch);
  }

  onDestroy(): void {
    this.destroying = true;
    this.lifecycleEpoch++;
    this.state = 'stopping';
    const stopSessionClaimed = this.claimStopOperationIfCurrent();
    this.stopStatusHeartbeat();
    if (stopSessionClaimed) {
      this.claimStatusSession('ENGINE_STOP_REQUESTED');
    } else {
      this.report('ENGINE_STOP_REQUESTED');
    }

    if (this.engineMayOwnFd && this.nativeEngine != null && this.identity != null) {
      try {
        const stopResult = this.nativeEngine.stopVpnEngineForExtensionDestroyV1(
          this.identity,
          EXTENSION_STOP_TIMEOUT_MS
        );
        if (isNativeVpnStopped(stopResult)) {
          this.engineMayOwnFd = false;
          this.report('ENGINE_NATIVE_STOPPED');
          this.destroyVpnAfterNativeStop();
          return;
        }
        this.state = 'draining';
        this.report('ENGINE_STOP_DRAINING');
        return;
      } catch (_error) {
        this.state = 'draining';
        this.report('ENGINE_STOP_DRAINING');
        return;
      }
    }

    if (this.vpnCreated) {
      this.destroyVpnAfterNativeStop();
      return;
    }
    if (!this.startInFlight) {
      this.state = 'stopped';
      this.report('ENGINE_STOPPED');
    }
  }

  private async startEngine(want: Want, epoch: number): Promise<void> {
    try {
      const request: P2wlanVpnStartCommandV1 = parseP2wlanVpnStartCommand(want);
      const settingsSnapshot = readP2wlanVpnEngineSettingsSnapshot(this.context.filesDir);
      if (settingsSnapshot.revision != request.settingsRevision) {
        throw new P2wlanVpnSettingsSnapshotError('VPN_ENGINE_SETTINGS_SNAPSHOT_STALE');
      }
      const nativeEngine = await loadNativeVpnEngineV1();
      this.nativeEngine = nativeEngine;
      if (!this.isCurrent(epoch)) {
        this.markStoppedIfUnowned();
        return;
      }

      const connection = vpnExtension.createVpnConnection(this.context);
      this.connection = connection;
      const supportsSystemVpnId: boolean = typeof connection.generateVpnId == 'function';
      // Older runtimes lack system VPN IDs. A local UUID still fences native
      // lifecycle operations; it is never presented as a system VPN identifier.
      const instanceId = supportsSystemVpnId
        ? await connection.generateVpnId() : util.generateRandomUUID();
      if (typeof instanceId != 'string' || instanceId.length == 0) {
        throw new NativeVpnAdapterError('VPN_ID_INVALID');
      }
      if (!this.isCurrent(epoch)) {
        this.markStoppedIfUnowned();
        return;
      }

      this.state = 'protecting';
      this.report('PROCESS_PROTECTION_REQUESTED');
      await connection.protectProcessNet();
      this.report('PROCESS_PROTECTED');
      if (!this.isCurrent(epoch)) {
        this.markStoppedIfUnowned();
        return;
      }

      const identityStorePath = `${this.context.filesDir}/p2wlan/vpn-engine-identity-v1.bin`;
      this.state = 'network_preparing';
      this.report('VPN_NETWORK_PREPARATION_REQUESTED');
      const networkResult = await nativeEngine.prepareVpnNetworkV1({
        identityStorePath: identityStorePath,
        settingsSnapshot: this.nativeSettingsSnapshot(settingsSnapshot)
      });
      if (networkResult == undefined) {
        throw new NativeVpnAdapterError('VPN_NETWORK_PREFLIGHT_FAILED');
      }
      if (networkResult.status == 'failed') {
        const code = typeof networkResult.code == 'string' &&
          /^[a-z][a-z0-9_]{0,63}$/.test(networkResult.code)
          ? networkResult.code : 'VPN_NETWORK_PREFLIGHT_FAILED';
        throw new NativeVpnAdapterError(code);
      }
      if (networkResult.status != 'ready' ||
          typeof networkResult.virtualIp != 'string' ||
          typeof networkResult.cidr != 'string') {
        throw new NativeVpnAdapterError('VPN_NETWORK_PREFLIGHT_FAILED');
      }
      this.preflightReserved = !settingsSnapshot.settings.manualMode;
      if (!this.isCurrent(epoch)) {
        this.discardPreflightReservation(identityStorePath, nativeEngine);
        this.markStoppedIfUnowned();
        return;
      }
      const latestSettings = readP2wlanVpnEngineSettingsSnapshot(this.context.filesDir);
      if (latestSettings.revision != request.settingsRevision) {
        this.discardPreflightReservation(identityStorePath, nativeEngine);
        throw new P2wlanVpnSettingsSnapshotError('VPN_ENGINE_SETTINGS_SNAPSHOT_STALE');
      }
      const network: P2wlanVpnNetworkV1 = {
        virtualIp: networkResult.virtualIp,
        cidr: networkResult.cidr
      };
      const vpnConfig = createVpnConfig(settingsSnapshot.settings, network);
      if (supportsSystemVpnId) {
        vpnConfig.vpnId = instanceId;
      }
      const routeSnapshot = getConfiguredRouteSnapshot(vpnConfig);

      this.state = 'creating';
      this.report('VPN_CREATE_REQUESTED');
      const fd = await connection.create(vpnConfig as vpnExtension.VpnConfig);
      this.vpnCreated = true;
      if (!Number.isInteger(fd) || fd < 0) {
        throw new NativeVpnAdapterError('VPN_FD_INVALID');
      }
      if (!this.isCurrent(epoch)) {
        this.discardPreflightReservation(identityStorePath, nativeEngine);
        await this.destroyVpnAfterNativeStopAsync();
        return;
      }

      const identity: OhosVpnIdentityV1 = {
        instanceId: instanceId,
        generation: this.nextGeneration()
      };
      this.identity = identity;
      this.report('VPN_CREATED');
      const nativeSettingsSnapshot: NativeVpnEngineSettingsSnapshotV1 =
        this.nativeSettingsSnapshot(settingsSnapshot, network);
      this.engineMayOwnFd = true;
      this.state = 'engine_starting';
      this.report('ENGINE_STARTING');
      const startResult = await nativeEngine.startVpnEngineV1({
        version: 1,
        identity: identity,
        fd: fd,
        configuredRoutes: routeSnapshot,
        processProtected: true,
        identityStorePath: `${this.context.filesDir}/p2wlan/vpn-engine-identity-v1.bin`,
        settingsSnapshot: nativeSettingsSnapshot
      });
      if (!this.isCurrent(epoch)) {
        await this.stopThenDestroyVpn(identity, nativeEngine);
        return;
      }
      if (startResult != undefined && startResult.status == 'failed') {
        if (typeof startResult.code != 'string' ||
            !/^[a-z][a-z0-9_]{0,63}$/.test(startResult.code)) {
          throw new NativeVpnAdapterError('NATIVE_START_RESULT_INVALID');
        }
        const nativeCode = startResult.code;
        if (nativeCode == 'start_timeout' || nativeCode == 'start_cancelled') {
          throw new NativeVpnAdapterError(nativeCode);
        }
        this.engineMayOwnFd = false;
        this.state = 'failed';
        this.report(nativeCode);
        await this.destroyVpnAfterNativeStopAsync();
        return;
      }
      if (startResult == undefined || startResult.status != 'ready') {
        throw new NativeVpnAdapterError(
          'NATIVE_START_RESULT_INVALID'
        );
      }
      this.preflightReserved = false;
      this.state = 'running';
      this.report('ENGINE_READY');
    } catch (error) {
      const code = error instanceof Error
        ? this.errorCode(error) : 'VPN_START_FAILED';
      if (this.engineMayOwnFd && this.identity != null && this.nativeEngine != null) {
        this.state = 'stopping';
        this.report(code);
        await this.stopThenDestroyVpn(this.identity, this.nativeEngine);
      } else if (this.vpnCreated) {
        this.state = 'failed';
        this.report(code);
        await this.destroyVpnAfterNativeStopAsync();
      } else if (this.destroying) {
        this.state = 'stopped';
        this.report(code);
      } else {
        this.state = 'failed';
        this.report(code);
      }
    } finally {
      if (this.preflightReserved && !this.engineMayOwnFd && this.nativeEngine != null) {
        this.discardPreflightReservation(
          `${this.context.filesDir}/p2wlan/vpn-engine-identity-v1.bin`,
          this.nativeEngine
        );
      }
      this.startInFlight = false;
      if (this.state == 'stopped' || this.state == 'failed') {
        this.stopStatusHeartbeat();
      }
    }
  }

  private nativeSettingsSnapshot(
    snapshot: P2wlanVpnEngineSettingsSnapshotV1,
    network?: P2wlanVpnNetworkV1
  ): NativeVpnEngineSettingsSnapshotV1 {
    const settings = snapshot.settings;
    const copied: NativeVpnEngineSettingsV1 = {
      controlServer: settings.controlServer,
      authToken: settings.authToken,
      networkId: settings.networkId,
      manualMode: settings.manualMode,
      virtualIp: network == undefined ? settings.virtualIp : network.virtualIp,
      deviceName: settings.deviceName,
      overlayCidr: network == undefined ? settings.overlayCidr : network.cidr,
      tunInterface: settings.tunInterface,
      mtu: settings.mtu,
      udpBind: settings.udpBind,
      udpAdvertise: settings.udpAdvertise.length == 0 ? null : settings.udpAdvertise,
      socketPool: settings.socketPool,
      relayServers: settings.relayServers.slice()
    };
    return {
      schemaVersion: 1,
      revision: snapshot.revision,
      settings: copied
    };
  }

  private discardPreflightReservation(
    identityStorePath: string,
    nativeEngine: NativeVpnEngineModuleV1
  ): void {
    try {
      nativeEngine.discardVpnNetworkV1(identityStorePath);
    } catch (_error) {
      console.info('[P2WLAN][VPN] VPN_NETWORK_RESERVATION_DISCARD_FAILED');
    }
    this.preflightReserved = false;
  }

  private async stopThenDestroyVpn(
    identity: OhosVpnIdentityV1,
    nativeEngine: NativeVpnEngineModuleV1
  ): Promise<void> {
    this.state = 'stopping';
    this.report('ENGINE_STOP_REQUESTED');
    try {
      const result = await nativeEngine.stopVpnEngineV1(identity);
      const stopStatus: string = result.status;
      if (stopStatus != 'stopped') {
        this.state = 'draining';
        this.report('ENGINE_STOP_DRAINING');
        return;
      }
      this.engineMayOwnFd = false;
      await this.destroyVpnAfterNativeStopAsync();
    } catch (_error) {
      this.state = 'draining';
      this.report('ENGINE_STOP_DRAINING');
    }
  }

  private destroyVpnAfterNativeStop(): void {
    const connection = this.connection;
    if (!this.vpnCreated || this.vpnDestroyStarted || connection == null) {
      return;
    }
    this.vpnDestroyStarted = true;
    void connection.destroy().then(() => {
      this.vpnCreated = false;
      this.state = this.destroying ? 'stopped' : 'failed';
      this.report('VPN_DESTROYED');
      if (this.state == 'stopped' || this.state == 'failed') {
        this.stopStatusHeartbeat();
      }
    }).catch((_error: Error) => {
      this.state = 'failed';
      this.report('VPN_DESTROY_FAILED');
      this.stopStatusHeartbeat();
    });
  }

  private async destroyVpnAfterNativeStopAsync(): Promise<void> {
    const connection = this.connection;
    if (!this.vpnCreated || this.vpnDestroyStarted || connection == null) {
      return;
    }
    this.vpnDestroyStarted = true;
    try {
      await connection.destroy();
      this.vpnCreated = false;
      this.state = this.destroying ? 'stopped' : 'failed';
      this.report('VPN_DESTROYED');
      if (this.state == 'stopped' || this.state == 'failed') {
        this.stopStatusHeartbeat();
      }
    } catch (_error) {
      this.state = 'failed';
      this.report('VPN_DESTROY_FAILED');
      this.stopStatusHeartbeat();
    }
  }

  private markStoppedIfUnowned(): void {
    if (!this.vpnCreated && !this.engineMayOwnFd) {
      this.state = 'stopped';
      this.report('ENGINE_STOPPED');
    }
  }

  private isCurrent(epoch: number): boolean {
    return !this.destroying && epoch == this.lifecycleEpoch;
  }

  private nextGeneration(): number {
    if (this.generation >= Number.MAX_SAFE_INTEGER) {
      throw new NativeVpnAdapterError('VPN_GENERATION_EXHAUSTED');
    }
    this.generation++;
    return this.generation;
  }

  private errorCode(error: Object): string {
    if (error instanceof NativeVpnAdapterError) {
      return error.code;
    }
    if (error instanceof P2wlanVpnRequestError) {
      return error.code;
    }
    if (error instanceof P2wlanVpnSettingsSnapshotError) {
      return error.code;
    }
    if (error instanceof P2wlanVpnEngineStatusSnapshotError) {
      return error.code;
    }
    if (error != undefined && typeof error == 'object') {
      const nativeError = error as HarmonyVpnErrorV1;
      if (nativeError.code == 2203001) {
        return 'VPN_AUTHORIZATION_DENIED';
      }
    }
    return 'VPN_START_FAILED';
  }

  private claimStopOperationIfCurrent(): boolean {
    let command: P2wlanVpnStopCommandV1 | null = null;
    try {
      command = consumeP2wlanVpnStopCommand(this.context.filesDir);
    } catch (_error) {
      command = null;
    }
    if (command != null && command.settingsRevision == this.settingsRevision &&
        this.statusRequestId.length > 0) {
      try {
        const current = readP2wlanVpnEngineStatusSnapshot(this.context.filesDir);
        if (current.requestId == command.expectedStatusRequestId &&
            current.requestId == this.statusRequestId &&
            current.settingsRevision == this.settingsRevision &&
            current.revision >= command.afterStatusRevision) {
          this.statusRequestId = command.requestId;
          this.statusOperation = 'stop';
          return true;
        }
      } catch (_error) {
        // A stop command is accepted only when its expected start session exists.
      }
    }
    this.statusOperation = 'stop';
    return false;
  }

  private report(code: string): void {
    console.info(`[P2WLAN][VPN] ${code}`);
    try {
      this.publishStatus(code);
    } catch (_error) {
      console.info('[P2WLAN][VPN] VPN_ENGINE_STATUS_SNAPSHOT_WRITE_FAILED');
    }
  }

  private publishStatus(code?: string): void {
    publishP2wlanVpnEngineStatusSnapshot(
      this.context.filesDir,
      this.statusRequestId,
      this.statusOperation,
      this.settingsRevision,
      this.publicStatus(),
      this.statusIdentity(),
      code,
      false
    );
  }

  private claimStatusSession(code: string): void {
    publishP2wlanVpnEngineStatusSnapshot(
      this.context.filesDir,
      this.statusRequestId,
      this.statusOperation,
      this.settingsRevision,
      this.publicStatus(),
      this.statusIdentity(),
      code,
      true
    );
  }

  private createStatusRequestId(): string {
    const timePart = Date.now().toString(36);
    const epochPart = this.lifecycleEpoch.toString(36);
    const randomPart = Math.random().toString(36).slice(2, 10);
    return `${timePart}-${epochPart}-${randomPart}`;
  }

  private statusIdentity(): P2wlanVpnEngineStatusIdentityV1 | null {
    const identity = this.identity;
    if (identity == null) {
      return null;
    }
    const snapshotIdentity: P2wlanVpnEngineStatusIdentityV1 = {
      instanceId: identity.instanceId,
      generation: identity.generation
    };
    return snapshotIdentity;
  }

  private publicStatus(): P2wlanVpnEngineStatusValueV1 {
    switch (this.state) {
      case 'running':
        return 'ready';
      case 'stopping':
        return 'stopping';
      case 'draining':
        return 'draining';
      case 'stopped':
      case 'idle':
        return 'stopped';
      case 'failed':
        return 'failed';
      default:
        return 'starting';
    }
  }

  private startStatusHeartbeat(): void {
    if (this.statusHeartbeatTimer >= 0) {
      return;
    }
    this.statusHeartbeatTimer = setInterval(() => {
      if (this.state == 'stopped' || this.state == 'failed') {
        this.stopStatusHeartbeat();
        return;
      }
      try {
        this.publishStatus();
      } catch (_error) {
        console.info('[P2WLAN][VPN] VPN_ENGINE_STATUS_SNAPSHOT_WRITE_FAILED');
      }
    }, 5000);
  }

  private stopStatusHeartbeat(): void {
    if (this.statusHeartbeatTimer < 0) {
      return;
    }
    clearInterval(this.statusHeartbeatTimer);
    this.statusHeartbeatTimer = -1;
  }
}
