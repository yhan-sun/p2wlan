
import hilog from '@ohos.hilog';
import { fileIo as fs } from '@kit.CoreFileKit';
import {
  FlutterAbility,
  FlutterEngine,
  MethodCall,
  MethodCallHandler,
  MethodChannel,
  MethodResult,
} from '@ohos/flutter_ohos';
import { GeneratedPluginRegistrant } from '../plugins/GeneratedPluginRegistrant';
import { queryNativeBuildInfo } from '../native/build_info';
import {
  clearP2wlanVpnStopCommand,
  publishP2wlanVpnStopCommand
} from '../vpn/vpn_lifecycle_command';
import {
  readP2wlanVpnEngineStatusSnapshot,
  readP2wlanVpnEngineStatusSnapshotIfPresent,
  P2wlanVpnEngineStatusSnapshotError,
  waitForAndFinalizeP2wlanVpnEngineStopSnapshot
} from '../vpn/vpn_engine_status_snapshot';
import {
  requestP2wlanVpnStart,
  requestP2wlanVpnStop,
  VpnAbilityRequestResult
} from '../vpn/vpn_request';

class PlatformMethodCallHandler implements MethodCallHandler {
  private filesDir: string;

  constructor(filesDir: string) {
    this.filesDir = filesDir;
  }

  onMethodCall(call: MethodCall, result: MethodResult): void {
    if (call.method == 'applicationSupportDirectory') {
      result.success(this.filesDir + '/p2wlan');
      return;
    }
    if (call.method == 'diagnosticsAuthToken') {
      result.success(this.readDiagnosticsAuthToken());
      return;
    }
    if (call.method == 'nativeBuildInfo') {
      void queryNativeBuildInfo().then((payload) => {
        result.success(payload);
      }).catch((_error: Error) => {
        result.success({ ok: false, error: { code: 'NATIVE_QUERY_FAILED' } });
      });
      return;
    }
    if (call.method == 'vpnEngineStatusV1') {
      try {
        result.success({
          ok: true,
          data: readP2wlanVpnEngineStatusSnapshot(this.filesDir)
        });
      } catch (error) {
        let code: string = 'VPN_ENGINE_STATUS_SNAPSHOT_READ_FAILED';
        if (error instanceof P2wlanVpnEngineStatusSnapshotError) {
          code = error.code;
        }
        result.success({ ok: false, error: { code: code } });
      }
      return;
    }
    if (call.method == 'vpnEngineStatusV2') {
      try {
        result.success({
          ok: true,
          data: readP2wlanVpnEngineStatusSnapshotIfPresent(this.filesDir)
        });
      } catch (error) {
        let code: string = 'VPN_ENGINE_STATUS_SNAPSHOT_READ_FAILED';
        if (error instanceof P2wlanVpnEngineStatusSnapshotError) {
          code = error.code;
        }
        result.success({ ok: false, error: { code: code } });
      }
      return;
    }
    if (call.method == 'startVpnV2') {
      this.startVpn(call.args as Object, result);
      return;
    }
    if (call.method == 'stopVpnV2') {
      this.stopVpn(call.args as Object, result);
      return;
    }
    result.notImplemented();
  }

  private readDiagnosticsAuthToken(): string | null {
    try {
      const file = fs.openSync(
        this.filesDir + '/p2wlan/p2wlan-daemon.diag-auth', fs.OpenMode.READ_ONLY
      );
      try {
        const bytes = new ArrayBuffer(65);
        const length = fs.readSync(file.fd, bytes, { offset: 0, length: 65 });
        if (length !== 64) {
          return null;
        }
        const raw = new Uint8Array(bytes, 0, length);
        let token = '';
        for (let i = 0; i < raw.length; i++) {
          token += String.fromCharCode(raw[i]);
        }
        return /^[0-9a-f]{64}$/.test(token) ? token : null;
      } finally {
        fs.closeSync(file);
      }
    } catch (_error) {
      return null;
    }
  }

  private startVpn(argumentsValue: Object, result: MethodResult): void {
    const args = this.readExactArguments(argumentsValue, ['requestId', 'settingsRevision']);
    if (args == null) {
      result.success({ ok: false, error: { code: 'INVALID_REQUEST' } });
      return;
    }
    const requestId = args.get('requestId');
    const settingsRevision = args.get('settingsRevision');
    if (requestId == undefined || settingsRevision == undefined ||
        !this.validRequestId(requestId) || !this.positiveInteger(settingsRevision)) {
      result.success({ ok: false, error: { code: 'INVALID_REQUEST' } });
      return;
    }
    try {
      clearP2wlanVpnStopCommand(this.filesDir);
    } catch (_error) {
      result.success({ ok: false, error: { code: 'VPN_OPERATION_REQUEST_CLEAR_FAILED' } });
      return;
    }
    void requestP2wlanVpnStart({
      version: 1,
      requestId: requestId as string,
      settingsRevision: settingsRevision as number
    }).then((requestResult: VpnAbilityRequestResult) => {
      result.success(requestResult);
    }).catch((_error: Error) => {
      result.success({ ok: false, error: { code: 'VPN_ABILITY_REQUEST_FAILED' } });
    });
  }

  private stopVpn(argumentsValue: Object, result: MethodResult): void {
    const args = this.readExactArguments(argumentsValue, [
      'requestId', 'expectedStatusRequestId', 'settingsRevision', 'afterStatusRevision'
    ]);
    if (args == null) {
      result.success({ ok: false, error: { code: 'INVALID_REQUEST' } });
      return;
    }
    const requestId = args.get('requestId');
    const expectedStatusRequestId = args.get('expectedStatusRequestId');
    const settingsRevision = args.get('settingsRevision');
    const afterStatusRevision = args.get('afterStatusRevision');
    if (requestId == undefined || expectedStatusRequestId == undefined ||
        settingsRevision == undefined || afterStatusRevision == undefined ||
        !this.validRequestId(requestId) || !this.validRequestId(expectedStatusRequestId) ||
        !this.positiveInteger(settingsRevision) || !this.positiveInteger(afterStatusRevision)) {
      result.success({ ok: false, error: { code: 'INVALID_REQUEST' } });
      return;
    }
    try {
      const current = readP2wlanVpnEngineStatusSnapshotIfPresent(this.filesDir);
      if (current == null ||
          current.requestId != expectedStatusRequestId ||
          current.settingsRevision != settingsRevision ||
          current.revision < (afterStatusRevision as number)) {
        result.success({ ok: false, error: { code: 'VPN_ENGINE_STATUS_SNAPSHOT_STALE' } });
        return;
      }
      publishP2wlanVpnStopCommand(
        this.filesDir,
        requestId as string,
        expectedStatusRequestId as string,
        settingsRevision as number,
        afterStatusRevision as number
      );
    } catch (_error) {
      result.success({ ok: false, error: { code: 'VPN_OPERATION_REQUEST_WRITE_FAILED' } });
      return;
    }
    void requestP2wlanVpnStop().then((requestResult: VpnAbilityRequestResult) => {
      if (!requestResult.ok) {
        clearP2wlanVpnStopCommand(this.filesDir);
      } else {
        void waitForAndFinalizeP2wlanVpnEngineStopSnapshot(
            this.filesDir,
            requestId as string,
            settingsRevision as number,
            15000,
            {
              requestId: expectedStatusRequestId as string,
              afterStatusRevision: afterStatusRevision as number
            }
          ).then((snapshot) => {
          hilog.info(0x0000, 'P2WLAN', '[STOP_STAGE] status_finalized revision=%{public}s',
            String(snapshot.revision));
        }).catch((_error: Error) => {
          hilog.info(0x0000, 'P2WLAN', '[STOP_STAGE] status_finalization_not_confirmed');
        });
      }
      result.success(requestResult);
    }).catch((_error: Error) => {
      clearP2wlanVpnStopCommand(this.filesDir);
      result.success({ ok: false, error: { code: 'VPN_ABILITY_REQUEST_FAILED' } });
    });
  }

  private readExactArguments(
    value: Object,
    expected: Array<string>
  ): Map<string, Object> | null {
    if (value == undefined || !(value instanceof Map)) {
      return null;
    }
    const argumentMap = value as Map<string, Object>;
    const actual = Array.from(argumentMap.keys());
    if (actual.length != expected.length ||
        !actual.every((key: string) => expected.indexOf(key) >= 0)) {
      return null;
    }
    return argumentMap;
  }

  private validRequestId(value: Object): boolean {
    return typeof value == 'string' && value.length > 0 && value.length <= 128 &&
      /^[A-Za-z0-9._:-]+$/.test(value as string);
  }

  private positiveInteger(value: Object): boolean {
    return typeof value == 'number' && Number.isInteger(value) &&
      (value as number) > 0 && (value as number) <= 9007199254740991;
  }
}

export default class EntryAbility extends FlutterAbility {
  configureFlutterEngine(flutterEngine: FlutterEngine) {
    super.configureFlutterEngine(flutterEngine)
    GeneratedPluginRegistrant.registerWith(flutterEngine)
    const platformChannel = new MethodChannel(
      flutterEngine.getDartExecutor(),
      'p2wlan/platform',
    )
    platformChannel.setMethodCallHandler(
      new PlatformMethodCallHandler(this.context.filesDir),
    )
  }
}
