import {
  parseP2wlanVpnEngineSettingsSnapshot,
  P2wlanVpnSettingsSnapshotError
} from '../../../main/ets/vpn/vpn_settings_snapshot';
import { describe, it, expect } from '@ohos/hypium';

function validSnapshot(): Object {
  return {
    schemaVersion: 1,
    revision: 7,
    settings: {
      controlServer: 'https://control.example.test',
      authToken: 'test-token',
      networkId: 'network-a',
      manualMode: false,
      virtualIp: '10.20.1.8',
      deviceName: 'Harmony device',
      overlayCidr: '10.20.0.0/16',
      tunInterface: 'p2wlan0',
      mtu: 1420,
      udpBind: '0.0.0.0:0',
      udpAdvertise: '',
      socketPool: '3',
      relayServers: ['relay.example.test:443']
    }
  };
}

function validSnapshotText(): string {
  return JSON.stringify(validSnapshot());
}

function assertSnapshotFailure(source: string, expectedCode: string): void {
  let code = '';
  try {
    parseP2wlanVpnEngineSettingsSnapshot(source);
  } catch (error) {
    const snapshotError = error as P2wlanVpnSettingsSnapshotError;
    code = snapshotError.code;
  }
  expect(code).assertEqual(expectedCode);
}

export default function vpnSettingsSnapshotTest() {
  describe('VpnEngineSettingsSnapshot', () => {
    it('accepts complete current schema and socket pool setting', 0, () => {
      const snapshot = parseP2wlanVpnEngineSettingsSnapshot(
        JSON.stringify(validSnapshot())
      );
      expect(snapshot.revision).assertEqual(7);
      expect(snapshot.settings.socketPool).assertEqual('3');
      expect(snapshot.settings.relayServers.length).assertEqual(1);
    });

    it('accepts an empty virtual IP in an otherwise valid settings snapshot', 0, () => {
      const source = validSnapshotText().replace(
        '"virtualIp":"10.20.1.8"',
        '"virtualIp":""'
      );
      const snapshot = parseP2wlanVpnEngineSettingsSnapshot(source);
      expect(snapshot.settings.virtualIp).assertEqual('');
    });

    it('rejects unknown settings fields', 0, () => {
      assertSnapshotFailure(
        validSnapshotText().replace(
          '"socketPool":"3"',
          '"socketPool":"3","extra":"must-not-be-ignored"'
        ),
        'VPN_ENGINE_SETTINGS_SNAPSHOT_INVALID'
      );
    });

    it('rejects empty managed credentials', 0, () => {
      assertSnapshotFailure(
        validSnapshotText().replace('"authToken":"test-token"', '"authToken":""'),
        'VPN_ENGINE_SETTINGS_TOKEN_MISSING'
      );
    });

    it('rejects an invalid revision', 0, () => {
      assertSnapshotFailure(
        validSnapshotText().replace('"revision":7', '"revision":0'),
        'VPN_ENGINE_SETTINGS_SNAPSHOT_INVALID'
      );
    });
  });
}
