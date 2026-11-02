import {
  parseP2wlanVpnEngineStatusSnapshot,
  P2wlanVpnEngineStatusSnapshotError
} from '../../../main/ets/vpn/vpn_engine_status_snapshot';
import { describe, it, expect } from '@ohos/hypium';

function validStatus(): Object {
  return {
    schemaVersion: 2,
    revision: 3,
    updatedAtEpochMs: 1791000000000,
    requestId: 'request-a',
    operation: 'start',
    settingsRevision: 7,
    identity: {
      instanceId: 'vpn-instance-a',
      generation: 2
    },
    status: 'ready'
  };
}

function assertStatusFailure(source: string): void {
  let code = '';
  try {
    parseP2wlanVpnEngineStatusSnapshot(source);
  } catch (error) {
    const snapshotError = error as P2wlanVpnEngineStatusSnapshotError;
    code = snapshotError.code;
  }
  expect(code).assertEqual('VPN_ENGINE_STATUS_SNAPSHOT_INVALID');
}

export default function vpnEngineStatusSnapshotTest() {
  describe('VpnEngineStatusSnapshot', () => {
    it('accepts the versioned ready status and identity', 0, () => {
      const snapshot = parseP2wlanVpnEngineStatusSnapshot(
        JSON.stringify(validStatus())
      );
      expect(snapshot.revision).assertEqual(3);
      expect(snapshot.requestId).assertEqual('request-a');
      expect(snapshot.identity?.instanceId).assertEqual('vpn-instance-a');
      expect(snapshot.status).assertEqual('ready');
    });

    it('accepts a starting status before the VPN identity exists', 0, () => {
      const source = JSON.stringify({
        schemaVersion: 2,
        revision: 1,
        updatedAtEpochMs: 1791000000000,
        requestId: 'request-starting',
        operation: 'start',
        settingsRevision: 1,
        identity: null,
        status: 'starting'
      });
      const snapshot = parseP2wlanVpnEngineStatusSnapshot(source);
      expect(snapshot.identity == null).assertTrue();
      expect(snapshot.status).assertEqual('starting');
    });

    it('accepts an optional stable code', 0, () => {
      const source = JSON.stringify(validStatus()).replace(
        '"status":"ready"}',
        '"status":"ready","code":"VPN_START_FAILED"}'
      );
      const snapshot = parseP2wlanVpnEngineStatusSnapshot(source);
      expect(snapshot.code).assertEqual('VPN_START_FAILED');
    });

    it('rejects unknown fields and status values', 0, () => {
      assertStatusFailure(
        JSON.stringify(validStatus()).replace(
          '"status":"ready"}',
          '"status":"ready","fd":10}'
        )
      );
      assertStatusFailure(
        JSON.stringify(validStatus()).replace(
          '"status":"ready"',
          '"status":"connected"'
        )
      );
    });

    it('rejects invalid revision and generation values', 0, () => {
      assertStatusFailure(
        JSON.stringify(validStatus()).replace('"revision":3', '"revision":0')
      );
      assertStatusFailure(
        JSON.stringify(validStatus()).replace(
          '"requestId":"request-a"',
          '"requestId":"invalid request"'
        )
      );
      assertStatusFailure(
        JSON.stringify(validStatus()).replace('"generation":2', '"generation":0')
      );
    });
  });
}
