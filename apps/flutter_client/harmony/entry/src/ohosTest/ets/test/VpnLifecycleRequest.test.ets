import { describe, it, expect } from '@ohos/hypium';
import { Want } from '@kit.AbilityKit';
import {
  buildP2wlanVpnStopWant,
  buildP2wlanVpnWant,
  createVpnConfig,
  getConfiguredRouteSnapshot,
  parseP2wlanVpnStartCommand,
  P2WLAN_VPN_REQUEST_PARAMETER,
  P2wlanVpnNetworkV1,
  P2wlanVpnRequestError
} from '../../../main/ets/vpn/vpn_request';
import { P2wlanVpnEngineSettingsV1 } from '../../../main/ets/vpn/vpn_settings_snapshot';

function validSettings(): P2wlanVpnEngineSettingsV1 {
  return {
    controlServer: 'https://control.example.test',
    authToken: 'private-test-token',
    networkId: 'network-a',
    manualMode: false,
    virtualIp: '',
    deviceName: 'Harmony device',
    overlayCidr: '10.20.0.0/16',
    tunInterface: 'p2wlan0',
    mtu: 1420,
    udpBind: '0.0.0.0:0',
    udpAdvertise: '',
    socketPool: '3',
    relayServers: []
  };
}

function assertNetworkFailure(network: P2wlanVpnNetworkV1): void {
  let code = '';
  try {
    createVpnConfig(validSettings(), network);
  } catch (error) {
    code = (error as P2wlanVpnRequestError).code;
  }
  expect(code).assertEqual('VPN_NETWORK_INVALID');
}

export default function vpnLifecycleRequestTest() {
  describe('VpnLifecycleRequest', () => {
    it('passes only the correlated request and settings revision in Want', 0, () => {
      const want = buildP2wlanVpnWant({
        version: 1,
        requestId: 'start-request-a',
        settingsRevision: 8
      });
      const parameters = want.parameters as Record<string, Object>;
      const encoded = parameters[P2WLAN_VPN_REQUEST_PARAMETER] as string;
      const command = parseP2wlanVpnStartCommand(want);
      expect(command.requestId).assertEqual('start-request-a');
      expect(command.settingsRevision).assertEqual(8);
      expect(encoded.indexOf('private-test-token')).assertEqual(-1);
      expect(Object.keys(JSON.parse(encoded)).length).assertEqual(3);
    });

    it('builds the stop Want as a plain object with only target fields', 0, () => {
      const want = buildP2wlanVpnStopWant();
      expect(want instanceof Want).assertFalse();
      expect(want.deviceId).assertEqual('');
      expect(want.bundleName).assertEqual('com.p2wlan.client');
      expect(want.abilityName).assertEqual('P2wlanVpnExtensionAbility');
      expect(Object.keys(want).length).assertEqual(3);
    });

    it('builds the OS route from the server-assigned address and CIDR', 0, () => {
      const config = createVpnConfig(validSettings(), {
        virtualIp: '10.44.12.7',
        cidr: '10.44.12.0/24'
      });
      expect(config.addresses.length).assertEqual(1);
      expect(config.addresses[0].address.address).assertEqual('10.44.12.7');
      expect(config.addresses[0].prefixLength).assertEqual(24);
      expect(getConfiguredRouteSnapshot(config)[0]).assertEqual('10.44.12.0/24');
      expect(config.dnsAddresses.length).assertEqual(0);
      expect(config.routes[0].isDefaultRoute).assertFalse();
    });

    it('rejects non-canonical or mismatched server assignments', 0, () => {
      assertNetworkFailure({ virtualIp: '10.44.12.7', cidr: '10.44.12.8/24' });
      assertNetworkFailure({ virtualIp: '10.44.12.7', cidr: '10.44.12.0/024' });
      assertNetworkFailure({ virtualIp: '010.44.12.7', cidr: '10.44.12.0/24' });
    });
  });
}
