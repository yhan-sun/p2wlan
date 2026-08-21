import 'package:flutter_test/flutter_test.dart';
import 'package:p2wlan_flutter_client/core/capabilities/platform_capabilities.dart';

void main() {
  group('PlatformCapabilities.fromPlatform', () {
    test('desktop OS enables local daemon + route + log capabilities', () {
      for (final os in ['windows', 'macos', 'linux']) {
        final c = PlatformCapabilities.fromPlatform(os);
        expect(c.canControlLocalDaemon, isTrue);
        expect(c.canRequestElevation, isTrue);
        expect(c.canVerifyRoutes, isTrue);
        expect(c.canRepairRoutes, isTrue);
        expect(c.canOpenLocalLogs, isTrue);
        expect(c.canCreateSupportBundle, isTrue);
        expect(c.canUseSystemTray, isTrue);
        expect(c.canActAsLocalVpnNode, isTrue);
        expect(c.canManageRemoteDevices, isTrue);
      }
    });

    test('Android enables the native VpnService local node', () {
      final c = PlatformCapabilities.fromPlatform('android');
      expect(c.canControlLocalDaemon, isTrue);
      expect(c.canVerifyRoutes, isTrue);
      expect(c.canRepairRoutes, isFalse);
      expect(c.canOpenLocalLogs, isFalse);
      expect(c.canActAsLocalVpnNode, isTrue);
      expect(c.canManageRemoteDevices, isTrue, reason: 'remote mgmt allowed');
    });

    test('iOS keeps remote management but disables local VPN ops', () {
      final c = PlatformCapabilities.fromPlatform('ios');
      expect(c.canControlLocalDaemon, isFalse);
      expect(c.canVerifyRoutes, isFalse);
      expect(c.canRepairRoutes, isFalse);
      expect(c.canOpenLocalLogs, isFalse);
      expect(c.canActAsLocalVpnNode, isFalse);
      expect(c.canManageRemoteDevices, isTrue, reason: 'remote mgmt allowed');
    });

    test('web is remote-management only', () {
      final c = PlatformCapabilities.fromPlatform('web');
      expect(c.canControlLocalDaemon, isFalse);
      expect(c.canActAsLocalVpnNode, isFalse);
      expect(c.canManageRemoteDevices, isTrue);
    });
  });

  group('PlatformCapabilities.withDaemonCapabilities', () {
    test('daemon can turn a capability off', () {
      final base = PlatformCapabilities.fromPlatform('macos');
      final c = base.withDaemonCapabilities({'canRepairRoutes': false});
      expect(c.canControlLocalDaemon, isTrue);
      expect(c.canRepairRoutes, isFalse);
    });

    test('daemon cannot turn a platform-incompatible one on', () {
      final base = PlatformCapabilities.fromPlatform('ios');
      final c = base.withDaemonCapabilities({'canControlLocalDaemon': true});
      expect(
        c.canControlLocalDaemon,
        isFalse,
        reason: 'mobile baseline is off; daemon cannot override',
      );
    });

    test('absent report is a no-op', () {
      final base = PlatformCapabilities.fromPlatform('windows');
      final c = base.withDaemonCapabilities(null);
      expect(c.canControlLocalDaemon, isTrue);
      expect(c.canActAsLocalVpnNode, isTrue);
    });
  });
}
