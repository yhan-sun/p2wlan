// Permission preflight model tests: the `satisfied`/`bad`/`warn` classification
// is pure and deterministic, so it is tested directly. The platform checkers
// read live system state (euid, /dev/net/tun, wintun.dll) and are exercised by
// the diagnostics platform panel and the onboarding flow.
import 'package:flutter_test/flutter_test.dart';
import 'package:p2wlan_flutter_client/core/capabilities/permission_preflight.dart';

void main() {
  PermissionPreflight preflight({
    String canCreateTun = 'true',
    String canModifyRoutes = 'true',
    bool needsElevation = false,
    List<PermissionCheck> checks = const [],
  }) {
    return PermissionPreflight(
      platform: 'test',
      canCreateTun: canCreateTun,
      canModifyRoutes: canModifyRoutes,
      needsElevation: needsElevation,
      recommendedAction: '',
      checks: checks,
    );
  }

  group('PermissionPreflight.satisfied', () {
    test('is true only when TUN + routes are possible without elevation', () {
      expect(preflight().satisfied, isTrue);
      expect(
        preflight(canCreateTun: 'false', canModifyRoutes: 'true').satisfied,
        isFalse,
      );
      expect(
        preflight(canCreateTun: 'true', canModifyRoutes: 'false').satisfied,
        isFalse,
      );
      expect(
        preflight(canCreateTun: 'unknown', canModifyRoutes: 'true').satisfied,
        isFalse,
      );
      expect(preflight(needsElevation: true).satisfied, isFalse);
    });
  });

  group('PermissionPreflight classification', () {
    test('bad is driven by real needsElevation / failed checks', () {
      expect(preflight().bad, isFalse);
      expect(preflight(needsElevation: true).bad, isTrue);
      expect(
        preflight(
          checks: const [
            PermissionCheck(label: 'x', status: 'fail', detail: ''),
          ],
        ).bad,
        isTrue,
      );
      expect(
        preflight(
          checks: const [
            PermissionCheck(label: 'x', status: 'warn', detail: ''),
          ],
        ).bad,
        isFalse,
      );
    });

    test('warn surfaces unknown capabilities and warn checks', () {
      expect(preflight().warn, isFalse);
      expect(preflight(canCreateTun: 'unknown').warn, isTrue);
      expect(preflight(canModifyRoutes: 'unknown').warn, isTrue);
      expect(
        preflight(
          checks: const [
            PermissionCheck(label: 'x', status: 'warn', detail: ''),
          ],
        ).warn,
        isTrue,
      );
    });
  });
}