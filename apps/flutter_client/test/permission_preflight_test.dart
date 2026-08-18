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
    PermissionPreflightState? state,
    bool elevationSupported = true,
    List<PermissionCheck> checks = const [],
  }) {
    bool? fact(String value) => switch (value) {
      'true' => true,
      'false' => false,
      _ => null,
    };
    final tun = fact(canCreateTun);
    final routes = fact(canModifyRoutes);
    return PermissionPreflight(
      platform: 'test',
      state:
          state ??
          (needsElevation
              ? PermissionPreflightState.elevationRequired
              : tun == true && routes == true
              ? PermissionPreflightState.satisfied
              : tun == null || routes == null
              ? PermissionPreflightState.runtimeVerificationRequired
              : PermissionPreflightState.failed),
      canCreateTun: tun,
      canModifyRoutes: routes,
      elevationSupported: elevationSupported,
      reasonCode: 'test',
      message: '',
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

    test(
      'runtime verification is distinct from satisfied and elevation required',
      () {
        final runtime = preflight(
          canCreateTun: 'unknown',
          state: PermissionPreflightState.runtimeVerificationRequired,
        );
        expect(runtime.needsElevation, isFalse);
        expect(runtime.satisfied, isFalse);
        expect(runtime.warn, isTrue);

        expect(
          preflight(
            state: PermissionPreflightState.elevationRequired,
          ).needsElevation,
          isTrue,
        );
        expect(preflight(state: PermissionPreflightState.failed).bad, isTrue);
        expect(
          preflight(
            state: PermissionPreflightState.unsupported,
            elevationSupported: false,
          ).elevationSupported,
          isFalse,
        );
      },
    );
  });
}
