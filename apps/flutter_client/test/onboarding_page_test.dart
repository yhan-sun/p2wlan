import 'dart:convert';
import 'dart:io';

import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:p2wlan_flutter_client/app/p2wlan_app.dart';
import 'package:p2wlan_flutter_client/app/app_strings.dart';
import 'package:p2wlan_flutter_client/core/api/diagnostics_api.dart';
import 'package:p2wlan_flutter_client/core/capabilities/platform_capabilities.dart';
import 'package:p2wlan_flutter_client/core/daemon/daemon_controller.dart';
import 'package:p2wlan_flutter_client/core/models/diagnostics_models.dart';
import 'package:p2wlan_flutter_client/core/security/secure_token_repository.dart';
import 'package:p2wlan_flutter_client/core/state/settings_store.dart';
import 'package:p2wlan_flutter_client/core/state/status_store.dart';
import 'package:p2wlan_flutter_client/features/onboarding/onboarding_page.dart';

class _OfflineDiagnosticsApi implements DiagnosticsApi {
  @override
  Future<bool> fetchHealth(String diagnosticsUrl) async => false;

  @override
  Future<DiagnosticsSnapshot> fetchStatus(String diagnosticsUrl) async =>
      throw const DiagnosticsApiException('offline');

  @override
  Future<bool> requestShutdown(String diagnosticsUrl) async => false;

  @override
  Future<SpeedTestResult> runSpeedTest(
    String diagnosticsUrl, {
    required String peerVirtualIp,
    Duration duration = const Duration(seconds: 10),
  }) => throw const DiagnosticsApiException('offline');

  @override
  Future<EventsResponse> fetchEvents(
    String diagnosticsUrl, {
    int since = 0,
    Duration timeout = const Duration(seconds: 30),
  }) => throw const DiagnosticsApiException('offline');

  @override
  Future<PeersPageResponse> fetchPeers(
    String diagnosticsUrl, {
    String? cursor,
    int limit = 100,
  }) => throw const DiagnosticsApiException('offline');

  @override
  Future<String> fetchLogTail(
    String diagnosticsUrl, {
    int lines = 120,
    int maxBytes = 262144,
  }) => throw const DiagnosticsApiException('offline');

  @override
  Future<RoutesResponse> verifyRoutes(String diagnosticsUrl) =>
      throw const DiagnosticsApiException('offline');

  @override
  Future<RouteRepairResponse> repairRoutes(String diagnosticsUrl) =>
      throw const DiagnosticsApiException('offline');

  @override
  void close() {}
}

/// A diagnostics API that reports the daemon as already running.
class _RunningDiagnosticsApi implements DiagnosticsApi {
  @override
  Future<bool> fetchHealth(String diagnosticsUrl) async => true;

  @override
  Future<DiagnosticsSnapshot> fetchStatus(String diagnosticsUrl) async {
    throw const DiagnosticsApiException('no status yet');
  }

  @override
  Future<bool> requestShutdown(String diagnosticsUrl) async => true;

  @override
  Future<SpeedTestResult> runSpeedTest(
    String diagnosticsUrl, {
    required String peerVirtualIp,
    Duration duration = const Duration(seconds: 10),
  }) => throw const DiagnosticsApiException('offline');

  @override
  Future<EventsResponse> fetchEvents(
    String diagnosticsUrl, {
    int since = 0,
    Duration timeout = const Duration(seconds: 30),
  }) => throw const DiagnosticsApiException('offline');

  @override
  Future<PeersPageResponse> fetchPeers(
    String diagnosticsUrl, {
    String? cursor,
    int limit = 100,
  }) => throw const DiagnosticsApiException('offline');

  @override
  Future<String> fetchLogTail(
    String diagnosticsUrl, {
    int lines = 120,
    int maxBytes = 262144,
  }) => throw const DiagnosticsApiException('offline');

  @override
  Future<RoutesResponse> verifyRoutes(String diagnosticsUrl) =>
      throw const DiagnosticsApiException('offline');

  @override
  Future<RouteRepairResponse> repairRoutes(String diagnosticsUrl) =>
      throw const DiagnosticsApiException('offline');

  @override
  void close() {}
}

/// A production-shaped status response with a VIP and one online peer. This
/// drives the real status store and onboarding model to `OnboardingStep.done`.
class _ReadyDiagnosticsApi extends _OfflineDiagnosticsApi {
  @override
  Future<bool> fetchHealth(String diagnosticsUrl) async => true;

  @override
  Future<DiagnosticsSnapshot> fetchStatus(String diagnosticsUrl) async {
    final json =
        jsonDecode(
              await File('../../contracts/fixtures/status.json').readAsString(),
            )
            as Map<String, dynamic>;
    final path = <String, dynamic>{
      'last_success_age_ms': 1,
      'last_failure_age_ms': null,
      'consecutive_failures': 0,
      'last_error': null,
      'last_error_code': null,
      'latency_ms': 8,
      'rtt_ewma_ms': 8,
    };
    json['peers'] = [
      {
        'node_id': 'node-b',
        'device_name': 'peer-b',
        'app_version': '0.1.118',
        'virtual_ip': '10.20.0.8',
        'endpoint': '192.0.2.8:60207',
        'nat_type': 'endpoint_independent',
        'online': true,
        'last_seen': 1,
        'state': 'direct',
        'active_path': 'direct',
        'direct_type': 'direct',
        'is_relay': false,
        'bytes_sent': 0,
        'bytes_received': 0,
        'relay_server': null,
        'warning': null,
        'connected_for_ms': 1000,
        'direct': path,
        'relay': path,
        'current_path_selection': {
          'path': 'direct',
          'reason_code': 'direct_confirmed',
          'reason': 'direct path confirmed',
          'direct_confirmed': true,
          'relay_hedged': false,
        },
      },
    ];
    (json['stats'] as Map<String, dynamic>)['total_peers'] = 1;
    return DiagnosticsSnapshot.fromJson(json);
  }

  @override
  Future<RoutesResponse> verifyRoutes(String diagnosticsUrl) async {
    return const RoutesResponse(
      contractVersion: 1,
      interfaceName: 'p2wlan0',
      mtu: 1420,
      healthy: true,
      conflictCount: 0,
      entries: [],
    );
  }
}

/// A daemon controller whose start/stop always succeed (no real binary needed).
class _FakeDaemonController implements DaemonController {
  @override
  Future<DaemonCommandResult> start(AppSettings settings) async {
    return const DaemonCommandResult(ok: true, message: 'started');
  }

  @override
  Future<DaemonCommandResult> stop(String diagnosticsUrl) async {
    return const DaemonCommandResult(ok: true, message: 'stopped');
  }
}

class _SettingsMemory {
  _SettingsMemory(this.value);

  AppSettings value;
}

/// In-memory SettingsStore used only to make the Widget Test deterministic.
/// The production store and persistence path are covered by security_test.dart.
class _MemorySettingsStore extends SettingsStore {
  _MemorySettingsStore(this._memory)
    : super(tokenRepository: InMemorySecureTokenRepository());

  final _SettingsMemory _memory;

  @override
  AppSettings get settings => _memory.value;

  @override
  Future<void> load() async => notifyListeners();

  @override
  Future<void> markOnboardingCompleted() async {
    if (_memory.value.onboardingCompleted) return;
    _memory.value = _memory.value.copyWith(onboardingCompleted: true);
    notifyListeners();
  }
}

Future<SettingsStore> _makeSettings(WidgetTester tester, bool completed) {
  return tester
      .runAsync<SettingsStore>(() async {
        final tempDir = await Directory.systemTemp.createTemp(
          'p2wlan_onboarding_test_',
        );
        final store = SettingsStore(
          settingsFile: File('${tempDir.path}/settings.json'),
          tokenRepository: InMemorySecureTokenRepository(),
        );
        await store.load();
        await store.updateSettings(
          AppSettings(
            manualMode: true,
            languageCode: 'zh-Hans',
            onboardingCompleted: completed,
          ),
        );
        return store;
      })
      .then((store) => store!);
}

StatusStore _makeStatus(
  SettingsStore settings, {
  DiagnosticsApi? api,
  DaemonController? daemonController,
}) => StatusStore(
  settingsStore: settings,
  diagnosticsApi: api ?? _OfflineDiagnosticsApi(),
  daemonController: daemonController,
);

void main() {
  testWidgets(
    'OnboardingPage shows the permission step from the real preflight when offline',
    (tester) async {
      final settings = await _makeSettings(tester, false);
      final status = _makeStatus(settings);
      await tester.pumpWidget(
        MaterialApp(
          home: AppStringsScope(
            strings: AppStrings.fromCode('zh-Hans'),
            child: OnboardingPage(
              settingsStore: settings,
              statusStore: status,
              capabilities: PlatformCapabilities.fromPlatform('macos'),
            ),
          ),
        ),
      );
      await tester.pump();

      // Permission step visible (daemon offline, preflight not satisfied).
      expect(find.text('授予并继续'), findsOneWidget);
      expect(find.text('授予本机权限'), findsOneWidget);
      // The preflight evidence is rendered, not a hardcoded boolean.
      expect(find.textContaining('需要授权'), findsWidgets);

      status.dispose();
    },
  );

  testWidgets('daemon health alone does not prove TUN and route readiness', (
    tester,
  ) async {
    final settings = await _makeSettings(tester, false);
    final status = _makeStatus(settings, api: _RunningDiagnosticsApi());
    // Establish daemon reachability before the page mounts so the permission
    // step is skipped on real evidence (health probe), not on a hardcoded flag.
    await tester.runAsync(() => status.refresh());
    await tester.pumpWidget(
      MaterialApp(
        home: AppStringsScope(
          strings: AppStrings.fromCode('zh-Hans'),
          child: OnboardingPage(
            settingsStore: settings,
            statusStore: status,
            capabilities: PlatformCapabilities.fromPlatform('macos'),
          ),
        ),
      ),
    );
    await tester.pump();

    // A health response without a healthy status snapshot and route proof is
    // not enough to skip the permission step.
    expect(find.text('授予并继续'), findsOneWidget);
    expect(find.text('等待分配虚拟 IP'), findsNothing);

    status.dispose();
  });

  testWidgets('tapping grant starts the daemon and advances once it is up', (
    tester,
  ) async {
    final settings = await _makeSettings(tester, false);
    final status = _makeStatus(
      settings,
      daemonController: _FakeDaemonController(),
    );
    await tester.pumpWidget(
      MaterialApp(
        home: AppStringsScope(
          strings: AppStrings.fromCode('zh-Hans'),
          child: OnboardingPage(
            settingsStore: settings,
            statusStore: status,
            capabilities: PlatformCapabilities.fromPlatform('macos'),
          ),
        ),
      ),
    );
    await tester.pump();

    expect(find.text('授予并继续'), findsOneWidget);
    await tester.tap(find.text('授予并继续'));
    // The daemon controller succeeds but the offline diagnostics API stays
    // unreachable, so permission cannot be marked granted from a fake launch:
    // the step must NOT advance purely from an optimistic boolean.
    await tester.pumpAndSettle();
    expect(find.text('授予并继续'), findsOneWidget);

    status.dispose();
  });

  testWidgets('P2WlanApp shows onboarding when not yet completed', (
    tester,
  ) async {
    final settings = await _makeSettings(tester, false);
    await tester.pumpWidget(
      P2WlanApp(
        initialRefresh: false,
        autoStartPolling: false,
        settingsStore: settings,
        diagnosticsApi: _OfflineDiagnosticsApi(),
      ),
    );
    // Wait for async bootstrap (real I/O needs runAsync) to reach onboarding.
    for (var i = 0; i < 30; i++) {
      await tester.runAsync(
        () => Future<void>.delayed(const Duration(milliseconds: 30)),
      );
      await tester.pump();
      if (find.text('把这台设备接入 P2WLAN').evaluate().isNotEmpty) break;
    }
    expect(find.text('把这台设备接入 P2WLAN'), findsOneWidget);
    expect(find.text('仪表盘'), findsNothing);
  });

  testWidgets('P2WlanApp shows the shell once onboarding is completed', (
    tester,
  ) async {
    final settings = await _makeSettings(tester, true);
    await tester.pumpWidget(
      P2WlanApp(
        initialRefresh: false,
        autoStartPolling: false,
        settingsStore: settings,
        diagnosticsApi: _OfflineDiagnosticsApi(),
      ),
    );
    // Wait for bootstrap to reach the shell (real I/O needs runAsync).
    for (var i = 0; i < 30; i++) {
      await tester.runAsync(
        () => Future<void>.delayed(const Duration(milliseconds: 30)),
      );
      await tester.pump();
      if (find.text('仪表盘').evaluate().isNotEmpty) break;
    }
    expect(find.text('仪表盘'), findsWidgets);
    expect(find.text('把这台设备接入 P2WLAN'), findsNothing);
  });

  testWidgets(
    'done completes onboarding once and persists across app restart',
    (tester) async {
      final memory = _SettingsMemory(
        const AppSettings(manualMode: true, languageCode: 'zh-Hans'),
      );
      final settings = _MemorySettingsStore(memory);
      final status = _makeStatus(settings, api: _ReadyDiagnosticsApi());
      var completions = 0;

      await tester.runAsync(() => status.refresh());
      await tester.pumpWidget(
        MaterialApp(
          home: AppStringsScope(
            strings: AppStrings.fromCode('zh-Hans'),
            child: OnboardingPage(
              settingsStore: settings,
              statusStore: status,
              capabilities: PlatformCapabilities.fromPlatform('macos'),
              onCompleted: () => completions++,
            ),
          ),
        ),
      );
      await tester.pump();

      expect(find.text('准备就绪'), findsOneWidget);
      expect(find.text('完成'), findsOneWidget);

      // Dispatch two taps before the first completion operation settles.
      await tester.tap(find.text('完成'));
      await tester.tap(find.text('完成'));
      await tester.pump();

      expect(settings.settings.onboardingCompleted, isTrue);
      expect(completions, 1);

      // The actual app entry point uses the persisted setting, not a transient
      // page-local flag, to select AppShell after a restart.
      final restartedSettings = _MemorySettingsStore(memory);
      await tester.pumpWidget(
        P2WlanApp(
          initialRefresh: false,
          autoStartPolling: false,
          settingsStore: restartedSettings,
          diagnosticsApi: _OfflineDiagnosticsApi(),
        ),
      );
      for (var i = 0; i < 30; i++) {
        await tester.runAsync(
          () => Future<void>.delayed(const Duration(milliseconds: 30)),
        );
        await tester.pump();
        if (find.text('仪表盘').evaluate().isNotEmpty) break;
      }
      expect(find.text('仪表盘'), findsWidgets);
      expect(find.text('把这台设备接入 P2WLAN'), findsNothing);

      status.dispose();
    },
  );
}
