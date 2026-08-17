import 'dart:io';

import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:p2wlan_flutter_client/app/p2wlan_app.dart';
import 'package:p2wlan_flutter_client/app/app_strings.dart';
import 'package:p2wlan_flutter_client/core/api/diagnostics_api.dart';
import 'package:p2wlan_flutter_client/core/capabilities/platform_capabilities.dart';
import 'package:p2wlan_flutter_client/core/models/diagnostics_models.dart';
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
  Future<({int revision, List<Map<String, dynamic>> events})> fetchEvents(
    String diagnosticsUrl, {
    int since = 0,
    Duration timeout = const Duration(seconds: 30),
  }) => throw const DiagnosticsApiException('offline');

  @override
  Future<({List<Map<String, dynamic>> peers, int total, String? nextCursor})>
  fetchPeers(String diagnosticsUrl, {String? cursor, int limit = 100}) =>
      throw const DiagnosticsApiException('offline');

  @override
  Future<String> fetchLogTail(
    String diagnosticsUrl, {
    int lines = 120,
    int maxBytes = 262144,
  }) => throw const DiagnosticsApiException('offline');

  @override
  Future<Map<String, dynamic>> verifyRoutes(String diagnosticsUrl) =>
      throw const DiagnosticsApiException('offline');

  @override
  Future<Map<String, dynamic>> repairRoutes(String diagnosticsUrl) =>
      throw const DiagnosticsApiException('offline');

  @override
  void close() {}
}

Future<SettingsStore> _makeSettings(WidgetTester tester, bool completed) {
  return tester
      .runAsync<SettingsStore>(() async {
        final tempDir = await Directory.systemTemp.createTemp(
          'p2wlan_onboarding_test_',
        );
        final store = SettingsStore(
          settingsFile: File('${tempDir.path}/settings.json'),
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

StatusStore _makeStatus(SettingsStore settings) => StatusStore(
  settingsStore: settings,
  diagnosticsApi: _OfflineDiagnosticsApi(),
);

void main() {
  testWidgets('OnboardingPage shows the permission step first, then advances', (
    tester,
  ) async {
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

    // Permission step visible (manual mode, permission not yet granted).
    expect(find.text('授予并继续'), findsOneWidget);
    expect(find.text('授予本机权限'), findsOneWidget);

    // Advance to the daemon step.
    await tester.tap(find.text('授予并继续'));
    await tester.pump();
    expect(find.text('启动 P2WLAN'), findsOneWidget);
    expect(find.text('启动本地守护进程'), findsOneWidget);

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
}
