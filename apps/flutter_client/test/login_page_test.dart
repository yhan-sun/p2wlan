import 'dart:io';

import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:p2wlan_flutter_client/app/app_strings.dart';
import 'package:p2wlan_flutter_client/app/app_theme.dart';
import 'package:p2wlan_flutter_client/app/app_tokens.dart';
import 'package:p2wlan_flutter_client/core/api/diagnostics_api.dart';
import 'package:p2wlan_flutter_client/core/models/diagnostics_models.dart';
import 'package:p2wlan_flutter_client/core/security/secure_token_repository.dart';
import 'package:p2wlan_flutter_client/core/state/settings_store.dart';
import 'package:p2wlan_flutter_client/core/state/status_store.dart';
import 'package:p2wlan_flutter_client/features/auth/login_page.dart';

void main() {
  testWidgets('Login page uses dark surfaces in dark theme', (tester) async {
    final stores = (await tester.runAsync(_makeStores))!;
    addTearDown(stores.dispose);

    await tester.pumpWidget(
      MaterialApp(
        theme: AppTheme.lightTheme,
        darkTheme: AppTheme.darkTheme,
        themeMode: ThemeMode.dark,
        home: AppStringsScope(
          strings: AppStrings.fromCode(
            stores.settingsStore.settings.languageCode,
          ),
          child: LoginPage(
            settingsStore: stores.settingsStore,
            statusStore: stores.statusStore,
            onAuthenticated: () {},
          ),
        ),
      ),
    );

    final decoratedColors = tester
        .widgetList<DecoratedBox>(find.byType(DecoratedBox))
        .map((box) => box.decoration)
        .whereType<BoxDecoration>()
        .map((decoration) => decoration.color)
        .whereType<Color>();
    final inputDecorations = tester
        .widgetList<InputDecorator>(find.byType(InputDecorator))
        .map((decorator) => decorator.decoration);

    expect(decoratedColors, contains(AppTokens.colorDarkSurface));
    expect(decoratedColors, isNot(contains(AppTokens.colorSurface)));
    expect(inputDecorations, hasLength(3));
    expect(
      inputDecorations.map((decoration) => decoration.fillColor),
      everyElement(AppTokens.colorDarkSurface),
    );
  });
}

Future<_Stores> _makeStores() async {
  final tempDir = await Directory.systemTemp.createTemp('p2wlan_login_test_');
  final settingsStore = SettingsStore(
    settingsFile: File('${tempDir.path}/settings.json'),
    tokenRepository: InMemorySecureTokenRepository(),
  );
  await settingsStore.load();
  final api = _OfflineDiagnosticsApi();
  final statusStore = StatusStore(
    settingsStore: settingsStore,
    diagnosticsApi: api,
  );
  return _Stores(tempDir, settingsStore, statusStore);
}

class _Stores {
  const _Stores(this.tempDir, this.settingsStore, this.statusStore);

  final Directory tempDir;
  final SettingsStore settingsStore;
  final StatusStore statusStore;

  void dispose() {
    statusStore.dispose();
    settingsStore.dispose();
    if (tempDir.existsSync()) {
      tempDir.deleteSync(recursive: true);
    }
  }
}

class _OfflineDiagnosticsApi implements DiagnosticsApi {
  @override
  Future<bool> fetchHealth(String diagnosticsUrl) async => false;

  @override
  Future<DiagnosticsSnapshot> fetchStatus(String diagnosticsUrl) {
    throw const DiagnosticsApiException('offline');
  }

  @override
  Future<bool> requestShutdown(String diagnosticsUrl) async => false;

  @override
  Future<SpeedTestResult> runSpeedTest(
    String diagnosticsUrl, {
    required String peerVirtualIp,
    Duration duration = const Duration(seconds: 10),
  }) {
    throw const DiagnosticsApiException('offline');
  }

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
