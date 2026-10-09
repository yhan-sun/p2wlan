import 'dart:convert';
import 'dart:io';

import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:p2wlan_flutter_client/app/p2wlan_app.dart';
import 'package:p2wlan_flutter_client/core/api/diagnostics_api.dart';
import 'package:p2wlan_flutter_client/core/daemon/daemon_controller.dart';
import 'package:p2wlan_flutter_client/core/models/diagnostics_models.dart';
import 'package:p2wlan_flutter_client/core/security/secure_token_repository.dart';
import 'package:p2wlan_flutter_client/core/state/settings_store.dart';

void main() {
  final expiredToken =
      'header.${base64Url.encode(utf8.encode('{"exp":1}'))}.signature';
  final cases = <String, AppSettings>{
    'missing server even with a credential': const AppSettings(
      authToken: 'saved-token',
    ),
    'whitespace server': const AppSettings(
      controlServer: '  ',
      authToken: 'saved-token',
    ),
    'missing login': const AppSettings(
      controlServer: 'https://control.example.com',
    ),
    'expired login': AppSettings(
      controlServer: 'https://control.example.com',
      authToken: expiredToken,
    ),
    'legacy offline flags': AppSettings.fromJson({
      'manualMode': true,
      'personalManualMode': true,
      'onboardingCompleted': true,
    }),
  };
  for (final entry in cases.entries) {
    test(
      'startup rejects ${entry.key} before platform or diagnostics work',
      () async {
        final api = _NoNetworkApi();
        final platform = _NoPlatformTransport();
        final controller = DaemonController(
          diagnosticsApi: api,
          androidVpnTransport: platform,
        );
        final result = await controller.start(entry.value);
        expect(result.ok, isFalse);
        expect(
          result.failureCode,
          DaemonStartupFailureCode.startupConfigInvalid,
        );
        expect(result.message, entry.value.connectionRequirementError);
        expect(result.manualCommand, isNull);
        expect(entry.value.hasAuthenticatedConnection, isFalse);
        expect(api.requests, 0);
        expect(platform.requests, 0);
      },
    );
  }

  test('configured login accepts automatically supplied relay settings', () {
    const settings = AppSettings(
      controlServer: 'https://control.example.com',
      authToken: 'saved-token',
    );
    expect(settings.relayServers, isEmpty);
    expect(settings.connectionRequirementError, isNull);
    expect(settings.hasAuthenticatedConnection, isTrue);
  });

  testWidgets(
    'legacy offline configuration returns to server login on app restart',
    (tester) async {
      final directory = (await tester.runAsync(
        () => Directory.systemTemp.createTemp('p2wlan-legacy-login-'),
      ))!;
      addTearDown(() => directory.deleteSync(recursive: true));
      final file = File('${directory.path}/settings.json');
      await tester.runAsync(
        () => file.writeAsString(
          jsonEncode({
            'languageCode': 'en',
            'manualMode': true,
            'personalManualMode': true,
            'onboardingCompleted': true,
            'controlServer': '',
            'deviceName': 'legacy-client',
          }),
        ),
      );
      final settings = _LoadedSettingsStore(
        settingsFile: file,
        tokenRepository: InMemorySecureTokenRepository(),
      );
      // Run the real disk migration outside the widget test's fake event loop.
      await tester.runAsync(settings.load);
      await tester.pumpWidget(
        P2WlanApp(
          settingsStore: settings,
          diagnosticsApi: _NoNetworkApi(),
          autoStartPolling: false,
          initialRefresh: false,
          autoCheckForUpdates: false,
          connectAfterLoginStartup: true,
        ),
      );
      await tester.pumpAndSettle();
      expect(settings.lastError, isNull);
      expect(find.text('Server address (required)'), findsOneWidget);
      expect(
        find.textContaining('Enter a server address and sign in'),
        findsOneWidget,
      );
      expect(find.text('Continue in manual / offline mode'), findsNothing);
      expect(settings.loaded, isTrue);
      expect(settings.settings.hasAuthenticatedConnection, isFalse);
      final persisted =
          jsonDecode((await tester.runAsync(file.readAsString))!) as Map;
      expect(persisted, isNot(contains('manualMode')));
      expect(persisted, isNot(contains('personalManualMode')));
      expect(tester.takeException(), isNull);
      await tester.pumpWidget(const SizedBox.shrink());
    },
  );
}

class _LoadedSettingsStore extends SettingsStore {
  _LoadedSettingsStore({super.settingsFile, super.tokenRepository});

  @override
  Future<void> load() async {
    if (!loaded) await super.load();
  }
}

class _NoNetworkApi implements DiagnosticsApi {
  var requests = 0;

  @override
  void cancelSpeedTest() {}

  @override
  void close() {}

  @override
  DiagnosticsApiException? healthFailureFor(String diagnosticsUrl) => null;

  @override
  dynamic noSuchMethod(Invocation invocation) {
    requests++;
    throw StateError(
      'Unexpected diagnostics request: ${invocation.memberName}',
    );
  }
}

class _NoPlatformTransport implements AndroidVpnTransport {
  var requests = 0;

  @override
  dynamic noSuchMethod(Invocation invocation) {
    requests++;
    throw StateError('Unexpected platform request: ${invocation.memberName}');
  }
}
