import 'dart:convert';
import 'dart:io';

import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:p2wlan_flutter_client/app/p2wlan_app.dart';
import 'package:p2wlan_flutter_client/core/security/secure_token_repository.dart';
import 'package:p2wlan_flutter_client/core/state/settings_store.dart';
import 'package:p2wlan_flutter_client/core/update/update_models.dart';
import 'package:p2wlan_flutter_client/core/update/update_service.dart';

void main() {
  testWidgets(
    'automatic update check runs once and does not repeat the banner',
    (tester) async {
      final tempDir = await tester.runAsync(
        () => Directory.systemTemp.createTemp('p2wlan_update_app_test_'),
      );
      final settingsStore = SettingsStore(
        settingsFile: File('${tempDir!.path}/settings.json'),
        tokenRepository: InMemorySecureTokenRepository(),
      );
      await tester.runAsync(() async {
        await settingsStore.load();
        await settingsStore.updateSettings(
          settingsStore.settings.copyWith(
            languageCode: 'en',
            manualMode: true,
            onboardingCompleted: true,
          ),
        );
      });
      addTearDown(() {
        if (tempDir.existsSync()) tempDir.deleteSync(recursive: true);
      });

      final transport = _CountingUpdateTransport(
        UpdateHttpResponse(
          statusCode: 200,
          body: utf8.encode(
            jsonEncode({
              'tag_name': 'v0.1.164',
              'html_url':
                  'https://github.com/yhan-sun/p2wlan/releases/tag/v0.1.164',
            }),
          ),
        ),
      );
      final service = UpdateService(
        currentAppVersion: '0.1.163',
        transport: transport,
      );

      await tester.pumpWidget(
        P2WlanApp(
          initialRefresh: false,
          autoStartPolling: false,
          settingsStore: settingsStore,
          updateService: service,
        ),
      );
      for (var attempt = 0; attempt < 30; attempt += 1) {
        await tester.runAsync(
          () => Future<void>.delayed(const Duration(milliseconds: 30)),
        );
        await tester.pump();
        if (find
            .byKey(const Key('automatic-update-banner'))
            .evaluate()
            .isNotEmpty) {
          break;
        }
      }

      expect(find.byKey(const Key('automatic-update-banner')), findsOneWidget);
      expect(transport.calls, 1);

      await tester.runAsync(() => settingsStore.updateLanguageCode('zh'));
      await tester.pumpAndSettle();

      expect(transport.calls, 1);
      expect(find.text('发现新版本'), findsOneWidget);
      expect(find.byKey(const Key('automatic-update-banner')), findsOneWidget);
    },
  );
}

class _CountingUpdateTransport implements UpdateHttpTransport {
  _CountingUpdateTransport(this.response);

  final UpdateHttpResponse response;
  var calls = 0;

  @override
  Future<UpdateHttpResponse> get(
    Uri uri, {
    required Map<String, String> headers,
    required Duration timeout,
    required int maxResponseBytes,
  }) async {
    calls += 1;
    return response;
  }
}
