import 'dart:async';
import 'dart:convert';
import 'dart:io';

import 'package:flutter_test/flutter_test.dart';
import 'package:p2wlan_flutter_client/core/models/diagnostics_models.dart';
import 'package:p2wlan_flutter_client/core/security/secure_token_repository.dart';
import 'package:p2wlan_flutter_client/core/state/settings_store.dart';

void main() {
  late Directory directory;
  late File file;
  late _Tokens tokens;
  late SettingsStore store;
  setUp(() async {
    directory = await Directory.systemTemp.createTemp('settings-mutation-');
    file = File('${directory.path}/settings.json');
    tokens = _Tokens();
    store = SettingsStore(settingsFile: file, tokenRepository: tokens);
    await store.load();
    await store.updateSettings(
      const AppSettings(
        controlServer: 'https://control.example.com',
        authToken: 'account-a',
        deviceName: 'Demo device',
        languageCode: 'en',
        diagnosticsUrl: 'http://127.0.0.1:39278/status',
      ),
    );
  });
  tearDown(() {
    store.dispose();
    directory.deleteSync(recursive: true);
  });

  final mutations = <String, Future<void> Function(SettingsStore)>{
    'language': (store) => store.updateLanguageCode('zh-Hans'),
    'theme': (store) => store.updateThemeMode('dark'),
    'diagnostics': (store) =>
        store.updateDiagnosticsUrl('http://127.0.0.1:39279/status'),
    'reset diagnostics': (store) => store.resetDiagnosticsUrl(),
    'onboarding': (store) => store.markOnboardingCompleted(),
  };
  for (final mutation in mutations.entries) {
    test(
      'failed ${mutation.key} mutation keeps the committed value and disk',
      () async {
        final original = store.settings.toJson();
        final originalFile = await file.readAsString();
        var notifications = 0;
        store.addListener(() => notifications++);
        tokens.failNextWrite = true;
        await expectLater(
          mutation.value(store),
          throwsA(isA<SecureTokenStorageException>()),
        );
        expect(store.settings.toJson(), original);
        expect(await file.readAsString(), originalFile);
        expect(notifications, 0);
        await mutation.value(store);
        expect(store.settings.toJson(), isNot(original));
        expect(notifications, 1);
      },
    );
  }

  test(
    'queued local preferences merge the latest committed connection',
    () async {
      tokens.entered = Completer<void>();
      tokens.release = Completer<void>();
      final connection = store.updateSettings(
        store.settings.copyWith(mtu: 1300),
      );
      await tokens.entered!.future;
      var notifications = 0;
      store.addListener(() => notifications++);
      final theme = store.updateThemeMode('dark');
      final language = store.updateLanguageCode('zh-Hans');
      final diagnostics = store.updateDiagnosticsUrl(
        'http://127.0.0.1:39279/status',
      );
      final profile = store.updateAccountIdentity(email: 'demo@example.com');
      expect(store.settings.mtu, defaultMtu);
      expect(store.settings.themeMode, 'system');
      expect(notifications, 0);
      tokens.release!.complete();
      await Future.wait([connection, theme, language, diagnostics, profile]);
      final saved =
          jsonDecode(await file.readAsString()) as Map<String, dynamic>;
      expect(store.settings.mtu, 1300);
      expect(saved['mtu'], 1300);
      expect(saved['themeMode'], 'dark');
      expect(saved['languageCode'], 'zh-Hans');
      expect(saved['diagnosticsUrl'], 'http://127.0.0.1:39279/status');
      expect(saved['accountEmail'], 'demo@example.com');
      expect(store.settings.authToken, 'account-a');
      expect(await tokens.read(), 'account-a');
      expect(notifications, 5);
    },
  );

  test(
    'queued global preferences do not restore the preceding account',
    () async {
      final entered = Completer<void>();
      final release = Completer<void>();
      store.applySessionChange = (current, next, commit) async {
        entered.complete();
        await release.future;
        await commit();
      };
      final switching = store.updateSettings(
        store.settings.copyWith(
          authToken: 'account-b',
          deviceName: 'New device',
        ),
      );
      await entered.future;
      final language = store.updateLanguageCode('zh-Hans');
      final theme = store.updateThemeMode('dark');
      final staleProfile = expectLater(
        store.updateAccountIdentity(email: 'old-account@example.com'),
        throwsA(isA<FormatException>()),
      );
      release.complete();
      await Future.wait([switching, language, theme, staleProfile]);
      expect(store.settings.authToken, 'account-b');
      expect(store.settings.deviceName, 'New device');
      expect(store.settings.accountEmail, isNot('old-account@example.com'));
      expect(store.settings.languageCode, 'zh-Hans');
      expect(store.settings.themeMode, 'dark');
      expect(await tokens.read(), 'account-b');
    },
  );

  for (final failOuter in [false, true]) {
    test(
      'machine credential reentry survives an outer ${failOuter ? 'failure' : 'commit'}',
      () async {
        store.applySessionChange = (current, next, commit) async {
          await store.updateMacosAdminPassword('demo-machine-password');
          tokens.failNextWrite = failOuter;
          await commit();
        };
        final switching = store.updateSettings(
          store.settings.copyWith(authToken: 'account-b'),
        );
        if (failOuter) {
          await expectLater(
            switching,
            throwsA(isA<SecureTokenStorageException>()),
          );
          expect(store.settings.authToken, 'account-a');
        } else {
          await switching;
          expect(store.settings.authToken, 'account-b');
        }
        expect(store.settings.macosAdminPassword, 'demo-machine-password');
        expect(store.settings.macosAdminPasswordCiphertext, isNotEmpty);
        await store.updateThemeMode('dark');
        final restored = SettingsStore(
          settingsFile: file,
          tokenRepository: tokens,
        );
        addTearDown(restored.dispose);
        await restored.load();
        expect(restored.settings.macosAdminPassword, 'demo-machine-password');
        expect(
          restored.settings.authToken,
          failOuter ? 'account-a' : 'account-b',
        );
        expect(
          await file.readAsString(),
          isNot(contains('demo-machine-password')),
        );
      },
    );
  }

  test(
    'a nested machine credential clear is not restored by account commit',
    () async {
      await store.updateMacosAdminPassword('old-machine-password');
      store.applySessionChange = (current, next, commit) async {
        await store.clearMacosAdminPassword();
        await commit();
      };
      await store.updateSettings(
        store.settings.copyWith(authToken: 'account-b'),
      );
      await store.updateLanguageCode('zh-Hans');
      expect(store.settings.macosAdminPassword, isEmpty);
      expect(store.settings.macosAdminPasswordCiphertext, isEmpty);
      final saved =
          jsonDecode(await file.readAsString()) as Map<String, dynamic>;
      expect(saved['macosAdminPasswordCiphertext'], isEmpty);
      expect(store.settings.authToken, 'account-b');
    },
  );
  for (final recovery in [(false, false), (true, false), (true, true)]) {
    final (failRestore, failClear) = recovery;
    test(
      'JSON commit failure ${failClear
          ? 'reports failed restore and clear'
          : failRestore
          ? 'clears an unrestorable credential'
          : 'restores the committed credential'}',
      () async {
        final original = store.settings;
        final backup = File('${file.path}.committed');
        await file.rename(backup.path);
        final blocker = Directory(file.path);
        await blocker.create();
        await File('${blocker.path}/block-rename').writeAsString('fixture');
        tokens.writes.clear();
        if (failRestore) tokens.failRestoreTo = original.authToken;
        tokens.failClear = failClear;
        try {
          await expectLater(
            store.updateSettings(
              original.copyWith(
                controlServer: 'https://other.example.com',
                authToken: 'account-b',
              ),
            ),
            throwsA(
              failRestore
                  ? isA<SettingsCredentialRestoreException>()
                  : isA<FileSystemException>(),
            ),
          );
          expect(store.settings, same(original));
          expect(tokens.writes, ['account-b', 'account-a']);
          expect(
            await tokens.read(),
            failClear
                ? 'account-b'
                : failRestore
                ? isNull
                : 'account-a',
          );
          if (failRestore) {
            expect(
              store.lastError,
              contains(
                failClear
                    ? 'credential recovery failed'
                    : 'previous credential could not be restored',
              ),
            );
            expect(store.lastError, isNot(contains('account-b')));
          }
        } finally {
          await blocker.delete(recursive: true);
          await backup.rename(file.path);
        }
        tokens.failRestoreTo = null;
        tokens.failClear = false;
        // A later successful save repairs storage from the still-committed
        // account, and a restart cannot pair its server with the failed token.
        await store.updateThemeMode('dark');
        final restored = SettingsStore(
          settingsFile: file,
          tokenRepository: tokens,
        );
        addTearDown(restored.dispose);
        await restored.load();
        expect(restored.settings.controlServer, original.controlServer);
        expect(restored.settings.authToken, original.authToken);
      },
    );
  }
}

class _Tokens extends InMemorySecureTokenRepository {
  bool failNextWrite = false;
  String? failRestoreTo;
  bool failClear = false;
  final writes = <String>[];
  Completer<void>? entered;
  Completer<void>? release;
  @override
  Future<void> write(String token) async {
    writes.add(token);
    final gate = release;
    if (gate != null) {
      if (entered?.isCompleted == false) entered!.complete();
      await gate.future;
      release = null;
    }
    if (failNextWrite || token == failRestoreTo) {
      failNextWrite = false;
      throw const SecureTokenStorageException('mock storage unavailable');
    }
    await super.write(token);
  }

  @override
  Future<void> clear() async {
    if (failClear) {
      throw const SecureTokenStorageException('mock clear unavailable');
    }
    await super.clear();
  }
}
