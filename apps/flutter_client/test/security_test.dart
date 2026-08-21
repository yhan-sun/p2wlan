import 'dart:convert';
import 'dart:io';

import 'package:flutter_test/flutter_test.dart';
import 'package:p2wlan_flutter_client/core/security/redactor.dart';
import 'package:p2wlan_flutter_client/core/security/secure_token_repository.dart';
import 'package:p2wlan_flutter_client/core/state/settings_store.dart';

void main() {
  group('LocalTokenRepository', () {
    test('round-trips and clears a local token file', () async {
      final tmp = await Directory.systemTemp.createTemp('p2wlan_local_token_');
      addTearDown(() async => tmp.delete(recursive: true));
      final file = File('${tmp.path}/nested/p2wlan-auth-token');
      final repo = LocalTokenRepository(file: file);

      expect(await repo.read(), isNull);
      await repo.write(' local-token ');
      expect(await repo.read(), 'local-token');
      expect(await file.readAsString(), 'local-token');

      await repo.clear();
      expect(await repo.read(), isNull);
    });
  });

  group('InMemorySecureTokenRepository', () {
    test('round-trips and clears', () async {
      final repo = InMemorySecureTokenRepository();
      expect(await repo.read(), isNull);
      await repo.write('tok');
      expect(await repo.read(), 'tok');
      await repo.clear();
      expect(await repo.read(), isNull);
    });
  });

  test('secure-store migration supports every legacy token spelling', () async {
    for (final key in const ['authToken', 'auth_token', 'token']) {
      final tmp = await Directory.systemTemp.createTemp('p2wlan_migrate_');
      addTearDown(() async => tmp.delete(recursive: true));
      final settingsFile = File('${tmp.path}/settings.json');
      await settingsFile.writeAsString('{"$key":"legacy-$key"}');
      final secure = InMemorySecureTokenRepository();
      final store = SettingsStore(
        settingsFile: settingsFile,
        tokenRepository: secure,
      );

      await store.load();

      expect(await secure.read(), 'legacy-$key');
      expect(store.settings.authToken, 'legacy-$key');
      final persisted = await settingsFile.readAsString();
      expect(persisted.contains('legacy-$key'), isFalse);
    }
  });

  test(
    'local token file write failure preserves the legacy settings value',
    () async {
      final tmp = await Directory.systemTemp.createTemp('p2wlan_migrate_fail_');
      addTearDown(() async => tmp.delete(recursive: true));
      final settingsFile = File('${tmp.path}/settings.json');
      await settingsFile.writeAsString('{"authToken":"legacy-token"}');
      final store = SettingsStore(
        settingsFile: settingsFile,
        tokenRepository: _FailingSecureTokenRepository(),
      );

      await store.load();

      expect(await settingsFile.readAsString(), contains('legacy-token'));
      expect(store.lastError, contains('local token file'));
    },
  );

  test(
    'an existing secure token wins and repeated migration is harmless',
    () async {
      final tmp = await Directory.systemTemp.createTemp(
        'p2wlan_migrate_repeat_',
      );
      addTearDown(() async => tmp.delete(recursive: true));
      final settingsFile = File('${tmp.path}/settings.json');
      await settingsFile.writeAsString('{"authToken":"legacy-token"}');
      final secure = InMemorySecureTokenRepository();
      await secure.write('secure-token');
      final store = SettingsStore(
        settingsFile: settingsFile,
        tokenRepository: secure,
      );

      await store.load();

      expect(await secure.read(), 'secure-token');
      expect(store.settings.authToken, 'secure-token');
      expect(
        await settingsFile.readAsString(),
        isNot(contains('legacy-token')),
      );
    },
  );

  group('SettingsStore token handling', () {
    test('onboarding completion rolls back when persistence fails', () async {
      final tmp = await Directory.systemTemp.createTemp(
        'p2wlan_onboarding_rollback_',
      );
      addTearDown(() async => tmp.delete(recursive: true));
      final store = SettingsStore(
        settingsFile: File('${tmp.path}/settings.json'),
        tokenRepository: _FailingSecureTokenRepository(),
      );
      await store.load();

      await expectLater(
        store.markOnboardingCompleted(),
        throwsA(isA<Exception>()),
      );
      expect(store.settings.onboardingCompleted, isFalse);
    });

    test(
      'token is never persisted to the settings JSON; local token file holds it',
      () async {
        final tmp = await Directory.systemTemp.createTemp('p2wlan_ss_');
        addTearDown(() async => tmp.delete(recursive: true));
        final settingsFile = File('${tmp.path}/settings.json');
        final secure = InMemorySecureTokenRepository();
        final store = SettingsStore(
          settingsFile: settingsFile,
          tokenRepository: secure,
        );
        await store.load();
        await store.updateSettings(
          store.settings.copyWith(authToken: 'managed-token'),
        );
        // JSON on disk must NOT contain the token.
        final raw = await settingsFile.readAsString();
        expect(
          raw.contains('managed-token'),
          isFalse,
          reason: 'auth token must not be written to settings JSON',
        );
        final persisted =
            (jsonDecode(raw) as Map<String, dynamic>)['authToken'];
        expect(
          persisted,
          '',
          reason: 'token field is blanked in persisted JSON',
        );
        // Secure store holds the effective value.
        expect(await secure.read(), 'managed-token');
        // In-memory settings still expose the token for the daemon launch.
        expect(store.settings.authToken, 'managed-token');
      },
    );

    test(
      'legacy in-JSON token migrates to the local token file on load',
      () async {
        final tmp = await Directory.systemTemp.createTemp('p2wlan_ss_');
        addTearDown(() async => tmp.delete(recursive: true));
        final settingsFile = File('${tmp.path}/settings.json');
        await settingsFile.writeAsString(
          '{"authToken":"legacy-token","manualMode":false}',
        );
        final secure = InMemorySecureTokenRepository();
        final store = SettingsStore(
          settingsFile: settingsFile,
          tokenRepository: secure,
        );
        await store.load();
        // Migrated into the local token file...
        expect(await secure.read(), 'legacy-token');
        // ...and still available in-memory...
        expect(store.settings.authToken, 'legacy-token');
        // ...and the token is NOT re-persisted to the JSON on subsequent save.
        await store.updateSettings(store.settings.copyWith(networkId: 'net1'));
        final raw = await settingsFile.readAsString();
        expect(raw.contains('legacy-token'), isFalse);
      },
    );

    test('logout (blank token) clears the local token file', () async {
      final tmp = await Directory.systemTemp.createTemp('p2wlan_ss_');
      addTearDown(() async => tmp.delete(recursive: true));
      final settingsFile = File('${tmp.path}/settings.json');
      final secure = InMemorySecureTokenRepository();
      final store = SettingsStore(
        settingsFile: settingsFile,
        tokenRepository: secure,
      );
      await store.load();
      await store.updateSettings(store.settings.copyWith(authToken: 'tok'));
      expect(await secure.read(), 'tok');
      // Simulate logout: clear the token.
      await store.updateSettings(store.settings.copyWith(authToken: ''));
      expect(await secure.read(), isNull);
    });
  });

  group('redactSensitive', () {
    test('masks bearer authorization headers', () {
      expect(
        redactSensitive('Authorization: Bearer abc.def-123'),
        'Authorization: Bearer <redacted>',
      );
    });

    test('masks json token fields (double-quoted)', () {
      expect(
        redactSensitive(r'{"token":"secret123"}'),
        r'{"token":"<redacted>"}',
      );
    });

    test('masks key=value and relay ticket forms', () {
      expect(
        redactSensitive('token=abc relay_ticket=ticket999'),
        'token=<redacted> relay_ticket=<redacted>',
      );
    });

    test('masks PEM private key bodies', () {
      const input =
          '-----BEGIN PRIVATE KEY-----\nMIIEv...\n-----END PRIVATE KEY-----';
      final out = redactSensitive(input);
      expect(out.contains('MIIEv'), isFalse);
      expect(out.contains('<redacted>'), isTrue);
    });

    test('leaves non-credential text untouched', () {
      expect(
        redactSensitive('route installed on p2wlan0'),
        'route installed on p2wlan0',
      );
    });

    test('does not redact the word token in prose without an assignment', () {
      // "token" alone (no : or = value) is not a credential occurrence.
      expect(
        redactSensitive('token rotation scheduled'),
        'token rotation scheduled',
      );
    });
  });
}

class _FailingSecureTokenRepository implements SecureTokenRepository {
  @override
  Future<String?> read() async => null;

  @override
  Future<void> write(String token) async {
    throw const SecureTokenStorageException('local token file write failed');
  }

  @override
  Future<void> clear() async {}
}
