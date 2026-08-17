import 'dart:convert';
import 'dart:io';

import 'package:flutter_test/flutter_test.dart';
import 'package:p2wlan_flutter_client/core/security/redactor.dart';
import 'package:p2wlan_flutter_client/core/security/secure_token_repository.dart';
import 'package:p2wlan_flutter_client/core/state/settings_store.dart';

void main() {
  group('SecureTokenRepository (file-backed)', () {
    late Directory tmp;
    late File tokenFile;
    late FileSecureTokenRepository repo;

    setUp(() async {
      tmp = await Directory.systemTemp.createTemp('p2wlan_tok_');
      tokenFile = File('${tmp.path}/token');
      repo = FileSecureTokenRepository(tokenFile);
    });

    tearDown(() async {
      if (await tmp.exists()) await tmp.delete(recursive: true);
    });

    test('read returns null when nothing stored', () async {
      expect(await repo.read(), isNull);
    });

    test('write then read round-trips the trimmed value', () async {
      await repo.write('  abc123  ');
      expect(await repo.read(), 'abc123');
    });

    test('writing empty clears the store', () async {
      await repo.write('secret');
      await repo.write('   ');
      expect(await repo.read(), isNull);
      expect(await tokenFile.exists(), isFalse);
    });

    test('no truncated temp file remains after a write', () async {
      await repo.write('secret');
      expect(await File('${tokenFile.path}.tmp').exists(), isFalse);
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

  group('SettingsStore token handling', () {
    test(
      'token is never persisted to the settings JSON; secure store holds it',
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

    test('legacy in-JSON token migrates to the secure store on load', () async {
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
      // Migrated into secure storage...
      expect(await secure.read(), 'legacy-token');
      // ...and still available in-memory...
      expect(store.settings.authToken, 'legacy-token');
      // ...and the token is NOT re-persisted to the JSON on subsequent save.
      await store.updateSettings(store.settings.copyWith(networkId: 'net1'));
      final raw = await settingsFile.readAsString();
      expect(raw.contains('legacy-token'), isFalse);
    });

    test('logout (blank token) clears the secure store', () async {
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
