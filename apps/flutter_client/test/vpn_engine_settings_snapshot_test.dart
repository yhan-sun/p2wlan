import 'dart:convert';
import 'dart:io';

import 'package:flutter_test/flutter_test.dart';
import 'package:p2wlan_flutter_client/core/models/diagnostics_models.dart';
import 'package:p2wlan_flutter_client/core/security/secure_token_repository.dart';
import 'package:p2wlan_flutter_client/core/state/settings_store.dart';
import 'package:p2wlan_flutter_client/core/state/vpn_engine_settings_snapshot.dart';

void main() {
  late Directory tempDirectory;

  setUp(() async {
    tempDirectory = await Directory.systemTemp.createTemp(
      'p2wlan-engine-snapshot-test-',
    );
  });

  tearDown(() async {
    if (await tempDirectory.exists()) {
      await tempDirectory.delete(recursive: true);
    }
  });

  File snapshotFile() =>
      File('${tempDirectory.path}/vpn-engine-settings-v1.json');

  AppSettings configuredSettings({
    String token = 'token-a',
    String relayServers = 'relay-a:443, relay-b:443,,',
  }) => AppSettings(
    controlServer: 'https://control.example',
    authToken: token,
    networkId: 'network-a',
    virtualIp: '10.20.0.8',
    deviceName: 'test-device',
    overlayCidr: '10.20.0.0/16',
    tunInterface: 'p2wlan0',
    mtu: 1420,
    udpBind: '0.0.0.0:0',
    udpAdvertise: '198.51.100.2:60207',
    socketPool: '2',
    relayServers: relayServers,
  );

  group('FileVpnEngineSettingsSnapshotWriter', () {
    test(
      'writes the full engine config and increments only changed revisions',
      () async {
        final writer = FileVpnEngineSettingsSnapshotWriter(
          file: snapshotFile(),
        );
        final settings = configuredSettings();

        expect(await writer.publish(settings), 1);
        final first = jsonDecode(await snapshotFile().readAsString()) as Map;
        expect(first['schemaVersion'], vpnEngineSettingsSchemaVersion);
        expect(first['revision'], 1);
        final values = first['settings'] as Map;
        expect(values['controlServer'], 'https://control.example');
        expect(values['authToken'], 'token-a');
        expect(values['networkId'], 'network-a');
        expect(values['manualMode'], false);
        expect(values['virtualIp'], '10.20.0.8');
        expect(values['deviceName'], 'test-device');
        expect(values['overlayCidr'], '10.20.0.0/16');
        expect(values['tunInterface'], 'p2wlan0');
        expect(values['mtu'], 1420);
        expect(values['udpBind'], '0.0.0.0:0');
        expect(values['udpAdvertise'], '198.51.100.2:60207');
        expect(values['socketPool'], '2');
        expect(values['relayServers'], ['relay-a:443', 'relay-b:443']);

        // A display-only field does not create a new engine revision.
        expect(await writer.publish(settings.copyWith(themeMode: 'dark')), 1);
        expect(
          await writer.publish(settings.copyWith(authToken: 'token-b')),
          2,
        );
        final second = jsonDecode(await snapshotFile().readAsString()) as Map;
        expect(second['revision'], 2);
        expect((second['settings'] as Map)['authToken'], 'token-b');
      },
    );

    test(
      'legacy offline flags cannot enable a tokenless engine snapshot',
      () async {
        final writer = FileVpnEngineSettingsSnapshotWriter(
          file: snapshotFile(),
        );

        final legacySettings = AppSettings.fromJson({
          'authToken': '',
          'manualMode': true,
          'personalManualMode': true,
        });
        final values = vpnEngineSettingsValues(legacySettings);
        expect(values['manualMode'], isFalse);
        expect(vpnEngineSettingsCanStart(values), isFalse);

        expect(await writer.publish(legacySettings), 1);
        final written = jsonDecode(await snapshotFile().readAsString()) as Map;
        final writtenSettings = written['settings'] as Map;
        expect(writtenSettings['manualMode'], isFalse);
        expect(writtenSettings['authToken'], isEmpty);
      },
    );

    test(
      'invalid existing schema is not overwritten or reset to revision one',
      () async {
        final file = snapshotFile();
        const malformed = '{"schemaVersion":2,"revision":9,"settings":{}}';
        await file.writeAsString(malformed);
        final writer = FileVpnEngineSettingsSnapshotWriter(file: file);

        await expectLater(
          writer.publish(configuredSettings()),
          throwsA(
            isA<VpnEngineSettingsSnapshotException>().having(
              (error) => error.code,
              'code',
              'VPN_ENGINE_SETTINGS_SNAPSHOT_INVALID',
            ),
          ),
        );
        expect(await file.readAsString(), malformed);
      },
    );

    test('oversized snapshot is rejected before a file is created', () async {
      final writer = FileVpnEngineSettingsSnapshotWriter(file: snapshotFile());

      await expectLater(
        writer.publish(
          configuredSettings(token: 't' * vpnEngineSettingsMaxBytes),
        ),
        throwsA(
          isA<VpnEngineSettingsSnapshotException>().having(
            (error) => error.code,
            'code',
            'VPN_ENGINE_SETTINGS_SNAPSHOT_TOO_LARGE',
          ),
        ),
      );
      expect(await snapshotFile().exists(), isFalse);
    });

    test(
      'write failure uses a stable code and does not expose a path',
      () async {
        final path = '${tempDirectory.path}/snapshot-is-a-directory';
        await Directory(path).create();
        final writer = FileVpnEngineSettingsSnapshotWriter(file: File(path));

        await expectLater(
          writer.publish(configuredSettings()),
          throwsA(
            isA<VpnEngineSettingsSnapshotException>()
                .having(
                  (error) => error.code,
                  'code',
                  'VPN_ENGINE_SETTINGS_SNAPSHOT_WRITE_FAILED',
                )
                .having(
                  (error) => error.toString(),
                  'message',
                  isNot(contains(path)),
                ),
          ),
        );
      },
    );
  });

  test('settings update rolls token and settings back when snapshot publication fails', () async {
    final file = File('${tempDirectory.path}/flutter-client-settings.json');
    final tokens = InMemorySecureTokenRepository();
    final writer = _FailingSnapshotWriter();
    final store = SettingsStore(
      settingsFile: file,
      tokenRepository: tokens,
      vpnEngineSnapshotWriter: writer,
    );
    await store.load();
    expect(writer.calls, 1);

    writer.fail = true;
    final proposed = store.settings.copyWith(
      controlServer: 'https://control.example',
      authToken: 'new-managed-token',
      deviceName: 'test-device',
    );
    await expectLater(
      store.updateSettings(proposed),
      throwsA(isA<Exception>()),
    );

    expect(store.settings.controlServer, '');
    expect(store.settings.authToken, '');
    expect(await tokens.read(), isNull);
    final persisted = AppSettings.fromJson(
      jsonDecode(await file.readAsString()) as Map<String, dynamic>,
    );
    expect(persisted.controlServer, '');
    expect(persisted.authToken, '');
    expect(
      store.lastError,
      contains('VPN_ENGINE_SETTINGS_SNAPSHOT_WRITE_FAILED'),
    );
    expect(store.lastError, isNot(contains('new-managed-token')));
    expect(writer.calls, 2); // rollback does not publish another revision.
    store.dispose();
  });

  test(
    'settings, token, and snapshot revision survive a fresh store instance',
    () async {
      final settingsFile = File(
        '${tempDirectory.path}/flutter-client-settings.json',
      );
      final tokenFile = File('${tempDirectory.path}/p2wlan-auth-token');
      final snapshot = snapshotFile();

      final firstStore = SettingsStore(
        settingsFile: settingsFile,
        tokenRepository: LocalTokenRepository(file: tokenFile),
        vpnEngineSnapshotWriter: FileVpnEngineSettingsSnapshotWriter(
          file: snapshot,
        ),
      );
      await firstStore.load();
      expect(jsonDecode(await snapshot.readAsString())['revision'], 1);

      await firstStore.updateSettings(
        firstStore.settings.copyWith(
          controlServer: 'https://control.example',
          authToken: 'persisted-token',
          deviceName: 'persisted-device',
        ),
      );
      expect(await tokenFile.readAsString(), 'persisted-token');
      expect(jsonDecode(await snapshot.readAsString())['revision'], 2);
      firstStore.dispose();

      final restartedStore = SettingsStore(
        settingsFile: settingsFile,
        tokenRepository: LocalTokenRepository(file: tokenFile),
        vpnEngineSnapshotWriter: FileVpnEngineSettingsSnapshotWriter(
          file: snapshot,
        ),
      );
      await restartedStore.load();

      expect(restartedStore.settings.authToken, 'persisted-token');
      expect(restartedStore.settings.controlServer, 'https://control.example');
      final restored = jsonDecode(await snapshot.readAsString()) as Map;
      expect(restored['revision'], 2);
      expect((restored['settings'] as Map)['authToken'], 'persisted-token');
      expect((restored['settings'] as Map)['deviceName'], 'persisted-device');
      restartedStore.dispose();
    },
  );
}

class _FailingSnapshotWriter implements VpnEngineSettingsSnapshotWriter {
  bool fail = false;
  int calls = 0;

  @override
  Future<int> publish(AppSettings settings) async {
    calls++;
    if (fail) {
      throw const VpnEngineSettingsSnapshotException(
        'VPN_ENGINE_SETTINGS_SNAPSHOT_WRITE_FAILED',
      );
    }
    return calls;
  }
}
