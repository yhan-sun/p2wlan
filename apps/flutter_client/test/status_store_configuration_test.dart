import 'dart:async';
import 'dart:io';

import 'package:flutter_test/flutter_test.dart';
import 'package:p2wlan_flutter_client/core/api/diagnostics_api.dart';
import 'package:p2wlan_flutter_client/core/daemon/daemon_controller.dart';
import 'package:p2wlan_flutter_client/core/models/diagnostics_models.dart';
import 'package:p2wlan_flutter_client/core/rooms/parallel_rooms.dart';
import 'package:p2wlan_flutter_client/core/security/secure_token_repository.dart';
import 'package:p2wlan_flutter_client/core/state/settings_store.dart';
import 'package:p2wlan_flutter_client/core/state/status_store.dart';

void main() {
  late _Harness harness;
  setUp(() async => harness = await _Harness.create());
  tearDown(() => harness.dispose());

  test(
    'an external runtime is unknown until an owned launch succeeds',
    () async {
      await harness.status.refresh();
      final originalMtu = harness.settings.settings.mtu;
      expect(harness.status.primaryConfigurationPending, isFalse);
      await harness.saveMtu(1300);
      expect(harness.status.primaryConfigurationPending, isTrue);
      // Reverting an edit cannot prove an externally started daemon's config.
      await harness.saveMtu(originalMtu);
      expect(harness.status.primaryConfigurationPending, isTrue);
      expect((await harness.status.startDaemon()).ok, isTrue);
      expect(harness.status.primaryConfigurationPending, isFalse);
      await harness.saveMtu(1300);
      expect(harness.status.primaryConfigurationPending, isTrue);
      // There is now actual launch evidence for the original configuration.
      await harness.saveMtu(originalMtu);
      expect(harness.status.primaryConfigurationPending, isFalse);
    },
  );

  test('failed saves do not create or replace pending configuration', () async {
    await harness.status.refresh();
    harness.tokens.failNextWrite = true;
    await expectLater(
      harness.saveMtu(1300),
      throwsA(isA<SecureTokenStorageException>()),
    );
    expect(harness.settings.settings.mtu, defaultMtu);
    expect(harness.status.primaryConfigurationPending, isFalse);
    await harness.saveMtu(1300);
    harness.tokens.failNextWrite = true;
    await expectLater(
      harness.saveMtu(1200),
      throwsA(isA<SecureTokenStorageException>()),
    );
    expect(harness.settings.settings.mtu, 1300);
    expect(harness.status.primaryConfigurationPending, isTrue);
    expect((await harness.status.startDaemon()).ok, isTrue);
    expect(harness.controller.launched.last.mtu, 1300);
    expect(harness.status.primaryConfigurationPending, isFalse);
  });

  test(
    'unrelated preferences and status refreshes preserve apply intent',
    () async {
      await harness.status.refresh();
      await harness.settings.updateLanguageCode('zh-Hans');
      await harness.settings.updateThemeMode('dark');
      await harness.settings.updateAccountIdentity(email: 'demo@example.com');
      expect(harness.status.primaryConfigurationPending, isFalse);
      await harness.saveMtu(1300);
      await harness.settings.updateThemeMode('light');
      await harness.status.refresh();
      expect(harness.status.primaryConfigurationPending, isTrue);
    },
  );

  test(
    'stop and failed start preserve apply intent until successful start',
    () async {
      await harness.status.refresh();
      await harness.saveMtu(1300);
      expect((await harness.status.stopPrimaryDaemon()).ok, isTrue);
      expect(harness.status.primaryConfigurationPending, isTrue);
      harness.controller.startWorks = false;
      expect((await harness.status.startDaemon()).ok, isFalse);
      expect(harness.status.primaryConfigurationPending, isTrue);
      harness.controller.startWorks = true;
      expect((await harness.status.startDaemon()).ok, isTrue);
      expect(harness.status.primaryConfigurationPending, isFalse);
    },
  );

  test('a save during startup is not confirmed by the older launch', () async {
    await harness.status.refresh();
    await harness.saveMtu(1300);
    harness.controller.startEntered = Completer<void>();
    harness.controller.releaseStart = Completer<void>();
    final starting = harness.status.startDaemon();
    await harness.controller.startEntered!.future;
    await harness.saveMtu(1200);
    harness.controller.releaseStart!.complete();
    expect((await starting).ok, isTrue);
    expect(harness.controller.launched.last.mtu, 1300);
    expect(harness.status.primaryConfigurationPending, isTrue);
    expect((await harness.status.startDaemon()).ok, isTrue);
    expect(harness.controller.launched.last.mtu, 1200);
    expect(harness.status.primaryConfigurationPending, isFalse);
  });

  test(
    'failed and successful account transitions keep separate apply intent',
    () async {
      await harness.status.refresh();
      await harness.saveMtu(1300);
      harness.controller.stopWorks = false;
      await expectLater(
        harness.settings.updateSettings(
          harness.settings.settings.copyWith(authToken: 'next-account'),
        ),
        throwsA(isA<AccountSessionChangeException>()),
      );
      expect(harness.status.primaryConfigurationPending, isTrue);
      harness.controller.stopWorks = true;
      harness.tokens.failNextWrite = true;
      await expectLater(
        harness.settings.updateSettings(
          harness.settings.settings.copyWith(authToken: 'next-account'),
        ),
        throwsA(isA<SecureTokenStorageException>()),
      );
      expect(harness.settings.settings.authToken, 'demo-token');
      expect(harness.status.primaryConfigurationPending, isTrue);
      await harness.settings.updateSettings(
        harness.settings.settings.copyWith(authToken: 'next-account'),
      );
      expect(harness.status.primaryConfigurationPending, isFalse);
      expect((await harness.status.startDaemon()).ok, isTrue);
      await harness.saveMtu(1200);
      expect(harness.status.primaryConfigurationPending, isTrue);
    },
  );

  test(
    'an old endpoint startup cannot clear a new endpoint apply intent',
    () async {
      await harness.status.refresh();
      await harness.saveMtu(1300);
      harness.controller.startEntered = Completer<void>();
      harness.controller.releaseStart = Completer<void>();
      final starting = harness.status.startDaemon();
      await harness.controller.startEntered!.future;
      await harness.settings.updateDiagnosticsUrl(
        'http://127.0.0.1:39278/status',
      );
      expect(harness.status.primaryConfigurationPending, isFalse);
      await harness.status.refresh();
      await harness.saveMtu(1200);
      expect(harness.status.primaryConfigurationPending, isTrue);
      harness.controller.releaseStart!.complete();
      await starting;
      expect(harness.status.primaryConfigurationPending, isTrue);
    },
  );

  test(
    'a pending save cannot expose uncommitted settings to a launch',
    () async {
      await harness.status.refresh();
      harness.tokens.entered = Completer<void>();
      harness.tokens.release = Completer<void>();
      harness.tokens.failNextWrite = true;
      final saving = harness.saveMtu(1300);
      final rejected = expectLater(
        saving,
        throwsA(isA<SecureTokenStorageException>()),
      );
      await harness.tokens.entered!.future;
      expect(harness.settings.settings.mtu, defaultMtu);
      expect((await harness.status.startDaemon()).ok, isTrue);
      expect(harness.controller.launched.last.mtu, defaultMtu);
      harness.tokens.release!.complete();
      await rejected;
      expect(harness.status.primaryConfigurationPending, isFalse);
    },
  );
  for (final sameProcess in [false, true]) {
    test(
      '${sameProcess ? 'runtime incarnation' : 'process'} replacement during startup cannot confirm the old launch',
      () async {
        await harness.status.refresh();
        await harness.saveMtu(1300);
        harness.controller.api.replaceAtFetch =
            harness.controller.api.fetches + 2;
        harness.controller.api.replaceRuntimeOnly = sameProcess;
        expect((await harness.status.startDaemon()).ok, isTrue);
        expect(harness.status.primaryConfigurationPending, isTrue);
        expect((await harness.status.startDaemon()).ok, isTrue);
        expect(harness.status.primaryConfigurationPending, isFalse);
      },
    );
  }
}

class _Harness {
  _Harness(
    this.directory,
    this.settings,
    this.status,
    this.tokens,
    this.controller,
  );
  final Directory directory;
  final SettingsStore settings;
  final StatusStore status;
  final _Tokens tokens;
  final _Controller controller;

  static Future<_Harness> create() async {
    final directory = await Directory.systemTemp.createTemp('configuration-');
    final tokens = _Tokens();
    final settings = SettingsStore(
      settingsFile: File('${directory.path}/settings.json'),
      tokenRepository: tokens,
    );
    await settings.load();
    await settings.updateSettings(
      const AppSettings(
        controlServer: 'https://control.example.com',
        authToken: 'demo-token',
        deviceName: 'Demo device',
        languageCode: 'en',
      ),
    );
    final api = _Api();
    final controller = _Controller(api);
    final rooms = ParallelRooms(
      readSettings: () => settings.settings,
      runtimeFactory: (_) => throw StateError('no room expected'),
      supported: false,
    );
    final status = StatusStore(
      settingsStore: settings,
      diagnosticsApi: api,
      daemonController: controller,
      parallelRooms: rooms,
      enableEventPolling: false,
      startupCatalogRefreshTimeout: const Duration(seconds: 1),
      startupCatalogRefreshInterval: Duration.zero,
    );
    return _Harness(directory, settings, status, tokens, controller);
  }

  Future<void> saveMtu(int mtu) =>
      settings.updateSettings(settings.settings.copyWith(mtu: mtu));
  void dispose() {
    status.dispose();
    settings.dispose();
    directory.deleteSync(recursive: true);
  }
}

class _Tokens extends InMemorySecureTokenRepository {
  bool failNextWrite = false;
  Completer<void>? entered;
  Completer<void>? release;
  @override
  Future<void> write(String token) async {
    final gate = release;
    if (gate != null) {
      if (entered?.isCompleted == false) entered!.complete();
      await gate.future;
      release = null;
    }
    if (failNextWrite) {
      failNextWrite = false;
      throw const SecureTokenStorageException('mock storage unavailable');
    }
    await super.write(token);
  }
}

class _Api extends DiagnosticsApi {
  bool reachable = true;
  int processId = 100;
  int runtimeIncarnation = 1;
  int fetches = 0;
  int? replaceAtFetch;
  bool replaceRuntimeOnly = false;
  @override
  Future<bool> fetchHealth(String diagnosticsUrl) async => reachable;
  @override
  Future<DiagnosticsSnapshot> fetchStatus(String diagnosticsUrl) async {
    fetches++;
    if (fetches == replaceAtFetch) {
      if (replaceRuntimeOnly) {
        runtimeIncarnation++;
      } else {
        processId += 100;
      }
    }
    return DiagnosticsSnapshot.fromJson({
      'process_id': processId,
      'runtime_incarnation': runtimeIncarnation,
      'network_id': 'default',
      'virtual_ip': '10.20.0.2',
      'peers': [],
    });
  }

  @override
  Future<RoutesResponse> verifyRoutes(String diagnosticsUrl) async =>
      const RoutesResponse(
        contractVersion: 1,
        interfaceName: 'p2wlan0',
        mtu: defaultMtu,
        healthy: true,
        conflictCount: 0,
        entries: [],
      );
}

class _Controller extends DaemonController {
  _Controller(this.api) : super(diagnosticsApi: api);
  final _Api api;
  final launched = <AppSettings>[];
  bool startWorks = true;
  bool stopWorks = true;
  Completer<void>? startEntered;
  Completer<void>? releaseStart;
  @override
  Future<DaemonCommandResult> start(
    AppSettings settings, {
    int? vpnSettingsRevision,
  }) async {
    launched.add(settings);
    if (startEntered?.isCompleted == false) startEntered!.complete();
    await releaseStart?.future;
    releaseStart = null;
    if (startWorks) {
      api.reachable = true;
      api.processId++;
    }
    return DaemonCommandResult(ok: startWorks, message: 'mock start');
  }

  @override
  Future<DaemonCommandResult> stop(String diagnosticsUrl) async {
    if (stopWorks) api.reachable = false;
    return DaemonCommandResult(ok: stopWorks, message: 'mock stop');
  }
}
