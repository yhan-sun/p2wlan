import 'dart:async';
import 'dart:convert';
import 'dart:io';

import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:p2wlan_flutter_client/app/app_strings.dart';
import 'package:p2wlan_flutter_client/core/api/control_api.dart';
import 'package:p2wlan_flutter_client/features/nodes/nodes_page.dart';
import 'package:p2wlan_flutter_client/core/api/diagnostics_api.dart';
import 'package:p2wlan_flutter_client/core/daemon/daemon_controller.dart';
import 'package:p2wlan_flutter_client/core/models/diagnostics_models.dart';
import 'package:p2wlan_flutter_client/core/rooms/room_profiles.dart';
import 'package:p2wlan_flutter_client/core/security/secure_token_repository.dart';
import 'package:p2wlan_flutter_client/core/state/settings_store.dart';
import 'package:p2wlan_flutter_client/core/state/status_store.dart';

import 'parallel_rooms_test.dart' as rooms;

String _token(String user, [int issued = 1]) =>
    'a.${base64Url.encode(utf8.encode(jsonEncode({'user_id': user, 'iat': issued})))}.b';

DiagnosticsSnapshot _snapshot(String account) => DiagnosticsSnapshot.fromJson({
  'node_id': 'local-$account',
  'network_id': 'default',
  'virtual_ip': '10.20.0.2',
  'process_id': account == 'a' ? 101 : 102,
  'peers': [
    {
      'node_id': 'peer-$account',
      'device_name': 'device-$account',
      'virtual_ip': '10.20.0.3',
    },
  ],
});

class _Api extends DiagnosticsApi {
  DiagnosticsSnapshot current = _snapshot('a');
  Completer<DiagnosticsSnapshot>? response;
  Completer<void>? requested;
  @override
  Future<bool> fetchHealth(String diagnosticsUrl) async => true;
  @override
  Future<DiagnosticsSnapshot> fetchStatus(String diagnosticsUrl) async {
    final pending = response;
    if (pending != null) {
      response = null;
      requested?.complete();
      return pending.future;
    }
    return current;
  }

  @override
  Future<RoutesResponse> verifyRoutes(String diagnosticsUrl) async =>
      const RoutesResponse(
        contractVersion: 1,
        interfaceName: 'p2wlan',
        mtu: 1500,
        healthy: true,
        conflictCount: 0,
        entries: [],
      );
}

class _Daemon extends DaemonController {
  _Daemon(this.api) : super(diagnosticsApi: api);
  final _Api api;
  bool stopWorks = true;
  int stops = 0;
  Completer<void>? stopping;
  Completer<void>? stopped;
  @override
  Future<DaemonCommandResult> stop(String diagnosticsUrl) async {
    stops++;
    if (stopping?.isCompleted == false) stopping!.complete();
    await stopped?.future;
    return DaemonCommandResult(
      ok: stopWorks,
      message: 'stop',
      graceful: stopWorks,
    );
  }

  @override
  Future<DaemonCommandResult> start(AppSettings settings) async {
    api.current = _snapshot(settings.authToken == _token('a') ? 'a' : 'b');
    return const DaemonCommandResult(ok: true, message: 'start');
  }
}

class _GateTokens extends InMemorySecureTokenRepository {
  Completer<void>? writing;
  Completer<void>? release;
  @override
  Future<void> write(String token) async {
    if (release != null) {
      writing!.complete();
      await release!.future;
    }
    await super.write(token);
  }
}

void main() {
  late Directory dir;
  late SettingsStore settings;
  late _GateTokens tokens;
  late _Api api;
  late _Daemon daemon;
  late StatusStore status;

  setUp(() async {
    dir = await Directory.systemTemp.createTemp('p2wlan-account-');
    tokens = _GateTokens();
    settings = SettingsStore(
      settingsFile: File('${dir.path}/settings.json'),
      tokenRepository: tokens,
    );
    await settings.load();
    await settings.updateSettings(
      AppSettings(
        authToken: _token('a'),
        controlServer: 'https://control.example',
      ),
    );
    api = _Api();
    daemon = _Daemon(api);
    status = StatusStore(
      settingsStore: settings,
      diagnosticsApi: api,
      daemonController: daemon,
      enableEventPolling: false,
      startupCatalogRefreshTimeout: Duration.zero,
    );
  });

  tearDown(() async {
    status.dispose();
    settings.dispose();
    await dir.delete(recursive: true);
  });

  test('account profiles are stable for A-B-A and token renewal', () {
    final legacy = File('${dir.path}/p2wlan-config.json');
    final a = settings.settings;
    final b = a.copyWith(authToken: _token('b'));
    final pathA = networkConfigFile(legacy, a).path;
    expect(networkConfigFile(legacy, b).path, isNot(pathA));
    expect(
      networkConfigFile(legacy, a.copyWith(authToken: _token('a', 2))).path,
      pathA,
    );
    expect(networkConfigFile(legacy, a).path, pathA);
    expect(
      pathA,
      contains('${Platform.pathSeparator}accounts${Platform.pathSeparator}'),
    );
    expect(pathA, isNot(legacy.path));
    expect(
      networkConfigFile(
        legacy,
        a.copyWith(controlServer: 'https://other.example'),
      ).path,
      isNot(pathA),
    );
    expect(
      networkConfigFile(legacy, a.copyWith(networkId: 'other')).path,
      isNot(pathA),
    );
  });

  test('room profile layout stays compatible and legacy key is not copied', () async {
    final legacy = File('${dir.path}/p2wlan-config.json');
    await legacy.writeAsString('legacy-private-identity');
    final account = settings.settings;
    final managed = networkConfigFile(legacy, account);
    expect(await managed.exists(), isFalse);
    expect(await legacy.readAsString(), 'legacy-private-identity');
    final room = account.copyWith(networkId: 'room-${'1'.padLeft(32, '0')}');
    expect(
      networkConfigFile(legacy, room).path,
      '${dir.path}${Platform.pathSeparator}rooms${Platform.pathSeparator}${roomProfileId(room)}${Platform.pathSeparator}p2wlan-config.json',
    );
    expect(
      networkConfigFile(legacy, account.copyWith(manualMode: true)).path,
      legacy.path,
    );
    expect(
      () => managedNetworkProfileId(account.copyWith(authToken: 'invalid')),
      throwsException,
    );
  });

  test(
    'credential entry after offline mode uses a fresh managed profile',
    () async {
      final legacy = File('${dir.path}/p2wlan-config.json');
      await legacy.writeAsString('offline-private-identity');
      await settings.updateSettings(
        settings.settings.copyWith(authToken: '', manualMode: true),
      );
      final current = settings.settings;

      await settings.updateConnectionSettings(
        diagnosticsUrl: current.diagnosticsUrl,
        controlServer: current.controlServer,
        authToken: _token('b'),
        networkId: current.networkId,
        virtualIp: current.virtualIp,
        deviceName: current.deviceName,
        manualMode: true,
        overlayCidr: current.overlayCidr,
        tunInterface: current.tunInterface,
        mtu: current.mtu,
        udpBind: current.udpBind,
        udpAdvertise: current.udpAdvertise,
        socketPool: current.socketPool,
        relayServers: current.relayServers,
        closeBehavior: current.closeBehavior,
      );

      expect(settings.settings.manualMode, isFalse);
      expect(settings.settings.authToken, _token('b'));
      final managed = networkConfigFile(legacy, settings.settings);
      expect(managed.path, isNot(legacy.path));
      expect(
        managed.path,
        contains('${Platform.pathSeparator}accounts${Platform.pathSeparator}'),
      );
      expect(await legacy.readAsString(), 'offline-private-identity');
    },
  );

  test(
    'personal daemon stops before B is saved and old peers are cleared',
    () async {
      await status.refresh();
      expect(status.snapshot!.peers.single.nodeId, 'peer-a');
      daemon.stopping = Completer<void>();
      daemon.stopped = Completer<void>();
      final switching = settings.updateSettings(
        settings.settings.copyWith(authToken: _token('b')),
      );
      await daemon.stopping!.future;
      expect(settings.settings.authToken, _token('a'));
      expect(await tokens.read(), _token('a'));
      daemon.stopped!.complete();
      await switching;
      expect(daemon.stops, 1);
      expect(settings.settings.authToken, _token('b'));
      expect(await tokens.read(), _token('b'));
      expect(status.snapshot, isNull);
      await status.refresh();
      expect(
        status.snapshot,
        isNull,
        reason: 'old diagnostics must not repopulate B before a new launch',
      );
      expect((await status.startDaemon()).ok, isTrue);
      expect(status.snapshot!.peers.single.nodeId, 'peer-b');
    },
  );

  test('failed stop preserves A and permits an explicit retry', () async {
    await status.refresh();
    daemon.stopWorks = false;
    await expectLater(
      settings.updateSettings(
        settings.settings.copyWith(authToken: _token('b')),
      ),
      throwsA(isA<AccountSessionChangeException>()),
    );
    expect(settings.settings.authToken, _token('a'));
    expect(await tokens.read(), _token('a'));
    expect(status.snapshot!.nodeId, 'local-a');
    daemon.stopWorks = true;
    await settings.updateSettings(
      settings.settings.copyWith(authToken: _token('b')),
    );
    expect(settings.settings.authToken, _token('b'));
    expect(status.snapshot, isNull);
  });

  test(
    'late A response cannot populate B on the same diagnostics URL',
    () async {
      api.response = Completer<DiagnosticsSnapshot>();
      final oldResponse = api.response!;
      api.requested = Completer<void>();
      final refreshing = status.refresh();
      await api.requested!.future;
      await settings.updateSettings(
        settings.settings.copyWith(authToken: _token('b')),
      );
      oldResponse.complete(_snapshot('a'));
      await refreshing;
      expect(status.snapshot, isNull);
      expect((await status.startDaemon()).ok, isTrue);
      expect(status.snapshot!.nodeId, 'local-b');
    },
  );

  test(
    'new connections stay paused until account persistence completes',
    () async {
      tokens.writing = Completer<void>();
      tokens.release = Completer<void>();
      final switching = settings.updateSettings(
        settings.settings.copyWith(authToken: _token('b')),
      );
      await tokens.writing!.future;
      expect(daemon.stops, 1);
      expect(status.parallelRooms.connectionsPaused, isTrue);
      expect((await status.parallelRooms.connect(rooms.room(1))).ok, isFalse);
      expect((await status.startDaemon()).ok, isFalse);
      expect(status.snapshot, isNull);
      tokens.release!.complete();
      await switching;
      expect(status.parallelRooms.connectionsPaused, isFalse);
      expect(await tokens.read(), _token('b'));
    },
  );

  test(
    'an A preference queued behind switching to B cannot restore A',
    () async {
      daemon.stopped = Completer<void>();
      daemon.stopping = Completer<void>();
      final switching = settings.updateSettings(
        settings.settings.copyWith(authToken: _token('b')),
      );
      await daemon.stopping!.future;
      final stale = settings.updateSettings(
        settings.settings.copyWith(deviceName: 'late-a-name'),
      );
      final rejected = expectLater(stale, throwsA(isA<FormatException>()));
      daemon.stopped!.complete();
      await switching;
      await rejected;
      expect(settings.settings.authToken, _token('b'));
      expect(settings.settings.deviceName, isNot('late-a-name'));
      expect(daemon.stops, 1);
    },
  );

  testWidgets('late local-device edit cannot overwrite the next account', (
    tester,
  ) async {
    await status.refresh();
    final control = _PendingDeviceEdit();
    await tester.pumpWidget(
      MaterialApp(
        home: AppStringsScope(
          strings: AppStrings.fromCode('en'),
          child: Scaffold(
            body: NodesPage(
              settingsStore: settings,
              statusStore: status,
              controlApi: control,
            ),
          ),
        ),
      ),
    );
    await tester.tap(find.byKey(const Key('nodes-edit-local')));
    await tester.pumpAndSettle();
    final fields = find.descendant(
      of: find.byType(AlertDialog),
      matching: find.byType(TextField),
    );
    await tester.enterText(fields.first, 'late-a-name');
    await tester.tap(find.widgetWithText(FilledButton, 'Save'));
    await tester.pumpAndSettle();
    expect(control.entered.isCompleted, isTrue);
    await tester.runAsync(
      () => settings.updateSettings(
        settings.settings.copyWith(
          authToken: _token('b'),
          deviceName: 'device-b',
        ),
      ),
    );
    control.reply.complete(
      const DeviceUpdateResult(
        deviceName: 'late-a-name',
        virtualIp: '10.20.0.2',
      ),
    );
    await tester.pump();
    expect(settings.settings.authToken, _token('b'));
    expect(settings.settings.deviceName, 'device-b');
    expect(daemon.stops, 1);
    expect(tester.takeException(), isNull);
    await tester.pumpWidget(const SizedBox.shrink());
  });

  test('ordinary preferences do not stop primary or clear its peers', () async {
    await status.refresh();
    final original = status.snapshot;
    await settings.updateSettings(
      settings.settings.copyWith(deviceName: 'new-name'),
    );
    expect(daemon.stops, 0);
    expect(status.snapshot, same(original));
  });

  test(
    'logout of a personal network stops it without any room sessions',
    () async {
      expect(status.parallelRooms.hasSessions, isFalse);
      await status.refresh();
      await settings.updateSettings(settings.settings.copyWith(authToken: ''));
      expect(daemon.stops, 1);
      expect(status.snapshot, isNull);
      expect(await tokens.read(), anyOf(isNull, isEmpty));
    },
  );

  test(
    'manual mode permits diagnostics refresh without requiring startDaemon',
    () async {
      await settings.updateSettings(
        settings.settings.copyWith(manualMode: true, authToken: ''),
      );
      expect(daemon.stops, 1);
      await status.refresh();
      expect(status.daemonReachable, isTrue);
    },
  );
}

class _PendingDeviceEdit extends ControlApi {
  final entered = Completer<void>();
  final reply = Completer<DeviceUpdateResult>();
  @override
  Future<DeviceUpdateResult> updateDevice({
    required String controlServer,
    required String authToken,
    required String deviceId,
    String? deviceName,
    String? virtualIp,
  }) {
    entered.complete();
    return reply.future;
  }
}
