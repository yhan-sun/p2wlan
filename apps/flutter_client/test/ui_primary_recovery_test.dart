import 'dart:convert';
import 'dart:io';

import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:p2wlan_flutter_client/app/app_strings.dart';
import 'package:p2wlan_flutter_client/app/app_theme.dart';
import 'package:p2wlan_flutter_client/core/api/diagnostics_api.dart';
import 'package:p2wlan_flutter_client/core/capabilities/permission_preflight.dart';
import 'package:p2wlan_flutter_client/core/capabilities/platform_capabilities.dart';
import 'package:p2wlan_flutter_client/core/daemon/daemon_controller.dart';
import 'package:p2wlan_flutter_client/core/models/diagnostics_models.dart';
import 'package:p2wlan_flutter_client/core/rooms/parallel_rooms.dart';
import 'package:p2wlan_flutter_client/core/rooms/room_api.dart';
import 'package:p2wlan_flutter_client/core/security/secure_token_repository.dart';
import 'package:p2wlan_flutter_client/core/state/settings_store.dart';
import 'package:p2wlan_flutter_client/core/state/status_store.dart';
import 'package:p2wlan_flutter_client/features/diagnostics/diagnostics_page.dart';
import 'package:p2wlan_flutter_client/features/settings/settings_page.dart';

DiagnosticsSnapshot _snapshot(String network, String ip) =>
    DiagnosticsSnapshot.fromJson({
      'network_id': network,
      'node_id': 'local-node',
      'virtual_ip': ip,
      'process_id': 101,
      'runtime_incarnation': 1,
      'revision': 1,
      'captured_revision': 1,
      'health': {
        'status': 'healthy',
        'control_connected': true,
        'device_lease_healthy': true,
      },
      'peers': [],
    });

class _Api extends DiagnosticsApi {
  @override
  Future<bool> fetchHealth(String diagnosticsUrl) async => true;
  @override
  Future<DiagnosticsSnapshot> fetchStatus(String diagnosticsUrl) async =>
      _snapshot('net1', '10.20.0.2');
  @override
  Future<RoutesResponse> verifyRoutes(String diagnosticsUrl) async =>
      const RoutesResponse(
        contractVersion: 1,
        interfaceName: 'p2wlan0',
        mtu: 1420,
        healthy: true,
        conflictCount: 0,
        entries: [],
      );
}

class _Controller extends DaemonController {
  _Controller(DiagnosticsApi api) : super(diagnosticsApi: api);
  int starts = 0;
  int stops = 0;
  @override
  Future<DaemonCommandResult> start(AppSettings settings) async {
    starts++;
    return const DaemonCommandResult(ok: true, message: '');
  }

  @override
  Future<DaemonCommandResult> stop(String diagnosticsUrl) async {
    stops++;
    return const DaemonCommandResult(ok: true, message: '');
  }
}

class _Runtime implements RoomRuntime {
  _Runtime(this.plan);
  final ParallelRoomPlan plan;
  int stops = 0;
  @override
  Future<bool> exists() async => false;
  @override
  Future<DaemonCommandResult> start() async =>
      const DaemonCommandResult(ok: true, message: '');
  @override
  Future<DaemonCommandResult> stop() async {
    stops++;
    return const DaemonCommandResult(ok: true, message: '');
  }

  @override
  Future<DiagnosticsSnapshot> status() async =>
      _snapshot(plan.room.id, '10.21.1.2');
  @override
  void close() {}
}

class _Harness {
  _Harness(
    this.directory,
    this.settings,
    this.status,
    this.controller,
    this.room,
  );
  final Directory directory;
  final SettingsStore settings;
  final StatusStore status;
  final _Controller controller;
  final _Runtime room;
  void dispose() {
    status.dispose();
    settings.dispose();
    directory.deleteSync(recursive: true);
  }
}

Future<_Harness> _harness() async {
  final directory = await Directory.systemTemp.createTemp('primary-recovery-');
  final settings = SettingsStore(
    settingsFile: File('${directory.path}/settings.json'),
    tokenRepository: InMemorySecureTokenRepository(),
  );
  await settings.load();
  final token =
      'a.${base64Url.encode(utf8.encode(jsonEncode({'user_id': 'owner'})))}.b';
  await settings.updateSettings(
    settings.settings.copyWith(
      controlServer: 'https://control.example.com',
      authToken: token,
      deviceName: 'Local device',
      languageCode: 'en',
    ),
  );
  late _Runtime runtime;
  final rooms = ParallelRooms(
    readSettings: () => settings.settings,
    runtimeFactory: (plan) => runtime = _Runtime(plan),
    supported: true,
    refreshInterval: Duration.zero,
  );
  final api = _Api();
  final controller = _Controller(api);
  final status = StatusStore(
    settingsStore: settings,
    diagnosticsApi: api,
    daemonController: controller,
    parallelRooms: rooms,
    enableEventPolling: false,
    startupCatalogRefreshTimeout: Duration.zero,
  );
  final connected = await rooms.connect(
    FriendRoom(
      id: 'room-00000000000000000000000000000001',
      code: '00000001',
      name: 'Other room',
      cidr: '10.21.1.0/24',
      ownerId: 'owner',
      role: 'owner',
      locked: false,
    ),
  );
  expect(connected.ok, isTrue);
  await status.refresh();
  return _Harness(directory, settings, status, controller, runtime);
}

Future<void> _pump(WidgetTester tester, Widget page) async {
  await tester.binding.setSurfaceSize(const Size(1280, 1200));
  addTearDown(() => tester.binding.setSurfaceSize(null));
  await tester.pumpWidget(
    MaterialApp(
      theme: AppTheme.lightTheme,
      home: Scaffold(
        body: AppStringsScope(strings: AppStrings.fromCode('en'), child: page),
      ),
    ),
  );
  await tester.pumpAndSettle();
}

Future<void> _waitFor(WidgetTester tester, bool Function() done) async {
  for (var count = 0; count < 100 && !done(); count++) {
    await tester.runAsync(
      () => Future<void>.delayed(const Duration(milliseconds: 10)),
    );
    await tester.pump();
  }
  expect(done(), isTrue);
}

void _expectOnlyPrimaryRestarted(_Harness harness) {
  expect(harness.controller.stops, 1);
  expect(harness.controller.starts, 1);
  expect(harness.room.stops, 0);
  expect(harness.status.parallelRooms.sessions, hasLength(1));
  expect(
    harness.status.parallelRooms.sessions.values.single.phase,
    RoomConnectionPhase.running,
  );
}

void main() {
  testWidgets(
    'pending settings survive page remount and restart only primary',
    (tester) async {
      final harness = (await tester.runAsync(_harness))!;
      addTearDown(harness.dispose);
      await _pump(
        tester,
        SettingsPage(
          settingsStore: harness.settings,
          statusStore: harness.status,
          capabilities: PlatformCapabilities.fromPlatform('macos'),
        ),
      );
      await tester.tap(find.text('Advanced Network'));
      await tester.pumpAndSettle();
      final mtu = find.byWidgetPredicate(
        (widget) =>
            widget is TextField && widget.decoration?.labelText == 'MTU',
      );
      await tester.enterText(mtu, '1300');
      await tester.pump();
      final save = find.byKey(const Key('settings-save-button'));
      await tester.ensureVisible(save);
      await tester.pumpAndSettle();
      expect(save.hitTestable(), findsOneWidget);
      await tester.tap(save);
      await _waitFor(
        tester,
        () => find.byKey(const Key('settings-save-button')).evaluate().isEmpty,
      );
      expect(harness.status.primaryConfigurationPending, isTrue);
      await tester.pumpWidget(const SizedBox.shrink());
      await _pump(
        tester,
        SettingsPage(
          settingsStore: harness.settings,
          statusStore: harness.status,
          capabilities: PlatformCapabilities.fromPlatform('macos'),
        ),
      );
      await tester.drag(find.byType(ListView).last, const Offset(0, 1600));
      await tester.pumpAndSettle();
      final restart = find.text('Restart and apply');
      await _waitFor(tester, () => restart.evaluate().isNotEmpty);
      await tester.ensureVisible(restart);
      await tester.pumpAndSettle();
      await tester.tap(restart);
      await _waitFor(tester, () => harness.controller.starts == 1);
      await tester.pumpAndSettle();
      _expectOnlyPrimaryRestarted(harness);
      expect(harness.status.primaryConfigurationPending, isFalse);
      expect(find.text('P2WLAN restart required'), findsNothing);
      expect(tester.takeException(), isNull);
    },
  );

  testWidgets('diagnostics restart preserves parallel rooms', (tester) async {
    var roomRequests = 0;
    final harness = (await tester.runAsync(_harness))!;
    addTearDown(harness.dispose);
    await _pump(
      tester,
      DiagnosticsPage(
        settingsStore: harness.settings,
        onOpenRooms: () => roomRequests++,
        statusStore: harness.status,
        capabilities: PlatformCapabilities.fromPlatform('macos'),
        permissionCheck: () async => const PermissionPreflight(
          platform: 'macos',
          state: PermissionPreflightState.satisfied,
          canCreateTun: true,
          canModifyRoutes: true,
          elevationSupported: true,
          reasonCode: 'ready',
          message: '',
          checks: [],
        ),
        logPreviewLoader: () async => const DiagnosticsLogPreview(
          path: '',
          content: '',
          shownLineCount: 0,
        ),
      ),
    );
    expect(find.text('Checking: default local connection'), findsOneWidget);
    await tester.tap(find.byKey(const Key('diagnostics-open-rooms')));
    expect(roomRequests, 1);
    final advanced = find.byKey(const Key('diagnostics-advanced'));
    await tester.ensureVisible(advanced);
    await tester.tap(advanced);
    await tester.pumpAndSettle();
    final restart = find.text('Restart network service (brief disconnect)');
    await tester.ensureVisible(restart);
    await tester.pumpAndSettle();
    await tester.tap(restart);
    await _waitFor(tester, () => harness.controller.starts == 1);
    await tester.pumpAndSettle();
    _expectOnlyPrimaryRestarted(harness);
    expect(tester.takeException(), isNull);
  });

  test('parallel room lifecycle cannot clear primary apply intent', () async {
    final harness = await _harness();
    addTearDown(harness.dispose);
    await harness.settings.updateSettings(
      harness.settings.settings.copyWith(mtu: 1300),
    );
    expect(harness.status.primaryConfigurationPending, isTrue);
    final room = harness.room.plan.room;
    expect((await harness.status.parallelRooms.disconnect(room.id)).ok, isTrue);
    expect(harness.status.primaryConfigurationPending, isTrue);
    expect((await harness.status.parallelRooms.connect(room)).ok, isTrue);
    expect(harness.status.primaryConfigurationPending, isTrue);
    expect(harness.controller.starts, 0);
    expect(harness.controller.stops, 0);
  });
}
